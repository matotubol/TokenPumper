use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Context, Result};
use arc_swap::ArcSwap;
use prost_types::Timestamp;
use tokio::{task::JoinHandle, time::sleep};
use tonic::{
    metadata::{errors::InvalidMetadataValue, MetadataValue},
    service::Interceptor,
    transport::Channel,
    Request, Status,
};
use tracing::{debug, warn};

use super::keypair::SigningKeypair;

use super::proto::auth::{
    auth_service_client::AuthServiceClient, GenerateAuthChallengeRequest,
    GenerateAuthTokensRequest, RefreshAccessTokenRequest, Role, Token,
};

/// Re-up the access token when it has this much TTL or less.
const REFRESH_MARGIN: Duration = Duration::from_secs(5 * 60);
/// Idle poll cadence.
const REFRESH_POLL: Duration = Duration::from_secs(5);

/// Tonic interceptor that stamps `authorization: Bearer <token>` onto every
/// outbound request. The token lives behind an `ArcSwap` so the refresh task
/// can hot-swap it without blocking inflight calls.
#[derive(Clone)]
pub struct BearerInterceptor {
    token: Arc<ArcSwap<String>>,
}

impl BearerInterceptor {
    pub fn new(initial: String) -> Self {
        Self {
            token: Arc::new(ArcSwap::from_pointee(initial)),
        }
    }

    pub fn store(&self, token: String) {
        self.token.store(Arc::new(token));
    }
}

impl Interceptor for BearerInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let snapshot = self.token.load();
        if snapshot.is_empty() {
            return Err(Status::unauthenticated("bearer token not yet available"));
        }
        let header: MetadataValue<_> = format!("Bearer {}", *snapshot)
            .parse()
            .map_err(|e: InvalidMetadataValue| Status::internal(e.to_string()))?;
        request.metadata_mut().insert("authorization", header);
        Ok(request)
    }
}

/// Runs the full challenge/response handshake once and returns
/// `(access_token, refresh_token)`.
///
/// The signed payload is `format!("{pubkey_base58}-{challenge}")`, byte-exact
/// to what `jito-solana`'s reference client produces.
pub async fn challenge_and_sign(
    client: &mut AuthServiceClient<Channel>,
    keypair: &SigningKeypair,
    role: Role,
) -> Result<(Token, Token)> {
    let pubkey = keypair.pubkey_bytes().to_vec();

    let challenge_resp = client
        .generate_auth_challenge(GenerateAuthChallengeRequest {
            role: role as i32,
            pubkey: pubkey.clone(),
        })
        .await
        .context("generate_auth_challenge")?
        .into_inner();

    let message = format!("{}-{}", keypair.pubkey_base58(), challenge_resp.challenge);
    let signed = keypair.sign(message.as_bytes()).to_vec();

    let tokens = client
        .generate_auth_tokens(GenerateAuthTokensRequest {
            challenge: message,
            client_pubkey: pubkey,
            signed_challenge: signed,
        })
        .await
        .context("generate_auth_tokens")?
        .into_inner();

    let access = tokens
        .access_token
        .ok_or_else(|| anyhow!("auth response missing access_token"))?;
    let refresh = tokens
        .refresh_token
        .ok_or_else(|| anyhow!("auth response missing refresh_token"))?;
    Ok((access, refresh))
}

/// Background task that keeps `interceptor`'s bearer token fresh.
pub fn spawn_token_refresher(
    mut auth_client: AuthServiceClient<Channel>,
    interceptor: BearerInterceptor,
    initial_access: Token,
    initial_refresh: Token,
    keypair: Arc<SigningKeypair>,
    role: Role,
    exit: Arc<AtomicBool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut refresh_token = initial_refresh;
        let mut access_expires = initial_access
            .expires_at_utc
            .expect("initial access token missing expires_at_utc");

        while !exit.load(Ordering::Relaxed) {
            let now = SystemTime::now();

            let refresh_expires = refresh_token
                .expires_at_utc
                .clone()
                .expect("refresh token missing expires_at_utc");
            let refresh_ttl = ttl_from(now, &refresh_expires);

            if refresh_ttl < REFRESH_MARGIN {
                match challenge_and_sign(&mut auth_client, &keypair, role).await {
                    Ok((access, new_refresh)) => {
                        debug!("rotated full auth token set");
                        interceptor.store(access.value.clone());
                        access_expires = access
                            .expires_at_utc
                            .expect("refreshed access token missing expires_at_utc");
                        refresh_token = new_refresh;
                    }
                    Err(err) => {
                        warn!(%err, "full auth re-handshake failed, retrying");
                        sleep(REFRESH_POLL).await;
                    }
                }
                continue;
            }

            let access_ttl = ttl_from(now, &access_expires);
            if access_ttl < REFRESH_MARGIN {
                match auth_client
                    .refresh_access_token(RefreshAccessTokenRequest {
                        refresh_token: refresh_token.value.clone(),
                    })
                    .await
                {
                    Ok(resp) => match resp.into_inner().access_token {
                        Some(access) => {
                            debug!("rotated access token via refresh");
                            interceptor.store(access.value.clone());
                            access_expires = access
                                .expires_at_utc
                                .expect("refreshed access token missing expires_at_utc");
                        }
                        None => warn!("refresh_access_token response missing access token"),
                    },
                    Err(err) => warn!(%err, "access token refresh failed, retrying"),
                }
                continue;
            }

            sleep(REFRESH_POLL).await;
        }
    })
}

fn ttl_from(now: SystemTime, ts: &Timestamp) -> Duration {
    SystemTime::try_from(ts.clone())
        .ok()
        .and_then(|t| t.duration_since(now).ok())
        .unwrap_or_default()
}
