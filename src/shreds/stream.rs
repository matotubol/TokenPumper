//! Slot stream orchestration: auth handshake → token refresher → heartbeat
//! → pinned UDP receiver → per-shred classifier that fires CREATE EVENT
//! once a focus slot accumulates `fire_at_shred_count` data shreds.
//!
//! Lives separately from the receiver/wire modules so `shreds.rs` is just
//! a thin parent file with `pub mod` declarations.

use std::net::SocketAddr;
use std::sync::{atomic::AtomicBool, Arc};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::task::JoinHandle as TokioJoinHandle;
use tracing::{info, warn};

use super::receiver::{spawn_receiver, ReceiverConfig, ReceiverHandle};
use super::wire::{get_slot, VariantClass, SIZE_OF_SIGNATURE, VARIANT_TABLE};
use crate::config::Config;
use crate::jito_auth::auth::{challenge_and_sign, spawn_token_refresher, BearerInterceptor};
use crate::jito_auth::heartbeat::{
    spawn_heartbeat, AuthedShredstreamClient, HeartbeatConfig, HeartbeatStats,
};
use crate::jito_auth::keypair::SigningKeypair;
use crate::jito_auth::proto::auth::{auth_service_client::AuthServiceClient, Role};
use crate::jito_auth::proto::shredstream::shredstream_client::ShredstreamClient;
use crate::jito_auth::transport::grpc_channel;
use crate::leaders::LeaderCache;
use crate::pumpfun::launch::{build_signed, LaunchContext};
use crate::pumpfun::tx::BuiltLaunchTx;

#[derive(Debug, Clone)]
pub struct SlotStreamConfig {
    /// Jito Block Engine gRPC URL — receives auth handshakes + heartbeats.
    pub grpc_url: String,
    /// Public `ip:port` to advertise. Source IP of our gRPC connection
    /// MUST match `advertise.ip()`.
    pub advertise: SocketAddr,
    /// Local UDP `ip:port` to bind the receiver on; port should match
    /// `advertise.port()`.
    pub bind: SocketAddr,
    pub regions: Vec<String>,
    pub pin_core: Option<usize>,
    pub recv_buffer_bytes: usize,
    pub busy_poll_us: u32,
    pub jito_keypair_path: std::path::PathBuf,
    pub fire_at_shred_count: u32,
}

impl SlotStreamConfig {
    pub fn from_config(cfg: &Config) -> Result<Self> {
        let advertise = cfg
            .shredstream_advertise
            .parse()
            .with_context(|| format!("parsing shredstream_advertise={}", cfg.shredstream_advertise))?;
        let bind = cfg
            .shredstream_bind
            .parse()
            .with_context(|| format!("parsing shredstream_bind={}", cfg.shredstream_bind))?;
        Ok(Self {
            grpc_url: cfg.shredstream_grpc_url.clone(),
            advertise,
            bind,
            regions: cfg.shredstream_regions.clone(),
            pin_core: cfg.slot_stream_pin_core,
            recv_buffer_bytes: cfg.shredstream_recv_buffer_bytes,
            busy_poll_us: cfg.shredstream_busy_poll_us,
            jito_keypair_path: cfg.jito_keypair_path.clone(),
            fire_at_shred_count: cfg.fire_at_shred_count,
        })
    }
}

pub struct SlotStreamHandle {
    receiver: Option<ReceiverHandle>,
    _tokio_tasks: Vec<TokioJoinHandle<()>>,
}

impl SlotStreamHandle {
    pub fn join(mut self) {
        if let Some(r) = self.receiver.take() {
            r.join();
        }
    }
}

pub async fn spawn(
    cfg: SlotStreamConfig,
    leader_cache: Arc<LeaderCache>,
    launch_ctx: LaunchContext,
    exit: Arc<AtomicBool>,
) -> Result<SlotStreamHandle> {
    let keypair = Arc::new(SigningKeypair::load(&cfg.jito_keypair_path)?);

    let channel = grpc_channel(&cfg.grpc_url)
        .await
        .with_context(|| format!("connecting grpc channel to {}", cfg.grpc_url))?;

    let mut auth_client = AuthServiceClient::new(channel.clone());
    let (access, refresh) =
        challenge_and_sign(&mut auth_client, &keypair, Role::ShredstreamSubscriber)
            .await
            .context("auth handshake")?;
    info!("auth handshake ok");

    let interceptor = BearerInterceptor::new(access.value.clone());
    let refresher = spawn_token_refresher(
        auth_client,
        interceptor.clone(),
        access,
        refresh,
        keypair.clone(),
        Role::ShredstreamSubscriber,
        exit.clone(),
    );

    let shred_client: AuthedShredstreamClient =
        ShredstreamClient::with_interceptor(channel, interceptor);

    let heartbeat = spawn_heartbeat(
        shred_client,
        HeartbeatConfig {
            advertise: cfg.advertise,
            regions: cfg.regions.clone(),
        },
        HeartbeatStats::new(),
        exit.clone(),
    );

    let receiver = spawn_udp_receiver(&cfg, leader_cache, launch_ctx, exit)?;

    Ok(SlotStreamHandle {
        receiver: Some(receiver),
        _tokio_tasks: vec![refresher, heartbeat],
    })
}

fn spawn_udp_receiver(
    cfg: &SlotStreamConfig,
    leader_cache: Arc<LeaderCache>,
    ctx: LaunchContext,
    exit: Arc<AtomicBool>,
) -> Result<ReceiverHandle> {
    let recv_cfg = ReceiverConfig {
        bind: cfg.bind,
        recv_buffer_bytes: cfg.recv_buffer_bytes,
        pin_core: cfg.pin_core,
        busy_poll_us: cfg.busy_poll_us,
    };

    let fire_at = cfg.fire_at_shred_count;
    let mut current_slot: u64 = u64::MAX;
    let mut shreds_in_slot: u32 = 0;
    let mut fired = false;

    let mut data_seen: u64 = 0;
    let mut coding_seen: u64 = 0;
    let mut invalid_seen: u64 = 0;
    let mut last_log = Instant::now();
    let mut tx_buf = BuiltLaunchTx::new();

    let handler = move |buf: &[u8]| {
        let Some(&vbyte) = buf.get(SIZE_OF_SIGNATURE) else {
            invalid_seen += 1;
            return;
        };
        match VARIANT_TABLE[vbyte as usize] {
            VariantClass::Data { .. } => data_seen += 1,
            VariantClass::Coding => {
                coding_seen += 1;
                return;
            }
            VariantClass::Invalid => {
                invalid_seen += 1;
                return;
            }
        }
        let Some(slot) = get_slot(buf) else {
            invalid_seen += 1;
            return;
        };

        if slot != current_slot {
            current_slot = slot;
            shreds_in_slot = 0;
        }
        shreds_in_slot += 1;

        if !fired && shreds_in_slot == fire_at && leader_cache.is_focus(slot) {
            fire_launch(&ctx, &mut tx_buf, slot);
            fired = true;
        }

        if last_log.elapsed() >= Duration::from_secs(10) {
            info!(data_seen, coding_seen, invalid_seen, current_slot, "shred recv stats");
            last_log = Instant::now();
        }
    };

    spawn_receiver(recv_cfg, handler, exit).context("spawn shred receiver")
}

/// Build + sign + submit the launch tx with the *current* blockhash. Runs
/// once when the receiver thread sees the focus slot cross
/// `fire_at_shred_count`. Allocations on the hot path: one `Vec<u8>` for
/// the submit copy (≈ 1.2 KB).
fn fire_launch(ctx: &LaunchContext, tx_buf: &mut BuiltLaunchTx, slot: u64) {
    build_signed(ctx, slot, tx_buf);

    match &ctx.submitter {
        Some(submitter) => {
            let sent = submitter.submit(tx_buf.as_bytes().to_vec());
            if sent {
                info!(slot, len = tx_buf.len(), "launch tx submitted to node1");
            } else {
                warn!(slot, len = tx_buf.len(), "launch tx submit dropped");
            }
        }
        None => {
            info!(
                slot,
                len = tx_buf.len(),
                "launch tx built (no submitter — debug or missing api key)"
            );
        }
    }
}
