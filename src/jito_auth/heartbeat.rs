use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio::time::{self, Instant, MissedTickBehavior};
use tonic::{codegen::InterceptedService, transport::Channel, Code};
use tracing::{debug, error, info, warn};

use super::auth::BearerInterceptor;
use super::proto::shared::Socket as ProtoSocket;
use super::proto::shredstream::{shredstream_client::ShredstreamClient, Heartbeat};

pub type AuthedShredstreamClient =
    ShredstreamClient<InterceptedService<Channel, BearerInterceptor>>;

#[derive(Debug, Clone)]
pub struct HeartbeatConfig {
    /// Public `ip:port` we want Jito to forward shreds to.
    ///
    /// `ip` MUST match the source IP Jito sees for this gRPC connection,
    /// otherwise the Block Engine refuses to route — spoofing the socket
    /// would let a client weaponize the flow against a third party.
    pub advertise: SocketAddr,
    /// Edge regions to subscribe to: `amsterdam, ny, frankfurt, tokyo, slc`.
    pub regions: Vec<String>,
}

#[derive(Default)]
pub struct HeartbeatStats {
    pub ok: AtomicU64,
    pub failed: AtomicU64,
}

impl HeartbeatStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

/// Jito replies with `ttl_ms` after each heartbeat. We retune to `ttl_ms / 3`
/// so we never miss the keep-alive deadline, matching the reference proxy.
pub fn spawn_heartbeat(
    mut client: AuthedShredstreamClient,
    cfg: HeartbeatConfig,
    stats: Arc<HeartbeatStats>,
    exit: Arc<AtomicBool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        info!(
            advertise = %cfg.advertise,
            regions = ?cfg.regions,
            "heartbeat task started"
        );
        let socket = ProtoSocket {
            ip: cfg.advertise.ip().to_string(),
            port: cfg.advertise.port() as i64,
        };

        let mut period = Duration::from_secs(1);
        let mut ticker = time::interval(period);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

        while !exit.load(Ordering::Relaxed) {
            ticker.tick().await;

            let beat = Heartbeat {
                socket: Some(socket.clone()),
                regions: cfg.regions.clone(),
            };

            match client.send_heartbeat(beat).await {
                Ok(resp) => {
                    stats.ok.fetch_add(1, Ordering::Relaxed);
                    let server_ttl = Duration::from_millis(resp.get_ref().ttl_ms as u64);
                    let desired = server_ttl / 3;
                    if !desired.is_zero() && desired != period {
                        debug!(
                            old = ?period,
                            new = ?desired,
                            server_ttl = ?server_ttl,
                            "retuning heartbeat cadence per server ttl_ms/3"
                        );
                        period = desired;
                        ticker = time::interval_at(Instant::now() + period, period);
                        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
                    }
                }
                Err(status) if status.code() == Code::InvalidArgument => {
                    error!(%status, "heartbeat rejected with InvalidArgument — bailing");
                    return;
                }
                Err(status) => {
                    stats.failed.fetch_add(1, Ordering::Relaxed);
                    warn!(%status, "heartbeat send failed");
                }
            }
        }
        info!("heartbeat task exiting");
    })
}
