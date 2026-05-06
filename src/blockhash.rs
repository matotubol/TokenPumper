//! Recent-blockhash cache. One synchronous fetch at startup, then a
//! background tokio task refreshes every `REFRESH_INTERVAL`. Readers
//! call `current()` for a lock-free copy out of the `ArcSwap`.
//!
//! At fire time the launch-tx builder reads the latest cached value and
//! stamps it into the message's `recent_blockhash` slot — no RPC on the
//! hot path. Solana's blockhash validity window is ~150 slots (~60s), so
//! a 10s refresh leaves us with a hash that's never older than ~10s when
//! we sign over it. If a refresh fails (RPC blip) we keep the previous
//! hash and log; only sustained failure could push us past the validity
//! window.
//!
//! The fetch itself uses `rpc::latest_blockhash` which is a `reqwest`
//! blocking client — wrap in `spawn_blocking` so it doesn't park a
//! tokio worker thread.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use arc_swap::ArcSwap;
use tracing::{info, warn};

use crate::rpc;

pub const REFRESH_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct BlockhashCache {
    inner: Arc<ArcSwap<[u8; 32]>>,
}

impl BlockhashCache {
    /// Fetches one blockhash synchronously (so the cache is hot before
    /// the slot stream comes up), then spawns a tokio task on the current
    /// runtime that refreshes every `REFRESH_INTERVAL`.
    pub async fn bootstrap(rpc_url: String) -> Result<Self> {
        let initial = fetch(rpc_url.clone()).await?;
        info!(
            blockhash = %bs58::encode(initial).into_string(),
            "blockhash cache bootstrapped"
        );
        let inner = Arc::new(ArcSwap::from_pointee(initial));
        spawn_refresher(rpc_url, inner.clone());
        Ok(Self { inner })
    }

    /// Lock-free read of the current cached blockhash.
    #[inline]
    pub fn current(&self) -> [u8; 32] {
        **self.inner.load()
    }
}

async fn fetch(rpc_url: String) -> Result<[u8; 32]> {
    tokio::task::spawn_blocking(move || rpc::latest_blockhash(&rpc_url)).await?
}

fn spawn_refresher(rpc_url: String, inner: Arc<ArcSwap<[u8; 32]>>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(REFRESH_INTERVAL);
        // First tick fires immediately — drop it, we just bootstrapped.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match fetch(rpc_url.clone()).await {
                Ok(h) => inner.store(Arc::new(h)),
                Err(e) => warn!(error = %e, "blockhash refresh failed; keeping previous"),
            }
        }
    });
}
