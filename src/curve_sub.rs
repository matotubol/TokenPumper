//! Yellowstone gRPC subscription module.
//!
//! Single long-lived bi-di stream owned by one tokio task, multiplexing
//! TWO filters in one `SubscribeRequest`:
//!   * `curve` — the bonding-curve PDA, reserves slice
//!   * `atas`  — every wallet's pre-derived associated-token account
//!
//! The curve PDA + every ATA are deterministic from the mint pubkey, so
//! all subscriptions are opened from the very first connect — Triton
//! stays silent until create_v2 lands and each ATA is created on first
//! buy.
//!
//! `accounts_data_slice` covers `[(8, 32), (64, 8)]` = 40 bytes total
//! per matched account. Curve account: bytes 0..32 of the slice =
//! reserves `[v_tok|v_sol|r_tok|r_sol]`. ATA: bytes 32..40 = `amount`
//! u64. Both ranges are read from the same global slice config — saves
//! us a per-filter slice setting on the wire while still trimming each
//! account from ~250/165 bytes down to 40.
//!
//! Reconnect policy: 1s backoff on stream close or error. Exits cleanly
//! when `exit` is set.

pub mod proto {
    pub mod geyser {
        tonic::include_proto!("geyser");
    }
    // geyser.proto's generated code references the
    // `solana.storage.confirmed_block` package — mirror the proto's
    // module path exactly.
    #[allow(dead_code)]
    pub mod solana {
        pub mod storage {
            pub mod confirmed_block {
                tonic::include_proto!("solana.storage.confirmed_block");
            }
        }
    }
}

mod decode;
mod request;
mod run;
mod transport;

use crate::config::Config;

pub use run::run;

#[derive(Debug, Clone)]
pub struct CurveSubConfig {
    pub endpoint: String,
    pub x_token: String,
    pub ping_interval_secs: u64,
}

impl CurveSubConfig {
    /// Returns `Some` only if both endpoint and x-token are set in
    /// config.toml. Either missing ⇒ feature disabled (returns `None`).
    pub fn from_config(cfg: &Config) -> Option<Self> {
        let endpoint = cfg.curve_sub_endpoint.clone()?;
        let x_token = cfg.curve_sub_x_token.clone()?;
        Some(Self {
            endpoint,
            x_token,
            ping_interval_secs: cfg.curve_sub_ping_interval_secs,
        })
    }
}

/// One pre-derived ATA to track. `label` is what shows up in logs
/// (`"dev"`, `"wallet-3"`, …); `ata` is the deterministic
/// associated-token-address bytes.
///
/// `wallet_index` ties a spread wallet's ATA back to its slot in the
/// runtime balances Vec — `Some(i)` for spread wallets, `None` for the
/// dev (observability only; dev's sell amount is the pre-computed quote).
#[derive(Debug, Clone)]
pub struct AtaSubscription {
    pub label: String,
    pub ata: [u8; 32],
    pub wallet_index: Option<usize>,
}

/// Everything the subscriber needs to know on startup that depends on
/// the picked token + the prepared wallet set.
#[derive(Debug, Clone)]
pub struct StreamInputs {
    pub curve: [u8; 32],
    pub atas: Vec<AtaSubscription>,
}
