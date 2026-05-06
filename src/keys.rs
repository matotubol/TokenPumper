pub mod assigner;
pub mod batch;
pub mod dev;
pub mod distribute;
pub mod eater;
pub mod funder;
pub mod refill;
pub mod sweep;
pub mod wallets;

pub mod storage;
mod generate;
mod singleton;
mod time;
mod transaction;

pub use storage::pubkey_base58;
pub use wallets::prepare;

/// Whether a key was loaded from disk or freshly created on this run.
/// Lives at the parent module so `funder.rs`, `singleton.rs`, and the
/// orchestrator share one definition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Loaded,
    Created,
}
