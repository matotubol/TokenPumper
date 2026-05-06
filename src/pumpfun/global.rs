//! One-shot decode of pump.fun's `Global` account at startup. We only
//! pull the three fields the launch tx actually needs:
//!   - `fee_recipient` — writable account in `buy` (mayhem-mode-off path)
//!   - `initial_virtual_token_reserves`
//!   - `initial_virtual_sol_reserves`
//!
//! The other ~20 fields (mayhem reserves, fee_basis_points, the random
//! recipient pool) we don't touch. Borsh field order from the IDL:
//!
//! ```text
//! offset  size  field
//! ------  ----  -----
//!      0     8  account discriminator
//!      8     1  initialized
//!      9    32  authority
//!     41    32  fee_recipient                   ← captured
//!     73     8  initial_virtual_token_reserves  ← captured
//!     81     8  initial_virtual_sol_reserves    ← captured
//!     89     8  initial_real_token_reserves
//!     97     8  token_total_supply
//!    105     8  fee_basis_points                ← captured
//!    113    32  withdraw_authority
//!    145     1  enable_migrate
//!    146     8  pool_migration_fee
//!    154     8  creator_fee_basis_points        ← captured
//!    162     ...
//! ```
//!
//! The Global account can in principle be updated by the program admin
//! (they can rotate `fee_recipient` or change the init reserves), so a
//! long-running process should refresh occasionally — but for now a
//! startup-only fetch is enough.

use anyhow::{anyhow, Context, Result};
use tracing::info;

use super::ix_builder::ix::GLOBAL_PDA;
use crate::rpc;

const FEE_RECIPIENT_OFFSET: usize = 8 + 1 + 32;
const INITIAL_VIRTUAL_TOKEN_RESERVES_OFFSET: usize = FEE_RECIPIENT_OFFSET + 32;
const INITIAL_VIRTUAL_SOL_RESERVES_OFFSET: usize = INITIAL_VIRTUAL_TOKEN_RESERVES_OFFSET + 8;
const FEE_BASIS_POINTS_OFFSET: usize = INITIAL_VIRTUAL_SOL_RESERVES_OFFSET + 8 + 8 + 8;
const CREATOR_FEE_BASIS_POINTS_OFFSET: usize = FEE_BASIS_POINTS_OFFSET + 8 + 32 + 1 + 8;
const MIN_GLOBAL_LEN: usize = CREATOR_FEE_BASIS_POINTS_OFFSET + 8;

#[derive(Debug, Clone, Copy)]
pub struct GlobalCache {
    pub fee_recipient: [u8; 32],
    pub initial_virtual_token_reserves: u64,
    pub initial_virtual_sol_reserves: u64,
    pub fee_basis_points: u64,
    pub creator_fee_basis_points: u64,
}

impl GlobalCache {
    /// Synchronously fetches and decodes the Global account. Blocks for
    /// one RPC roundtrip — call once at startup, store the result.
    pub fn bootstrap(rpc_url: &str) -> Result<Self> {
        let global_b58 = bs58::encode(GLOBAL_PDA).into_string();
        let data = rpc::account_data(rpc_url, &global_b58)
            .with_context(|| format!("fetching Global account at {global_b58}"))?;

        if data.len() < MIN_GLOBAL_LEN {
            return Err(anyhow!(
                "Global account data is {} bytes, want ≥ {}",
                data.len(),
                MIN_GLOBAL_LEN,
            ));
        }

        let mut fee_recipient = [0u8; 32];
        fee_recipient.copy_from_slice(
            &data[FEE_RECIPIENT_OFFSET..FEE_RECIPIENT_OFFSET + 32],
        );

        let initial_virtual_token_reserves = u64::from_le_bytes(
            data[INITIAL_VIRTUAL_TOKEN_RESERVES_OFFSET
                ..INITIAL_VIRTUAL_TOKEN_RESERVES_OFFSET + 8]
                .try_into()
                .unwrap(),
        );

        let initial_virtual_sol_reserves = u64::from_le_bytes(
            data[INITIAL_VIRTUAL_SOL_RESERVES_OFFSET
                ..INITIAL_VIRTUAL_SOL_RESERVES_OFFSET + 8]
                .try_into()
                .unwrap(),
        );

        let fee_basis_points = u64::from_le_bytes(
            data[FEE_BASIS_POINTS_OFFSET..FEE_BASIS_POINTS_OFFSET + 8]
                .try_into()
                .unwrap(),
        );

        let creator_fee_basis_points = u64::from_le_bytes(
            data[CREATOR_FEE_BASIS_POINTS_OFFSET..CREATOR_FEE_BASIS_POINTS_OFFSET + 8]
                .try_into()
                .unwrap(),
        );

        info!(
            fee_recipient = %bs58::encode(fee_recipient).into_string(),
            initial_virtual_sol = initial_virtual_sol_reserves,
            initial_virtual_tokens = initial_virtual_token_reserves,
            fee_bps = fee_basis_points,
            creator_fee_bps = creator_fee_basis_points,
            "Global account decoded",
        );

        Ok(Self {
            fee_recipient,
            initial_virtual_token_reserves,
            initial_virtual_sol_reserves,
            fee_basis_points,
            creator_fee_basis_points,
        })
    }
}
