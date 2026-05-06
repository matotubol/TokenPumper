//! Address Lookup Table (ALT) cache. Fetched once at startup, the
//! resolved indices live in `AltIndices` and the launch tx footer just
//! references them — runtime expands the indices to pubkeys, no extra
//! work on our hot path.

use anyhow::{anyhow, Context, Result};
use tracing::info;

use super::ix_builder::ix::{
    EVENT_AUTHORITY_PDA, FEE_CONFIG_PDA, GLOBAL_PARAMS_PDA, GLOBAL_PDA,
    GLOBAL_VOLUME_ACCUMULATOR_PDA, MAYHEM_PROGRAM_ID, MINT_AUTHORITY_PDA, PUMP_FEE_PROGRAM_ID,
    SOL_VAULT_PDA, TOKEN_2022_PROGRAM_ID,
};
use crate::rpc;

const LOOKUP_TABLE_META_SIZE: usize = 56;

#[derive(Debug, Clone, Copy)]
pub struct AltIndices {
    pub alt_pubkey: [u8; 32],
    // Writable-in-ALT.
    pub mayhem_program: u8,
    pub sol_vault: u8,
    // Readonly-in-ALT. Programs that any outer ix targets (system,
    // ata, compute_budget, pump) stay in static keys per the agave
    // sanitizer; only programs/PDAs we never invoke directly live here.
    pub mint_authority: u8,
    pub global: u8,
    pub token_2022_program: u8,
    pub global_params: u8,
    pub event_authority: u8,
    pub global_volume_accumulator: u8,
    pub fee_config: u8,
    pub pump_fee_program: u8,
}

impl AltIndices {
    pub fn bootstrap(rpc_url: &str, alt_b58: &str) -> Result<Self> {
        let alt_pubkey: [u8; 32] = bs58::decode(alt_b58)
            .into_vec()
            .with_context(|| format!("decoding ALT pubkey {}", alt_b58))?
            .try_into()
            .map_err(|_| anyhow!("ALT pubkey didn't decode to 32 bytes"))?;
        let data = rpc::account_data(rpc_url, alt_b58)
            .with_context(|| format!("fetching ALT {}", alt_b58))?;
        let body = data.get(LOOKUP_TABLE_META_SIZE..).ok_or_else(|| {
            anyhow!("ALT data {} bytes < {} header", data.len(), LOOKUP_TABLE_META_SIZE)
        })?;
        if body.len() % 32 != 0 {
            return Err(anyhow!("ALT body {} bytes not multiple of 32", body.len()));
        }
        let entries: Vec<[u8; 32]> = body
            .chunks_exact(32)
            .map(|c| c.try_into().unwrap())
            .collect();
        info!(alt = alt_b58, entries = entries.len(), "ALT loaded");

        let find = |want: &[u8; 32], label: &str| -> Result<u8> {
            entries
                .iter()
                .position(|e| e == want)
                .map(|i| i as u8)
                .ok_or_else(|| anyhow!("ALT missing {}", label))
        };

        Ok(Self {
            alt_pubkey,
            mayhem_program: find(&MAYHEM_PROGRAM_ID, "mayhem_program")?,
            sol_vault: find(&SOL_VAULT_PDA, "sol_vault")?,
            mint_authority: find(&MINT_AUTHORITY_PDA, "mint_authority")?,
            global: find(&GLOBAL_PDA, "global")?,
            token_2022_program: find(&TOKEN_2022_PROGRAM_ID, "token_2022_program")?,
            global_params: find(&GLOBAL_PARAMS_PDA, "global_params")?,
            event_authority: find(&EVENT_AUTHORITY_PDA, "event_authority")?,
            global_volume_accumulator: find(
                &GLOBAL_VOLUME_ACCUMULATOR_PDA,
                "global_volume_accumulator",
            )?,
            fee_config: find(&FEE_CONFIG_PDA, "fee_config")?,
            pump_fee_program: find(&PUMP_FEE_PROGRAM_ID, "pump_fee_program")?,
        })
    }
}
