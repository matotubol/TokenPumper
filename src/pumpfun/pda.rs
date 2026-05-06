//! Program-derived-address arithmetic for the launch tx.
//!
//! `find_program_address` follows Solana's exact algorithm: SHA-256 over
//! `seeds || [bump] || program_id || "ProgramDerivedAddress"`, walking
//! `bump` from 255 downward, returning the first hash that does NOT
//! decompress to a valid Ed25519 point. The on-curve check is delegated
//! to `ed25519_dalek::VerifyingKey::from_bytes` — that call's only
//! validation is the same `CompressedEdwardsY::decompress` Solana uses,
//! so the bumps match the on-chain runtime byte for byte.
//!
//! For PDAs that don't depend on per-launch inputs (mint_authority,
//! global, event_authority, …) we use the bytes hardcoded in
//! `ix_builder::ix` — the unit tests at the bottom verify those constants
//! match what this module computes. For per-launch inputs we derive at
//! launch-pick time via `LaunchPdas::derive`; that's ~70 µs of CPU
//! per launch (7 find_program_address calls × ~10 µs), well off the
//! hot fire path.

use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use super::ix_builder::ix::{MAYHEM_PROGRAM_ID, PUMP_PROGRAM_ID, SOL_VAULT_PDA, TOKEN_2022_PROGRAM_ID, ATA_PROGRAM_ID};

const PDA_MARKER: &[u8] = b"ProgramDerivedAddress";
const MAX_SEED_LEN: usize = 32;

/// Solana `find_program_address`. Returns `(address, bump)`. Panics only
/// if every bump 255..=0 lands on the curve, which is statistically
/// impossible (~2⁻²⁵⁶ per attempt).
pub fn find_program_address(seeds: &[&[u8]], program_id: &[u8; 32]) -> ([u8; 32], u8) {
    for bump in (0u8..=255).rev() {
        if let Some(addr) = create_program_address(seeds, &[bump], program_id) {
            return (addr, bump);
        }
    }
    panic!("find_program_address exhausted bump space");
}

fn create_program_address(
    seeds: &[&[u8]],
    bump: &[u8],
    program_id: &[u8; 32],
) -> Option<[u8; 32]> {
    let mut hasher = Sha256::new();
    for seed in seeds {
        if seed.len() > MAX_SEED_LEN {
            return None;
        }
        hasher.update(seed);
    }
    hasher.update(bump);
    hasher.update(program_id);
    hasher.update(PDA_MARKER);
    let hash: [u8; 32] = hasher.finalize().into();

    // PDAs are defined as points OFF the Ed25519 curve. If the hash
    // decompresses successfully it's on-curve → reject this bump.
    if VerifyingKey::from_bytes(&hash).is_ok() {
        None
    } else {
        Some(hash)
    }
}

/// SPL Associated Token Address. Same algorithm as the SPL ATA program
/// uses internally — `find_program_address([wallet, token_program, mint])`
/// under the ATA program ID. For TOKEN_2022 mints, `token_program`
/// should be `TOKEN_2022_PROGRAM_ID`.
pub fn associated_token_address(
    wallet: &[u8; 32],
    mint: &[u8; 32],
    token_program: &[u8; 32],
) -> [u8; 32] {
    find_program_address(&[wallet, token_program, mint], &ATA_PROGRAM_ID).0
}

// ── Per-launch PDA bundle ────────────────────────────────────────────────

/// All non-constant accounts the launch tx needs that aren't already
/// hardcoded program IDs / fixed PDAs. Computed once per launch right
/// after a token is picked from `tokens.json`; the hot fire path just
/// reads these out of an already-built message buffer.
#[derive(Debug, Clone, Copy)]
pub struct LaunchPdas {
    pub bonding_curve: [u8; 32],
    pub associated_bonding_curve: [u8; 32],
    pub mayhem_state: [u8; 32],
    pub mayhem_token_vault: [u8; 32],
    pub associated_user: [u8; 32],
    pub creator_vault: [u8; 32],
    pub user_volume_accumulator: [u8; 32],
    /// `pumpPda(["bonding-curve-v2", mint])` — SDK appends this as the
    /// first remaining account on `buy`; pump rejects the ix with
    /// `BuybackFeeRecipientMissing` (6062) without it.
    pub bonding_curve_v2: [u8; 32],
}

impl LaunchPdas {
    /// Derives every per-launch PDA / ATA. `mint` is the token's pubkey
    /// (= public side of the keypair stored in tokens.json); `user` is
    /// the funder = creator (loaded from `keys/funder/key.json`).
    pub fn derive(mint: &[u8; 32], user: &[u8; 32]) -> Self {
        let bonding_curve = find_program_address(
            &[b"bonding-curve", mint],
            &PUMP_PROGRAM_ID,
        ).0;
        Self {
            bonding_curve,
            associated_bonding_curve: associated_token_address(
                &bonding_curve,
                mint,
                &TOKEN_2022_PROGRAM_ID,
            ),
            mayhem_state: find_program_address(
                &[b"mayhem-state", mint],
                &MAYHEM_PROGRAM_ID,
            ).0,
            mayhem_token_vault: associated_token_address(
                &SOL_VAULT_PDA,
                mint,
                &TOKEN_2022_PROGRAM_ID,
            ),
            associated_user: associated_token_address(
                user,
                mint,
                &TOKEN_2022_PROGRAM_ID,
            ),
            creator_vault: find_program_address(
                &[b"creator-vault", user],
                &PUMP_PROGRAM_ID,
            ).0,
            user_volume_accumulator: find_program_address(
                &[b"user_volume_accumulator", user],
                &PUMP_PROGRAM_ID,
            ).0,
            bonding_curve_v2: find_program_address(
                &[b"bonding-curve-v2", mint],
                &PUMP_PROGRAM_ID,
            ).0,
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────
//
// Cross-check our SHA-256 + on-curve loop against the bytes the Python
// `solders` library produced offline (those bytes live in
// `ix_builder::ix` as constants). If either implementation drifts these
// tests fail loudly.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pumpfun::ix_builder::ix::{
        EVENT_AUTHORITY_PDA, FEE_CONFIG_PDA, GLOBAL_PARAMS_PDA, GLOBAL_PDA,
        GLOBAL_VOLUME_ACCUMULATOR_PDA, MINT_AUTHORITY_PDA, PUMP_FEE_PROGRAM_ID, SOL_VAULT_PDA,
    };

    #[test]
    fn fixed_pdas_match_python_decoded_constants() {
        assert_eq!(
            find_program_address(&[b"mint-authority"], &PUMP_PROGRAM_ID).0,
            MINT_AUTHORITY_PDA,
        );
        assert_eq!(
            find_program_address(&[b"global"], &PUMP_PROGRAM_ID).0,
            GLOBAL_PDA,
        );
        assert_eq!(
            find_program_address(&[b"__event_authority"], &PUMP_PROGRAM_ID).0,
            EVENT_AUTHORITY_PDA,
        );
        assert_eq!(
            find_program_address(&[b"global-params"], &MAYHEM_PROGRAM_ID).0,
            GLOBAL_PARAMS_PDA,
        );
        assert_eq!(
            find_program_address(&[b"sol-vault"], &MAYHEM_PROGRAM_ID).0,
            SOL_VAULT_PDA,
        );
        assert_eq!(
            find_program_address(&[b"global_volume_accumulator"], &PUMP_PROGRAM_ID).0,
            GLOBAL_VOLUME_ACCUMULATOR_PDA,
        );
        assert_eq!(
            find_program_address(&[b"fee_config", &PUMP_PROGRAM_ID], &PUMP_FEE_PROGRAM_ID).0,
            FEE_CONFIG_PDA,
        );
    }
}
