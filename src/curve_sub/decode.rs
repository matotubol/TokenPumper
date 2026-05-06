//! Account-slice decoders. The single `accounts_data_slice` we send
//! is the union of two byte ranges — `[(8, 32), (64, 8)]` — so every
//! matched account update arrives as exactly 40 bytes regardless of
//! filter. The first 32 bytes are reserves (only meaningful for the
//! bonding-curve account) and the last 8 are the SPL-Token `amount`
//! field (only meaningful for ATA accounts).

use std::ops::Range;

/// `(offset, length)` pairs sent in `SubscribeRequestAccountsDataSlice`.
pub(super) const SLICES: &[(u64, u64)] = &[(8, 32), (64, 8)];
pub(super) const SLICE_TOTAL_LEN: usize = 40;

const RESERVES_RANGE: Range<usize> = 0..32;
const AMOUNT_RANGE: Range<usize> = 32..40;

#[derive(Debug, Default, Clone, Copy)]
pub(super) struct Reserves {
    pub v_tok: u64,
    pub v_sol: u64,
    pub r_tok: u64,
    pub r_sol: u64,
}

impl Reserves {
    pub(super) fn from_slice(slice: &[u8; SLICE_TOTAL_LEN]) -> Self {
        let b = &slice[RESERVES_RANGE];
        Self {
            v_tok: u64::from_le_bytes(b[0..8].try_into().unwrap()),
            v_sol: u64::from_le_bytes(b[8..16].try_into().unwrap()),
            r_tok: u64::from_le_bytes(b[16..24].try_into().unwrap()),
            r_sol: u64::from_le_bytes(b[24..32].try_into().unwrap()),
        }
    }
}

pub(super) fn token_amount(slice: &[u8; SLICE_TOTAL_LEN]) -> u64 {
    let b = &slice[AMOUNT_RANGE];
    u64::from_le_bytes(b.try_into().unwrap())
}
