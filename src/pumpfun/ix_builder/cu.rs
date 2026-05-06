//! Compute Budget program — pre-decoded program ID and instruction tags
//! for direct byte writes. Single-byte instruction tags, no Anchor
//! discriminator. Source: solana-compute-budget-interface.

/// `ComputeBudget111111111111111111111111111111` decoded once offline.
pub const COMPUTE_BUDGET_PROGRAM_ID: [u8; 32] = [
    3, 6, 70, 111, 229, 33, 23, 50, 255, 236, 173, 186, 114, 195, 155, 231, 188, 140, 229, 187,
    197, 247, 18, 107, 44, 67, 155, 58, 64, 0, 0, 0,
];

pub const CB_SET_COMPUTE_UNIT_LIMIT: u8 = 0x02;
pub const CB_SET_COMPUTE_UNIT_PRICE: u8 = 0x03;

/// Wire size of a `SetComputeUnitLimit` data section: 1 tag byte + u32 LE.
pub const CU_LIMIT_DATA_LEN: u8 = 5;
/// Wire size of a `SetComputeUnitPrice` data section: 1 tag byte + u64 LE.
pub const CU_PRICE_DATA_LEN: u8 = 9;
