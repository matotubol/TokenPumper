//! Buyback fee-recipient pool. Pump.fun's SDK picks one of these eight
//! addresses at random per dev-buy ix — the on-chain program rejects the
//! `buy` with `BuybackFeeRecipientMissing` (error 6062) if a recipient
//! outside the pool is supplied.
//!
//! Source: `docs/pump-sdk/src/bondingCurve.ts::CURRENT_FEE_RECIPIENTS_FOR_BUYBACK`.
//! If pump rotates the pool, regenerate via `scripts/decode_pubkeys.py`.

/// 8 valid buyback recipients, decoded once and inlined as raw bytes.
/// b58 strings preserved in comments for cross-reference.
pub const BUYBACK_FEE_RECIPIENTS: [[u8; 32]; 8] = [
    // [0] 5YxQFdt3Tr9zJLvkFccqXVUwhdTWJQc1fFg2YPbxvxeD
    [
        67, 158, 101, 16, 192, 61, 101, 250, 217, 49, 232, 157, 4, 190, 11, 183, 13, 81, 151, 31,
        81, 196, 21, 251, 52, 76, 7, 219, 65, 159, 33, 34,
    ],
    // [1] 9M4giFFMxmFGXtc3feFzRai56WbBqehoSeRE5GK7gf7
    [
        2, 35, 85, 22, 169, 23, 19, 76, 103, 88, 140, 73, 56, 32, 174, 21, 94, 233, 102, 101, 87,
        122, 193, 183, 24, 218, 71, 221, 207, 42, 5, 14,
    ],
    // [2] GXPFM2caqTtQYC2cJ5yJRi9VDkpsYZXzYdwYpGnLmtDL
    [
        230, 167, 226, 32, 104, 187, 136, 100, 10, 165, 127, 144, 147, 8, 198, 31, 239, 113, 26, 1,
        99, 245, 167, 85, 192, 112, 188, 134, 13, 31, 99, 103,
    ],
    // [3] 3BpXnfJaUTiwXnJNe7Ej1rcbzqTTQUvLShZaWazebsVR
    [
        32, 124, 236, 218, 91, 204, 108, 177, 234, 240, 241, 109, 104, 64, 69, 102, 177, 141, 86,
        210, 72, 26, 203, 49, 112, 50, 101, 110, 144, 85, 28, 120,
    ],
    // [4] 5cjcW9wExnJJiqgLjq7DEG75Pm6JBgE1hNv4B2vHXUW6
    [
        68, 150, 65, 248, 73, 88, 220, 115, 167, 106, 133, 216, 117, 111, 85, 192, 44, 218, 202,
        137, 186, 25, 50, 121, 12, 54, 138, 177, 87, 233, 45, 115,
    ],
    // [5] EHAAiTxcdDwQ3U4bU6YcMsQGaekdzLS3B5SmYo46kJtL
    [
        197, 75, 150, 181, 201, 49, 148, 30, 70, 234, 75, 226, 224, 227, 17, 39, 116, 79, 198, 183,
        76, 251, 69, 94, 254, 175, 139, 213, 113, 121, 44, 237,
    ],
    // [6] 5eHhjP8JaYkz83CWwvGU2uMUXefd3AazWGx4gpcuEEYD
    [
        68, 252, 31, 120, 249, 74, 51, 208, 144, 156, 94, 107, 95, 176, 33, 87, 10, 216, 219, 173,
        141, 232, 253, 179, 210, 14, 209, 205, 153, 235, 142, 78,
    ],
    // [7] A7hAgCzFw14fejgCp387JUJRMNyz4j89JKnhtKU8piqW
    [
        135, 112, 21, 126, 235, 235, 103, 138, 101, 93, 185, 155, 55, 246, 177, 50, 108, 118, 87,
        219, 144, 207, 184, 168, 122, 190, 248, 199, 182, 242, 200, 105,
    ],
];

/// Pick a recipient from the pool deterministically off the slot — gives
/// us spread across the 8 wallets without needing rng state, and keeps
/// the choice reproducible for any given fire slot (handy in logs).
#[inline]
pub fn pick_for_slot(slot: u64) -> &'static [u8; 32] {
    &BUYBACK_FEE_RECIPIENTS[(slot as usize) % BUYBACK_FEE_RECIPIENTS.len()]
}
