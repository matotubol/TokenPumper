//! Zero-copy shred header parsing.
//!
//! Every function takes a raw packet `&[u8]` and extracts fields at fixed
//! byte offsets. Offsets cross-checked against agave
//! `ledger/src/shred.rs:845-861` (OFFSET_OF_*) and
//! `ledger/src/shred.rs:634-664` (ShredVariant encoding).
//!
//! Only the data-shred path is parsed — coding shreds are dropped at the
//! variant check by `is_data_variant`. PumpBeast does not do FEC recovery,
//! so missing data shreds simply forfeit a segment.
//!
//! Data-shred wire layout (all little-endian):
//!   [0..64]   signature                     (64 bytes)
//!   [64]      variant byte                  (1 byte: type nibble | proof_size nibble)
//!   [65..73]  slot                          (u64)
//!   [73..77]  index                         (u32)
//!   [77..79]  version                       (u16, unused)
//!   [79..83]  fec_set_index                 (u32)
//!   [83..85]  parent_offset                 (u16, unused)
//!   [85]      flags                         (u8)
//!   [86..88]  size                          (u16 = total bytes of common+data header+payload)

// ── Wire constants ──────────────────────────────────────────────────────────

pub const SIZE_OF_SIGNATURE: usize = 64;
pub const SIZE_OF_DATA_SHRED_HEADERS: usize = 88;

pub const SIZE_OF_MERKLE_ROOT: usize = 32;
pub const SIZE_OF_MERKLE_PROOF_ENTRY: usize = 20;

pub const SHRED_DATA_PAYLOAD_SIZE: usize = 1203;

pub const DATA_COMPLETE_SHRED: u8 = 0b0100_0000;
pub const LAST_SHRED_IN_SLOT: u8 = 0b1100_0000;

pub const MAX_DATA_SHREDS_PER_SLOT: u32 = 32_768;
pub const DATA_SHREDS_PER_FEC_BLOCK: u32 = 32;

// ── Shred variant decoding ──────────────────────────────────────────────────

/// Pre-decoded `(class, proof-derived capacity)` for one variant byte.
/// Read once at the top of the recv hot path via `VARIANT_TABLE[byte]`,
/// replacing the old per-shred `parse_variant + is_data_variant + data_capacity`
/// chain with a single L1 load and a small `match`.
#[derive(Clone, Copy)]
pub enum VariantClass {
    /// Variant byte not recognized — drop without counting.
    Invalid,
    /// Coding shred (MerkleCode family). Bumped into `coding_shreds_seen`,
    /// otherwise ignored — we don't do FEC recovery.
    Coding,
    /// Data shred. `capacity` already incorporates the proof-size and
    /// resigned-byte costs, so callers feed it straight into
    /// `get_data_with_capacity` without recomputing.
    Data {
        proof_size: u8,
        resigned: bool,
        capacity: u16,
    },
}

/// 256-entry classification table indexed by the variant byte. Built once
/// at compile time so the recv path pays one cache-line load per shred
/// instead of branching through the variant nibble decode.
pub const VARIANT_TABLE: [VariantClass; 256] = build_variant_table();

const fn build_variant_table() -> [VariantClass; 256] {
    let mut t = [VariantClass::Invalid; 256];
    let mut b: u32 = 0;
    while b < 256 {
        t[b as usize] = classify_variant(b as u8);
        b += 1;
    }
    t
}

/// Const equivalent of the old `parse_variant` match. Maps each variant
/// byte to `Coding`, `Data { … }`, or `Invalid`.
///
///   0x60 / 0x70 → MerkleCode (resigned at 0x70)
///   0x90 / 0xB0 → MerkleData chained (resigned at 0xB0)
const fn classify_variant(byte: u8) -> VariantClass {
    let proof_size = byte & 0x0F;
    match byte & 0xF0 {
        0x60 | 0x70 => VariantClass::Coding,
        0x90 => match data_capacity_const(proof_size, false) {
            Some(c) => VariantClass::Data {
                proof_size,
                resigned: false,
                capacity: c as u16,
            },
            None => VariantClass::Invalid,
        },
        0xB0 => match data_capacity_const(proof_size, true) {
            Some(c) => VariantClass::Data {
                proof_size,
                resigned: true,
                capacity: c as u16,
            },
            None => VariantClass::Invalid,
        },
        _ => VariantClass::Invalid,
    }
}

// ── Common header fields ────────────────────────────────────────────────────

#[inline(always)]
pub fn get_slot(buf: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(buf.get(65..73)?.try_into().ok()?))
}

#[inline(always)]
pub fn get_index(buf: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(buf.get(73..77)?.try_into().ok()?))
}

#[inline(always)]
pub fn get_fec_set_index(buf: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(buf.get(79..83)?.try_into().ok()?))
}

// ── Data shred fields ───────────────────────────────────────────────────────

#[inline(always)]
pub fn get_flags(buf: &[u8]) -> Option<u8> {
    buf.get(85).copied()
}

#[inline(always)]
pub fn get_data_size(buf: &[u8]) -> Option<u16> {
    Some(u16::from_le_bytes(buf.get(86..88)?.try_into().ok()?))
}

/// Extract the entry-data payload (`buf[88..size]`) given a pre-computed
/// capacity (typically from `VARIANT_TABLE`).
///
/// `capacity` bounds `size` so we never read merkle-proof bytes as entry
/// data. Matches agave `merkle::ShredData::get_data`
/// (`shred/merkle.rs:163-179`).
#[inline]
pub fn get_data_with_capacity(buf: &[u8], capacity: usize) -> Option<&[u8]> {
    let size = get_data_size(buf)? as usize;
    if size < SIZE_OF_DATA_SHRED_HEADERS
        || size > SIZE_OF_DATA_SHRED_HEADERS + capacity
        || size > buf.len()
    {
        return None;
    }
    buf.get(SIZE_OF_DATA_SHRED_HEADERS..size)
}

#[inline(always)]
pub fn is_data_complete(flags: u8) -> bool {
    flags & DATA_COMPLETE_SHRED != 0
}

#[inline(always)]
pub fn is_last_in_slot(flags: u8) -> bool {
    flags & LAST_SHRED_IN_SLOT == LAST_SHRED_IN_SLOT
}

// ── Capacity math ───────────────────────────────────────────────────────────

/// Usable entry-data capacity inside a data shred (after headers, merkle
/// root, merkle proof, and optional retransmit signature). Const variant
/// driven by `build_variant_table` at compile time.
const fn data_capacity_const(proof_size: u8, resigned: bool) -> Option<usize> {
    let used = SIZE_OF_DATA_SHRED_HEADERS
        + SIZE_OF_MERKLE_ROOT
        + (proof_size as usize) * SIZE_OF_MERKLE_PROOF_ENTRY
        + if resigned { SIZE_OF_SIGNATURE } else { 0 };
    if used > SHRED_DATA_PAYLOAD_SIZE {
        None
    } else {
        Some(SHRED_DATA_PAYLOAD_SIZE - used)
    }
}
