//! Hot-path region filter — single-`u64` sliding bitset over a per-epoch
//! presence bitmap.
//!
//! ## Memory shape
//!
//!  * `presence: Arc<[u64]>` — one bit per slot in the epoch. Bit `i` is
//!    set iff `slot_codes[i]`'s region is in the configured allowed set.
//!    ~54 KiB for a mainnet epoch (432_000 / 8 bytes). Lives in L2 and is
//!    only touched on window slides.
//!  * `FraWindow { base, mask, .. }` — the only state the per-shred fast
//!    path reads. Sized so the compiler keeps `base` and `mask` in
//!    registers across `contains()` calls.
//!
//! ## Hot path
//!
//! `contains(slot)` is `sub + shr + cmp + setb + and + test` — six
//! instructions, no memory load past the struct's two u64 fields. The
//! branch is on the result, fully predictable when the watchlist is a
//! small fraction of all slots (the dominant case for region filtering).
//!
//! ## Cold path
//!
//! `slide_to(highest)` fires only when a new high-water slot is observed
//! (~2.5/sec at Solana cadence). Reads at most two words from `presence`
//! and stores one new `mask`. The caller decides when to invoke it; the
//! method itself short-circuits if the window already covers `highest`.

use std::sync::Arc;

use super::cache::{EpochLeaderMap, MAX_REGIONS};

/// Half-window size used by `slide_to` — when a new high-water slot lands,
/// the window is repositioned so the slot sits at offset `HALF_WINDOW`
/// inside the 64-bit mask. That leaves room for both slightly-older
/// stragglers (offsets 0..HALF_WINDOW) and slightly-newer slots that may
/// arrive in the same batch (offsets HALF_WINDOW+1..63) before the next
/// slide.
const HALF_WINDOW: u64 = 31;

/// Build the per-epoch presence bitmap. Bit `i` is set iff
/// `map.slot_codes[i]` is one of the codes whose bit is set in
/// `allowed_mask`. Output size = `ceil(slots_in_epoch / 64)` `u64`s
/// (~6_750 for mainnet).
pub fn build_presence_bitmap(map: &EpochLeaderMap, allowed_mask: u64) -> Vec<u64> {
    let n = map.slot_codes.len();
    let mut bits = vec![0u64; n.div_ceil(64)];
    for (i, &code) in map.slot_codes.iter().enumerate() {
        // UNKNOWN_REGION_CODE = 0xFF is well outside MAX_REGIONS, so the
        // bound check below also rejects unknown slots in one comparison.
        if (code as usize) < MAX_REGIONS {
            let hit = (allowed_mask >> (code as u64)) & 1;
            bits[i >> 6] |= hit << (i & 63);
        }
    }
    bits
}

/// 64-slot sliding view over `presence`. The struct fits in 5×8 bytes; the
/// hot fields (`base`, `mask`) sit at the front so a `&FraWindow` keeps
/// them registered across inlined `contains()` call sites.
#[repr(C)]
pub struct FraWindow {
    /// Earliest absolute slot covered by `mask`. Slot `(base + i)` is
    /// represented by bit `i` for `i in 0..64`.
    base: u64,
    /// Per-slot presence bits relative to `base`. Bit `i` set ⇔ slot
    /// `(base + i)` has a leader in the configured region set.
    mask: u64,
    epoch_start_slot: u64,
    epoch_end_slot: u64,
    presence: Arc<[u64]>,
}

impl FraWindow {
    /// Construct a window over `presence`, positioned at the epoch start
    /// with the mask pre-loaded from bitmap offset 0. The first
    /// `contains()` call therefore returns a meaningful answer without
    /// requiring the caller to slide first.
    pub fn new(presence: Arc<[u64]>, epoch_start_slot: u64, epoch_end_slot: u64) -> Self {
        debug_assert!(epoch_end_slot >= epoch_start_slot);
        let mask = read_u64_at_bit_offset(&presence, 0);
        Self {
            base: epoch_start_slot,
            mask,
            epoch_start_slot,
            epoch_end_slot,
            presence,
        }
    }

    /// Convenience: build directly from a loaded leader map + allowed
    /// region names. Bundles `build_presence_bitmap` + `new` so the caller
    /// doesn't have to thread the intermediate `Vec<u64>` itself.
    pub fn from_map(map: &EpochLeaderMap, allowed: &[String]) -> Self {
        let mask = map.allowed_mask(allowed);
        let presence: Arc<[u64]> = build_presence_bitmap(map, mask).into();
        Self::new(presence, map.epoch_start_slot, map.epoch_end_slot)
    }

    /// Hot-path test: does the window currently mark `slot` as in-region?
    ///
    /// No memory access beyond the two `u64` fields of `self` (which the
    /// compiler keeps in registers). Returns `false` for any slot outside
    /// the current 64-slot window — the caller is responsible for sliding
    /// the window forward as new high-water slots are observed.
    #[inline(always)]
    pub fn contains(&self, slot: u64) -> bool {
        let off = slot.wrapping_sub(self.base);
        // wrapping_shr masks the shift amount mod 64, so `off >= 64`
        // produces a defined-but-meaningless bit — the in_range AND below
        // zeroes it out. No data-dependent branch.
        let bit = self.mask.wrapping_shr(off as u32) & 1;
        let in_range = (off < 64) as u64;
        (bit & in_range) != 0
    }

    /// Reposition the window so that `highest` sits near the right edge.
    /// No-op when the window already covers `highest`. Cold path —
    /// expected to fire ~once per Solana slot tick (~2.5/sec).
    #[cold]
    pub fn slide_to(&mut self, highest: u64) {
        let cur_edge = self.base.wrapping_add(63);
        if highest <= cur_edge && highest >= self.base {
            return;
        }
        if highest < self.epoch_start_slot || highest > self.epoch_end_slot {
            // Slot outside the cached epoch — caller must rotate to a new
            // presence bitmap. Until then, refuse to match anything.
            self.mask = 0;
            self.base = highest.saturating_sub(HALF_WINDOW);
            return;
        }
        let new_base = highest
            .saturating_sub(HALF_WINDOW)
            .max(self.epoch_start_slot);
        let bit_off = new_base.wrapping_sub(self.epoch_start_slot);
        self.mask = read_u64_at_bit_offset(&self.presence, bit_off);
        self.base = new_base;
    }

    pub fn base(&self) -> u64 {
        self.base
    }

    pub fn mask(&self) -> u64 {
        self.mask
    }
}

/// Read 64 contiguous bits from a `&[u64]` bit-stream at an arbitrary bit
/// offset. Out-of-range bits read as zero, so callers can safely query
/// near the end of the bitmap without bounds checks of their own.
#[inline]
fn read_u64_at_bit_offset(bits: &[u64], bit_off: u64) -> u64 {
    let word = (bit_off >> 6) as usize;
    let shift = (bit_off & 63) as u32;
    let lo = bits.get(word).copied().unwrap_or(0).wrapping_shr(shift);
    if shift == 0 {
        lo
    } else {
        let hi = bits
            .get(word + 1)
            .copied()
            .unwrap_or(0)
            .wrapping_shl(64 - shift);
        lo | hi
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leaders::cache::EpochLeaderMap;

    fn map_from_codes(epoch_start: u64, codes: Vec<u8>, regions: Vec<&str>) -> EpochLeaderMap {
        use crate::leaders::cache::Region;
        let n = codes.len() as u64;
        let regions: Vec<Region> = regions
            .into_iter()
            .map(|r| Region::from_str(r).unwrap())
            .collect();
        EpochLeaderMap {
            epoch: 1,
            epoch_start_slot: epoch_start,
            epoch_end_slot: epoch_start + n - 1,
            slots_in_epoch: n,
            regions: regions.into_boxed_slice(),
            software_clients: Box::new([]),
            slot_codes: codes.into_boxed_slice(),
            validators: Box::new([]),
        }
    }

    #[test]
    fn presence_bitmap_marks_only_allowed_codes() {
        // 4 slots: codes [0, 1, 0, 2]. Allowed = code 0 only.
        let map = map_from_codes(0, vec![0, 1, 0, 2], vec!["FRA", "AMS", "NYC"]);
        let mask = map.allowed_mask(&["FRA".into()]);
        let bits = build_presence_bitmap(&map, mask);
        // bit 0 set, bit 1 clear, bit 2 set, bit 3 clear → 0b0101 = 5
        assert_eq!(bits[0], 0b0101);
    }

    #[test]
    fn unknown_codes_never_match() {
        let map = map_from_codes(0, vec![super::super::cache::UNKNOWN_REGION_CODE; 4], vec![]);
        let bits = build_presence_bitmap(&map, !0u64); // every code allowed
        assert_eq!(bits[0], 0);
    }

    #[test]
    fn window_contains_after_slide() {
        // slots [100..164]. Mark slots 100, 105, 130 as in-region.
        let mut codes = vec![1u8; 64]; // code 1 = "OUT"
        codes[0] = 0;
        codes[5] = 0;
        codes[30] = 0;
        let map = map_from_codes(100, codes, vec!["FRA", "OUT"]);
        let mut w = FraWindow::from_map(&map, &["FRA".into()]);

        w.slide_to(105);
        // After slide: window centered around 105, base = 105 - 31 = 100.
        assert_eq!(w.base(), 100);
        assert!(w.contains(100));
        assert!(w.contains(105));
        assert!(w.contains(130));
        assert!(!w.contains(101));
        assert!(!w.contains(99)); // before base
        assert!(!w.contains(164)); // outside window
    }

    #[test]
    fn window_clamps_to_epoch_end() {
        // 100 slots, all in-region. base never exceeds epoch_end - 63.
        let map = map_from_codes(0, vec![0; 100], vec!["FRA"]);
        let mut w = FraWindow::from_map(&map, &["FRA".into()]);
        w.slide_to(95);
        // 95 is past the epoch_end (99), but actually within [0..99].
        // saturating_sub(31) → 64, so window covers [64..127]. The bitmap
        // tail beyond slot 99 reads as zero from `read_u64_at_bit_offset`.
        assert!(w.contains(95));
        assert!(w.contains(99));
        assert!(!w.contains(100)); // beyond epoch end, presence reads 0
    }

    #[test]
    fn slide_outside_epoch_clears_mask() {
        let map = map_from_codes(1000, vec![0; 64], vec!["FRA"]);
        let mut w = FraWindow::from_map(&map, &["FRA".into()]);
        w.slide_to(2_000_000); // way past epoch_end
        assert_eq!(w.mask(), 0);
        assert!(!w.contains(2_000_000));
    }

    #[test]
    fn read_u64_at_bit_offset_handles_zero_shift() {
        let bits = vec![0xDEAD_BEEF_DEAD_BEEFu64, 0xCAFE_BABE_CAFE_BABEu64];
        assert_eq!(read_u64_at_bit_offset(&bits, 0), 0xDEAD_BEEF_DEAD_BEEF);
        assert_eq!(read_u64_at_bit_offset(&bits, 64), 0xCAFE_BABE_CAFE_BABE);
    }

    #[test]
    fn read_u64_at_bit_offset_spans_two_words() {
        // word0 = ...high 8 bits = 0xAB, word1 = low 8 bits = 0xCD.
        let bits = vec![0xAB00_0000_0000_0000u64, 0x0000_0000_0000_00CDu64];
        // bit_off = 56 → shift = 56. lo = word0 >> 56 = 0xAB.
        // hi = word1 << 8 = 0xCD00. result = 0xCD00 | 0xAB = 0xCDAB.
        assert_eq!(read_u64_at_bit_offset(&bits, 56), 0xCDAB);
    }

    #[test]
    fn read_u64_at_bit_offset_past_end_returns_zero() {
        let bits = vec![0xFFFF_FFFF_FFFF_FFFFu64];
        // bit_off way past end → both words are out-of-range → 0.
        assert_eq!(read_u64_at_bit_offset(&bits, 1_000), 0);
    }
}
