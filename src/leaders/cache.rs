//! Loader for the per-epoch leader-region cache file.
//!
//! Wire format is a slim JSON: a region table, a validator table, and a
//! flat per-slot byte array. `slots[i]` is the *region* index (not a
//! validator index) for absolute slot `epochStartSlot + i`. The hot path
//! never needs the validator metadata, so the slot table maps directly to
//! the byte that gates `FraWindow`.
//!
//! ## In-memory shape
//!
//! Three contiguous, heap-allocated arrays — no per-element `String` or
//! `Box` allocations, no `Vec` capacity overhead:
//!
//!  * `regions: Box<[Region]>` — ≤64 fixed-width 4-byte country codes.
//!    Whole table fits in a few cache lines.
//!  * `slot_codes: Box<[u8]>` — ~432 KB, one byte per slot. Sequential
//!    access is fully prefetched; one cache line covers 64 slots.
//!  * `validators: Box<[Validator]>` — ~130 KB, fixed 66-byte records.
//!    Cold-only — never touched on the shred path.

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

/// Sentinel for slot entries / validators with no resolved country. Always
/// outside the 64-bit allowed-mask, so unknown slots can never be marked
/// in-region.
pub const UNKNOWN_REGION_CODE: u8 = u8::MAX;

/// Hard ceiling on distinct regions. The hot-path filter compresses the
/// allowed-region set into a single `u64` mask, so codes must fit in
/// `0..64`. Mainnet has ~25–35 distinct validator-region strings today.
pub const MAX_REGIONS: usize = 64;

/// Max bytes in a region code. Today validators.app emits alpha-2 country
/// (`"DE"`, `"US"`); a future producer may switch to 3-char city tags
/// (`"FRA"`, `"AMS"`). 4 bytes covers both with a null-terminator slot.
pub const REGION_LEN: usize = 4;

/// Sentinel for validators with no resolved software client. Same `u8::MAX`
/// trick as the region sentinel so a single bound check rejects unknowns.
pub const UNKNOWN_SOFTWARE_CLIENT_IDX: u8 = u8::MAX;

/// Max distinct software clients we'll record. Realistically there are a
/// handful (Agave, Jito-Solana, Firedancer, Frankendancer, ...) — 32 is
/// well above the empirical ceiling and leaves `0xFF` reserved as the
/// "unknown" sentinel.
pub const MAX_SOFTWARE_CLIENTS: usize = 32;

/// Max bytes in a software-client display name. Long enough for things
/// like `"Frankendancer 0.1.0"` with room to spare.
pub const SOFTWARE_CLIENT_NAME_LEN: usize = 32;

/// Fixed-width region tag. Stored inline (no `String`) so the regions
/// table is one contiguous 4-byte-per-entry buffer that fits in L1.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Region {
    bytes: [u8; REGION_LEN],
}

impl Region {
    /// Pack a `&str` into a fixed-width region tag. Returns `None` if the
    /// input is empty or longer than `REGION_LEN`.
    pub fn from_str(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        if b.is_empty() || b.len() > REGION_LEN {
            return None;
        }
        let mut bytes = [0u8; REGION_LEN];
        bytes[..b.len()].copy_from_slice(b);
        Some(Self { bytes })
    }

    /// Borrow the tag as a `&str`. The buffer is always populated with
    /// ASCII (validators.app country codes), so the UTF-8 check is just
    /// for safety — it never fails on real data.
    pub fn as_str(&self) -> &str {
        let len = self
            .bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(REGION_LEN);
        std::str::from_utf8(&self.bytes[..len]).unwrap_or("")
    }
}

impl std::fmt::Debug for Region {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Fixed-width software-client name. Same shape as `Region`, just a
/// longer inline buffer. Stored as `Box<[SoftwareClient]>` in the loaded
/// map — ~10 entries × 32 bytes is trivial and fully cache-line-friendly.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct SoftwareClient {
    bytes: [u8; SOFTWARE_CLIENT_NAME_LEN],
}

impl SoftwareClient {
    /// Pack a `&str` into a fixed-width client name. Returns `None` if
    /// the input is empty or longer than `SOFTWARE_CLIENT_NAME_LEN`.
    pub fn from_str(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        if b.is_empty() || b.len() > SOFTWARE_CLIENT_NAME_LEN {
            return None;
        }
        let mut bytes = [0u8; SOFTWARE_CLIENT_NAME_LEN];
        bytes[..b.len()].copy_from_slice(b);
        Some(Self { bytes })
    }

    /// Borrow the inline buffer as a `&str`. Always ASCII in practice.
    pub fn as_str(&self) -> &str {
        let len = self
            .bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(SOFTWARE_CLIENT_NAME_LEN);
        std::str::from_utf8(&self.bytes[..len]).unwrap_or("")
    }
}

impl std::fmt::Debug for SoftwareClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Cold-path validator record. Stored as a contiguous `Box<[Validator]>`
/// — fixed 67 bytes per entry, no per-record allocation. The shred fast
/// path never reads this; it exists only for offline lookup ("which
/// validator was leader for slot X / how do I look up its votekey / what
/// client is it running").
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Validator {
    pub pubkey: [u8; 32],
    pub votekey: [u8; 32],
    /// Region index into `EpochLeaderMap::regions`, or `UNKNOWN_REGION_CODE`.
    pub region_idx: u8,
    /// Validators.app `is_dz` flag (delegation/zero-stake). 0 = false, 1 = true.
    pub is_dz: u8,
    /// Index into `EpochLeaderMap::software_clients`, or
    /// `UNKNOWN_SOFTWARE_CLIENT_IDX` if validators.app didn't report one.
    pub software_client_idx: u8,
}

/// Wire format. Field names are camelCase to match the JSON producer.
#[derive(Debug, Deserialize)]
struct EpochLeaderMapWire {
    epoch: u64,
    #[serde(rename = "epochStartSlot")]
    epoch_start_slot: u64,
    #[serde(rename = "epochEndSlot")]
    epoch_end_slot: u64,
    #[serde(rename = "slotsInEpoch")]
    slots_in_epoch: u64,
    /// Region table — at most `MAX_REGIONS` entries, each ≤ `REGION_LEN`.
    regions: Vec<String>,
    /// Software-client table — at most `MAX_SOFTWARE_CLIENTS` entries.
    /// Optional in the wire format so older cache files keep parsing.
    #[serde(default, rename = "softwareClients")]
    software_clients: Vec<String>,
    /// Validator table — deduplicated, indexed by validator (not slot).
    #[serde(default)]
    validators: Vec<ValidatorWire>,
    /// `slots[i]` = region code for absolute slot `epochStartSlot + i`,
    /// or `UNKNOWN_REGION_CODE` (255) for slots with no resolved leader.
    slots: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct ValidatorWire {
    pubkey: String,
    #[serde(default)]
    votekey: Option<String>,
    /// Region index into the file's `regions` table. `null` = unknown.
    #[serde(default)]
    region: Option<u8>,
    #[serde(default)]
    #[serde(rename = "isDz")]
    is_dz: Option<bool>,
    /// Software-client index into the file's `softwareClients` table.
    /// `null` = validators.app didn't report a client.
    #[serde(default)]
    #[serde(rename = "softwareClient")]
    software_client: Option<u8>,
}

/// Loaded map. Each array is `Box<[T]>` rather than `Vec<T>` — once
/// frozen we never grow them, so the capacity field is wasted.
#[derive(Debug)]
pub struct EpochLeaderMap {
    pub epoch: u64,
    pub epoch_start_slot: u64,
    pub epoch_end_slot: u64,
    pub slots_in_epoch: u64,
    pub regions: Box<[Region]>,
    pub software_clients: Box<[SoftwareClient]>,
    pub slot_codes: Box<[u8]>,
    pub validators: Box<[Validator]>,
}

impl EpochLeaderMap {
    /// Load from a `leaders-epoch-{N}.json` file produced by `fetch.rs`
    /// (or an external producer that matches the same shape).
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading leader cache {}", path.display()))?;
        let wire: EpochLeaderMapWire = serde_json::from_str(&raw)
            .with_context(|| format!("parsing leader cache {}", path.display()))?;
        Self::from_wire(wire, path)
    }

    fn from_wire(wire: EpochLeaderMapWire, path: &Path) -> Result<Self> {
        if wire.slots.len() as u64 != wire.slots_in_epoch {
            return Err(anyhow!(
                "leader cache {}: slots.len() = {} but slotsInEpoch = {}",
                path.display(),
                wire.slots.len(),
                wire.slots_in_epoch,
            ));
        }
        let span = wire.epoch_end_slot.saturating_sub(wire.epoch_start_slot) + 1;
        if span != wire.slots_in_epoch {
            return Err(anyhow!(
                "leader cache {}: epochEndSlot - epochStartSlot + 1 = {} but slotsInEpoch = {}",
                path.display(),
                span,
                wire.slots_in_epoch,
            ));
        }
        if wire.regions.len() > MAX_REGIONS {
            return Err(anyhow!(
                "leader cache {}: regions table has {} entries, max is {}",
                path.display(),
                wire.regions.len(),
                MAX_REGIONS,
            ));
        }
        if wire.software_clients.len() > MAX_SOFTWARE_CLIENTS {
            return Err(anyhow!(
                "leader cache {}: softwareClients table has {} entries, max is {}",
                path.display(),
                wire.software_clients.len(),
                MAX_SOFTWARE_CLIENTS,
            ));
        }

        let mut regions: Vec<Region> = Vec::with_capacity(wire.regions.len());
        for r in &wire.regions {
            let region = Region::from_str(r).ok_or_else(|| {
                anyhow!(
                    "leader cache {}: region {:?} is empty or longer than {} bytes",
                    path.display(),
                    r,
                    REGION_LEN,
                )
            })?;
            regions.push(region);
        }

        let mut software_clients: Vec<SoftwareClient> =
            Vec::with_capacity(wire.software_clients.len());
        for c in &wire.software_clients {
            let client = SoftwareClient::from_str(c).ok_or_else(|| {
                anyhow!(
                    "leader cache {}: software client {:?} is empty or longer than {} bytes",
                    path.display(),
                    c,
                    SOFTWARE_CLIENT_NAME_LEN,
                )
            })?;
            software_clients.push(client);
        }

        let mut validators: Vec<Validator> = Vec::with_capacity(wire.validators.len());
        for v in wire.validators {
            let pubkey = decode_pubkey(&v.pubkey).with_context(|| {
                format!("leader cache {}: bad validator pubkey", path.display())
            })?;
            let votekey = match v.votekey.as_deref() {
                Some(s) => decode_pubkey(s).with_context(|| {
                    format!("leader cache {}: bad validator votekey", path.display())
                })?,
                None => [0u8; 32],
            };
            let region_idx = v.region.unwrap_or(UNKNOWN_REGION_CODE);
            if region_idx != UNKNOWN_REGION_CODE && (region_idx as usize) >= regions.len() {
                return Err(anyhow!(
                    "leader cache {}: validator region index {} out of range (regions.len() = {})",
                    path.display(),
                    region_idx,
                    regions.len(),
                ));
            }
            let software_client_idx = v
                .software_client
                .unwrap_or(UNKNOWN_SOFTWARE_CLIENT_IDX);
            if software_client_idx != UNKNOWN_SOFTWARE_CLIENT_IDX
                && (software_client_idx as usize) >= software_clients.len()
            {
                return Err(anyhow!(
                    "leader cache {}: validator software-client index {} out of range \
                     (softwareClients.len() = {})",
                    path.display(),
                    software_client_idx,
                    software_clients.len(),
                ));
            }
            validators.push(Validator {
                pubkey,
                votekey,
                region_idx,
                is_dz: u8::from(v.is_dz.unwrap_or(false)),
                software_client_idx,
            });
        }

        for (i, &code) in wire.slots.iter().enumerate() {
            if code != UNKNOWN_REGION_CODE && (code as usize) >= regions.len() {
                return Err(anyhow!(
                    "leader cache {}: slots[{}] = {} but only {} regions in table",
                    path.display(),
                    i,
                    code,
                    regions.len(),
                ));
            }
        }

        Ok(Self {
            epoch: wire.epoch,
            epoch_start_slot: wire.epoch_start_slot,
            epoch_end_slot: wire.epoch_end_slot,
            slots_in_epoch: wire.slots_in_epoch,
            regions: regions.into_boxed_slice(),
            software_clients: software_clients.into_boxed_slice(),
            slot_codes: wire.slots.into_boxed_slice(),
            validators: validators.into_boxed_slice(),
        })
    }

    /// Resolve a list of region names to a 64-bit allowed-mask. Bit `c` of
    /// the result is set iff region code `c` matches one of `allowed`.
    /// Names not present in the cache are silently skipped; the caller is
    /// expected to validate that the resulting mask is non-zero.
    pub fn allowed_mask(&self, allowed: &[String]) -> u64 {
        let mut mask = 0u64;
        for name in allowed {
            let Some(needle) = Region::from_str(name) else {
                continue;
            };
            for (i, r) in self.regions.iter().enumerate() {
                if *r == needle {
                    mask |= 1u64 << i;
                    break;
                }
            }
        }
        mask
    }
}

/// Decode a base58 pubkey string into a 32-byte array. Used for both
/// `pubkey` and `votekey` fields of the validator table.
fn decode_pubkey(s: &str) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    let n = bs58::decode(s)
        .onto(&mut out[..])
        .with_context(|| format!("base58 decode {s:?}"))?;
    if n != 32 {
        return Err(anyhow!("expected 32 bytes, got {n}"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp(json: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("pumpbeast-leader-test-{nanos}.json"));
        std::fs::write(&p, json).unwrap();
        p
    }

    #[test]
    fn loads_minimal_map() {
        let path = write_temp(
            r#"{
                "epoch": 815,
                "epochStartSlot": 100,
                "epochEndSlot": 103,
                "slotsInEpoch": 4,
                "regions": ["DE", "US"],
                "validators": [],
                "slots": [0, 0, 1, 255]
            }"#,
        );
        let map = EpochLeaderMap::load_from_file(&path).unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(map.epoch, 815);
        assert_eq!(map.epoch_start_slot, 100);
        assert_eq!(map.slots_in_epoch, 4);
        assert_eq!(
            map.regions.iter().map(Region::as_str).collect::<Vec<_>>(),
            vec!["DE", "US"],
        );
        assert_eq!(&*map.slot_codes, &[0u8, 0, 1, UNKNOWN_REGION_CODE]);
    }

    #[test]
    fn loads_validators() {
        // 32-byte pubkeys encoded base58 — these are the system program
        // and a stake-program-ish key, just convenient real-shape values.
        let path = write_temp(
            r#"{
                "epoch": 1, "epochStartSlot": 0, "epochEndSlot": 1, "slotsInEpoch": 2,
                "regions": ["DE"],
                "validators": [
                    {"pubkey":"11111111111111111111111111111111","votekey":"Stake11111111111111111111111111111111111111","region":0,"isDz":true}
                ],
                "slots": [0, 0]
            }"#,
        );
        let map = EpochLeaderMap::load_from_file(&path).unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(map.validators.len(), 1);
        let v = &map.validators[0];
        assert_eq!(v.region_idx, 0);
        assert_eq!(v.is_dz, 1);
        assert_eq!(v.software_client_idx, UNKNOWN_SOFTWARE_CLIENT_IDX);
        assert_eq!(v.pubkey, [0u8; 32]); // system program is all-zeros
    }

    #[test]
    fn loads_software_clients() {
        let path = write_temp(
            r#"{
                "epoch": 1, "epochStartSlot": 0, "epochEndSlot": 1, "slotsInEpoch": 2,
                "regions": ["DE"],
                "softwareClients": ["Agave 2.0.4", "Firedancer 0.1.0"],
                "validators": [
                    {"pubkey":"11111111111111111111111111111111","region":0,"isDz":false,"softwareClient":1}
                ],
                "slots": [0, 0]
            }"#,
        );
        let map = EpochLeaderMap::load_from_file(&path).unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(map.software_clients.len(), 2);
        assert_eq!(map.software_clients[0].as_str(), "Agave 2.0.4");
        assert_eq!(map.software_clients[1].as_str(), "Firedancer 0.1.0");
        assert_eq!(map.validators[0].software_client_idx, 1);
    }

    #[test]
    fn rejects_out_of_range_software_client_idx() {
        let path = write_temp(
            r#"{
                "epoch": 1, "epochStartSlot": 0, "epochEndSlot": 1, "slotsInEpoch": 2,
                "regions": ["DE"],
                "softwareClients": ["Agave"],
                "validators": [
                    {"pubkey":"11111111111111111111111111111111","region":0,"softwareClient":7}
                ],
                "slots": [0, 0]
            }"#,
        );
        let err = EpochLeaderMap::load_from_file(&path).unwrap_err();
        std::fs::remove_file(&path).ok();
        let msg = format!("{err:#}");
        assert!(msg.contains("software-client index 7"), "{msg}");
    }

    #[test]
    fn allowed_mask_picks_known_regions() {
        let path = write_temp(
            r#"{
                "epoch": 1, "epochStartSlot": 0, "epochEndSlot": 2, "slotsInEpoch": 3,
                "regions": ["FRA", "AMS", "NYC"],
                "validators": [],
                "slots": [0, 1, 2]
            }"#,
        );
        let map = EpochLeaderMap::load_from_file(&path).unwrap();
        std::fs::remove_file(&path).ok();

        let mask = map.allowed_mask(&["FRA".into(), "AMS".into(), "DOES_NOT_EXIST".into()]);
        assert_eq!(mask, 0b011);
    }

    #[test]
    fn rejects_length_mismatch() {
        let path = write_temp(
            r#"{
                "epoch": 1, "epochStartSlot": 0, "epochEndSlot": 4, "slotsInEpoch": 5,
                "regions": ["DE"],
                "validators": [],
                "slots": [0, 0]
            }"#,
        );
        let err = EpochLeaderMap::load_from_file(&path).unwrap_err();
        std::fs::remove_file(&path).ok();
        let msg = format!("{err:#}");
        assert!(msg.contains("slots.len() = 2"), "{msg}");
    }

    #[test]
    fn rejects_out_of_range_slot_code() {
        let path = write_temp(
            r#"{
                "epoch": 1, "epochStartSlot": 0, "epochEndSlot": 1, "slotsInEpoch": 2,
                "regions": ["DE"],
                "validators": [],
                "slots": [0, 5]
            }"#,
        );
        let err = EpochLeaderMap::load_from_file(&path).unwrap_err();
        std::fs::remove_file(&path).ok();
        let msg = format!("{err:#}");
        assert!(msg.contains("slots[1] = 5"), "{msg}");
    }

    #[test]
    fn region_packs_and_unpacks() {
        let r = Region::from_str("DE").unwrap();
        assert_eq!(r.as_str(), "DE");
        let r = Region::from_str("FRA").unwrap();
        assert_eq!(r.as_str(), "FRA");
        assert!(Region::from_str("").is_none());
        assert!(Region::from_str("TOOLONG").is_none());
    }
}
