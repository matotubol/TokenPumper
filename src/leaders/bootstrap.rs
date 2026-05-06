//! Per-epoch leader cache wrapper. Loads (or fetches + writes, then loads)
//! the slim per-epoch JSON map and pre-resolves the focus country (from
//! Config) so the hot path is a single byte compare against `slot_codes`.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use tracing::info;

use super::cache::{EpochLeaderMap, Region};
use super::fetch;

pub struct LeaderCache {
    map: EpochLeaderMap,
    /// Region index for the focus country in `map.regions`, or `None` if
    /// no leaders for that country were scheduled this epoch.
    focus_region_idx: Option<u8>,
}

impl LeaderCache {
    /// Load the cache for the current epoch, fetching it from RPC +
    /// validators.app if the local file is missing.
    pub async fn bootstrap(
        rpc_url: &str,
        validators_app_token: Option<&str>,
        cache_dir: &Path,
        focus_country: &str,
    ) -> Result<Self> {
        let epoch_info = fetch::get_epoch_info(rpc_url)
            .await
            .context("getEpochInfo")?;
        info!(
            epoch = epoch_info.epoch,
            absolute_slot = epoch_info.absolute_slot,
            slots_in_epoch = epoch_info.slots_in_epoch,
            "current epoch"
        );

        let path = cache_path(cache_dir, epoch_info.epoch);
        if !path.exists() {
            let token = validators_app_token.ok_or_else(|| {
                anyhow!(
                    "leader cache {} missing and validators_app_token not set in config.toml",
                    path.display()
                )
            })?;
            fetch::build_and_write(rpc_url, token, &epoch_info, &path)
                .await
                .with_context(|| format!("building leader cache at {}", path.display()))?;
        }

        let map = EpochLeaderMap::load_from_file(&path)
            .with_context(|| format!("loading leader cache {}", path.display()))?;

        let focus_region_idx = resolve_region_idx(&map, focus_country);
        Ok(Self {
            map,
            focus_region_idx,
        })
    }

    pub fn epoch(&self) -> u64 {
        self.map.epoch
    }

    pub fn epoch_start_slot(&self) -> u64 {
        self.map.epoch_start_slot
    }

    pub fn epoch_end_slot(&self) -> u64 {
        self.map.epoch_end_slot
    }

    pub fn slots_in_epoch(&self) -> u64 {
        self.map.slots_in_epoch
    }

    pub fn map(&self) -> &EpochLeaderMap {
        &self.map
    }

    /// True iff `slot` falls in the cached epoch and its leader's country
    /// matches the configured focus.
    pub fn is_focus(&self, slot: u64) -> bool {
        let Some(idx) = self.focus_region_idx else {
            return false;
        };
        if slot < self.map.epoch_start_slot || slot > self.map.epoch_end_slot {
            return false;
        }
        let off = (slot - self.map.epoch_start_slot) as usize;
        self.map.slot_codes[off] == idx
    }

    /// Number of slots in the cached epoch whose leader is in the focus country.
    pub fn focus_slot_count(&self) -> usize {
        let Some(idx) = self.focus_region_idx else {
            return 0;
        };
        self.map.slot_codes.iter().filter(|&&c| c == idx).count()
    }
}

fn cache_path(cache_dir: &Path, epoch: u64) -> PathBuf {
    cache_dir.join(format!("leaders-epoch-{epoch}.json"))
}

fn resolve_region_idx(map: &EpochLeaderMap, country: &str) -> Option<u8> {
    let needle = Region::from_str(country)?;
    map.regions
        .iter()
        .position(|r| *r == needle)
        .map(|i| i as u8)
}
