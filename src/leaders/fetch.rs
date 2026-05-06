//! Per-epoch leader-region fetcher. Runs at startup if the cache file
//! for the current epoch is missing.
//!
//! Pulls `getEpochInfo`, `getLeaderSchedule`, `getVoteAccounts` from the
//! configured RPC plus a validator metadata roll from validators.app,
//! then stitches them into the slim three-array shape the loader
//! consumes:
//!
//!   { epoch, epochStartSlot, epochEndSlot, slotsInEpoch,
//!     regions: [...],     // ≤ MAX_REGIONS country codes
//!     validators: [...],  // deduplicated, indexed by validator
//!     slots: [...] }      // u8 region index per slot, UNKNOWN = 255
//!
//! Validator metadata is *not* duplicated per slot — `slots[i]` holds the
//! region code directly, which is the only thing the hot path needs.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, warn};

use super::cache::{MAX_REGIONS, MAX_SOFTWARE_CLIENTS, UNKNOWN_REGION_CODE};

/// Generous timeout — `getLeaderSchedule` on a fresh epoch is ~10–30 MB
/// of JSON over a single TCP connection, which on a public RPC can take
/// 30+ seconds even on a fast link.
const RPC_TIMEOUT: Duration = Duration::from_secs(60);

const VALIDATORS_APP_URL: &str =
    "https://www.validators.app/api/v1/validators/mainnet.json?limit=9999&active_only=false";

// ── Public API ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
pub struct EpochInfo {
    pub epoch: u64,
    #[serde(rename = "slotIndex")]
    pub slot_index: u64,
    #[serde(rename = "slotsInEpoch")]
    pub slots_in_epoch: u64,
    #[serde(rename = "absoluteSlot")]
    pub absolute_slot: u64,
}

/// One JSON-RPC `getEpochInfo` call. Used to find out which epoch we're
/// in (and therefore which cache file to look for / produce).
pub async fn get_epoch_info(rpc_url: &str) -> Result<EpochInfo> {
    let client = build_client()?;
    let body = json!({"jsonrpc":"2.0","id":1,"method":"getEpochInfo","params":[]});
    rpc_call(&client, rpc_url, body, "getEpochInfo").await
}

/// Fetch leader schedule + vote accounts + validators.app in parallel,
/// stitch them into the slim per-epoch table, and write the JSON cache
/// file at `out_path`.
pub async fn build_and_write(
    rpc_url: &str,
    validators_app_token: &str,
    epoch_info: &EpochInfo,
    out_path: &Path,
) -> Result<()> {
    info!(
        epoch = epoch_info.epoch,
        rpc_url,
        "fetching leader schedule + vote accounts + validators.app"
    );
    let client = build_client()?;
    let (schedule, vote, vapp) = tokio::try_join!(
        fetch_leader_schedule(&client, rpc_url),
        fetch_vote_accounts(&client, rpc_url),
        fetch_validators_app(&client, validators_app_token),
    )?;

    let mut metas: HashMap<String, ValidatorMeta> = HashMap::new();
    for v in vote.current.iter().chain(vote.delinquent.iter()) {
        metas
            .entry(v.node_pubkey.clone())
            .or_default()
            .vote_pubkey = Some(v.vote_pubkey.clone());
    }

    let vapp_list = match vapp {
        VAppResponse::Array(v) => v,
        VAppResponse::Wrapped { validators } => validators,
    };
    let mut with_country = 0usize;
    let mut with_client = 0usize;
    for v in vapp_list {
        let Some(account) = v.account else { continue };
        let entry = metas.entry(account).or_default();
        if let Some(dck) = v.data_center_key.as_deref() {
            if let Some(c) = parse_country(dck) {
                entry.country = Some(c);
                with_country += 1;
            }
        }
        entry.is_dz = v.is_dz;
        if let Some(name) = v.software_client.as_deref() {
            let trimmed = name.trim();
            if !trimmed.is_empty() {
                entry.software_client = Some(trimmed.to_string());
                with_client += 1;
            }
        }
    }
    info!(
        validators = metas.len(),
        with_country, with_client, "validator metadata merged"
    );

    let epoch_start_slot = epoch_info.absolute_slot - epoch_info.slot_index;
    let epoch_end_slot = epoch_start_slot + epoch_info.slots_in_epoch - 1;

    // ── Region table ──────────────────────────────────────────────────────
    // Walk the leader schedule and intern every distinct country we see
    // among scheduled validators. We don't include countries from
    // unscheduled validators — they'd just bloat the table.
    let mut region_idx: HashMap<String, u8> = HashMap::new();
    let mut regions: Vec<String> = Vec::new();
    for identity in schedule.keys() {
        let Some(meta) = metas.get(identity) else {
            continue;
        };
        let Some(country) = meta.country.as_deref() else {
            continue;
        };
        if region_idx.contains_key(country) {
            continue;
        }
        if regions.len() >= MAX_REGIONS {
            bail!(
                "more than {} distinct regions in leader schedule (saw {:?} as #{})",
                MAX_REGIONS,
                country,
                regions.len() + 1,
            );
        }
        let code = regions.len() as u8;
        region_idx.insert(country.to_string(), code);
        regions.push(country.to_string());
    }

    // ── Software-client table ──────────────────────────────────────────────
    // Same dedup pattern as regions — walk scheduled validators, intern
    // every distinct client string we see.
    let mut software_client_idx: HashMap<String, u8> = HashMap::new();
    let mut software_clients: Vec<String> = Vec::new();
    for identity in schedule.keys() {
        let Some(meta) = metas.get(identity) else {
            continue;
        };
        let Some(client) = meta.software_client.as_deref() else {
            continue;
        };
        if software_client_idx.contains_key(client) {
            continue;
        }
        if software_clients.len() >= MAX_SOFTWARE_CLIENTS {
            bail!(
                "more than {} distinct software clients in leader schedule \
                 (saw {:?} as #{})",
                MAX_SOFTWARE_CLIENTS,
                client,
                software_clients.len() + 1,
            );
        }
        let code = software_clients.len() as u8;
        software_client_idx.insert(client.to_string(), code);
        software_clients.push(client.to_string());
    }

    // ── Validator table ────────────────────────────────────────────────────
    // Deduplicated by identity (the leader-schedule key). Order is the
    // schedule's hash iteration order — stable enough for cache files,
    // and the loader doesn't care which slot a validator sits in.
    let mut validators_out: Vec<ValidatorOut> = Vec::with_capacity(schedule.len());
    let mut unmapped = 0usize;
    for identity in schedule.keys() {
        let meta = metas.get(identity);
        if meta.is_none() {
            unmapped += 1;
        }
        let region = meta
            .and_then(|m| m.country.as_deref())
            .and_then(|c| region_idx.get(c).copied());
        let votekey = meta.and_then(|m| m.vote_pubkey.clone());
        let is_dz = meta.and_then(|m| m.is_dz).unwrap_or(false);
        let software_client = meta
            .and_then(|m| m.software_client.as_deref())
            .and_then(|c| software_client_idx.get(c).copied());
        validators_out.push(ValidatorOut {
            pubkey: identity.clone(),
            votekey,
            region,
            is_dz,
            software_client,
        });
    }

    // ── Slot table ─────────────────────────────────────────────────────────
    // One u8 per slot — the region code directly. UNKNOWN_REGION_CODE
    // (255) for slots whose leader had no resolved country.
    let mut slots: Vec<u8> = vec![UNKNOWN_REGION_CODE; epoch_info.slots_in_epoch as usize];
    for (identity, slot_indices) in &schedule {
        let region_code = metas
            .get(identity)
            .and_then(|m| m.country.as_deref())
            .and_then(|c| region_idx.get(c).copied())
            .unwrap_or(UNKNOWN_REGION_CODE);
        for &idx in slot_indices {
            let i = idx as usize;
            if i < slots.len() {
                slots[i] = region_code;
            }
        }
    }
    let unfilled = slots
        .iter()
        .filter(|&&c| c == UNKNOWN_REGION_CODE)
        .count();
    if unfilled > 0 {
        warn!(
            unfilled,
            "leader schedule had gaps or validators with unresolved country — \
             those slots will load as UNKNOWN region"
        );
    }
    info!(
        slots = slots.len(),
        regions = regions.len(),
        software_clients = software_clients.len(),
        validators = validators_out.len(),
        unfilled,
        identities_unmapped_from_vapp = unmapped,
        "slot map built"
    );

    let file = EpochLeaderMapFile {
        epoch: epoch_info.epoch,
        epoch_start_slot,
        epoch_end_slot,
        slots_in_epoch: epoch_info.slots_in_epoch,
        fetched_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        regions,
        software_clients,
        validators: validators_out,
        slots,
    };

    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating cache dir {}", parent.display()))?;
    }
    let serialized = serde_json::to_vec(&file).context("serializing leader cache JSON")?;
    let bytes = serialized.len();
    std::fs::write(out_path, serialized)
        .with_context(|| format!("writing leader cache {}", out_path.display()))?;
    info!(path = %out_path.display(), bytes, "wrote leader cache");
    Ok(())
}

// ── RPC plumbing ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct RpcEnvelope<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

async fn rpc_call<T: for<'de> Deserialize<'de>>(
    client: &reqwest::Client,
    rpc_url: &str,
    body: serde_json::Value,
    method: &'static str,
) -> Result<T> {
    let resp: RpcEnvelope<T> = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST {rpc_url} ({method})"))?
        .error_for_status()
        .with_context(|| format!("RPC {method} returned non-2xx"))?
        .json()
        .await
        .with_context(|| format!("parsing JSON-RPC response for {method}"))?;
    if let Some(err) = resp.error {
        bail!("RPC {method} error {}: {}", err.code, err.message);
    }
    resp.result
        .ok_or_else(|| anyhow!("RPC {method} response missing both result and error"))
}

fn build_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(RPC_TIMEOUT)
        .build()
        .context("building reqwest client for leader-cache fetch")
}

// ── Leader schedule ────────────────────────────────────────────────────────

async fn fetch_leader_schedule(
    client: &reqwest::Client,
    rpc_url: &str,
) -> Result<HashMap<String, Vec<u32>>> {
    let body = json!({"jsonrpc":"2.0","id":1,"method":"getLeaderSchedule","params":[]});
    let map: Option<HashMap<String, Vec<u32>>> =
        rpc_call(client, rpc_url, body, "getLeaderSchedule").await?;
    map.ok_or_else(|| anyhow!("getLeaderSchedule returned null (epoch boundary?)"))
}

// ── Vote accounts ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct VoteAccountsResult {
    current: Vec<VoteAccount>,
    delinquent: Vec<VoteAccount>,
}

#[derive(Debug, Deserialize)]
struct VoteAccount {
    #[serde(rename = "nodePubkey")]
    node_pubkey: String,
    #[serde(rename = "votePubkey")]
    vote_pubkey: String,
}

async fn fetch_vote_accounts(
    client: &reqwest::Client,
    rpc_url: &str,
) -> Result<VoteAccountsResult> {
    let body = json!({"jsonrpc":"2.0","id":1,"method":"getVoteAccounts","params":[]});
    rpc_call(client, rpc_url, body, "getVoteAccounts").await
}

// ── validators.app ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct VAppEntryWire {
    #[serde(default)]
    account: Option<String>,
    #[serde(default)]
    data_center_key: Option<String>,
    #[serde(default)]
    is_dz: Option<bool>,
    /// Human-readable client name from validators.app
    /// (`"Agave 2.0.4"`, `"Firedancer 0.1.0"`, ...). The companion
    /// `software_client_id` integer is intentionally not pulled — the
    /// string is what we want to surface, and it dedups cleanly on its
    /// own.
    #[serde(default)]
    software_client: Option<String>,
}

/// validators.app sometimes returns a bare array, sometimes wraps it under
/// a `validators` key. Mirror that.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum VAppResponse {
    Array(Vec<VAppEntryWire>),
    Wrapped { validators: Vec<VAppEntryWire> },
}

async fn fetch_validators_app(
    client: &reqwest::Client,
    token: &str,
) -> Result<VAppResponse> {
    let resp = client
        .get(VALIDATORS_APP_URL)
        .header("Token", token)
        .send()
        .await
        .with_context(|| format!("GET {VALIDATORS_APP_URL}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("validators.app HTTP {status}: {body}");
    }
    resp.json::<VAppResponse>()
        .await
        .context("parsing validators.app response")
}

// ── Helpers ────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
struct ValidatorMeta {
    vote_pubkey: Option<String>,
    country: Option<String>,
    is_dz: Option<bool>,
    software_client: Option<String>,
}

/// validators.app `data_center_key` looks like `"9-DE-Falkenstein"`. We
/// take `parts[1]` (alpha-2 country). Switching to the city tag
/// (`parts[2]`, e.g. `"FRA"`) is a one-line change here.
fn parse_country(data_center_key: &str) -> Option<String> {
    let mut parts = data_center_key.split('-');
    parts.next()?;
    let cc = parts.next()?;
    if cc.is_empty() {
        None
    } else {
        Some(cc.to_string())
    }
}

// ── Output file shape ──────────────────────────────────────────────────────

#[derive(Serialize)]
struct EpochLeaderMapFile {
    epoch: u64,
    #[serde(rename = "epochStartSlot")]
    epoch_start_slot: u64,
    #[serde(rename = "epochEndSlot")]
    epoch_end_slot: u64,
    #[serde(rename = "slotsInEpoch")]
    slots_in_epoch: u64,
    #[serde(rename = "fetchedAtUnixSecs")]
    fetched_at_unix_secs: u64,
    regions: Vec<String>,
    #[serde(rename = "softwareClients")]
    software_clients: Vec<String>,
    validators: Vec<ValidatorOut>,
    /// One byte per slot — region index into `regions`, or 255 for unknown.
    slots: Vec<u8>,
}

#[derive(Serialize)]
struct ValidatorOut {
    pubkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    votekey: Option<String>,
    /// Region index into `regions`; absent for validators with no resolved country.
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<u8>,
    #[serde(rename = "isDz")]
    is_dz: bool,
    /// Index into `softwareClients`; absent for validators with no
    /// reported client.
    #[serde(rename = "softwareClient", skip_serializing_if = "Option::is_none")]
    software_client: Option<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_country_handles_typical_keys() {
        assert_eq!(
            parse_country("9-DE-Falkenstein"),
            Some("DE".to_string())
        );
        assert_eq!(parse_country("16276-NL-Naaldwijk"), Some("NL".to_string()));
        assert_eq!(parse_country("0-FRA"), Some("FRA".to_string()));
    }

    #[test]
    fn parse_country_rejects_malformed() {
        assert_eq!(parse_country(""), None);
        assert_eq!(parse_country("singleword"), None);
        assert_eq!(parse_country("9-"), None);
    }
}
