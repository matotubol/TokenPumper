//! Token roster: load `cache/tokens.json` at startup and make sure every
//! entry has a `privatekey`. Missing slots are filled by popping lines off
//! the top of `keys/tokens.jsonl`, which is then rewritten without those
//! lines so the same key can never be assigned twice.
//!
//! The `privatekey` field stores each line from `tokens.jsonl` verbatim —
//! a JSON array of 64 u8s, the standard Solana keypair-bytes format. A
//! consumer can recover the bytes with `serde_json::from_str::<Vec<u8>>`.

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use tracing::info;

const TOKENS_CACHE_FILE: &str = "tokens.json";
const TOKENS_KEY_FILE: &str = "tokens.jsonl";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSpec {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Symbol")]
    pub symbol: String,
    #[serde(rename = "Description")]
    pub description: String,
    pub website: String,
    pub twitter: String,
    pub is_used: bool,
    pub privatekey: String,
}

impl TokenSpec {
    /// Mint pubkey extracted from `privatekey`. The stored value is a
    /// JSON array of 64 u8s — the standard Solana keypair format
    /// `[secret32 || pubkey32]` — so the pubkey is the last 32 bytes.
    pub fn mint_pubkey(&self) -> Result<[u8; 32]> {
        let kp = self.parse_keypair_bytes()?;
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&kp[32..64]);
        Ok(pk)
    }

    /// Mint signing key, ready to sign the create_v2 portion of the
    /// launch tx. The mint must sign because `create_v2` materializes
    /// the mint account via `system_program::create_account`, and that
    /// requires the new account to authorize its own creation.
    pub fn mint_keypair(&self) -> Result<ed25519_dalek::SigningKey> {
        let kp = self.parse_keypair_bytes()?;
        ed25519_dalek::SigningKey::from_keypair_bytes(&kp)
            .map_err(|e| anyhow!("invalid mint keypair for {}: {}", self.symbol, e))
    }

    fn parse_keypair_bytes(&self) -> Result<[u8; 64]> {
        let bytes: Vec<u8> = serde_json::from_str(&self.privatekey)
            .with_context(|| format!("parsing privatekey for {}", self.symbol))?;
        bytes.try_into().map_err(|v: Vec<u8>| {
            anyhow!("{} privatekey is {} bytes, want 64", self.symbol, v.len())
        })
    }
}

/// `Ok(None)` means `cache/tokens.json` does not exist — the caller should
/// print a friendly message and exit. `Ok(Some(_))` returns the fully
/// hydrated roster; any keys that were drawn from `keys/tokens.jsonl` have
/// already been removed from that file on disk.
pub fn load_and_hydrate(cache_dir: &Path, keys_dir: &Path) -> Result<Option<Vec<TokenSpec>>> {
    let cache_path = cache_dir.join(TOKENS_CACHE_FILE);
    if !cache_path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(&cache_path)
        .with_context(|| format!("reading {}", cache_path.display()))?;
    let mut tokens: Vec<TokenSpec> = serde_json::from_str(&raw)
        .with_context(|| format!("parsing {}", cache_path.display()))?;

    let needed: Vec<usize> = tokens
        .iter()
        .enumerate()
        .filter(|(_, t)| t.privatekey.is_empty())
        .map(|(i, _)| i)
        .collect();

    if needed.is_empty() {
        info!(count = tokens.len(), "tokens already hydrated");
        return Ok(Some(tokens));
    }

    let keys_path = keys_dir.join(TOKENS_KEY_FILE);
    let lines = read_lines(&keys_path)?;
    if lines.len() < needed.len() {
        return Err(anyhow!(
            "{} tokens need keys but {} only has {} entries",
            needed.len(),
            keys_path.display(),
            lines.len()
        ));
    }

    let (consumed, remaining) = lines.split_at(needed.len());
    for (slot, line) in needed.iter().zip(consumed.iter()) {
        tokens[*slot].privatekey = line.clone();
    }

    // Order matters: shrink the source pool first. If we crash before
    // writing tokens.json the consumed lines are lost — annoying but safe.
    // Doing it the other way around would risk handing the same key to a
    // future token if the second write fails.
    write_atomic(&keys_path, &join_lines(remaining).into_bytes())?;
    let mut json = serde_json::to_vec_pretty(&tokens)?;
    json.push(b'\n');
    write_atomic(&cache_path, &json)?;

    info!(
        consumed = consumed.len(),
        remaining = remaining.len(),
        "hydrated tokens from {}",
        keys_path.display()
    );

    Ok(Some(tokens))
}

/// Choose which entry in the roster to launch this run.
///
/// `debug = true` always returns the last index — the reserved debug
/// sentinel. `debug = false` returns the first index in `0..len-1` whose
/// `is_used` is false; the final slot is intentionally excluded so the
/// debug sentinel is never burned in a real run.
pub fn pick(tokens: &[TokenSpec], debug: bool) -> Result<usize> {
    if tokens.is_empty() {
        return Err(anyhow!("token roster is empty"));
    }
    if debug {
        return Ok(tokens.len() - 1);
    }
    let last = tokens.len() - 1;
    tokens
        .iter()
        .take(last)
        .position(|t| !t.is_used)
        .ok_or_else(|| anyhow!("no unused tokens left (debug sentinel reserved)"))
}

/// Flip `is_used = true` on the picked token and persist the roster.
/// Caller should only invoke this after a successful upload, and never in
/// debug mode (the sentinel must remain reusable).
pub fn mark_used(cache_dir: &Path, tokens: &mut [TokenSpec], idx: usize) -> Result<()> {
    tokens[idx].is_used = true;
    let cache_path = cache_dir.join(TOKENS_CACHE_FILE);
    let mut json = serde_json::to_vec_pretty(&tokens)?;
    json.push(b'\n');
    write_atomic(&cache_path, &json)
}

fn read_lines(path: &Path) -> Result<Vec<String>> {
    let f = fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut out = Vec::new();
    for line in BufReader::new(f).lines() {
        let line = line.with_context(|| format!("reading {}", path.display()))?;
        if !line.trim().is_empty() {
            out.push(line);
        }
    }
    Ok(out)
}

fn join_lines(lines: &[String]) -> String {
    let mut s = String::with_capacity(lines.iter().map(|l| l.len() + 1).sum());
    for line in lines {
        s.push_str(line);
        s.push('\n');
    }
    s
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("path has no filename: {}", path.display()))?;
    let mut tmp = PathBuf::from(path);
    tmp.set_file_name(format!(".{name}.tmp"));
    fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}
