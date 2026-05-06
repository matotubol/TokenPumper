use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;

use super::{generate, storage, Origin};

/// Load `path` if it exists, otherwise create a fresh keypair, persist
/// it (mode 0o600), and return it. The `Origin` lets the caller distinguish
/// "found existing" from "just minted" — used by the wallet orchestrator
/// to decide whether to recycle keys after a sweep.
pub fn ensure(path: &Path, label: &str, hint: Option<&str>) -> Result<(SigningKey, Origin)> {
    if path.exists() {
        let kp = storage::read(path)?;
        println!(
            "{label} loaded   {}  {}",
            path.display(),
            storage::pubkey_base58(&kp)
        );
        return Ok((kp, Origin::Loaded));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating parent dir {}", parent.display()))?;
    }
    let kp = generate::keypair();
    storage::write_new(path, &kp)?;
    println!(
        "{label} created  {}  {}",
        path.display(),
        storage::pubkey_base58(&kp)
    );
    if let Some(h) = hint {
        println!("  -> {h}");
    }
    Ok((kp, Origin::Created))
}

/// Force-replace the key at `path` with a fresh one. Used after a successful
/// sweep when the caller wants to recycle a previously-loaded key.
pub fn regenerate(path: &Path, label: &str) -> Result<SigningKey> {
    if path.exists() {
        fs::remove_file(path)
            .with_context(|| format!("removing stale key {}", path.display()))?;
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating parent dir {}", parent.display()))?;
    }
    let kp = generate::keypair();
    storage::write_new(path, &kp)?;
    println!(
        "{label} recreated  {}  {}",
        path.display(),
        storage::pubkey_base58(&kp)
    );
    Ok(kp)
}
