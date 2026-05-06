use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;

use super::{generate, storage, time, Origin};

pub fn resolve_today(keys_dir: &Path, count: usize) -> Result<(Vec<SigningKey>, Origin)> {
    let dir = today_dir(keys_dir)?;
    if is_complete(&dir, count) {
        Ok((load(&dir, count)?, Origin::Loaded))
    } else {
        Ok((create_fresh(&dir, count)?, Origin::Created))
    }
}

pub fn regenerate_today(keys_dir: &Path, count: usize) -> Result<Vec<SigningKey>> {
    let dir = today_dir(keys_dir)?;
    create_fresh(&dir, count)
}

fn today_dir(keys_dir: &Path) -> Result<PathBuf> {
    Ok(keys_dir.join(time::today()?))
}

fn is_complete(dir: &Path, count: usize) -> bool {
    dir.exists() && (1..=count).all(|i| dir.join(format!("{i}.json")).exists())
}

fn load(dir: &Path, count: usize) -> Result<Vec<SigningKey>> {
    (1..=count)
        .map(|i| storage::read(&dir.join(format!("{i}.json"))))
        .collect()
}

fn create_fresh(dir: &Path, count: usize) -> Result<Vec<SigningKey>> {
    fs::create_dir_all(dir)
        .with_context(|| format!("creating batch dir {}", dir.display()))?;
    clear_jsons(dir)?;
    (1..=count)
        .map(|i| {
            let path = dir.join(format!("{i}.json"));
            let kp = generate::keypair();
            storage::write_new(&path, &kp)?;
            println!("created   {}  {}", path.display(), storage::pubkey_base58(&kp));
            Ok(kp)
        })
        .collect()
}

fn clear_jsons(dir: &Path) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)
        .with_context(|| format!("reading batch dir {}", dir.display()))?
    {
        let entry = entry?;
        if entry.path().extension().is_some_and(|x| x == "json") {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}
