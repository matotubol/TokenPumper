use std::path::Path;

use anyhow::Result;
use ed25519_dalek::SigningKey;

use super::{singleton, Origin};

pub fn resolve(path: &Path) -> Result<(SigningKey, Origin)> {
    singleton::ensure(path, "funder", None)
}

pub fn regenerate(path: &Path) -> Result<SigningKey> {
    singleton::regenerate(path, "funder")
}
