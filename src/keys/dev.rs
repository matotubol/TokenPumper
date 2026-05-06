use std::path::Path;

use anyhow::Result;
use ed25519_dalek::SigningKey;

use super::{singleton, Origin};

/// Load `keys/dev/key.json` (or create it on first run). The dev key
/// signs `create_v2` *and* the bundled buy ix on every launch, so it
/// must be persistent — unlike funder it is NOT swept or recycled.
pub fn resolve(path: &Path) -> Result<(SigningKey, Origin)> {
    singleton::ensure(path, "dev", Some("fund manually before launching"))
}
