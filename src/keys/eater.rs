use std::path::Path;

use anyhow::Result;
use ed25519_dalek::SigningKey;

use super::singleton;

pub fn ensure(path: &Path) -> Result<SigningKey> {
    let (kp, _origin) = singleton::ensure(path, "eater", None)?;
    Ok(kp)
}
