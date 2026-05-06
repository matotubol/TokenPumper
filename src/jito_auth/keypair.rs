//! Loaded ed25519 keypair used for Jito auth handshakes.
//!
//! Wraps an `ed25519_dalek::SigningKey` so the `jito_auth` module gets the
//! exact `pubkey_bytes() / pubkey_base58() / sign()` surface its handshake
//! expects, while reusing the Solana-format JSON loader from `keys::storage`.

use std::path::Path;

use anyhow::{Context, Result};
use ed25519_dalek::{Signer, SigningKey};

pub struct SigningKeypair {
    inner: SigningKey,
}

impl SigningKeypair {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let inner = crate::keys::storage::read(path)
            .with_context(|| format!("loading auth keypair from {}", path.display()))?;
        Ok(Self { inner })
    }

    pub fn pubkey_bytes(&self) -> [u8; 32] {
        self.inner.verifying_key().to_bytes()
    }

    pub fn pubkey_base58(&self) -> String {
        bs58::encode(self.pubkey_bytes()).into_string()
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.inner.sign(msg).to_bytes()
    }
}
