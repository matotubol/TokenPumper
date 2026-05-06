use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::SigningKey;

pub fn write_new(path: &Path, kp: &SigningKey) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts
        .open(path)
        .with_context(|| format!("creating keypair file {}", path.display()))?;
    f.write_all(encode_json(kp).as_bytes())
        .with_context(|| format!("writing keypair file {}", path.display()))
}

pub fn read(path: &Path) -> Result<SigningKey> {
    let s = fs::read_to_string(path)
        .with_context(|| format!("reading keypair file {}", path.display()))?;
    decode_json(&s).ok_or_else(|| anyhow!("malformed keypair JSON in {}", path.display()))
}

pub fn pubkey_base58(kp: &SigningKey) -> String {
    bs58::encode(kp.verifying_key().as_bytes()).into_string()
}

fn encode_json(kp: &SigningKey) -> String {
    let bytes = kp.to_keypair_bytes();
    let parts: Vec<String> = bytes.iter().map(u8::to_string).collect();
    format!("[{}]", parts.join(","))
}

fn decode_json(s: &str) -> Option<SigningKey> {
    let inner = s.trim().strip_prefix('[')?.strip_suffix(']')?;
    let bytes: Vec<u8> = inner
        .split(',')
        .map(|t| t.trim().parse().ok())
        .collect::<Option<Vec<_>>>()?;
    let arr: [u8; 64] = bytes.try_into().ok()?;
    SigningKey::from_keypair_bytes(&arr).ok()
}
