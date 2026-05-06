use ed25519_dalek::SigningKey;
use rand_core::OsRng;

pub fn keypair() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}
