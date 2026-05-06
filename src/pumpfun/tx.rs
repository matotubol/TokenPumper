//! Sign and emit the launch tx wire bytes. No send path here — the
//! returned `BuiltLaunchTx` is just bytes; the caller hands them to
//! whatever third-party submitter they want (Jito bundle, Astralane,
//! plain RPC, …).
//!
//! Two signatures, both over the same v0 message body that
//! `ix_builder::ix::write_create_v2_and_buy_message` writes. Order
//! matches the account list: signature 0 is the funder (account index
//! 0), signature 1 is the mint (account index 1).

use ed25519_dalek::{Signer, SigningKey};

use super::ix_builder::ix::{self, LaunchInputs, SIG_SECTION_LEN};

/// Solana UDP MTU. Any tx must fit inside.
pub const MAX_TX_SIZE: usize = 1232;

/// Stack-allocated signed tx, ready to send. `as_bytes()` returns the
/// wire-format slice — copy into a UDP datagram, RPC payload, or wrap
/// in a Jito bundle envelope.
pub struct BuiltLaunchTx {
    buf: [u8; MAX_TX_SIZE],
    len: usize,
}

impl BuiltLaunchTx {
    pub fn new() -> Self {
        Self { buf: [0u8; MAX_TX_SIZE], len: 0 }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for BuiltLaunchTx {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the launch tx: write the v0 message into `out`, sign with both
/// `funder` and `mint`, splat the two signatures into the front. Caller
/// owns the buffer so successive launches reuse the same allocation.
///
/// Sig section layout (129 bytes):
///   `out.buf[0]      = 0x02`              shortvec(2)
///   `out.buf[1..65]  = funder_signature`  matches account 0
///   `out.buf[65..129]= mint_signature`    matches account 1
pub fn build_signed_launch_tx(
    inp: &LaunchInputs,
    funder: &SigningKey,
    mint: &SigningKey,
    out: &mut BuiltLaunchTx,
) {
    let end = ix::write_create_v2_and_buy_message(&mut out.buf, inp);

    let msg = &out.buf[SIG_SECTION_LEN..end];
    let funder_sig = funder.sign(msg).to_bytes();
    let mint_sig = mint.sign(msg).to_bytes();

    out.buf[0] = 2; // shortvec(2) — two signatures
    out.buf[1..1 + 64].copy_from_slice(&funder_sig);
    out.buf[1 + 64..1 + 64 + 64].copy_from_slice(&mint_sig);

    out.len = end;
}
