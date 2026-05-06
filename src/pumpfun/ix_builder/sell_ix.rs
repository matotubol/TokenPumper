//! Pump.fun sell ix tx template — direct sell-all from the dev wallet.
//! No forwarder, no ALT — the 18-key account list fits comfortably under
//! the 1232 UDP MTU as a legacy tx, so we skip V0 + ALT-footer machinery.
//!
//! Tx shape (4 ixs):
//!
//!   1. ComputeBudget::SetComputeUnitPrice  (price first — scheduler ranks ASAP)
//!   2. ComputeBudget::SetComputeUnitLimit
//!   3. pump.fun sell                       (16 accts: 14 IDL + 2 SDK remaining)
//!   4. System::Transfer                    (node1 tip, pinned LAST)
//!
//! ## Account list (18 keys × 32 = 576 bytes)
//!
//! Order obeys agave's required grouping: writable signers → readonly
//! signers → writable non-signers → readonly non-signers.
//!
//! ```text
//!   0  user                          — dev, writable signer
//!   1  bonding_curve                 — writable (PDA per mint)
//!   2  associated_bonding_curve      — writable (ATA(bonding_curve, mint))
//!   3  associated_user               — writable (ATA(user, mint))
//!   4  fee_recipient                 — writable (from on-chain Global)
//!   5  creator_vault                 — writable (PDA per dev = creator)
//!   6  buyback_fee_recipient         — writable (one of 8 SDK-blessed)
//!   7  tip_recipient                 — writable (node1 tip wallet)
//!   8  mint                          — readonly
//!   9  global                        — readonly (PDA, fixed)
//!  10  system_program                — readonly (target of ix4, sell acct 7)
//!  11  token_2022_program            — readonly (sell acct 9)
//!  12  event_authority               — readonly (PDA, fixed; sell acct 10)
//!  13  pump_program                  — readonly (target of ix3; sell acct 11)
//!  14  fee_config                    — readonly (PDA, fixed; sell acct 12)
//!  15  pump_fee_program              — readonly (sell acct 13)
//!  16  bonding_curve_v2              — readonly (PDA; SDK remaining[0])
//!  17  compute_budget_program        — readonly (target of ix1+2)
//! ```
//!
//! ## Sell ix accounts (16, IDL ordering)
//!
//! Note `creator_vault` and `token_program` are SWAPPED relative to the
//! buy ix — the IDL puts them at positions 8/9 vs buy's 9/10. The
//! SDK-appended remaining accounts are `[bonding_curve_v2, buyback_fee_recipient]`
//! per `docs/pump-sdk/src/sdk.ts:807..819` (non-cashback case;
//! `is_cashback_enabled = false` in our launch).
//!
//! ## Args
//!
//!   [8]  SELL discriminator
//!   [8]  amount u64 LE                  (tokens to sell, raw)
//!   [8]  min_sol_output u64 LE          (slippage floor, lamports)

use ed25519_dalek::{Signer, SigningKey};

use super::cu::{
    CB_SET_COMPUTE_UNIT_LIMIT, CB_SET_COMPUTE_UNIT_PRICE, COMPUTE_BUDGET_PROGRAM_ID,
    CU_LIMIT_DATA_LEN, CU_PRICE_DATA_LEN,
};
use super::ix::{
    EVENT_AUTHORITY_PDA, FEE_CONFIG_PDA, GLOBAL_PDA, PUMP_FEE_PROGRAM_ID, PUMP_PROGRAM_ID,
    SYSTEM_PROGRAM_ID, TOKEN_2022_PROGRAM_ID,
};
use crate::pumpfun::discriminators;
use crate::pumpfun::tx::MAX_TX_SIZE;

// ── Account-list slot indices ────────────────────────────────────────────

const ACC_USER: u8 = 0;
const ACC_BONDING_CURVE: u8 = 1;
const ACC_ASSOCIATED_BONDING_CURVE: u8 = 2;
const ACC_ASSOCIATED_USER: u8 = 3;
const ACC_FEE_RECIPIENT: u8 = 4;
const ACC_CREATOR_VAULT: u8 = 5;
const ACC_BUYBACK_FEE_RECIPIENT: u8 = 6;
const ACC_TIP_RECIPIENT: u8 = 7;
const ACC_MINT: u8 = 8;
const ACC_GLOBAL: u8 = 9;
const ACC_SYSTEM_PROGRAM: u8 = 10;
const ACC_TOKEN_2022_PROGRAM: u8 = 11;
const ACC_EVENT_AUTHORITY: u8 = 12;
const ACC_PUMP_PROGRAM: u8 = 13;
const ACC_FEE_CONFIG: u8 = 14;
const ACC_PUMP_FEE_PROGRAM: u8 = 15;
const ACC_BONDING_CURVE_V2: u8 = 16;
const ACC_COMPUTE_BUDGET_PROGRAM: u8 = 17;

const NUM_KEYS: u8 = 18;
const NUM_REQUIRED_SIGS: u8 = 1;
const NUM_READONLY_SIGNED: u8 = 0;
const NUM_READONLY_UNSIGNED: u8 = 10;
const NUM_INSTRUCTIONS: u8 = 4;

/// Pump.fun `sell` accounts in IDL order (16 = 14 IDL + 2 SDK remaining).
const SELL_ACCOUNTS: [u8; 16] = [
    ACC_GLOBAL,                   //  0 global
    ACC_FEE_RECIPIENT,            //  1 fee_recipient
    ACC_MINT,                     //  2 mint
    ACC_BONDING_CURVE,            //  3 bonding_curve
    ACC_ASSOCIATED_BONDING_CURVE, //  4 associated_bonding_curve
    ACC_ASSOCIATED_USER,          //  5 associated_user
    ACC_USER,                     //  6 user (signer)
    ACC_SYSTEM_PROGRAM,           //  7 system_program
    ACC_CREATOR_VAULT,            //  8 creator_vault         (SWAPPED vs buy)
    ACC_TOKEN_2022_PROGRAM,       //  9 token_program         (SWAPPED vs buy)
    ACC_EVENT_AUTHORITY,          // 10 event_authority
    ACC_PUMP_PROGRAM,             // 11 program
    ACC_FEE_CONFIG,               // 12 fee_config
    ACC_PUMP_FEE_PROGRAM,         // 13 fee_program
    ACC_BONDING_CURVE_V2,         // 14 SDK remaining[0] (readonly)
    ACC_BUYBACK_FEE_RECIPIENT,    // 15 SDK remaining[1] (writable, LAST)
];

/// Reserved space for the signature section: shortvec(1) + 1×64-byte sig.
pub const SIG_SECTION_LEN: usize = 1 + 64;

/// Per-fire inputs for the sell tx.
pub struct SellInputs<'a> {
    pub user: &'a [u8; 32],
    pub mint: &'a [u8; 32],
    pub bonding_curve: &'a [u8; 32],
    pub associated_bonding_curve: &'a [u8; 32],
    pub associated_user: &'a [u8; 32],
    pub fee_recipient: &'a [u8; 32],
    pub creator_vault: &'a [u8; 32],
    pub buyback_fee_recipient: &'a [u8; 32],
    pub bonding_curve_v2: &'a [u8; 32],
    pub tip_recipient: &'a [u8; 32],
    pub recent_blockhash: &'a [u8; 32],

    pub amount_tokens: u64,
    pub min_sol_output: u64,
    pub tip_lamports: u64,

    pub cu_limit: u32,
    pub cu_price_micro_lamports: u64,
}

/// Stack-allocated signed sell tx, ready to ship over QUIC.
pub struct BuiltSellTx {
    buf: [u8; MAX_TX_SIZE],
    len: usize,
}

impl BuiltSellTx {
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

impl Default for BuiltSellTx {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the legacy-format sell tx into `out.buf` and sign over the
/// message body with the dev key. After return:
///   `out.buf[0]      = 0x01`              shortvec(1) — one signature
///   `out.buf[1..65]  = dev_signature`     matches account 0
///   `out.buf[..out.len]` is the wire-format slice.
pub fn build_signed_sell_tx(inp: &SellInputs, signer: &SigningKey, out: &mut BuiltSellTx) {
    let end = write_sell_message(&mut out.buf, inp);
    let msg = &out.buf[SIG_SECTION_LEN..end];
    let sig = signer.sign(msg).to_bytes();
    out.buf[0] = 1;
    out.buf[1..1 + 64].copy_from_slice(&sig);
    out.len = end;
}

/// Writes the unsigned legacy sell message into `buf[SIG_SECTION_LEN..]`.
/// Returns the absolute end offset, i.e. the slice to sign over is
/// `buf[SIG_SECTION_LEN..returned_len]`.
pub fn write_sell_message(buf: &mut [u8], inp: &SellInputs) -> usize {
    let mut pos = SIG_SECTION_LEN;

    // ── Header ──────────────────────────────────────────────────────────
    buf[pos] = NUM_REQUIRED_SIGS;
    pos += 1;
    buf[pos] = NUM_READONLY_SIGNED;
    pos += 1;
    buf[pos] = NUM_READONLY_UNSIGNED;
    pos += 1;

    // ── Static account list ─────────────────────────────────────────────
    buf[pos] = NUM_KEYS;
    pos += 1;
    let keys: [&[u8; 32]; 18] = [
        inp.user,                     //  0 writable signer
        inp.bonding_curve,            //  1 writable
        inp.associated_bonding_curve, //  2 writable
        inp.associated_user,          //  3 writable
        inp.fee_recipient,            //  4 writable
        inp.creator_vault,            //  5 writable
        inp.buyback_fee_recipient,    //  6 writable
        inp.tip_recipient,            //  7 writable (node1 tip)
        inp.mint,                     //  8 readonly
        &GLOBAL_PDA,                  //  9 readonly
        &SYSTEM_PROGRAM_ID,           // 10 readonly (target of ix4)
        &TOKEN_2022_PROGRAM_ID,       // 11 readonly
        &EVENT_AUTHORITY_PDA,         // 12 readonly
        &PUMP_PROGRAM_ID,             // 13 readonly (target of ix3)
        &FEE_CONFIG_PDA,              // 14 readonly
        &PUMP_FEE_PROGRAM_ID,         // 15 readonly
        inp.bonding_curve_v2,         // 16 readonly
        &COMPUTE_BUDGET_PROGRAM_ID,   // 17 readonly (target of ix1+2)
    ];
    for k in keys.iter() {
        buf[pos..pos + 32].copy_from_slice(*k);
        pos += 32;
    }

    // ── Recent blockhash ────────────────────────────────────────────────
    buf[pos..pos + 32].copy_from_slice(inp.recent_blockhash);
    pos += 32;

    // ── Instructions ────────────────────────────────────────────────────
    buf[pos] = NUM_INSTRUCTIONS;
    pos += 1;

    // Ix 1: SetComputeUnitPrice
    buf[pos] = ACC_COMPUTE_BUDGET_PROGRAM;
    pos += 1;
    buf[pos] = 0; // shortvec(0) accounts
    pos += 1;
    buf[pos] = CU_PRICE_DATA_LEN;
    pos += 1;
    buf[pos] = CB_SET_COMPUTE_UNIT_PRICE;
    pos += 1;
    buf[pos..pos + 8].copy_from_slice(&inp.cu_price_micro_lamports.to_le_bytes());
    pos += 8;

    // Ix 2: SetComputeUnitLimit
    buf[pos] = ACC_COMPUTE_BUDGET_PROGRAM;
    pos += 1;
    buf[pos] = 0;
    pos += 1;
    buf[pos] = CU_LIMIT_DATA_LEN;
    pos += 1;
    buf[pos] = CB_SET_COMPUTE_UNIT_LIMIT;
    pos += 1;
    buf[pos..pos + 4].copy_from_slice(&inp.cu_limit.to_le_bytes());
    pos += 4;

    // Ix 3: pump.fun sell
    const SELL_DATA_LEN: u8 = 8 + 8 + 8;
    buf[pos] = ACC_PUMP_PROGRAM;
    pos += 1;
    buf[pos] = SELL_ACCOUNTS.len() as u8; // shortvec(16)
    pos += 1;
    buf[pos..pos + 16].copy_from_slice(&SELL_ACCOUNTS);
    pos += 16;
    buf[pos] = SELL_DATA_LEN;
    pos += 1;
    buf[pos..pos + 8].copy_from_slice(&discriminators::SELL);
    pos += 8;
    buf[pos..pos + 8].copy_from_slice(&inp.amount_tokens.to_le_bytes());
    pos += 8;
    buf[pos..pos + 8].copy_from_slice(&inp.min_sol_output.to_le_bytes());
    pos += 8;

    // Ix 4: System::Transfer — node1 tip from user → tip_recipient.
    const TRANSFER_DATA_LEN: u8 = 4 + 8;
    const SYSTEM_TRANSFER_TAG: u32 = 2;
    buf[pos] = ACC_SYSTEM_PROGRAM;
    pos += 1;
    buf[pos] = 2; // shortvec(2): from + to
    pos += 1;
    buf[pos] = ACC_USER;
    pos += 1;
    buf[pos] = ACC_TIP_RECIPIENT;
    pos += 1;
    buf[pos] = TRANSFER_DATA_LEN;
    pos += 1;
    buf[pos..pos + 4].copy_from_slice(&SYSTEM_TRANSFER_TAG.to_le_bytes());
    pos += 4;
    buf[pos..pos + 8].copy_from_slice(&inp.tip_lamports.to_le_bytes());
    pos += 8;

    pos
}
