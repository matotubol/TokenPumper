//! Pump.fun `buy_exact_sol_in` tx template — single spread-wallet buy with
//! its own ATA::CreateIdempotent baked in. Legacy format (no ALT) — fits
//! comfortably under the 1232-byte UDP MTU.
//!
//! Tx shape (5 ixs):
//!
//!   1. ComputeBudget::SetComputeUnitPrice  (price first — scheduler ranks ASAP)
//!   2. ComputeBudget::SetComputeUnitLimit
//!   3. SPL ATA::CreateIdempotent           (for the wallet's ATA)
//!   4. pump.fun buy_exact_sol_in           (16 IDL + 2 SDK remaining = 18 accts)
//!   5. System::Transfer                    (node1 tip, pinned LAST)
//!
//! ## Account list (21 keys × 32 = 672 bytes)
//!
//! Order obeys agave's required grouping: writable signers → readonly
//! signers → writable non-signers → readonly non-signers.
//!
//! ```text
//!   0  user                          — wallet, writable signer
//!   1  bonding_curve                 — writable
//!   2  associated_bonding_curve      — writable
//!   3  associated_user               — writable (wallet's ATA)
//!   4  fee_recipient                 — writable
//!   5  creator_vault                 — writable (PDA per dev = creator)
//!   6  user_volume_accumulator       — writable (PDA per buyer wallet)
//!   7  buyback_fee_recipient         — writable (one of 8 SDK-blessed)
//!   8  tip_recipient                 — writable (node1 tip)
//!   9  mint                          — readonly
//!  10  global                        — readonly (PDA, fixed)
//!  11  system_program                — readonly (target of ix3+5; buy acct 7)
//!  12  token_2022_program            — readonly (target of ix3; buy acct 8)
//!  13  event_authority               — readonly (PDA, fixed; buy acct 10)
//!  14  pump_program                  — readonly (target of ix4; buy acct 11)
//!  15  fee_config                    — readonly (PDA, fixed; buy acct 14)
//!  16  pump_fee_program              — readonly (buy acct 15)
//!  17  bonding_curve_v2              — readonly (PDA; SDK remaining[0])
//!  18  global_volume_accumulator     — readonly (PDA, fixed; buy acct 12)
//!  19  ata_program                   — readonly (target of ix3)
//!  20  compute_budget_program        — readonly (target of ix1+2)
//! ```
//!
//! ## buy_exact_sol_in ix accounts (16 IDL + 2 SDK remaining)
//!
//! Same layout as the regular `buy` ix — token_program + creator_vault
//! sit at IDL positions 8/9 (NOT swapped like sell). SDK-appended
//! remaining accounts are `[bonding_curve_v2, buyback_fee_recipient]`
//! per `docs/pump-sdk/src/sdk.ts:737..747`.
//!
//! ## Args (Borsh-packed)
//!
//!   [8]  BUY_EXACT_SOL_IN discriminator
//!   [8]  spendable_sol_in u64 LE          (lamports we'll spend, fees included)
//!   [8]  min_tokens_out   u64 LE          (slippage floor; 0 = accept any)
//!   [1]  track_volume     OptionBool      (0 = false; spread wallets opt out)

use ed25519_dalek::{Signer, SigningKey};

use super::cu::{
    CB_SET_COMPUTE_UNIT_LIMIT, CB_SET_COMPUTE_UNIT_PRICE, COMPUTE_BUDGET_PROGRAM_ID,
    CU_LIMIT_DATA_LEN, CU_PRICE_DATA_LEN,
};
use super::ix::{
    ATA_PROGRAM_ID, EVENT_AUTHORITY_PDA, FEE_CONFIG_PDA, GLOBAL_PDA,
    GLOBAL_VOLUME_ACCUMULATOR_PDA, PUMP_FEE_PROGRAM_ID, PUMP_PROGRAM_ID, SYSTEM_PROGRAM_ID,
    TOKEN_2022_PROGRAM_ID,
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
const ACC_USER_VOLUME_ACCUMULATOR: u8 = 6;
const ACC_BUYBACK_FEE_RECIPIENT: u8 = 7;
const ACC_TIP_RECIPIENT: u8 = 8;
const ACC_MINT: u8 = 9;
const ACC_GLOBAL: u8 = 10;
const ACC_SYSTEM_PROGRAM: u8 = 11;
const ACC_TOKEN_2022_PROGRAM: u8 = 12;
const ACC_EVENT_AUTHORITY: u8 = 13;
const ACC_PUMP_PROGRAM: u8 = 14;
const ACC_FEE_CONFIG: u8 = 15;
const ACC_PUMP_FEE_PROGRAM: u8 = 16;
const ACC_BONDING_CURVE_V2: u8 = 17;
const ACC_GLOBAL_VOLUME_ACCUMULATOR: u8 = 18;
const ACC_ATA_PROGRAM: u8 = 19;
const ACC_COMPUTE_BUDGET_PROGRAM: u8 = 20;

const NUM_KEYS: u8 = 21;
const NUM_REQUIRED_SIGS: u8 = 1;
const NUM_READONLY_SIGNED: u8 = 0;
const NUM_READONLY_UNSIGNED: u8 = 12;
const NUM_INSTRUCTIONS: u8 = 5;

/// Pump.fun `buy_exact_sol_in` accounts (16 IDL + 2 SDK remaining).
const BUY_EXACT_SOL_ACCOUNTS: [u8; 18] = [
    ACC_GLOBAL,                    //  0 global
    ACC_FEE_RECIPIENT,             //  1 fee_recipient
    ACC_MINT,                      //  2 mint
    ACC_BONDING_CURVE,             //  3 bonding_curve
    ACC_ASSOCIATED_BONDING_CURVE,  //  4 associated_bonding_curve
    ACC_ASSOCIATED_USER,           //  5 associated_user
    ACC_USER,                      //  6 user (signer)
    ACC_SYSTEM_PROGRAM,            //  7 system_program
    ACC_TOKEN_2022_PROGRAM,        //  8 token_program
    ACC_CREATOR_VAULT,             //  9 creator_vault
    ACC_EVENT_AUTHORITY,           // 10 event_authority
    ACC_PUMP_PROGRAM,              // 11 program
    ACC_GLOBAL_VOLUME_ACCUMULATOR, // 12 global_volume_accumulator
    ACC_USER_VOLUME_ACCUMULATOR,   // 13 user_volume_accumulator
    ACC_FEE_CONFIG,                // 14 fee_config
    ACC_PUMP_FEE_PROGRAM,          // 15 fee_program
    ACC_BONDING_CURVE_V2,          // 16 SDK remaining[0] (readonly)
    ACC_BUYBACK_FEE_RECIPIENT,     // 17 SDK remaining[1] (writable, LAST)
];

/// SPL ATA::CreateIdempotent accounts (6).
const ATA_IDEMPOTENT_ACCOUNTS: [u8; 6] = [
    ACC_USER,               // 0 funder (signer, writable) — pays rent
    ACC_ASSOCIATED_USER,    // 1 ata
    ACC_USER,               // 2 wallet (owner)
    ACC_MINT,               // 3 mint
    ACC_SYSTEM_PROGRAM,     // 4 system_program
    ACC_TOKEN_2022_PROGRAM, // 5 token_program
];

/// Reserved space for the signature section: shortvec(1) + 1×64-byte sig.
pub const SIG_SECTION_LEN: usize = 1 + 64;

/// Per-fire inputs for the buy tx.
pub struct BuyExactSolInputs<'a> {
    pub user: &'a [u8; 32],
    pub mint: &'a [u8; 32],
    pub bonding_curve: &'a [u8; 32],
    pub associated_bonding_curve: &'a [u8; 32],
    pub associated_user: &'a [u8; 32],
    pub fee_recipient: &'a [u8; 32],
    pub creator_vault: &'a [u8; 32],
    pub user_volume_accumulator: &'a [u8; 32],
    pub buyback_fee_recipient: &'a [u8; 32],
    pub bonding_curve_v2: &'a [u8; 32],
    pub tip_recipient: &'a [u8; 32],
    pub recent_blockhash: &'a [u8; 32],

    pub spendable_sol_in: u64,
    pub min_tokens_out: u64,
    pub tip_lamports: u64,

    pub cu_limit: u32,
    pub cu_price_micro_lamports: u64,
}

/// Stack-allocated signed buy tx, ready to ship over QUIC.
pub struct BuiltBuyTx {
    buf: [u8; MAX_TX_SIZE],
    len: usize,
}

impl BuiltBuyTx {
    pub fn new() -> Self {
        Self {
            buf: [0u8; MAX_TX_SIZE],
            len: 0,
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl Default for BuiltBuyTx {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the legacy-format buy tx into `out.buf` and sign over the message
/// body with the wallet key. After return:
///   `out.buf[0]      = 0x01`            shortvec(1) — one signature
///   `out.buf[1..65]  = wallet_signature`
///   `out.buf[..out.len]` is the wire-format slice.
pub fn build_signed_buy_tx(
    inp: &BuyExactSolInputs,
    signer: &SigningKey,
    out: &mut BuiltBuyTx,
) {
    let end = write_buy_message(&mut out.buf, inp);
    let msg = &out.buf[SIG_SECTION_LEN..end];
    let sig = signer.sign(msg).to_bytes();
    out.buf[0] = 1;
    out.buf[1..1 + 64].copy_from_slice(&sig);
    out.len = end;
}

/// Writes the unsigned legacy buy message into `buf[SIG_SECTION_LEN..]`.
/// Returns the absolute end offset, i.e. the slice to sign over is
/// `buf[SIG_SECTION_LEN..returned_len]`.
pub fn write_buy_message(buf: &mut [u8], inp: &BuyExactSolInputs) -> usize {
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
    let keys: [&[u8; 32]; 21] = [
        inp.user,                       //  0 writable signer
        inp.bonding_curve,              //  1 writable
        inp.associated_bonding_curve,   //  2 writable
        inp.associated_user,            //  3 writable
        inp.fee_recipient,              //  4 writable
        inp.creator_vault,              //  5 writable
        inp.user_volume_accumulator,    //  6 writable
        inp.buyback_fee_recipient,      //  7 writable
        inp.tip_recipient,              //  8 writable (node1 tip)
        inp.mint,                       //  9 readonly
        &GLOBAL_PDA,                    // 10 readonly
        &SYSTEM_PROGRAM_ID,             // 11 readonly (target of ix3+5)
        &TOKEN_2022_PROGRAM_ID,         // 12 readonly (target of ix3)
        &EVENT_AUTHORITY_PDA,           // 13 readonly
        &PUMP_PROGRAM_ID,               // 14 readonly (target of ix4)
        &FEE_CONFIG_PDA,                // 15 readonly
        &PUMP_FEE_PROGRAM_ID,           // 16 readonly
        inp.bonding_curve_v2,           // 17 readonly
        &GLOBAL_VOLUME_ACCUMULATOR_PDA, // 18 readonly
        &ATA_PROGRAM_ID,                // 19 readonly (target of ix3)
        &COMPUTE_BUDGET_PROGRAM_ID,     // 20 readonly (target of ix1+2)
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

    // Ix 3: SPL ATA::CreateIdempotent — single byte tag = 0x01.
    buf[pos] = ACC_ATA_PROGRAM;
    pos += 1;
    buf[pos] = ATA_IDEMPOTENT_ACCOUNTS.len() as u8; // shortvec(6)
    pos += 1;
    buf[pos..pos + 6].copy_from_slice(&ATA_IDEMPOTENT_ACCOUNTS);
    pos += 6;
    buf[pos] = 1; // shortvec(1) data
    pos += 1;
    buf[pos] = 0x01; // CreateIdempotent
    pos += 1;

    // Ix 4: pump.fun buy_exact_sol_in
    const BUY_DATA_LEN: u8 = 8 + 8 + 8 + 1;
    buf[pos] = ACC_PUMP_PROGRAM;
    pos += 1;
    buf[pos] = BUY_EXACT_SOL_ACCOUNTS.len() as u8; // shortvec(18)
    pos += 1;
    buf[pos..pos + BUY_EXACT_SOL_ACCOUNTS.len()].copy_from_slice(&BUY_EXACT_SOL_ACCOUNTS);
    pos += BUY_EXACT_SOL_ACCOUNTS.len();
    buf[pos] = BUY_DATA_LEN;
    pos += 1;
    buf[pos..pos + 8].copy_from_slice(&discriminators::BUY_EXACT_SOL_IN);
    pos += 8;
    buf[pos..pos + 8].copy_from_slice(&inp.spendable_sol_in.to_le_bytes());
    pos += 8;
    buf[pos..pos + 8].copy_from_slice(&inp.min_tokens_out.to_le_bytes());
    pos += 8;
    buf[pos] = 0; // track_volume = false (spread wallets opt out of cashback bookkeeping)
    pos += 1;

    // Ix 5: System::Transfer — node1 tip from user → tip_recipient.
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
