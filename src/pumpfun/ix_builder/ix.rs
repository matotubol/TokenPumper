//! Pump.fun launch-tx template — `create_v2` + idempotent ATA + `buy`,
//! mayhem and cashback both forced off. Writes the **unsigned v0
//! message** for the launch into a caller-owned buffer; the signing path
//! (two signers: funder + mint) lives in a future `tx.rs`.
//!
//! Style mirrors PumpBeast's `sniper_tx.rs`: every program ID and every
//! fixed PDA is decoded once via `scripts/decode_pubkeys.py` and inlined
//! as a `[u8; 32]` const. No `find_program_address` at runtime, no
//! `bs58::decode`, no `Vec`. Per-launch inputs (mint, bonding_curve,
//! associated_*, etc.) are passed in as `&[u8; 32]` references — the
//! caller derives them.
//!
//! ## Account list (17 static + 10 ALT-loaded = 27 runtime positions)
//!
//! Static keys hold: signers, per-launch-variable PDAs/ATAs, AND every
//! program any outer ix targets — agave's sanitizer at
//! `transaction-view/src/sanitize.rs:152` requires
//! `program_id_index <= num_static_account_keys - 1`, so programs in
//! the ALT are rejected with `Transaction failed to sanitize accounts
//! offsets correctly`. We invoke compute_budget, pump, ata, and system
//! directly — those four must be static.
//!
//! ALT carries the rest: program-invariant PDAs and the *referenced*
//! programs (mayhem_program, token_2022_program, pump_fee_program) that
//! pump CPIs internally but our outer ixs never target.
//!
//! ```text
//! Static keys (idx 0..=16, written into the message):
//!   0  user                                — funder (creator), writable signer
//!   1  mint                                — fresh keypair from tokens.json, writable signer
//!   2  bonding_curve                       — writable
//!   3  associated_bonding_curve            — writable
//!   4  mayhem_state                        — writable
//!   5  mayhem_token_vault                  — writable
//!   6  fee_recipient                       — writable
//!   7  creator_vault                       — writable
//!   8  user_volume_accumulator             — writable
//!   9  associated_user                     — writable
//!  10  tip_recipient                       — writable
//!  11  buyback_fee_recipient               — writable
//!  12  bonding_curve_v2                    — readonly (per-mint PDA)
//!  13  system_program                      — readonly (program target of ix6)
//!  14  ata_program                         — readonly (program target of ix4)
//!  15  compute_budget_program              — readonly (program target of ix1+2)
//!  16  pump_program                        — readonly (program target of ix3+5)
//! ALT-loaded writable (idx 17..=18, footer.writable_indices):
//!  17  mayhem_program
//!  18  sol_vault
//! ALT-loaded readonly (idx 19..=26, footer.readonly_indices):
//!  19  mint_authority
//!  20  global
//!  21  token_2022_program
//!  22  global_params
//!  23  event_authority
//!  24  global_volume_accumulator
//!  25  fee_config
//!  26  pump_fee_program
//! ```

use super::cu::{
    CB_SET_COMPUTE_UNIT_LIMIT, CB_SET_COMPUTE_UNIT_PRICE, COMPUTE_BUDGET_PROGRAM_ID,
    CU_LIMIT_DATA_LEN, CU_PRICE_DATA_LEN,
};
use crate::pumpfun::discriminators;

// ── Program IDs ──────────────────────────────────────────────────────────

pub const SYSTEM_PROGRAM_ID: [u8; 32] = [0; 32];

/// `6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P`
pub const PUMP_PROGRAM_ID: [u8; 32] = [
    1, 86, 224, 246, 147, 102, 90, 207, 68, 219, 21, 104, 191, 23, 91, 170, 81, 137, 203, 151, 245,
    210, 255, 59, 101, 93, 43, 182, 253, 109, 24, 176,
];

/// `MAyhSmzXzV1pTf7LsNkrNwkWKTo4ougAJ1PPg47MD4e`
pub const MAYHEM_PROGRAM_ID: [u8; 32] = [
    5, 42, 229, 215, 167, 218, 167, 36, 166, 234, 176, 167, 41, 84, 145, 133, 90, 212, 160, 103,
    22, 96, 103, 76, 78, 3, 69, 89, 128, 61, 101, 163,
];

/// `pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ`
pub const PUMP_FEE_PROGRAM_ID: [u8; 32] = [
    12, 53, 255, 169, 5, 90, 142, 86, 141, 168, 247, 188, 7, 86, 21, 39, 76, 241, 201, 44, 164, 31,
    64, 0, 156, 81, 106, 164, 20, 194, 124, 112,
];

/// `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb` (SPL Token-2022).
pub const TOKEN_2022_PROGRAM_ID: [u8; 32] = [
    6, 221, 246, 225, 238, 117, 143, 222, 24, 66, 93, 188, 228, 108, 205, 218, 182, 26, 252, 77,
    131, 185, 13, 39, 254, 189, 249, 40, 216, 161, 139, 252,
];

/// `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL` (Associated Token program).
pub const ATA_PROGRAM_ID: [u8; 32] = [
    140, 151, 37, 143, 78, 36, 137, 241, 187, 61, 16, 41, 20, 142, 13, 131, 11, 90, 19, 153, 218,
    255, 16, 132, 4, 142, 123, 216, 219, 233, 248, 89,
];

// ── Fixed PDAs (per-launch-invariant) ────────────────────────────────────
//
// All seven derived once via solders + Python and inlined as bytes. The
// human-readable bs58 form is in the doc comment for cross-reference.

/// `pumpPda(["mint-authority"])` = `TSLvdd1pWpHVjahSpsvCXUbgwsL3JAcvokwaKt1eokM`
pub const MINT_AUTHORITY_PDA: [u8; 32] = [
    6, 197, 193, 206, 99, 141, 37, 103, 210, 100, 104, 176, 94, 185, 81, 209, 162, 141, 204, 110,
    18, 52, 130, 181, 198, 117, 20, 151, 112, 230, 43, 242,
];

/// `pumpPda(["global"])` = `4wTV1YmiEkRvAtNtsSGPtUrqRYQMe5SKy2uB4Jjaxnjf`
pub const GLOBAL_PDA: [u8; 32] = [
    58, 134, 94, 105, 238, 15, 84, 128, 202, 188, 246, 99, 87, 228, 220, 47, 24, 213, 141, 69, 193,
    234, 116, 137, 251, 55, 35, 217, 121, 60, 114, 166,
];

/// `pumpPda(["__event_authority"])` = `Ce6TQqeHC9p8KetsN6JsjHK7UTZk7nasjjnr7XxXp9F1`
pub const EVENT_AUTHORITY_PDA: [u8; 32] = [
    172, 241, 54, 235, 1, 252, 28, 78, 136, 61, 35, 200, 181, 132, 74, 181, 154, 55, 246, 106, 221,
    87, 197, 233, 172, 59, 83, 224, 89, 211, 92, 100,
];

/// `mayhemPda(["global-params"])` = `13ec7XdrjF3h3YcqBTFDSReRcUFwbCnJaAQspM4j6DDJ`
pub const GLOBAL_PARAMS_PDA: [u8; 32] = [
    0, 173, 174, 162, 125, 179, 198, 243, 208, 78, 92, 240, 162, 2, 159, 3, 227, 57, 143, 8, 83,
    149, 239, 239, 239, 23, 31, 198, 74, 248, 23, 65,
];

/// `mayhemPda(["sol-vault"])` = `BwWK17cbHxwWBKZkUYvzxLcNQ1YVyaFezduWbtm2de6s`
pub const SOL_VAULT_PDA: [u8; 32] = [
    162, 139, 95, 210, 106, 180, 121, 166, 169, 204, 108, 191, 107, 11, 35, 235, 97, 136, 90, 55,
    30, 1, 32, 172, 169, 19, 190, 239, 61, 19, 138, 120,
];

/// `pumpPda(["global_volume_accumulator"])` = `Hq2wp8uJ9jCPsYgNHex8RtqdvMPfVGoYwjvF1ATiwn2Y`
pub const GLOBAL_VOLUME_ACCUMULATOR_PDA: [u8; 32] = [
    250, 9, 17, 165, 72, 99, 65, 45, 99, 31, 78, 7, 135, 3, 41, 108, 3, 95, 13, 19, 51, 160, 217,
    200, 131, 141, 115, 183, 16, 254, 110, 45,
];

/// `feePda(["fee_config", PUMP_PROGRAM_ID])` = `8Wf5TiAheLUqBrKXeYg2JtAFFMWtKdG2BSFgqUcPVwTt`
pub const FEE_CONFIG_PDA: [u8; 32] = [
    111, 154, 180, 164, 241, 149, 141, 192, 169, 201, 76, 63, 183, 44, 7, 153, 88, 67, 237, 164,
    133, 227, 162, 79, 16, 198, 147, 153, 248, 25, 148, 15,
];

// ── Account-list slots (indices into the 24-key message account list) ────

// Positions in the runtime account list. Static slots come first
// (matched 1:1 against the message's static keys), then ALT writable,
// then ALT readonly — `NUM_*_STATIC` controls how the runtime splits
// expanded ALT entries onto these.
const ACC_USER: u8 = 0;
const ACC_MINT: u8 = 1;
const ACC_BONDING_CURVE: u8 = 2;
const ACC_ASSOCIATED_BONDING_CURVE: u8 = 3;
const ACC_MAYHEM_STATE: u8 = 4;
const ACC_MAYHEM_TOKEN_VAULT: u8 = 5;
const ACC_FEE_RECIPIENT: u8 = 6;
const ACC_CREATOR_VAULT: u8 = 7;
const ACC_USER_VOLUME_ACCUMULATOR: u8 = 8;
const ACC_ASSOCIATED_USER: u8 = 9;
const ACC_TIP_RECIPIENT: u8 = 10;
const ACC_BUYBACK_FEE_RECIPIENT: u8 = 11;
const ACC_BONDING_CURVE_V2: u8 = 12;
// Programs we directly invoke must be static (agave sanitizer enforces
// `program_id_index <= num_static_account_keys - 1`):
const ACC_SYSTEM_PROGRAM: u8 = 13;
const ACC_ATA_PROGRAM: u8 = 14;
const ACC_COMPUTE_BUDGET_PROGRAM: u8 = 15;
const ACC_PUMP_PROGRAM: u8 = 16;
// ALT writable (footer.writable_indices, in this order):
const ACC_MAYHEM_PROGRAM: u8 = 17;
const ACC_SOL_VAULT: u8 = 18;
// ALT readonly (footer.readonly_indices, in this order). Programs we
// only *reference* (CPI'd internally by pump, not invoked by an outer
// ix) can stay here:
const ACC_MINT_AUTHORITY: u8 = 19;
const ACC_GLOBAL: u8 = 20;
const ACC_TOKEN_2022_PROGRAM: u8 = 21;
const ACC_GLOBAL_PARAMS: u8 = 22;
const ACC_EVENT_AUTHORITY: u8 = 23;
const ACC_GLOBAL_VOLUME_ACCUMULATOR: u8 = 24;
const ACC_FEE_CONFIG: u8 = 25;
const ACC_PUMP_FEE_PROGRAM: u8 = 26;

/// Static keys count in the message header — only the keys we actually
/// inline (signers + per-launch-variable + every directly-invoked
/// program). ALT entries are NOT counted.
const NUM_STATIC_KEYS: u8 = 17;
const NUM_REQUIRED_SIGS: u8 = 2; // user + mint
const NUM_READONLY_SIGNED: u8 = 0;
// bonding_curve_v2 + system + ata + compute_budget + pump = 5 readonly statics.
const NUM_READONLY_UNSIGNED_STATIC: u8 = 5;
const NUM_INSTRUCTIONS: u8 = 6;

/// ALT footer counts (must match the order in `AltIndices`).
const NUM_ALT_WRITABLE: u8 = 2;
const NUM_ALT_READONLY: u8 = 8;

// Per-ix account-index arrays — IDL ordering, mapped onto the 24-key list.

/// create_v2 accounts (16, IDL line 2075). Account positions match the
/// IDL exactly; values are slots in the message account list above.
const CREATE_V2_ACCOUNTS: [u8; 16] = [
    ACC_MINT,                     //  0 mint
    ACC_MINT_AUTHORITY,           //  1 mint_authority
    ACC_BONDING_CURVE,            //  2 bonding_curve
    ACC_ASSOCIATED_BONDING_CURVE, //  3 associated_bonding_curve
    ACC_GLOBAL,                   //  4 global
    ACC_USER,                     //  5 user
    ACC_SYSTEM_PROGRAM,           //  6 system_program
    ACC_TOKEN_2022_PROGRAM,       //  7 token_program
    ACC_ATA_PROGRAM,              //  8 associated_token_program
    ACC_MAYHEM_PROGRAM,           //  9 mayhem_program_id
    ACC_GLOBAL_PARAMS,            // 10 global_params
    ACC_SOL_VAULT,                // 11 sol_vault
    ACC_MAYHEM_STATE,             // 12 mayhem_state
    ACC_MAYHEM_TOKEN_VAULT,       // 13 mayhem_token_vault
    ACC_EVENT_AUTHORITY,          // 14 event_authority
    ACC_PUMP_PROGRAM,             // 15 program
];

/// SPL ATA::CreateIdempotent accounts (6).
const ATA_IDEMPOTENT_ACCOUNTS: [u8; 6] = [
    ACC_USER,               // 0 funder (signer, writable)
    ACC_ASSOCIATED_USER,    // 1 ata
    ACC_USER,               // 2 wallet (owner)
    ACC_MINT,               // 3 mint
    ACC_SYSTEM_PROGRAM,     // 4 system_program
    ACC_TOKEN_2022_PROGRAM, // 5 token_program
];

/// buy accounts (16 IDL + 2 SDK-appended remaining = 18). Pos 16 and 17
/// match `docs/pump-sdk/src/sdk.ts:737..747` `.remainingAccounts([...])`.
const BUY_ACCOUNTS: [u8; 18] = [
    ACC_GLOBAL,                    //  0 global
    ACC_FEE_RECIPIENT,             //  1 fee_recipient
    ACC_MINT,                      //  2 mint
    ACC_BONDING_CURVE,             //  3 bonding_curve
    ACC_ASSOCIATED_BONDING_CURVE,  //  4 associated_bonding_curve
    ACC_ASSOCIATED_USER,           //  5 associated_user
    ACC_USER,                      //  6 user
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
    ACC_BUYBACK_FEE_RECIPIENT,     // 17 SDK remaining[1] (writable)
];

// V0 message version prefix: high bit set marks "versioned", low bits = 0.
const MESSAGE_VERSION_PREFIX_V0: u8 = 0x80;

// ── Per-launch inputs ────────────────────────────────────────────────────

/// Everything the launch message needs that isn't a const. PDAs are
/// derived elsewhere (a future `pda.rs`); `fee_recipient` is read from
/// the on-chain `Global` account at startup; the buy quote
/// (`buy_amount_tokens` / `buy_max_sol_cost`) is computed off the
/// bonding-curve init reserves.
pub struct LaunchInputs<'a> {
    // 32-byte pubkeys ----------------------------------------------------
    pub user: &'a [u8; 32],                    // funder = creator
    pub mint: &'a [u8; 32],                    // tokens.json privatekey → pubkey
    pub bonding_curve: &'a [u8; 32],           // PDA pump per mint
    pub associated_bonding_curve: &'a [u8; 32],
    pub mayhem_state: &'a [u8; 32],            // PDA mayhem per mint
    pub mayhem_token_vault: &'a [u8; 32],      // ATA(mint, sol_vault, TOKEN_2022)
    pub fee_recipient: &'a [u8; 32],           // from on-chain Global
    pub creator_vault: &'a [u8; 32],           // PDA pump per creator
    pub user_volume_accumulator: &'a [u8; 32], // PDA pump per user
    pub associated_user: &'a [u8; 32],         // ATA(mint, user, TOKEN_2022)
    pub tip_recipient: &'a [u8; 32],           // submitter tip wallet (e.g. node1)
    pub buyback_fee_recipient: &'a [u8; 32],   // one of 8 SDK-blessed wallets
    pub bonding_curve_v2: &'a [u8; 32],        // PDA pump per mint
    pub recent_blockhash: &'a [u8; 32],

    // ALT — pre-resolved indices into `cfg.address_lookup_table`.
    pub alt: &'a crate::pumpfun::alt::AltIndices,

    // create_v2 args -----------------------------------------------------
    pub name: &'a str,
    pub symbol: &'a str,
    pub uri: &'a str,

    // buy args -----------------------------------------------------------
    pub buy_amount_tokens: u64,
    pub buy_max_sol_cost: u64,
    pub track_volume: bool,

    // tip ----------------------------------------------------------------
    pub tip_lamports: u64,

    // CU -----------------------------------------------------------------
    pub cu_limit: u32,
    pub cu_price_micro_lamports: u64,
}

// ── Builder ──────────────────────────────────────────────────────────────

/// Reserved space at the start of the tx buffer for the signature
/// section: shortvec(2) + 2 × 64-byte signatures = 129 bytes. The signer
/// fills these in after signing the message body.
pub const SIG_SECTION_LEN: usize = 1 + 2 * 64;

/// Writes the unsigned launch message into `buf` starting at
/// `SIG_SECTION_LEN`. Returns the absolute end offset, i.e. the slice to
/// sign over is `buf[SIG_SECTION_LEN..returned_len]`.
///
/// Caller workflow:
///   1. let end = write_create_v2_and_buy_message(&mut buf, &inputs);
///   2. user_sig = sign(&buf[SIG_SECTION_LEN..end]) with funder key
///   3. mint_sig = sign(&buf[SIG_SECTION_LEN..end]) with mint key
///   4. buf[0] = 2; buf[1..65] = user_sig; buf[65..129] = mint_sig;
///   5. send buf[..end] over RPC / Jito.
pub fn write_create_v2_and_buy_message(buf: &mut [u8], inp: &LaunchInputs) -> usize {
    let mut pos = SIG_SECTION_LEN;

    // ── V0 version prefix + header ──────────────────────────────────────
    buf[pos] = MESSAGE_VERSION_PREFIX_V0;
    pos += 1;
    buf[pos] = NUM_REQUIRED_SIGS;
    pos += 1;
    buf[pos] = NUM_READONLY_SIGNED;
    pos += 1;
    buf[pos] = NUM_READONLY_UNSIGNED_STATIC;
    pos += 1;

    // ── Static account list (17 × 32 = 544 bytes) ───────────────────────
    buf[pos] = NUM_STATIC_KEYS;
    pos += 1;
    let keys: [&[u8; 32]; 17] = [
        inp.user,                     //  0 writable signer
        inp.mint,                     //  1 writable signer
        inp.bonding_curve,            //  2 writable
        inp.associated_bonding_curve, //  3 writable
        inp.mayhem_state,             //  4 writable
        inp.mayhem_token_vault,       //  5 writable
        inp.fee_recipient,            //  6 writable
        inp.creator_vault,            //  7 writable
        inp.user_volume_accumulator,  //  8 writable
        inp.associated_user,          //  9 writable
        inp.tip_recipient,            // 10 writable (submitter tip)
        inp.buyback_fee_recipient,    // 11 writable (SDK remaining[1])
        inp.bonding_curve_v2,         // 12 readonly (SDK remaining[0])
        &SYSTEM_PROGRAM_ID,           // 13 readonly (target of ix6)
        &ATA_PROGRAM_ID,              // 14 readonly (target of ix4)
        &COMPUTE_BUDGET_PROGRAM_ID,   // 15 readonly (target of ix1+2)
        &PUMP_PROGRAM_ID,             // 16 readonly (target of ix3+5)
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

    // Ix 1: SetComputeUnitPrice — placed before the limit so the banking
    // scheduler can rank the tx as soon as it parses the price.
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

    // Ix 3: pump.fun create_v2
    //
    // Data layout (8-byte disc + borsh args):
    //   [8]  CREATE_V2 discriminator
    //   [4]  name_len u32 LE
    //   [N]  name bytes
    //   [4]  symbol_len u32 LE
    //   [N]  symbol bytes
    //   [4]  uri_len u32 LE
    //   [N]  uri bytes
    //   [32] creator pubkey (= user)
    //   [1]  is_mayhem_mode = 0
    //   [1]  is_cashback_enabled = 0  (OptionBool { bool } per IDL)
    let create_v2_data_len = 8
        + 4 + inp.name.len()
        + 4 + inp.symbol.len()
        + 4 + inp.uri.len()
        + 32 + 1 + 1;
    buf[pos] = ACC_PUMP_PROGRAM;
    pos += 1;
    buf[pos] = CREATE_V2_ACCOUNTS.len() as u8; // shortvec(16)
    pos += 1;
    buf[pos..pos + 16].copy_from_slice(&CREATE_V2_ACCOUNTS);
    pos += 16;
    pos += write_shortvec(buf, pos, create_v2_data_len as u16);
    buf[pos..pos + 8].copy_from_slice(&discriminators::CREATE_V2);
    pos += 8;
    pos += write_str(buf, pos, inp.name);
    pos += write_str(buf, pos, inp.symbol);
    pos += write_str(buf, pos, inp.uri);
    buf[pos..pos + 32].copy_from_slice(inp.user); // creator = funder
    pos += 32;
    buf[pos] = 0; // is_mayhem_mode = false
    pos += 1;
    buf[pos] = 0; // is_cashback_enabled = false
    pos += 1;

    // Ix 4: SPL ATA::CreateIdempotent — single byte tag = 0x01.
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

    // Ix 5: pump.fun buy
    //
    // Data layout:
    //   [8]  BUY discriminator
    //   [8]  amount u64 LE                 (tokens out, raw)
    //   [8]  max_sol_cost u64 LE           (slippage cap, lamports)
    //   [1]  track_volume u8               (OptionBool { bool })
    const BUY_DATA_LEN: u8 = 8 + 8 + 8 + 1;
    buf[pos] = ACC_PUMP_PROGRAM;
    pos += 1;
    buf[pos] = BUY_ACCOUNTS.len() as u8; // shortvec(18)
    pos += 1;
    buf[pos..pos + BUY_ACCOUNTS.len()].copy_from_slice(&BUY_ACCOUNTS);
    pos += BUY_ACCOUNTS.len();
    buf[pos] = BUY_DATA_LEN;
    pos += 1;
    buf[pos..pos + 8].copy_from_slice(&discriminators::BUY);
    pos += 8;
    buf[pos..pos + 8].copy_from_slice(&inp.buy_amount_tokens.to_le_bytes());
    pos += 8;
    buf[pos..pos + 8].copy_from_slice(&inp.buy_max_sol_cost.to_le_bytes());
    pos += 8;
    buf[pos] = inp.track_volume as u8;
    pos += 1;

    // Ix 6: System::Transfer — submitter tip from user → tip_recipient.
    //
    // Bincode-tagged enum, default config: 4-byte LE tag + variant body.
    //   [4]  instruction = 2 (Transfer) u32 LE
    //   [8]  lamports u64 LE
    const TRANSFER_DATA_LEN: u8 = 4 + 8;
    const SYSTEM_TRANSFER_TAG: u32 = 2;
    buf[pos] = ACC_SYSTEM_PROGRAM;
    pos += 1;
    buf[pos] = 2; // shortvec(2) accounts: from + to
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

    // ── ALT footer ─────────────────────────────────────────────────────
    // One ALT entry. Layout per Solana wire format:
    //   shortvec(1)            — number of ALT entries
    //   alt_pubkey (32)        — looked up by runtime
    //   shortvec(N_writable)   — count of writable indices
    //   N_writable bytes       — indices into ALT (each 1 byte)
    //   shortvec(N_readonly)   — count of readonly indices
    //   N_readonly bytes       — indices into ALT (each 1 byte)
    buf[pos] = 1;
    pos += 1;
    buf[pos..pos + 32].copy_from_slice(&inp.alt.alt_pubkey);
    pos += 32;

    buf[pos] = NUM_ALT_WRITABLE;
    pos += 1;
    buf[pos] = inp.alt.mayhem_program;
    pos += 1;
    buf[pos] = inp.alt.sol_vault;
    pos += 1;

    buf[pos] = NUM_ALT_READONLY;
    pos += 1;
    buf[pos] = inp.alt.mint_authority;
    pos += 1;
    buf[pos] = inp.alt.global;
    pos += 1;
    buf[pos] = inp.alt.token_2022_program;
    pos += 1;
    buf[pos] = inp.alt.global_params;
    pos += 1;
    buf[pos] = inp.alt.event_authority;
    pos += 1;
    buf[pos] = inp.alt.global_volume_accumulator;
    pos += 1;
    buf[pos] = inp.alt.fee_config;
    pos += 1;
    buf[pos] = inp.alt.pump_fee_program;
    pos += 1;

    pos
}

/// Borsh string: u32-LE length prefix + raw UTF-8 bytes. Returns the
/// number of bytes written (4 + s.len()).
#[inline]
fn write_str(buf: &mut [u8], pos: usize, s: &str) -> usize {
    let len = s.len();
    buf[pos..pos + 4].copy_from_slice(&(len as u32).to_le_bytes());
    buf[pos + 4..pos + 4 + len].copy_from_slice(s.as_bytes());
    4 + len
}

/// Solana shortvec (variable-length compact-u16). Returns bytes written
/// (1, 2, or 3). For ix data lengths > 127 we need this — `name + symbol
/// + uri` blows past one byte easily for createV2.
#[inline]
fn write_shortvec(buf: &mut [u8], pos: usize, mut n: u16) -> usize {
    let mut written = 0;
    loop {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            buf[pos + written] = byte;
            return written + 1;
        }
        byte |= 0x80;
        buf[pos + written] = byte;
        written += 1;
    }
}
