//! Spread-wallet buy fire-time context. Bundles every input the curve-sub
//! trigger needs to build + sign + submit a `cu_price + cu_limit + ATA::CreateIdempotent
//! + buy_exact_sol_in + tip` tx for one wallet.
//!
//! Mirrors `SellContext`, but per-wallet — one `BuyContext` per spread
//! wallet configured under `[[accounts]]`. The curve-sub task fires every
//! configured `BuyContext` immediately on the first observed curve update;
//! the dev sell still waits 1s after that to land *after* this batch.
//!
//! `spendable_sol_in` is the wallet's jittered config amount (see
//! `keys::assigner`). `min_tokens_out = 0` — landing matters more than
//! price for a first-tick buy off a brand-new curve.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use tracing::{info, warn};

use crate::blockhash::BlockhashCache;
use crate::pumpfun::buyback;
use crate::pumpfun::ix_builder::buy_exact_sol_ix::{
    build_signed_buy_tx, BuiltBuyTx, BuyExactSolInputs,
};
use crate::pumpfun::pda::LaunchPdas;
use crate::senders::node1::{Node1Submitter, TIP_RECIPIENT};

pub struct BuyContext {
    /// Log-friendly tag — `"wallet-1"`, `"wallet-2"`, …
    pub label: String,

    pub wallet: SigningKey,
    pub user_pubkey: [u8; 32],
    pub mint_pubkey: [u8; 32],
    pub fee_recipient: [u8; 32],

    /// Per-launch PDAs shared with the dev launch context: `bonding_curve`,
    /// `associated_bonding_curve`, `bonding_curve_v2`, `creator_vault`
    /// (creator_vault is keyed by the dev = creator, NOT the buyer wallet,
    /// so it's the same PDA for every wallet).
    pub pdas: LaunchPdas,
    /// Buyer wallet's ATA — `find_program_address([wallet, TOKEN_2022, mint],
    /// ATA_PROGRAM)`. Pre-derived at startup.
    pub associated_user: [u8; 32],
    /// Buyer wallet's `user_volume_accumulator` PDA — keyed by the wallet
    /// pubkey. Auto-init by pump on first buy from this wallet.
    pub user_volume_accumulator: [u8; 32],

    pub blockhash: BlockhashCache,
    pub spendable_sol_in: u64,
    pub tip_lamports: u64,
    pub cu_limit: u32,
    pub cu_price_micro_lamports: u64,

    /// `None` in debug mode (or when `node1_api_key` is unset). The build
    /// + sign path still runs so the wire format is exercised.
    pub submitter: Option<Arc<Node1Submitter>>,
}

/// Build + sign the buy tx using the current cached blockhash. `slot`
/// rotates the buyback recipient across the 8-wallet pool — same scheme
/// as launch + sell.
pub fn build_signed(ctx: &BuyContext, slot: u64, out: &mut BuiltBuyTx) {
    let blockhash = ctx.blockhash.current();
    let inputs = BuyExactSolInputs {
        user: &ctx.user_pubkey,
        mint: &ctx.mint_pubkey,
        bonding_curve: &ctx.pdas.bonding_curve,
        associated_bonding_curve: &ctx.pdas.associated_bonding_curve,
        associated_user: &ctx.associated_user,
        fee_recipient: &ctx.fee_recipient,
        creator_vault: &ctx.pdas.creator_vault,
        user_volume_accumulator: &ctx.user_volume_accumulator,
        buyback_fee_recipient: buyback::pick_for_slot(slot),
        bonding_curve_v2: &ctx.pdas.bonding_curve_v2,
        tip_recipient: &TIP_RECIPIENT,
        recent_blockhash: &blockhash,
        spendable_sol_in: ctx.spendable_sol_in,
        min_tokens_out: 0,
        tip_lamports: ctx.tip_lamports,
        cu_limit: ctx.cu_limit,
        cu_price_micro_lamports: ctx.cu_price_micro_lamports,
    };
    build_signed_buy_tx(&inputs, &ctx.wallet, out);
}

/// Build + sign + submit one wallet buy via node1. Returns true if the
/// tx was queued onto the submit channel (NOT confirmation of landing).
/// In debug mode (no submitter wired) returns true after logging.
pub fn fire_buy(ctx: &BuyContext, slot: u64, out: &mut BuiltBuyTx) -> bool {
    build_signed(ctx, slot, out);
    let bytes = out.as_bytes();
    info!(
        wallet = %ctx.label,
        len = bytes.len(),
        spendable_sol_in = ctx.spendable_sol_in,
        slot,
        "buy tx built"
    );
    match ctx.submitter.as_ref() {
        Some(s) => {
            let queued = s.submit(bytes.to_vec());
            if queued {
                info!(wallet = %ctx.label, "buy tx submitted to node1");
            } else {
                warn!(wallet = %ctx.label, "buy tx submit dropped (node1 worker exited?)");
            }
            queued
        }
        None => {
            info!(
                wallet = %ctx.label,
                "buy tx not submitted (no submitter wired — debug mode)"
            );
            true
        }
    }
}
