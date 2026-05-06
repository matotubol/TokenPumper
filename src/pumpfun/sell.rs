//! Sell-tx fire-time context. Bundles every input the sell trigger needs
//! to build + sign + submit a `sell + tip` tx for the dev wallet.
//! Mirrors `LaunchContext` but with one signer (the dev) and a smaller
//! account list — sell only needs ~half the launch's keys.
//!
//! Amount sold = the exact tokens we received from the dev buy bundled
//! with `create_v2`, computed by `quote::quote_buy_at_create` and stashed
//! here at startup. `min_sol_output` is configurable; default 0 means
//! "accept any output" (safe for a dev sell-all where pricing is
//! irrelevant compared to landing).

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use tracing::{info, warn};

use crate::blockhash::BlockhashCache;
use crate::pumpfun::buyback;
use crate::pumpfun::ix_builder::sell_ix::{
    build_signed_sell_tx, BuiltSellTx, SellInputs,
};
use crate::pumpfun::pda::LaunchPdas;
use crate::senders::node1::{Node1Submitter, TIP_RECIPIENT};

pub struct SellContext {
    pub dev: SigningKey,
    pub user_pubkey: [u8; 32],
    pub mint_pubkey: [u8; 32],
    pub fee_recipient: [u8; 32],
    pub pdas: LaunchPdas,

    pub blockhash: BlockhashCache,
    pub amount_tokens: u64,
    pub min_sol_output: u64,
    pub tip_lamports: u64,
    pub cu_limit: u32,
    pub cu_price_micro_lamports: u64,

    /// `None` in debug mode (or when `node1_api_key` is unset). Building
    /// + signing still runs so the path is exercised; the submit is a
    /// no-op log line.
    pub submitter: Option<Arc<Node1Submitter>>,
}

/// Build + sign the sell tx using the current cached blockhash. `slot`
/// rotates the buyback recipient across the 8-wallet pool.
pub fn build_signed(ctx: &SellContext, slot: u64, out: &mut BuiltSellTx) {
    let blockhash = ctx.blockhash.current();
    let inputs = SellInputs {
        user: &ctx.user_pubkey,
        mint: &ctx.mint_pubkey,
        bonding_curve: &ctx.pdas.bonding_curve,
        associated_bonding_curve: &ctx.pdas.associated_bonding_curve,
        associated_user: &ctx.pdas.associated_user,
        fee_recipient: &ctx.fee_recipient,
        creator_vault: &ctx.pdas.creator_vault,
        buyback_fee_recipient: buyback::pick_for_slot(slot),
        bonding_curve_v2: &ctx.pdas.bonding_curve_v2,
        tip_recipient: &TIP_RECIPIENT,
        recent_blockhash: &blockhash,
        amount_tokens: ctx.amount_tokens,
        min_sol_output: ctx.min_sol_output,
        tip_lamports: ctx.tip_lamports,
        cu_limit: ctx.cu_limit,
        cu_price_micro_lamports: ctx.cu_price_micro_lamports,
    };
    build_signed_sell_tx(&inputs, &ctx.dev, out);
}

/// Build + sign + submit one sell tx via node1. Returns true if the tx
/// was queued onto the submit channel (NOT confirmation of landing).
/// In debug mode (no submitter wired) returns true after logging.
pub fn fire_sell(ctx: &SellContext, slot: u64, out: &mut BuiltSellTx) -> bool {
    build_signed(ctx, slot, out);
    let bytes = out.as_bytes();
    info!(
        len = bytes.len(),
        amount_tokens = ctx.amount_tokens,
        min_sol_output = ctx.min_sol_output,
        slot,
        "sell tx built"
    );
    match ctx.submitter.as_ref() {
        Some(s) => {
            let queued = s.submit(bytes.to_vec());
            if queued {
                info!("sell tx submitted to node1");
            } else {
                warn!("sell tx submit dropped (node1 worker exited?)");
            }
            queued
        }
        None => {
            info!("sell tx not submitted (no submitter wired — debug mode)");
            true
        }
    }
}

// ── Per-spread-wallet sell ───────────────────────────────────────────────
//
// `WalletSellContext` is the per-wallet sibling of `SellContext`. It
// carries the wallet's signing key + its own ATA, but the sell amount is
// NOT known at startup — it's whatever the wallet ends up holding after
// `fire_buy` lands, observed by curve-sub via a Yellowstone ATA update
// and passed to `fire_wallet_sell` at deadline time.

pub struct WalletSellContext {
    /// Log-friendly tag — `"wallet-1"`, `"wallet-2"`, …
    pub label: String,

    pub wallet: SigningKey,
    pub user_pubkey: [u8; 32],
    pub mint_pubkey: [u8; 32],
    pub fee_recipient: [u8; 32],

    /// Per-launch (mint-level) PDAs shared with the dev: `bonding_curve`,
    /// `associated_bonding_curve`, `creator_vault` (keyed by the dev =
    /// creator, NOT the seller), `bonding_curve_v2`.
    pub pdas: LaunchPdas,
    /// This wallet's ATA — `find_program_address([wallet, TOKEN_2022, mint],
    /// ATA_PROGRAM)`. Pre-derived at startup.
    pub associated_user: [u8; 32],

    pub blockhash: BlockhashCache,
    pub min_sol_output: u64,
    pub tip_lamports: u64,
    pub cu_limit: u32,
    pub cu_price_micro_lamports: u64,

    pub submitter: Option<Arc<Node1Submitter>>,
}

/// Build + sign the per-wallet sell tx using the current cached blockhash
/// and a runtime-observed `amount_tokens` (from the wallet's ATA update).
/// `slot` rotates the buyback recipient across the 8-wallet pool.
pub fn build_signed_wallet(
    ctx: &WalletSellContext,
    slot: u64,
    amount_tokens: u64,
    out: &mut BuiltSellTx,
) {
    let blockhash = ctx.blockhash.current();
    let inputs = SellInputs {
        user: &ctx.user_pubkey,
        mint: &ctx.mint_pubkey,
        bonding_curve: &ctx.pdas.bonding_curve,
        associated_bonding_curve: &ctx.pdas.associated_bonding_curve,
        associated_user: &ctx.associated_user,
        fee_recipient: &ctx.fee_recipient,
        creator_vault: &ctx.pdas.creator_vault,
        buyback_fee_recipient: buyback::pick_for_slot(slot),
        bonding_curve_v2: &ctx.pdas.bonding_curve_v2,
        tip_recipient: &TIP_RECIPIENT,
        recent_blockhash: &blockhash,
        amount_tokens,
        min_sol_output: ctx.min_sol_output,
        tip_lamports: ctx.tip_lamports,
        cu_limit: ctx.cu_limit,
        cu_price_micro_lamports: ctx.cu_price_micro_lamports,
    };
    build_signed_sell_tx(&inputs, &ctx.wallet, out);
}

/// Build + sign + submit one wallet sell via node1. `amount_tokens` is
/// the observed ATA balance — caller is expected to skip wallets that
/// never reported a non-zero balance within the deadline.
pub fn fire_wallet_sell(
    ctx: &WalletSellContext,
    slot: u64,
    amount_tokens: u64,
    out: &mut BuiltSellTx,
) -> bool {
    build_signed_wallet(ctx, slot, amount_tokens, out);
    let bytes = out.as_bytes();
    info!(
        wallet = %ctx.label,
        len = bytes.len(),
        amount_tokens,
        min_sol_output = ctx.min_sol_output,
        slot,
        "wallet sell tx built"
    );
    match ctx.submitter.as_ref() {
        Some(s) => {
            let queued = s.submit(bytes.to_vec());
            if queued {
                info!(wallet = %ctx.label, "wallet sell tx submitted to node1");
            } else {
                warn!(wallet = %ctx.label, "wallet sell tx submit dropped (node1 worker exited?)");
            }
            queued
        }
        None => {
            info!(
                wallet = %ctx.label,
                "wallet sell tx not submitted (no submitter wired — debug mode)"
            );
            true
        }
    }
}
