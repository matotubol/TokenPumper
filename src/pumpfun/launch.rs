//! Launch fire-time context. Bundles every input the slot trigger needs
//! to build + sign + submit a `create_v2 + buy + tip` tx the moment it
//! decides a focus slot has crossed `fire_at_shred_count`. Everything is
//! pre-computed at startup so the receiver thread does only:
//!   1. read the latest blockhash from the cache (lock-free),
//!   2. build the message, sign twice (~50 µs ed25519 each),
//!   3. push the wire bytes into the node1 worker's queue (try_send + waker).
//!
//! No RPC, no allocations beyond the one `Vec<u8>` for the submit copy.

use std::sync::Arc;

use ed25519_dalek::SigningKey;

use crate::blockhash::BlockhashCache;
use crate::pumpfun::alt::AltIndices;
use crate::pumpfun::buyback;
use crate::pumpfun::ix_builder::ix::LaunchInputs;
use crate::pumpfun::pda::LaunchPdas;
use crate::pumpfun::tx::{build_signed_launch_tx, BuiltLaunchTx};
use crate::senders::node1::{Node1Submitter, TIP_RECIPIENT};

pub struct LaunchContext {
    // Signers ------------------------------------------------------------
    /// Dev key (`keys/dev/key.json`) — creator + buyer in `create_v2 + buy`.
    pub dev: SigningKey,
    pub mint: SigningKey,

    // Pubkeys (bytes for direct splat into the message buffer) ----------
    pub user_pubkey: [u8; 32],
    pub mint_pubkey: [u8; 32],
    pub fee_recipient: [u8; 32],
    pub pdas: LaunchPdas,
    pub alt: AltIndices,

    // Per-launch dynamic data -------------------------------------------
    pub blockhash: BlockhashCache,
    pub name: String,
    pub symbol: String,
    pub uri: String,
    pub buy_amount_tokens: u64,
    pub buy_max_sol_cost: u64,
    pub tip_lamports: u64,
    pub cu_limit: u32,
    pub cu_price_micro_lamports: u64,

    /// `None` in debug mode (or when `node1_api_key` is unset). The
    /// trigger still builds + signs the tx so we exercise the build path,
    /// but skips the submit.
    pub submitter: Option<Arc<Node1Submitter>>,
}

/// Build + sign the launch tx into `out` using the current cached
/// blockhash and the buyback recipient deterministic in `slot_for_buyback`.
/// Shared between the fire path (`shreds::stream::fire_launch`) and the
/// startup `simulateTransaction` smoke test in main.
pub fn build_signed(ctx: &LaunchContext, slot_for_buyback: u64, out: &mut BuiltLaunchTx) {
    let blockhash = ctx.blockhash.current();
    let inputs = LaunchInputs {
        user: &ctx.user_pubkey,
        mint: &ctx.mint_pubkey,
        bonding_curve: &ctx.pdas.bonding_curve,
        associated_bonding_curve: &ctx.pdas.associated_bonding_curve,
        mayhem_state: &ctx.pdas.mayhem_state,
        mayhem_token_vault: &ctx.pdas.mayhem_token_vault,
        fee_recipient: &ctx.fee_recipient,
        creator_vault: &ctx.pdas.creator_vault,
        user_volume_accumulator: &ctx.pdas.user_volume_accumulator,
        associated_user: &ctx.pdas.associated_user,
        tip_recipient: &TIP_RECIPIENT,
        buyback_fee_recipient: buyback::pick_for_slot(slot_for_buyback),
        bonding_curve_v2: &ctx.pdas.bonding_curve_v2,
        recent_blockhash: &blockhash,
        name: &ctx.name,
        symbol: &ctx.symbol,
        uri: &ctx.uri,
        buy_amount_tokens: ctx.buy_amount_tokens,
        buy_max_sol_cost: ctx.buy_max_sol_cost,
        track_volume: true,
        tip_lamports: ctx.tip_lamports,
        cu_limit: ctx.cu_limit,
        cu_price_micro_lamports: ctx.cu_price_micro_lamports,
        alt: &ctx.alt,
    };
    build_signed_launch_tx(&inputs, &ctx.dev, &ctx.mint, out);
}
