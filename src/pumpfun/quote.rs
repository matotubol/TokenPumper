//! Bonding-curve buy quote. On a fresh `create_v2` the curve's reserves
//! are exactly the global init values, so the quote is fully
//! deterministic — no slippage cap, no safety pad.
//!
//! Uses the canonical pump.fun formula from the IDL docs (see
//! `buy_exact_sol_in` doc-comment, lines 798-814 of `pump.json`):
//!
//! ```text
//! total_fee_bps = protocol_fee_bps + creator_fee_bps
//! net_sol       = floor(spendable_sol * 10_000 / (10_000 + total_fee_bps))
//! protocol_fee  = ceil(net_sol * protocol_fee_bps / 10_000)
//! creator_fee   = ceil(net_sol * creator_fee_bps  / 10_000)
//! if net_sol + protocol_fee + creator_fee > spendable_sol:
//!     net_sol  -= overshoot
//! tokens_out    = floor((net_sol - 1) * vTokens / (vSol + net_sol - 1))
//! ```
//!
//! For the launch tx we feed `tokens_out` as the buy ix's `amount` and
//! `spendable_sol` as `max_sol_cost`. On a fresh curve the program's own
//! cost calculation will produce ≤ `max_sol_cost`, so the tx lands.

use super::global::GlobalCache;

#[derive(Debug, Clone, Copy)]
pub struct BuyQuote {
    /// Tokens delivered to the buyer (raw, includes mint decimals).
    pub amount_tokens: u64,
    /// Max lamports the program is allowed to charge — passed straight
    /// through as the buy ix's `max_sol_cost`.
    pub max_sol_cost: u64,
}

/// Pump.fun's actual on-chain fees, in basis points. Hardcoded to match
/// PumpBeast `pump/curve.rs:15-16` and the values its unit-tests verify
/// against on-chain truth (`30_000 → 29_629`, `2_000_000_000 → 1_975_308_641`).
///
/// `Global.creator_fee_basis_points` (read at startup) is misleading — it
/// reports `5` on mainnet but pump's `buy` charges `30` per the program's
/// internal constants (likely `25` platform + `5` creator combined into
/// one ceil-rounded fee). Reading the Global value made our quote
/// under-charge by 25 bps and pump rejected with `TooMuchSolRequired (6002)`:
/// `Right: 1002475247 vs Left: 1000000000` on a 1-SOL buy.
const PROTOCOL_FEE_BPS: u64 = 95;
const CREATOR_FEE_BPS: u64 = 30;

/// Quote a buy that spends exactly `sol_in` lamports against a curve in
/// its initial state. Caller responsibility: `sol_in > 0` and the global
/// cache reflects current chain state.
///
/// All multiplications widen to `u128` — `(net_sol - 1) * v_tokens`
/// alone is ~1e24 for a 1 SOL buy and would overflow u64.
pub fn quote_buy_at_create(global: &GlobalCache, sol_in: u64) -> BuyQuote {
    let v_sol = global.initial_virtual_sol_reserves;
    let v_tokens = global.initial_virtual_token_reserves;

    // Closed-form inverse of pump's two-ceil fee scheme. Single combined
    // (10_000 + 95 + 30 = 10_125) denom over-shoots the truth by at most
    // 1 lamport, so a single conditional decrement is exact. See
    // PumpBeast `reserves_delta_for_spendable` for the proof.
    const COMBINED: u128 = 10_000 + PROTOCOL_FEE_BPS as u128 + CREATOR_FEE_BPS as u128;
    let x = ((sol_in as u128) * 10_000 / COMBINED) as u64;

    let fp = ((x as u128 * PROTOCOL_FEE_BPS as u128 + 9_999) / 10_000) as u64;
    let fc = ((x as u128 * CREATOR_FEE_BPS as u128 + 9_999) / 10_000) as u64;
    let required = x as u128 + fp as u128 + fc as u128;
    let net_sol = x - ((required > sol_in as u128) as u64);

    // tokens_out = floor((net_sol - 1) * v_tok / (v_sol + net_sol - 1))
    // — the `-1` on the numerator side is on-chain truth; omitting it
    // over-counts tokens by ~tokens_out / net_sol per pump.fun IDL spec.
    let amount_tokens = if net_sol == 0 || v_tokens == 0 {
        0
    } else {
        let s = (net_sol - 1) as u128;
        let n = s * v_tokens as u128;
        let d = v_sol as u128 + s;
        (n / d) as u64
    };

    BuyQuote { amount_tokens, max_sol_cost: sol_in }
}
