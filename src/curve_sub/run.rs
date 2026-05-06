//! Long-lived task body. One bi-di gRPC stream multiplexing the curve
//! filter + the ATAs filter. Decodes per-filter, dispatches the sell
//! trigger off the first curve update, reconnects on stream close.

use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::{self, MissedTickBehavior};
use tonic::Code;
use tracing::{debug, error, info, warn};

use crate::pumpfun::buy::{fire_buy, BuyContext};
use crate::pumpfun::ix_builder::buy_exact_sol_ix::BuiltBuyTx;
use crate::pumpfun::ix_builder::sell_ix::BuiltSellTx;
use crate::pumpfun::sell::{fire_sell, fire_wallet_sell, SellContext, WalletSellContext};

use super::decode::{token_amount, Reserves, SLICE_TOTAL_LEN};
use super::proto::geyser::{geyser_client::GeyserClient, subscribe_update::UpdateOneof};
use super::request::{build_filter_request, build_ping_request, FILTER_ATAS, FILTER_CURVE};
use super::transport::{build_endpoint, ReqStream, XTokenInterceptor};
use super::{CurveSubConfig, StreamInputs};

/// Bounded mpsc capacity for outbound `SubscribeRequest`s — one initial
/// filter + one ping every `ping_interval_secs`. 8 is overkill but cheap.
const REQ_CHANNEL_CAPACITY: usize = 8;

/// Wakeup cadence for the exit-flag check. 200ms = 5 wakeups/sec while
/// idle, invisible on a multi-core runtime.
const EXIT_CHECK_INTERVAL: Duration = Duration::from_millis(200);

pub async fn run(
    cfg: CurveSubConfig,
    inputs: StreamInputs,
    buy_ctxs: Vec<Arc<BuyContext>>,
    wallet_sell_ctxs: Vec<Arc<WalletSellContext>>,
    wallet_balances: Arc<Vec<AtomicU64>>,
    sell_ctx: Option<Arc<SellContext>>,
    exit: Arc<AtomicBool>,
) {
    let curve_b58 = bs58::encode(&inputs.curve).into_string();
    let ata_labels: HashMap<[u8; 32], String> = inputs
        .atas
        .iter()
        .map(|a| (a.ata, a.label.clone()))
        .collect();
    // Routing for spread-wallet ATA updates → balance slot in the
    // shared atomics Vec. Dev's ATA has wallet_index = None so it never
    // appears here (its sell amount is the pre-computed quote, not
    // observed at runtime).
    let ata_to_wallet_idx: HashMap<[u8; 32], usize> = inputs
        .atas
        .iter()
        .filter_map(|a| a.wallet_index.map(|i| (a.ata, i)))
        .collect();
    info!(
        endpoint = %cfg.endpoint,
        curve = %curve_b58,
        ata_count = ata_labels.len(),
        "curve-sub task started"
    );

    let interceptor = match XTokenInterceptor::new(&cfg.x_token) {
        Ok(i) => i,
        Err(e) => {
            error!(error = %e, "curve-sub: x-token rejected");
            return;
        }
    };
    let endpoint = match build_endpoint(&cfg.endpoint) {
        Ok(ep) => ep,
        Err(e) => {
            error!(error = %e, "curve-sub: endpoint config invalid");
            return;
        }
    };

    let ping_period = Duration::from_secs(cfg.ping_interval_secs);

    // Latched across reconnects so a transient stream error can't cause
    // the buys/sell to fire twice.
    let mut first_signal_fired = false;

    while !exit.load(Ordering::Relaxed) {
        let channel = match endpoint.connect().await {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "curve-sub connect failed; retry in 1s");
                time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        let mut client = GeyserClient::with_interceptor(channel, interceptor.clone());

        let (req_tx, req_rx) = mpsc::channel(REQ_CHANNEL_CAPACITY);
        let req_stream = ReqStream { rx: req_rx };
        let mut updates = match client.subscribe(req_stream).await {
            Ok(r) => r.into_inner(),
            Err(status) => {
                if status.code() == Code::Unauthenticated {
                    error!(%status, "curve-sub: x-token rejected by server, bailing");
                    return;
                }
                warn!(%status, "curve-sub subscribe failed; retry in 1s");
                time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };

        if req_tx
            .send(build_filter_request(&inputs.curve, &inputs.atas))
            .await
            .is_err()
        {
            warn!("curve-sub initial send failed; retry in 1s");
            time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        info!(
            curve = %curve_b58,
            atas = ata_labels.len(),
            "curve-sub connected"
        );

        // First ping fires `ping_period` from now — we just sent the
        // initial sub, no need to bang the wire.
        let mut ping_ticker = time::interval_at(time::Instant::now() + ping_period, ping_period);
        ping_ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut exit_check = time::interval(EXIT_CHECK_INTERVAL);
        exit_check.set_missed_tick_behavior(MissedTickBehavior::Skip);

        // Reset baseline on each (re)connect — first curve update of a
        // new stream is logged as the baseline.
        let mut prev = Reserves::default();

        loop {
            if exit.load(Ordering::Relaxed) {
                info!("curve-sub: exit signal observed, draining");
                return;
            }
            tokio::select! {
                biased;
                _ = exit_check.tick() => continue,

                msg = updates.message() => match msg {
                    Ok(Some(update)) => {
                        let filters = update.filters.clone();
                        let Some(oneof) = update.update_oneof else { continue };
                        match oneof {
                            UpdateOneof::Account(acc) => {
                                let slot = acc.slot;
                                let Some(info) = acc.account else { continue };
                                let Ok(slice): Result<[u8; SLICE_TOTAL_LEN], _> =
                                    info.data.as_slice().try_into()
                                else {
                                    warn!(
                                        slot,
                                        len = info.data.len(),
                                        "curve-sub: unexpected slice length"
                                    );
                                    continue;
                                };

                                if filters.iter().any(|f| f == FILTER_CURVE) {
                                    handle_curve(
                                        &slice,
                                        slot,
                                        &mut prev,
                                        &mut first_signal_fired,
                                        &buy_ctxs,
                                        &wallet_sell_ctxs,
                                        &wallet_balances,
                                        sell_ctx.as_ref(),
                                    );
                                } else if filters.iter().any(|f| f == FILTER_ATAS) {
                                    let pubkey: [u8; 32] = match info.pubkey.as_slice().try_into() {
                                        Ok(p) => p,
                                        Err(_) => {
                                            warn!(slot, "curve-sub: ata update missing pubkey");
                                            continue;
                                        }
                                    };
                                    let label = ata_labels
                                        .get(&pubkey)
                                        .map(String::as_str)
                                        .unwrap_or("?");
                                    let amount = token_amount(&slice);
                                    info!(slot, wallet = label, amount, "ata update");
                                    if let Some(idx) = ata_to_wallet_idx.get(&pubkey) {
                                        // Latest-write-wins; the deadline task
                                        // reads whatever was last seen by the
                                        // 1s mark. CreateIdempotent → 0 is
                                        // overwritten by the buy → real amount.
                                        wallet_balances[*idx]
                                            .store(amount, Ordering::Relaxed);
                                    }
                                }
                            }
                            UpdateOneof::Pong(_) => debug!("curve-sub pong"),
                            _ => {}
                        }
                    }
                    Ok(None) => {
                        warn!("curve-sub stream closed by server; reconnecting");
                        break;
                    }
                    Err(status) => {
                        warn!(%status, "curve-sub stream error; reconnecting");
                        break;
                    }
                },

                _ = ping_ticker.tick() => {
                    if req_tx.send(build_ping_request()).await.is_err() {
                        warn!("curve-sub req channel closed during ping; reconnecting");
                        break;
                    }
                }
            }
        }

        time::sleep(Duration::from_secs(1)).await;
    }
    info!("curve-sub task exiting");
}

fn handle_curve(
    slice: &[u8; SLICE_TOTAL_LEN],
    slot: u64,
    prev: &mut Reserves,
    first_signal_fired: &mut bool,
    buy_ctxs: &[Arc<BuyContext>],
    wallet_sell_ctxs: &[Arc<WalletSellContext>],
    wallet_balances: &Arc<Vec<AtomicU64>>,
    sell_ctx: Option<&Arc<SellContext>>,
) {
    let curr = Reserves::from_slice(slice);
    if prev.v_tok == 0 {
        info!(
            slot,
            v_tok = curr.v_tok,
            v_sol = curr.v_sol,
            r_tok = curr.r_tok,
            r_sol = curr.r_sol,
            "tracked reserves (baseline)"
        );
    } else {
        let delta = curr.r_sol.wrapping_sub(prev.r_sol) as i64;
        info!(
            slot,
            v_tok = curr.v_tok,
            v_sol = curr.v_sol,
            r_tok = curr.r_tok,
            r_sol = curr.r_sol,
            delta,
            "tracked reserves"
        );
    }
    *prev = curr;

    // First-signal trigger: on the very first curve update, fire every
    // configured spread-wallet buy immediately, then schedule the dev
    // sell + per-wallet sells 1s out. Latched across reconnects via
    // `first_signal_fired` so transient stream errors can't double-fire.
    if *first_signal_fired {
        return;
    }
    *first_signal_fired = true;

    // Buys fire synchronously — `fire_buy` only builds + signs (~50µs)
    // then pushes bytes into the node1 submitter's mpsc; the actual UDP
    // send is on the node1 worker, so this doesn't stall the stream loop.
    let mut buy_buf = BuiltBuyTx::new();
    for ctx in buy_ctxs.iter() {
        fire_buy(ctx.as_ref(), slot, &mut buy_buf);
    }
    if !buy_ctxs.is_empty() {
        info!(slot, count = buy_ctxs.len(), "wallet buys fired");
    }

    // Deadline task: 1s after the first curve update, fire the dev sell
    // (known amount) and every spread wallet whose balance landed within
    // the window. The atomic load is whatever the most recent ATA update
    // wrote — usually the post-buy balance; CreateIdempotent's 0 is
    // overwritten by the buy. Wallets still showing 0 missed the window
    // and stay locked — we'd be selling against post-dev-sell reserves.
    let dev_sell = sell_ctx.cloned();
    let wallets = wallet_sell_ctxs.to_vec();
    let balances = Arc::clone(wallet_balances);
    let fire_slot = slot;
    tokio::spawn(async move {
        time::sleep(Duration::from_secs(1)).await;
        let mut sell_buf = BuiltSellTx::new();
        if let Some(sc) = dev_sell.as_ref() {
            fire_sell(sc.as_ref(), fire_slot, &mut sell_buf);
        }
        let mut fired = 0usize;
        let mut skipped = 0usize;
        for (idx, ctx) in wallets.iter().enumerate() {
            let amount = balances[idx].load(Ordering::Relaxed);
            if amount == 0 {
                info!(
                    wallet = %ctx.label,
                    "wallet sell skipped: no balance observed by 1s deadline"
                );
                skipped += 1;
                continue;
            }
            fire_wallet_sell(ctx.as_ref(), fire_slot, amount, &mut sell_buf);
            fired += 1;
        }
        info!(
            slot = fire_slot,
            dev = dev_sell.is_some(),
            wallets_fired = fired,
            wallets_skipped = skipped,
            "deadline batch sells dispatched"
        );
    });
    info!(
        slot,
        wallets = wallet_sell_ctxs.len(),
        "sells scheduled: dev + per-wallet fire in 1s",
    );
}
