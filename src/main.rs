mod blockhash;
mod config;
mod curve_sub;
mod ipfs;
mod jito_auth;
mod keys;
mod leaders;
mod pumpfun;
mod rpc;
mod senders;
mod shreds;
mod ui;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::Result;
use tracing::info;

use leaders::LeaderCache;
use shreds::{SlotStreamConfig, SlotStreamHandle};

fn main() -> Result<()> {
    init_tracing();
    let cfg = config::Config::load()?;
    if cfg.debug {
        println!("DEBUG MODE: on-chain transactions will be skipped");
    }
    if cfg.ipfs_debugmode {
        println!("IPFS DEBUG MODE: pinata uploads will be skipped");
    }

    let mut tokens = match pumpfun::tokens::load_and_hydrate(&cfg.cache_dir, &cfg.keys_dir)? {
        Some(t) => t,
        None => {
            println!("no tokens.json yet created — exiting..");
            std::process::exit(1);
        }
    };
    let token_idx = pumpfun::tokens::pick(&tokens, cfg.token_debug)?;
    println!(
        "tokens loaded: {}; selected [{}] {} ({}){}",
        tokens.len(),
        token_idx,
        tokens[token_idx].name,
        tokens[token_idx].symbol,
        if cfg.token_debug { "  [DEBUG SENTINEL]" } else { "" },
    );

    // 1. Wallets settle first — sweep + recycle + refill + distribute. If
    //    this fails we haven't burned a Jito auth session yet.
    let prepared = keys::prepare(&cfg)?;

    // 2. IPFS: pin image + metadata JSON before going live so the `uri`
    //    is in hand when the trigger fires. The token is claimed (is_used
    //    flipped) only on a successful pin — and never in debug mode, so
    //    the sentinel survives across runs.
    let metadata = pumpfun::metadata::upload(&cfg, &tokens[token_idx])?;
    if !cfg.token_debug {
        pumpfun::tokens::mark_used(&cfg.cache_dir, &mut tokens, token_idx)?;
    }
    println!("\nToken metadata staged:");
    println!("  image: {}", metadata.image_uri);
    println!("  uri:   {}", metadata.uri);

    // 3. Tokio runtime — drives leader-cache fetch + jito auth tasks +
    //    heartbeat. The receiver itself runs on its own pinned OS thread.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    // 4. Leader cache: per-epoch, fetched once at startup.
    let leader_cache = Arc::new(rt.block_on(LeaderCache::bootstrap(
        &cfg.rpc_url,
        cfg.validators_app_token.as_deref(),
        &cfg.cache_dir,
        &cfg.focus_country,
    ))?);
    ui::print_leader_cache(&leader_cache);

    // 5. Blockhash cache: one synchronous fetch + 10s refresher task. The
    //    fire path will read this lock-free and stamp it into the launch
    //    message's recent_blockhash slot.
    let blockhash_cache =
        rt.block_on(blockhash::BlockhashCache::bootstrap(cfg.rpc_url.clone()))?;

    // 6. Global account: one-time decode for fee_recipient + bonding-curve
    //    init reserves + fee bps. Combined with `LaunchPdas::derive` this
    //    is everything the launch message needs that depends on chain state.
    let global = pumpfun::global::GlobalCache::bootstrap(&cfg.rpc_url)?;
    let mint_pubkey = tokens[token_idx].mint_pubkey()?;
    let dev_pubkey = prepared.dev.verifying_key().to_bytes();
    let launch_pdas = pumpfun::pda::LaunchPdas::derive(&mint_pubkey, &dev_pubkey);

    // 6b. ALT: pre-warm into memory so the fire path uses 1-byte indices
    //     instead of 32-byte pubkeys for every static program/PDA.
    let alt = pumpfun::alt::AltIndices::bootstrap(&cfg.rpc_url, &cfg.address_lookup_table)?;

    // 7. Quote the dev buy off the curve's init reserves — exact, since
    //    the curve hasn't traded yet at create time.
    let quote = pumpfun::quote::quote_buy_at_create(&global, cfg.buy_sol_lamports);
    println!(
        "buy quote @ {} lamports → {} tokens (max_sol_cost {} lamports)",
        cfg.buy_sol_lamports, quote.amount_tokens, quote.max_sol_cost,
    );

    let exit = Arc::new(AtomicBool::new(false));

    // 8. node1 QUIC submitter. Connects + authenticates synchronously so
    //    we fail fast if creds are wrong, then idles its event loop until
    //    the slot trigger pushes bytes through `Node1Submitter::submit`.
    let node1_handle = rt.block_on(spawn_node1(&cfg, &exit))?;
    let submitter = node1_handle.as_ref().map(|h| Arc::new(h.submitter()));

    // 9. Bundle every input the slot trigger needs. The actual tx is built
    //    + signed + submitted at fire time inside `shreds::stream::fire_launch`,
    //    using the latest cached blockhash so the message is fresh.
    let mint_signer = tokens[token_idx].mint_keypair()?;
    let launch_ctx = pumpfun::launch::LaunchContext {
        dev: prepared.dev.clone(),
        mint: mint_signer,
        user_pubkey: dev_pubkey,
        mint_pubkey,
        fee_recipient: global.fee_recipient,
        pdas: launch_pdas,
        alt,
        blockhash: blockhash_cache.clone(),
        name: tokens[token_idx].name.clone(),
        symbol: tokens[token_idx].symbol.clone(),
        uri: metadata.uri.clone(),
        buy_amount_tokens: quote.amount_tokens,
        buy_max_sol_cost: quote.max_sol_cost,
        tip_lamports: cfg.node1_tip_lamports,
        cu_limit: cfg.cu_limit,
        cu_price_micro_lamports: cfg.creator_cu_buy_price_lamports,
        submitter: submitter.clone(),
    };

    // 9b. Sell context — sized to the exact dev-buy quote (`amount_tokens`).
    //     Curve-sub spawns a sleep-then-fire task on its first observed
    //     account update, so the dev sell-all lands ~1s after pump's
    //     create_v2 + dev buy hits the chain.
    let sell_ctx = Arc::new(pumpfun::sell::SellContext {
        dev: prepared.dev.clone(),
        user_pubkey: dev_pubkey,
        mint_pubkey,
        fee_recipient: global.fee_recipient,
        pdas: launch_pdas,
        blockhash: blockhash_cache.clone(),
        amount_tokens: quote.amount_tokens,
        min_sol_output: cfg.sell_min_sol_output_lamports,
        tip_lamports: cfg.node1_tip_lamports,
        cu_limit: cfg.cu_sell_limit,
        cu_price_micro_lamports: cfg.creator_cu_sell_price_lamports,
        submitter: submitter.clone(),
    });
    println!(
        "sell context ready: {} tokens, min_sol_output={} lamports, tip={} lamports",
        quote.amount_tokens, cfg.sell_min_sol_output_lamports, cfg.node1_tip_lamports,
    );

    // 9c. Curve subscribe (Yellowstone gRPC): start streaming reserves
    //     for the deterministic bonding-curve PDA + every wallet's
    //     pre-derived ATA before launch fires. None of these accounts
    //     exist yet — provider stays silent until create_v2 lands, then
    //     curve reserves writes + per-wallet ATA creation/buys log. On
    //     the FIRST observed curve update we (a) fire a `buy_exact_sol_in`
    //     from every spread wallet immediately, and (b) schedule the dev
    //     `fire_sell` to run 1s later (lands after the wallet buys).
    //
    //     ATA list = dev + every child indexed in `[[accounts]]`. The ATA
    //     itself is `find_program_address([wallet, TOKEN_2022, mint],
    //     ATA_PROGRAM)`. The same per-wallet ATA + a freshly-derived
    //     `user_volume_accumulator` PDA feed into each BuyContext.
    let curve_sub_handle = match curve_sub::CurveSubConfig::from_config(&cfg) {
        Some(sub_cfg) => {
            let mut atas: Vec<curve_sub::AtaSubscription> = Vec::new();
            let mut buy_ctxs: Vec<Arc<pumpfun::buy::BuyContext>> = Vec::new();
            let mut wallet_sell_ctxs: Vec<Arc<pumpfun::sell::WalletSellContext>> = Vec::new();
            atas.push(curve_sub::AtaSubscription {
                label: "dev".to_string(),
                ata: launch_pdas.associated_user,
                wallet_index: None,
            });
            for (slot_idx, assignment) in prepared.assigner.iter().enumerate() {
                let wallet = &prepared.children[assignment.index];
                let wallet_pubkey = wallet.verifying_key().to_bytes();
                let ata = pumpfun::pda::associated_token_address(
                    &wallet_pubkey,
                    &mint_pubkey,
                    &pumpfun::ix_builder::ix::TOKEN_2022_PROGRAM_ID,
                );
                let user_volume_accumulator = pumpfun::pda::find_program_address(
                    &[b"user_volume_accumulator", &wallet_pubkey],
                    &pumpfun::ix_builder::ix::PUMP_PROGRAM_ID,
                )
                .0;
                let label = format!("wallet-{}", assignment.index + 1);
                atas.push(curve_sub::AtaSubscription {
                    label: label.clone(),
                    ata,
                    wallet_index: Some(slot_idx),
                });
                buy_ctxs.push(Arc::new(pumpfun::buy::BuyContext {
                    label: label.clone(),
                    wallet: wallet.clone(),
                    user_pubkey: wallet_pubkey,
                    mint_pubkey,
                    fee_recipient: global.fee_recipient,
                    pdas: launch_pdas,
                    associated_user: ata,
                    user_volume_accumulator,
                    blockhash: blockhash_cache.clone(),
                    spendable_sol_in: assignment.amount,
                    tip_lamports: cfg.node1_tip_lamports,
                    cu_limit: cfg.cu_buy_limit,
                    cu_price_micro_lamports: assignment.cu_price_lamports,
                    submitter: submitter.clone(),
                }));
                wallet_sell_ctxs.push(Arc::new(pumpfun::sell::WalletSellContext {
                    label,
                    wallet: wallet.clone(),
                    user_pubkey: wallet_pubkey,
                    mint_pubkey,
                    fee_recipient: global.fee_recipient,
                    pdas: launch_pdas,
                    associated_user: ata,
                    blockhash: blockhash_cache.clone(),
                    min_sol_output: cfg.sell_min_sol_output_lamports,
                    tip_lamports: cfg.node1_tip_lamports,
                    cu_limit: cfg.cu_sell_limit,
                    cu_price_micro_lamports: assignment.cu_price_lamports,
                    submitter: submitter.clone(),
                }));
            }
            // One AtomicU64 per spread wallet — slot index parallel to
            // `wallet_sell_ctxs`. Curve-sub stores the latest observed
            // ATA balance here on each update; the deadline task reads
            // and fires sells for any wallet with `> 0` at the 1s mark.
            let wallet_balances: Arc<Vec<AtomicU64>> = Arc::new(
                (0..wallet_sell_ctxs.len()).map(|_| AtomicU64::new(0)).collect(),
            );
            println!(
                "curve-sub: subscribing to curve {} + {} ATA(s) via {}",
                bs58::encode(&launch_pdas.bonding_curve).into_string(),
                atas.len(),
                sub_cfg.endpoint,
            );
            println!(
                "curve-sub: {} wallet buy(s) armed; per-wallet sells fire at +1s for any wallet whose balance lands first",
                buy_ctxs.len(),
            );
            let inputs = curve_sub::StreamInputs {
                curve: launch_pdas.bonding_curve,
                atas,
            };
            Some(rt.spawn(curve_sub::run(
                sub_cfg,
                inputs,
                buy_ctxs,
                wallet_sell_ctxs,
                wallet_balances,
                Some(sell_ctx.clone()),
                exit.clone(),
            )))
        }
        None => {
            println!("curve-sub: skipped (curve_sub_endpoint / curve_sub_x_token not set)");
            None
        }
    };

    // 10. Slot stream: auth handshake + heartbeat + UDP receiver.
    let slot_handle = rt.block_on(spawn_slot_stream(&cfg, &leader_cache, launch_ctx, &exit))?;

    println!("\nSlot stream running; press Ctrl+C to exit.");
    rt.block_on(tokio::signal::ctrl_c())?;
    info!("shutdown signal received");
    exit.store(true, Ordering::Relaxed);
    slot_handle.join();
    if let Some(h) = node1_handle {
        rt.block_on(h.shutdown());
    }
    if let Some(h) = curve_sub_handle {
        let _ = rt.block_on(h);
    }

    Ok(())
}

async fn spawn_node1(
    cfg: &config::Config,
    exit: &Arc<AtomicBool>,
) -> Result<Option<senders::node1::Node1Handle>> {
    let Some(raw_key) = cfg.node1_api_key.as_deref() else {
        println!("node1: skipped (node1_api_key not set in config.toml)");
        return Ok(None);
    };
    let api_key = senders::node1::parse_api_key(raw_key)?;
    let node_cfg = senders::node1::Node1Config {
        endpoint: cfg.node1_endpoint.clone(),
        server_name: cfg.node1_server_name.clone(),
        api_key,
    };
    let handle = senders::node1::spawn(node_cfg, exit.clone()).await?;
    println!(
        "node1: connected to {} (tip {} lamports)",
        cfg.node1_endpoint, cfg.node1_tip_lamports,
    );
    Ok(Some(handle))
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt().with_env_filter(filter).try_init();
}

async fn spawn_slot_stream(
    cfg: &config::Config,
    leader_cache: &Arc<LeaderCache>,
    launch_ctx: pumpfun::launch::LaunchContext,
    exit: &Arc<AtomicBool>,
) -> Result<SlotStreamHandle> {
    let stream_cfg = SlotStreamConfig::from_config(cfg)?;
    shreds::spawn(stream_cfg, leader_cache.clone(), launch_ctx, exit.clone()).await
}
