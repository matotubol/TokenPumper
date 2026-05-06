//! End-to-end wallet bootstrap: resolve → audit → sweep → settle → recycle
//! → refill → distribute. Returns a `Prepared` snapshot the runtime hands
//! to the rest of the program.
//!
//! Living here (rather than in `main.rs`) keeps the orchestrator close to
//! the building blocks it composes: every step is a `keys::*` submodule
//! call, plus a few `rpc::*` calls and `ui::*` prints.

use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;

use super::assigner::Assigner;
use super::sweep::{Sender, SweepResult};
use super::{batch, dev, distribute, eater, funder, pubkey_base58, refill, sweep, Origin};
use crate::config::Config;
use crate::rpc;
use crate::ui;

#[allow(dead_code)] // consumed by feature work that builds on this bootstrap
pub struct Prepared {
    pub eater: SigningKey,
    pub funder: SigningKey,
    pub dev: SigningKey,
    pub children: Vec<SigningKey>,
    pub assigner: Assigner,
}

pub fn prepare(cfg: &Config) -> Result<Prepared> {
    let eater = eater::ensure(&cfg.eater_path)?;
    let (funder_loaded, funder_origin) = funder::resolve(&cfg.funder_path)?;
    let (dev, _dev_origin) = dev::resolve(&cfg.dev_path)?;
    let (children_loaded, batch_origin) =
        batch::resolve_today(&cfg.keys_dir, cfg.batch_size)?;
    let assigner = Assigner::build(&cfg.accounts, cfg.batch_size)?;
    ui::print_assignments(&assigner);

    let funder_b58 = pubkey_base58(&funder_loaded);
    let eater_b58 = pubkey_base58(&eater);
    let dev_b58 = pubkey_base58(&dev);
    let child_b58s: Vec<String> = children_loaded.iter().map(pubkey_base58).collect();

    let batch_was_loaded = matches!(batch_origin, Origin::Loaded);
    let funder_was_loaded = matches!(funder_origin, Origin::Loaded);

    let mut to_check: Vec<&str> = vec![
        funder_b58.as_str(),
        eater_b58.as_str(),
        dev_b58.as_str(),
    ];
    if batch_was_loaded {
        to_check.extend(child_b58s.iter().map(String::as_str));
    }
    let lamports = rpc::balances(&cfg.rpc_url, &to_check)?;
    let funder_balance = lamports[0].unwrap_or(0);
    let eater_balance = lamports[1].unwrap_or(0);
    let dev_balance = lamports[2].unwrap_or(0);
    let child_balances: Vec<u64> = if batch_was_loaded {
        lamports[3..].iter().map(|l| l.unwrap_or(0)).collect()
    } else {
        vec![0; children_loaded.len()]
    };

    let dev_required = cfg.buy_sol_lamports + cfg.node1_tip_lamports + 50_000_000; // ~0.05 SOL slack for rent + sigs
    println!(
        "dev wallet  {}  balance={} lamports ({:.4} SOL){}",
        dev_b58,
        dev_balance,
        dev_balance as f64 / 1e9,
        if dev_balance < dev_required {
            format!(
                "  ⚠ UNDERFUNDED — need ≥{} lamports ({:.4} SOL) for buy+tip+rent",
                dev_required,
                dev_required as f64 / 1e9,
            )
        } else {
            String::new()
        },
    );

    ui::print_state(
        &funder_b58,
        funder_balance,
        &children_loaded,
        if batch_was_loaded { Some(&child_balances) } else { None },
    );

    let mut senders: Vec<Sender<'_>> = Vec::new();
    senders.push(Sender {
        label: "funder".to_string(),
        key: &funder_loaded,
        balance: funder_balance,
    });
    if batch_was_loaded {
        for (i, kp) in children_loaded.iter().enumerate() {
            senders.push(Sender {
                label: format!("{}.json", i + 1),
                key: kp,
                balance: child_balances[i],
            });
        }
    }

    let any_funded = senders.iter().any(|s| s.balance > 0);
    if any_funded {
        let sweep_results =
            sweep::to_eater(&cfg.rpc_url, &senders, &eater, eater_balance, cfg.debug)?;
        ui::print_sweep(&sweep_results);
        if !cfg.debug {
            wait_for_sweep_settled(&cfg.rpc_url, &sweep_results)?;
        }
    }

    // Safety gate: before overwriting any key file, every wallet we're
    // about to rotate must show 0 lamports on chain. RPC error → bail
    // (keep keys). Stranded funds → bail (keep keys). Funds-loss
    // prevention for the case where a sweep tx silently failed
    // (Outcome::Failed) or got skipped (rent-exempt protection).
    if !cfg.debug {
        verify_zero_before_recycle(
            &cfg.rpc_url,
            if funder_was_loaded { Some(&funder_loaded) } else { None },
            if batch_was_loaded { Some(&children_loaded) } else { None },
        )?;
    }

    let funder = if funder_was_loaded && !cfg.debug {
        println!("\nRecreating funder key...");
        funder::regenerate(&cfg.funder_path)?
    } else {
        funder_loaded
    };

    let children = if batch_was_loaded && !cfg.debug {
        println!("\nRecycling batch...");
        batch::regenerate_today(&cfg.keys_dir, cfg.batch_size)?
    } else {
        children_loaded
    };

    refill::eater_to_funder(&cfg.rpc_url, &eater, &funder, cfg.eater_amount, cfg.debug)?;
    distribute::funder_to_children(&cfg.rpc_url, &funder, &children, &assigner, cfg.debug)?;

    Ok(Prepared {
        eater,
        funder,
        dev,
        children,
        assigner,
    })
}

/// Pre-recycle safety net. Every wallet about to be overwritten on disk
/// must read back 0 lamports from chain (or not exist at all). Any
/// non-zero balance or RPC error → bail without rotating. Use this as
/// the last line of defence: even if the sweep tx loop silently dropped
/// a chunk via `Outcome::Failed` or `Outcome::Skipped`, this catches it
/// before the keys are gone.
fn verify_zero_before_recycle(
    rpc_url: &str,
    funder_to_rotate: Option<&SigningKey>,
    children_to_rotate: Option<&[SigningKey]>,
) -> Result<()> {
    let mut to_check: Vec<(String, String)> = Vec::new();
    if let Some(kp) = funder_to_rotate {
        to_check.push(("funder".to_string(), pubkey_base58(kp)));
    }
    if let Some(kps) = children_to_rotate {
        for (i, kp) in kps.iter().enumerate() {
            to_check.push((format!("{}.json", i + 1), pubkey_base58(kp)));
        }
    }
    if to_check.is_empty() {
        return Ok(());
    }

    let pubkey_refs: Vec<&str> = to_check.iter().map(|(_, p)| p.as_str()).collect();
    println!(
        "\nVerifying {} wallet(s) show 0 balance on chain before recycle...",
        to_check.len()
    );
    let balances = rpc::balances(rpc_url, &pubkey_refs)
        .context("RPC error during pre-recycle balance verification; refusing to rotate keys")?;

    let mut stranded: Vec<(String, u64)> = Vec::new();
    for ((label, _), bal) in to_check.iter().zip(balances.iter()) {
        match bal {
            None | Some(0) => {} // not on chain or empty — safe to rotate
            Some(lamports) => stranded.push((label.clone(), *lamports)),
        }
    }

    if !stranded.is_empty() {
        bail!(
            "pre-recycle verification: {} wallet(s) still hold funds, refusing to rotate keys: {:?}",
            stranded.len(),
            stranded,
        );
    }
    println!("All {} wallet(s) verified empty.", to_check.len());
    Ok(())
}

/// Poll `getSignatureStatuses` for every signature emitted by the sweep,
/// returning once all are confirmed/finalized or the timeout fires. Cheaper
/// than re-fetching every wallet's balance (one RPC call covers all sigs).
fn wait_for_sweep_settled(rpc_url: &str, results: &[SweepResult]) -> Result<()> {
    let sigs: Vec<&str> = results.iter().filter_map(|r| r.signature()).collect();
    if sigs.is_empty() {
        return Ok(());
    }
    println!("\nWaiting for sweep to confirm ({} sig(s))...", sigs.len());

    let timeout = Duration::from_secs(30);
    let interval = Duration::from_millis(500);
    let start = Instant::now();
    loop {
        let statuses = rpc::signature_statuses(rpc_url, &sigs)?;
        let pending: Vec<&str> = sigs
            .iter()
            .copied()
            .zip(statuses.iter())
            .filter_map(|(sig, status)| match status {
                Some(s) if s.is_confirmed_or_finalized() && s.err.is_none() => None,
                Some(s) if s.err.is_some() => {
                    Some(sig) // surface; treated as still-pending until timeout
                }
                _ => Some(sig),
            })
            .collect();
        if pending.is_empty() {
            println!("All sweep tx confirmed.");
            return Ok(());
        }
        if start.elapsed() > timeout {
            bail!(
                "sweep didn't confirm within {}s; pending sigs: {:?}",
                timeout.as_secs(),
                pending,
            );
        }
        thread::sleep(interval);
    }
}
