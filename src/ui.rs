//! Pure CLI presentation. Lives outside `main.rs` so the orchestrator
//! reads as wiring; lives outside `keys::*` so the key modules don't have
//! to know about `Assigner` or the leader cache.

use ed25519_dalek::SigningKey;

use crate::keys::assigner::Assigner;
use crate::keys::sweep::{Outcome, SweepResult};
use crate::keys::pubkey_base58;
use crate::leaders::LeaderCache;

pub const LAMPORTS_PER_SOL: f64 = 1_000_000_000.0;

pub fn print_leader_cache(cache: &LeaderCache) {
    println!(
        "\nLeader cache: epoch {} ({} slots, {}..={}); focus slots: {}",
        cache.epoch(),
        cache.slots_in_epoch(),
        cache.epoch_start_slot(),
        cache.epoch_end_slot(),
        cache.focus_slot_count(),
    );
}

pub fn print_assignments(assigner: &Assigner) {
    if assigner.is_empty() {
        return;
    }
    println!("\nAssignments (randomized this run):");
    for a in assigner.iter() {
        println!(
            "  {:>2}.json  amount {:.9} SOL  cu_price {} lamports",
            a.index + 1,
            a.amount as f64 / LAMPORTS_PER_SOL,
            a.cu_price_lamports,
        );
    }
}

pub fn print_state(
    funder_pk: &str,
    funder_balance: u64,
    children: &[SigningKey],
    child_balances: Option<&[u64]>,
) {
    println!("\nState:");
    println!(
        "  funder    {}  {}",
        funder_pk,
        format_balance(funder_balance)
    );
    for (i, kp) in children.iter().enumerate() {
        let pk = pubkey_base58(kp);
        let bal_str = match child_balances {
            Some(bals) => format_balance(bals.get(i).copied().unwrap_or(0)),
            None => "fresh".to_string(),
        };
        println!("  {}.json   {}  {}", i + 1, pk, bal_str);
    }
}

pub fn print_sweep(results: &[SweepResult]) {
    if results.is_empty() {
        return;
    }
    println!("\nSweep results:");
    for r in results {
        match &r.outcome {
            Outcome::Sent { lamports, signature } => println!(
                "  {}: sent {:.9} SOL  sig: {}",
                r.label,
                *lamports as f64 / LAMPORTS_PER_SOL,
                signature
            ),
            Outcome::Skipped { reason } => println!("  {}: skipped ({})", r.label, reason),
            Outcome::Failed { error } => println!("  {}: FAILED  {}", r.label, error),
        }
    }
}

pub fn format_balance(lamports: u64) -> String {
    match lamports {
        0 => "0".to_string(),
        n => format!("{:.9} SOL", n as f64 / LAMPORTS_PER_SOL),
    }
}
