use anyhow::{bail, Result};
use ed25519_dalek::SigningKey;

use super::assigner::Assigner;
use super::{storage, transaction};
use crate::rpc;

/// Safety slack added on top of each jittered per-wallet amount. Covers
/// tips + signature fees so the wallet keeps headroom regardless of where
/// jitter lands inside [base*0.7, base].
const PER_WALLET_SAFETY_LAMPORTS: u64 = 100_000_000; // 0.1 SOL

pub fn funder_to_children(
    rpc_url: &str,
    funder: &SigningKey,
    children: &[SigningKey],
    assigner: &Assigner,
    debug: bool,
) -> Result<()> {
    if assigner.is_empty() {
        println!("\nNo accounts configured for distribution; skipping.");
        return Ok(());
    }

    for a in assigner.iter() {
        if a.index >= children.len() {
            bail!(
                "assignment index {} out of range 0..{}",
                a.index,
                children.len()
            );
        }
        if a.amount < transaction::RENT_EXEMPT_MIN_LAMPORTS {
            bail!(
                "assignment for index {} amount {} is below rent-exempt minimum {}; tx would fail",
                a.index + 1,
                a.amount,
                transaction::RENT_EXEMPT_MIN_LAMPORTS
            );
        }
    }

    let recipients: Vec<([u8; 32], u64)> = assigner
        .iter()
        .map(|a| {
            (
                children[a.index].verifying_key().to_bytes(),
                a.amount + PER_WALLET_SAFETY_LAMPORTS,
            )
        })
        .collect();
    let total: u64 = recipients.iter().map(|(_, a)| *a).sum();

    println!(
        "\nDistributing from funder to {} child(ren) (total {:.9} SOL)...",
        recipients.len(),
        total as f64 / 1_000_000_000.0
    );

    if debug {
        println!("  [debug] skipping distribute tx");
    } else {
        let blockhash = rpc::latest_blockhash(rpc_url)?;
        let tx = transaction::build_distribute(funder, &recipients, &blockhash);
        let sig = rpc::send_transaction(rpc_url, &tx)?;
        println!("  sent  sig: {sig}");
    }

    for a in assigner.iter() {
        let child_pk = storage::pubkey_base58(&children[a.index]);
        let sent = a.amount + PER_WALLET_SAFETY_LAMPORTS;
        println!(
            "  {}.json  {}  {:.9} SOL (jitter {:.9} + safety {:.9})  cu_price={} lamports",
            a.index + 1,
            child_pk,
            sent as f64 / 1_000_000_000.0,
            a.amount as f64 / 1_000_000_000.0,
            PER_WALLET_SAFETY_LAMPORTS as f64 / 1_000_000_000.0,
            a.cu_price_lamports,
        );
    }

    Ok(())
}
