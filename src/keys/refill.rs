use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use ed25519_dalek::SigningKey;

use super::{storage, transaction};
use crate::rpc;

pub fn eater_to_funder(
    rpc_url: &str,
    eater: &SigningKey,
    funder: &SigningKey,
    amount: u64,
    debug: bool,
) -> Result<()> {
    let funder_pk = funder.verifying_key().to_bytes();
    let funder_b58 = storage::pubkey_base58(funder);

    println!(
        "\nRefilling funder with {:.9} SOL from eater...",
        amount as f64 / 1_000_000_000.0
    );

    if debug {
        println!("  [debug] skipping refill tx; funder {funder_b58}");
        return Ok(());
    }

    let pre = rpc::balance(rpc_url, &funder_b58)?;
    let target = pre.saturating_add(amount);

    let blockhash = rpc::latest_blockhash(rpc_url)?;
    let tx = transaction::build_distribute(eater, &[(funder_pk, amount)], &blockhash);
    let sig = rpc::send_transaction(rpc_url, &tx)?;
    println!("  sent  sig: {sig}");

    let timeout = Duration::from_secs(30);
    let interval = Duration::from_millis(500);
    let start = Instant::now();
    loop {
        let current = rpc::balance(rpc_url, &funder_b58)?;
        if current >= target {
            println!(
                "  confirmed; funder now {:.9} SOL",
                current as f64 / 1_000_000_000.0
            );
            return Ok(());
        }
        if start.elapsed() > timeout {
            bail!(
                "timeout waiting for funder balance ≥ {target} lamports; last seen {current}"
            );
        }
        thread::sleep(interval);
    }
}
