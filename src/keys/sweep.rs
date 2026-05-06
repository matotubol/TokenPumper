use anyhow::Result;
use ed25519_dalek::SigningKey;

use super::{storage, transaction};
use crate::rpc;

pub struct Sender<'a> {
    pub label: String,
    pub key: &'a SigningKey,
    pub balance: u64,
}

pub struct SweepResult {
    pub label: String,
    pub outcome: Outcome,
}

pub enum Outcome {
    Sent { lamports: u64, signature: String },
    Skipped { reason: &'static str },
    Failed { error: String },
}

pub fn to_eater(
    rpc_url: &str,
    senders: &[Sender<'_>],
    eater: &SigningKey,
    eater_balance: u64,
    debug: bool,
) -> Result<Vec<SweepResult>> {
    let eater_pk = eater.verifying_key().to_bytes();

    let mut results: Vec<SweepResult> = Vec::new();
    let mut work: Vec<&Sender<'_>> = Vec::new();

    for s in senders {
        if s.balance == 0 {
            continue;
        }
        if s.key.verifying_key().to_bytes() == eater_pk {
            results.push(SweepResult {
                label: s.label.clone(),
                outcome: Outcome::Skipped {
                    reason: "destination equals source (this wallet is the eater)",
                },
            });
            continue;
        }
        work.push(s);
    }

    if work.is_empty() {
        return Ok(results);
    }

    if debug {
        for s in &work {
            results.push(SweepResult {
                label: s.label.clone(),
                outcome: Outcome::Skipped { reason: "debug mode: tx not sent" },
            });
        }
        return Ok(results);
    }

    println!(
        "\nSweeping to eater {} (currently {:.9} SOL, fee paid by eater)...",
        storage::pubkey_base58(eater),
        eater_balance as f64 / 1_000_000_000.0
    );
    let blockhash = rpc::latest_blockhash(rpc_url)?;

    let mut running_eater = eater_balance;
    for chunk in work.chunks(transaction::MAX_CHILDREN_PER_SWEEP_TX) {
        let chunk_total: u64 = chunk.iter().map(|s| s.balance).sum();
        let chunk_fee: u64 = (chunk.len() as u64 + 1) * transaction::LAMPORTS_PER_SIGNATURE;
        let projected = running_eater
            .saturating_add(chunk_total)
            .saturating_sub(chunk_fee);

        if projected < transaction::RENT_EXEMPT_MIN_LAMPORTS {
            for s in chunk {
                results.push(SweepResult {
                    label: s.label.clone(),
                    outcome: Outcome::Skipped {
                        reason: "would leave eater below rent-exempt minimum",
                    },
                });
            }
            continue;
        }

        let kps: Vec<&SigningKey> = chunk.iter().map(|s| s.key).collect();
        let amounts: Vec<u64> = chunk.iter().map(|s| s.balance).collect();
        let tx = transaction::build_consolidated_sweep(eater, &kps, &amounts, &blockhash);

        match rpc::send_transaction(rpc_url, &tx) {
            Ok(sig) => {
                running_eater = projected;
                for s in chunk {
                    results.push(SweepResult {
                        label: s.label.clone(),
                        outcome: Outcome::Sent {
                            lamports: s.balance,
                            signature: sig.clone(),
                        },
                    });
                }
            }
            Err(e) => {
                let err_str = e.to_string();
                for s in chunk {
                    results.push(SweepResult {
                        label: s.label.clone(),
                        outcome: Outcome::Failed {
                            error: err_str.clone(),
                        },
                    });
                }
            }
        }
    }
    Ok(results)
}

impl SweepResult {
    /// Signature emitted for this sweep, if it was actually sent. Used by
    /// the orchestrator to poll `getSignatureStatuses` instead of re-fetching
    /// every balance.
    pub fn signature(&self) -> Option<&str> {
        match &self.outcome {
            Outcome::Sent { signature, .. } => Some(signature.as_str()),
            _ => None,
        }
    }
}
