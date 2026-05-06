use anyhow::{bail, Result};
use rand_core::{OsRng, RngCore};

use crate::config::AccountFunding;

#[derive(Debug, Clone)]
pub struct WalletAssignment {
    pub index: usize,
    pub amount: u64,
    pub cu_price_lamports: u64,
}

pub struct Assigner {
    slots: Vec<Option<WalletAssignment>>,
}

impl Assigner {
    pub fn build(accounts: &[AccountFunding], batch_size: usize) -> Result<Self> {
        let mut rng = OsRng;
        let mut slots: Vec<Option<WalletAssignment>> = (0..batch_size).map(|_| None).collect();

        for a in accounts {
            if a.index < 1 || a.index > batch_size {
                bail!(
                    "config account index {} out of range 1..={}",
                    a.index,
                    batch_size
                );
            }
            let slot = a.index - 1;
            if slots[slot].is_some() {
                bail!("duplicate config entry for index {}", a.index);
            }
            slots[slot] = Some(WalletAssignment {
                index: slot,
                amount: jitter(a.amount, &mut rng),
                cu_price_lamports: jitter(a.cu_price_lamports, &mut rng),
            });
        }
        Ok(Self { slots })
    }

    pub fn iter(&self) -> impl Iterator<Item = &WalletAssignment> {
        self.slots.iter().filter_map(|s| s.as_ref())
    }

    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// Uniform draw from [base * 0.7, base], inclusive. base == 0 → 0.
fn jitter(base: u64, rng: &mut impl RngCore) -> u64 {
    if base == 0 {
        return 0;
    }
    let min = ((base as u128) * 70 / 100) as u64;
    let span = base - min + 1;
    min + (rng.next_u64() % span)
}
