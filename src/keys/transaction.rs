use ed25519_dalek::{Signer, SigningKey};

const SYSTEM_PROGRAM: [u8; 32] = [0; 32];
pub const LAMPORTS_PER_SIGNATURE: u64 = 5_000;
// (data_len + 128) * 3480 * 2 for a system account with 0-byte data.
pub const RENT_EXEMPT_MIN_LAMPORTS: u64 = 890_880;
// max children per consolidated sweep tx: 113N + 166 ≤ 1232 → N ≤ 9.
pub const MAX_CHILDREN_PER_SWEEP_TX: usize = 9;

pub fn build_consolidated_sweep(
    eater: &SigningKey,
    children: &[&SigningKey],
    amounts: &[u64],
    recent_blockhash: &[u8; 32],
) -> Vec<u8> {
    assert_eq!(children.len(), amounts.len());
    let n = children.len();
    let eater_pk = eater.verifying_key().to_bytes();

    let mut account_keys: Vec<[u8; 32]> = Vec::with_capacity(n + 2);
    account_keys.push(eater_pk);
    for c in children {
        account_keys.push(c.verifying_key().to_bytes());
    }
    account_keys.push(SYSTEM_PROGRAM);

    let system_program_index = (n + 1) as u8;

    let mut message = Vec::with_capacity(166 + n * 113);
    message.extend_from_slice(&[(n + 1) as u8, 0u8, 1u8]);
    push_shortvec(&mut message, account_keys.len() as u16);
    for k in &account_keys {
        message.extend_from_slice(k);
    }
    message.extend_from_slice(recent_blockhash);
    push_shortvec(&mut message, n as u16);
    for (i, &amount) in amounts.iter().enumerate() {
        message.push(system_program_index);
        push_shortvec(&mut message, 2);
        message.push((i + 1) as u8);
        message.push(0);
        push_shortvec(&mut message, 12);
        message.extend_from_slice(&2u32.to_le_bytes());
        message.extend_from_slice(&amount.to_le_bytes());
    }

    let eater_sig = eater.sign(&message).to_bytes();
    let child_sigs: Vec<[u8; 64]> = children.iter().map(|c| c.sign(&message).to_bytes()).collect();

    let mut tx = Vec::with_capacity(1 + 64 * (n + 1) + message.len());
    push_shortvec(&mut tx, (n + 1) as u16);
    tx.extend_from_slice(&eater_sig);
    for sig in &child_sigs {
        tx.extend_from_slice(sig);
    }
    tx.extend_from_slice(&message);
    tx
}

pub fn build_distribute(
    sender: &SigningKey,
    recipients: &[([u8; 32], u64)],
    recent_blockhash: &[u8; 32],
) -> Vec<u8> {
    let n = recipients.len();
    let sender_pk = sender.verifying_key().to_bytes();

    let mut account_keys: Vec<[u8; 32]> = Vec::with_capacity(n + 2);
    account_keys.push(sender_pk);
    for (pk, _) in recipients {
        account_keys.push(*pk);
    }
    account_keys.push(SYSTEM_PROGRAM);

    let system_program_index = (n + 1) as u8;

    let mut message = Vec::with_capacity(166 + n * 49);
    message.extend_from_slice(&[1u8, 0, 1]);
    push_shortvec(&mut message, account_keys.len() as u16);
    for k in &account_keys {
        message.extend_from_slice(k);
    }
    message.extend_from_slice(recent_blockhash);
    push_shortvec(&mut message, n as u16);
    for (i, (_, amount)) in recipients.iter().enumerate() {
        message.push(system_program_index);
        push_shortvec(&mut message, 2);
        message.push(0);
        message.push((i + 1) as u8);
        push_shortvec(&mut message, 12);
        message.extend_from_slice(&2u32.to_le_bytes());
        message.extend_from_slice(&amount.to_le_bytes());
    }

    let sender_sig = sender.sign(&message).to_bytes();

    let mut tx = Vec::with_capacity(1 + 64 + message.len());
    push_shortvec(&mut tx, 1);
    tx.extend_from_slice(&sender_sig);
    tx.extend_from_slice(&message);
    tx
}

fn push_shortvec(out: &mut Vec<u8>, mut n: u16) {
    loop {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            return;
        }
        byte |= 0x80;
        out.push(byte);
    }
}
