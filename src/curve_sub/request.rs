//! Builders for outbound `SubscribeRequest`s — initial filter and ping.

use std::collections::HashMap;

use super::decode::SLICES;
use super::proto::geyser::{
    CommitmentLevel, SubscribeRequest, SubscribeRequestAccountsDataSlice,
    SubscribeRequestFilterAccounts, SubscribeRequestPing,
};
use super::AtaSubscription;

pub(super) const FILTER_CURVE: &str = "curve";
pub(super) const FILTER_ATAS: &str = "atas";

pub(super) fn build_filter_request(
    curve: &[u8; 32],
    atas: &[AtaSubscription],
) -> SubscribeRequest {
    let mut accounts: HashMap<String, SubscribeRequestFilterAccounts> = HashMap::with_capacity(2);
    accounts.insert(
        FILTER_CURVE.to_string(),
        SubscribeRequestFilterAccounts {
            account: vec![bs58::encode(curve).into_string()],
            ..Default::default()
        },
    );
    if !atas.is_empty() {
        accounts.insert(
            FILTER_ATAS.to_string(),
            SubscribeRequestFilterAccounts {
                account: atas
                    .iter()
                    .map(|a| bs58::encode(&a.ata).into_string())
                    .collect(),
                ..Default::default()
            },
        );
    }
    SubscribeRequest {
        accounts,
        accounts_data_slice: SLICES
            .iter()
            .map(|&(offset, length)| SubscribeRequestAccountsDataSlice { offset, length })
            .collect(),
        commitment: Some(CommitmentLevel::Processed as i32),
        ..Default::default()
    }
}

pub(super) fn build_ping_request() -> SubscribeRequest {
    SubscribeRequest {
        ping: Some(SubscribeRequestPing { id: 1 }),
        ..Default::default()
    }
}
