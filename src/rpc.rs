use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use reqwest::blocking::Client;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};

const RPC_TIMEOUT: Duration = Duration::from_secs(15);

fn client() -> Result<&'static Client> {
    static CLIENT: OnceLock<Client> = OnceLock::new();
    if let Some(c) = CLIENT.get() {
        return Ok(c);
    }
    let c = Client::builder()
        .timeout(RPC_TIMEOUT)
        .build()
        .context("building blocking RPC client")?;
    Ok(CLIENT.get_or_init(|| c))
}

#[derive(Deserialize)]
struct RpcEnvelope<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    code: i64,
    message: String,
    #[serde(default)]
    data: Option<Value>,
}

fn rpc_call<T: DeserializeOwned>(rpc_url: &str, body: Value, method: &str) -> Result<T> {
    let resp: RpcEnvelope<T> = client()?
        .post(rpc_url)
        .json(&body)
        .send()
        .with_context(|| format!("POST {rpc_url} ({method})"))?
        .error_for_status()
        .with_context(|| format!("RPC {method} returned non-2xx"))?
        .json()
        .with_context(|| format!("parsing JSON-RPC response for {method}"))?;
    if let Some(err) = resp.error {
        let data = err
            .data
            .as_ref()
            .map(|d| format!("  data: {d}"))
            .unwrap_or_default();
        bail!("RPC {method} error {}: {}{}", err.code, err.message, data);
    }
    resp.result
        .ok_or_else(|| anyhow!("RPC {method} response missing both result and error"))
}

pub fn balances(rpc_url: &str, pubkeys: &[&str]) -> Result<Vec<Option<u64>>> {
    #[derive(Deserialize)]
    struct AccountsResult {
        value: Vec<Option<Account>>,
    }
    #[derive(Deserialize)]
    struct Account {
        lamports: u64,
    }
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getMultipleAccounts",
        "params": [pubkeys, { "encoding": "base64", "commitment": "confirmed" }],
    });
    let result: AccountsResult = rpc_call(rpc_url, body, "getMultipleAccounts")?;
    Ok(result.value.into_iter().map(|a| a.map(|x| x.lamports)).collect())
}

pub fn balance(rpc_url: &str, pubkey: &str) -> Result<u64> {
    #[derive(Deserialize)]
    struct BalanceResult {
        value: u64,
    }
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getBalance",
        "params": [pubkey, { "commitment": "confirmed" }],
    });
    let result: BalanceResult = rpc_call(rpc_url, body, "getBalance")?;
    Ok(result.value)
}

/// Raw account bytes via `getAccountInfo` (base64 encoding). Errors if
/// the account doesn't exist. Used to grab pump.fun's `Global` at
/// startup without dragging in an Anchor client.
pub fn account_data(rpc_url: &str, pubkey_b58: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;

    #[derive(Deserialize)]
    struct Resp {
        value: Option<AccountInfo>,
    }
    #[derive(Deserialize)]
    struct AccountInfo {
        // [base64_string, "base64"]
        data: (String, String),
    }
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [pubkey_b58, { "encoding": "base64", "commitment": "confirmed" }],
    });
    let resp: Resp = rpc_call(rpc_url, body, "getAccountInfo")?;
    let info = resp
        .value
        .ok_or_else(|| anyhow!("account {pubkey_b58} not found"))?;
    base64::engine::general_purpose::STANDARD
        .decode(info.data.0)
        .context("decoding account data base64")
}

pub fn latest_blockhash(rpc_url: &str) -> Result<[u8; 32]> {
    #[derive(Deserialize)]
    struct BlockhashResult {
        value: BlockhashValue,
    }
    #[derive(Deserialize)]
    struct BlockhashValue {
        blockhash: String,
    }
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getLatestBlockhash",
        "params": [{ "commitment": "confirmed" }],
    });
    let result: BlockhashResult = rpc_call(rpc_url, body, "getLatestBlockhash")?;
    let bytes = bs58::decode(&result.value.blockhash)
        .into_vec()
        .context("decoding blockhash base58")?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("blockhash wrong size: got {} bytes, want 32", v.len()))
}

pub fn send_transaction(rpc_url: &str, tx_bytes: &[u8]) -> Result<String> {
    let encoded = bs58::encode(tx_bytes).into_string();
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "sendTransaction",
        "params": [encoded, { "skipPreflight": false, "preflightCommitment": "confirmed" }],
    });
    rpc_call(rpc_url, body, "sendTransaction")
}

/// `getSignatureStatuses` for one or more signatures. Each entry is `Some`
/// when the cluster has observed the signature; the inner `confirmation_status`
/// is `"processed"`, `"confirmed"`, or `"finalized"` (or `None` if pending).
pub fn signature_statuses(rpc_url: &str, sigs: &[&str]) -> Result<Vec<Option<SignatureStatus>>> {
    #[derive(Deserialize)]
    struct StatusResult {
        value: Vec<Option<SignatureStatus>>,
    }
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getSignatureStatuses",
        "params": [sigs, { "searchTransactionHistory": false }],
    });
    let result: StatusResult = rpc_call(rpc_url, body, "getSignatureStatuses")?;
    Ok(result.value)
}

#[derive(Debug, Deserialize)]
pub struct SignatureStatus {
    #[serde(rename = "confirmationStatus")]
    pub confirmation_status: Option<String>,
    pub err: Option<Value>,
}

impl SignatureStatus {
    pub fn is_confirmed_or_finalized(&self) -> bool {
        matches!(
            self.confirmation_status.as_deref(),
            Some("confirmed") | Some("finalized")
        )
    }
}
