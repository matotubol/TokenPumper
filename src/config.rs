use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    pub rpc_url: String,
    pub eater_amount: u64,
    #[serde(default)]
    pub debug: bool,
    #[serde(default)]
    pub validators_app_token: Option<String>,

    // ── Wallet sizing & paths ────────────────────────────────────────────
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    #[serde(default = "default_eater_path")]
    pub eater_path: PathBuf,
    #[serde(default = "default_funder_path")]
    pub funder_path: PathBuf,
    #[serde(default = "default_dev_path")]
    pub dev_path: PathBuf,
    #[serde(default = "default_keys_dir")]
    pub keys_dir: PathBuf,
    #[serde(default = "default_cache_dir")]
    pub cache_dir: PathBuf,

    // ── Shredstream ──────────────────────────────────────────────────────
    pub shredstream_grpc_url: String,
    #[serde(default = "default_jito_keypair_path")]
    pub jito_keypair_path: PathBuf,
    /// Public `ip:port` we advertise to Jito. Source IP of our gRPC
    /// connection MUST match `ip` here, otherwise heartbeats are rejected.
    pub shredstream_advertise: String,
    /// Local UDP `ip:port` to bind. Port should match `shredstream_advertise`.
    pub shredstream_bind: String,
    #[serde(default = "default_regions")]
    pub shredstream_regions: Vec<String>,
    #[serde(default)]
    pub slot_stream_pin_core: Option<usize>,
    #[serde(default = "default_recv_buffer_bytes")]
    pub shredstream_recv_buffer_bytes: usize,
    #[serde(default)]
    pub shredstream_busy_poll_us: u32,

    // ── Leader cache ─────────────────────────────────────────────────────
    #[serde(default = "default_focus_country")]
    pub focus_country: String,

    // ── Event detection ──────────────────────────────────────────────────
    /// Fire CREATE EVENT once a focus-country slot reaches this many data
    /// shreds. Empirically ~130 — slightly above the typical event-emit
    /// shred index, low enough to avoid waiting for the slot to finish.
    #[serde(default = "default_fire_at_shred_count")]
    pub fire_at_shred_count: u32,

    // ── IPFS / Pinata ────────────────────────────────────────────────────
    /// Pinata scoped-key JWT. Required when `ipfs_debugmode = false`.
    #[serde(default)]
    pub pinata_jwt: Option<String>,
    /// When true, skip Pinata API calls and return placeholder URIs. Lets
    /// you exercise the bootstrap flow without burning API quota.
    #[serde(default)]
    pub ipfs_debugmode: bool,
    /// Public gateway base used to build the URLs we put on-chain. Trailing
    /// slash optional.
    #[serde(default = "default_ipfs_gateway")]
    pub ipfs_gateway: String,

    // ── Token roster ─────────────────────────────────────────────────────
    /// When true, always launch the last entry in `cache/tokens.json` (the
    /// debug-reserved sentinel — `Testnet Taco` in the shipped roster) and
    /// never flip its `is_used`. When false, walk the roster top-to-bottom
    /// for the first `is_used == false` entry, excluding the final slot.
    #[serde(default)]
    pub token_debug: bool,

    // ── Launch tx ────────────────────────────────────────────────────────
    /// Lamports to spend on the dev buy bundled with `create_v2`. Default
    /// 0.1 SOL.
    #[serde(default = "default_buy_sol_lamports")]
    pub buy_sol_lamports: u64,
    /// Compute-unit limit on the creator's launch tx — sized for
    /// create_v2 + dev buy + ATA idempotent (~210k).
    #[serde(default = "default_cu_limit")]
    pub cu_limit: u32,
    /// Priority fee in micro-lamports per CU for the creator's launch
    /// (buy) tx. Each `[[accounts]]` entry has its own `cu_price_lamports`.
    #[serde(default = "default_cu_price_lamports")]
    pub creator_cu_buy_price_lamports: u64,
    /// Priority fee in micro-lamports per CU for the creator's sell-all tx.
    #[serde(default = "default_cu_price_lamports")]
    pub creator_cu_sell_price_lamports: u64,
    /// Global CU limit for "normal" buy txs (per-account buys, future
    /// uses) — distinct from the creator's launch tx which still uses
    /// `cu_limit` because create_v2 needs the extra CU.
    #[serde(default = "default_cu_normal_limit")]
    pub cu_buy_limit: u32,
    /// Global CU limit for sell txs. The dev sell-all is 4 ixs (CU
    /// price + CU limit + sell + tip); 95k is comfortable margin.
    #[serde(default = "default_cu_normal_limit")]
    pub cu_sell_limit: u32,

    /// Address Lookup Table containing the static program IDs and PDAs
    /// the launch tx references. Pre-warmed at startup; the dev tx uses
    /// 1-byte indices instead of inlining 32-byte pubkeys.
    #[serde(default = "default_address_lookup_table")]
    pub address_lookup_table: String,

    // ── node1 QUIC submitter ─────────────────────────────────────────────
    /// `host:port` of the regional node1 endpoint. Default = Frankfurt.
    #[serde(default = "default_node1_endpoint")]
    pub node1_endpoint: String,
    /// SNI for the QUIC handshake — same hostname as `node1_endpoint`.
    #[serde(default = "default_node1_server_name")]
    pub node1_server_name: String,
    /// 36-char UUID API key. None → skip the QUIC sender (debug runs).
    #[serde(default)]
    pub node1_api_key: Option<String>,
    /// Tip in lamports paid out to a node1 tip wallet inside the launch
    /// tx. Min per docs = 0.001 SOL = 1_000_000 lamports.
    #[serde(default = "default_node1_tip_lamports")]
    pub node1_tip_lamports: u64,

    // ── Sell tx ──────────────────────────────────────────────────────────
    /// Slippage floor on the dev sell-all. 0 = accept any output (safe
    /// when landing matters more than price).
    #[serde(default)]
    pub sell_min_sol_output_lamports: u64,

    // ── Curve subscribe (Yellowstone gRPC) ───────────────────────────────
    /// Yellowstone gRPC endpoint, e.g. `https://your-endpoint.rpcpool.com:443`.
    /// `None` disables the reserves stream.
    #[serde(default)]
    pub curve_sub_endpoint: Option<String>,
    /// `x-token` value the provider issues per customer.
    #[serde(default)]
    pub curve_sub_x_token: Option<String>,
    /// App-layer ping interval. Triton recommends < 30s to dodge proxy
    /// idle timeouts.
    #[serde(default = "default_curve_sub_ping_interval_secs")]
    pub curve_sub_ping_interval_secs: u64,

    #[serde(default)]
    pub accounts: Vec<AccountFunding>,
}

fn default_batch_size() -> usize {
    15
}
fn default_eater_path() -> PathBuf {
    PathBuf::from("keys/eater.json")
}
fn default_funder_path() -> PathBuf {
    PathBuf::from("keys/funder/key.json")
}
fn default_dev_path() -> PathBuf {
    PathBuf::from("keys/dev/key.json")
}
fn default_keys_dir() -> PathBuf {
    PathBuf::from("keys")
}
fn default_cache_dir() -> PathBuf {
    PathBuf::from("cache")
}
fn default_jito_keypair_path() -> PathBuf {
    PathBuf::from("keys/jitoshreds.json")
}
fn default_regions() -> Vec<String> {
    vec!["frankfurt".to_string()]
}
fn default_recv_buffer_bytes() -> usize {
    64 * 1024 * 1024
}
fn default_focus_country() -> String {
    "DE".to_string()
}
fn default_fire_at_shred_count() -> u32 {
    130
}
fn default_ipfs_gateway() -> String {
    "https://gateway.pinata.cloud/ipfs/".to_string()
}
fn default_buy_sol_lamports() -> u64 {
    100_000_000 // 0.1 SOL
}
fn default_cu_limit() -> u32 {
    210_000
}
fn default_cu_price_lamports() -> u64 {
    100_000
}
fn default_cu_normal_limit() -> u32 {
    95_000
}
fn default_node1_endpoint() -> String {
    "fra.node1.me:16666".to_string()
}
fn default_node1_server_name() -> String {
    "fra.node1.me".to_string()
}
fn default_node1_tip_lamports() -> u64 {
    1_000_000 // 0.001 SOL — node1 minimum
}
fn default_address_lookup_table() -> String {
    "J7tuiJanfndJWHzdLEgxFVwFkdyaryi96tjxwhPgckse".to_string()
}
fn default_curve_sub_ping_interval_secs() -> u64 {
    25
}

#[derive(Deserialize)]
pub struct AccountFunding {
    pub index: usize,
    pub amount: u64,
    pub cu_price_lamports: u64,
}

impl Config {
    pub fn load() -> Result<Self> {
        let raw = fs::read_to_string("config.toml").context("reading config.toml")?;
        toml::from_str(&raw).context("parsing config.toml")
    }
}
