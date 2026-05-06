//! node1 QUIC submitter — Quinn-based, ports node1's reference example
//! verbatim. Quiche/BoringSSL refused to omit the ALPN extension and
//! node1's server rejects every ALPN we offer (`solana-tpu`, `node1-tpu`,
//! `h3`, …). Rustls + empty `alpn_protocols` skips the extension entirely
//! and the server is happy with that — same path the docs use.
//!
//! Wire protocol per `docs/node1.md`:
//!   1. Open the first bidi stream. Write the 16-byte UUID API key.
//!      `finish()`. Server replies 1 byte: `0` ok.
//!   2. Per tx: open a fresh bidi stream. Write the raw tx bytes (no
//!      length prefix). `finish()`. Read 6-byte response header
//!      (BE u16 status + BE u32 msg_len) + msg_len UTF-8 bytes.
//!   3. Keep-alive every 15 s — Quinn handles this for us via
//!      `TransportConfig::keep_alive_interval`.
//!
//! The slot trigger calls [`Node1Submitter::submit`] from the receiver
//! thread (not a tokio context). `submit` is a non-blocking
//! `try_send` on a `tokio::mpsc::UnboundedSender` plus an internal
//! tokio task picks it up and writes the bidi stream.

use std::net::ToSocketAddrs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Connection, Endpoint, IdleTimeout, TransportConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::{info, warn};

/// `node1YtWCoTwwVYTFLfS19zquRQzYX332hs1HEuRBjC` — one of node1's six tip
/// wallets, decoded once and inlined as raw bytes. Used as the recipient
/// of the tip-transfer ix appended to each launch tx.
pub const TIP_RECIPIENT: [u8; 32] = [
    11, 187, 220, 239, 133, 123, 195, 55, 149, 111, 123, 224, 192, 86, 213, 149, 14, 232, 182, 21,
    240, 243, 55, 45, 209, 33, 43, 114, 69, 121, 219, 23,
];

const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const AUTH_TIMEOUT: Duration = Duration::from_secs(5);
const SEND_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
pub struct Node1Config {
    pub endpoint: String,
    pub server_name: String,
    pub api_key: [u8; 16],
}

/// Lock-free, clone-able submit handle. Cheap enough for the slot trigger
/// to hold a copy. Calling `submit` does an `UnboundedSender::send` —
/// non-blocking, no awaiting, safe from outside any tokio context.
#[derive(Clone)]
pub struct Node1Submitter {
    tx: UnboundedSender<Vec<u8>>,
}

impl Node1Submitter {
    pub fn submit(&self, bytes: Vec<u8>) -> bool {
        match self.tx.send(bytes) {
            Ok(()) => true,
            Err(_) => {
                warn!("node1 worker exited — submit dropped");
                false
            }
        }
    }
}

pub struct Node1Handle {
    submitter: Node1Submitter,
    worker: Option<JoinHandle<()>>,
    endpoint: Endpoint,
}

impl Node1Handle {
    pub fn submitter(&self) -> Node1Submitter {
        self.submitter.clone()
    }

    /// Drop the submit channel, wait for the worker task to drain, close
    /// the QUIC endpoint cleanly. Block until `endpoint.wait_idle()`
    /// returns so the FIN packets land before the runtime shuts down.
    pub async fn shutdown(mut self) {
        drop(self.submitter);
        if let Some(h) = self.worker.take() {
            let _ = h.await;
        }
        self.endpoint.close(0u32.into(), b"shutdown");
        self.endpoint.wait_idle().await;
    }
}

/// Connect, complete the 16-byte UUID handshake on stream 0, then return
/// a handle. Blocks (via the tokio `Handle`) for up to
/// `CONNECT_TIMEOUT + AUTH_TIMEOUT` waiting for auth.
pub async fn spawn(cfg: Node1Config, exit: Arc<AtomicBool>) -> Result<Node1Handle> {
    install_crypto_provider();

    let peer_addr = resolve(&cfg.endpoint)?;
    let endpoint = build_endpoint()?;

    info!(endpoint = %cfg.endpoint, server_name = %cfg.server_name, "node1 quic connecting");
    let conn = timeout(
        CONNECT_TIMEOUT,
        endpoint
            .connect(peer_addr, &cfg.server_name)
            .context("endpoint.connect")?,
    )
    .await
    .map_err(|_| anyhow!("node1 connect timed out after {:?}", CONNECT_TIMEOUT))?
    .context("quic handshake")?;

    timeout(AUTH_TIMEOUT, authenticate(&conn, &cfg.api_key))
        .await
        .map_err(|_| anyhow!("node1 auth timed out after {:?}", AUTH_TIMEOUT))?
        .context("node1 auth")?;
    info!("node1 auth ok");

    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let conn_for_worker = conn.clone();
    let exit_for_worker = exit.clone();
    let worker = tokio::spawn(run_worker(conn_for_worker, rx, exit_for_worker));

    Ok(Node1Handle {
        submitter: Node1Submitter { tx },
        worker: Some(worker),
        endpoint,
    })
}

/// Parse a 36-char hyphenated UUID into 16 raw bytes. Saves the `uuid`
/// crate dependency.
pub fn parse_api_key(s: &str) -> Result<[u8; 16]> {
    let stripped: String = s.chars().filter(|c| *c != '-').collect();
    if stripped.len() != 32 {
        bail!("api key must be a 36-char UUID, got {}", s.len());
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&stripped[i * 2..i * 2 + 2], 16)
            .with_context(|| format!("invalid hex byte at offset {} in api key", i * 2))?;
    }
    Ok(out)
}

// ── Internals ──────────────────────────────────────────────────────────

fn resolve(host_port: &str) -> Result<std::net::SocketAddr> {
    host_port
        .to_socket_addrs()
        .with_context(|| format!("resolving {}", host_port))?
        .find(std::net::SocketAddr::is_ipv4)
        .ok_or_else(|| anyhow!("no IPv4 address resolved for {}", host_port))
}

fn build_endpoint() -> Result<Endpoint> {
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();

    let quic_crypto =
        QuicClientConfig::try_from(crypto).context("QuicClientConfig::try_from(rustls)")?;
    let mut client_config = ClientConfig::new(Arc::new(quic_crypto));

    let mut transport = TransportConfig::default();
    transport
        .max_idle_timeout(Some(IdleTimeout::try_from(MAX_IDLE_TIMEOUT).unwrap()))
        .keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
    client_config.transport_config(Arc::new(transport));

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).context("Endpoint::client")?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

async fn authenticate(conn: &Connection, api_key: &[u8; 16]) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await.context("auth open_bi")?;
    send.write_all(api_key).await.context("auth write_all")?;
    send.finish().context("auth finish")?;

    // Server replies with one byte: 0 = ok, anything else = rejected.
    let reply = recv.read_to_end(8).await.context("auth read reply")?;
    match reply.first().copied() {
        Some(0) => Ok(()),
        Some(code) => bail!("node1 auth rejected, reply byte = {}", code),
        None => bail!("node1 auth: empty server reply"),
    }
}

async fn run_worker(
    conn: Connection,
    mut rx: UnboundedReceiver<Vec<u8>>,
    exit: Arc<AtomicBool>,
) {
    loop {
        if exit.load(Ordering::Relaxed) {
            info!("node1 worker exit requested");
            return;
        }
        tokio::select! {
            biased;
            maybe_bytes = rx.recv() => {
                let Some(bytes) = maybe_bytes else {
                    info!("node1 submit channel closed; worker exiting");
                    return;
                };
                let conn = conn.clone();
                tokio::spawn(send_one(conn, bytes));
            }
            reason = conn.closed() => {
                warn!(?reason, "node1 connection closed");
                return;
            }
        }
    }
}

async fn send_one(conn: Connection, bytes: Vec<u8>) {
    let len = bytes.len();
    let result = timeout(SEND_TIMEOUT, send_one_inner(&conn, &bytes)).await;
    match result {
        Ok(Ok((status, msg))) => {
            if status == 200 {
                info!(status, %msg, len, "node1 tx accepted");
            } else {
                warn!(status, %msg, len, "node1 tx rejected");
            }
        }
        Ok(Err(e)) => warn!(error = %e, len, "node1 tx send failed"),
        Err(_) => warn!(len, "node1 tx send timed out"),
    }
}

async fn send_one_inner(conn: &Connection, bytes: &[u8]) -> Result<(u16, String)> {
    let (mut send, mut recv) = conn.open_bi().await.context("tx open_bi")?;
    send.write_all(bytes).await.context("tx write_all")?;
    send.finish().context("tx finish")?;

    let mut header = [0u8; 6];
    recv.read_exact(&mut header).await.context("tx read header")?;
    let status = u16::from_be_bytes([header[0], header[1]]);
    let msg_len = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;

    let mut msg = vec![0u8; msg_len];
    if msg_len > 0 {
        recv.read_exact(&mut msg).await.context("tx read msg")?;
    }
    Ok((status, String::from_utf8_lossy(&msg).into_owned()))
}

/// Install rustls's default crypto provider once. Reqwest pulls in
/// rustls 0.21 which is a separate crate version with its own provider
/// state, so this 0.23 installation doesn't conflict.
fn install_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

// ── SkipServerVerification ─────────────────────────────────────────────
//
// node1 docs example uses `solana_tls_utils::SkipServerVerification`. We
// don't pull in the heavy Solana SDK for one trait impl — inline it.

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(
            rustls::crypto::CryptoProvider::get_default()
                .cloned()
                .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider())),
        ))
    }
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
