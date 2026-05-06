use std::time::Duration;

use anyhow::{Context, Result};
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

/// Builds a tonic channel against a Jito block-engine URL. `https://` endpoints
/// get webpki-roots TLS; plaintext otherwise.
pub async fn grpc_channel(url: &str) -> Result<Channel> {
    let endpoint = Endpoint::from_shared(url.to_string())
        .with_context(|| format!("invalid grpc url: {url}"))?
        .connect_timeout(Duration::from_secs(10))
        .http2_keep_alive_interval(Duration::from_secs(15))
        .keep_alive_timeout(Duration::from_secs(20))
        .keep_alive_while_idle(true);

    let endpoint = if url.starts_with("https") {
        endpoint
            .tls_config(ClientTlsConfig::new().with_enabled_roots())
            .context("configuring TLS for grpc channel")?
    } else {
        endpoint
    };

    endpoint
        .connect()
        .await
        .with_context(|| format!("connecting grpc channel to {url}"))
}
