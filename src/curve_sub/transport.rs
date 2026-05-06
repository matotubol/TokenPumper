//! Shared gRPC transport plumbing — interceptor, request-stream adapter,
//! endpoint builder. Keeps the keep-alive + TLS knobs in one place so
//! `run` stays focused on the protocol loop.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Context as _, Result};
use tokio::sync::mpsc;
use tonic::codegen::tokio_stream::Stream;
use tonic::metadata::{Ascii, MetadataValue};
use tonic::service::Interceptor;
use tonic::transport::{ClientTlsConfig, Endpoint};
use tonic::{Request, Status};

use super::proto::geyser::SubscribeRequest;

/// Stamps `x-token: <value>` on every outbound request. Mirrors the
/// `BearerInterceptor` pattern in `jito_auth` — static token, no refresh.
#[derive(Clone)]
pub(super) struct XTokenInterceptor {
    token: MetadataValue<Ascii>,
}

impl XTokenInterceptor {
    pub(super) fn new(token: &str) -> Result<Self> {
        let token: MetadataValue<Ascii> = token
            .parse()
            .context("x-token contains non-ASCII bytes")?;
        Ok(Self { token })
    }
}

impl Interceptor for XTokenInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        request.metadata_mut().insert("x-token", self.token.clone());
        Ok(request)
    }
}

/// Adapter from `mpsc::Receiver<SubscribeRequest>` to a `Stream` that
/// tonic's bi-di `subscribe()` can consume. Hand-rolled to avoid pulling
/// `tokio_stream`.
pub(super) struct ReqStream {
    pub rx: mpsc::Receiver<SubscribeRequest>,
}

impl Stream for ReqStream {
    type Item = SubscribeRequest;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

pub(super) fn build_endpoint(url: &str) -> Result<Endpoint> {
    let endpoint = Endpoint::from_shared(url.to_string())
        .with_context(|| format!("invalid grpc url: {url}"))?
        .connect_timeout(Duration::from_secs(10))
        .http2_keep_alive_interval(Duration::from_secs(15))
        .keep_alive_timeout(Duration::from_secs(20))
        .keep_alive_while_idle(true);

    if url.starts_with("https") {
        endpoint
            .tls_config(ClientTlsConfig::new().with_enabled_roots())
            .context("configuring TLS for curve-sub channel")
    } else {
        Ok(endpoint)
    }
}
