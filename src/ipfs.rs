//! Pinata IPFS pinning client (v3 Files API).
//!
//! One endpoint covers both file and JSON uploads:
//!
//!   POST https://uploads.pinata.cloud/v3/files   (multipart/form-data)
//!     fields:
//!       file     — the bytes (for JSON, wrap as a file with mime application/json)
//!       network  — "public" (or "private"; pump indexers need public)
//!       name     — optional display name
//!
//! Auth is `Authorization: Bearer <jwt>`. Response is wrapped:
//!
//!   { "data": { "id", "name", "cid", "size", "number_of_files", "mime_type", "group_id" } }
//!
//! We surface only the `cid`. Higher layers (`pumpfun::metadata`) compose this
//! into the image → JSON → uri pipeline that pump's `createV2` consumes.

use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use reqwest::blocking::{multipart, Client};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::to_vec as json_to_vec;
use tracing::{info, warn};

const UPLOAD_URL: &str = "https://uploads.pinata.cloud/v3/files";
const NETWORK: &str = "public";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Deserialize)]
struct UploadEnvelope {
    data: UploadData,
}

#[derive(Deserialize)]
struct UploadData {
    cid: String,
}

fn client() -> Result<&'static Client> {
    static CLIENT: OnceLock<Client> = OnceLock::new();
    if let Some(c) = CLIENT.get() {
        return Ok(c);
    }
    let c = Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .context("building pinata HTTP client")?;
    Ok(CLIENT.get_or_init(|| c))
}

/// Pin a raw file (image, audio, etc.) to public IPFS. Returns the CID.
pub fn pin_file(jwt: &str, bytes: Vec<u8>, filename: &str, mime: &str) -> Result<String> {
    upload(jwt, bytes, filename, mime)
}

/// Pin a JSON value to public IPFS. Wraps the value as an
/// `application/json` file under the v3 endpoint. Returns the CID.
pub fn pin_json<T: Serialize>(jwt: &str, value: &T) -> Result<String> {
    let bytes = json_to_vec(value).context("serializing JSON for pinata upload")?;
    upload(jwt, bytes, "metadata.json", "application/json")
}

/// Build the public gateway URL for a CID. `gateway_base` should end with `/`.
pub fn gateway_url(gateway_base: &str, cid: &str) -> String {
    if gateway_base.ends_with('/') {
        format!("{gateway_base}{cid}")
    } else {
        format!("{gateway_base}/{cid}")
    }
}

/// GET each URL once so the gateway pulls the content from IPFS into its
/// edge cache. The next visitor (typically an indexer) hits a hot path
/// instead of paying the DHT-lookup cold start. Failures are logged but
/// not propagated — a cold gateway is still a working code path, just
/// slower for the first indexer fetch.
pub fn warm_up(urls: &[&str]) {
    for &url in urls {
        match warm_one(url) {
            Ok(bytes) => info!(%url, bytes, "gateway warmed"),
            Err(e) => warn!(%url, error = %e, "gateway warm-up failed"),
        }
    }
}

fn warm_one(url: &str) -> Result<usize> {
    let resp = client()?
        .get(url)
        .send()
        .with_context(|| format!("warm-up GET {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        bail!("HTTP {status}");
    }
    // Drain the body so the gateway actually retrieves the bytes — not
    // just acks the headers.
    let bytes = resp.bytes().context("draining warm-up body")?;
    Ok(bytes.len())
}

fn upload(jwt: &str, bytes: Vec<u8>, filename: &str, mime: &str) -> Result<String> {
    let part = multipart::Part::bytes(bytes)
        .file_name(filename.to_string())
        .mime_str(mime)
        .with_context(|| format!("invalid mime type {mime:?} for {filename}"))?;
    let form = multipart::Form::new()
        .part("file", part)
        .text("network", NETWORK);

    let resp = client()?
        .post(UPLOAD_URL)
        .bearer_auth(jwt)
        .multipart(form)
        .send()
        .context("POST pinata v3/files")?;
    let env = parse_response::<UploadEnvelope>(resp, "v3/files")?;
    Ok(env.data.cid)
}

fn parse_response<T: DeserializeOwned>(
    resp: reqwest::blocking::Response,
    method: &str,
) -> Result<T> {
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().unwrap_or_else(|_| "<no body>".to_string());
        bail!("pinata {method} HTTP {status}: {body}");
    }
    resp.json::<T>()
        .with_context(|| format!("decoding {method} response"))
        .map_err(|e| anyhow!("{e:#}"))
}
