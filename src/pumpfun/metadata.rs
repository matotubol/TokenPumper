//! pump.fun token metadata: shape the JSON the way pump's frontend +
//! indexers expect, pin both the image and the JSON to IPFS, and surface
//! the metadata URL — that string becomes the `uri` arg of `createV2`.
//!
//! Order of operations:
//!   1. read image bytes from disk
//!   2. POST image to pinata → `image_uri` (gateway URL of the image CID)
//!   3. embed `image_uri` into the metadata JSON
//!   4. POST metadata JSON to pinata → `uri` (gateway URL of the JSON CID)
//!
//! The pump program never validates the URI; indexers do. Use the gateway
//! URL form (https://...) rather than `ipfs://` so older indexers resolve.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use tracing::info;

use crate::config::Config;
use crate::ipfs;
use crate::pumpfun::tokens::TokenSpec;

const ASSETS_DIR: &str = "assets";

/// Result of pinning a token's image + JSON metadata. `uri` is the value
/// you pass into `createV2`; `image_uri` lives inside the JSON the
/// indexer fetches from `uri`.
#[derive(Debug, Clone)]
pub struct UploadedMetadata {
    pub uri: String,
    pub image_uri: String,
}

/// JSON shape pump.fun's frontend / indexers consume. Camel-case is
/// intentional — matches the existing on-chain corpus exactly. Field
/// declaration order is the wire order: name, symbol, description, image,
/// showName, createdOn, twitter, website.
#[derive(Serialize)]
struct PumpJson<'a> {
    name: &'a str,
    symbol: &'a str,
    description: &'a str,
    image: &'a str,
    #[serde(rename = "showName")]
    show_name: bool,
    #[serde(rename = "createdOn")]
    created_on: &'a str,
    twitter: &'a str,
    website: &'a str,
}

const CREATED_ON: &str = "https://pump.fun";

pub fn upload(cfg: &Config, token: &TokenSpec) -> Result<UploadedMetadata> {
    if cfg.ipfs_debugmode {
        let placeholder = UploadedMetadata {
            uri: "ipfs://debug-mode-metadata".to_string(),
            image_uri: "ipfs://debug-mode-image".to_string(),
        };
        info!(
            uri = %placeholder.uri,
            image_uri = %placeholder.image_uri,
            "ipfs debug mode: skipping pinata uploads"
        );
        return Ok(placeholder);
    }

    let jwt = cfg
        .pinata_jwt
        .as_deref()
        .ok_or_else(|| anyhow!("pinata_jwt not set in config.toml"))?;

    // 1. Pin the image. Path is derived from the token's symbol so each
    //    roster entry resolves to its own artwork in `assets/`.
    let image_path: PathBuf = [ASSETS_DIR, &format!("{}.png", token.symbol)].iter().collect();
    let image_bytes = std::fs::read(&image_path)
        .with_context(|| format!("reading token image {}", image_path.display()))?;
    let filename = image_path
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_else(|| "image".to_string());
    let mime = mime_for(&image_path);
    info!(
        path = %image_path.display(),
        bytes = image_bytes.len(),
        mime,
        "pinning token image"
    );
    let image_cid = ipfs::pin_file(jwt, image_bytes, &filename, mime)?;
    let image_uri = ipfs::gateway_url(&cfg.ipfs_gateway, &image_cid);
    info!(cid = %image_cid, url = %image_uri, "image pinned");

    // 2. Pin the JSON metadata pointing at the image.
    let json = PumpJson {
        name: &token.name,
        symbol: &token.symbol,
        description: &token.description,
        image: &image_uri,
        show_name: true,
        created_on: CREATED_ON,
        twitter: &token.twitter,
        website: &token.website,
    };
    info!(name = %token.name, symbol = %token.symbol, "pinning token metadata json");
    let metadata_cid = ipfs::pin_json(jwt, &json)?;
    let uri = ipfs::gateway_url(&cfg.ipfs_gateway, &metadata_cid);
    info!(cid = %metadata_cid, url = %uri, "metadata pinned");

    // 3. Warm the gateway: GET both URLs so an indexer's first fetch hits
    //    a hot cache instead of paying the DHT cold-start cost.
    info!("warming gateway with metadata + image URLs");
    ipfs::warm_up(&[uri.as_str(), image_uri.as_str()]);

    Ok(UploadedMetadata { uri, image_uri })
}

fn mime_for(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("webp") => "image/webp",
        Some("gif") => "image/gif",
        _ => "application/octet-stream",
    }
}
