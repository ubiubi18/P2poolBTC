use anyhow::{bail, Context, Result};
use reqwest::{redirect::Policy, Client, StatusCode, Url};
use serde_json::Value;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

const MAX_INDEX_JSON_BYTES: usize = 8 * 1024 * 1024;
const MAX_INDEX_TEXT_BYTES: usize = 128;
const MAX_CONCURRENT_INDEX_REQUESTS: usize = 8;
const INDEX_TIMEOUT_SECONDS: u64 = 8;
const INDEX_QUEUE_TIMEOUT_SECONDS: u64 = 2;

#[derive(Debug, Clone)]
pub(crate) struct BitcoinExplorerIndexClient {
    base_url: Url,
    remote: bool,
    client: Client,
    request_slots: Arc<Semaphore>,
}

impl BitcoinExplorerIndexClient {
    pub(crate) fn new(raw_base_url: &str, allow_remote: bool) -> Result<Self> {
        let mut base_url = Url::parse(raw_base_url).context("invalid Bitcoin index URL")?;
        if !base_url.username().is_empty() || base_url.password().is_some() {
            bail!("Bitcoin index URL must not embed credentials");
        }
        if base_url.query().is_some() || base_url.fragment().is_some() {
            bail!("Bitcoin index URL must not contain a query or fragment");
        }
        let host = base_url
            .host_str()
            .context("Bitcoin index URL must include a host")?;
        let remote = match base_url.scheme() {
            "http" => {
                let host: IpAddr = host
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse()
                    .context("HTTP Bitcoin index URL must use a literal loopback address")?;
                if !host.is_loopback() {
                    bail!("HTTP Bitcoin index URL must stay on loopback");
                }
                false
            }
            "https" if allow_remote => {
                if host.eq_ignore_ascii_case("localhost") {
                    bail!("remote Bitcoin index URL must not use localhost");
                }
                if host
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<IpAddr>()
                    .is_ok_and(|address| !is_public_remote_address(address))
                {
                    bail!("remote Bitcoin index URL must use a public address");
                }
                true
            }
            "https" => {
                bail!("remote Bitcoin index URL requires explicit opt-in");
            }
            _ => bail!("Bitcoin index URL must use loopback HTTP or opted-in HTTPS"),
        };
        if base_url.port_or_known_default().is_none() {
            bail!("Bitcoin index URL must include a usable port");
        }
        base_url.set_query(None);
        base_url.set_fragment(None);
        let normalized_path = base_url.path().trim_end_matches('/').to_string();
        base_url.set_path(if normalized_path.is_empty() {
            "/"
        } else {
            &normalized_path
        });
        let client = Client::builder()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(INDEX_TIMEOUT_SECONDS))
            .build()
            .context("failed to build Bitcoin index HTTP client")?;
        Ok(Self {
            base_url,
            remote,
            client,
            request_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_INDEX_REQUESTS)),
        })
    }

    pub(crate) fn backend_label(&self) -> &'static str {
        if self.remote {
            "remote_https_esplora"
        } else {
            "host_esplora"
        }
    }

    pub(crate) fn is_remote(&self) -> bool {
        self.remote
    }

    pub(crate) async fn tip_height(&self) -> Result<u64> {
        let _permit = self.acquire_request_slot().await?;
        let response = self.get(&["blocks", "tip", "height"]).await?;
        if !response.status().is_success() {
            bail!("Bitcoin index returned HTTP {}", response.status());
        }
        let body = read_bounded(response, MAX_INDEX_TEXT_BYTES).await?;
        let body = std::str::from_utf8(&body).context("Bitcoin index tip height is not UTF-8")?;
        body.trim()
            .parse::<u64>()
            .context("Bitcoin index tip height is invalid")
    }

    pub(crate) async fn transaction(&self, txid: &str) -> Result<Option<Value>> {
        validate_hash(txid, "Bitcoin transaction id")?;
        self.get_optional_json(&["tx", txid]).await
    }

    pub(crate) async fn block(&self, block_hash: &str) -> Result<Option<Value>> {
        validate_hash(block_hash, "Bitcoin block hash")?;
        self.get_optional_json(&["block", block_hash]).await
    }

    pub(crate) async fn block_transactions(
        &self,
        block_hash: &str,
        start_index: usize,
    ) -> Result<Option<Value>> {
        validate_hash(block_hash, "Bitcoin block hash")?;
        if start_index > 10_000_000 {
            bail!("Bitcoin block transaction cursor exceeds the supported range");
        }
        let start_index = start_index.to_string();
        self.get_optional_json(&["block", block_hash, "txs", &start_index])
            .await
    }

    pub(crate) async fn block_at_height(&self, height: u64) -> Result<Option<Value>> {
        let height = height.to_string();
        let Some(hash) = self.get_optional_text(&["block-height", &height]).await? else {
            return Ok(None);
        };
        validate_hash(hash.trim(), "Bitcoin index block hash")?;
        self.block(hash.trim()).await
    }

    pub(crate) async fn blocks(&self, start_height: Option<u64>) -> Result<Option<Value>> {
        match start_height {
            Some(height) => {
                let height = height.to_string();
                self.get_optional_json(&["blocks", &height]).await
            }
            None => self.get_optional_json(&["blocks"]).await,
        }
    }

    pub(crate) async fn address(&self, address: &str) -> Result<Option<Value>> {
        validate_address_path(address)?;
        self.get_optional_json(&["address", address]).await
    }

    pub(crate) async fn address_transactions(
        &self,
        address: &str,
        cursor: Option<&str>,
    ) -> Result<Option<Value>> {
        validate_address_path(address)?;
        if let Some(cursor) = cursor {
            validate_hash(cursor, "Bitcoin address-history cursor")?;
            self.get_optional_json(&["address", address, "txs", "chain", cursor])
                .await
        } else {
            self.get_optional_json(&["address", address, "txs", "chain"])
                .await
        }
    }

    pub(crate) async fn address_utxos(&self, address: &str) -> Result<Option<Value>> {
        validate_address_path(address)?;
        self.get_optional_json(&["address", address, "utxo"]).await
    }

    pub(crate) async fn transaction_outspends(&self, txid: &str) -> Result<Option<Value>> {
        validate_hash(txid, "Bitcoin transaction id")?;
        self.get_optional_json(&["tx", txid, "outspends"]).await
    }

    async fn get_optional_json(&self, segments: &[&str]) -> Result<Option<Value>> {
        let _permit = self.acquire_request_slot().await?;
        let response = self.get(segments).await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            bail!("Bitcoin index returned HTTP {}", response.status());
        }
        let body = read_bounded(response, MAX_INDEX_JSON_BYTES).await?;
        serde_json::from_slice(&body)
            .context("Bitcoin index returned invalid JSON")
            .map(Some)
    }

    async fn get_optional_text(&self, segments: &[&str]) -> Result<Option<String>> {
        let _permit = self.acquire_request_slot().await?;
        let response = self.get(segments).await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            bail!("Bitcoin index returned HTTP {}", response.status());
        }
        let body = read_bounded(response, MAX_INDEX_TEXT_BYTES).await?;
        String::from_utf8(body)
            .context("Bitcoin index returned non-UTF-8 text")
            .map(Some)
    }

    async fn get(&self, segments: &[&str]) -> Result<reqwest::Response> {
        let mut url = self.base_url.clone();
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|_| anyhow::anyhow!("Bitcoin index URL cannot accept path segments"))?;
            path.pop_if_empty();
            for segment in segments {
                path.push(segment);
            }
        }
        self.client
            .get(url)
            .header(
                reqwest::header::ACCEPT,
                "application/json, text/plain;q=0.9",
            )
            .send()
            .await
            .context("Bitcoin index request failed")
    }

    async fn acquire_request_slot(&self) -> Result<OwnedSemaphorePermit> {
        timeout(
            Duration::from_secs(INDEX_QUEUE_TIMEOUT_SECONDS),
            Arc::clone(&self.request_slots).acquire_owned(),
        )
        .await
        .context("Bitcoin index request queue is saturated")?
        .context("Bitcoin index request limiter is closed")
    }
}

fn is_public_remote_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_private()
                && !address.is_loopback()
                && !address.is_link_local()
                && !address.is_unspecified()
                && !address.is_multicast()
                && !address.is_documentation()
                && !address.is_broadcast()
        }
        IpAddr::V6(address) => {
            let octets = address.octets();
            let unique_local = octets[0] & 0xfe == 0xfc;
            let unicast_link_local = octets[0] == 0xfe && octets[1] & 0xc0 == 0x80;
            !address.is_loopback()
                && !address.is_unspecified()
                && !unique_local
                && !unicast_link_local
                && !address.is_multicast()
        }
    }
}

async fn read_bounded(mut response: reqwest::Response, maximum: usize) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        bail!("Bitcoin index response exceeds the size limit");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("failed to read Bitcoin index response")?
    {
        if body.len().saturating_add(chunk.len()) > maximum {
            bail!("Bitcoin index response exceeds the size limit");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn validate_hash(value: &str, label: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{label} must be 32 bytes encoded as hexadecimal");
    }
    Ok(())
}

fn validate_address_path(address: &str) -> Result<()> {
    if !(14..=128).contains(&address.len())
        || !address.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        bail!("Bitcoin address path is invalid");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_client_requires_safe_transport_and_explicit_remote_opt_in() {
        let local = BitcoinExplorerIndexClient::new("http://127.0.0.1:3002", false).unwrap();
        assert_eq!(local.backend_label(), "host_esplora");
        assert!(!local.is_remote());
        assert!(BitcoinExplorerIndexClient::new("http://[::1]:3002/api", false).is_ok());
        assert!(BitcoinExplorerIndexClient::new("https://blockstream.info/api", false).is_err());
        let remote = BitcoinExplorerIndexClient::new("https://blockstream.info/api", true).unwrap();
        assert_eq!(remote.backend_label(), "remote_https_esplora");
        assert!(remote.is_remote());
        assert!(BitcoinExplorerIndexClient::new("https://1.1.1.1/api", true).is_ok());
        assert!(BitcoinExplorerIndexClient::new("https://127.0.0.1:3002", true).is_err());
        let private_ipv4 = std::net::Ipv4Addr::new(10, 0, 0, 1);
        assert!(
            BitcoinExplorerIndexClient::new(&format!("https://{private_ipv4}/api"), true).is_err()
        );
        assert!(BitcoinExplorerIndexClient::new("https://[fc00::1]/api", true).is_err());
        assert!(BitcoinExplorerIndexClient::new("http://localhost:3002", false).is_err());
        assert!(BitcoinExplorerIndexClient::new("http://192.0.2.1:3002", true).is_err());
        assert!(BitcoinExplorerIndexClient::new("http://user:pass@127.0.0.1:3002", false).is_err());
        assert!(
            BitcoinExplorerIndexClient::new("https://user:pass@example.com/api", true).is_err()
        );
        assert!(BitcoinExplorerIndexClient::new("http://127.0.0.1:3002?token=x", false).is_err());
    }

    #[test]
    fn index_paths_reject_unbounded_or_ambiguous_values() {
        assert!(validate_hash(&"a".repeat(64), "hash").is_ok());
        assert!(validate_hash("../etc/passwd", "hash").is_err());
        assert!(validate_address_path("bc1qexampleaddress000000000000000000000000").is_ok());
        assert!(validate_address_path("bc1qbad/address").is_err());
    }
}
