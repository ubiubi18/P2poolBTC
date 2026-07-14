use anyhow::{anyhow, bail, Context, Result};
use cid::{Cid, Version};
use governance_core::{sha256_hex, verify_car_integrity};
use reqwest::multipart::{Form, Part};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::output::{deterministic_json, secure_output_directory, write_new};

const MAX_GATEWAY_CAR_BYTES: usize = 2_500_000_000;
const MAX_CONTROL_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_PINSET_BYTES: u64 = 1024 * 1024;
const MAX_SECRET_BYTES: u64 = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PinsetManifestV1 {
    schema_version: u16,
    ecosystem_cid: Option<String>,
    cids: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ExternalPinProvider {
    pub endpoint: Url,
    pub token_file: PathBuf,
}

pub fn parse_external_provider(value: &str) -> Result<ExternalPinProvider> {
    let (endpoint, token_file) = value
        .split_once('=')
        .context("external pin provider must be URL=/absolute/token-file")?;
    let mut endpoint = validate_https_or_loopback_url(endpoint, "external pin provider")?;
    ensure_trailing_slash(&mut endpoint);
    let token_file = PathBuf::from(token_file);
    validate_secret_file(&token_file)?;
    Ok(ExternalPinProvider {
        endpoint,
        token_file,
    })
}

pub async fn import_to_public_kubo(
    client: &Client,
    api: &str,
    allow_remote_api: bool,
    root_cid: &str,
    car: &[u8],
) -> Result<()> {
    let base = validate_kubo_api(api, allow_remote_api)?;
    let import_url = base.join("api/v0/dag/import?pin-roots=false")?;
    let part = Part::bytes(car.to_vec())
        .file_name("governance-source.car")
        .mime_str("application/vnd.ipld.car")?;
    let response = client
        .post(import_url)
        .multipart(Form::new().part("file", part))
        .send()
        .await
        .context("public Kubo DAG import failed")?;
    let status = response.status();
    if !status.is_success() {
        bail!("public Kubo DAG import returned {status}");
    }
    let pin_url = base.join(&format!("api/v0/pin/add?arg={root_cid}&recursive=true"))?;
    let response = client
        .post(pin_url)
        .send()
        .await
        .context("public Kubo recursive pin failed")?;
    let status = response.status();
    if !status.is_success() {
        bail!("public Kubo recursive pin returned {status}");
    }
    let body = read_bounded_response_text(response, MAX_CONTROL_RESPONSE_BYTES).await?;
    if !kubo_pin_response_confirms_root(&body, root_cid) {
        bail!("public Kubo recursive pin did not confirm the expected root CID");
    }
    let verify_url = base.join(&format!("api/v0/pin/ls?arg={root_cid}&type=recursive"))?;
    let response = client
        .post(verify_url)
        .send()
        .await
        .context("public Kubo pin verification failed")?;
    let status = response.status();
    if !status.is_success() {
        bail!("public Kubo pin verification returned {status}");
    }
    let body = read_bounded_response_text(response, MAX_CONTROL_RESPONSE_BYTES).await?;
    if !kubo_pin_response_confirms_root(&body, root_cid) {
        bail!("public Kubo pin set does not contain the expected recursive root");
    }
    Ok(())
}

pub async fn request_external_pins(
    client: &Client,
    root_cid: &str,
    providers: &[ExternalPinProvider],
) -> Result<()> {
    for provider in providers {
        let token = read_secret_file(&provider.token_file)?;
        let url = provider.endpoint.join("pins")?;
        let response = client
            .post(url)
            .bearer_auth(token)
            .json(&serde_json::json!({
                "cid": root_cid,
                "name": format!("pohw-governance-{root_cid}")
            }))
            .send()
            .await
            .context("external pin request failed")?;
        if !response.status().is_success() {
            bail!("external pin provider returned {}", response.status());
        }
    }
    Ok(())
}

pub fn pin_locally(
    store: &Path,
    ecosystem_cid: Option<&str>,
    root_cid: &str,
    car: &[u8],
) -> Result<()> {
    if let Some(cid) = ecosystem_cid {
        validate_canonical_cid(cid, Some(0x71))?;
    }
    let verified = verify_car_integrity(car)?;
    if verified.to_string() != root_cid {
        bail!("local pin CAR root does not match the declared CID");
    }
    let store = secure_output_directory(store)?;
    let car_path = store.join(format!("{root_cid}.car"));
    if car_path.exists() {
        let existing = fs::read(&car_path)?;
        if existing != car {
            bail!("local pin CAR already exists with different bytes");
        }
    } else {
        write_new(&car_path, car)?;
    }
    let digest_path = store.join(format!("{root_cid}.car.sha256"));
    let digest = format!("{}  {root_cid}.car\n", sha256_hex(car));
    if digest_path.exists() {
        if fs::read(&digest_path)? != digest.as_bytes() {
            bail!("local pin checksum already exists with different content");
        }
    } else {
        write_new(&digest_path, digest.as_bytes())?;
    }

    let pinset_path = store.join("pinset-v1.json");
    let mut pinset = if pinset_path.exists() {
        let bytes = read_bounded_regular_file(&pinset_path, MAX_PINSET_BYTES, "local pinset")?;
        serde_json::from_slice::<PinsetManifestV1>(&bytes)?
    } else {
        PinsetManifestV1 {
            schema_version: 1,
            ecosystem_cid: ecosystem_cid.map(ToOwned::to_owned),
            cids: Vec::new(),
        }
    };
    if pinset.schema_version != 1 {
        bail!("unsupported local pinset schema");
    }
    if pinset.cids.len() > 100_000 {
        bail!("local pinset exceeds the deterministic CID limit");
    }
    if let Some(cid) = &pinset.ecosystem_cid {
        validate_canonical_cid(cid, Some(0x71))?;
    }
    for cid in &pinset.cids {
        validate_canonical_cid(cid, None)?;
    }
    if let Some(expected) = ecosystem_cid {
        match &pinset.ecosystem_cid {
            Some(existing) if existing != expected => {
                bail!("local pinset is bound to a different ecosystem CID")
            }
            None => pinset.ecosystem_cid = Some(expected.to_string()),
            Some(_) => {}
        }
    }
    let mut cids = pinset.cids.into_iter().collect::<BTreeSet<_>>();
    cids.insert(root_cid.to_string());
    if cids.len() > 100_000 {
        bail!("local pinset exceeds the deterministic CID limit");
    }
    pinset.cids = cids.into_iter().collect();
    let bytes = deterministic_json(&pinset)?;
    let temporary = store.join(".pinset-v1.json.tmp");
    if temporary.exists() {
        bail!("refusing to overwrite stale local pinset temporary file");
    }
    write_new(&temporary, &bytes)?;
    fs::rename(&temporary, &pinset_path)?;
    Ok(())
}

pub async fn fetch_car_from_gateways(
    client: &Client,
    expected_cid: &str,
    gateways: &[String],
) -> Result<Vec<u8>> {
    if gateways.len() < 2 {
        bail!("configure at least two independent public IPFS gateways");
    }
    let mut errors = Vec::new();
    for (index, gateway) in gateways.iter().enumerate() {
        match fetch_from_gateway(client, expected_cid, gateway).await {
            Ok(bytes) => return Ok(bytes),
            Err(error) => errors.push(format!("gateway {}: {error:#}", index + 1)),
        }
    }
    Err(anyhow!(
        "all configured gateways failed CID verification: {}",
        errors.join("; ")
    ))
}

async fn fetch_from_gateway(client: &Client, expected_cid: &str, gateway: &str) -> Result<Vec<u8>> {
    let mut base = validate_https_or_loopback_url(gateway, "IPFS gateway")?;
    ensure_trailing_slash(&mut base);
    let url = base.join(&format!("ipfs/{expected_cid}?format=car"))?;
    let mut response = client.get(url).send().await?;
    if !response.status().is_success() {
        bail!("gateway returned {}", response.status());
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_GATEWAY_CAR_BYTES as u64)
    {
        bail!("gateway CAR exceeds local size limit");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len().saturating_add(chunk.len()) > MAX_GATEWAY_CAR_BYTES {
            bail!("gateway CAR exceeds local size limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    let verified = verify_car_integrity(&bytes)?;
    if verified.to_string() != expected_cid {
        bail!("gateway returned a different root CID");
    }
    Ok(bytes)
}

pub fn http_client() -> Result<Client> {
    Ok(Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(600))
        .user_agent("pohw-governance/0.1")
        .build()?)
}

fn validate_kubo_api(value: &str, allow_remote: bool) -> Result<Url> {
    let mut url = Url::parse(value).context("invalid public Kubo API URL")?;
    validate_url_shape(&url, "public Kubo API")?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
    if !loopback && !allow_remote {
        bail!("refusing a non-loopback Kubo control API without --allow-remote-api");
    }
    if !loopback && url.scheme() != "https" {
        bail!("remote Kubo control APIs require HTTPS");
    }
    ensure_trailing_slash(&mut url);
    Ok(url)
}

fn validate_https_or_loopback_url(value: &str, label: &str) -> Result<Url> {
    let url = Url::parse(value).with_context(|| format!("invalid {label} URL"))?;
    validate_url_shape(&url, label)?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
    if !loopback && url.scheme() != "https" {
        bail!("{label} must use HTTPS unless it is loopback");
    }
    Ok(url)
}

fn validate_url_shape(url: &Url, label: &str) -> Result<()> {
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("{label} URL must be an HTTP(S) origin/path without credentials, query, or fragment");
    }
    Ok(())
}

fn validate_secret_file(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("pin-provider token file must be absolute");
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("pin-provider token must be a non-symlink regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("pin-provider token file must not be accessible by group or world");
        }
    }
    Ok(())
}

fn read_secret_file(path: &Path) -> Result<String> {
    validate_secret_file(path)?;
    let bytes = read_bounded_regular_file(path, MAX_SECRET_BYTES, "pin-provider token")?;
    let value = String::from_utf8(bytes)
        .context("pin-provider token file is not UTF-8")?
        .trim()
        .to_string();
    if value.is_empty()
        || value.len() > MAX_SECRET_BYTES as usize
        || value.chars().any(char::is_control)
    {
        bail!("pin-provider token file is empty or malformed");
    }
    Ok(value)
}

async fn read_bounded_response_text(
    mut response: reqwest::Response,
    maximum: usize,
) -> Result<String> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        bail!("public IPFS control response exceeds the local size limit");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes
            .len()
            .checked_add(chunk.len())
            .map_or(true, |size| size > maximum)
        {
            bail!("public IPFS control response exceeds the local size limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes).context("public IPFS control response is not UTF-8")
}

fn read_bounded_regular_file(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>> {
    let expected = fs::symlink_metadata(path)?;
    if expected.file_type().is_symlink() || !expected.is_file() || expected.len() > maximum {
        bail!("{label} must be a bounded non-symlink regular file");
    }
    let mut file = OpenOptions::new().read(true).open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || !same_file_metadata(&expected, &opened) || opened.len() > maximum {
        bail!("{label} changed while opening");
    }
    let mut bytes = Vec::with_capacity(opened.len().min(1024 * 1024) as usize);
    (&mut file).take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != opened.len() || bytes.len() as u64 > maximum {
        bail!("{label} changed while reading");
    }
    Ok(bytes)
}

#[cfg(unix)]
fn same_file_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.file_type() == right.file_type() && left.len() == right.len()
}

fn ensure_trailing_slash(url: &mut Url) {
    if !url.path().ends_with('/') {
        url.set_path(&format!("{}/", url.path()));
    }
}

fn validate_canonical_cid(value: &str, expected_codec: Option<u64>) -> Result<()> {
    let cid: Cid = value.parse().context("pinset contains a malformed CID")?;
    if cid.version() != Version::V1
        || expected_codec.is_some_and(|codec| cid.codec() != codec)
        || !matches!(cid.codec(), 0x55 | 0x71)
        || cid.hash().code() != 0x12
        || cid.hash().digest().len() != 32
        || cid.to_string() != value
    {
        bail!("pinset CID does not use the canonical CIDv1/SHA2-256 profile");
    }
    Ok(())
}

fn kubo_pin_response_confirms_root(body: &str, expected_root: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    let pins_confirm = value
        .get("Pins")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|pins| pins.iter().any(|pin| pin.as_str() == Some(expected_root)));
    let keys_confirm = value
        .get("Keys")
        .and_then(serde_json::Value::as_object)
        .and_then(|keys| keys.get(expected_root))
        .and_then(|entry| entry.get("Type"))
        .and_then(serde_json::Value::as_str)
        == Some("recursive");
    pins_confirm || keys_confirm
}

#[cfg(test)]
mod tests {
    use super::*;
    use governance_core::package_dag_cbor;

    #[test]
    fn control_api_is_loopback_only_by_default() {
        assert!(validate_kubo_api("http://127.0.0.1:5001", false).is_ok());
        assert!(validate_kubo_api("http://localhost:5001", false).is_ok());
        assert!(validate_kubo_api("http://192.0.2.1:5001", false).is_err());
        assert!(validate_kubo_api("https://example.test", true).is_ok());
    }

    #[test]
    fn public_gateways_require_https() {
        assert!(validate_https_or_loopback_url("https://ipfs.example", "gateway").is_ok());
        assert!(validate_https_or_loopback_url("http://ipfs.example", "gateway").is_err());
        assert!(validate_https_or_loopback_url("http://127.0.0.1:8080", "gateway").is_ok());
    }

    #[test]
    fn external_provider_paths_are_preserved_and_secret_files_are_not_followed() {
        let directory = tempfile::tempdir().unwrap();
        let token = directory.path().join("token");
        fs::write(&token, b"test-token\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt};
            fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
            let link = directory.path().join("token-link");
            symlink(&token, &link).unwrap();
            assert!(validate_secret_file(&link).is_err());
        }
        let provider = parse_external_provider(&format!(
            "https://pins.example.test/api/v1={}",
            token.display()
        ))
        .unwrap();
        assert_eq!(
            provider.endpoint.as_str(),
            "https://pins.example.test/api/v1/"
        );
        assert_eq!(
            provider.endpoint.join("pins").unwrap().as_str(),
            "https://pins.example.test/api/v1/pins"
        );
    }

    #[test]
    fn local_pin_accepts_generic_canonical_object_car_and_rechecks_root() {
        let package =
            package_dag_cbor(serde_json::json!({"schemaVersion": 1, "kind": "proposal"})).unwrap();
        let directory = tempfile::tempdir().unwrap();
        pin_locally(
            directory.path(),
            None,
            &package.root_cid.to_string(),
            &package.car_bytes,
        )
        .unwrap();
        assert!(directory
            .path()
            .join(format!("{}.car", package.root_cid))
            .is_file());
        assert!(pin_locally(
            directory.path(),
            None,
            "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &package.car_bytes
        )
        .is_err());
    }

    #[test]
    fn kubo_pin_confirmation_is_structured_and_exact() {
        let root = "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(kubo_pin_response_confirms_root(
            &format!(r#"{{"Pins":["{root}"]}}"#),
            root,
        ));
        assert!(kubo_pin_response_confirms_root(
            &format!(r#"{{"Keys":{{"{root}":{{"Type":"recursive"}}}}}}"#),
            root,
        ));
        assert!(!kubo_pin_response_confirms_root(
            &format!(r#"{{"Pins":["{root}-suffix"]}}"#),
            root,
        ));
        assert!(!kubo_pin_response_confirms_root("not-json", root));
    }
}
