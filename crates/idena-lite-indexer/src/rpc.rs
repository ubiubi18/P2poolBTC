use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use pohw_core::snapshot::IdenaStatus;
use reqwest::Url;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::json;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

const MAX_IDENA_API_KEY_BYTES: usize = 512;
const MAX_IDENA_RPC_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct IdenaRpcClient {
    url: Url,
    api_key: String,
    client: reqwest::Client,
}

impl IdenaRpcClient {
    pub fn new(url: impl AsRef<str>, api_key: impl Into<String>) -> Result<Self> {
        Self::new_with_remote_policy(url, api_key, false)
    }

    pub fn new_with_remote_policy(
        url: impl AsRef<str>,
        api_key: impl Into<String>,
        allow_remote_rpc: bool,
    ) -> Result<Self> {
        let url = validate_rpc_url(
            Url::parse(url.as_ref()).context("invalid Idena RPC URL")?,
            allow_remote_rpc,
        )?;
        let api_key = validate_api_key(api_key.into())?;
        Ok(Self {
            url,
            api_key,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .context("failed to build Idena RPC HTTP client")?,
        })
    }

    pub fn from_api_key_file(url: impl AsRef<str>, path: impl AsRef<Path>) -> Result<Self> {
        Self::from_api_key_file_with_remote_policy(url, path, false)
    }

    pub fn from_api_key_file_with_remote_policy(
        url: impl AsRef<str>,
        path: impl AsRef<Path>,
        allow_remote_rpc: bool,
    ) -> Result<Self> {
        let api_key = read_protected_secret_file(path.as_ref(), "Idena API key")?;
        Self::new_with_remote_policy(url, api_key, allow_remote_rpc)
    }

    pub async fn syncing(&self) -> Result<SyncingResponse> {
        self.call("bcn_syncing", json!([])).await
    }

    pub async fn epoch(&self) -> Result<EpochResponse> {
        self.call("dna_epoch", json!([])).await
    }

    pub async fn block_at(&self, height: u64) -> Result<Option<BlockResponse>> {
        self.call("bcn_blockAt", json!([height])).await
    }

    pub async fn identities(&self) -> Result<Vec<IdentityResponse>> {
        self.call("dna_identities", json!([])).await
    }

    pub async fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
            "key": self.api_key,
        });
        let response = self
            .client
            .post(self.url.clone())
            .json(&body)
            .send()
            .await
            .with_context(|| format!("Idena RPC request {method} failed"))?
            .error_for_status()
            .with_context(|| format!("Idena RPC request {method} returned HTTP error"))?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_IDENA_RPC_RESPONSE_BYTES as u64)
        {
            return Err(anyhow!("Idena RPC response {method} is too large"));
        }
        let body = response
            .bytes()
            .await
            .with_context(|| format!("Idena RPC response {method} failed while reading body"))?;
        if body.len() > MAX_IDENA_RPC_RESPONSE_BYTES {
            return Err(anyhow!("Idena RPC response {method} is too large"));
        }
        let response: JsonRpcResponse<T> = serde_json::from_slice(&body)
            .with_context(|| format!("Idena RPC response {method} is not valid JSON"))?;

        if let Some(error) = response.error {
            return Err(anyhow!(
                "Idena RPC {method} error {}: {}",
                error.code,
                error.message
            ));
        }
        response
            .result
            .ok_or_else(|| anyhow!("Idena RPC {method} returned no result"))
    }
}

fn read_protected_secret_file(path: &Path, label: &str) -> Result<String> {
    validate_protected_secret_file(path, label)?;
    let secret = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {label} file {}", path.display()))?
        .trim()
        .to_string();
    validate_api_key(secret).with_context(|| format!("{label} file {}", path.display()))
}

fn validate_rpc_url(url: Url, allow_remote_rpc: bool) -> Result<Url> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(anyhow!("Idena RPC URL scheme must be http or https"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("Idena RPC URL must include a host"))?;
    if !allow_remote_rpc && !is_loopback_rpc_host(host) {
        return Err(anyhow!(
            "Idena RPC URL host must be loopback unless remote RPC is explicitly allowed"
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(anyhow!(
            "Idena RPC URL must not include userinfo; use the local API key file instead"
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(anyhow!(
            "Idena RPC URL must not include query or fragment data"
        ));
    }
    Ok(url)
}

fn is_loopback_rpc_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|ip_address| ip_address.is_loopback())
}

fn validate_api_key(api_key: String) -> Result<String> {
    let api_key = api_key.trim().to_string();
    if api_key.is_empty() || api_key.len() > MAX_IDENA_API_KEY_BYTES {
        return Err(anyhow!(
            "Idena API key must be 1-{MAX_IDENA_API_KEY_BYTES} bytes"
        ));
    }
    if api_key.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(anyhow!("Idena API key must not contain control characters"));
    }
    Ok(api_key)
}

fn validate_protected_secret_file(path: &Path, label: &str) -> Result<()> {
    if let Some(parent) = non_empty_parent(path) {
        validate_private_file_parent(parent, label)?;
    }
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} file {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(anyhow!(
            "{label} file {} must not be a symlink",
            path.display()
        ));
    }
    if !metadata.file_type().is_file() {
        return Err(anyhow!(
            "{label} path {} must be a regular file",
            path.display()
        ));
    }
    if metadata.len() > MAX_IDENA_API_KEY_BYTES as u64 {
        return Err(anyhow!(
            "{label} file {} is too large: {} bytes; maximum is {}",
            path.display(),
            metadata.len(),
            MAX_IDENA_API_KEY_BYTES
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(anyhow!(
                "{label} file {} is too permissive ({mode:o}); run chmod 600 {}",
                path.display(),
                path.display()
            ));
        }
    }
    Ok(())
}

fn non_empty_parent(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

fn validate_private_file_parent(path: &Path, label: &str) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to inspect {label} file directory {}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(anyhow!(
            "{label} file directory {} must not be a symlink",
            path.display()
        ));
    }
    if !metadata.is_dir() {
        return Err(anyhow!(
            "{label} file directory path {} is not a directory",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o022 != 0 {
            return Err(anyhow!(
                "{label} file directory {} is writable by group or others ({mode:o})",
                path.display()
            ));
        }
    }
    validate_no_unsafe_symlink_ancestors(path, label)?;
    Ok(())
}

#[cfg(unix)]
fn validate_no_unsafe_symlink_ancestors(path: &Path, label: &str) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("failed to resolve current directory for secret path validation")?
            .join(path)
    };
    for ancestor in absolute.ancestors() {
        let metadata = match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "failed to inspect {label} file directory ancestor {}",
                        ancestor.display()
                    )
                });
            }
        };
        if !metadata.file_type().is_symlink() {
            continue;
        }
        let parent = ancestor.parent().unwrap_or_else(|| Path::new("/"));
        let parent_metadata = std::fs::symlink_metadata(parent).with_context(|| {
            format!(
                "failed to inspect {label} file directory symlink parent {}",
                parent.display()
            )
        })?;
        let parent_mode = parent_metadata.permissions().mode() & 0o777;
        if metadata.uid() != 0 || parent_mode & 0o022 != 0 {
            return Err(anyhow!(
                "{label} file directory {} contains unsafe symlink ancestor {}",
                path.display(),
                ancestor.display()
            ));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_no_unsafe_symlink_ancestors(_path: &Path, _label: &str) -> Result<()> {
    Ok(())
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncingResponse {
    pub syncing: bool,
    pub current_block: u64,
    pub highest_block: u64,
    pub wrong_time: bool,
    pub genesis_block: u64,
    pub message: String,
}

impl SyncingResponse {
    pub fn is_effectively_syncing(&self) -> bool {
        self.syncing && !(self.highest_block > 0 && self.current_block >= self.highest_block)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpochResponse {
    pub start_block: u64,
    pub epoch: u16,
    pub next_validation: DateTime<Utc>,
    pub current_period: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockResponse {
    pub coinbase: String,
    pub hash: String,
    pub parent_hash: String,
    pub height: u64,
    pub timestamp: i64,
    pub root: String,
    pub identity_root: String,
    pub transactions: Option<Vec<String>>,
    pub is_empty: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityResponse {
    pub address: String,
    pub state: IdenaStatus,
    #[serde(default)]
    pub pubkey: String,
    #[serde(default)]
    pub delegatee: Option<String>,
    #[serde(default)]
    pub is_pool: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("pohw-idena-rpc-{name}-{unique}"));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn write_secret_file(path: &Path, content: &str) {
        fs::write(path, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn rpc_url_validation_rejects_unsafe_forms() {
        assert!(IdenaRpcClient::new("http://127.0.0.1:9009", "api-key").is_ok());
        assert!(IdenaRpcClient::new("ftp://127.0.0.1:9009", "api-key").is_err());
        assert!(IdenaRpcClient::new("http://user:pass@127.0.0.1:9009", "api-key").is_err());
        assert!(IdenaRpcClient::new("http://127.0.0.1:9009/?key=leak", "api-key").is_err());
        assert!(IdenaRpcClient::new("http://127.0.0.1:9009/#fragment", "api-key").is_err());
        assert!(IdenaRpcClient::new("http://198.51.100.10:9009", "api-key").is_err());
        assert!(IdenaRpcClient::new_with_remote_policy(
            "http://198.51.100.10:9009",
            "api-key",
            true
        )
        .is_ok());
    }

    #[test]
    fn api_key_validation_rejects_empty_or_control_values() {
        assert!(IdenaRpcClient::new("http://127.0.0.1:9009", "").is_err());
        assert!(IdenaRpcClient::new("http://127.0.0.1:9009", "bad\nkey").is_err());
        assert!(IdenaRpcClient::new("http://127.0.0.1:9009", "api-key").is_ok());
    }

    #[test]
    fn api_key_file_is_protected_and_validated() {
        let datadir = temp_dir("api-key-file-validation");
        let empty = datadir.join("empty-key");
        write_secret_file(&empty, "");
        assert!(IdenaRpcClient::from_api_key_file("http://127.0.0.1:9009", &empty).is_err());

        let control = datadir.join("control-key");
        write_secret_file(&control, "bad\nkey");
        assert!(IdenaRpcClient::from_api_key_file("http://127.0.0.1:9009", &control).is_err());

        let valid = datadir.join("valid-key");
        write_secret_file(&valid, "api-key");
        let client = IdenaRpcClient::from_api_key_file("http://127.0.0.1:9009", &valid).unwrap();
        assert_eq!(client.api_key, "api-key");
        fs::remove_dir_all(datadir).unwrap();
    }

    #[test]
    fn api_key_file_rejects_large_files_before_reading() {
        let datadir = temp_dir("api-key-large-file");
        let large = datadir.join("api.key");
        fs::File::create(&large)
            .unwrap()
            .set_len(MAX_IDENA_API_KEY_BYTES as u64 + 1)
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&large, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let err = IdenaRpcClient::from_api_key_file("http://127.0.0.1:9009", &large).unwrap_err();

        assert!(
            format!("{err:#}").contains("too large"),
            "unexpected error: {err:#}"
        );
        fs::remove_dir_all(datadir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn api_key_file_rejects_group_or_world_writable_parent_directory() {
        use std::os::unix::fs::PermissionsExt;

        let datadir = temp_dir("api-key-writable-parent");
        let key = datadir.join("api.key");
        write_secret_file(&key, "api-key");
        fs::set_permissions(&datadir, fs::Permissions::from_mode(0o777)).unwrap();

        let err = IdenaRpcClient::from_api_key_file("http://127.0.0.1:9009", &key).unwrap_err();

        assert!(
            format!("{err:#}").contains("writable by group or others"),
            "unexpected error: {err:#}"
        );
        fs::set_permissions(&datadir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(datadir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn api_key_file_rejects_symlink_parent_directory() {
        use std::os::unix::fs::symlink;

        let datadir = temp_dir("api-key-symlink-parent");
        let real = datadir.join("real");
        let link = datadir.join("link");
        fs::create_dir_all(&real).unwrap();
        symlink(&real, &link).unwrap();
        let key = real.join("api.key");
        write_secret_file(&key, "api-key");

        let err = IdenaRpcClient::from_api_key_file("http://127.0.0.1:9009", link.join("api.key"))
            .unwrap_err();

        assert!(
            format!("{err:#}").contains("must not be a symlink"),
            "unexpected error: {err:#}"
        );
        fs::remove_dir_all(datadir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn api_key_file_rejects_symlink_ancestor_directory() {
        use std::os::unix::fs::symlink;

        let datadir = temp_dir("api-key-symlink-ancestor");
        let real = datadir.join("real");
        let child = real.join("child");
        let link = datadir.join("link");
        fs::create_dir_all(&child).unwrap();
        symlink(&real, &link).unwrap();
        let key = child.join("api.key");
        write_secret_file(&key, "api-key");

        let err = IdenaRpcClient::from_api_key_file(
            "http://127.0.0.1:9009",
            link.join("child").join("api.key"),
        )
        .unwrap_err();

        assert!(
            format!("{err:#}").contains("unsafe symlink ancestor"),
            "unexpected error: {err:#}"
        );
        fs::remove_dir_all(datadir).unwrap();
    }
}
