use crate::client::SshClient;
use crate::config::ShuttleConfig;
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

/// Sensitive path prefixes under $HOME that are always blocked.
const BLOCKED_HOME_PREFIXES: &[&str] = &[
    ".config/styrene",
    ".ssh",
    ".aws",
    ".gnupg",
    ".gpg",
    ".omegon",
    ".kube",
    ".docker",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".config/gcloud",
    ".azure",
];

/// Absolute path prefixes outside $HOME that are always blocked.
/// Includes /private/* variants for macOS where /etc → /private/etc.
const BLOCKED_ABSOLUTE_PREFIXES: &[&str] = &[
    "/etc",
    "/private/etc",
    "/var/run/secrets",
    "/private/var/run/secrets",
    "/proc",
    "/sys",
    "/dev",
    "/Library/Keychains",
    "/System",
];

/// Validate that a local path is safe for file transfer operations.
///
/// Blocks:
/// - Path traversal (`..` after canonicalization)
/// - Sensitive directories under `$HOME` (credentials, identity, config)
/// - System directories (`/etc`, `/proc`, `/var/run/secrets`)
fn validate_local_path(path: &str) -> omegon_extension::Result<std::path::PathBuf> {
    let p = Path::new(path);

    let canonical = p
        .canonicalize()
        .or_else(|_| {
            p.parent()
                .and_then(|parent| parent.canonicalize().ok())
                .map(|parent| parent.join(p.file_name().unwrap_or_default()))
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::NotFound, "parent dir not found")
                })
        })
        .map_err(|e| {
            omegon_extension::Error::invalid_params(format!("invalid path: {e}"))
        })?;

    let canonical_str = canonical.to_string_lossy();
    if canonical_str.contains("..") {
        return Err(omegon_extension::Error::invalid_params(
            "path traversal not allowed",
        ));
    }

    // Block system directories (absolute paths outside $HOME)
    for prefix in BLOCKED_ABSOLUTE_PREFIXES {
        if canonical.starts_with(prefix) {
            return Err(omegon_extension::Error::invalid_params(
                "access to system directories is blocked",
            ));
        }
    }

    // Block sensitive locations under $HOME
    if let Some(home) = dirs::home_dir() {
        for prefix in BLOCKED_HOME_PREFIXES {
            let sensitive = home.join(prefix);
            if canonical.starts_with(&sensitive) {
                return Err(omegon_extension::Error::invalid_params(
                    "access to credential/config directories is blocked",
                ));
            }
        }
    }

    Ok(canonical)
}

/// Copy a local file to a remote host via SFTP.
pub async fn scp_push(
    client: &Arc<Mutex<SshClient>>,
    _config: &ShuttleConfig,
    params: &Value,
) -> omegon_extension::Result<Value> {
    let local_path = params
        .get("local_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| omegon_extension::Error::invalid_params("missing 'local_path'"))?;

    let remote_path = params
        .get("remote_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| omegon_extension::Error::invalid_params("missing 'remote_path'"))?;

    let local = validate_local_path(local_path)?;
    if !local.exists() {
        return Err(omegon_extension::Error::invalid_params(format!(
            "local file not found: {local_path}"
        )));
    }
    if !local.is_file() {
        return Err(omegon_extension::Error::invalid_params(format!(
            "local path is not a file: {local_path}"
        )));
    }

    let data = tokio::fs::read(&local)
        .await
        .map_err(|e| omegon_extension::Error::internal_error(format!("read {local_path}: {e}")))?;

    let bytes_written = data.len();

    let client_guard = client.lock().await;
    let sftp = client_guard
        .sftp()
        .await
        .map_err(|e| omegon_extension::Error::internal_error(e.to_string()))?;

    sftp.create(remote_path)
        .await
        .map_err(|e| omegon_extension::Error::internal_error(format!("sftp create: {e}")))?
        .write_all(&data)
        .await
        .map_err(|e| omegon_extension::Error::internal_error(format!("sftp write: {e}")))?;

    Ok(json!({
        "host": client_guard.host_name(),
        "local_path": local_path,
        "remote_path": remote_path,
        "bytes_written": bytes_written,
    }))
}

/// Copy a remote file to the local machine via SFTP.
pub async fn scp_pull(
    client: &Arc<Mutex<SshClient>>,
    _config: &ShuttleConfig,
    params: &Value,
) -> omegon_extension::Result<Value> {
    let remote_path = params
        .get("remote_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| omegon_extension::Error::invalid_params("missing 'remote_path'"))?;

    let local_path = params
        .get("local_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| omegon_extension::Error::invalid_params("missing 'local_path'"))?;

    let local = validate_local_path(local_path)?;

    let client_guard = client.lock().await;
    let sftp = client_guard
        .sftp()
        .await
        .map_err(|e| omegon_extension::Error::internal_error(e.to_string()))?;

    let data = sftp
        .read(remote_path)
        .await
        .map_err(|e| omegon_extension::Error::internal_error(format!("sftp read: {e}")))?;

    tokio::fs::write(&local, &data)
        .await
        .map_err(|e| omegon_extension::Error::internal_error(format!("write {local_path}: {e}")))?;

    Ok(json!({
        "host": client_guard.host_name(),
        "remote_path": remote_path,
        "local_path": local_path,
        "bytes_written": data.len(),
    }))
}

/// List files at a path on a remote host.
pub async fn sftp_ls(
    client: &Arc<Mutex<SshClient>>,
    _config: &ShuttleConfig,
    params: &Value,
) -> omegon_extension::Result<Value> {
    let path = params
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| omegon_extension::Error::invalid_params("missing 'path'"))?;

    let client_guard = client.lock().await;
    let sftp = client_guard
        .sftp()
        .await
        .map_err(|e| omegon_extension::Error::internal_error(e.to_string()))?;

    let entries = sftp
        .read_dir(path)
        .await
        .map_err(|e| omegon_extension::Error::internal_error(format!("sftp readdir: {e}")))?;

    let items: Vec<Value> = entries
        .into_iter()
        .map(|entry| {
            json!({
                "name": entry.file_name(),
                "size": entry.metadata().size.unwrap_or(0),
                "is_dir": entry.metadata().is_dir(),
            })
        })
        .collect();

    Ok(json!({
        "host": client_guard.host_name(),
        "path": path,
        "entries": items,
    }))
}

/// Read a remote file's contents without copying it locally.
pub async fn sftp_read(
    client: &Arc<Mutex<SshClient>>,
    config: &ShuttleConfig,
    params: &Value,
) -> omegon_extension::Result<Value> {
    let path = params
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| omegon_extension::Error::invalid_params("missing 'path'"))?;

    let max_bytes = params
        .get("max_bytes")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or(config.max_output_bytes)
        .min(config.max_output_bytes);

    let client_guard = client.lock().await;
    let sftp = client_guard
        .sftp()
        .await
        .map_err(|e| omegon_extension::Error::internal_error(e.to_string()))?;

    let data = sftp
        .read(path)
        .await
        .map_err(|e| omegon_extension::Error::internal_error(format!("sftp read: {e}")))?;

    let truncated = data.len() > max_bytes;
    let content = if truncated {
        String::from_utf8_lossy(&data[..max_bytes]).into_owned()
    } else {
        String::from_utf8_lossy(&data).into_owned()
    };

    Ok(json!({
        "host": client_guard.host_name(),
        "path": path,
        "content": content,
        "size": data.len(),
        "truncated": truncated,
    }))
}
