use crate::client::SshClient;
use crate::config::ShuttleConfig;
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
fn validate_local_path(
    path: &str,
    allowed_roots: &Option<Vec<std::path::PathBuf>>,
) -> omegon_extension::Result<std::path::PathBuf> {
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
        .map_err(|e| omegon_extension::Error::invalid_params(format!("invalid path: {e}")))?;

    let canonical_str = canonical.to_string_lossy();
    if canonical_str.contains("..") {
        return Err(omegon_extension::Error::invalid_params(
            "path traversal not allowed",
        ));
    }

    // Positive allowlist: local transfer paths must remain under an
    // operator-approved root (defaults to the process cwd). The sensitive
    // blocklist below remains defense-in-depth.
    if let Some(roots) = allowed_roots {
        if !roots.iter().any(|root| canonical.starts_with(root)) {
            return Err(omegon_extension::Error::invalid_params(
                "local path is outside allowed_local_roots",
            ));
        }
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

fn validate_remote_path(
    path: &str,
    allowed_roots: &Option<Vec<String>>,
    operation: &str,
) -> omegon_extension::Result<()> {
    if !path.starts_with('/') || path.split('/').any(|component| component == "..") {
        return Err(omegon_extension::Error::invalid_params(format!(
            "remote {operation} path must be absolute and cannot contain '..'"
        )));
    }
    if path.as_bytes().contains(&0) {
        return Err(omegon_extension::Error::invalid_params(format!(
            "remote {operation} path contains a null byte"
        )));
    }
    if let Some(roots) = allowed_roots {
        let normalized = path.trim_end_matches('/');
        if !roots
            .iter()
            .any(|root| normalized == root || normalized.starts_with(&format!("{root}/")))
        {
            return Err(omegon_extension::Error::invalid_params(format!(
                "remote {operation} path is outside configured allowed roots"
            )));
        }
    }
    Ok(())
}

/// Copy a local file to a remote host via SFTP.
pub async fn scp_push(
    client: &Arc<Mutex<SshClient>>,
    config: &ShuttleConfig,
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

    let local = validate_local_path(local_path, &config.allowed_local_roots)?;
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

    validate_remote_path(remote_path, &config.allowed_remote_write_roots, "write")?;

    let data = tokio::fs::read(&local)
        .await
        .map_err(|e| omegon_extension::Error::internal_error(format!("read {local_path}: {e}")))?;
    if data.len() > config.max_transfer_bytes {
        return Err(omegon_extension::Error::invalid_params(format!(
            "local file exceeds max_transfer_bytes ({})",
            config.max_transfer_bytes
        )));
    }

    let bytes_written = data.len();

    let client_guard = client.lock().await;
    let validity = client_guard.binding_validity();
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
    if let Some(validity) = validity {
        validity
            .ensure_valid()
            .map_err(|e| omegon_extension::Error::internal_error(e.to_string()))?;
    }

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
    config: &ShuttleConfig,
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

    validate_remote_path(remote_path, &config.allowed_remote_read_roots, "read")?;
    let local = validate_local_path(local_path, &config.allowed_local_roots)?;

    let max_bytes = params
        .get("max_bytes")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or(config.max_transfer_bytes)
        .min(config.max_transfer_bytes);

    let client_guard = client.lock().await;
    let validity = client_guard.binding_validity();
    let sftp = client_guard
        .sftp()
        .await
        .map_err(|e| omegon_extension::Error::internal_error(e.to_string()))?;

    let mut remote = sftp
        .open(remote_path)
        .await
        .map_err(|e| omegon_extension::Error::internal_error(format!("sftp open: {e}")))?;
    let mut out = tokio::fs::File::create(&local)
        .await
        .map_err(|e| omegon_extension::Error::internal_error(format!("write {local_path}: {e}")))?;

    let mut remaining = max_bytes + 1;
    let mut bytes_read = 0usize;
    let mut buf = vec![0u8; 8192];
    let mut truncated = false;
    while remaining > 0 {
        if let Some(validity) = &validity {
            validity
                .ensure_valid()
                .map_err(|e| omegon_extension::Error::internal_error(e.to_string()))?;
        }
        let to_read = remaining.min(buf.len());
        let n = remote
            .read(&mut buf[..to_read])
            .await
            .map_err(|e| omegon_extension::Error::internal_error(format!("sftp read: {e}")))?;
        if n == 0 {
            break;
        }
        bytes_read += n;
        remaining -= n;
        let write_n = if bytes_read > max_bytes {
            truncated = true;
            n - (bytes_read - max_bytes)
        } else {
            n
        };
        if write_n > 0 {
            out.write_all(&buf[..write_n]).await.map_err(|e| {
                omegon_extension::Error::internal_error(format!("write {local_path}: {e}"))
            })?;
        }
        if truncated {
            break;
        }
    }

    Ok(json!({
        "host": client_guard.host_name(),
        "remote_path": remote_path,
        "local_path": local_path,
        "bytes_written": bytes_read.min(max_bytes),
        "truncated": truncated,
    }))
}

/// List files at a path on a remote host.
pub async fn sftp_ls(
    client: &Arc<Mutex<SshClient>>,
    config: &ShuttleConfig,
    params: &Value,
) -> omegon_extension::Result<Value> {
    let path = params
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| omegon_extension::Error::invalid_params("missing 'path'"))?;

    validate_remote_path(path, &config.allowed_remote_read_roots, "read")?;

    let client_guard = client.lock().await;
    let validity = client_guard.binding_validity();
    let sftp = client_guard
        .sftp()
        .await
        .map_err(|e| omegon_extension::Error::internal_error(e.to_string()))?;

    let entries = sftp
        .read_dir(path)
        .await
        .map_err(|e| omegon_extension::Error::internal_error(format!("sftp readdir: {e}")))?;
    if let Some(validity) = validity {
        validity
            .ensure_valid()
            .map_err(|e| omegon_extension::Error::internal_error(e.to_string()))?;
    }

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
        .unwrap_or(config.max_transfer_bytes)
        .min(config.max_transfer_bytes);

    let client_guard = client.lock().await;
    let validity = client_guard.binding_validity();
    let sftp = client_guard
        .sftp()
        .await
        .map_err(|e| omegon_extension::Error::internal_error(e.to_string()))?;

    validate_remote_path(path, &config.allowed_remote_read_roots, "read")?;

    let mut remote = sftp
        .open(path)
        .await
        .map_err(|e| omegon_extension::Error::internal_error(format!("sftp open: {e}")))?;
    let mut data = Vec::with_capacity(max_bytes.min(8192));
    let mut remaining = max_bytes + 1;
    let mut buf = vec![0u8; 8192];
    while remaining > 0 {
        if let Some(validity) = &validity {
            validity
                .ensure_valid()
                .map_err(|e| omegon_extension::Error::internal_error(e.to_string()))?;
        }
        let to_read = remaining.min(buf.len());
        let n = remote
            .read(&mut buf[..to_read])
            .await
            .map_err(|e| omegon_extension::Error::internal_error(format!("sftp read: {e}")))?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
        remaining -= n;
    }

    let truncated = data.len() > max_bytes;
    if truncated {
        data.truncate(max_bytes);
    }
    let content = String::from_utf8_lossy(&data).into_owned();

    Ok(json!({
        "host": client_guard.host_name(),
        "path": path,
        "content": content,
        "size": data.len(),
        "truncated": truncated,
    }))
}
