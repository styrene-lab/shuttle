use crate::config::ShuttleConfig;
use crate::pool::ConnectionPool;
use crate::tools;
use crate::tunnel::TunnelManager;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use styrene_identity::signer::{IdentitySigner, RootSecret};
use tokio::sync::RwLock;
use zeroize::Zeroize;

pub struct ShuttleExtension {
    config: Arc<RwLock<ShuttleConfig>>,
    pool: ConnectionPool,
    tunnels: TunnelManager,
    /// Holds the signer so re-derivation works after TTL expiry without
    /// needing the env var again.
    signer: Arc<RwLock<Option<Box<dyn IdentitySigner>>>>,
    root_cache: Arc<RwLock<CachedRoot>>,
}

const ROOT_SECRET_TTL: std::time::Duration = std::time::Duration::from_secs(300);

struct CachedRoot {
    secret: Option<RootSecret>,
    cached_at: Option<std::time::Instant>,
}

impl CachedRoot {
    fn empty() -> Self {
        Self {
            secret: None,
            cached_at: None,
        }
    }

    fn get(&self) -> Option<&RootSecret> {
        let cached_at = self.cached_at?;
        if cached_at.elapsed() > ROOT_SECRET_TTL {
            return None;
        }
        self.secret.as_ref()
    }

    fn set(&mut self, root: &RootSecret) {
        self.secret = Some(RootSecret::new(*root.as_bytes()));
        self.cached_at = Some(std::time::Instant::now());
    }
}

impl ShuttleExtension {
    pub fn new() -> Self {
        let config = ShuttleConfig::default();
        Self {
            config: Arc::new(RwLock::new(config)),
            pool: ConnectionPool::new(),
            tunnels: TunnelManager::new(),
            signer: Arc::new(RwLock::new(None)),
            root_cache: Arc::new(RwLock::new(CachedRoot::empty())),
        }
    }

    /// Ensure the signer is initialized (first call only).
    async fn ensure_signer(&self) -> omegon_extension::Result<()> {
        {
            let s = self.signer.read().await;
            if s.is_some() {
                return Ok(());
            }
        }

        let discovered = styrene_identity::discover::discover().ok_or_else(|| {
            omegon_extension::Error::internal_error(
                "no styrene identity found — run `styrene identity init` first",
            )
        })?;

        // Read passphrase from env once, then remove it so child processes
        // and /proc/pid/environ don't inherit it.
        let mut passphrase = std::env::var("STYRENE_PASSPHRASE")
            .map(|s| s.into_bytes())
            .map_err(|_| {
                omegon_extension::Error::internal_error(
                    "set STYRENE_PASSPHRASE to unlock the identity file",
                )
            })?;

        #[allow(unused_unsafe)]
        unsafe {
            std::env::remove_var("STYRENE_PASSPHRASE");
        }

        let provider = styrene_identity::file_signer::StaticPassphraseProvider::new(&passphrase);
        passphrase.zeroize();

        let signer =
            styrene_identity::file_signer::FileSigner::new(&discovered.path, Box::new(provider));

        let mut s = self.signer.write().await;
        *s = Some(Box::new(signer));
        Ok(())
    }

    async fn root_secret(&self) -> omegon_extension::Result<RootSecret> {
        // Fast path: TTL cache hit
        {
            let cache = self.root_cache.read().await;
            if let Some(root) = cache.get() {
                return Ok(RootSecret::new(*root.as_bytes()));
            }
        }

        // Slow path: derive from signer (works after TTL expiry too)
        self.ensure_signer().await?;
        let signer_guard = self.signer.read().await;
        let signer = signer_guard.as_ref().unwrap();
        let root = signer.root_secret().await.map_err(|e| {
            omegon_extension::Error::internal_error(format!("unlock identity: {e}"))
        })?;

        let mut cache = self.root_cache.write().await;
        cache.set(&root);

        Ok(root)
    }

    async fn execute_tool(&self, name: &str, params: Value) -> omegon_extension::Result<Value> {
        match name {
            "ssh_exec" => self.tool_ssh_exec(params).await,
            "ssh_script" => self.tool_ssh_script(params).await,
            "scp_push" => self.tool_scp_push(params).await,
            "scp_pull" => self.tool_scp_pull(params).await,
            "sftp_ls" => self.tool_sftp_ls(params).await,
            "sftp_read" => self.tool_sftp_read(params).await,
            "ssh_tunnel_open" => self.tool_tunnel_open(params).await,
            "ssh_tunnel_close" => self.tool_tunnel_close(params).await,
            "ssh_tunnel_list" => self.tool_tunnel_list(params).await,
            "ssh_hosts" => self.tool_ssh_hosts(params).await,
            "ssh_ping" => self.tool_ssh_ping(params).await,
            "ssh_migrate_analyze" => self.tool_migrate_analyze(params).await,
            _ => Err(omegon_extension::Error::method_not_found(&format!(
                "tool '{name}'"
            ))),
        }
    }

    fn extract_host(params: &Value) -> omegon_extension::Result<&str> {
        params
            .get("host")
            .and_then(|v| v.as_str())
            .ok_or_else(|| omegon_extension::Error::invalid_params("missing 'host'"))
    }

    async fn acquire_client(
        &self,
        host_name: &str,
    ) -> omegon_extension::Result<Arc<tokio::sync::Mutex<crate::client::SshClient>>> {
        let config = self.config.read().await;
        let root = self.root_secret().await?;
        self.pool
            .acquire(host_name, &config, &root)
            .await
            .map_err(|e| omegon_extension::Error::internal_error(e.to_string()))
    }

    // ── Tool implementations ─────────────────────────────────────────────

    async fn tool_ssh_exec(&self, params: Value) -> omegon_extension::Result<Value> {
        let host = Self::extract_host(&params)?;
        let command = params.get("command").and_then(|v| v.as_str()).unwrap_or("");
        let command_hash = format!("{:016x}", fxhash(command.as_bytes()));
        tracing::info!(
            tool = "ssh_exec",
            host,
            command_hash,
            command_len = command.len(),
            "executing remote command"
        );
        let client = self.acquire_client(host).await?;
        let config = self.config.read().await;
        let result = crate::exec::ssh_exec(&client, &config, &params).await;
        if let Ok(ref v) = result {
            tracing::info!(
                tool = "ssh_exec",
                host,
                exit_code = v.get("exit_code").and_then(|v| v.as_u64()).unwrap_or(255),
                truncated = v
                    .get("truncated")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                "command completed"
            );
        }
        result
    }

    async fn tool_ssh_script(&self, params: Value) -> omegon_extension::Result<Value> {
        let host = Self::extract_host(&params)?;
        let script = params.get("script").and_then(|v| v.as_str()).unwrap_or("");
        let interpreter = params
            .get("interpreter")
            .and_then(|v| v.as_str())
            .unwrap_or("/bin/bash");
        let script_hash = format!("{:016x}", fxhash(script.as_bytes()));
        tracing::info!(
            tool = "ssh_script",
            host,
            interpreter,
            script_hash,
            script_len = script.len(),
            "executing remote script"
        );
        let client = self.acquire_client(host).await?;
        let config = self.config.read().await;
        let result = crate::exec::ssh_script(&client, &config, &params).await;
        if let Ok(ref v) = result {
            tracing::info!(
                tool = "ssh_script",
                host,
                exit_code = v.get("exit_code").and_then(|v| v.as_u64()).unwrap_or(255),
                "script completed"
            );
        }
        result
    }

    async fn tool_scp_push(&self, params: Value) -> omegon_extension::Result<Value> {
        let host = Self::extract_host(&params)?;
        let local = params
            .get("local_path")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let remote = params
            .get("remote_path")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        tracing::info!(
            tool = "scp_push",
            host,
            local_hash = format!("{:016x}", fxhash(local.as_bytes())),
            remote_hash = format!("{:016x}", fxhash(remote.as_bytes())),
            "uploading file"
        );
        let client = self.acquire_client(host).await?;
        let config = self.config.read().await;
        let result = crate::transfer::scp_push(&client, &config, &params).await;
        if let Ok(ref v) = result {
            tracing::info!(
                tool = "scp_push",
                host,
                bytes = v.get("bytes_written").and_then(|v| v.as_u64()).unwrap_or(0),
                "upload complete"
            );
        }
        result
    }

    async fn tool_scp_pull(&self, params: Value) -> omegon_extension::Result<Value> {
        let host = Self::extract_host(&params)?;
        let remote = params
            .get("remote_path")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let local = params
            .get("local_path")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        tracing::info!(
            tool = "scp_pull",
            host,
            remote_hash = format!("{:016x}", fxhash(remote.as_bytes())),
            local_hash = format!("{:016x}", fxhash(local.as_bytes())),
            "downloading file"
        );
        let client = self.acquire_client(host).await?;
        let config = self.config.read().await;
        crate::transfer::scp_pull(&client, &config, &params).await
    }

    async fn tool_sftp_ls(&self, params: Value) -> omegon_extension::Result<Value> {
        let host = Self::extract_host(&params)?;
        let path = params.get("path").and_then(|v| v.as_str()).unwrap_or("");
        tracing::info!(
            tool = "sftp_ls",
            host,
            path_hash = format!("{:016x}", fxhash(path.as_bytes())),
            "listing remote directory"
        );
        let client = self.acquire_client(host).await?;
        let config = self.config.read().await;
        crate::transfer::sftp_ls(&client, &config, &params).await
    }

    async fn tool_sftp_read(&self, params: Value) -> omegon_extension::Result<Value> {
        let host = Self::extract_host(&params)?;
        let path = params.get("path").and_then(|v| v.as_str()).unwrap_or("");
        tracing::info!(
            tool = "sftp_read",
            host,
            path_hash = format!("{:016x}", fxhash(path.as_bytes())),
            "reading remote file"
        );
        let client = self.acquire_client(host).await?;
        let config = self.config.read().await;
        let result = crate::transfer::sftp_read(&client, &config, &params).await;
        if let Ok(ref v) = result {
            tracing::info!(
                tool = "sftp_read",
                host,
                size = v.get("size").and_then(|v| v.as_u64()).unwrap_or(0),
                truncated = v
                    .get("truncated")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                "read complete"
            );
        }
        result
    }

    async fn tool_tunnel_open(&self, params: Value) -> omegon_extension::Result<Value> {
        let host = Self::extract_host(&params)?;
        let local_port_raw = params
            .get("local_port")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| omegon_extension::Error::invalid_params("missing 'local_port'"))?;
        if local_port_raw > 65535 {
            return Err(omegon_extension::Error::invalid_params(format!(
                "local_port must be 0-65535 (got {local_port_raw})"
            )));
        }
        let local_port = local_port_raw as u16;
        let remote_host = params
            .get("remote_host")
            .and_then(|v| v.as_str())
            .unwrap_or("127.0.0.1");
        let remote_port_raw = params
            .get("remote_port")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| omegon_extension::Error::invalid_params("missing 'remote_port'"))?;
        if remote_port_raw > 65535 {
            return Err(omegon_extension::Error::invalid_params(format!(
                "remote_port must be 0-65535 (got {remote_port_raw})"
            )));
        }
        let remote_port = remote_port_raw as u16;

        tracing::info!(
            tool = "ssh_tunnel_open",
            host,
            local_port,
            remote_host,
            remote_port,
            "opening tunnel"
        );
        let client = self.acquire_client(host).await?;
        let config = self.config.read().await;
        self.tunnels
            .open(
                host,
                local_port,
                remote_host,
                remote_port,
                &config.allowed_tunnel_destinations,
                client,
            )
            .await
    }

    async fn tool_tunnel_close(&self, params: Value) -> omegon_extension::Result<Value> {
        let tunnel_id = params
            .get("tunnel_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| omegon_extension::Error::invalid_params("missing 'tunnel_id'"))?;
        tracing::info!(tool = "ssh_tunnel_close", tunnel_id, "closing tunnel");
        self.tunnels.close(tunnel_id).await
    }

    async fn tool_tunnel_list(&self, _params: Value) -> omegon_extension::Result<Value> {
        self.tunnels.list().await
    }

    async fn tool_migrate_analyze(&self, params: Value) -> omegon_extension::Result<Value> {
        tracing::info!(
            tool = "ssh_migrate_analyze",
            "scanning ~/.ssh for migration"
        );
        crate::migrate::ssh_migrate_analyze(&params).await
    }

    async fn tool_ssh_hosts(&self, _params: Value) -> omegon_extension::Result<Value> {
        let config = self.config.read().await;
        let hosts: Vec<Value> = config
            .host_names()
            .into_iter()
            .filter_map(|name| {
                config.resolve_host(name).ok().map(|entry| {
                    json!({
                        "name": name,
                        "address": entry.address,
                        "user": entry.user,
                        "port": entry.port,
                    })
                })
            })
            .collect();
        Ok(json!({ "hosts": hosts }))
    }

    async fn tool_ssh_ping(&self, params: Value) -> omegon_extension::Result<Value> {
        let host = Self::extract_host(&params)?;
        tracing::info!(tool = "ssh_ping", host, "testing connectivity");
        let start = std::time::Instant::now();
        match self.acquire_client(host).await {
            Ok(_client) => {
                let elapsed = start.elapsed();
                tracing::info!(
                    tool = "ssh_ping",
                    host,
                    latency_ms = elapsed.as_millis(),
                    "reachable"
                );
                Ok(json!({
                    "host": host,
                    "reachable": true,
                    "latency_ms": elapsed.as_millis(),
                }))
            }
            Err(e) => {
                tracing::warn!(tool = "ssh_ping", host, error = %e, "unreachable");
                Ok(json!({
                    "host": host,
                    "reachable": false,
                    "error": e.to_string(),
                }))
            }
        }
    }
}

/// Fast non-cryptographic hash for audit log script fingerprinting.
fn fxhash(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in data {
        hash = hash.wrapping_mul(0x100000001b3);
        hash ^= b as u64;
    }
    hash
}

#[async_trait::async_trait]
impl omegon_extension::Extension for ShuttleExtension {
    fn name(&self) -> &str {
        "shuttle"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    async fn handle_rpc(&self, method: &str, params: Value) -> omegon_extension::Result<Value> {
        match method {
            "initialize" => {
                let tools = tools::tool_definitions();
                Ok(json!({
                    "protocol_version": 2,
                    "extension_info": {
                        "name": self.name(),
                        "version": self.version(),
                        "sdk_version": "0.19"
                    },
                    "capabilities": {
                        "tools": true,
                    },
                    "tools": tools,
                }))
            }

            "get_tools" | "tools/list" => Ok(json!(tools::tool_definitions())),

            "bootstrap_config" => {
                let map: HashMap<String, Value> =
                    serde_json::from_value(params).unwrap_or_default();
                self.on_config(map).await;
                Ok(json!({ "acknowledged": true }))
            }

            "execute_tool" | "tools/call" => {
                let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or(json!({}));
                self.execute_tool(name, args).await
            }

            _ => Err(omegon_extension::Error::method_not_found(method)),
        }
    }

    async fn on_config(&self, config: HashMap<String, Value>) {
        let mut cfg = self.config.write().await;
        cfg.apply_rpc_config(&config);

        if let Err(e) = cfg.load_hosts() {
            tracing::warn!("failed to load hosts: {e}");
        } else {
            let host_count = cfg.host_names().len();
            tracing::info!(
                hosts = host_count,
                "hosts loaded from {}",
                cfg.hosts_file.display()
            );

            if cfg.allowed_hosts.is_none() && !cfg.allow_all_hosts {
                tracing::error!(
                    "allowed_hosts is not configured and allow_all_hosts is false — no hosts are accessible. Set allowed_hosts or explicitly set allow_all_hosts=true."
                );
            } else if cfg.allowed_hosts.is_none() {
                tracing::warn!(
                    "allow_all_hosts=true — all {} hosts in hosts.toml are accessible. Prefer allowed_hosts for least privilege.",
                    host_count
                );
            }
        }
    }
}
