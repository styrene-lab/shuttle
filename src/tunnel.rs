use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

const MAX_TUNNELS: usize = 8;
const MIN_LOCAL_PORT: u16 = 1024;

fn is_strict_loopback(host: &str) -> bool {
    if host == "localhost" {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.is_loopback(),
        Ok(IpAddr::V6(v6)) => v6.is_loopback(),
        Err(_) => false,
    }
}

fn normalize_tunnel_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn tunnel_destination_allowed(allowed: &[String], remote_host: &str, remote_port: u16) -> bool {
    let normalized_host = normalize_tunnel_host(remote_host);
    allowed.iter().any(|entry| {
        let entry = entry.trim();
        let Some((host, port)) = entry.rsplit_once(':') else {
            return false;
        };
        let allowed_host = normalize_tunnel_host(host.trim_matches(['[', ']']));
        allowed_host == normalized_host && (port == "*" || port == remote_port.to_string())
    })
}

/// Tracks active tunnels and their state.
pub struct TunnelManager {
    tunnels: Arc<Mutex<HashMap<String, TunnelEntry>>>,
    next_id: Arc<std::sync::atomic::AtomicU64>,
}

struct TunnelEntry {
    host: String,
    local_port: u16,
    remote_host: String,
    remote_port: u16,
    cancel: tokio::sync::watch::Sender<bool>,
}

impl Default for TunnelManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TunnelManager {
    pub fn new() -> Self {
        Self {
            tunnels: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        }
    }

    /// Open a local-to-remote port-forward tunnel.
    ///
    /// Binds a local TCP listener and for each incoming connection, opens a
    /// direct-tcpip channel through the SSH host to forward traffic.
    pub async fn open(
        &self,
        host_name: &str,
        local_port: u16,
        remote_host: &str,
        remote_port: u16,
        allowed_tunnel_destinations: &Option<Vec<String>>,
        ssh_client: Arc<Mutex<crate::client::SshClient>>,
    ) -> omegon_extension::Result<Value> {
        // Enforce tunnel count limit
        let current = self.tunnels.lock().await.len();
        if current >= MAX_TUNNELS {
            return Err(omegon_extension::Error::internal_error(format!(
                "tunnel limit reached ({MAX_TUNNELS}). Close an existing tunnel first."
            )));
        }

        // Enforce unprivileged ports only
        if local_port < MIN_LOCAL_PORT {
            return Err(omegon_extension::Error::invalid_params(format!(
                "local_port must be >= {MIN_LOCAL_PORT} (got {local_port})"
            )));
        }

        // Enforce tunnel destination allowlist
        if let Some(ref allowed) = allowed_tunnel_destinations {
            let dest = format!("{}:{remote_port}", normalize_tunnel_host(remote_host));
            if !tunnel_destination_allowed(allowed, remote_host, remote_port) {
                return Err(omegon_extension::Error::invalid_params(format!(
                    "tunnel destination {dest} not in allowed_tunnel_destinations"
                )));
            }
        } else {
            // No explicit allowlist — only permit strict loopback.
            // Parse as IP to block alternative representations (0.0.0.0,
            // 127.0.0.2, ::ffff:127.0.0.1, hex/octal forms).
            if !is_strict_loopback(remote_host) {
                return Err(omegon_extension::Error::invalid_params(format!(
                    "tunnel to '{remote_host}' requires allowed_tunnel_destinations \
                     in config (only 127.0.0.1 and ::1 are allowed by default)"
                )));
            }
        }

        let listener = TcpListener::bind(format!("127.0.0.1:{local_port}"))
            .await
            .map_err(|e| {
                omegon_extension::Error::internal_error(format!("bind port {local_port}: {e}"))
            })?;

        let actual_port = listener
            .local_addr()
            .map(|a| a.port())
            .unwrap_or(local_port);

        let id = format!(
            "tun-{}",
            self.next_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );

        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

        let rhost = remote_host.to_string();
        let rport = remote_port;
        let spawn_id = id.clone();

        tokio::spawn(async move {
            let tunnel_id = spawn_id;
            let mut cancel_rx = cancel_rx;
            loop {
                tokio::select! {
                    accept = listener.accept() => {
                        let Ok((mut local_stream, _)) = accept else {
                            break;
                        };
                        let client = ssh_client.clone();
                        let rh = rhost.clone();
                        let tid = tunnel_id.clone();
                        tokio::spawn(async move {
                            let client_guard = client.lock().await;
                            let channel = match client_guard
                                .direct_tcpip(&rh, rport as u32, "127.0.0.1", 0)
                                .await
                            {
                                Ok(ch) => ch,
                                Err(e) => {
                                    tracing::error!(tunnel = %tid, "direct-tcpip failed: {e}");
                                    return;
                                }
                            };
                            drop(client_guard);
                            let mut stream = channel.into_stream();
                            let _ = tokio::io::copy_bidirectional(&mut local_stream, &mut stream).await;
                        });
                    }
                    _ = cancel_rx.changed() => {
                        if *cancel_rx.borrow() {
                            break;
                        }
                    }
                }
            }
            tracing::info!(tunnel = %tunnel_id, "tunnel closed");
        });

        self.tunnels.lock().await.insert(
            id.clone(),
            TunnelEntry {
                host: host_name.to_string(),
                local_port: actual_port,
                remote_host: remote_host.to_string(),
                remote_port,
                cancel: cancel_tx,
            },
        );

        Ok(json!({
            "tunnel_id": id,
            "host": host_name,
            "local_port": actual_port,
            "remote_host": remote_host,
            "remote_port": remote_port,
        }))
    }

    /// Close a tunnel by ID.
    pub async fn close(&self, tunnel_id: &str) -> omegon_extension::Result<Value> {
        let mut tunnels = self.tunnels.lock().await;
        let entry = tunnels.remove(tunnel_id).ok_or_else(|| {
            omegon_extension::Error::invalid_params(format!("tunnel not found: {tunnel_id}"))
        })?;

        let _ = entry.cancel.send(true);

        Ok(json!({
            "tunnel_id": tunnel_id,
            "closed": true,
        }))
    }

    /// List all active tunnels.
    pub async fn list(&self) -> omegon_extension::Result<Value> {
        let tunnels = self.tunnels.lock().await;
        let items: Vec<Value> = tunnels
            .iter()
            .map(|(id, t)| {
                json!({
                    "tunnel_id": id,
                    "host": t.host,
                    "local_port": t.local_port,
                    "remote_host": t.remote_host,
                    "remote_port": t.remote_port,
                })
            })
            .collect();

        Ok(json!({ "tunnels": items }))
    }
}
