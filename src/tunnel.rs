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

#[doc(hidden)]
pub fn tunnel_destination_allowed_for_test(
    allowed: &[String],
    remote_host: &str,
    remote_port: u16,
) -> bool {
    tunnel_destination_allowed(allowed, remote_host, remote_port)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TunnelStatus {
    Listening,
    Degraded,
    Closed,
}

impl TunnelStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Listening => "listening",
            Self::Degraded => "degraded",
            Self::Closed => "closed",
        }
    }
}

#[derive(Debug)]
struct TunnelRuntime {
    status: TunnelStatus,
    active_connections: usize,
    accepted_connections: u64,
    failed_connections: u64,
    last_error: Option<String>,
}

/// Tracks local listeners and their forwarding health independently from the
/// underlying transport. A future mesh transport can feed the same lifecycle
/// surface without changing the public tunnel tools.
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
    runtime: Arc<Mutex<TunnelRuntime>>,
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

    pub async fn open(
        &self,
        host_name: &str,
        local_port: u16,
        remote_host: &str,
        remote_port: u16,
        allowed_tunnel_destinations: &Option<Vec<String>>,
        ssh_client: Arc<Mutex<crate::client::SshClient>>,
    ) -> omegon_extension::Result<Value> {
        let current = self.tunnels.lock().await.len();
        if current >= MAX_TUNNELS {
            return Err(omegon_extension::Error::internal_error(format!(
                "tunnel limit reached ({MAX_TUNNELS}). Close an existing tunnel first."
            )));
        }
        if local_port < MIN_LOCAL_PORT {
            return Err(omegon_extension::Error::invalid_params(format!(
                "local_port must be >= {MIN_LOCAL_PORT} (got {local_port})"
            )));
        }

        if let Some(ref allowed) = allowed_tunnel_destinations {
            let dest = format!("{}:{remote_port}", normalize_tunnel_host(remote_host));
            if !tunnel_destination_allowed(allowed, remote_host, remote_port) {
                return Err(omegon_extension::Error::invalid_params(format!(
                    "tunnel destination {dest} not in allowed_tunnel_destinations"
                )));
            }
        } else if !is_strict_loopback(remote_host) {
            return Err(omegon_extension::Error::invalid_params(format!(
                "tunnel to '{remote_host}' requires allowed_tunnel_destinations in config (only 127.0.0.1 and ::1 are allowed by default)"
            )));
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
        let (cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);
        let runtime = Arc::new(Mutex::new(TunnelRuntime {
            status: TunnelStatus::Listening,
            active_connections: 0,
            accepted_connections: 0,
            failed_connections: 0,
            last_error: None,
        }));

        let rhost = remote_host.to_string();
        let spawn_id = id.clone();
        let spawn_runtime = runtime.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept = listener.accept() => {
                        let (mut local_stream, _) = match accept {
                            Ok(value) => value,
                            Err(error) => {
                                let mut state = spawn_runtime.lock().await;
                                state.status = TunnelStatus::Degraded;
                                state.last_error = Some(format!("local accept failed: {error}"));
                                tracing::error!(tunnel = %spawn_id, error = %error, "tunnel listener failed");
                                break;
                            }
                        };
                        {
                            let mut state = spawn_runtime.lock().await;
                            state.accepted_connections += 1;
                            state.active_connections += 1;
                        }
                        let client = ssh_client.clone();
                        let rh = rhost.clone();
                        let tid = spawn_id.clone();
                        let conn_runtime = spawn_runtime.clone();
                        tokio::spawn(async move {
                            let (channel_result, validity) = {
                                let client_guard = client.lock().await;
                                (
                                    client_guard.direct_tcpip(&rh, remote_port as u32, "127.0.0.1", 0).await,
                                    client_guard.binding_validity(),
                                )
                            };
                            match channel_result {
                                Ok(channel) => {
                                    let mut stream = channel.into_stream();
                                    let forwarding = tokio::io::copy_bidirectional(&mut local_stream, &mut stream);
                                    tokio::pin!(forwarding);
                                    let result = if let Some(validity) = validity {
                                        loop {
                                            tokio::select! {
                                                result = &mut forwarding => break result,
                                                _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => {
                                                    if !validity.is_valid() {
                                                        break Err(std::io::Error::new(
                                                            std::io::ErrorKind::PermissionDenied,
                                                            "endpoint binding expired or was revoked",
                                                        ));
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        forwarding.await
                                    };
                                    if let Err(error) = result {
                                        let mut state = conn_runtime.lock().await;
                                        state.failed_connections += 1;
                                        state.last_error = Some(format!("forwarding failed: {error}"));
                                        tracing::warn!(tunnel = %tid, error = %error, "tunnel forwarding failed");
                                    }
                                }
                                Err(error) => {
                                    let mut state = conn_runtime.lock().await;
                                    state.status = TunnelStatus::Degraded;
                                    state.failed_connections += 1;
                                    state.last_error = Some(format!("direct-tcpip failed: {error}"));
                                    tracing::error!(tunnel = %tid, error = %error, "direct-tcpip failed");
                                }
                            }
                            let mut state = conn_runtime.lock().await;
                            state.active_connections = state.active_connections.saturating_sub(1);
                        });
                    }
                    changed = cancel_rx.changed() => {
                        if changed.is_err() || *cancel_rx.borrow() {
                            break;
                        }
                    }
                }
            }
            let mut state = spawn_runtime.lock().await;
            state.status = TunnelStatus::Closed;
            tracing::info!(tunnel = %spawn_id, "tunnel listener closed");
        });

        self.tunnels.lock().await.insert(
            id.clone(),
            TunnelEntry {
                host: host_name.to_string(),
                local_port: actual_port,
                remote_host: remote_host.to_string(),
                remote_port,
                cancel: cancel_tx,
                runtime,
            },
        );

        Ok(json!({
            "tunnel_id": id,
            "host": host_name,
            "transport": "ssh",
            "status": "listening",
            "local_port": actual_port,
            "remote_host": remote_host,
            "remote_port": remote_port,
        }))
    }

    pub async fn close(&self, tunnel_id: &str) -> omegon_extension::Result<Value> {
        let entry = self.tunnels.lock().await.remove(tunnel_id).ok_or_else(|| {
            omegon_extension::Error::invalid_params(format!("tunnel not found: {tunnel_id}"))
        })?;
        let _ = entry.cancel.send(true);
        entry.runtime.lock().await.status = TunnelStatus::Closed;
        Ok(json!({ "tunnel_id": tunnel_id, "closed": true }))
    }

    pub async fn list(&self) -> omegon_extension::Result<Value> {
        let tunnels = self.tunnels.lock().await;
        let mut items = Vec::with_capacity(tunnels.len());
        for (id, tunnel) in tunnels.iter() {
            let runtime = tunnel.runtime.lock().await;
            items.push(json!({
                "tunnel_id": id,
                "host": tunnel.host,
                "transport": "ssh",
                "status": runtime.status.as_str(),
                "local_port": tunnel.local_port,
                "remote_host": tunnel.remote_host,
                "remote_port": tunnel.remote_port,
                "active_connections": runtime.active_connections,
                "accepted_connections": runtime.accepted_connections,
                "failed_connections": runtime.failed_connections,
                "last_error": runtime.last_error,
            }));
        }
        Ok(json!({ "tunnels": items }))
    }
}
