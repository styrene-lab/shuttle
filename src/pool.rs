use crate::client::{ClientError, SshClient};
use crate::config::{AuthProfile, ShuttleConfig};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use styrene_identity::signer::RootSecret;
use tokio::sync::Mutex;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ConnectionKey {
    host: String,
    address: String,
    port: u16,
    user: String,
    auth: String,
}

struct PooledConnection {
    client: Arc<Mutex<SshClient>>,
    last_used: Instant,
}

/// Bounded cache of authenticated SSH sessions.
///
/// Pool identity includes the exact authentication profile. Sessions are never
/// reused across profiles, even when two profiles happen to derive the same key.
pub struct ConnectionPool {
    entries: Mutex<HashMap<ConnectionKey, PooledConnection>>,
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Reuse a live connection or create a fresh one using exactly one selected
    /// profile. Authentication never falls back to another profile.
    pub async fn acquire(
        &self,
        host_name: &str,
        auth_name: Option<&str>,
        config: &ShuttleConfig,
        root: Option<&RootSecret>,
        password: Option<String>,
    ) -> Result<Arc<Mutex<SshClient>>, ClientError> {
        let entry = config
            .resolve_host(host_name)
            .map_err(|error| ClientError::Auth(error.to_string()))?;
        let (resolved_auth, profile) = entry
            .resolve_auth(auth_name)
            .map_err(|error| ClientError::Auth(error.to_string()))?;
        let key = ConnectionKey {
            host: host_name.to_owned(),
            address: entry.address.clone(),
            port: entry.port,
            user: entry.user.clone(),
            auth: resolved_auth,
        };

        {
            let mut entries = self.entries.lock().await;
            if let Some(pooled) = entries.get_mut(&key) {
                if !pooled.client.lock().await.is_closed() {
                    pooled.last_used = Instant::now();
                    tracing::debug!(host = host_name, auth = %key.auth, "reusing pooled SSH session");
                    return Ok(pooled.client.clone());
                }
                entries.remove(&key);
                tracing::info!(host = host_name, auth = %key.auth, "discarded closed SSH session");
            }
        }

        if matches!(profile, AuthProfile::PublicKey { .. }) && root.is_none() {
            return Err(ClientError::Auth(
                "public-key identity is unavailable".to_string(),
            ));
        }

        let client = Arc::new(Mutex::new(
            tokio::time::timeout(
                std::time::Duration::from_secs(config.connect_timeout_secs),
                SshClient::connect(
                    host_name,
                    entry,
                    &profile,
                    root,
                    password,
                    &config.known_hosts_file,
                ),
            )
            .await
            .map_err(|_| {
                ClientError::Timeout(
                    format!("{host_name} (connect)"),
                    std::time::Duration::from_secs(config.connect_timeout_secs),
                )
            })??,
        ));

        let mut entries = self.entries.lock().await;
        // Another caller may have connected concurrently. Prefer the already
        // published live session and let this redundant session drop.
        if let Some(existing) = entries.get_mut(&key) {
            if !existing.client.lock().await.is_closed() {
                existing.last_used = Instant::now();
                return Ok(existing.client.clone());
            }
        }

        while entries.len() >= config.connection_pool_size {
            let oldest = entries
                .iter()
                .min_by_key(|(_, value)| value.last_used)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                entries.remove(&oldest);
                tracing::debug!(host = %oldest.host, auth = %oldest.auth, "evicted SSH session from pool");
            } else {
                break;
            }
        }
        entries.insert(
            key,
            PooledConnection {
                client: client.clone(),
                last_used: Instant::now(),
            },
        );
        Ok(client)
    }

    pub async fn size(&self) -> usize {
        self.entries.lock().await.len()
    }
}
