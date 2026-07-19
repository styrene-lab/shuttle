use crate::binding::{BindingLease, BindingValidity};
use crate::client::{ClientError, ConnectionTarget, HostVerifier, SshClient};
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
    binding_id: Option<String>,
    host_key_pin: Option<String>,
}

struct PooledConnection {
    client: Arc<Mutex<SshClient>>,
    last_used: Instant,
    expires_at: Option<std::time::SystemTime>,
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
        binding: Option<Arc<BindingLease>>,
    ) -> Result<Arc<Mutex<SshClient>>, ClientError> {
        let entry = config
            .resolve_host(host_name)
            .map_err(|error| ClientError::Auth(error.to_string()))?;
        let (resolved_auth, profile) = entry
            .resolve_auth(auth_name)
            .map_err(|error| ClientError::Auth(error.to_string()))?;
        let (address, port, binding_id, host_key_pin, validity) = match &binding {
            Some(lease) => {
                let binding = lease.binding();
                (
                    binding.address.to_string(),
                    binding.port,
                    Some(binding.binding_id.clone()),
                    Some(
                        binding
                            .host_key_pin
                            .canonical_fingerprint()
                            .map_err(|error| ClientError::Binding(error.to_string()))?,
                    ),
                    Some(lease.validity()),
                )
            }
            None => (entry.address.clone(), entry.port, None, None, None),
        };
        let expires_at = validity.as_ref().map(BindingValidity::expires_at);
        let key = ConnectionKey {
            host: host_name.to_owned(),
            address,
            port,
            user: entry.user.clone(),
            auth: resolved_auth,
            binding_id,
            host_key_pin,
        };

        {
            let mut entries = self.entries.lock().await;
            if let Some(pooled) = entries.get_mut(&key) {
                let expired = pooled
                    .expires_at
                    .is_some_and(|expires_at| expires_at <= std::time::SystemTime::now());
                if !expired
                    && pooled.client.lock().await.is_valid()
                    && !pooled.client.lock().await.is_closed()
                {
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

        let connect = async {
            match binding.as_ref() {
                Some(lease) => {
                    let binding = lease.binding();
                    let target = ConnectionTarget {
                        address: binding.address.to_string(),
                        port: binding.port,
                        verifier: HostVerifier::EphemeralPinnedKey {
                            logical_host: host_name.to_string(),
                            pin: binding.host_key_pin.clone(),
                        },
                        valid_until: Some(lease.validity()),
                    };
                    SshClient::connect_target(host_name, entry, &profile, root, password, target)
                        .await
                }
                None => {
                    SshClient::connect(
                        host_name,
                        entry,
                        &profile,
                        root,
                        password,
                        &config.known_hosts_file,
                    )
                    .await
                }
            }
        };
        let connect_timeout = match expires_at {
            Some(expiry) => expiry
                .duration_since(std::time::SystemTime::now())
                .map_err(|_| ClientError::Binding("endpoint binding expired".to_string()))?
                .min(std::time::Duration::from_secs(config.connect_timeout_secs)),
            None => std::time::Duration::from_secs(config.connect_timeout_secs),
        };
        if let Some(validity) = validity.as_ref() {
            validity
                .ensure_valid()
                .map_err(|error| ClientError::Binding(error.to_string()))?;
        }
        let client = Arc::new(Mutex::new(
            tokio::time::timeout(connect_timeout, connect)
                .await
                .map_err(|_| {
                    ClientError::Timeout(format!("{host_name} (connect)"), connect_timeout)
                })??,
        ));

        let mut entries = self.entries.lock().await;
        // Another caller may have connected concurrently. Prefer the already
        // published live session and let this redundant session drop.
        if let Some(existing) = entries.get_mut(&key) {
            let expired = existing
                .expires_at
                .is_some_and(|expires_at| expires_at <= std::time::SystemTime::now());
            if !expired
                && existing.client.lock().await.is_valid()
                && !existing.client.lock().await.is_closed()
            {
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
                expires_at,
            },
        );
        Ok(client)
    }

    pub async fn size(&self) -> usize {
        self.entries.lock().await.len()
    }
}
