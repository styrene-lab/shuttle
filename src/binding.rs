use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

const MAX_BINDING_TTL: Duration = Duration::from_secs(15 * 60);
const CLOCK_SKEW: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EndpointBinding {
    pub binding_id: String,
    pub issuer: String,
    pub audience: String,
    pub logical_host: String,
    pub address: IpAddr,
    pub port: u16,
    pub host_key_pin: HostKeyPin,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    #[serde(default)]
    pub producer_tool: String,
    #[serde(default)]
    pub provider_reference_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HostKeyPin {
    pub key_algorithm: String,
    pub fingerprint_algorithm: String,
    pub digest_base64: String,
}

impl HostKeyPin {
    pub fn canonical_fingerprint(&self) -> Result<String, BindingError> {
        if self.fingerprint_algorithm != "sha256" {
            return Err(BindingError::Invalid("unsupported fingerprint algorithm"));
        }
        if !matches!(
            self.key_algorithm.as_str(),
            "ssh-ed25519" | "ssh-rsa" | "ecdsa-sha2-nistp256"
        ) {
            return Err(BindingError::Invalid("unsupported SSH key algorithm"));
        }
        use base64::Engine;
        let digest = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(&self.digest_base64)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&self.digest_base64))
            .map_err(|_| BindingError::Invalid("invalid host-key digest encoding"))?;
        if digest.len() != 32 {
            return Err(BindingError::Invalid(
                "SHA-256 host-key digest must be 32 bytes",
            ));
        }
        Ok(format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
        ))
    }
}

impl EndpointBinding {
    pub fn validate(&self, now: SystemTime) -> Result<(), BindingError> {
        if self.binding_id.is_empty() || self.issuer.is_empty() || self.logical_host.is_empty() {
            return Err(BindingError::Invalid(
                "binding identity fields cannot be empty",
            ));
        }
        if self.audience != "shuttle" {
            return Err(BindingError::AudienceMismatch);
        }
        if self.port == 0 || self.address.is_unspecified() || self.address.is_multicast() {
            return Err(BindingError::EndpointPolicyDenied);
        }
        let issued = UNIX_EPOCH + Duration::from_millis(self.issued_at_ms);
        let expires = UNIX_EPOCH + Duration::from_millis(self.expires_at_ms);
        if issued > now + CLOCK_SKEW {
            return Err(BindingError::Invalid("binding issued in the future"));
        }
        if expires <= now {
            return Err(BindingError::Expired);
        }
        if expires
            .duration_since(issued)
            .map_err(|_| BindingError::Invalid("expiry precedes issue time"))?
            > MAX_BINDING_TTL
        {
            return Err(BindingError::Invalid("binding exceeds maximum TTL"));
        }
        self.host_key_pin.canonical_fingerprint()?;
        Ok(())
    }

    pub fn expires_at(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(self.expires_at_ms)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BindingError {
    #[error("endpoint binding is invalid: {0}")]
    Invalid(&'static str),
    #[error("endpoint binding expired")]
    Expired,
    #[error("endpoint binding was revoked or is unknown")]
    Revoked,
    #[error("endpoint binding audience mismatch")]
    AudienceMismatch,
    #[error("endpoint binding denied by endpoint policy")]
    EndpointPolicyDenied,
}

#[derive(Debug)]
pub struct BindingLease {
    binding: EndpointBinding,
    active: Arc<AtomicBool>,
}

impl BindingLease {
    pub fn binding(&self) -> &EndpointBinding {
        &self.binding
    }

    pub fn validity(&self) -> BindingValidity {
        BindingValidity {
            expires_at: self.binding.expires_at(),
            active: self.active.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct BindingValidity {
    expires_at: SystemTime,
    active: Arc<AtomicBool>,
}

impl BindingValidity {
    pub fn ensure_valid(&self) -> Result<(), BindingError> {
        self.ensure_valid_at(SystemTime::now())
    }

    fn ensure_valid_at(&self, now: SystemTime) -> Result<(), BindingError> {
        if !self.active.load(Ordering::Acquire) {
            return Err(BindingError::Revoked);
        }
        if self.expires_at <= now {
            return Err(BindingError::Expired);
        }
        Ok(())
    }

    pub fn is_valid(&self) -> bool {
        self.ensure_valid().is_ok()
    }

    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
}

struct RegistryEntry {
    lease: Arc<BindingLease>,
}

#[derive(Default)]
pub struct BindingRegistry {
    entries: RwLock<HashMap<String, RegistryEntry>>,
}

impl BindingRegistry {
    pub async fn replace(&self, bindings: Vec<EndpointBinding>) -> Result<usize, BindingError> {
        self.replace_at(bindings, SystemTime::now()).await
    }

    async fn replace_at(
        &self,
        bindings: Vec<EndpointBinding>,
        now: SystemTime,
    ) -> Result<usize, BindingError> {
        let current_snapshot: HashMap<String, Arc<BindingLease>> = self
            .entries
            .read()
            .await
            .iter()
            .map(|(id, entry)| (id.clone(), entry.lease.clone()))
            .collect();
        let mut next = HashMap::new();
        let mut replaced = Vec::new();
        for binding in bindings {
            binding.validate(now)?;
            let active = match current_snapshot.get(&binding.binding_id) {
                Some(lease) if lease.binding == binding => lease.active.clone(),
                Some(lease) => {
                    replaced.push(lease.active.clone());
                    Arc::new(AtomicBool::new(true))
                }
                None => Arc::new(AtomicBool::new(true)),
            };
            let binding_id = binding.binding_id.clone();
            let lease = Arc::new(BindingLease { binding, active });
            if next.insert(binding_id, RegistryEntry { lease }).is_some() {
                return Err(BindingError::Invalid("duplicate binding ID"));
            }
        }
        let mut current = self.entries.write().await;
        for active in replaced {
            active.store(false, Ordering::Release);
        }
        for (id, entry) in current.iter() {
            if !next.contains_key(id) {
                entry.lease.active.store(false, Ordering::Release);
            }
        }
        let count = next.len();
        *current = next;
        Ok(count)
    }

    pub async fn resolve(&self, handle: &str) -> Result<Arc<BindingLease>, BindingError> {
        self.resolve_at(handle, SystemTime::now()).await
    }

    async fn resolve_at(
        &self,
        handle: &str,
        now: SystemTime,
    ) -> Result<Arc<BindingLease>, BindingError> {
        let lease = self
            .entries
            .read()
            .await
            .get(handle)
            .map(|entry| entry.lease.clone())
            .ok_or(BindingError::Revoked)?;
        lease.binding.validate(now)?;
        lease.validity().ensure_valid_at(now)?;
        Ok(lease)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn binding(now_ms: u64) -> EndpointBinding {
        EndpointBinding {
            binding_id: "binding-1".to_string(),
            issuer: "harness".to_string(),
            audience: "shuttle".to_string(),
            logical_host: "machine".to_string(),
            address: "127.0.0.1".parse().unwrap(),
            port: 2222,
            host_key_pin: HostKeyPin {
                key_algorithm: "ssh-ed25519".to_string(),
                fingerprint_algorithm: "sha256".to_string(),
                digest_base64: base64::engine::general_purpose::STANDARD_NO_PAD.encode([7_u8; 32]),
            },
            issued_at_ms: now_ms,
            expires_at_ms: now_ms + 60_000,
            producer_tool: "test-provider".to_string(),
            provider_reference_hash: "redacted".to_string(),
        }
    }

    #[test]
    fn validates_canonical_pin_and_endpoint_policy() {
        let now_ms = 1_700_000_000_000;
        let now = UNIX_EPOCH + Duration::from_millis(now_ms);
        let valid = binding(now_ms);
        assert!(valid.validate(now).is_ok());
        assert!(valid
            .host_key_pin
            .canonical_fingerprint()
            .unwrap()
            .starts_with("SHA256:"));

        let mut denied = binding(now_ms);
        denied.address = "0.0.0.0".parse().unwrap();
        assert!(matches!(
            denied.validate(now),
            Err(BindingError::EndpointPolicyDenied)
        ));
    }

    #[test]
    fn rejects_wrong_audience_future_and_excessive_ttl() {
        let now_ms = 1_700_000_000_000;
        let now = UNIX_EPOCH + Duration::from_millis(now_ms);

        let mut wrong_audience = binding(now_ms);
        wrong_audience.audience = "other".to_string();
        assert!(matches!(
            wrong_audience.validate(now),
            Err(BindingError::AudienceMismatch)
        ));

        let mut future = binding(now_ms);
        future.issued_at_ms = now_ms + 31_000;
        future.expires_at_ms = future.issued_at_ms + 60_000;
        assert!(matches!(
            future.validate(now),
            Err(BindingError::Invalid(_))
        ));

        let mut excessive = binding(now_ms);
        excessive.expires_at_ms = now_ms + MAX_BINDING_TTL.as_millis() as u64 + 1;
        assert!(matches!(
            excessive.validate(now),
            Err(BindingError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn replacement_revokes_omitted_handles() {
        let now_ms = 1_700_000_000_000;
        let now = UNIX_EPOCH + Duration::from_millis(now_ms);
        let registry = BindingRegistry::default();
        registry
            .replace_at(vec![binding(now_ms)], now)
            .await
            .unwrap();
        let lease = registry.resolve_at("binding-1", now).await.unwrap();
        assert!(lease.validity().ensure_valid_at(now).is_ok());
        registry.replace_at(Vec::new(), now).await.unwrap();
        assert!(matches!(
            registry.resolve_at("binding-1", now).await,
            Err(BindingError::Revoked)
        ));
        assert!(matches!(
            lease.validity().ensure_valid_at(now),
            Err(BindingError::Revoked)
        ));
    }

    #[tokio::test]
    async fn invalid_replacement_is_atomic() {
        let now_ms = 1_700_000_000_000;
        let now = UNIX_EPOCH + Duration::from_millis(now_ms);
        let registry = BindingRegistry::default();
        registry
            .replace_at(vec![binding(now_ms)], now)
            .await
            .unwrap();
        let live = registry.resolve_at("binding-1", now).await.unwrap();
        let mut changed = binding(now_ms);
        changed.port = 2200;
        let mut invalid = binding(now_ms);
        invalid.binding_id = "binding-2".to_string();
        invalid.audience = "wrong".to_string();
        assert!(registry
            .replace_at(vec![changed, invalid], now)
            .await
            .is_err());
        assert!(live.validity().ensure_valid_at(now).is_ok());
        assert_eq!(
            registry
                .resolve_at("binding-1", now)
                .await
                .unwrap()
                .binding()
                .port,
            2222
        );
    }

    #[tokio::test]
    async fn changed_binding_id_payload_revokes_existing_lease() {
        let now_ms = 1_700_000_000_000;
        let now = UNIX_EPOCH + Duration::from_millis(now_ms);
        let registry = BindingRegistry::default();
        registry
            .replace_at(vec![binding(now_ms)], now)
            .await
            .unwrap();
        let old = registry.resolve_at("binding-1", now).await.unwrap();
        let mut changed = binding(now_ms);
        changed.port = 2200;
        registry.replace_at(vec![changed], now).await.unwrap();
        assert!(matches!(
            old.validity().ensure_valid_at(now),
            Err(BindingError::Revoked)
        ));
        assert!(registry
            .resolve_at("binding-1", now)
            .await
            .unwrap()
            .validity()
            .ensure_valid_at(now)
            .is_ok());
    }
}
