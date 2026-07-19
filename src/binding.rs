use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

const MAX_BINDING_TTL: Duration = Duration::from_secs(15 * 60);
const CLOCK_SKEW: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Deserialize)]
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

#[derive(Default)]
pub struct BindingRegistry {
    entries: RwLock<HashMap<String, Arc<EndpointBinding>>>,
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
        let mut next = HashMap::new();
        for binding in bindings {
            binding.validate(now)?;
            if next
                .insert(binding.binding_id.clone(), Arc::new(binding))
                .is_some()
            {
                return Err(BindingError::Invalid("duplicate binding ID"));
            }
        }
        let count = next.len();
        *self.entries.write().await = next;
        Ok(count)
    }

    pub async fn resolve(&self, handle: &str) -> Result<Arc<EndpointBinding>, BindingError> {
        self.resolve_at(handle, SystemTime::now()).await
    }

    async fn resolve_at(
        &self,
        handle: &str,
        now: SystemTime,
    ) -> Result<Arc<EndpointBinding>, BindingError> {
        let binding = self
            .entries
            .read()
            .await
            .get(handle)
            .cloned()
            .ok_or(BindingError::Revoked)?;
        binding.validate(now)?;
        Ok(binding)
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
        assert!(registry.resolve_at("binding-1", now).await.is_ok());
        registry.replace_at(Vec::new(), now).await.unwrap();
        assert!(matches!(
            registry.resolve_at("binding-1", now).await,
            Err(BindingError::Revoked)
        ));
    }
}
