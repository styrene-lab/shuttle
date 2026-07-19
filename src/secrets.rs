use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use tokio::sync::RwLock;

/// Secrets delivered by Omegon's bootstrap protocol. Values remain in memory,
/// are redacted under Debug, and are zeroized when replaced or dropped.
pub struct SecretStore {
    values: RwLock<HashMap<String, SecretString>>,
}

impl SecretStore {
    pub fn new() -> Self {
        Self {
            values: RwLock::new(HashMap::new()),
        }
    }

    pub async fn bootstrap(&self, values: HashMap<String, String>) {
        let mut store = self.values.write().await;
        store.clear();
        store.extend(
            values
                .into_iter()
                .map(|(name, value)| (name, SecretString::from(value))),
        );
    }

    pub async fn expose(&self, name: &str) -> Option<String> {
        self.values
            .read()
            .await
            .get(name)
            .map(|value| value.expose_secret().to_owned())
    }
}

impl Default for SecretStore {
    fn default() -> Self {
        Self::new()
    }
}
