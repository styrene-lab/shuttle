use crate::client::{ClientError, SshClient};
use crate::config::{AuthProfile, ShuttleConfig};
use std::sync::Arc;
use styrene_identity::signer::RootSecret;
use tokio::sync::Mutex;

pub struct ConnectionPool;

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self
    }

    /// Create a fresh SSH connection using exactly one selected profile.
    /// There is deliberately no authentication fallback.
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
        let (_, profile) = entry
            .resolve_auth(auth_name)
            .map_err(|error| ClientError::Auth(error.to_string()))?;

        if matches!(profile, AuthProfile::PublicKey { .. }) && root.is_none() {
            return Err(ClientError::Auth(
                "public-key identity is unavailable".to_string(),
            ));
        }

        let client = SshClient::connect(
            host_name,
            entry,
            &profile,
            root,
            password,
            &config.known_hosts_file,
        )
        .await?;

        Ok(Arc::new(Mutex::new(client)))
    }
}
