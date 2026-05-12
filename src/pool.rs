use crate::client::{ClientError, SshClient};
use crate::config::ShuttleConfig;
use std::sync::Arc;
use styrene_identity::signer::RootSecret;
use tokio::sync::Mutex;

pub struct ConnectionPool;

impl ConnectionPool {
    pub fn new() -> Self {
        Self
    }

    /// Create a fresh SSH connection to a host.
    ///
    /// Each call opens a new connection and authenticates. This is
    /// intentional for v1 — connection reuse requires liveness probes
    /// and careful session lifecycle management that will come later.
    pub async fn acquire(
        &self,
        host_name: &str,
        config: &ShuttleConfig,
        root: &RootSecret,
    ) -> Result<Arc<Mutex<SshClient>>, ClientError> {
        let entry = config
            .resolve_host(host_name)
            .map_err(|e| ClientError::Auth(e.to_string()))?;

        let client =
            SshClient::connect(host_name, entry, root, &config.known_hosts_file).await?;

        Ok(Arc::new(Mutex::new(client)))
    }
}
