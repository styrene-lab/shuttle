use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct HostEntry {
    pub address: String,
    pub user: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub identity_label: String,
    #[serde(default)]
    pub trust_on_first_use: bool,
}

fn default_port() -> u16 {
    22
}

const MAX_TIMEOUT_SECS: u64 = 3600;
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

#[derive(Debug, Clone)]
pub struct ShuttleConfig {
    pub hosts_file: PathBuf,
    pub known_hosts_file: PathBuf,
    pub default_timeout_secs: u64,
    pub max_output_bytes: usize,
    pub allowed_hosts: Option<Vec<String>>,
    pub allowed_tunnel_destinations: Option<Vec<String>>,
    pub connection_pool_size: usize,
    hosts: HashMap<String, HostEntry>,
    /// Once true, hosts_file and known_hosts_file cannot be changed via RPC.
    paths_locked: bool,
}

impl Default for ShuttleConfig {
    fn default() -> Self {
        let base = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join(".omegon")
            .join("shuttle");
        Self {
            hosts_file: base.join("hosts.toml"),
            known_hosts_file: base.join("known_hosts"),
            default_timeout_secs: 30,
            max_output_bytes: 1_048_576,
            allowed_hosts: None,
            allowed_tunnel_destinations: None,
            connection_pool_size: 4,
            hosts: HashMap::new(),
            paths_locked: false,
        }
    }
}

impl ShuttleConfig {
    pub fn load_hosts(&mut self) -> Result<(), ConfigError> {
        if !self.hosts_file.exists() {
            return Err(ConfigError::HostsFileNotFound(
                self.hosts_file.display().to_string(),
            ));
        }
        let content = std::fs::read_to_string(&self.hosts_file)
            .map_err(|e| ConfigError::Io(self.hosts_file.display().to_string(), e))?;
        self.hosts = toml::from_str(&content)
            .map_err(|e| ConfigError::Parse(self.hosts_file.display().to_string(), e))?;
        // Lock file paths after first successful load — prevents RPC config
        // from redirecting to attacker-controlled files.
        self.paths_locked = true;
        Ok(())
    }

    pub fn resolve_host(&self, name: &str) -> Result<&HostEntry, ConfigError> {
        if let Some(ref allowed) = self.allowed_hosts {
            if !allowed.iter().any(|a| a == name) {
                return Err(ConfigError::HostNotAllowed(name.to_string()));
            }
        }
        self.hosts
            .get(name)
            .ok_or_else(|| ConfigError::HostNotFound(name.to_string()))
    }

    pub fn host_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.hosts.keys().map(|s| s.as_str()).collect();
        names.sort();
        names
    }

    pub fn apply_rpc_config(&mut self, config: &HashMap<String, serde_json::Value>) {
        // File paths can only be set before first load (paths_locked = false).
        if !self.paths_locked {
            if let Some(v) = config.get("hosts_file").and_then(|v| v.as_str()) {
                self.hosts_file = expand_tilde(v);
            }
            if let Some(v) = config.get("known_hosts_file").and_then(|v| v.as_str()) {
                self.known_hosts_file = expand_tilde(v);
            }
        }

        if let Some(v) = config.get("default_timeout_secs").and_then(|v| v.as_u64()) {
            self.default_timeout_secs = v.clamp(1, MAX_TIMEOUT_SECS);
        }
        if let Some(v) = config.get("max_output_bytes").and_then(|v| v.as_u64()) {
            self.max_output_bytes = (v as usize).clamp(1024, MAX_OUTPUT_BYTES);
        }
        if let Some(v) = config.get("connection_pool_size").and_then(|v| v.as_u64()) {
            self.connection_pool_size = (v as usize).clamp(1, 32);
        }
        if let Some(v) = config.get("allowed_hosts").and_then(|v| v.as_str()) {
            let new_hosts: Vec<String> = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !new_hosts.is_empty() {
                // Can only tighten — if already set, intersect with new list.
                // Prevents RPC config from widening access after initial load.
                // An empty intersection means ZERO hosts are accessible — that's
                // correct behavior, not a fallback case.
                self.allowed_hosts = match self.allowed_hosts.take() {
                    Some(existing) => {
                        let intersection: Vec<String> = existing
                            .into_iter()
                            .filter(|h| new_hosts.contains(h))
                            .collect();
                        if intersection.is_empty() {
                            tracing::warn!(
                                "allowed_hosts intersection is empty — no hosts accessible"
                            );
                        }
                        Some(intersection)
                    }
                    None => Some(new_hosts),
                };
            }
        }
        if let Some(v) = config
            .get("allowed_tunnel_destinations")
            .and_then(|v| v.as_str())
        {
            let new_dests: Vec<String> = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !new_dests.is_empty() {
                // Same intersection-tightening as allowed_hosts — can only
                // narrow the set, never widen it after initial configuration.
                self.allowed_tunnel_destinations =
                    match self.allowed_tunnel_destinations.take() {
                        Some(existing) => {
                            let intersection: Vec<String> = existing
                                .into_iter()
                                .filter(|d| new_dests.contains(d))
                                .collect();
                            if intersection.is_empty() {
                                tracing::warn!(
                                    "allowed_tunnel_destinations intersection is empty"
                                );
                            }
                            Some(intersection)
                        }
                        None => Some(new_dests),
                    };
            }
        }
    }
}

fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("hosts file not found: {0}")]
    HostsFileNotFound(String),
    #[error("host not found: {0}")]
    HostNotFound(String),
    #[error("host not in allowlist: {0}")]
    HostNotAllowed(String),
    #[error("failed to read {0}: {1}")]
    Io(String, std::io::Error),
    #[error("failed to parse {0}: {1}")]
    Parse(String, toml::de::Error),
}
