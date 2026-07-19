use crate::auth;
use crate::binding::HostKeyPin;
use crate::config::{AuthProfile, HostEntry};
use russh::client;
use russh_keys::key::PublicKey;
use std::net::ToSocketAddrs;
use std::path::Path;
use std::sync::Arc;
use styrene_identity::signer::RootSecret;

pub enum HostVerifier {
    ConfiguredKnownHost {
        logical_host: String,
        known_hosts_path: std::path::PathBuf,
        tofu: bool,
    },
    EphemeralPinnedKey {
        logical_host: String,
        pin: HostKeyPin,
    },
}

pub struct ConnectionTarget {
    pub address: String,
    pub port: u16,
    pub verifier: HostVerifier,
    pub valid_until: Option<std::time::SystemTime>,
}

pub struct SshClient {
    handle: client::Handle<ShuttleHandler>,
    host_name: String,
    valid_until: Option<std::time::SystemTime>,
}

impl SshClient {
    pub async fn connect(
        host_name: &str,
        entry: &HostEntry,
        profile: &AuthProfile,
        root: Option<&RootSecret>,
        password: Option<String>,
        known_hosts_path: &Path,
    ) -> Result<Self, ClientError> {
        let target = ConnectionTarget {
            address: entry.address.clone(),
            port: entry.port,
            verifier: HostVerifier::ConfiguredKnownHost {
                logical_host: host_name.to_string(),
                known_hosts_path: known_hosts_path.to_path_buf(),
                tofu: entry.trust_on_first_use,
            },
            valid_until: None,
        };
        Self::connect_target(host_name, entry, profile, root, password, target).await
    }

    pub async fn connect_target(
        host_name: &str,
        entry: &HostEntry,
        profile: &AuthProfile,
        root: Option<&RootSecret>,
        password: Option<String>,
        target: ConnectionTarget,
    ) -> Result<Self, ClientError> {
        let addr = format!("{}:{}", target.address, target.port);
        Self::ensure_valid_until(target.valid_until)?;
        let socket_addr = addr
            .to_socket_addrs()
            .map_err(|e| ClientError::Resolve(addr.clone(), e))?
            .next()
            .ok_or_else(|| {
                ClientError::Resolve(addr.clone(), std::io::Error::other("no addresses resolved"))
            })?;

        let config = Arc::new(client::Config {
            ..Default::default()
        });

        let handler = ShuttleHandler {
            verifier: target.verifier,
        };

        let mut handle = client::connect(config, socket_addr, handler)
            .await
            .map_err(ClientError::Connection)?;

        let authenticated = match profile {
            AuthProfile::PublicKey { identity_label } => {
                let root = root.ok_or_else(|| {
                    ClientError::Auth("public-key identity is unavailable".to_string())
                })?;
                let key_pair = auth::derive_key_pair(root, identity_label)
                    .map_err(|error| ClientError::Auth(error.to_string()))?;
                handle
                    .authenticate_publickey(&entry.user, key_pair)
                    .await
                    .map_err(ClientError::Connection)?
            }
            AuthProfile::Password { .. } => {
                let password = password.ok_or_else(|| {
                    ClientError::Auth("configured password secret is unavailable".to_string())
                })?;
                handle
                    .authenticate_password(&entry.user, password)
                    .await
                    .map_err(ClientError::Connection)?
            }
        };

        if !authenticated {
            return Err(ClientError::Auth(
                "server rejected selected authentication profile".to_string(),
            ));
        }
        Self::ensure_valid_until(target.valid_until)?;

        tracing::info!(host = host_name, user = %entry.user, "authenticated");

        Ok(Self {
            handle,
            host_name: host_name.to_string(),
            valid_until: target.valid_until,
        })
    }

    fn ensure_valid_until(valid_until: Option<std::time::SystemTime>) -> Result<(), ClientError> {
        if valid_until.is_some_and(|expiry| expiry <= std::time::SystemTime::now()) {
            return Err(ClientError::Binding("endpoint binding expired".to_string()));
        }
        Ok(())
    }

    fn ensure_valid(&self) -> Result<(), ClientError> {
        Self::ensure_valid_until(self.valid_until)
    }

    pub async fn exec(
        &self,
        command: &str,
        timeout: std::time::Duration,
        max_output: usize,
    ) -> Result<ExecResult, ClientError> {
        self.ensure_valid()?;
        let mut channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(ClientError::Connection)?;

        channel
            .exec(true, command)
            .await
            .map_err(ClientError::Connection)?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_code: Option<u32> = None;
        let mut stdout_truncated = false;
        let mut stderr_truncated = false;

        // Collect stdout/stderr until both Eof and ExitStatus are received,
        // or the channel closes (None). Some servers send ExitStatus before
        // Eof, others after. If a server sends only one, the outer timeout
        // on line 134 is the safety net — worst case latency equals the
        // configured timeout, not a hang.
        let collect = async {
            let mut eof_seen = false;
            loop {
                match channel.wait().await {
                    Some(russh::ChannelMsg::Data { ref data }) => {
                        if stdout.len() < max_output {
                            let remaining = max_output - stdout.len();
                            if data.len() <= remaining {
                                stdout.extend_from_slice(data);
                            } else {
                                stdout.extend_from_slice(&data[..remaining]);
                                stdout_truncated = true;
                            }
                        }
                    }
                    Some(russh::ChannelMsg::ExtendedData { ref data, ext }) => {
                        if ext == 1 && stderr.len() < max_output {
                            let remaining = max_output - stderr.len();
                            if data.len() <= remaining {
                                stderr.extend_from_slice(data);
                            } else {
                                stderr.extend_from_slice(&data[..remaining]);
                                stderr_truncated = true;
                            }
                        }
                    }
                    Some(russh::ChannelMsg::ExitStatus { exit_status }) => {
                        exit_code = Some(exit_status);
                        if eof_seen {
                            break;
                        }
                    }
                    Some(russh::ChannelMsg::Eof) => {
                        eof_seen = true;
                        if exit_code.is_some() {
                            break;
                        }
                    }
                    None => break,
                    _ => {}
                }
            }
        };

        tokio::time::timeout(timeout, collect)
            .await
            .map_err(|_| ClientError::Timeout(self.host_name.clone(), timeout))?;

        Ok(ExecResult {
            stdout,
            stderr,
            exit_code: exit_code.unwrap_or(255),
            truncated: stdout_truncated || stderr_truncated,
        })
    }

    pub async fn sftp(&self) -> Result<russh_sftp::client::SftpSession, ClientError> {
        self.ensure_valid()?;
        let channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(ClientError::Connection)?;

        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(ClientError::Connection)?;

        let sftp = russh_sftp::client::SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| ClientError::Sftp(e.to_string()))?;

        Ok(sftp)
    }

    pub async fn direct_tcpip(
        &self,
        remote_host: &str,
        remote_port: u32,
        local_host: &str,
        local_port: u32,
    ) -> Result<russh::Channel<client::Msg>, ClientError> {
        self.ensure_valid()?;
        self.handle
            .channel_open_direct_tcpip(remote_host, remote_port, local_host, local_port)
            .await
            .map_err(ClientError::Connection)
    }

    pub fn host_name(&self) -> &str {
        &self.host_name
    }

    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }
}

#[derive(Debug)]
pub struct ExecResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: u32,
    pub truncated: bool,
}

struct ShuttleHandler {
    verifier: HostVerifier,
}

#[async_trait::async_trait]
impl client::Handler for ShuttleHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let fp_str = server_public_key.fingerprint().to_string();
        match &self.verifier {
            HostVerifier::EphemeralPinnedKey { logical_host, pin } => {
                let expected = pin
                    .canonical_fingerprint()
                    .map_err(|_| russh::Error::UnknownKey)?;
                let key_algorithm = server_public_key.name();
                let matched = key_algorithm == pin.key_algorithm && fp_str == expected;
                if !matched {
                    tracing::error!(host = %logical_host, "ephemeral host-key pin mismatch");
                }
                Ok(matched)
            }
            HostVerifier::ConfiguredKnownHost {
                logical_host,
                known_hosts_path,
                tofu,
            } => {
                tracing::debug!(host = %logical_host, fingerprint = %fp_str, "checking server key");
                match check_known_host(known_hosts_path, logical_host, &fp_str) {
                    KnownHostResult::Match => Ok(true),
                    KnownHostResult::Mismatch => {
                        tracing::error!(host = %logical_host, "HOST KEY MISMATCH — possible MITM attack");
                        Ok(false)
                    }
                    KnownHostResult::Unknown if *tofu => {
                        tracing::warn!(host = %logical_host, fingerprint = %fp_str, "trust-on-first-use: recording new host key");
                        if record_host_key(known_hosts_path, logical_host, &fp_str).is_err() {
                            return Ok(false);
                        }
                        Ok(true)
                    }
                    KnownHostResult::Unknown => {
                        tracing::error!(host = %logical_host, "unknown host key and TOFU disabled — rejecting");
                        Ok(false)
                    }
                }
            }
        }
    }
}

enum KnownHostResult {
    Match,
    Mismatch,
    Unknown,
}

fn check_known_host(path: &Path, host_name: &str, server_fingerprint: &str) -> KnownHostResult {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return KnownHostResult::Unknown,
    };

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, ' ');
        let Some(name) = parts.next() else {
            continue;
        };
        let Some(fp) = parts.next() else { continue };
        if name == host_name {
            if fp.trim() == server_fingerprint {
                return KnownHostResult::Match;
            } else {
                return KnownHostResult::Mismatch;
            }
        }
    }

    KnownHostResult::Unknown
}

fn record_host_key(path: &Path, host_name: &str, fingerprint: &str) -> std::io::Result<()> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let mut file = opts.open(path)?;
    writeln!(file, "{host_name} {fingerprint}")?;
    file.sync_all()?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("failed to resolve {0}: {1}")]
    Resolve(String, std::io::Error),
    #[error("connection error: {0}")]
    Connection(russh::Error),
    #[error("endpoint binding rejected: {0}")]
    Binding(String),

    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("command timed out on {0} after {1:?}")]
    Timeout(String, std::time::Duration),
    #[error("SFTP error: {0}")]
    Sftp(String),
}
