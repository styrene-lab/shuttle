# Changelog

## [Unreleased]

## [0.1.0] - 2026-05-15

### Added

- Pure-Rust SSH remote execution extension for Omegon.
- HKDF-SHA256 key derivation from a Styrene root identity — no SSH key files on disk.
- Ed25519 SSH authentication via per-host identity labels.
- Host configuration through `~/.omegon/shuttle/hosts.toml`.
- SSH command execution, script execution, SFTP transfer/list/read operations, and local-to-remote SSH tunnels.
- Trust-on-first-use host key recording with a Shuttle-managed known_hosts file.
- Migration guidance and analysis tooling for moving from traditional `~/.ssh/config` and key files.
