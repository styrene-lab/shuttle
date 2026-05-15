# Changelog

## [Unreleased]

## [0.1.1](https://github.com/styrene-lab/shuttle/compare/v0.1.0...v0.1.1) - 2026-05-15

### Other

- add changelog for v0.1.0 release
- *(release)* re-add aarch64-unknown-linux-gnu — all openssl-free now
- *(release)* drop aarch64-unknown-linux-gnu from default matrix

## [0.1.0] - 2026-05-15

### Added

- Pure-Rust SSH remote execution extension for Omegon.
- HKDF-SHA256 key derivation from a Styrene root identity — no SSH key files on disk.
- Ed25519 SSH authentication via per-host identity labels.
- Host configuration through `~/.omegon/shuttle/hosts.toml`.
- SSH command execution, script execution, SFTP transfer/list/read operations, and local-to-remote SSH tunnels.
- Trust-on-first-use host key recording with a Shuttle-managed known_hosts file.
- Migration guidance and analysis tooling for moving from traditional `~/.ssh/config` and key files.
