# Changelog

## [Unreleased]

### Release maturity

- Shuttle is currently a **Security-Hardened Controlled Preview** distributed through **Armory**.
- The `0.x` line develops in the **Live Preview** channel.
- `1.0.0` is reserved for **General Availability** after the exit criteria in `ROADMAP.md` are satisfied.

### Added

- Operator-facing `README.md` covering preview status, security boundaries, configuration, and stability expectations.
- `ROADMAP.md` defining staged milestones from Controlled Preview through `1.0.0-rc.N` and GA.
- Manifest release metadata for Armory maturity, channel, distribution, and GA target.
- Ephemeral endpoint bindings with strict host-key pins, bounded lifetime, pool isolation, and revocation propagation through SSH channels, tunnels, and SFTP operations.

### Changed

- Removed deployment-specific `truenas` and `VANDERLYN_TRUENAS_SHUTTLE_PASSWORD` defaults from the generic extension manifest.
- Password secrets are now entirely named by configured authentication profiles.
- Empty host policy fails closed unless `allow_all_hosts` is explicitly enabled.

### Security

- Added bounded connection pooling, transfer limits, exact tunnel destination authorization, remote-path validation, and structured tool tracing.
- Added transactional endpoint-binding registry replacement so rejected refreshes cannot partially revoke active leases.

## [0.1.0] - 2026-05-15

### Added

- Pure-Rust SSH remote execution extension for Omegon.
- HKDF-SHA256 key derivation from a Styrene root identity — no SSH key files on disk.
- Ed25519 SSH authentication via per-host identity labels.
- Host configuration through `~/.omegon/shuttle/hosts.toml`.
- SSH command execution, script execution, SFTP transfer/list/read operations, and local-to-remote SSH tunnels.
- Trust-on-first-use host key recording with a Shuttle-managed known_hosts file.
- Migration guidance and analysis tooling for moving from traditional `~/.ssh/config` and key files.
