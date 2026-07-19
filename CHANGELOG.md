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

## [0.2.0] - 2026-07-19

### Release maturity

- Published as a **Security-Hardened Controlled Preview** through Armory.
- This release is suitable for operator-approved remote-machine workflows while the endpoint-binding and stable error-contract GA gates remain open.

### Added

- Explicit authentication profiles with exact selection and no credential fallback.
- Bounded SSH connection pooling isolated by endpoint, user, authentication profile, and ephemeral binding context.
- Ephemeral endpoint bindings with strict host-key pins, bounded lifetime, atomic replacement, and revocation propagation through pooled sessions, SSH channels, active tunnels, and SFTP operations.
- Dedicated connection and transfer limits, structured tracing, remote path validation, exact tunnel destination authorization, and migration analysis hardening.
- Mandatory disposable-sshd integration gates for CI and release workflows.
- Operator-facing `README.md`, GA roadmap, authentication documentation, and transport/identity architecture guidance.

### Changed

- Removed deployment-specific host and password defaults from the generic extension manifest.
- Empty host policy now fails closed unless `allow_all_hosts` is explicitly enabled.
- OpenSSH wildcard, negated, and multi-alias host patterns are reported but excluded from generated Shuttle migration records.

### Security

- Ephemeral endpoints never consult or mutate permanent known-host state and cannot use TOFU.
- Failed endpoint-binding registry refreshes are transactional and cannot partially revoke active leases.
- Bound tunnel forwarding and chunked SFTP operations observe binding expiry and revocation during operation.
- Local uploads are restricted to configured roots and all transfer sizes are bounded.

## [0.1.0] - 2026-05-15

### Added

- Pure-Rust SSH remote execution extension for Omegon.
- HKDF-SHA256 key derivation from a Styrene root identity — no SSH key files on disk.
- Ed25519 SSH authentication via per-host identity labels.
- Host configuration through `~/.omegon/shuttle/hosts.toml`.
- SSH command execution, script execution, SFTP transfer/list/read operations, and local-to-remote SSH tunnels.
- Trust-on-first-use host key recording with a Shuttle-managed known_hosts file.
- Migration guidance and analysis tooling for moving from traditional `~/.ssh/config` and key files.
