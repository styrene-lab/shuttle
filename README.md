# Shuttle

Shuttle is Omegon's point-to-point remote-machine operations extension. It gives an agent explicit, bounded affordances for discovering configured machines, probing authenticated reachability, executing commands and scripts, transferring files, and opening SSH tunnels on the operator's behalf.

Shuttle is an execution substrate, not a fleet manager. The operator supplies intent, the agent plans and invokes operations, and Shuttle enforces configured host, identity, host-key, path, destination, timeout, output, and transfer boundaries.

## Release status

> **Current channel: Security-Hardened Controlled Preview**  
> **Distribution: Armory**  
> **Development track: Live Preview**  
> **GA target: 1.0.0**

The current `0.1.x` line is suitable for controlled use and operational evaluation through Armory. It is not yet covered by the compatibility and support guarantees that will begin with `1.0.0`.

While Shuttle is in Live Preview:

- releases may add or refine tool result and error fields;
- endpoint-binding integration remains preview functionality;
- operators should test against non-critical or explicitly approved machines first;
- security defects receive priority treatment;
- feedback from real remote-machine workflows drives the path to GA.

See [ROADMAP.md](ROADMAP.md) for milestones and the exact GA exit criteria.

## Capabilities

Shuttle currently exposes:

- `ssh_hosts` — list configured and allowed machines;
- `ssh_ping` — test authenticated reachability;
- `ssh_exec` — run a bounded command;
- `ssh_script` — execute a bounded script through stdin;
- `sftp_ls` and `sftp_read` — inspect remote files;
- `scp_push` and `scp_pull` — transfer bounded files;
- `ssh_tunnel_open`, `ssh_tunnel_list`, and `ssh_tunnel_close` — manage local-to-remote forwarding;
- `ssh_public_key` — retrieve a configured derived public key;
- `ssh_migrate_analyze` — inspect an existing OpenSSH setup and draft migration guidance.

The current production transport is SSH. Styrene Mesh remains a post-GA-compatible evolution path, not a requirement for Shuttle 1.0.

## Security model

Shuttle fails closed around configured policy:

- hosts require an allowlist unless `allow_all_hosts` is explicitly enabled;
- authentication profiles are selected exactly, without credential fallback;
- static SSH endpoints use host-key verification and optional explicit TOFU;
- ephemeral endpoints use harness-issued bindings and strict pinned-key verification, never permanent TOFU state;
- connection, command, output, and transfer sizes are bounded;
- local paths, remote lexical roots, and tunnel destinations can be restricted;
- pooled sessions are isolated by endpoint and identity context;
- expired or revoked endpoint bindings cannot authorize new channels;
- bound tunnels and chunked SFTP reads observe revocation during operation.

Remote path restrictions are lexical policy boundaries, not a remote filesystem sandbox. A remote symlink may resolve outside a permitted prefix. Configure remote accounts and filesystem permissions accordingly.

The endpoint-binding control plane relies on Omegon treating `bootstrap_endpoint_bindings` as privileged extension bootstrap traffic. Ordinary tool arguments carry only an opaque binding handle, never endpoint trust material.

## Installation

During Controlled Preview, install Shuttle from its Armory listing. Armory is the supported distribution channel for preview builds and release metadata.

After installation, configure at least:

1. a `hosts.toml` file;
2. `allowed_hosts`, or the explicit `allow_all_hosts` escape hatch;
3. an authentication profile and corresponding secret or Styrene identity;
4. host-key trust for each static endpoint;
5. optional local, remote, and tunnel policy boundaries.

## Host configuration

Default path:

```text
~/.omegon/shuttle/hosts.toml
```

Public-key profile example:

```toml
[prod-web]
address = "10.0.1.50"
user = "deploy"
port = 22
default_auth = "operator"
trust_on_first_use = false

[prod-web.auth.operator]
type = "public_key"
identity_label = "prod"
```

Password profile example:

```toml
[legacy-host]
address = "192.0.2.40"
user = "operator"
default_auth = "password"
trust_on_first_use = false

[legacy-host.auth.password]
type = "password"
secret = "LEGACY_HOST_PASSWORD"
```

Secrets named by password profiles must be supplied through Omegon's extension secret bootstrap. Shuttle does not require any deployment-specific password globally.

## Host-key enrollment

Static hosts default to rejecting unknown host keys. Operators can either:

- provision the expected fingerprint in Shuttle's known-hosts file; or
- temporarily enable `trust_on_first_use = true`, establish the first verified connection, and disable TOFU afterward.

A host-key mismatch is a security event. Confirm an intentional server-key rotation before changing the stored fingerprint.

Ephemeral endpoint bindings are separate: they use only the short-lived pinned key supplied by the privileged harness binding registry and never read or write permanent known-host state.

## Operational limits

Important manifest settings include:

- `default_timeout_secs`;
- `connect_timeout_secs`;
- `max_output_bytes`;
- `max_transfer_bytes`;
- `connection_pool_size`;
- `allowed_local_roots`;
- `allowed_remote_read_roots`;
- `allowed_remote_write_roots`;
- `allowed_tunnel_destinations`.

Prefer narrow policy values. Empty remote-root lists preserve unrestricted legacy remote paths and should be avoided for higher-risk hosts.

## Development verification

```bash
cargo fmt --check
cargo test --lib --bins --test unit -- --test-threads=1
cargo test --doc
cargo clippy --all-targets -- -D warnings
./test-infra/run.sh
```

Live SSH tests use the infrastructure under `test-infra/`. Mandatory live integration CI is a 1.0 GA exit criterion; see [ROADMAP.md](ROADMAP.md).

## Documentation

- [ROADMAP.md](ROADMAP.md) — Live Preview milestones and 1.0 GA gate
- [SKILL.md](SKILL.md) — migration and agent guidance
- [Authentication profiles](docs/authentication-profiles.md)
- [Transport and identity architecture](docs/transport-identity-architecture.md)
- [CHANGELOG.md](CHANGELOG.md)

## Stability promise

Before `1.0.0`, Shuttle follows semantic versioning but reserves the right to make preview-breaking changes when needed for security or a stable agent contract. Such changes must be documented in the changelog and Armory release notes.

At `1.0.0`, Shuttle will declare its documented tool inputs, operation results, machine-readable error taxonomy, configuration schema, and supported upgrade path GA-stable.
