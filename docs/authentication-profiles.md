# Authentication Profiles

## Decision

Shuttle owns SSH authentication and transport primitives. It does not own remote user provisioning, account migration, `authorized_keys` policy, sudo policy, password rotation, shell selection, or SSH daemon configuration.

A host may expose multiple named authentication profiles. Every connection-using tool may select one profile explicitly; when omitted, the host's configured default is used. Shuttle never falls back from one profile to another after authentication failure.

This separation lets an operator or agent use generic SSH operations to inspect and, when authorized, improve a remote machine without embedding a deterministic account-management workflow in Shuttle.

## Configuration contract

```toml
[truenas]
address = "192.168.0.10"
user = "omegon"
default_auth = "derived-key"
trust_on_first_use = false

[truenas.auth.derived-key]
method = "public_key"
identity_label = "vanderlyn-ops"

[truenas.auth.bootstrap]
method = "password"
secret = "VANDERLYN_TRUENAS_SHUTTLE_PASSWORD"
```

Legacy entries containing a top-level `identity_label` remain equivalent to a single public-key profile named `default`.

Password values never appear in `hosts.toml` or tool arguments. The profile stores only the harness secret name. The corresponding value must be delivered through the extension's `bootstrap_secrets` RPC and is retained only in process memory as a secret value.

## Tool contract

Connection-using tools accept an optional `auth` field naming a configured profile:

```json
{
  "host": "truenas",
  "auth": "bootstrap",
  "command": "id"
}
```

Omitting `auth` selects `default_auth`. Selection is exact: rejection of `bootstrap` or `derived-key` is returned as a failure and never triggers another profile.

`ssh_public_key` returns the non-secret OpenSSH public key for a configured public-key profile. It is host-bound and allowlist-bound; callers cannot enumerate arbitrary identity labels.

## Security boundaries

Shuttle enforces:

- host allowlisting;
- exact authentication-profile selection;
- host-key verification before credentials are submitted;
- in-memory secret isolation;
- no secret material in logs, errors, or tool results;
- path, tunnel, timeout, and output restrictions already owned by Shuttle.

Shuttle does not decide:

- whether a remote account should exist;
- whether or how a public key should be installed;
- whether passwords should be rotated or disabled;
- whether remote SSH policy should change;
- whether a machine has been "upgraded".

Those are operator/workflow decisions implemented with generic SSH and platform-specific interfaces.

## Host-key posture

Password profiles use the same host-key verification path as public-key profiles. Unknown keys are rejected unless the host explicitly enables trust-on-first-use. For sensitive bootstrap credentials, pre-pinning the host key is preferred. A mismatch always fails before authentication and is never bypassed.

## Runtime and deployment modes

The design must work without the local OpenSSH client, `ssh-agent`, or `~/.ssh/config`. Interactive Omegon, deployed daemon Omegon, and one-shot jobs all receive credentials through the same harness bootstrap protocol and use the same pure-Rust SSH path.

## Validation matrix

Validated against TrueNAS 24.10.2.4 using a named `password` profile and the
Omegon 0.25 extension contract:

| Capability | Result |
| --- | --- |
| Extension startup and secret bootstrap | Pass |
| `args` and `arguments` RPC envelopes | Pass; covered by regression tests |
| Host allowlist and pinned host-key verification | Pass |
| `ssh_hosts` / `ssh_ping` | Pass |
| `ssh_exec` / `ssh_script` | Pass |
| `sftp_ls` / `sftp_read` | Pass |
| `scp_push` / `scp_pull` | Pass; byte-for-byte round trip verified |
| Tunnel open / list / close | Pass on an allowed loopback destination |
| Local path policy | Pass; `/tmp` was rejected when outside `allowed_local_roots` |
| Tunnel port policy | Pass; ephemeral port `0` was rejected because local ports must be at least 1024 |

The live tests used temporary probe files only and removed the remote probe.
They did not alter persistent remote configuration.

## Operational notes

- The native extension launcher expects the manifest binary (`shuttle`) to
  resolve to the current release build. Development installs may use a symlink
  to `target/release/shuttle`; packaged installs should ship the binary itself.
- Shuttle's compact fingerprint file format is `<host-alias> <base64-digest>`.
  It intentionally does not use OpenSSH's `known_hosts` line format.
- Transfer paths and tunnel destinations are policy-controlled independently
  from the remote account's privileges. An administrative remote account does
  not bypass Shuttle's local transport restrictions.
- `ssh_ping` opens and authenticates a fresh connection; the current pool does
  not reuse sessions. This is correct but means observed latency includes the
  SSH handshake and authentication.

## Compatibility and evolution

The first implementation supports `public_key` and `password`. The profile model can later add keyboard-interactive, SSH certificates, hardware signers, or imported OpenSSH identities without changing tool schemas or introducing implicit fallback.
