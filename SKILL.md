# SSH Migration Skill — Shuttle Extension

Guidance for operators migrating from traditional SSH key management to shuttle's deterministic HKDF-derived identity model.

## What Operators Have Today

A typical `~/.ssh/` directory:

```
~/.ssh/
├── config              # Host aliases, per-host settings
├── id_ed25519          # Default private key
├── id_ed25519.pub      # Corresponding public key
├── id_rsa              # Legacy RSA key (may still be in use)
├── known_hosts         # Server fingerprints (accumulated over time)
├── prod-deploy.pem     # AWS/cloud key file
├── work-key            # Separate key for a specific org
└── work-key.pub
```

The `~/.ssh/config` file maps hostnames to connection parameters:

```
Host prod-web
    HostName 10.0.1.50
    User deploy
    Port 22
    IdentityFile ~/.ssh/prod-deploy.pem

Host staging
    HostName staging.example.com
    User admin
    IdentityFile ~/.ssh/work-key

Host github.com
    User git
    IdentityFile ~/.ssh/id_ed25519
```

### Pain points this creates

- **Key sprawl**: Multiple key files, different formats (PEM, OpenSSH), different algorithms (RSA, Ed25519). No relationship between them.
- **No single identity**: Each key is independent. Rotating one doesn't affect others. Losing one doesn't help recover others.
- **Manual distribution**: Public keys must be manually copied to each server's `authorized_keys`. No central provisioning.
- **known_hosts rot**: Accumulated entries for servers that no longer exist, IP changes that trigger scary warnings, hashed entries that are opaque.
- **Config drift**: `~/.ssh/config` grows organically. Entries go stale. Conflicting wildcards. Hard to audit.

## How Shuttle Is Different

Shuttle replaces the entire `~/.ssh/` model with a single root identity that derives all keys mathematically.

### One root → all keys

```
Styrene Identity (32-byte root secret, encrypted on disk)
    └── HKDF-SHA256 with domain separation
        ├── "prod"     → unique Ed25519 key for prod servers
        ├── "staging"  → unique Ed25519 key for staging
        ├── "github"   → unique Ed25519 key for GitHub
        └── "lab"      → unique Ed25519 key for lab machines
```

Each `identity_label` in `hosts.toml` maps to a deterministic Ed25519 key. The same label always produces the same key from the same root. Different labels produce cryptographically independent keys.

### No key files

Private keys never exist as files. They are derived in memory from the root secret via HKDF, used for the SSH handshake, and zeroized. Nothing to accidentally commit, nothing to exfiltrate from disk, nothing to rotate individually.

### One file to back up

The encrypted identity file (`~/.config/styrene/identity.key`, 97 bytes) is the only thing that matters. Back it up once. If you lose it, re-create it and re-distribute the new public keys. If you keep it, all derived keys are recoverable.

## Migration Workflow

### Step 1: Audit the current setup

Use `ssh_migrate_analyze` to scan `~/.ssh/` and generate a migration plan:

```
→ ssh_migrate_analyze
```

This reads `~/.ssh/config` and lists key files (names only, never content) to produce:
- A draft `hosts.toml` for shuttle
- The `shuttle-keygen` commands to export public keys
- A mapping from old config → new config

### Step 2: Choose identity labels

Each `identity_label` should reflect the **trust domain**, not the individual host. Hosts that should share a key get the same label. Hosts that should be isolated get different labels.

Good label design:

| Label | Used for | Rationale |
|-------|----------|-----------|
| `prod` | All production servers | Same team manages them, same trust level |
| `staging` | Staging environment | Different key so staging compromise doesn't reach prod |
| `ci` | CI/CD runners | Automated systems get their own key |
| `personal` | Personal dev boxes | Your machines, your key |

Bad label design:
- One label per host (defeats the purpose — might as well use separate keys)
- One label for everything (no isolation at all)

### Step 3: Generate and distribute public keys

For each label, export the public key and add it to the remote servers.

**Important: Key distribution must be done by the operator, not by the agent.** The agent should never be given instructions to modify `authorized_keys` on remote servers — that is a privilege escalation vector.

```bash
# Generate the public key for a label (run this locally as the operator)
shuttle-keygen ~/.config/styrene/identity.key prod
# → ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... shuttle-prod

# Add it to the remote server (operator action, not agent action)
ssh deploy@10.0.1.50 "echo 'ssh-ed25519 AAAAC3...' >> ~/.ssh/authorized_keys"
```

### Step 4: Write hosts.toml

```toml
[prod-web-1]
address = "10.0.1.50"
user = "deploy"
port = 22
identity_label = "prod"

[staging]
address = "staging.example.com"
user = "admin"
identity_label = "staging"
```

### Step 5: Test with ssh_ping

```
→ ssh_ping { "host": "prod-web-1" }
# Should return { "reachable": true, "latency_ms": 23 }
```

### Step 6: Decommission old keys (optional)

Once shuttle is working, the old key files in `~/.ssh/` are no longer needed for hosts managed by shuttle. Keep them until you've verified every host, then archive or delete.

**Do not delete `~/.ssh/known_hosts` yet** — shuttle maintains its own known_hosts file separately at `~/.omegon/shuttle/known_hosts`. The old file is still used by your regular `ssh` client.

## Concepts Reference

### authorized_keys

The file on the **remote server** that lists which public keys can log in. Located at `~/.ssh/authorized_keys` on the remote host. Each line is one public key in OpenSSH format:

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... comment
```

Shuttle's `shuttle-keygen` outputs this exact format. Paste the output into the remote server's `authorized_keys` file.

### known_hosts

The file on the **local machine** that records server fingerprints. Prevents man-in-the-middle attacks by remembering what each server's key looked like on first connection.

Shuttle maintains its own known_hosts at `~/.omegon/shuttle/known_hosts`. It does NOT share with `~/.ssh/known_hosts`. When you first connect to a host via shuttle:
- If `trust_on_first_use = true` in hosts.toml: the key is recorded automatically
- If `trust_on_first_use = false` (default): the connection is rejected until you manually add the fingerprint

### identity_label

The string that selects which HKDF-derived key to use. Think of it as a named slot in the key hierarchy. The label `"prod"` always derives the same key from the same root secret. The label `"staging"` derives a completely different key.

Labels are arbitrary strings. They don't need to match hostnames. Multiple hosts can share a label (same key) or each host can have its own (maximum isolation).

### SSH agent vs. shuttle

Traditional SSH uses `ssh-agent` — a daemon that holds decrypted private keys in memory and signs on behalf of SSH clients. Shuttle does not use `ssh-agent`. Instead, it derives the key in-process, signs the SSH challenge, and zeroizes the key material. There is no persistent agent process and no `SSH_AUTH_SOCK`.

The `styrene-identity` crate does provide a `StyreneAgent` (SSH agent implementation) for other use cases (git signing, etc.), but shuttle connects directly via `russh` without an intermediary.

### ProxyJump / bastion hosts

Traditional SSH uses `ProxyJump` or `ProxyCommand` in `~/.ssh/config` to reach hosts behind a bastion:

```
Host internal-db
    HostName 10.0.5.200
    ProxyJump bastion.example.com
```

Shuttle does not support ProxyJump directly. Instead, use `ssh_tunnel_open` to create a port forward through the bastion, then connect to the forwarded port. Or configure the bastion itself as a shuttle host and run commands on it that reach the internal network.

### Key algorithms

Shuttle uses Ed25519 exclusively. There is no RSA, ECDSA, or DSA support. Ed25519 is the current best practice: fast, small keys (32 bytes), and no known weaknesses. If a remote server only accepts RSA keys, it must be reconfigured to accept Ed25519 before shuttle can connect.

## Troubleshooting

### "server rejected public key"

The HKDF-derived public key for the configured `identity_label` is not in the remote server's `authorized_keys`. Run `shuttle-keygen` with the same identity file and label, then add the output to the server.

### "unknown host key and TOFU disabled"

The server's host key is not in shuttle's known_hosts file and `trust_on_first_use` is `false` for this host. Either:
- Set `trust_on_first_use = true` in hosts.toml for the first connection, then set it back to `false`
- Manually add the server's fingerprint to `~/.omegon/shuttle/known_hosts`

### "HOST KEY MISMATCH"

The server's host key changed since the last connection. This could mean:
- The server was reinstalled or its SSH keys were regenerated
- A man-in-the-middle attack is in progress

Verify with the server operator. If the change is legitimate, remove the old entry from `~/.omegon/shuttle/known_hosts` and reconnect with TOFU enabled.

### "no styrene identity found"

Shuttle cannot find the identity file. Ensure either:
- `~/.config/styrene/identity.key` exists, or
- `STYRENE_IDENTITY_PATH` environment variable points to the identity file

Create one with: `shuttle-keygen /path/to/identity.key <label>`

### "set STYRENE_PASSPHRASE to unlock the identity file"

The identity file is encrypted and the passphrase was not provided. Set the `STYRENE_PASSPHRASE` environment variable before starting omegon.

### "tunnel destination ... requires allowed_tunnel_destinations"

By default, tunnels can only forward to `127.0.0.1` (loopback) on the remote host. To tunnel to other destinations, set `allowed_tunnel_destinations` in the shuttle config:

```
allowed_tunnel_destinations = "db.internal:5432,cache.internal:6379"
```

Each entry is `host:port` or `host:*` for all ports on that host.

## Tunnel Configuration

Shuttle's tunnels are local-to-remote port forwards only. When you open a tunnel, shuttle:
1. Binds a TCP listener on `127.0.0.1:<local_port>` on your machine
2. For each connection, opens an SSH `direct-tcpip` channel to `<remote_host>:<remote_port>` as seen from the SSH host

**Default behavior**: Only `127.0.0.1`, `::1`, and `localhost` are permitted as `remote_host`. This means you can only reach services running on the SSH host itself.

**To reach internal services** (databases, APIs, admin panels) behind the SSH host, configure `allowed_tunnel_destinations` with explicit host:port pairs. The allowlist can only be tightened after initial configuration — it cannot be widened via runtime config updates.

**Limits**: Maximum 8 concurrent tunnels. Local port must be >= 1024 (no privileged ports).

## Fresh Start (No Existing SSH Setup)

If you don't have an existing `~/.ssh/` to migrate from:

1. **Create a styrene identity** (operator action):
   ```bash
   export STYRENE_PASSPHRASE="your-secure-passphrase"
   shuttle-keygen ~/.config/styrene/identity.key prod
   ```

2. **Create `~/.omegon/shuttle/hosts.toml`**:
   ```toml
   [my-server]
   address = "203.0.113.50"
   user = "deploy"
   identity_label = "prod"
   trust_on_first_use = true
   ```

3. **Add the public key to the remote server** (operator action — not the agent):
   ```bash
   # Copy the shuttle-keygen output to the server
   ssh deploy@203.0.113.50 "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys" <<< "ssh-ed25519 AAAA..."
   ```

4. **Set the passphrase for omegon**:
   ```bash
   export STYRENE_PASSPHRASE="your-secure-passphrase"
   ```

5. **Test**: Use `ssh_ping` to verify connectivity, then `ssh_exec` to run a command.

## Security Considerations

Shuttle is strictly more restrictive than giving an agent raw `ssh` access. However, operators should understand what they are accepting:

- **Command execution is unrestricted on allowed hosts.** There is no command blocklist. If the agent can reach a host, it can run any command the SSH user's permissions allow. Restrict access using `allowed_hosts` and the principle of least privilege for the remote SSH user.
- **Output flows to the agent's context.** Command output, file contents from `sftp_read`, and directory listings enter the agent's context window. A per-call output cap (default 1 MiB) limits volume, but the agent can make many calls.
- **Long-running commands persist until timeout.** The maximum timeout is 3600 seconds. A reverse shell or persistent process will run until the timeout fires.
- **Tunnel destinations on loopback can reach internal services.** Even the restrictive loopback-only default allows the agent to reach any service listening on the SSH host's localhost (Redis, admin panels, metadata endpoints). Use the remote SSH user's firewall or bind-address restrictions for defense in depth.
