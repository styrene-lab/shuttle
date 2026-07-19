# Transport and Identity Architecture

Shuttle's current production transport is SSH. The public tool surface should not become synonymous with SSH, because Styrene Mesh can provide lower-friction tunnels and RPC for peers already inside the ecosystem.

## Operator contract

Shuttle is an individual point-to-point substrate. It does **not** own fleet inventory, desired state, scheduling, orchestration, rollout policy, reconciliation, or machine lifecycle. A management system may invoke Shuttle, but those responsibilities remain above its boundary.

An operator with Shuttle installed should be able to reason with the agent about configured remote machines in ordinary operational language. The agent discovers the available hosts and capabilities through Shuttle's tool definitions, inspects remote state with bounded read/probe operations, and performs the operator's authorized directives through the same explicit tool surface.

Shuttle is the execution substrate, not an autonomous remote-management actor. The operator supplies intent, the agent plans and invokes operations, and Shuttle enforces configured host, identity, path, destination, timeout, and output boundaries. Results must contain enough structured evidence for the agent and operator to verify what happened rather than infer success from transport availability.

This contract applies regardless of transport. SSH, Styrene Mesh streams, and Styrene Mesh RPC should project compatible operation-level capabilities while retaining transport and authenticated-principal metadata for policy and audit decisions.

## Boundary

The extension has three conceptual layers:

1. **Operations** — execute, copy/read, directory listing, tunnel lifecycle, and connectivity probes.
2. **Transport sessions** — authenticated SSH today; Styrene Mesh RPC and streams later.
3. **Identity and authorization** — named authentication profiles today; Styrene Identity principals, attestations, and policy later.

Current code still uses concrete `SshClient` parameters internally. New operation semantics should be kept out of that client. When the first Mesh operation lands, extract operation-focused traits rather than a single broad transport trait:

```rust
trait RemoteExec { /* execute request -> bounded result */ }
trait RemoteFs { /* stat/read/write/list requests */ }
trait TunnelTransport { /* open bidirectional stream */ }
trait PeerProbe { /* authenticated reachability and identity */ }
```

Small capability traits avoid forcing Mesh RPC into SSH channel semantics or forcing SSH into Mesh's peer/RPC model. A session registry should key sessions by `(transport, endpoint, identity_profile)` and expose transport-neutral lifecycle metadata.

## Ephemeral SSH endpoint bindings

Provider and infrastructure extensions compose with Shuttle through the harness; Shuttle does not depend on AWS, Kubernetes, or their CLIs. The narrow handoff is an ephemeral, provenance-aware SSH endpoint binding: effectively a short-lived internal `known_hosts` record with a logical-host identity and endpoint override.

The binding keeps three values distinct:

- **Logical host** — the durable Shuttle policy identity, such as `payments-prod-17`.
- **Network endpoint** — the temporary socket, such as `127.0.0.1:49152` from an SSM port-forward.
- **Cryptographic identity** — the expected SSH host-key fingerprint.

The harness owns a binding registry and passes Shuttle only an opaque `endpoint_binding` handle. Shuttle resolves that handle through a harness capability; it does not accept security fields embedded in ordinary tool arguments. The immutable, versioned registry record is conceptually:

```rust
struct EphemeralSshEndpointV1 {
    binding_id: BindingId,
    issuer: HarnessExtensionId,
    audience: ShuttleExtensionId,
    logical_host: String,
    address: IpAddr,
    port: NonZeroU16,
    host_key_pin: SshHostKeyPin,
    issued_at: SystemTime,
    expires_at: SystemTime,
    producer_session: Option<LeaseHandle>,
    provenance: SanitizedProvenance,
}

struct SshHostKeyPin {
    key_algorithm: SshKeyAlgorithm,
    fingerprint_algorithm: Sha256,
    digest: [u8; 32],
}
```

The harness authenticates the issuer, requires audience `shuttle`, validates schema version and integrity, enforces producer capability, and preserves cancellation/revocation state. Shuttle rejects unknown handles rather than trusting caller-provided provenance or endpoint fields. Wire timestamps use UTC Unix milliseconds with explicit maximum TTL and clock-skew bounds.

Bindings are bounded multi-use by default: operations may reuse them until expiry or revocation, but they are not bearer authorization to a host. The configured logical-host policy and authentication profile remain authoritative. A future single-use mode requires atomic harness consumption and per-binding singleflight connection establishment.

Shuttle then:

1. resolves the handle and requires `logical_host` to be permitted by existing host policy;
2. rejects bindings that are expired, revoked, issued too far in the future, exceed maximum TTL, or target the wrong audience;
3. restricts endpoints: reject port zero and unspecified, multicast, or broadcast addresses; provider-created port forwards must resolve to loopback or a harness-owned local socket;
4. connects to the temporary endpoint without treating it as a new authorized host;
5. verifies the presented key using only the canonical structured pin; and
6. authenticates with a policy-authorized profile for `logical_host` and returns sanitized provenance evidence.

Ephemeral verification is a separate verifier mode from permanent host trust:

```rust
enum HostVerifier {
    ConfiguredKnownHost { logical_host: String, tofu: bool },
    EphemeralPinnedKey { pin: SshHostKeyPin },
}
```

`EphemeralPinnedKey` never reads or writes permanent `known_hosts`, never performs TOFU, rejects unsupported algorithms, and compares decoded digest bytes rather than display strings. Key rotation requires the producer to issue a new binding; one binding pins exactly one host key.

Expiry is checked before endpoint use, immediately before connection, after authentication before pool publication, and before every new SSH channel. Connection timeout is bounded by `min(connect_timeout, expires_at - now)`. Expiry or revocation prevents new channels, evicts binding-owned pooled sessions, and closes binding-owned tunnels; an already-running non-tunnel operation may finish within its normal operation timeout.

Ephemeral sessions cannot share the static-host pool namespace. Their pool key includes `(binding_id, logical_host, endpoint, auth_profile, host_key_pin)`, and each entry stores binding expiry. A session verified under one binding can never replace or satisfy another binding, even at the same recycled socket. Per-binding singleflight prevents redundant concurrent authentication and publication-after-expiry races.

A binding cannot widen `allowed_hosts`, waive host-key verification, select arbitrary credentials, or become permanent configuration. The optional operation `auth` argument may select only a profile already permitted by the logical host; producer data never selects credentials. Bindings contain no private key, provider credential, command, or provider-specific authorization.

Provenance returned to the operator is a sanitized record containing issuer, producer tool, binding ID, and a redacted or hashed provider reference. Raw producer strings and potentially bearer-like provider session IDs are never echoed or traced.

Binding failures are typed and retain `{ operation, transport: "ssh", phase, code, retryable }`. Required non-retryable codes include `binding_invalid`, `binding_expired`, `binding_revoked`, `binding_audience_mismatch`, `endpoint_policy_denied`, and `host_key_pin_mismatch`. Transient connection failures are retryable only while the binding remains valid.

This supports composition without direct extension coupling. For example, an AWS tool may create an SSM port-forward and register a temporary endpoint; the harness returns its opaque handle; Shuttle performs pinned SSH. Provider-session death revokes the registry entry, after which Shuttle closes dependent sessions and tunnels. EC2 Instance Connect instead composes by publishing Shuttle's public key through AWS and then using Shuttle's ordinary configured endpoint. Pure SSM command execution remains an AWS operation and does not pass through Shuttle.

Do not generalize this into a fleet lease or orchestration framework. Introduce a broader transport-neutral endpoint contract only when a second transport, such as Styrene Mesh, demonstrates requirements beyond this SSH-specific binding.

## Stable operation results

Results should expose a `transport` discriminator (`ssh` now, `mesh` later) while retaining operation-level fields. Tunnel records already do this. Future changes should add it to execution, transfer, and probe results without renaming existing fields.

Errors should preserve three dimensions:

- operation: `exec`, `read`, `tunnel`, etc.;
- transport: `ssh` or `mesh`;
- phase: resolve, authenticate, connect, request, stream, or close.

Do not leak credentials, root secrets, private keys, RPC payload secrets, or full command bodies into traces.

## Styrene Identity affordances

Authentication profiles are the compatibility boundary. Future profile variants can include a Styrene Identity selector without changing host records or tool arguments:

```toml
[auth.mesh-prod]
type = "styrene_identity"
principal = "service/operator"
policy = "remote-operations"
```

A resolved identity should yield a principal identifier and signing/authentication capability, not raw secret material. Authorization decisions should use authenticated principal and requested capability. SSH derived-key labels remain an SSH-specific credential mechanism, not the global identity model.

Suggested Mesh capabilities:

- `shuttle.exec`
- `shuttle.fs.read`
- `shuttle.fs.write`
- `shuttle.tunnel.open`
- `shuttle.rpc.call`

## Mesh evolution path

1. Add transport-neutral result metadata and error classification.
2. Extract `TunnelTransport` from the proven SSH tunnel path.
3. Add Mesh peer resolution and authenticated probe using Styrene Identity.
4. Add Mesh tunnel streams behind the existing tunnel manager/lifecycle API.
5. Add an explicit Mesh RPC tool after capability policy and payload limits are specified.
6. Extract exec/filesystem traits only where Mesh implementations need them.

This sequence avoids speculative abstraction while preserving a clean migration path.

## Verification requirements

Every transport implementation must test:

- identity/profile isolation in session reuse;
- compatibility of calls without `endpoint_binding`;
- binding issuer, audience, integrity, maximum TTL, clock skew, expiry, and revocation;
- replay behavior and concurrent acquisition for bounded multi-use and future single-use bindings;
- expiry during resolution, connection, authentication, pool publication, and channel creation;
- expired or revoked pooled-session rejection and dependent-tunnel closure;
- same endpoint and auth with different binding IDs or pins never sharing a session;
- permanent known-host and TOFU state cannot satisfy or persist an ephemeral pin;
- canonical pin decoding, unsupported algorithms, malformed pins, and key rotation;
- endpoint policy for loopback forwards, forbidden addresses, DNS resolution, and recycled ports;
- authenticated provenance preservation, tamper rejection, and provider-reference redaction;
- producer-session death invalidating dependent sessions and tunnels;
- typed binding error code, phase, and retryability projection;
- reconnect after a dead session;
- bounded output and transfer sizes;
- timeout and cancellation behavior;
- exact destination authorization;
- tunnel listener failure, stream failure, and close races;
- sanitized structured tracing;
- transport-independent result fields.
