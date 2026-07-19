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

A minimal representation is:

```rust
struct EphemeralSshEndpoint {
    logical_host: String,
    address: String,
    port: u16,
    host_key_fingerprint: String,
    expires_at: SystemTime,
    provenance: String,
}
```

The harness validates the producer and preserves provenance before passing the binding to Shuttle. Shuttle then:

1. requires `logical_host` to be permitted by its existing host policy;
2. rejects expired bindings;
3. connects to the temporary `address:port` without treating it as a new authorized host;
4. verifies the presented SSH host key against `host_key_fingerprint`;
5. authenticates with the configured profile for `logical_host`; and
6. includes binding provenance in structured operation evidence.

A binding cannot widen `allowed_hosts`, waive host-key verification, select arbitrary credentials, or become permanent configuration. It contains no private key, provider credential, command, or provider-specific authorization. Provider references such as an AWS SSM session ID remain opaque provenance.

This supports composition without direct extension coupling. For example, an AWS tool may create an SSM port-forward and return a temporary endpoint; the harness mediates the binding; Shuttle performs verified SSH. EC2 Instance Connect instead composes by publishing Shuttle's public key through AWS and then using Shuttle's ordinary configured endpoint. Pure SSM command execution remains an AWS operation and does not pass through Shuttle.

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
- ephemeral endpoint expiry and logical-host policy enforcement;
- endpoint-override host-key fingerprint verification;
- provenance preservation without provider credential leakage;
- reconnect after a dead session;
- bounded output and transfer sizes;
- timeout and cancellation behavior;
- exact destination authorization;
- tunnel listener failure, stream failure, and close races;
- sanitized structured tracing;
- transport-independent result fields.
