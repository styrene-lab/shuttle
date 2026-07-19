# Transport and Identity Architecture

Shuttle's current production transport is SSH. The public tool surface should not become synonymous with SSH, because Styrene Mesh can provide lower-friction tunnels and RPC for peers already inside the ecosystem.

## Operator contract

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
- reconnect after a dead session;
- bounded output and transfer sizes;
- timeout and cancellation behavior;
- exact destination authorization;
- tunnel listener failure, stream failure, and close races;
- sanitized structured tracing;
- transport-independent result fields.
