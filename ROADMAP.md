# Shuttle Roadmap to 1.0.0

## Release policy

Shuttle uses release maturity, not feature count, to define General Availability.

| Version/channel | Maturity | Distribution | Promise |
|---|---|---|---|
| `0.1.x` | **Security-Hardened Controlled Preview** | Armory | Controlled operational evaluation; security fixes prioritized; preview contracts may evolve. |
| `0.x` Live Preview | **Live Preview** | Armory | Regular releases that close the published GA gates with documented compatibility notes. |
| `1.0.0-rc.N` | **GA Release Candidate** | Armory | Feature and contract freeze; only release-blocking fixes accepted. |
| `1.0.0` | **General Availability** | Armory | Production-supported, documented, compatibility-governed release. |

Armory is the distribution and discovery surface throughout preview and GA. “Live Preview” means that operators can use current builds while development continues in public milestones; it does not weaken Shuttle's fail-closed security posture.

## Current baseline: 0.1.x

The current baseline is a security-hardened controlled preview with:

- configured-host discovery and authenticated probes;
- bounded command and script execution;
- bounded SFTP inspection and file transfer;
- policy-controlled SSH tunnels;
- exact authentication-profile selection;
- static host-key verification;
- bounded, identity-isolated connection pooling;
- harness-issued ephemeral endpoint bindings with pinned host keys, expiry, replacement, and revocation propagation;
- structured tracing that excludes credentials and command bodies;
- unit tests, SDK smoke CI, cross-platform release packaging, and release automation.

The preview designation remains necessary because live integration evidence, operator packaging, stable machine-readable contracts, and the privileged binding-bootstrap contract are not yet complete.

## Principles for the path to GA

1. **No fleet-management expansion.** Shuttle remains a point-to-point execution substrate.
2. **No Mesh dependency for 1.0.** SSH is sufficient for GA. Styrene Mesh can arrive behind compatible operation contracts later.
3. **Security before compatibility before convenience.** Preview-breaking changes are acceptable when required to establish safe 1.0 contracts.
4. **Evidence over claims.** A capability is GA-ready only when its live behavior is exercised in mandatory CI.
5. **Agent-reasonable contracts.** Results and failures must be structured enough for an agent to choose safe next actions without parsing prose.
6. **Armory is the release surface.** Every preview milestone ships with maturity, compatibility, known-limit, and upgrade metadata.

## Milestone 1 — Preview packaging and operator contract

**Target:** next `0.1.x` release

- [x] Define the current maturity as Security-Hardened Controlled Preview.
- [x] Define Armory as the preview and GA distribution channel.
- [x] Publish an operator-facing README and security boundary.
- [x] Remove deployment-specific required secrets and host defaults from the package manifest.
- [ ] Add Armory metadata for maturity, documentation, supported platforms, and known limitations.
- [ ] Verify clean installation from Armory on every supported release target.
- [ ] Add a first-run configuration diagnostic that reports missing host, allowlist, identity, secret, and host-key prerequisites without exposing secret values.
- [ ] Ensure `.flynt/` and `.omegon/` runtime state cannot enter release artifacts.

**Exit condition:** a new operator can install from Armory, understand that the build is preview software, configure one host, and perform an authenticated probe using only published documentation.

## Milestone 2 — Mandatory live transport verification

**Target:** `0.2.x`

- [ ] Run the sshd-backed integration suite in a dedicated required CI job.
- [ ] Make absent integration infrastructure a failure in that CI job, not a successful skip.
- [ ] Test command execution, stderr, exit status, timeout, and truncation against live sshd.
- [ ] Test script stdin and interpreter restrictions.
- [ ] Test SFTP list/read/upload/download and transfer limits.
- [ ] Test tunnel forwarding through a real target service, listener release, failure reporting, and close races.
- [ ] Test connection reuse, pool eviction, identity isolation, and dead-session recovery.
- [ ] Test static unknown-key, pinned-key, mismatch, and explicit TOFU behavior.
- [ ] Publish CI evidence and supported target matrix in Armory release metadata.

**Exit condition:** every static SSH capability offered to an operator is exercised against live infrastructure in required CI.

## Milestone 3 — Stable operation evidence and errors

**Target:** `0.3.x`

- [ ] Add `transport: "ssh"` to every operation result without removing existing fields.
- [ ] Define stable operation result schemas for exec, script, probe, transfer, listing, migration, and tunnel lifecycle.
- [ ] Define machine-readable failures with at least:
  - `operation`;
  - `transport`;
  - `phase`;
  - `code`;
  - `retryable`;
  - sanitized human-readable detail.
- [ ] Preserve distinct codes for policy denial, binding expiry/revocation, host-key mismatch, authentication rejection, timeout, transport closure, and remote operation failure.
- [ ] Add sanitized endpoint-binding evidence: issuer, producer tool, binding ID, and redacted provider reference.
- [ ] Document retry behavior so agents do not retry non-retryable security failures.
- [ ] Add contract tests that lock input, result, and error shapes.

**Exit condition:** an agent can determine what failed, where it failed, and whether retry is safe without parsing unstable error prose.

## Milestone 4 — Endpoint-binding control-plane completion

**Target:** `0.4.x`

- [ ] Make endpoint-binding bootstrap a formally privileged Omegon host capability, or require a signed/versioned harness envelope.
- [ ] Feature-gate endpoint bindings when the host cannot prove that privileged bootstrap boundary.
- [ ] Add live sshd tests for correct pins, mismatched pins, expiry, omission revocation, changed-payload revocation, and recycled endpoints.
- [ ] Verify permanent known-host and TOFU state cannot satisfy or persist an ephemeral pin.
- [ ] Add per-binding connection singleflight or prove redundant concurrent authentication cannot publish stale sessions.
- [ ] Ensure revoked binding-owned pool entries are proactively evicted.
- [ ] Verify active bound tunnels terminate within a documented revocation latency.
- [ ] Verify SFTP revocation behavior and document in-flight request granularity.
- [ ] Resolve endpoint classes, including loopback/provider-forward requirements and broadcast-address rejection.
- [ ] Compare decoded host-key digest bytes using a dedicated constant-time equality path.
- [ ] Reconcile the architecture document so implemented 1.0 requirements and post-1.0 enhancements are clearly separated.

**Exit condition:** a compromised ordinary tool caller cannot mint endpoint trust, and binding expiry/revocation behavior is proven end to end.

## Milestone 5 — Operational hardening and release rehearsal

**Target:** `0.5.x` through `0.9.x`

- [ ] Define the support matrix for Omegon SDK, Linux/macOS architectures, OpenSSH server versions, and authentication modes.
- [ ] Test clean install, upgrade, rollback, and uninstall through Armory.
- [ ] Test migration from the earliest supported preview configuration.
- [ ] Add bounded shutdown behavior for pooled sessions and tunnels.
- [ ] Add health diagnostics for configuration, identity availability, trust state, and integration compatibility.
- [ ] Document lexical remote-root semantics and remote symlink limitations prominently.
- [ ] Review password handling, secret names, logs, errors, and crash output for disclosure.
- [ ] Perform dependency and license review; generate release SBOM/provenance where Armory supports it.
- [ ] Conduct a final threat-model review of SSH, SFTP, tunnel, local-path, and bootstrap boundaries.
- [ ] Run soak tests for repeated execution, transfer, reconnect, and tunnel churn.
- [ ] Publish a versioned compatibility policy and deprecation process.

**Exit condition:** installation and sustained operation are repeatable on every supported platform, and documented upgrades do not require operator guesswork.

## Milestone 6 — 1.0 release candidate

**Target:** `1.0.0-rc.1`

At RC entry:

- all tool inputs, result schemas, errors, manifest settings, and host configuration fields freeze;
- all GA documentation is complete;
- all required CI and live integration jobs are green;
- no known critical or high security findings remain;
- Armory clearly labels the artifact as a GA release candidate;
- only release-blocking correctness, security, compatibility, packaging, or documentation changes are accepted.

RC validation must include:

- [ ] clean Armory installation on all supported targets;
- [ ] static-host and endpoint-binding live suites;
- [ ] upgrade from the latest supported preview;
- [ ] release artifact checksum and provenance verification;
- [ ] adversarial security assessment;
- [ ] operator acceptance run using only released documentation;
- [ ] agent acceptance run covering discovery, diagnosis, execution, transfer, and tunnel workflows.

A material contract or security change resets the RC soak period and increments `rc.N`.

## 1.0.0 — GA definition

Shuttle `1.0.0` is GA-ready only when every item below is true.

### Product and distribution

- [ ] Armory installation, upgrade, and rollback are tested on every supported target.
- [ ] Armory metadata identifies Shuttle as GA and links version-matched documentation.
- [ ] Release artifacts include checksums and supported provenance metadata.
- [ ] No environment-specific host, secret, or policy defaults ship in the generic package.

### Stable operator and agent contract

- [ ] Tool inputs, outputs, errors, configuration, and host schema are versioned and documented.
- [ ] Every operation emits transport and sufficient structured evidence.
- [ ] Every failure emits stable code, phase, and retryability.
- [ ] Backward compatibility and deprecation policy are published.
- [ ] Static SSH calls without endpoint bindings remain covered and compatible.

### Security

- [ ] Host, credential, host-key, path, transfer, timeout, and tunnel policies fail closed.
- [ ] Endpoint-binding bootstrap trust is enforced by the host or cryptographic envelope.
- [ ] Expiry and revocation prevent new channels and terminate dependent tunnels within the documented bound.
- [ ] Secret-safe logs and errors are verified.
- [ ] No unresolved critical or high adversarial findings remain.

### Verification and operations

- [ ] Unit, contract, SDK smoke, live sshd, release-install, and upgrade suites are required and green.
- [ ] Live tests cover all documented static and ephemeral SSH behavior.
- [ ] Supported platform and server matrix is published.
- [ ] Soak testing meets the defined reliability threshold.
- [ ] Operator and agent acceptance runs pass from clean environments.

### Documentation and support

- [ ] README, installation, configuration, security, migration, troubleshooting, and upgrade documentation are complete.
- [ ] Known limitations are explicit, including remote symlink and in-flight SFTP revocation semantics.
- [ ] GA support and vulnerability-reporting channels are published.
- [ ] CHANGELOG contains the preview-to-GA compatibility and migration summary.

## Explicitly post-1.0

These are valuable but do not block SSH-focused GA:

- Styrene Mesh streams;
- Styrene Mesh RPC;
- fleet inventory or orchestration;
- rollout scheduling or desired-state reconciliation;
- broad transport abstraction without a second proven transport;
- single-use endpoint bindings unless a concrete producer requires them.

## Progress accounting

A checkbox is closed only by repository evidence: merged implementation, required green tests, published documentation, or a recorded release artifact. Preview use and anecdotal success inform priorities but do not replace a GA gate.

The authoritative status is this roadmap plus the latest Armory release metadata. The changelog records what shipped; this file records what remains before `1.0.0`.
