---
format: aep.planning-md/3
id: story:oidc-durable-state
kind: story
status: draft
title: Sessions, refresh families, links and keys survive a restart
relations:
- decomposes: epic:openid-provider
- serves: vision:mandate
- depends_on: story:domain-folds-over-the-kit
- depends_on: story:listener-outbound-stall
revision: 1
---
# Sessions, refresh families, links and keys survive a restart

Parity story 7, second half (durable storage).

## Why

**Exists:** ADR 0009 decides event sourcing through the organization's `eventlog` kit, pinned at
`0.3.0` (`Cargo.toml:22-23`); only `crates/mandate-provisioning` and the worker depend on it
(`crates/mandate-provisioning/Cargo.toml:17`, `services/worker/Cargo.toml:18-19`). Every control-plane
fold is in memory and seeded from flags; "a restart loses every session, every unredeemed
authorization code, every credential and every link" (`docs/public/roadmap.md`, *What is not true
yet*). The kit's surface is asynchronous and the listener has no runtime
(`services/control-plane/src/serve.rs:16-22`, ruling D2). `story:domain-folds-over-the-kit` (draft)
moves the federation fold onto the kit; `story:listener-outbound-stall` (draft) records that one slow
upstream call stalls every route.

For an OP behind a gateway, a restart that forgets refresh families signs every user out, and a
restart that forgets signing keys invalidates every token in flight.

**New:** the async runtime (fork F9-A); every fold the OP road reads — federation (links, clients,
profiles), identity (sessions, refresh families, epochs), credential (codes, credentials, signing
keys) — rebuilt from the kit's SQLite store on a PersistentVolume at start; concurrent request
handling with the existing per-request limits.

## Acceptance

- `story:domain-folds-over-the-kit` acceptance holds (federation fold built by the kit's store).
- `durable::restart_preserves_road`: a test starts the binary on a store directory, completes a
  login, an authorization, a refresh, a key rotation; kills the process; restarts on the same
  directory; and the refresh token, the session cookie, the link and both published keys are still
  honoured, while a revoked key stays revoked (`RealSigner::new_with_revocations`,
  `crates/mandate-token/src/signing_real.rs:789`).
- `durable::one_use_code_across_restart`: a code redeemed before the restart is refused after it.
- `durable::concurrent_routes`: with an upstream that answers after its deadline, another route
  answers within its own bound — `story:listener-outbound-stall`'s acceptance, which this closes.
- `durable::redaction_rewrites_profile`: redacting a principal's profile rewrites the projection,
  records the redaction, and the next token omits the redacted claims (ADR 0009).
- Readiness (`story:oidc-deployment-package`) reports storage.
- The ESS conformance run is unchanged or better: the folds' scenarios pass against the kit-backed
  target.

## Scope

- `Cargo.toml`, `dependency-boundaries.json` (`tokio`, `hyper` admitted for `services/control-plane`
  only), `deny.toml`.
- `services/control-plane/src/serve.rs` (listener on the runtime), `adapters.rs` (folds over the
  kit), `main.rs` (`--state-dir`).
- `crates/mandate-federation/src/record.rs`, `crates/mandate-identity/src/port.rs`,
  `services/sts/src/store.rs` (fold sources).
- `deploy/helm/mandate/templates/` (PVC wiring).

## Out of scope

A Postgres backend, more than one replica, backup and restore runbooks (`story:recovery-runbooks`).

## Depends on

`story:domain-folds-over-the-kit` (absorbed or first), `story:listener-outbound-stall` (closed by
this), fork F9 decided by the operator. Parallel with every other parity story until the swap proof.

## Size

**L — 5–6 implementor-days**, the largest in the epic. A runtime change under a listener that has
drawn several adversary rounds, three domains' folds moved onto a store, and a restart harness.
Splits into (a) runtime and listener; (b) federation and identity folds; (c) credential folds and
keys; (d) restart harness.
