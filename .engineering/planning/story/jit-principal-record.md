---
format: aep.planning-md/1
id: story:jit-principal-record
kind: story
status: active
title: A just-in-time login records the principal its event declares
relations:
- decomposes: epic:authentication
- serves: vision:mandate
scope:
- confidence: inferred
  path: crates/mandate-identity/src/port.rs
- confidence: cited
  path: dependency-boundaries.json
- confidence: cited
  path: services/control-plane/Cargo.toml
- confidence: cited
  path: services/control-plane/src/adapters.rs
- confidence: inferred
  path: services/control-plane/tests/adapters.rs
revision: 9
---
# A just-in-time login mints a principal nothing records

## Why

`identity.yaml`'s header names `mandate.federation.ExternalPrincipalProvisioned`
the writer of the `mandate.identity.Principal` record, and the identity fold
materializes it (`crates/mandate-identity/src/port.rs`).

The served composition does not fold it. Measured 2026-09-21 on
`story:federated-jit-login`: every just-in-time login creates a `PrincipalId`,
carries it through login, authorize, token and introspect, and
`/oauth/introspect` answers `"active": true` with **no `mandate.identity.Principal`
record anywhere**. The road stays green because nothing on it reads
`IdentityRead::principal` — only `Session::principal`, which is a different
read.

So the road trusts a principal it never wrote down. Nothing today depends on
the record; the first thing that does will find it missing, and the failure
will look like a lookup bug rather than a writer that was never wired.

## What blocks it, measured

`Deployment` cannot construct the event. `IdentityEvent::ExternalPrincipalProvisioned`
carries a generated type from `mandate-contract`, which is a **dev-dependency**
of `services/control-plane` (`services/control-plane/Cargo.toml`); the library
target cannot see it. `cargo check -p mandate-control-plane --locked --lib` with
the import added answers `error[E0433]: cannot find module or crate mandate_contract`.

So this is not an adapter edit. It needs either `mandate-contract` promoted to a
dependency — a `dependency-boundaries.json` change with a reason — or the event
constructible without it.

## Acceptance

`cargo test -p mandate-control-plane --locked` exits 0 with a case asserting
that after a just-in-time login the identity fold holds a
`mandate.identity.Principal` for the minted `PrincipalId`, red before and green
after. `cargo run -p xtask -- boundaries` exits 0.

## Out of scope

What `/oauth/introspect` answers, which is correct today. The JIT sequence
itself.

## Scope

Derived 2026-09-22 by `story-scoper`. Every line is **cited** (read from the story or the tree) or
**inferred** (a reading that could be wrong).

- **Primary surface:** `services/control-plane` — cited; the story names the crate, its blocked
  library target and `cargo test -p mandate-control-plane`
- **Files:** `services/control-plane/src/adapters.rs:2423-2456` — cited; `Deployment::provisioned`
  folds the provisioning event into `self.federation` only (`:2455`), and the module header at
  `:68-76` records the gap in as many words
- **Files:** `services/control-plane/Cargo.toml:38` — cited; `mandate-contract` sits under
  `[dev-dependencies]`, which is what blocks the library target
- **Symbols:** `Deployment::provisioned`, `Deployment::record_identity`,
  `IdentityEvent::ExternalPrincipalProvisioned`, `IdentityRead::principal` — cited
- **Not touched in this crate:** `services/control-plane/src/{serve.rs,main.rs,authority.rs}` — cited;
  none of the three names `mandate_identity`, `IdentityEvent` or the provisioning event
- **Also likely:** `services/control-plane/tests/adapters.rs` — inferred, the acceptance case needs an
  in-process `Deployment` to read the fold from, and `tests/serve.rs` moves its deployment onto a
  listener thread (`serve.rs:1540-1545`)
- **Also likely:** `crates/mandate-identity/src/port.rs:348` — inferred, and only on the story's
  second design path ("the event constructible without it"), which means a native
  `ExternalPrincipalProvisioned` struct beside `SessionOpened` instead of the generated type
- **`dependency-boundaries.json:144`** — cited as the story's stated cost of promotion; the allowlist
  already carries `mandate-control-plane -> mandate-contract` and `xtask::boundaries`
  (`xtask/src/main.rs:275-287`) matches on name without kind, so the edit may turn out to be none
- **`Deployment` has no public identity read accessor today** — inferred from absence; the acceptance
  case needs one added in `adapters.rs`
- **Documents:** none — cited; `docs/architecture/federated-login.md:29,49,105` already states the
  declared writer this story wires, and `contracts/coverage.json` maps the element to
  `mandate-federation`, not to the composition
- **Confidence:** high — the story names the defect site, the tree confirms the fold call, the
  manifest kind and the absence of identity wiring in every other `src` file of the crate
- **Would collide with:** any unit touching `services/control-plane/src/adapters.rs` or
  `services/control-plane/Cargo.toml`; on the second design path, also any unit touching
  `crates/mandate-identity/src/port.rs`
