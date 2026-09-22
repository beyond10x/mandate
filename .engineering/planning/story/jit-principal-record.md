---
format: aep.planning-md/1
id: story:jit-principal-record
kind: story
status: draft
title: A just-in-time login records the principal its event declares
relations:
- decomposes: epic:authentication
- serves: vision:mandate
revision: 1
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
