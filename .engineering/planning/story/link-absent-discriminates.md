---
format: aep.planning-md/1
id: story:link-absent-discriminates
kind: story
status: active
title: Never linked and revoked are different refusals
relations:
- decomposes: epic:authentication
- serves: vision:mandate
scope:
- confidence: cited
  path: crates/mandate-federation/src/authenticate.rs
- confidence: inferred
  path: crates/mandate-federation/src/lib.rs
- confidence: inferred
  path: crates/mandate-federation/src/link.rs
- confidence: cited
  path: crates/mandate-federation/src/record.rs
- confidence: inferred
  path: crates/mandate-federation/tests/authenticate.rs
- confidence: cited
  path: services/control-plane/src/adapters.rs
revision: 10
---
# LinkAbsent stands for two conditions and one of them may create a record

## Why

`DenialClause::LinkAbsent` is returned by `authenticate_federation` both when
an external subject was never linked and when its link was revoked.
`Projection::link` (`crates/mandate-federation/src/record.rs`) filters on
`LinkState::Linked`, so a revoked record reads as no record at all, and
`ProvisionExternalPrincipal`'s own `ExternalKeyExists` guard reads the same
`Linked`-only port.

A composition that admits just-in-time provisioning on that clause therefore
provisions around a revocation: the next login after `UnlinkExternalPrincipal`
mints a **new** `PrincipalId` for the same subject. Measured 2026-09-21 by the
adversary on `story:federated-jit-login`, and reproduced independently by its
implementor.

`services/control-plane` closed it for itself at `c87b563` by reading the key
off the fold across every lifecycle state. That fix is one composition's. The
overload is in the crate, so every future composition inherits it, and no check
in an adapter can stop the next one.

## What this story delivers

A machine-checkable distinction in `mandate-federation`, one of:

- a second clause, so *never linked* and *revoked* are different refusals; or
- a state-blind key read the handler consults, so `ExternalKeyExists` refuses a
  key any record holds in any state.

The first is a contract change and needs the declared cause of
`AuthenticateFederation` to tile the new clause — see
`contracts/obligations/federation.json` and the registry's rules. The second is
a handler change and needs none.

Whichever is taken, `services/control-plane`'s own `key_holds_no_record`
pre-check becomes redundant and should be removed in the same unit, so the
condition is decided in one place.

## Acceptance

`cargo test -p mandate-federation --locked` exits 0 with a case in which
`ProvisionExternalPrincipal` refuses a key an `Unlinked` record holds, red
before the change and green after. `cargo xtask obligations-registry` exits 0.
If the clause is split, the split is verbatim against the declared cause and the
sibling clauses still tile it.

## Out of scope

`services/control-plane`'s behaviour, which is already correct. Any change to
what `UnlinkExternalPrincipal` itself decides.

## Scope

Derived 2026-09-22 by `story-scoper`. Every line is **cited** (read from the story or the tree) or
**inferred** (a reading that could be wrong).

- **Primary surface:** `crates/mandate-federation` — cited, the story names the crate as where the
  distinction must be machine-checkable
- **Files:** `crates/mandate-federation/src/authenticate.rs:181-189` — cited, the `ExternalKeyExists`
  guard in `provision_external_principal` that reads the `Linked`-only port
- **Files:** `crates/mandate-federation/src/record.rs:842-859` — cited, `impl LinkStore for
  Projection` is where the `LinkState::Linked` filter sits
- **Files:** `services/control-plane/src/adapters.rs:2355-2414` — cited, `key_holds_no_record` and its
  call site, which the story says become redundant and go in the same unit
- **Symbols:** `DenialClause::LinkAbsent`, `DenialClause::ExternalKeyExists`, `Projection::link`,
  `provision_external_principal`, `Deployment::key_holds_no_record` — cited
- **Also likely:** `crates/mandate-federation/tests/authenticate.rs` — inferred, the existing
  `ExternalKeyExists` case is at `:473`, so the red-then-green `Unlinked` case most likely joins it
- **Also likely:** `crates/mandate-federation/src/link.rs:115+` — inferred, `link_external_principal`
  is the third caller of the same port and its `LinkConflict` clause depends on the same filter, so a
  state-blind `Projection::link` forces it to filter for itself
- **Also likely:** `crates/mandate-federation/src/lib.rs:505-518` — inferred, the `LinkStore` doc
  already promises "an implementation may return a row in any lifecycle state", which `Projection`
  contradicts
- **Documents:** none — cited, the acceptance is two commands (`cargo test -p mandate-federation`,
  `cargo xtask obligations-registry`) and no document
- **The `Linked` filter is in three places, not one** — cited, the port impl plus an independent
  re-filter in each handler (`authenticate.rs:118-120`, `authenticate.rs:184-186`). Removing it from
  `Projection::link` alone leaves `authenticate_federation` unchanged, which is what this story's
  *Out of scope* requires, and does change `link_external_principal`.
- **If the clause is split instead:** `contracts/obligations/federation.json:63`,
  `contracts/conformance/obligations-report.json`, `crates/mandate-server/src/obligations.rs:115-139`
  and `docs/architecture/command-obligations.md:36` — cited, the clause list must tile the declared
  cause verbatim (`xtask/src/obligations_registry.rs:23,659,795`) and the same phrase is pinned in all
  four. Wave H takes the handler route, so none of these is touched.
- **Confidence:** high — the story cites the crate, the file and the defect site, and all three were
  read in the tree; only the route between two lawful fixes is open
- **Would collide with:** any unit touching `mandate-federation`'s link-read surface — `record.rs`,
  `authenticate.rs` or `link.rs` — and any unit touching `services/control-plane/src/adapters.rs`
