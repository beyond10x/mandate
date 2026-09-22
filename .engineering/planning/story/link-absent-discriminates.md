---
format: aep.planning-md/1
id: story:link-absent-discriminates
kind: story
status: implemented
title: Never linked and revoked are different refusals
relations:
- decomposes: epic:authentication
- serves: vision:mandate
scope:
- confidence: cited
  path: crates/mandate-conformance/src/external.rs
- confidence: cited
  path: crates/mandate-conformance/tests/target.rs
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
revision: 14
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

Derived 2026-09-22 by `story-scoper`, and **rewritten at wave H's close from what the unit
measured**. Every line is **cited** (read from the story or the tree) or **inferred** (a reading that
could be wrong).

- **Primary surface:** `crates/mandate-federation` — cited
- **Files:** `crates/mandate-federation/src/lib.rs` — cited, where `LinkStore` is declared. This is
  where the change landed: the port now has one **required** method, `records_on_key`, answering every
  record on the key in every state, and `link` is derived from it inside the crate
- **Files:** `crates/mandate-federation/src/authenticate.rs:181-189` — cited, the `ExternalKeyExists`
  guard in `provision_external_principal`, which reads the required method
- **Files:** `crates/mandate-federation/src/record.rs:842-859` — cited, `impl LinkStore for
  Projection`
- **Files:** `services/control-plane/src/adapters.rs:2355-2414` — cited, `key_holds_no_record` and its
  call site, removed in the same unit
- **Files:** `crates/mandate-conformance/src/external.rs` and `crates/mandate-conformance/tests/target.rs`
  — cited after the fact: the other implementor of the port, and the suite that scans it for every
  method a `Substituted` implements. A port change reaches them, and the scoper did not predict it
- **Symbols:** `DenialClause::LinkAbsent`, `DenialClause::ExternalKeyExists`,
  `LinkStore::records_on_key`, `Projection::link`, `provision_external_principal`,
  `Deployment::key_holds_no_record` — cited

**The mechanism claim this section carried was false, and both the unit and the adversary measured
it.** It read: *"Removing it from `Projection::link` alone leaves `authenticate_federation`
unchanged."* It does not. `Projection::link` answers `min_by_key(id)`, so a state-blind version makes
the key's holder the smallest record in **any** state: a key with a smaller revoked record and a
larger linked one stops promoting the surviving link, `authenticate_federation` denies `LinkAbsent` to
a validly linked principal, and `LinkConflict` stops firing. `tests/replay.rs:403` caught it.

What landed instead: `link` prefers the smallest `Linked` record and falls back to the smallest record
in any state only when the key has none — and the preference is **derived in the crate**, not left to
each adapter, because adversary pass 1 showed that a guarantee stated to implementors as prose is a
guarantee one implementation keeps and the next one does not.

- **The `Linked` filter was in three places, not one** — cited: the port impl, plus an independent
  re-filter in `authenticate.rs:118-120` and `authenticate.rs:184-186`
- **Left standing and reported:** `ConnectionStore::enabled_for_issuer` filters on `Enabled` in the
  implementor and `resolve_tenant` never re-reads `candidate.state`, so a store including a disabled
  sibling can turn a `TenantZero` refusal into a match. Bounded to the selected connection's own
  organization. Same class, different clause, its own story
- **Documents:** none — cited, the acceptance is two commands and no document
- **If the clause is split instead:** `contracts/obligations/federation.json:63`,
  `contracts/conformance/obligations-report.json`, `crates/mandate-server/src/obligations.rs:115-139`
  and `docs/architecture/command-obligations.md:36` — cited. Wave H took the handler route; none was
  touched
- **Confidence:** high for the surface, and the mechanism line is now measured rather than inferred
- **Would collide with:** any unit touching `mandate-federation`'s link-read surface — `lib.rs`,
  `record.rs`, `authenticate.rs` or `link.rs` — `services/control-plane/src/adapters.rs`, or
  `crates/mandate-conformance`'s implementation of the port
