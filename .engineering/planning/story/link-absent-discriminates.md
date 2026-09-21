---
format: aep.planning-md/1
id: story:link-absent-discriminates
kind: story
status: draft
title: Never linked and revoked are different refusals
relations:
- decomposes: epic:authentication
- serves: vision:mandate
revision: 1
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
