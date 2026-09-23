---
format: aep.planning-md/1
id: story:enabled-for-issuer-filters-in-the-implementor
kind: story
status: active
title: enabled_for_issuer leaves its filter to the implementor
relations:
- decomposes: epic:hardening
- serves: vision:mandate
scope:
- confidence: inferred
  path: crates/mandate-conformance/src/external.rs
- confidence: inferred
  path: crates/mandate-conformance/tests/adversary_conformance_2.rs
- confidence: inferred
  path: crates/mandate-conformance/tests/target.rs
- confidence: cited
  path: crates/mandate-federation/src/authenticate.rs
- confidence: cited
  path: crates/mandate-federation/src/lib.rs
- confidence: inferred
  path: crates/mandate-federation/src/record.rs
revision: 6
---
# `enabled_for_issuer` leaves its filter to the implementor

## Why

`ConnectionStore::enabled_for_issuer` (`crates/mandate-federation/src/lib.rs:482`) documents itself as
answering *"every **`Enabled`** connection for this issuer"*, and nothing enforces that: the filter is
the implementor's, and `resolve_tenant` (`crates/mandate-federation/src/authenticate.rs:314-336`)
never re-reads `candidate.state`. A store that includes a disabled sibling connection hands
`resolve_tenant` a rule the domain does not admit.

This is the same class `story:link-absent-discriminates` closed for `LinkStore` in wave H: *a
guarantee a command's correctness depends on that is a property of one implementation of a port rather
than of the port.* That story moved `LinkStore`'s guarantee into a required method and derived the
rest in the crate. `ConnectionStore` was not moved with it — a different clause on a different
command, deliberately left rather than smuggled in.

**The failure direction is closed, which is why this is a note and not a blocker.** Both the unit and
adversary pass 2 measured the same thing: a non-filtering store can only *add* organizations to
`matched`, and `resolve_tenant`'s final check —
`organization_id != connection.organization_id → OrganizationMismatch` — reads the **selected**
connection, which `resolve` has already proved `Enabled`. Over-reporting therefore yields
`TenantAmbiguous`, never an admission into another tenant. Neither could construct an admission a
correct store would have denied.

Untouched by wave H: `git diff 06c6747..8b7a6e0` on both symbols is empty.

## What this story delivers

`ConnectionStore` answers connections in every state, the way `LinkStore::records_on_key` now does,
and `resolve` and `resolve_tenant` read `ConnectionState` themselves — so the admission rule is the
command's and an adapter cannot hold half of it.

## Acceptance

`cargo test -p mandate-federation --locked` exits 0 with a case in which a `ConnectionStore`
answering a `Disabled` connection for the issuer changes no decision, red before the change and green
after. The existing `TenantZero`, `TenantAmbiguous` and `OrganizationMismatch` cases stay green and
unmodified.

## Out of scope

`LinkStore`, which wave H moved. `PrincipalStore::state_of`, whose default is the documented
`mandate.identity` seam rather than a private filter.

## Scope

Derived 2026-09-23 by `aep-drive:story-scoper` at `92fc026`. Every line is **cited** or **inferred**.

- **Primary surface:** `crates/mandate-federation` — cited
- **Files:** `crates/mandate-federation/src/lib.rs:482-489` (`ConnectionStore::enabled_for_issuer`), `:753-759` (impl for `RecordedPrincipals`, inferred); `src/authenticate.rs:241,310-336` (`resolve`, `resolve_tenant`) — cited
- **Also likely:** `src/record.rs:807-815,973`; `crates/mandate-conformance/src/external.rs:581`, `tests/target.rs:796`, `tests/adversary_conformance_2.rs:85` if the method is renamed — inferred
- **Confidence:** medium — rename versus semantics-only is undecided, and the acceptance keeps existing cases unmodified
