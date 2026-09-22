---
format: aep.planning-md/1
id: story:host-spelling-folded
kind: story
status: active
title: Both halves of the SSRF check fold the same host spellings
relations:
- decomposes: epic:hardening
- serves: vision:mandate
scope:
- confidence: cited
  path: crates/mandate-federation/src/verifier_real.rs
- confidence: inferred
  path: crates/mandate-federation/tests/adversary_verifier_2.rs
- confidence: cited
  path: crates/mandate-federation/tests/verifier_real.rs
revision: 7
---
# Every spelling of a host is folded before both checks, not before one

## Why

`UreqJwks::admits` (`crates/mandate-federation/src/verifier_real.rs:326`) is the
SSRF containment on the one network call federated login makes. It refuses a
`jwks_uri` whose host is an address literal or a spelling of the loopback
interface **before** the configured host list is consulted, so no deployment can
list its way to the loopback.

`loopback()` (`:498`) trims a trailing dot before its name comparisons and then
parses the **untrimmed** host for the literal one. So the two checks disagree on
which spellings they fold, and one spelling gets through:

| host | `literal_address` | `loopback` | reaches the allowed-host list |
|---|---|---|---|
| `127.0.0.1` | true | true | no |
| `localhost.` | false | true | no |
| **`127.0.0.1.`** | **false** | **false** | **yes** |
| `::1` | true | true | no |

Measured 2026-09-21 against a verbatim copy of both functions, during
`story:connection-jwks-hosts`. `loopback()`'s own documentation states the rule
it breaks: a host reaching the list is *"never an address literal and never a
spelling of the loopback interface"*.

## Severity, stated honestly

Low, and it should not be inflated. Reaching the list still needs `https`, and
still needs a deployment to have written `127.0.0.1.` into its own
`jwks_hosts` — which is a deployment fetching its key set from its own
loopback on purpose. Nothing in the repository does that and no workflow
produces it.

The class is the finding, not the instance: **two checks over one host that fold
different spellings will disagree, and the disagreement is what gets through.**
`localhost.` is handled and `127.0.0.1.` is not, for no reason either function
states.

## What this story delivers

One folded name computed once and used by both parses, so a spelling cannot be
literal to one check and not to the other. A case per row of the table above,
red before and green after for the `127.0.0.1.` row.

Then the enumeration the fix is worth: every other spelling a resolver folds —
trailing dot, case, IPv6 bracket forms, zero-compression, IPv4-mapped IPv6,
percent-encoding in the authority — measured against both checks, with the
result recorded whether or not it needs a fix.

## Acceptance

`cargo test -p mandate-federation --locked` exits 0 with a case for each row,
the `127.0.0.1.` case red before the change. The enumeration above is recorded
in the test module's documentation, naming each spelling and what both checks
answer for it.

## Out of scope

Widening or narrowing what `admits` allows. The scheme and host-list rules are
right; this is about which host they are asked about.

## Scope

Derived 2026-09-22 by `story-scoper`. Every line is **cited** (read from the story or the tree) or
**inferred** (a reading that could be wrong).

- **Primary surface:** `crates/mandate-federation` — cited, the acceptance is `cargo test -p
  mandate-federation --locked`
- **Files:** `crates/mandate-federation/src/verifier_real.rs:318,484,498` — cited, `admits`,
  `literal_address` and `loopback` are all in this one file
- **Files:** `crates/mandate-federation/tests/verifier_real.rs:2179` — cited,
  `a_listed_host_that_spells_the_loopback_interface_is_refused` already enumerates `localhost.`,
  `localhost..`, `127.0.0.1` and `[::1]`, and is where the table's rows and the missing `127.0.0.1.`
  row land
- **Symbols:** `UreqJwks::admits`, `literal_address`, `loopback` — cited
- **Symbols:** `origin` / `Uri::host` (`src/verifier_real.rs:414`) — inferred, it already lowercases
  the host and strips IPv6 brackets, so it is the other candidate site for the one folded name
- **Also likely:** `crates/mandate-federation/tests/adversary_verifier_2.rs` — inferred, it holds the
  same guard's other spelling cases (`:425` `localhost.`/`localhost.localdomain`, `:474`
  `[::1]`/`[::ffff:127.0.0.1]`) that the enumeration must be measured against
- **Documents:** none — cited, the acceptance records the enumeration in the test module's own `//!`
  documentation, and `docs/public/federated-login.md:135` states a rule the fix does not change
- **The story's `admits` citation is off by a branch** — cited, it says `:326`, which is the
  issuer-own-origin return; the signature is `:318` and the branch where the two checks disagree is
  `:328-331`. `loopback()` at `:498` is exact.
- **Confidence:** high — the story names the defect site, both functions were read at the cited lines,
  and the acceptance names the crate
- **Would collide with:** any unit touching `mandate-federation`'s JWKS destination guard in
  `src/verifier_real.rs` (`origin`, `listed`, `literal_address`, `loopback`, `admits`) or the single
  2.4k-line `tests/verifier_real.rs`
