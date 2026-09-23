---
format: aep.planning-md/1
id: story:folded-is-not-an-address-fold
kind: story
status: implemented
title: folded agrees on names, and the two halves of the guard disagree on addresses
relations:
- decomposes: epic:hardening
- serves: vision:mandate
scope:
- confidence: cited
  path: crates/mandate-federation/src/verifier_real.rs
- confidence: cited
  path: crates/mandate-federation/tests/adversary_host_spelling_2.rs
- confidence: inferred
  path: crates/mandate-federation/tests/verifier_real.rs
revision: 8
---
# `folded` agrees on names, and the two halves of the guard disagree on addresses

## Why

`story:host-spelling-folded` closed one spelling disagreement in `UreqJwks::admits`
(`crates/mandate-federation/src/verifier_real.rs`): the destination host is now folded once and the
same name is handed to every comparison. The fold strips trailing dots, and that is the whole of what
it does.

One layer down, the same class is still open, and the unit's own documentation says so. The
containment halves — `literal_address` and `loopback` — read the host through `IpAddr::from_str`,
which collapses every spelling of one address. The issuer's own-origin comparison is string equality,
which collapses none of them. So `[::1]`, `[0:0:0:0:0:0:0:1]` and `[0:0::0:1]` are one host to the
first two and three strangers to the third: a loopback issuer whose discovery document spells its own
address a second valid way gets two answers for one host.

Measured 2026-09-22 by adversary pass 2 of that story, red against the shipped guard:

```
issuer http://[::1]:8443: [::1] and [0:0:0:0:0:0:0:1] are one address and the guard gave them two
answers: alike=true, otherwise=false
```

**It fails closed** — the disagreement produces a refusal, not an admission — which is why this is a
smaller finding than the one the parent story closed, and it reproduces identically at that story's
base commit. Nothing was found that reaches it: `end_to_end.rs` binds `127.0.0.1`, and
`normalised_issuer`'s own `is_loopback` refuses the IPv4-mapped forms outright.

## What this story delivers

The own-origin comparison asks the same question as the containment halves: whether two hosts are one
host. Which way that is resolved is this story's call — comparing parsed addresses widens the
own-origin arm, and refusing every literal own-origin narrows it — and the choice is recorded with the
measurement that decided it.

## Acceptance

`cargo test -p mandate-federation --locked` exits 0 with the case below green, red before the change.
The 12,168-decision sweep the parent story used is re-run and its account of what moved is written
down.

## Out of scope

`folded` itself, which agrees on names and is not a general spelling-equivalence. Percent-encoded and
`inet_aton` spellings, which the parent story recorded as residue: refusing those widens the guard
rather than agreeing which host it was asked about.

## The case the adversary wrote, kept here because nothing else keeps it

Red against `af2982c`. It was not committed — one red case takes a suite's exit status for everything
— and its worktree does not outlive the wave.

```rust
/// `folded` is not total: the guard still folds different spellings at different sites.
///
/// The story's class is *"two checks over one host that fold different spellings will
/// disagree"*. The correction folds the trailing dot at all three sites and stops there,
/// but `literal_address` and `loopback` read the host through `IpAddr::from_str`, which
/// collapses every spelling of one address, while the issuer's own-origin comparison is
/// string equality, which collapses none of them. The module's own table says so in as
/// many words — *"IPv6 bracket forms, zero-compression and the IPv4-mapped forms are all
/// one literal to `IpAddr`"* (`tests/verifier_real.rs:2374-2376` region) — and then lists
/// `[::1]`, `[0:0:0:0:0:0:0:1]` and `[0:0::0:1]` as three rows.
///
/// So a loopback issuer whose discovery document spells its own host a second valid way
/// gets two answers for one host, which is the property
/// `a_trailing_dot_does_not_change_what_the_jwks_destination_guard_answers` is named for,
/// asked about a spelling other than the trailing dot. The disagreement fails closed here
/// — a refusal, not an admission — which is why this is a smaller finding than pass 1's.
///
/// Asserted as an equality rather than as an admission, because which way it should be
/// resolved is the unit's call and not this case's: folding `IpAddr` at the own-origin
/// comparison widens it, and refusing every literal own-origin narrows it.
#[test]
fn one_host_gets_one_answer_at_the_issuers_own_origin_however_the_literal_is_spelled() {
    let no_hosts_listed: [String; 0] = [];

    for (canonical, second_spelling) in [
        ("[::1]", "[0:0:0:0:0:0:0:1]"),
        ("[::1]", "[0:0::0:1]"),
        ("[0:0:0:0:0:0:0:1]", "[::1]"),
    ] {
        for scheme in ["http", "https"] {
            let issuer = Issuer::new(format!("{scheme}://{canonical}:8443"));

            let spelled_alike = UreqJwks::admits(
                &issuer,
                &format!("{scheme}://{canonical}:8443/jwks"),
                &no_hosts_listed,
            );
            let spelled_otherwise = UreqJwks::admits(
                &issuer,
                &format!("{scheme}://{second_spelling}:8443/jwks"),
                &no_hosts_listed,
            );

            assert_eq!(
                spelled_alike, spelled_otherwise,
                "issuer {scheme}://{canonical}:8443: {canonical} and {second_spelling} \
                 are one address and the guard gave them two answers: \
                 alike={spelled_alike}, otherwise={spelled_otherwise}"
            );
        }
    }
}

```

## Scope

Derived 2026-09-23 by `aep-drive:story-scoper` at `92fc026`. Every line is **cited** (read from the story or the tree) or **inferred**.

- **Primary surface:** `crates/mandate-federation` — cited
- **Files:** `crates/mandate-federation/src/verifier_real.rs:345` (own-origin comparison in `UreqJwks::admits`) — cited
- **Files:** `crates/mandate-federation/tests/verifier_real.rs` (the red case, beside `a_trailing_dot_does_not_change_what_the_jwks_destination_guard_answers`) — inferred
- **Also likely:** `crates/mandate-federation/tests/adversary_host_spelling_2.rs` (the 12,168-decision sweep that is re-run) — cited, its own doc at `:14`
- **Symbols:** `UreqJwks::admits`, `folded`, `literal_address`, `loopback`, `origin` — cited
- **Confidence:** high
- **Would collide with:** any unit touching the JWKS destination guard in `verifier_real.rs`
- **Not established:** where the account of what the sweep moved is written

## Scope — confirmed at close

From the implementor's confirmation table, wave I–K (`docs/plans/2026-09-23-waves-i-j-k-execution.md`). Corrections to the `## Scope` above are kept visible here, not deleted there.

folded-is-not-an-address-fold
- `src/verifier_real.rs` own-origin comparison, and `origin` itself in the correction — confirmed
- `tests/verifier_real.rs` — confirmed
- `tests/adversary_host_spelling_2.rs` as "the sweep that is re-run" — wrong: it only describes the sweep; the code was never committed and was rebuilt in scratch
