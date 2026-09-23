---
format: aep.planning-md/1
id: story:control-plane-loopback-fold
kind: story
status: active
title: The control-plane's own loopback fold asks a different question from the one beside it
relations:
- decomposes: epic:hardening
- serves: vision:mandate
scope:
- confidence: cited
  path: services/control-plane/src/adapters.rs
- confidence: inferred
  path: services/control-plane/tests/adapters.rs
- confidence: cited
  path: services/control-plane/tests/adversary_host_spelling_1.rs
revision: 7
---
# The control-plane's own loopback fold asks a different question from the one beside it

## Why

`services/control-plane/src/adapters.rs:626` holds `is_loopback`, the guard deciding whether a
deployment's own issuer may be plaintext. `Configuration::checked` (`:573`) calls it on every
deployment build. It is the sibling of `mandate-federation`'s JWKS destination guard, and it folds
the host differently in two ways that were measured on 2026-09-22 while `story:host-spelling-folded`
was being attacked.

**It splits the authority on its last `:`, so userinfo defeats it.** In
`http://localhost:80@evil.example` the "port" is `80@evil.example` and the "host" is `localhost`, so
`Configuration::checked` answers `Ok` for a plaintext issuer identifier naming `evil.example`. The
guard beside it, `origin` (`crates/mandate-federation/src/verifier_real.rs:436`), refuses any `@`
outright. Measured by a case the adversary wrote, which was red:

```
panicked at services/control-plane/tests/adversary_host_spelling_1.rs:66:9:
assertion `left == right` failed: http://localhost:80@evil.example is a plaintext issuer identifier
naming evil.example, and `http` is admitted on the loopback and nowhere else
  left: None
 right: Some(Issuer(SchemeUnadmitted))
```

**It folds no trailing dot, and parses only `Ipv4Addr`.** `http://localhost.` and `http://127.0.0.1.`
are `SchemeUnadmitted` — fail-closed, so not the same severity — and `[::1]` is compared as a string
rather than parsed. This is the same class `story:host-spelling-folded` closed on the federation
side: *two checks over one host that fold different spellings will disagree, and the disagreement is
what gets through.*

**What reaches it, stated plainly: nothing was found.** The string is the operator's own issuer,
supplied at deployment build. No fixture, workflow or route was found that produces it, and it is not
attacker-controlled. The adversary recorded the finding `INFEASIBLE` on that ground. What is wrong is
that one guard refuses `@` and its sibling does not, in a codebase whose whole argument is that a
condition is decided in one place.

## What this story delivers

`is_loopback` answers the same question as `origin`: it refuses an authority carrying `@` rather than
reading a host out of it, and it folds the host the way the federation guard now does before
comparing. The adversary's case moves into this repository as a committed regression case.

## Acceptance

`cargo test -p mandate-control-plane --locked` exits 0 with a case in which
`Configuration::checked("http://localhost:80@evil.example")` is refused `SchemeUnadmitted`, red
before the change and green after. Every existing plaintext-loopback case stays green.

## Out of scope

The federation guard, which `story:host-spelling-folded` already moved. Any change to which schemes
are admitted, or to what a conforming issuer identifier is.

## The case the adversary wrote, kept here because nothing else keeps it

Written during wave H's attack on `story:host-spelling-folded`, red against the tree at that
time. It was not committed — a red case takes a suite's exit status for everything — and its
worktree is gone, so the text lives here. It is this story's regression case.

```rust
//! Adversary pass 1 over the `host-spelling-folded` unit of `story:host-spelling-folded`
//! (commit `d6b1876`), on the *other* guard that decides a host over plaintext.
//!
//! Nothing here changes an implementation file and nothing here opens a socket:
//! [`Configuration::checked`] decides a string.
//!
//! # Why this file is beside the unit under attack
//!
//! The story's finding is a class, not an instance: *two checks over one host that fold
//! different spellings will disagree, and the disagreement is what gets through.* This
//! repository has **two** guards that decide whether a host over plaintext is the loopback
//! interface, and they are two different parsers over one authority:
//!
//! | guard | userinfo | source |
//! |---|---|---|
//! | `UreqJwks::admits` → `origin` | **refused** — `if authority.contains('@') { return None }` | `crates/mandate-federation/src/verifier_real.rs:436` |
//! | `Configuration::checked` → `is_loopback` | **not looked at** — the last `:` splits a "port" off and whatever precedes it is the host | `services/control-plane/src/adapters.rs:626` |
//!
//! `is_loopback` is the whole of the reason a plaintext issuer is admitted at all
//! (`services/control-plane/src/adapters.rs:601`). Its own documentation says it answers
//! "whether an authority names this host"; `Configuration::checked`'s says `http` is
//! admitted "on the loopback ... for a deployment running on a developer's own machine";
//! and `services/control-plane/tests/adapters.rs:609-610` states the bound as "`http` on
//! the loopback is admitted for a deployment a developer runs on their own machine, **and
//! nowhere else**."
//!
//! This is `pre-existing`: the unit's diff touches two files and neither is this one. It
//! is reported here because it is the same defect class the story is about, one guard
//! over.

use mandate_control_plane::adapters::{Configuration, ConfigurationRefused, IssuerRefused};
use mandate_sts::code::CodeLifetime;
use mandate_types::Duration;

/// The configuration the deployment builds from, with only the issuer varying.
fn configured(issuer: &str) -> Configuration {
    Configuration {
        issuer: issuer.to_owned(),
        code_lifetime: CodeLifetime::new(Duration::new("PT5M")),
        session_lifetime: Duration::new("PT8H"),
        keys: Vec::new(),
    }
}

/// A plaintext issuer whose authority carries userinfo is not on the loopback, and the
/// guard that exists to say so does not look at the userinfo.
///
/// `is_loopback` (`services/control-plane/src/adapters.rs:626`) splits the authority on its
/// **last** `:` and calls whatever precedes it the host. In
/// `localhost:80@evil.example` the last `:` is the one inside the userinfo, so the "port"
/// is `80@evil.example` and the "host" is `localhost` — and the guard answers that a
/// plaintext issuer naming `evil.example` is the developer's own machine.
///
/// The sibling guard in the crate this wave's unit changed does look: `origin`
/// (`crates/mandate-federation/src/verifier_real.rs:436`) refuses any authority carrying
/// `@` outright, "because it exists here only to make a URI *look* like it names one host
/// while naming another". Two parsers, one authority, two answers — which is the class
/// `story:host-spelling-folded` reports, one guard over from where it fixed it.
#[test]
fn a_plaintext_issuer_naming_another_host_behind_userinfo_is_not_the_loopback() {
    for named_elsewhere in [
        "http://localhost:80@evil.example",
        "http://localhost:8080@evil.example",
        "http://127.0.0.1:80@evil.example",
    ] {
        assert_eq!(
            configured(named_elsewhere).checked().err(),
            Some(ConfigurationRefused::Issuer(
                IssuerRefused::SchemeUnadmitted
            )),
            "{named_elsewhere} is a plaintext issuer identifier naming evil.example, and \
             `http` is admitted on the loopback and nowhere else"
        );
    }
}
```

## Scope

Derived 2026-09-23 by `aep-drive:story-scoper` at `92fc026`. Every line is **cited** or **inferred**.

- **Primary surface:** `services/control-plane` — cited
- **Files:** `services/control-plane/src/adapters.rs:626` (`is_loopback`), called from `normalised_issuer` `:594` — cited
- **Files:** `services/control-plane/tests/adversary_host_spelling_1.rs` (new) — cited
- **Also likely:** `services/control-plane/tests/adapters.rs` (existing plaintext-loopback cases stay green) — inferred
- **Symbols:** `is_loopback`, `normalised_issuer`, `Configuration::checked`, `IssuerRefused::SchemeUnadmitted` — cited
- **Confidence:** high
- **Would collide with:** any unit touching `adapters.rs`
