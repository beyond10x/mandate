//! Adversary pass 1 over the `host-spelling-folded` unit of `story:host-spelling-folded`
//! (commit `d6b1876`), on the *other* guard that decides a host over plaintext, kept as the
//! regression case of `story:control-plane-loopback-fold`.
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

/// The loopback spellings the federation guard folds are the loopback here too.
///
/// `folded` (`crates/mandate-federation/src/verifier_real.rs`) strips one trailing dot from
/// a name, and `loopback` reads the host through `IpAddr::from_str`, so `localhost.` and
/// every spelling of `::1` are one interface to it. `127.0.0.1.` is none: an address has no
/// absolute form, and both guards refuse it. This guard compared `[::1]` as a string
/// and parsed only IPv4, so it answered a different question about the same host.
#[test]
fn a_plaintext_issuer_spelling_the_loopback_another_way_is_the_loopback() {
    for admitted in [
        "http://localhost.:8080",
        "http://[0:0:0:0:0:0:0:1]:8080",
        "http://[0::1]",
    ] {
        assert!(
            configured(admitted).checked().is_ok(),
            "{admitted} names the loopback interface, as the federation guard folds it"
        );
    }
}

/// A plaintext authority whose port does not parse is not decided to be the loopback.
///
/// `origin` refuses an authority whose spelled port does not parse, because the host it
/// would read is a guess. Neither is a name that only resembles the loopback admitted.
#[test]
fn a_plaintext_issuer_this_guard_would_have_to_guess_about_is_refused() {
    for refused in [
        "http://localhost:80x",
        "http://127.0.0.1:99999",
        "http://[::1]x",
        "http://[::2]:8080",
        "http://.",
        "http://127.0.0.1.:8080",
        "http://127.0.0.1.",
        "http://localhost.evil.example",
        "http://127.0.0.1.evil.example",
    ] {
        assert_eq!(
            configured(refused).checked().err(),
            Some(ConfigurationRefused::Issuer(
                IssuerRefused::SchemeUnadmitted
            )),
            "{refused} is not a plaintext issuer on the loopback"
        );
    }
}
