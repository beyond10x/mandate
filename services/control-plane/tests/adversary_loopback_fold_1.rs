//! Adversary pass 1 over `story:control-plane-loopback-fold` (commit `b8c25f3` on `9a68796`).
//!
//! Nothing here changes an implementation file and nothing here opens a socket:
//! [`Configuration::checked`] decides a string.

use mandate_control_plane::adapters::{Configuration, ConfigurationRefused, IssuerRefused};
use mandate_sts::code::CodeLifetime;
use mandate_types::Duration;

fn configured(issuer: &str) -> Configuration {
    Configuration {
        issuer: issuer.to_owned(),
        code_lifetime: CodeLifetime::new(Duration::new("PT5M")),
        session_lifetime: Duration::new("PT8H"),
        keys: Vec::new(),
    }
}

fn refused(issuer: &str) -> bool {
    configured(issuer).checked().err()
        == Some(ConfigurationRefused::Issuer(
            IssuerRefused::SchemeUnadmitted,
        ))
}

/// `is_loopback`'s own comment says "An IPv6 literal carries colons of its own and is
/// bracketed", and RFC 3986 3.2.2 agrees: `host = IP-literal / IPv4address / reg-name`,
/// where an IP-literal is `[` IPv6address `]` and a reg-name carries no `:`. The fold now
/// reads the unbracketed tail through `rsplit_once(':')` and then `IpAddr::from_str`, and
/// reads a bracketed host through the same parse, so it admits as plaintext-on-loopback
/// authorities that are no URI host at all. Every one of these was `SchemeUnadmitted` at
/// the base, where the host was compared to `"[::1]"` as a string and parsed as IPv4 only.
#[test]
fn a_plaintext_authority_that_is_no_rfc3986_host_is_not_admitted() {
    let admitted: Vec<&str> = [
        "http://::1:8080",
        "http://::1:",
        "http://0::1:8080",
        "http://[localhost]:8080",
        "http://[127.0.0.1]",
        "http://[::1.]:8080",
    ]
    .into_iter()
    .filter(|issuer| !refused(issuer))
    .collect();
    assert!(
        admitted.is_empty(),
        "admitted as a plaintext loopback issuer, yet none is an RFC 3986 host: {admitted:?}"
    );
}

/// A trailing dot is the absolute form of a name; two of them are a name with an empty
/// label, which is no spelling of anything (the federation `folded` doc says so of `..`).
/// `trim_end_matches('.')` strips every one, so `localhost..` is admitted as `localhost`.
#[test]
fn a_plaintext_host_with_an_empty_trailing_label_is_not_admitted() {
    let admitted: Vec<&str> = ["http://localhost..:8080", "http://127.0.0.1..."]
        .into_iter()
        .filter(|issuer| !refused(issuer))
        .collect();
    assert!(
        admitted.is_empty(),
        "admitted as a plaintext loopback issuer with an empty label: {admitted:?}"
    );
}

/// The spellings the brief named, none of which names the loopback. Green probes, kept so a
/// later change to the fold is measured against them.
#[test]
fn no_spelling_of_another_host_is_admitted_over_plaintext() {
    let admitted: Vec<&str> = [
        "http://localhost@evil.example",
        "http://LOCALHOST:80@EVIL.EXAMPLE",
        "http://@localhost",
        "http://evil.example@localhost",
        "http://localhost%40evil.example",
        "http://localhost:80%40evil.example",
        "http://%6c%6f%63%61%6c%68%6f%73%74",
        "http://localhost%2e",
        "http://[::ffff:127.0.0.1]",
        "http://[::127.0.0.1]",
        "http://[::ffff:7f00:1]:80",
        "http://0.0.0.0",
        "http://[::]",
        "http://0",
        "http://127.1",
        "http://2130706433",
        "http://0x7f.0.0.1",
        "http://[::1%25eth0]",
        "http://[::1%eth0]:80",
        "http://",
        "http://:8080",
        "http://[]",
        "http://[]:80",
        "http://.localhost",
        "http://localhost.evil.example.",
        "http://localhost:80:80",
        "http://localhost:-1",
        "http://localhost:65536",
        "http://localhost\\@evil.example",
        "http://localhost\\.evil.example",
        "http://local host",
        "http://x[::1]",
        "http://[::1]]",
        "http://[::1]:80]",
    ]
    .into_iter()
    .filter(|issuer| !refused(issuer))
    .collect();
    assert!(admitted.is_empty(), "admitted over plaintext: {admitted:?}");
}
