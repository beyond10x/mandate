//! Adversary pass 2 over `story:control-plane-loopback-fold` (commit `bd882e1` on `9a68796`).
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

/// `is_loopback`'s comment says "A port that is spelled must parse", and RFC 3986 3.2.3
/// spells a port `*DIGIT`. The check is `str::parse::<u16>`, which accepts a leading `+`,
/// so an authority no URI parser reads is admitted as a plaintext loopback issuer and
/// published verbatim as this deployment's issuer identifier.
#[test]
fn a_plaintext_port_that_is_not_all_digits_is_not_admitted() {
    let admitted: Vec<&str> = [
        "http://localhost:+80",
        "http://127.0.0.1:+8080",
        "http://[::1]:+80",
    ]
    .into_iter()
    .filter(|issuer| !refused(issuer))
    .collect();
    assert!(
        admitted.is_empty(),
        "RFC 3986 3.2.3: port = *DIGIT; admitted as plaintext loopback: {admitted:?}"
    );
}

/// The correction must not refuse a loopback issuer the repository itself uses: the
/// literals in `tests/adapters.rs`, the `format!("http://{address}")` issuers of
/// `tests/end_to_end.rs` and `tests/adversary_login_road.rs` (a `SocketAddr`, so
/// `[::1]:port` when bound on IPv6), and the absolute and path-carrying spellings.
#[test]
fn every_loopback_issuer_the_repository_uses_is_still_admitted() {
    let loopback_v6 = std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 41_234));
    let loopback_v4 = std::net::SocketAddr::from(([127, 0, 0, 1], 41_234));
    let formatted_v6 = format!("http://{loopback_v6}");
    let formatted_v4 = format!("http://{loopback_v4}");
    let refused_legit: Vec<&str> = [
        "http://127.0.0.1:8080",
        "http://localhost:8080",
        "http://[::1]:8080",
        "http://localhost",
        "http://localhost/",
        "http://127.0.0.1/tenant",
        "http://[::1]/",
        "http://[0:0:0:0:0:0:0:1]:8080",
        "http://LOCALHOST:8080",
        "HTTP://localhost:8080",
        "http://localhost.:8080",
        "http://127.255.255.254:1",
        "http://localhost:",
        formatted_v6.as_str(),
        formatted_v4.as_str(),
    ]
    .into_iter()
    .filter(|issuer| configured(issuer).checked().is_err())
    .collect();
    assert!(
        refused_legit.is_empty(),
        "loopback issuers refused: {refused_legit:?}"
    );
}
