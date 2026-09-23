//! Adversary pass 2 on `story:folded-is-not-an-address-fold`, against `4783e6a`.
//!
//! The correction's comment in `origin` says "Inside brackets there is an IPv6 address and
//! nothing else", and the class case it added is named
//! `every_authority_the_guard_admits_is_the_port_and_address_the_fetcher_reads`. The code
//! checks `folded(host).parse::<Ipv6Addr>()`, so `[::1.]` and `[::1..]` pass the grammar,
//! and the class case strips trailing dots from the host `ureq` reads before comparing,
//! so it cannot see what the fetcher does with them.
//!
//! What the fetcher does is `ureq`'s `DefaultResolver`: it formats
//! `"{authority.host()}:{port}"` and hands that to `std::net::ToSocketAddrs`. For a
//! bracketed host with a trailing dot that string is `[::1.]:80`, which is neither a
//! `SocketAddr` nor a name a resolver answers.
//!
//! The second case is the real-world shapes an operator configures, asked of the guard,
//! so that the correction's narrower grammar is shown not to refuse one of them.

use std::net::{IpAddr, ToSocketAddrs};

use mandate_federation::verifier_real::UreqJwks;
use mandate_types::Issuer;

/// The socket addresses `ureq`'s `DefaultResolver` resolves for `uri`, formed exactly as
/// `DefaultResolver::host_and_port` forms them.
fn resolved_by_the_fetcher(uri: &str) -> Result<Vec<IpAddr>, String> {
    let parsed = uri
        .parse::<ureq::http::Uri>()
        .map_err(|error| format!("http::Uri refuses it: {error}"))?;
    let default = if parsed.scheme_str() == Some("https") {
        443
    } else {
        80
    };
    let port = parsed.port_u16().unwrap_or(default);
    let host = parsed.host().ok_or("no host")?;
    let addr = format!("{host}:{port}");
    addr.to_socket_addrs()
        .map(|addresses| addresses.map(|address| address.ip()).collect())
        .map_err(|error| format!("{addr} does not resolve: {error}"))
}

/// Every bracketed spelling the guard admits as an IPv6 issuer's own origin is one the
/// fetcher resolves to that address.
#[test]
fn a_bracketed_literal_the_guard_admits_as_the_issuers_own_is_one_the_fetcher_resolves() {
    let mut disagreements = Vec::new();
    for (issuer, address) in [
        ("http://[::1]", "::1"),
        ("http://[::1]:8443", "::1"),
        ("https://[2001:db8::7]", "2001:db8::7"),
    ] {
        let issuer = Issuer::new(issuer);
        let scheme = issuer.as_str().split_once("://").expect("scheme").0;
        let port = issuer
            .as_str()
            .rsplit_once("]:")
            .map(|(_, port)| format!(":{port}"))
            .unwrap_or_default();
        let expected: IpAddr = address.parse().expect("an address");
        for spelling in [
            format!("[{address}]"),
            format!("[{address}.]"),
            format!("[{address}..]"),
        ] {
            let uri = format!("{scheme}://{spelling}{port}/jwks");
            if !UreqJwks::admits(&issuer, &uri, &[]) {
                continue;
            }
            match resolved_by_the_fetcher(&uri) {
                Ok(addresses) if addresses.contains(&expected) => {}
                outcome => disagreements.push(format!(
                    "issuer {}: the guard admitted {uri} as {expected}, and the fetcher \
                     reads it as {outcome:?}",
                    issuer.as_str()
                )),
            }
        }
    }
    assert!(
        disagreements.is_empty(),
        "admitted by the guard, not the address the fetcher resolves:\n{}",
        disagreements.join("\n")
    );
}

/// The issuer and `jwks_uri` shapes real IdPs publish, and the ones this repository's
/// tests and docs use, are still admitted under the correction's grammar.
#[test]
fn the_shapes_real_identity_providers_publish_are_still_admitted() {
    let listed = |hosts: &[&str]| hosts.iter().map(|h| (*h).to_owned()).collect::<Vec<_>>();
    for (issuer, jwks_uri, hosts) in [
        (
            "https://accounts.google.com",
            "https://www.googleapis.com/oauth2/v3/certs",
            listed(&["www.googleapis.com"]),
        ),
        (
            "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
            "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/discovery/v2.0/keys",
            listed(&[]),
        ),
        (
            "https://dev-123456.okta.com/oauth2/default",
            "https://dev-123456.okta.com/oauth2/default/v1/keys?client_id=0oa1",
            listed(&[]),
        ),
        (
            "https://tenant.eu.auth0.com/",
            "https://tenant.eu.auth0.com/.well-known/jwks.json",
            listed(&[]),
        ),
        (
            "https://kc.example:8443/realms/acme",
            "https://kc.example:8443/realms/acme/protocol/openid-connect/certs",
            listed(&[]),
        ),
        (
            "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_AbC123",
            "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_AbC123/.well-known/jwks.json",
            listed(&[]),
        ),
        (
            "https://idp.example",
            "https://keys.idp.example:8443/jwks",
            listed(&["keys.idp.example:8443"]),
        ),
        (
            "https://idp.example",
            "https://idp.example:443/jwks",
            listed(&[]),
        ),
        (
            "https://IDP.example",
            "https://idp.example./jwks",
            listed(&[]),
        ),
        (
            "http://127.0.0.1:41234",
            "http://127.0.0.1:41234/jwks",
            listed(&[]),
        ),
        ("http://[::1]:41234", "http://[::1]:41234/jwks", listed(&[])),
        (
            "http://localhost:8080",
            "http://localhost:8080/jwks",
            listed(&[]),
        ),
        (
            "https://my_idp.internal",
            "https://my_idp.internal/jwks",
            listed(&[]),
        ),
    ] {
        assert!(
            UreqJwks::admits(&Issuer::new(issuer), jwks_uri, &hosts),
            "issuer {issuer}: the legitimate key set {jwks_uri} (listed {hosts:?}) is refused"
        );
    }
}
