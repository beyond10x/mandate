//! Adversary pass 1 on `story:federation-guard-trailing-dots` and
//! `story:bracketed-literal-trailing-dot`, against `4f268d7` over `bde627b`.
//!
//! Nothing here changes an implementation file. Resolution is asked of
//! `std::net::ToSocketAddrs` exactly as `ureq`'s `DefaultResolver` asks it — the helper
//! is the one `tests/adversary_folded_address_2.rs` uses — and no socket is opened.

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

/// The control-plane guard's `is_loopback` (`services/control-plane/src/adapters.rs`),
/// transcribed line for line; the brief names it the model this guard is asked to match.
fn control_plane_is_loopback(authority: &str) -> bool {
    if authority.contains('@') {
        return false;
    }
    let (host, bracketed, port) = match authority.split_once(']') {
        Some((inside, after)) => match (inside.strip_prefix('['), after) {
            (Some(host), "") => (host, true, None),
            (Some(host), _) => match after.strip_prefix(':') {
                Some(port) => (host, true, Some(port)),
                None => return false,
            },
            (None, _) => return false,
        },
        None => match authority.rsplit_once(':') {
            Some((host, port)) => (host, false, Some(port)),
            None => (authority, false, None),
        },
    };
    if let Some(spelled) = port.filter(|port| !port.is_empty())
        && (!spelled.bytes().all(|byte| byte.is_ascii_digit()) || spelled.parse::<u16>().is_err())
    {
        return false;
    }
    if bracketed {
        return host
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|address| address.is_loopback());
    }
    if host.contains(':') {
        return false;
    }
    let name = match host.strip_suffix('.') {
        Some(name) if !name.is_empty() => name,
        _ => host,
    };
    name.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|address| address.is_loopback())
}

/// The acceptance of `story:bracketed-literal-trailing-dot` — "the guard answers what the
/// fetcher does: either it refuses the destination, or the fetcher reaches" the address —
/// asked of the unbracketed IPv4 literal with one trailing dot, which the change still
/// folds and admits, and which the class case in `tests/verifier_real.rs` still folds
/// before comparing (`read.strip_suffix('.')`), so it cannot see what the fetcher does.
#[test]
fn an_ipv4_literal_with_one_trailing_dot_is_admitted_only_if_the_fetcher_reaches_it() {
    let no_hosts_listed: [String; 0] = [];
    let mut unfetchable = Vec::new();
    for (issuer, destination, address) in [
        ("http://127.0.0.1", "http://127.0.0.1./jwks", "127.0.0.1"),
        (
            "http://127.0.0.1:8080",
            "http://127.0.0.1.:8080/jwks",
            "127.0.0.1",
        ),
        ("http://127.0.0.1.", "http://127.0.0.1./jwks", "127.0.0.1"),
        ("http://127.0.0.2", "http://127.0.0.2./jwks", "127.0.0.2"),
        (
            "https://127.0.0.1:8443",
            "https://127.0.0.1.:8443/jwks",
            "127.0.0.1",
        ),
    ] {
        let expected: IpAddr = address.parse().expect("an address");
        let admitted = UreqJwks::admits(&Issuer::new(issuer), destination, &no_hosts_listed);
        let resolved = resolved_by_the_fetcher(destination);
        if admitted && !resolved.as_ref().is_ok_and(|all| all.contains(&expected)) {
            unfetchable.push(format!("{issuer} -> {destination}: {resolved:?}"));
        }
    }
    assert!(
        unfetchable.is_empty(),
        "admitted by the guard, and the fetcher does not reach the address: {unfetchable:#?}"
    );
}

/// The control: a *name* with one trailing dot is admitted and the fetcher resolves it,
/// which is the premise `story:bracketed-literal-trailing-dot` puts out of scope.
#[test]
fn a_loopback_name_with_one_trailing_dot_is_admitted_and_the_fetcher_resolves_it() {
    let no_hosts_listed: [String; 0] = [];
    let destination = "http://localhost./jwks";
    assert!(UreqJwks::admits(
        &Issuer::new("http://localhost"),
        destination,
        &no_hosts_listed
    ));
    let resolved = resolved_by_the_fetcher(destination);
    assert!(
        resolved
            .as_ref()
            .is_ok_and(|all| all.iter().all(IpAddr::is_loopback)),
        "{destination}: {resolved:?}"
    );
}

/// `origin` now refuses an empty label at the end of a name because "it is no spelling of
/// anything and the resolver refuses it". An empty label in the middle, or at the start,
/// is the same thing, and `loopback`'s `ends_with(".localdomain")` makes one of them the
/// loopback interface, so a plaintext issuer spelled that way is admitted at its own
/// origin.
#[test]
fn a_plaintext_name_with_an_empty_label_elsewhere_is_admitted_only_if_the_fetcher_reaches_it() {
    let no_hosts_listed: [String; 0] = [];
    let mut unfetchable = Vec::new();
    for host in [
        ".localdomain",
        "..localdomain",
        "keys..localdomain",
        ".localhost",
        "local..host",
        ".127.0.0.1",
    ] {
        let issuer = format!("http://{host}");
        let destination = format!("http://{host}/jwks");
        let admitted = UreqJwks::admits(&Issuer::new(&issuer), &destination, &no_hosts_listed);
        let resolved = resolved_by_the_fetcher(&destination);
        if admitted && resolved.is_err() {
            unfetchable.push(format!("{destination}: {resolved:?}"));
        }
    }
    assert!(
        unfetchable.is_empty(),
        "admitted as a plaintext loopback issuer's own origin, and the fetcher resolves \
         nothing: {unfetchable:#?}"
    );
}

/// The two guards over every dot spelling of the loopback: the federation guard admits a
/// plaintext issuer's own origin exactly when the host is the loopback interface, and the
/// control-plane guard's `is_loopback` says "so the two cannot disagree about one host".
#[test]
fn the_two_guards_agree_on_every_dot_spelling_of_the_loopback() {
    let no_hosts_listed: [String; 0] = [];
    let mut disagreements = Vec::new();
    for host in [
        "localhost",
        "localhost.",
        "localhost..",
        "localhost...",
        ".localhost",
        "..localhost",
        "local..host",
        "LOCALHOST.",
        "LOCALHOST..",
        "127.0.0.1",
        "127.0.0.1.",
        "127.0.0.1..",
        ".127.0.0.1",
        "127..0.0.1",
        "127.0.0.2.",
        "[::1]",
        "[::1.]",
        "[::1..]",
        "[.::1]",
        "[0:0:0:0:0:0:0:1.]",
        ".",
        "..",
    ] {
        for port in ["", ":", ":8080"] {
            let authority = format!("{host}{port}");
            let federation = UreqJwks::admits(
                &Issuer::new(format!("http://{authority}")),
                &format!("http://{authority}/jwks"),
                &no_hosts_listed,
            );
            let control_plane = control_plane_is_loopback(&authority);
            if federation != control_plane {
                disagreements.push(format!(
                    "{authority}: federation {federation}, control-plane {control_plane}"
                ));
            }
        }
    }
    assert!(disagreements.is_empty(), "{disagreements:#?}");
}

/// The two guards diverge over the `localdomain` class, and exactly there: the federation
/// guard's `loopback` counts `localhost.localdomain` and `keys.localdomain` as the loopback
/// interface, and the control-plane guard does not.
///
/// Decided, not a defect: wave J ruled that the control plane does not widen plaintext
/// issuer admission to the `localdomain` class (coordinator decision, correction round 1
/// of wave L unit L1). Opened as `the_two_guards_agree_on_the_localdomain_class`, which
/// asserted agreement; it now asserts the decided divergence, so either guard moving
/// turns it red.
#[test]
fn the_two_guards_diverge_on_the_localdomain_class_as_decided() {
    let no_hosts_listed: [String; 0] = [];
    let mut disagreements = Vec::new();
    for host in [
        "localhost.localdomain",
        "localhost.localdomain.",
        "keys.localdomain",
    ] {
        let federation = UreqJwks::admits(
            &Issuer::new(format!("http://{host}")),
            &format!("http://{host}/jwks"),
            &no_hosts_listed,
        );
        let control_plane = control_plane_is_loopback(host);
        if !federation || control_plane {
            disagreements.push(format!(
                "{host}: federation {federation}, control-plane {control_plane}; decided: \
                 federation true, control-plane false"
            ));
        }
    }
    assert!(disagreements.is_empty(), "{disagreements:#?}");
}
