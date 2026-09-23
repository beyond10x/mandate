//! Adversary pass 2 on `story:federation-guard-trailing-dots` and
//! `story:bracketed-literal-trailing-dot`, against `edfc215` over `bde627b`.
//!
//! Nothing here changes an implementation file. Resolution is asked of
//! `std::net::ToSocketAddrs` exactly as `ureq`'s `DefaultResolver` asks it, and no socket
//! is opened. Resolution results depend on this machine's glibc resolver.

use std::net::{IpAddr, ToSocketAddrs};

use mandate_federation::verifier_real::UreqJwks;
use mandate_types::Issuer;

/// The addresses `ureq`'s `DefaultResolver` resolves for `uri`, formed as
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

/// The control-plane guard's `is_loopback` (`services/control-plane/src/adapters.rs` at
/// `edfc215`), transcribed line for line.
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

/// The correction's own rule — "an address has no absolute form … a host that reads as an
/// address only once its dot is folded is refused" — asked of the IPv4 spellings the
/// resolver reads as an address and `IpAddr::from_str` does not: `127.1`, `2130706433`,
/// `0x7f.1`. Undotted, glibc's `inet_aton` reads each as `127.0.0.1`; dotted, it reads
/// none of them and the name lookup fails, exactly as for `127.0.0.1.`. The guard decides
/// "address" with Rust's parser, so each dotted spelling is a name to it, folded, and
/// admitted as the issuer's own origin.
#[test]
fn a_numeric_shorthand_address_with_a_trailing_dot_is_admitted_only_if_the_fetcher_reaches_it() {
    let no_hosts_listed: [String; 0] = [];
    let loopback: IpAddr = "127.0.0.1".parse().expect("an address");
    let mut unfetchable = Vec::new();
    for host in ["127.1", "2130706433", "0x7f.1", "0x7f000001"] {
        for issuer_spelling in [host.to_owned(), format!("{host}.")] {
            let issuer = format!("https://{issuer_spelling}");
            let destination = format!("https://{host}./jwks");
            let admitted = UreqJwks::admits(
                &Issuer::new(issuer.as_str()),
                &destination,
                &no_hosts_listed,
            );
            let resolved = resolved_by_the_fetcher(&destination);
            if admitted && !resolved.as_ref().is_ok_and(|all| all.contains(&loopback)) {
                unfetchable.push(format!("{issuer} -> {destination}: {resolved:?}"));
            }
        }
    }
    assert!(
        unfetchable.is_empty(),
        "admitted by the guard, and the fetcher does not reach the address: {unfetchable:#?}"
    );
}

/// Both guards give one loopback answer for every spelling of both corpora — dots, empty
/// labels, IPv6 forms, ports — except the decided `localdomain` class; and `localhost.`
/// is admitted by both and resolves.
#[test]
fn the_two_guards_agree_on_every_spelling_but_the_localdomain_class() {
    let no_hosts_listed: [String; 0] = [];
    let hosts = [
        "localhost",
        "LocalHost",
        "127.0.0.1",
        "127.0.0.2",
        "127.255.255.254",
        "127.1",
        "0.0.0.0",
        "idp.example",
        "localhost.localhost",
        "local..host",
        "[::1]",
        "[0::1]",
        "[0:0:0:0:0:0:0:1]",
        "[::0.0.0.1]",
        "[::ffff:127.0.0.1]",
        "[::1%25lo]",
        "[v1.x]",
        "[::2]",
        "[::1.]",
        "[::1..]",
        "[.::1]",
        "[::1]]",
        "[[::1]]",
        "::1",
        "",
    ];
    let mut disagreements = Vec::new();
    for base in hosts {
        let bracketed = base.starts_with('[');
        let mut spellings = vec![base.to_owned()];
        if !bracketed {
            for affix in [".", "..", "..."] {
                spellings.push(format!("{base}{affix}"));
                spellings.push(format!("{affix}{base}"));
            }
            spellings.push(format!(".{base}."));
        }
        for spelling in spellings {
            for port in ["", ":", ":0", ":8080", ":65535", ":65536", ":+80", ":80:"] {
                let authority = format!("{spelling}{port}");
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
    }
    assert!(disagreements.is_empty(), "{disagreements:#?}");

    for (issuer, destination) in [
        ("http://localhost", "http://localhost./jwks"),
        ("http://localhost.", "http://localhost/jwks"),
        ("http://localhost.:8080", "http://localhost.:8080/jwks"),
    ] {
        let authority = issuer.trim_start_matches("http://");
        assert!(
            UreqJwks::admits(&Issuer::new(issuer), destination, &no_hosts_listed)
                && control_plane_is_loopback(authority),
            "{issuer} -> {destination}: localhost. is the loopback to both guards"
        );
        let resolved = resolved_by_the_fetcher(destination);
        assert!(
            resolved
                .as_ref()
                .is_ok_and(|all| !all.is_empty() && all.iter().all(IpAddr::is_loopback)),
            "{destination}: {resolved:?}"
        );
    }
}
