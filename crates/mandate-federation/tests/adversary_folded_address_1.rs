//! Adversary pass 1 on `story:folded-is-not-an-address-fold`.
//!
//! The guard (`UreqJwks::admits`) and the fetcher (`ureq` over `http::Uri`) read the
//! authority of a `jwks_uri` with two different parsers, and they disagree on the port of
//! a bracketed literal followed by anything that is not `:`.
//!
//! `origin` splits `[::1]x:9999` at the first `]` and asks whether what follows starts
//! with `:`. It does not, so the port is "not spelled" and becomes the scheme's default.
//! `http::Authority::port` takes the last `:` in the authority, so `ureq` connects to
//! `[::1]:9999`. The guard says "the issuer's own origin, port 80"; the connection goes to
//! port 9999 on that host.
//!
//! The widening in this story multiplies the spellings that reach that disagreement:
//! at the base only the issuer's exact spelling did, now every spelling `IpAddr` reads as
//! the issuer's address does. The second case pins that half on its own, so it can be
//! told apart from the first when run against the base.

use std::io::Read;
use std::net::TcpListener;
use std::time::{Duration, Instant};

use mandate_federation::verifier_real::UreqJwks;
use mandate_types::Issuer;

/// Whether the shipped agent, asked for `url`, opens a connection to `listener`.
fn shipped_agent_reaches(listener: &TcpListener, url: &str) -> bool {
    listener
        .set_nonblocking(true)
        .expect("listener goes non-blocking");
    let agent = ureq::Agent::new_with_config(UreqJwks::hardened_config());
    let url = url.to_owned();
    let fetch = std::thread::spawn(move || {
        let _ = agent.get(&url).call();
    });
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut reached = false;
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                let mut buffer = [0_u8; 64];
                let _ = stream.read(&mut buffer);
                reached = true;
                break;
            }
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    drop(fetch);
    reached
}

fn assert_guard_and_fetcher_agree(issuer: &str, spelling: &str) {
    let listener = TcpListener::bind("[::1]:0").expect("bind the IPv6 loopback");
    let port = listener.local_addr().expect("bound address").port();
    assert_ne!(port, 80, "the listener must not sit on the default port");

    let uri = format!("http://{spelling}x:{port}/jwks");
    let admitted = UreqJwks::admits(&Issuer::new(issuer), &uri, &[]);
    let reached = shipped_agent_reaches(&listener, &uri);

    assert!(
        !(admitted && reached),
        "issuer {issuer} (port 80): the guard admitted {uri} as the issuer's own origin \
         (admitted={admitted}), and the shipped agent connected to port {port} on it \
         (reached={reached}) — the guard and the fetcher read two different ports"
    );
}

/// The issuer's exact spelling. Nothing in the story's diff reaches this; it is here so
/// the second case can be attributed.
#[test]
fn a_bracketed_literal_with_trailing_junk_is_the_default_port_to_the_guard_and_the_spelled_one_to_ureq()
 {
    assert_guard_and_fetcher_agree("http://[::1]", "[::1]");
}

/// A second valid spelling of the issuer's address — admitted only since the widening.
#[test]
fn the_widening_admits_a_second_spelling_of_the_issuer_that_ureq_fetches_from_another_port() {
    assert_guard_and_fetcher_agree("http://[::1]", "[0:0::0:1]");
}

/// The same shape under `https`, asked of the guard alone: a routable IPv6 issuer on the
/// default port admits a destination the fetcher would open on port 22 of that host.
#[test]
fn an_https_literal_issuer_admits_a_destination_whose_spelled_port_the_guard_never_reads() {
    let issuer = Issuer::new("https://[2001:db8::7]");
    for destination in [
        "https://[2001:db8::7]x:22/jwks",
        "https://[2001:0db8:0:0:0:0:0:7]x:22/jwks",
    ] {
        assert!(
            !UreqJwks::admits(&issuer, destination, &[]),
            "issuer https://[2001:db8::7] (port 443): {destination} names port 22 to \
             `http::Authority::port` and was admitted as the issuer's own origin"
        );
    }
}
