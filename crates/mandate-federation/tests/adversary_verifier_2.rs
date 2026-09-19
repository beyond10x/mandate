//! Adversary pass 2 over the `federation-verifier` unit of
//! `story:signing-and-verification`, after correction round 1.
//!
//! Pass 1 is `tests/adversary_verifier_1.rs`. This file does not repeat it: every case
//! here drives a fix from round 1 as a *class* rather than as the one example that was
//! reported, or drives `verifier_real.rs` against its own documentation — the module's
//! doc table at `verifier_real.rs:17-28`, the `UreqJwks::admits` contract at
//! `verifier_real.rs:281-304`, and the key-cache contract at `verifier_real.rs:869-890`.
//! Nothing here changes an implementation file.
//!
//! No key is committed: every key is generated when the case runs. No case reaches the
//! network: the transport cases bind their own `TcpListener` on the loopback interface
//! and answer themselves.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use mandate_federation::FederationVerifier;
use mandate_federation::record::{ConnectionState, FederationConnection};
use mandate_federation::verifier_real::{
    AllowedAlgorithms, FixedClock, InMemoryJwks, JwksSource, RealVerifier, RefusalReason, UreqJwks,
};
use mandate_model::TenantResolutionRule;
use mandate_types::value::Uuid;
use mandate_types::{
    ClientId, CredentialProof, FederationConnectionId, Issuer, OrganizationId, SigningAlgorithm,
};

const ISSUER: &str = "https://idp.example/one";
const CLIENT: &str = "configured-client";
const SUBJECT: &str = "subject-one";
const ES256: &str = "ES256";
const NOW: u64 = 1_758_240_000;
const ONE_DAY: u64 = 24 * 60 * 60;

// ---------------------------------------------------------------- key material

struct Keys {
    signing: EncodingKey,
    published: Jwk,
    kid: String,
}

/// A generated P-256 key and the JWK an issuer would publish for it.
fn keys(kid: &str) -> Keys {
    let signing = EncodingKey::from_ec_der(
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
            .expect("a generated elliptic-curve key")
            .as_ref(),
    );
    let mut published = Jwk::from_encoding_key(&signing, Algorithm::ES256).expect("a public JWK");
    published.common.key_id = Some(kid.to_owned());
    Keys {
        signing,
        published,
        kid: kid.to_owned(),
    }
}

fn key_set(published: &[&Keys]) -> serde_json::Value {
    serde_json::json!({
        "keys": published
            .iter()
            .map(|keys| serde_json::to_value(&keys.published).expect("a serializable JWK"))
            .collect::<Vec<_>>(),
    })
}

// --------------------------------------------------------------------- tokens

fn claims(issuer: &str) -> serde_json::Value {
    serde_json::json!({
        "iss": issuer,
        "sub": SUBJECT,
        "aud": CLIENT,
        "iat": NOW,
        "exp": NOW + 300,
    })
}

fn with(mut claims: serde_json::Value, name: &str, value: serde_json::Value) -> serde_json::Value {
    claims
        .as_object_mut()
        .expect("a claims object")
        .insert(name.to_owned(), value);
    claims
}

fn mint(keys: &Keys, claims: &serde_json::Value) -> CredentialProof {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(keys.kid.clone());
    let token = encode(&header, claims, &keys.signing).expect("a signed token");
    CredentialProof::from_bytes(token.into_bytes())
}

// ------------------------------------------------------------------- the crate

fn connection(tag: u8) -> FederationConnectionId {
    FederationConnectionId::new(Uuid::from_bytes([tag; 16]))
}

fn organization(tag: u8) -> OrganizationId {
    OrganizationId::new(Uuid::from_bytes([tag; 16]))
}

fn a_connection(issuer: &str) -> FederationConnection {
    FederationConnection {
        id: connection(1),
        organization_id: organization(10),
        issuer: Issuer::new(issuer),
        client_id: ClientId::new(CLIENT),
        tenant_resolution: TenantResolutionRule {
            configured_organization: organization(10),
            verified_claim_name: None,
            verified_claim_value: None,
        },
        jit_provisioning: false,
        state: ConnectionState::Enabled,
    }
}

fn allowlist() -> AllowedAlgorithms {
    AllowedAlgorithms::configured(&[SigningAlgorithm::new(ES256)])
        .expect("an approved algorithm is admitted")
}

fn verifier<S: JwksSource>(source: S, clock: FixedClock) -> RealVerifier<S, FixedClock> {
    RealVerifier::new(allowlist(), source, clock)
        .configure_connection(connection(1), &SigningAlgorithm::new(ES256))
        .expect("an admitted algorithm for this connection")
}

/// A listener that answers exactly `requests` requests with fixed documents and then
/// stops, returning the paths it was asked for. Nothing leaves the loopback interface.
fn serve(
    listener: TcpListener,
    discovery: serde_json::Value,
    jwks: serde_json::Value,
    requests: usize,
) -> JoinHandle<Vec<String>> {
    std::thread::spawn(move || {
        let mut asked = Vec::new();
        for _ in 0..requests {
            let (mut stream, _) = listener.accept().expect("a connection from the source");
            let mut reader =
                BufReader::new(stream.try_clone().expect("a reader over the connection"));
            let mut request = String::new();
            reader.read_line(&mut request).expect("a request line");
            let path = request
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_owned();
            loop {
                let mut header = String::new();
                let read = reader.read_line(&mut header).expect("a header line");
                if read == 0 || header.trim().is_empty() {
                    break;
                }
            }
            let body = if path.contains("openid-configuration") {
                discovery.to_string()
            } else {
                jwks.to_string()
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("the fixed response");
            stream.flush().expect("a flushed response");
            asked.push(path);
        }
        asked
    })
}

// ============================== 1. the negative cache, as a class rather than a sequence
//
// Pass-1 finding A1-4 was closed by a negative cache, and `verifier_real.rs:884-886`
// states what it bounds: "That second look happens at most once per issuer per refetch
// interval, whatever the rate of presentation ... one unknown `kid` presented a thousand
// times must not be a thousand reads". Pass-1's case and `tests/verifier_real.rs:1190`
// both present the unknown `kid` in a loop on one thread. The rate an unauthenticated
// caller controls is not a loop.

/// One unknown `kid` presented on several threads at once is still one source read.
#[test]
fn an_unknown_kid_presented_at_once_is_not_one_source_read_per_thread() {
    struct Counting {
        inner: InMemoryJwks,
        reads: Arc<AtomicUsize>,
    }

    impl JwksSource for Counting {
        fn jwks(&self, issuer: &Issuer) -> Option<serde_json::Value> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            // A real key-set read is a network round trip. The cache lock is released
            // across it (pass-1 finding A1-5, `verifier_real.rs:887-890`), which is what
            // leaves this window open.
            std::thread::sleep(Duration::from_millis(150));
            self.inner.jwks(issuer)
        }
    }

    const PRESENTATIONS: usize = 8;

    let published = keys("2026-09");
    let unknown = keys("attacker-chosen");
    let inner = InMemoryJwks::new();
    inner.publish(&Issuer::new(ISSUER), key_set(&[&published]));
    let reads = Arc::new(AtomicUsize::new(0));
    let verifier = verifier(
        Counting {
            inner,
            reads: Arc::clone(&reads),
        },
        FixedClock::at(NOW),
    );
    verifier
        .verify(&a_connection(ISSUER), &mint(&published, &claims(ISSUER)))
        .expect("the published key verifies, and the set is now cached");
    let after_warmup = reads.load(Ordering::SeqCst);

    // Nothing here is signed by a published key and nothing here needs to be: the `kid`
    // is resolved before the signature is checked, so an unauthenticated caller reaches
    // the source, and decides how many of these arrive at once.
    let proof = mint(&unknown, &claims(ISSUER));
    let start = Barrier::new(PRESENTATIONS);
    std::thread::scope(|scope| {
        for _ in 0..PRESENTATIONS {
            scope.spawn(|| {
                start.wait();
                verifier
                    .verify(&a_connection(ISSUER), &proof)
                    .expect_err("no published key carries this kid");
            });
        }
    });

    let cost = reads.load(Ordering::SeqCst) - after_warmup;
    assert!(
        cost <= 1,
        "{PRESENTATIONS} simultaneous presentations of one unknown kid cost {cost} source \
         reads: the negative cache bounds a sequence, not a rate, and the check and the \
         store are not one act (verifier_real.rs:884-886, 899-913)"
    );
}

/// Two different unknown `kid`s inside one interval are one source read, not one each.
#[test]
fn two_unknown_kids_inside_one_interval_are_one_source_read() {
    let published = keys("2026-09");
    let first = keys("attacker-chosen-one");
    let second = keys("attacker-chosen-two");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER), key_set(&[&published]));
    let verifier = verifier(source.clone(), FixedClock::at(NOW));
    verifier
        .verify(&a_connection(ISSUER), &mint(&published, &claims(ISSUER)))
        .expect("the published key verifies, and the set is now cached");
    let after_warmup = source.fetches();

    for unknown in [&first, &second] {
        verifier
            .verify(&a_connection(ISSUER), &mint(unknown, &claims(ISSUER)))
            .expect_err("no published key carries this kid");
    }

    // The interval is per issuer, not per `kid`: a negative cache keyed by `kid` would be
    // no bound at all, the `kid` being the caller's to choose. Nothing in the 44 + 26
    // cases distinguishes the two — both present one `kid`.
    assert_eq!(
        source.fetches() - after_warmup,
        1,
        "a second unknown kid inside the interval was looked up again, so the negative \
         cache is keyed by kid and an unauthenticated caller has an unbounded supply of \
         them (verifier_real.rs:884-886)"
    );
}

/// An operator's `forget` outruns the interval an unauthenticated caller keeps warm.
#[test]
fn forgetting_an_issuer_refetches_inside_the_negative_interval() {
    let withdrawn = keys("2026-09");
    let rotated = keys("2026-10");
    let unknown = keys("attacker-chosen");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER), key_set(&[&withdrawn]));
    let verifier = verifier(source.clone(), FixedClock::at(NOW));
    verifier
        .verify(&a_connection(ISSUER), &mint(&withdrawn, &claims(ISSUER)))
        .expect("the published key verifies, and the set is now cached");

    // The caller decides when the negative interval starts, and can hold it open for as
    // long as it keeps presenting: the emergency path must not be inside it.
    verifier
        .verify(&a_connection(ISSUER), &mint(&unknown, &claims(ISSUER)))
        .expect_err("no published key carries this kid");
    source.publish(&Issuer::new(ISSUER), key_set(&[&rotated]));
    verifier
        .verify(&a_connection(ISSUER), &mint(&rotated, &claims(ISSUER)))
        .expect_err("the rotated kid is inside the interval the attacker opened");

    verifier.forget(&Issuer::new(ISSUER));

    verifier
        .verify(&a_connection(ISSUER), &mint(&rotated, &claims(ISSUER)))
        .expect("forget drops the miss with the set, not the set alone");
    verifier
        .verify(&a_connection(ISSUER), &mint(&withdrawn, &claims(ISSUER)))
        .expect_err("and the withdrawn key stops verifying in the same act");
}

// ================================ the verification companion, for the claim it names only
//
// Pass-1 finding A1-2 was closed by requiring `email_verified` to be exactly `true`.
// `verifier_real.rs:1165-1188` states the rule for the class: two claims have a companion,
// every other claim is issuer-asserted as signed.

/// The companion rule decides the standing of the claim it names and of no other.
#[test]
fn the_companion_rule_decides_only_the_claim_it_names() {
    let signing = keys("2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER), key_set(&[&signing]));
    let verifier = verifier(source, FixedClock::at(NOW));
    let carrying = |claims: serde_json::Value| {
        verifier
            .verify(&a_connection(ISSUER), &mint(&signing, &claims))
            .expect("the signature is valid; a claim's standing is not the signature's")
    };

    // A claim OIDC gives no companion is asserted as signed, whatever the address beside
    // it is doing: an absent `email_verified` must not refuse a login that resolves its
    // tenant on another claim.
    let mixed = carrying(with(
        with(claims(ISSUER), "email", "person@acme.example".into()),
        "hd",
        "acme.example".into(),
    ));
    assert_eq!(mixed.verified_claim("hd"), Some("acme.example"));
    assert_eq!(mixed.verified_claim("email"), None);
    assert_eq!(mixed.unverified_hint("email"), Some("person@acme.example"));

    // A companion with nothing to vouch for vouches for nothing: no claim appears.
    let orphaned = carrying(with(claims(ISSUER), "email_verified", true.into()));
    assert_eq!(orphaned.verified_claim("email"), None);
    assert_eq!(orphaned.unverified_hint("email"), None);

    // And a companion cannot promote a value that is not one: `email` is only a claim
    // when it is a string, and `true` beside a non-string address promotes nothing.
    let unreadable = carrying(with(
        with(
            claims(ISSUER),
            "email",
            serde_json::json!(["person@acme.example"]),
        ),
        "email_verified",
        true.into(),
    ));
    assert_eq!(unreadable.verified_claim("email"), None);
    assert_eq!(unreadable.unverified_hint("email"), None);
}

// ====================================== 2. `UreqJwks::admits`, as a class of URI forms
//
// Pass-1 finding A1-3 was closed by parsing the `jwks_uri` instead of prefix-matching it.
// `verifier_real.rs:281-304` states the contract the parse implements. These cases drive
// that contract, not the one example the ruling named.

/// The issuer's own origin is still its origin when the document spells the default port.
#[test]
fn the_default_port_is_the_same_origin_as_no_port_at_all() {
    // RFC 3986 6.2.3, scheme-based normalization: "the scheme's default port... is
    // equivalent to an empty or elided port". The comparison here is a string equality
    // over the whole authority, so the two spellings of one origin are two origins, and
    // a discovery document that spells the port leaves the connection with no key set at
    // all (`RefusalReason::KeySetUnavailable`, which names no port).
    assert!(
        UreqJwks::admits(
            &Issuer::new("https://idp.example"),
            "https://idp.example:443/jwks",
            &[]
        ),
        "the issuer's own host on the scheme's default port is the issuer's own origin"
    );
    assert!(
        UreqJwks::admits(
            &Issuer::new("https://idp.example:443"),
            "https://idp.example/jwks",
            &[]
        ),
        "and the equivalence holds whichever side spells it"
    );
}

/// A host the deployment listed is a host, not every port on it.
#[test]
fn a_listed_jwks_host_does_not_admit_every_port_on_it() {
    let issuer = Issuer::new("https://idp.example");
    let listed = ["keys.idp.example".to_owned()];

    // The issuer's own arm compares host *and* port (`verifier_real.rs:310`). The listed
    // arm compares the host alone, so the port is the discovery document's to choose —
    // and the document is the input this whole guard exists to bound
    // (`verifier_real.rs:284-286`). 2375 is the Docker daemon, not a key set.
    assert!(
        !UreqJwks::admits(&issuer, "https://keys.idp.example:2375/jwks", &listed),
        "a port the deployment never listed was admitted on a host it did"
    );
}

/// The `localhost` guard on a listed host is two names away from the loopback interface.
#[test]
fn a_listed_host_that_is_the_loopback_under_another_name_is_refused() {
    let issuer = Issuer::new("https://idp.example");

    // `verifier_real.rs:315` refuses the host `localhost` by string equality, "which is
    // the shape an SSRF attempt at a link-local metadata service takes". Both of these
    // resolve to 127.0.0.1 on an ordinary Linux host — `localhost.localdomain` is in the
    // stock `/etc/hosts`, and a trailing dot is the absolute form of the same name.
    for loopback_name in ["localhost.localdomain", "localhost."] {
        assert!(
            !UreqJwks::admits(
                &issuer,
                &format!("https://{loopback_name}/jwks"),
                &[loopback_name.to_owned()]
            ),
            "{loopback_name} is the loopback interface, and the guard beside it refuses \
             `localhost` and every address literal"
        );
    }
}

/// URI forms the destination parse must not be confused by, in both directions.
#[test]
fn uri_forms_the_destination_parse_must_not_be_confused_by() {
    let issuer = Issuer::new("https://idp.example");
    let listed = ["keys.idp.example".to_owned()];

    for admitted in [
        // RFC 3986 3.1: the scheme is case-insensitive.
        "HTTPS://idp.example/jwks",
        // RFC 3986 3.2.2: so is the host.
        "https://IDP.EXAMPLE/jwks",
        // The authority ends at the first `/`, `?` or `#`, so neither reaches it.
        "https://idp.example/jwks?rotated=1",
        "https://idp.example/jwks#current",
    ] {
        assert!(
            UreqJwks::admits(&issuer, admitted, &[]),
            "{admitted} names the issuer's own origin"
        );
    }

    for refused in [
        // A percent-encoded `@` is userinfo the moment anything decodes it.
        "https://idp.example%40attacker.example/jwks",
        // A backslash is a path separator to a WHATWG parser and not to this one.
        "https://idp.example\\@attacker.example/jwks",
        // An IPv6 literal is an address, not a name a deployment may list.
        "https://[::1]/jwks",
        "https://[::ffff:127.0.0.1]/jwks",
        // A suffix, a prefix and a label boundary are not a host.
        "https://evil-keys.idp.example/jwks",
        "https://keys.idp.example.attacker.example/jwks",
    ] {
        assert!(
            !UreqJwks::admits(
                &issuer,
                refused,
                &[listed[0].clone(), "::1".to_owned(), "[::1]".to_owned()]
            ),
            "{refused} was admitted as a key-set destination"
        );
    }

    // An empty list is the default, and it admits the issuer's own origin and nothing
    // else — including the host the deployment would have listed.
    assert!(!UreqJwks::admits(
        &issuer,
        "https://keys.idp.example/jwks",
        &[]
    ));
    assert!(UreqJwks::admits(
        &issuer,
        "https://keys.idp.example/jwks",
        &listed
    ));
}

// ================================================ 3. the audience, as the module states it
//
// `verifier_real.rs:21`: "the `aud` claim — one value or a list — must name
// `FederationConnection::client_id`; a list naming any other party needs an `azp` naming
// this one, and an `azp` naming another party is refused (OIDC Core 3.1.3.7)".

/// An `azp` that is not a string is still an `azp`, and this one names another party.
#[test]
fn an_azp_that_is_not_a_string_is_not_silently_unread() {
    let signing = keys("2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER), key_set(&[&signing]));
    let verifier = verifier(source, FixedClock::at(NOW));

    // Every other standard claim is refused when it arrives in a shape OIDC does not
    // define: a non-integer `exp` (adversary_verifier_1.rs:1171), a non-string `sub`
    // (:1280), an `aud` that is neither a string nor a list of them
    // (`verifier_real.rs:1204-1210`). `azp` is read with the same `text` helper and is
    // the one whose malformed form changes nothing.
    let denied = verifier.verify(
        &a_connection(ISSUER),
        &mint(
            &signing,
            &with(
                claims(ISSUER),
                "azp",
                serde_json::json!(["another-relying-party"]),
            ),
        ),
    );

    assert!(
        denied.is_err(),
        "a token whose azp names a party that is not this client was admitted because the \
         azp arrived as a list rather than a string (verifier_real.rs:21, 1007-1012)"
    );
    assert_eq!(
        verifier.refusals().last(),
        Some(&RefusalReason::AuthorizedPartyMismatch),
        "and the refusal is the one the module declares for it"
    );
}

/// An `aud` list that names this client twice names no other party.
#[test]
fn an_audience_list_naming_only_this_client_is_admitted_however_often_it_names_it() {
    let signing = keys("2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER), key_set(&[&signing]));
    let verifier = verifier(source, FixedClock::at(NOW));

    // OIDC Core 3.1.3.7 step 3 rejects a token whose audience contains a party the client
    // does not trust. This one contains no such party; the count is not the test, the
    // membership is. `verifier_real.rs:1016` counts.
    let validated = verifier.verify(
        &a_connection(ISSUER),
        &mint(
            &signing,
            &with(claims(ISSUER), "aud", serde_json::json!([CLIENT, CLIENT])),
        ),
    );

    assert!(
        validated.is_ok(),
        "an aud naming this client and nobody else was refused as untrusted: {:?}",
        verifier.refusals().last()
    );
}

/// The `exp` bound admits the instant it names and refuses the one after it.
#[test]
fn the_maximum_proof_lifetime_is_the_instant_it_names() {
    let signing = keys("2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER), key_set(&[&signing]));
    let verifier = verifier(source, FixedClock::at(NOW));

    let admitted = verifier
        .verify(
            &a_connection(ISSUER),
            &mint(
                &signing,
                &with(claims(ISSUER), "exp", (NOW + ONE_DAY).into()),
            ),
        )
        .expect("a day ahead is the bound, not beyond it");
    assert_eq!(admitted.subject().as_str(), SUBJECT);

    verifier
        .verify(
            &a_connection(ISSUER),
            &mint(
                &signing,
                &with(claims(ISSUER), "exp", (NOW + ONE_DAY + 1).into()),
            ),
        )
        .expect_err("one second past the bound is past it");
    assert_eq!(
        verifier.refusals().last(),
        Some(&RefusalReason::ExpiryTooDistant)
    );
}

// ================================================== 4. the shipped configuration, driven
//
// Pass-1 finding A1-10: the ureq cases built their own agent, so `UreqJwks::new()` was
// never the thing under test. Round 1 added two cases that drive it — both against a
// listener that answers nothing. Neither reads a key set, and neither measures the five
// seconds `hardened_config` configures.

/// The shipped source reads a key set over its own configuration, and the proof verifies.
#[test]
fn the_shipped_source_reads_a_key_set_and_the_proof_verifies() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port the test owns");
    let address = listener.local_addr().expect("the bound address");
    let issuer = format!("http://{address}");
    let signing = keys("2026-09");
    let served = serve(
        listener,
        serde_json::json!({ "issuer": issuer, "jwks_uri": format!("{issuer}/jwks") }),
        key_set(&[&signing]),
        2,
    );
    let verifier = verifier(UreqJwks::new(), FixedClock::at(NOW));

    let validated = verifier
        .verify(&a_connection(&issuer), &mint(&signing, &claims(&issuer)))
        .expect("the shipped configuration reads the key set the listener served");

    assert_eq!(validated.subject().as_str(), SUBJECT);
    assert_eq!(
        served.join().expect("the listener thread"),
        vec![
            "/.well-known/openid-configuration".to_owned(),
            "/jwks".to_owned()
        ],
        "the document, then the key set it named, and nothing else"
    );
}

/// A listener that speaks no TLS is a refusal inside the configured timeout, not a hang.
#[test]
fn the_shipped_source_refuses_a_listener_that_speaks_no_tls_inside_the_timeout() {
    let talkative = TcpListener::bind("127.0.0.1:0").expect("a loopback port the test owns");
    let plaintext = talkative.local_addr().expect("the bound address");
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = talkative.accept() {
            // A plain HTTP answer to a TLS ClientHello: the shape of an https URI pointed
            // at a port that is not speaking TLS.
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}",
            );
            let _ = stream.flush();
        }
    });

    let started = Instant::now();
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
        UreqJwks::new().jwks(&Issuer::new(format!("https://{plaintext}")))
    }));
    let elapsed = started.elapsed();
    assert!(
        outcome.is_ok(),
        "the shipped source panicked on a port that speaks no TLS instead of refusing"
    );
    assert!(
        outcome.ok().flatten().is_none(),
        "a plaintext answer to a TLS handshake is not a key set"
    );
    assert!(
        elapsed < Duration::from_secs(6),
        "a failed handshake took {elapsed:?}, past the five seconds hardened_config configures"
    );

    // And a listener that accepts, holds the connection and never answers: the timeout is
    // a property of the request, not of the peer closing it.
    let silent = TcpListener::bind("127.0.0.1:0").expect("a loopback port the test owns");
    let stalled = silent.local_addr().expect("the bound address");
    std::thread::spawn(move || {
        let mut held = Vec::new();
        while let Ok((stream, _)) = silent.accept() {
            held.push(stream);
        }
    });
    let (answered, finished) = mpsc::channel();
    std::thread::spawn(move || {
        let began = Instant::now();
        let key_set = UreqJwks::new().jwks(&Issuer::new(format!("https://{stalled}")));
        let _ = answered.send((key_set.is_none(), began.elapsed()));
    });

    match finished.recv_timeout(Duration::from_secs(20)) {
        Ok((refused, took)) => {
            assert!(
                refused,
                "a listener that never answers publishes no key set"
            );
            assert!(
                took < Duration::from_secs(6),
                "a stalled TLS handshake took {took:?}, past the five seconds \
                 hardened_config configures"
            );
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!(
                "the shipped source never returned from a stalled handshake: the global \
                 timeout at verifier_real.rs:259 does not bound the connect phase"
            )
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            panic!("the shipped source panicked on a stalled handshake instead of refusing")
        }
    }
}
