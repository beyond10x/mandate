//! The eight federation cases over the real verifier, and the algorithm, key and clock
//! policy `decision-blocker:algorithm-policy` requires evidence for.
//!
//! No test double stands in for [`mandate_federation::FederationVerifier`] here: every
//! case mints a real JWT with a key generated in this process and verifies it through
//! [`RealVerifier`]. The other ports of the crate — the allocator and the session issuer
//! — keep their fixtures, because they belong to other stories.
//!
//! # Every spelling of a host the JWKS destination guard is asked about
//!
//! [`UreqJwks::admits`] refuses a `jwks_uri` host that is an address literal or a
//! spelling of the loopback interface *before* `allowed_hosts` is consulted, so no
//! deployment can list its way to the loopback. Both halves of that refusal are asked
//! about one folded name, so a spelling cannot be an address literal to one half and an
//! ordinary name to the other.
//!
//! Measured 2026-09-22 for `story:host-spelling-folded` against `literal_address` and
//! `loopback` (`verifier_real.rs`), before and after the fold was computed once. "reaches
//! the list" is the destination arriving at `allowed_hosts` at all; it is still refused
//! there unless the deployment wrote that exact spelling into `jwks_hosts`.
//!
//! | spelling | host after `origin` | `literal_address` | `loopback` | reaches the list |
//! |---|---|---|---|---|
//! | `127.0.0.1` | `127.0.0.1` | true | true | no |
//! | `127.0.0.1.` | `127.0.0.1.` | false → **true** | false → **true** | **yes → no** |
//! | `127.0.0.1..` | `127.0.0.1..` | false → **true** | false → **true** | **yes → no** |
//! | `127.0.0.2` | `127.0.0.2` | true | true | no |
//! | `127.0.0.2.` | `127.0.0.2.` | false → **true** | false → **true** | **yes → no** |
//! | `127.255.255.254.` | `127.255.255.254.` | false → **true** | false → **true** | **yes → no** |
//! | `localhost` | `localhost` | false | true | no |
//! | `localhost.` | `localhost.` | false | true | no |
//! | `localhost..` | `localhost..` | false | true | no |
//! | `LOCALHOST` | `localhost` | false | true | no |
//! | `LOCALHOST.` | `localhost.` | false | true | no |
//! | `localhost.localdomain` | `localhost.localdomain` | false | true | no |
//! | `localhost.localdomain.` | `localhost.localdomain.` | false | true | no |
//! | `keys.localdomain` | `keys.localdomain` | false | true | no |
//! | `keys.localdomain.` | `keys.localdomain.` | false | true | no |
//! | `[::1]` | `::1` | true | true | no |
//! | `[::1.]` | `::1.` | false → **true** | false → **true** | **yes → no** |
//! | `[0:0:0:0:0:0:0:1]` | `0:0:0:0:0:0:0:1` | true | true | no |
//! | `[0:0:0:0:0:0:0:1.]` | `0:0:0:0:0:0:0:1.` | false → **true** | false → **true** | **yes → no** |
//! | `[0:0::0:1]` | `0:0::0:1` | true | true | no |
//! | `[::ffff:127.0.0.1]` | `::ffff:127.0.0.1` | true | false | no |
//! | `[::ffff:127.0.0.1.]` | `::ffff:127.0.0.1.` | false → **true** | false | **yes → no** |
//! | `[::ffff:7f00:1]` | `::ffff:7f00:1` | true | false | no |
//! | `[::FFFF:7F00:1]` | `::ffff:7f00:1` | true | false | no |
//! | `[::127.0.0.1]` | `::127.0.0.1` | true | false | no |
//!
//! Case is folded by `origin`, which lowercases the host, so `LOCALHOST` and
//! `[::FFFF:7F00:1]` never reach either check in the spelling they were written in. IPv6
//! bracket forms, zero-compression and the IPv4-mapped forms are all one literal to
//! `IpAddr`, and `::ffff:127.0.0.1` is refused as a *literal* rather than as a loopback,
//! because `Ipv6Addr::is_loopback` is false for a mapped address.
//!
//! An IPv6 destination **can** be listed, but only as `<host>:<port>`. `listed` splits an
//! entry on its last `:`, so the entry `::1` names the host `::` on port 1 and matches
//! nothing, while `::1:443` names `::1` on 443 and matches. The cases below list that
//! form: without it every IPv6 row is vacuous — nothing in `allowed_hosts` could match it,
//! so deleting the containment guard from `admits` leaves the row green and the row
//! asserts nothing about the guard it was written for.
//!
//! ## What this fold widened, and why it was kept
//!
//! Folding a spelling narrows the containment guard and widens the issuer's own origin,
//! because an absolute spelling of the issuer's host is the issuer's host. **It moves
//! decisions in both directions, and a measurement that sees only one direction is a
//! measurement taken where the other branch is dead.** Under the empty host list the
//! containment branch cannot admit anything at all, so a sweep scoped to it reports the
//! widening and none of the narrowing.
//!
//! Measured `06c6747` → head over every ordered (issuer, destination) pair of the 39
//! spellings in these tables, under both schemes and under four host lists each — empty,
//! the bare host, `host:port`, and a list carrying every spelling at once — **12 168
//! decisions**:
//!
//! | direction | decisions | branch they leave through |
//! |---|---|---|
//! | refused → admitted | **241** | the issuer's own origin, all of them |
//! | admitted → refused | **716** | the containment guard, all of them |
//!
//! Not one decision is widened through the containment guard, which is the SSRF
//! containment this story is about; and every one of the 716 narrowed decisions is an
//! address literal spelled with a trailing dot — `127.0.0.1.`, `[::1.]`,
//! `[::ffff:127.0.0.1.]` and their siblings — which is precisely the bypass this story
//! closed. Each of the 241 widened decisions is a pair whose two spellings are one host.
//!
//! `tests/adversary_host_spelling_2.rs` ran the same sweep independently over its own
//! 39-spelling corpus and reports 269 and 777 with the same split by branch and the same
//! account of what the narrowed decisions are; the counts differ because the corpora do,
//! the structure does not.
//!
//! Seven of the widened decisions are the plaintext own-origin branch with the issuer and
//! the `jwks_uri` spelled the *same* way — the shape
//! `services/control-plane/tests/end_to_end.rs` drives:
//!
//! | issuer and `jwks_uri` | base | head |
//! |---|---|---|
//! | `http://127.0.0.1./` | refused | admitted |
//! | `http://127.0.0.1../` | refused | admitted |
//! | `http://127.0.0.2./` | refused | admitted |
//! | `http://127.255.255.254./` | refused | admitted |
//! | `http://[::1.]/` | refused | admitted |
//! | `http://[0:0:0:0:0:0:0:1.]/` | refused | admitted |
//! | `http://127.0.0.1.:443/` | refused | admitted |
//!
//! The rest are pairs whose two spellings differ, which is the case a discovery document
//! produces: it writes `jwks_uri` and it does not have to spell the host the way the
//! deployment spelled the issuer. `verifier_real.rs`'s contract admits plaintext for a
//! loopback issuer, and an absolute spelling of the loopback is the loopback; refusing
//! these was the same fold disagreement pointing the other way.
//!
//! ## What the fold still does not fold
//!
//! `folded` strips trailing dots and nothing else. `literal_address` and `loopback` read
//! the host through `IpAddr::from_str`, which collapses every spelling of one address,
//! while the issuer's own-origin comparison is string equality, which collapses none — so
//! `[::1]`, `[0:0:0:0:0:0:0:1]` and `[0:0::0:1]` are one host to the first two and three
//! strangers to the third. A loopback issuer whose discovery document spells its own
//! address a second valid way is refused. It fails closed, it reproduces at `06c6747`,
//! and `tests/adversary_host_spelling_2.rs` holds the case that reports it; closing it
//! means comparing parsed addresses rather than names, which is a different story.
//!
//! ## What still reaches the list, and why it is not fixed here
//!
//! These are spellings a C resolver folds and `std::net::IpAddr` does not. They reached
//! the list before this fold and they reach it after it, because refusing them widens
//! what the guard refuses rather than agreeing on which host it is asked about, and
//! `story:host-spelling-folded` puts that out of scope.
//!
//! | spelling | host after `origin` | `literal_address` | `loopback` | reaches the list |
//! |---|---|---|---|---|
//! | `127.1` | `127.1` | false | false | yes |
//! | `2130706433` | `2130706433` | false | false | yes |
//! | `0177.0.0.1` | `0177.0.0.1` | false | false | yes |
//! | `0` | `0` | false | false | yes |
//! | `127.0.0.001` | `127.0.0.001` | false | false | yes |
//! | `127.0.0.1%2e` | `127.0.0.1%2e` | false | false | yes |
//! | `localhost%2e` | `localhost%2e` | false | false | yes |
//! | `%6cocalhost` | `%6cocalhost` | false | false | yes |
//! | `%31%32%37.0.0.1` | `%31%32%37.0.0.1` | false | false | yes |
//! | `.` | `.` | false | false | yes |
//!
//! `inet_aton` reads all five of the first rows as an address and `IpAddr::from_str`
//! reads none of them: `0` is `0.0.0.0`, `127.1` and `2130706433` are `127.0.0.1`,
//! `0177.0.0.1` is octal for the same, and `127.0.0.001` is rejected by Rust only for its
//! leading zeros. `origin` percent-decodes nothing, so a percent-encoded authority is
//! compared as the literal bytes it was written as — which is also what `listed` compares, so such a host
//! is admitted only when the deployment listed that exact encoded string. Whether a
//! *name* resolves to the loopback interface at fetch time remains the resolution-order
//! residue recorded with DNS rebinding in `verifier_real.rs`'s own module documentation.
//!
//! # No key is committed and no test reaches the network
//!
//! Every private key is generated by `aws_lc_rs` when the case runs
//! (`../sources/original-design.md:2509`: no production private key in source or config).
//! The `ureq` source is exercised against a `TcpListener` this file binds on the loopback
//! interface and answers itself.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex, OnceLock};
use std::thread::JoinHandle;

use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair,
};
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, encode};
use mandate_federation::authenticate::{
    AuthenticateFederation, Authenticated, authenticate_federation,
};
use mandate_federation::link::{LinkExternalPrincipal, Linked, link_external_principal};
use mandate_federation::record::{ConnectionState, ExternalKey, FederationEvent, Projection};
use mandate_federation::verifier_real::{
    AlgorithmPolicyError, AllowedAlgorithms, FixedClock, InMemoryJwks, JwksSource, RealVerifier,
    RefusalReason, UreqJwks,
};
use mandate_federation::{
    ConnectionStore, DenialClause, Denied, FederationVerifier, PrincipalState,
    RecordedPrincipals, RecordingSessionIssuer, RequestContext, SequentialAllocator,
};
use mandate_model::TenantResolutionRule;
use mandate_types::value::Uuid;
use mandate_types::{
    Audience, ClientId, CorrelationId, CredentialId, CredentialProof, DenialReason,
    ExternalLinkMethod, ExternalPrincipalId, ExternalSubject, FederationConnectionId, Issuer,
    OrganizationId, PrincipalId, REDACTED, SigningAlgorithm, Timestamp, VerifiedContext,
};

const ISSUER_ONE: &str = "https://idp.example/one";
const ISSUER_TWO: &str = "https://idp.example/two";
const CLIENT: &str = "configured-client";
const SUBJECT: &str = "subject-one";
const EMAIL: &str = "person@acme.example";
const RS256: &str = "RS256";
const ES256: &str = "ES256";

/// The instant every case is dated from, as seconds since the Unix epoch.
const NOW: u64 = 1_758_240_000;

// ---------------------------------------------------------------- key material

/// A generated key pair, the public JWK that publishes it, and the algorithm it signs
/// under. Nothing here is read from the repository: `aws_lc_rs` generates the key when
/// the case runs.
struct Keys {
    signing: EncodingKey,
    published: Jwk,
    algorithm: Algorithm,
    kid: String,
}

/// One RSA-2048 key for the whole file: generation is the expensive part, and a case that
/// needs a *different* key uses a fresh P-256 one.
fn rsa_pkcs1() -> &'static [u8] {
    static GENERATED: OnceLock<Vec<u8>> = OnceLock::new();
    GENERATED.get_or_init(|| {
        let pair = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048)
            .expect("an RSA key");
        let pkcs8: Pkcs8V1Der<'static> = pair.as_der().expect("the generated key in PKCS#8 DER");
        pkcs1_of(pkcs8.as_ref())
    })
}

/// `jsonwebtoken`'s RSA signer parses an RFC 8017 `RSAPrivateKey`; `aws_lc_rs` serializes
/// PKCS#8. The PKCS#8 wrapper is `SEQUENCE { INTEGER, AlgorithmIdentifier, OCTET STRING }`
/// and the octet string is that `RSAPrivateKey`.
fn pkcs1_of(pkcs8: &[u8]) -> Vec<u8> {
    let (tag, body, _) = element(pkcs8);
    assert_eq!(tag, 0x30, "PKCS#8 is a SEQUENCE");
    let (_, _, after_version) = element(body);
    let (_, _, after_algorithm) = element(after_version);
    let (tag, key, _) = element(after_algorithm);
    assert_eq!(tag, 0x04, "the private key is an OCTET STRING");
    key.to_vec()
}

/// One DER element: its tag, its content, and what follows it.
fn element(input: &[u8]) -> (u8, &[u8], &[u8]) {
    let first = usize::from(input[1]);
    let (length, header) = if first < 0x80 {
        (first, 2)
    } else {
        let count = first & 0x7f;
        let mut length = 0_usize;
        for byte in &input[2..2 + count] {
            length = (length << 8) | usize::from(*byte);
        }
        (length, 2 + count)
    };
    (
        input[0],
        &input[header..header + length],
        &input[header + length..],
    )
}

fn ec_pkcs8(algorithm: Algorithm) -> Vec<u8> {
    let signing = match algorithm {
        Algorithm::ES256 => &ECDSA_P256_SHA256_FIXED_SIGNING,
        Algorithm::ES384 => &ECDSA_P384_SHA384_FIXED_SIGNING,
        other => panic!("no elliptic-curve key is generated for {other:?}"),
    };
    EcdsaKeyPair::generate_pkcs8(signing, &SystemRandom::new())
        .expect("a generated elliptic-curve key")
        .as_ref()
        .to_vec()
}

/// A key pair published under `kid`. Each call to the elliptic-curve arms generates a new
/// key, which is what a rotation window needs.
fn keys(algorithm: Algorithm, kid: &str) -> Keys {
    let signing = match algorithm {
        Algorithm::RS256 => EncodingKey::from_rsa_der(rsa_pkcs1()),
        Algorithm::ES256 | Algorithm::ES384 => EncodingKey::from_ec_der(&ec_pkcs8(algorithm)),
        other => panic!("no key is generated for {other:?}"),
    };
    let mut published = Jwk::from_encoding_key(&signing, algorithm).expect("a public JWK");
    published.common.key_id = Some(kid.to_owned());
    Keys {
        signing,
        published,
        algorithm,
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

fn claims(issuer: &str, subject: &str) -> serde_json::Value {
    serde_json::json!({
        "iss": issuer,
        "sub": subject,
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

/// Claims carrying an address the issuer asserted it had verified.
fn verified_email(issuer: &str, subject: &str, email: &str) -> serde_json::Value {
    with(
        with(claims(issuer, subject), "email", email.into()),
        "email_verified",
        true.into(),
    )
}

fn mint(keys: &Keys, claims: &serde_json::Value) -> CredentialProof {
    let mut header = Header::new(keys.algorithm);
    header.kid = Some(keys.kid.clone());
    let token = encode(&header, claims, &keys.signing).expect("a signed token");
    CredentialProof::from_bytes(token.into_bytes())
}

/// The unpadded base64url form the JOSE compact serialization uses, for the tokens this
/// file has to assemble by hand because no signer would produce them.
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut encoded = String::new();
    for chunk in bytes.chunks(3) {
        let first = u32::from(chunk[0]);
        let second = u32::from(chunk.get(1).copied().unwrap_or_default());
        let third = u32::from(chunk.get(2).copied().unwrap_or_default());
        let packed = (first << 16) | (second << 8) | third;
        encoded.push(char::from(ALPHABET[((packed >> 18) & 63) as usize]));
        encoded.push(char::from(ALPHABET[((packed >> 12) & 63) as usize]));
        if chunk.len() > 1 {
            encoded.push(char::from(ALPHABET[((packed >> 6) & 63) as usize]));
        }
        if chunk.len() > 2 {
            encoded.push(char::from(ALPHABET[(packed & 63) as usize]));
        }
    }
    encoded
}

/// A token whose header names `none` and which carries no signature at all.
fn unsigned(kid: &str, claims: &serde_json::Value) -> CredentialProof {
    let header = serde_json::json!({ "alg": "none", "typ": "JWT", "kid": kid });
    let token = format!(
        "{}.{}.",
        base64url(header.to_string().as_bytes()),
        base64url(claims.to_string().as_bytes())
    );
    CredentialProof::from_bytes(token.into_bytes())
}

// ------------------------------------------------------------------- the crate

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization(tag: u8) -> OrganizationId {
    OrganizationId::new(uuid(tag))
}

fn connection(tag: u8) -> FederationConnectionId {
    FederationConnectionId::new(uuid(tag))
}

fn principal(tag: u8) -> PrincipalId {
    PrincipalId::new(uuid(tag))
}

fn context(organization_id: OrganizationId) -> VerifiedContext {
    VerifiedContext {
        subject: principal(0x51),
        actor: None,
        organization: organization_id,
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("signing-and-verification"),
    }
}

fn unconditional(organization_id: OrganizationId) -> TenantResolutionRule {
    TenantResolutionRule {
        configured_organization: organization_id,
        verified_claim_name: None,
        verified_claim_value: None,
    }
}

fn on_claim(organization_id: OrganizationId, name: &str, value: &str) -> TenantResolutionRule {
    TenantResolutionRule {
        configured_organization: organization_id,
        verified_claim_name: Some(name.to_owned()),
        verified_claim_value: Some(value.to_owned()),
    }
}

fn created(
    connection_id: FederationConnectionId,
    organization_id: OrganizationId,
    issuer: &str,
    tenant_resolution: TenantResolutionRule,
) -> FederationEvent {
    FederationEvent::FederationConnectionCreated {
        context: context(organization_id),
        connection_id,
        issuer: Issuer::new(issuer),
        client_id: ClientId::new(CLIENT),
        tenant_resolution,
        jit_provisioning: false,
    }
}

fn linked(
    connection_id: FederationConnectionId,
    organization_id: OrganizationId,
    subject: &str,
    principal_id: PrincipalId,
) -> FederationEvent {
    FederationEvent::ExternalPrincipalLinked {
        context: context(organization_id),
        connection_id,
        principal_id,
        external_principal_id: ExternalPrincipalId::new(uuid(0x71)),
        subject: ExternalSubject::new(subject),
        link_method: ExternalLinkMethod::Administrator,
        linked_at: at(),
    }
}

fn at() -> Timestamp {
    Timestamp::new("2026-09-18T00:00:00Z")
}

fn request() -> RequestContext {
    RequestContext {
        audience: Audience::new("mandate"),
        correlation: CorrelationId::new("signing-and-verification"),
        credential: CredentialId::new(uuid(0xcd)),
        at: at(),
    }
}

fn a_connection(issuer: &str) -> mandate_federation::record::FederationConnection {
    a_connection_of(connection(1), issuer)
}

fn a_connection_of(
    id: FederationConnectionId,
    issuer: &str,
) -> mandate_federation::record::FederationConnection {
    mandate_federation::record::FederationConnection {
        id,
        organization_id: organization(10),
        issuer: Issuer::new(issuer),
        client_id: ClientId::new(CLIENT),
        tenant_resolution: unconditional(organization(10)),
        jit_provisioning: false,
        state: ConnectionState::Enabled,
    }
}

// ------------------------------------------------------------------ the verifier

/// The allowlist the approving authority recorded on
/// `decision-blocker:algorithm-policy`, and nothing else.
fn allowlist() -> AllowedAlgorithms {
    AllowedAlgorithms::configured(&[SigningAlgorithm::new(RS256), SigningAlgorithm::new(ES256)])
        .expect("the approved allowlist is admitted")
}

fn verifier(
    source: &InMemoryJwks,
    clock: &FixedClock,
    configured: &[(FederationConnectionId, &str)],
) -> RealVerifier<InMemoryJwks, FixedClock> {
    let mut built = RealVerifier::new(allowlist(), source.clone(), clock.clone());
    for (connection_id, name) in configured {
        built = built
            .configure_connection(*connection_id, &SigningAlgorithm::new(*name))
            .expect("an admitted algorithm for this connection");
    }
    built
}

fn authenticate(
    projection: &Projection,
    connection_id: FederationConnectionId,
    verifier: &RealVerifier<InMemoryJwks, FixedClock>,
    proof: CredentialProof,
) -> Result<Authenticated, Denied> {
    let input = AuthenticateFederation {
        connection_id,
        proof,
    };
    let mut sessions = RecordingSessionIssuer::new();
    authenticate_federation(
        &input,
        &request(),
        verifier,
        projection,
        projection,
        &mut sessions,
    )
}

fn link(
    projection: &Projection,
    allocator: &mut SequentialAllocator,
    connection_id: FederationConnectionId,
    subject: &str,
    principal_id: PrincipalId,
) -> Result<Linked, Denied> {
    let organization_id = organization(10);
    let links = RecordedPrincipals::over(projection.clone()).with_principal(
        principal_id,
        organization_id,
        PrincipalState::Active,
    );
    let input = LinkExternalPrincipal {
        context: context(organization_id),
        connection_id,
        external_subject: ExternalSubject::new(subject),
        principal_id,
        method: ExternalLinkMethod::Administrator,
    };
    link_external_principal(&input, &request(), projection, &links, allocator)
}

// ============================================================ the eight cases

/// `issuer-isolation`: equal subjects under distinct issuers resolve distinct external
/// keys, over two real key sets and both admitted algorithms.
#[test]
fn issuer_isolation() {
    let rsa = keys(Algorithm::RS256, "one-2026-09");
    let ec = keys(Algorithm::ES256, "two-2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&rsa]));
    source.publish(&Issuer::new(ISSUER_TWO), key_set(&[&ec]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(
        &source,
        &clock,
        &[(connection(1), RS256), (connection(2), ES256)],
    );

    let mut log = vec![
        created(
            connection(1),
            organization(10),
            ISSUER_ONE,
            unconditional(organization(10)),
        ),
        created(
            connection(2),
            organization(10),
            ISSUER_TWO,
            unconditional(organization(10)),
        ),
    ];
    let projection = Projection::fold(&log).expect("two connections");
    let mut allocator = SequentialAllocator::new();

    let first = link(
        &projection,
        &mut allocator,
        connection(1),
        "shared-subject",
        principal(0x21),
    )
    .expect("no link exists for this key");
    log.push(first.event);
    let projection = Projection::fold(&log).expect("one link");
    let second = link(
        &projection,
        &mut allocator,
        connection(2),
        "shared-subject",
        principal(0x22),
    )
    .expect("the same subject under another issuer is another key");
    log.push(second.event);
    let projection = Projection::fold(&log).expect("two links");

    let one = authenticate(
        &projection,
        connection(1),
        &verifier,
        mint(&rsa, &claims(ISSUER_ONE, "shared-subject")),
    )
    .expect("the RS256 proof under issuer one resolves");
    let two = authenticate(
        &projection,
        connection(2),
        &verifier,
        mint(&ec, &claims(ISSUER_TWO, "shared-subject")),
    )
    .expect("the ES256 proof under issuer two resolves");

    assert_eq!(one.principal_id, principal(0x21));
    assert_eq!(two.principal_id, principal(0x22));
    assert_ne!(
        one.principal_id, two.principal_id,
        "equal subjects under distinct issuers are distinct accounts"
    );
}

/// `email-isolation`: an equal verified email under distinct issuers merges no principal.
#[test]
fn email_isolation() {
    let shared = "person@example.test";
    let one = keys(Algorithm::RS256, "one-2026-09");
    let two = keys(Algorithm::ES256, "two-2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&one]));
    source.publish(&Issuer::new(ISSUER_TWO), key_set(&[&two]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(
        &source,
        &clock,
        &[(connection(1), RS256), (connection(2), ES256)],
    );

    let verified_email = |issuer: &str, subject: &str| {
        with(
            with(claims(issuer, subject), "email", shared.into()),
            "email_verified",
            true.into(),
        )
    };

    let mut log = vec![
        created(
            connection(1),
            organization(10),
            ISSUER_ONE,
            unconditional(organization(10)),
        ),
        created(
            connection(2),
            organization(10),
            ISSUER_TWO,
            unconditional(organization(10)),
        ),
    ];
    let projection = Projection::fold(&log).expect("two connections");
    let mut allocator = SequentialAllocator::new();
    let first = link(
        &projection,
        &mut allocator,
        connection(1),
        "subject-under-one",
        principal(0x21),
    )
    .expect("no link exists for this key");
    log.push(first.event);
    let projection = Projection::fold(&log).expect("one link");

    let denied = authenticate(
        &projection,
        connection(2),
        &verifier,
        mint(&two, &verified_email(ISSUER_TWO, "subject-under-two")),
    )
    .expect_err("the same verified email under another issuer is not a link");
    assert_eq!(denied.reason, DenialReason::Denied);
    assert_eq!(
        denied.clause,
        DenialClause::LinkAbsent,
        "no automatic principal merge on equal email"
    );

    let second = link(
        &projection,
        &mut allocator,
        connection(2),
        "subject-under-two",
        principal(0x22),
    )
    .expect("an explicit link is the only route");
    log.push(second.event);
    let projection = Projection::fold(&log).expect("two links");

    let under_one = authenticate(
        &projection,
        connection(1),
        &verifier,
        mint(&one, &verified_email(ISSUER_ONE, "subject-under-one")),
    )
    .expect("the explicit link under issuer one resolves");
    let under_two = authenticate(
        &projection,
        connection(2),
        &verifier,
        mint(&two, &verified_email(ISSUER_TWO, "subject-under-two")),
    )
    .expect("the explicit link under issuer two resolves");
    assert_ne!(
        under_one.principal_id, under_two.principal_id,
        "an equal verified email merged nothing"
    );
}

/// `explicit-link`: the link an administrator made resolves a real proof, and the audit
/// record carries no part of the presented token.
#[test]
fn explicit_link() {
    let rsa = keys(Algorithm::RS256, "one-2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&rsa]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), RS256)]);

    let mut log = vec![created(
        connection(1),
        organization(10),
        ISSUER_ONE,
        unconditional(organization(10)),
    )];
    let projection = Projection::fold(&log).expect("one connection");
    let mut allocator = SequentialAllocator::new();
    let accepted = link(
        &projection,
        &mut allocator,
        connection(1),
        SUBJECT,
        principal(0x21),
    )
    .expect("a same-organization administrator with no conflicting link");

    let proof = mint(&rsa, &claims(ISSUER_ONE, SUBJECT));
    let presented = String::from_utf8(proof.expose_bytes().to_vec()).expect("a compact token");
    let rendering = format!("{:?}", accepted.event);
    assert!(
        !rendering.contains(REDACTED),
        "the audit record carries no transient value at all: {rendering}"
    );
    for segment in presented.split('.') {
        assert!(
            segment.is_empty() || !rendering.contains(segment),
            "the audit record carries no part of the presented token: {rendering}"
        );
    }

    log.push(accepted.event);
    let projection = Projection::fold(&log).expect("one link");
    let key = ExternalKey {
        organization_id: organization(10),
        issuer: Issuer::new(ISSUER_ONE),
        subject: ExternalSubject::new(SUBJECT),
    };
    assert_eq!(
        projection.link(&key).map(|link| link.principal_id),
        Some(principal(0x21)),
        "the exact key resolves"
    );

    let authenticated = authenticate(&projection, connection(1), &verifier, proof)
        .expect("the new link resolves a real proof");
    assert_eq!(authenticated.principal_id, principal(0x21));
}

/// `link-conflict`: the exact key is already linked, the second link is denied, and the
/// surviving link is the one a real proof authenticates.
#[test]
fn link_conflict() {
    let rsa = keys(Algorithm::RS256, "one-2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&rsa]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), RS256)]);

    let mut log = vec![created(
        connection(1),
        organization(10),
        ISSUER_ONE,
        unconditional(organization(10)),
    )];
    let projection = Projection::fold(&log).expect("one connection");
    let mut allocator = SequentialAllocator::new();
    let accepted = link(
        &projection,
        &mut allocator,
        connection(1),
        SUBJECT,
        principal(0x21),
    )
    .expect("no link exists for this key");
    log.push(accepted.event);
    let projection = Projection::fold(&log).expect("one link");
    let before = log.len();

    let denied = link(
        &projection,
        &mut allocator,
        connection(1),
        SUBJECT,
        principal(0x22),
    )
    .expect_err("the exact key is already linked to another principal");
    assert_eq!(denied.reason, DenialReason::Denied);
    assert_eq!(denied.clause, DenialClause::LinkConflict);
    assert_eq!(log.len(), before, "a denial emits no event");

    let authenticated = authenticate(
        &projection,
        connection(1),
        &verifier,
        mint(&rsa, &claims(ISSUER_ONE, SUBJECT)),
    )
    .expect("the surviving link resolves");
    assert_eq!(authenticated.principal_id, principal(0x21));
}

/// `tenant-valid`: one configured tenant matches a claim the issuer signed *and* asserted
/// it had verified.
#[test]
fn tenant_valid() {
    let rsa = keys(Algorithm::RS256, "one-2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&rsa]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), RS256)]);

    let log = vec![
        created(
            connection(1),
            organization(10),
            ISSUER_ONE,
            on_claim(organization(10), "email", EMAIL),
        ),
        linked(connection(1), organization(10), SUBJECT, principal(0x21)),
    ];
    let projection = Projection::fold(&log).expect("one connection, one link");

    let authenticated = authenticate(
        &projection,
        connection(1),
        &verifier,
        mint(&rsa, &verified_email(ISSUER_ONE, SUBJECT, EMAIL)),
    )
    .expect("exactly one configured tenant matches");

    assert_eq!(
        authenticated.organization_id,
        organization(10),
        "the exact configured organization"
    );
    assert_eq!(authenticated.principal_id, principal(0x21));
}

/// `tenant-zero`: a signed proof that matches no configured tenant is denied.
#[test]
fn tenant_zero() {
    let rsa = keys(Algorithm::RS256, "one-2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&rsa]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), RS256)]);

    let log = vec![
        created(
            connection(1),
            organization(10),
            ISSUER_ONE,
            on_claim(organization(10), "org", "acme"),
        ),
        linked(connection(1), organization(10), SUBJECT, principal(0x21)),
    ];
    let projection = Projection::fold(&log).expect("one connection, one link");

    let denied = authenticate(
        &projection,
        connection(1),
        &verifier,
        mint(
            &rsa,
            &with(claims(ISSUER_ONE, SUBJECT), "org", "another".into()),
        ),
    )
    .expect_err("no configured tenant matches");

    assert_eq!(denied.reason, DenialReason::TenantMismatch);
    assert_eq!(denied.clause, DenialClause::TenantZero);
}

/// `tenant-ambiguous`: two configured tenants match one signed proof; no tenant is
/// guessed.
#[test]
fn tenant_ambiguous() {
    let rsa = keys(Algorithm::RS256, "one-2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&rsa]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(
        &source,
        &clock,
        &[(connection(1), RS256), (connection(2), RS256)],
    );

    let log = vec![
        created(
            connection(1),
            organization(10),
            ISSUER_ONE,
            on_claim(organization(10), "org", "acme"),
        ),
        created(
            connection(2),
            organization(11),
            ISSUER_ONE,
            on_claim(organization(11), "org", "acme"),
        ),
        linked(connection(1), organization(10), SUBJECT, principal(0x21)),
    ];
    let projection = Projection::fold(&log).expect("two connections, one link");
    assert_eq!(
        projection
            .enabled_for_issuer(&Issuer::new(ISSUER_ONE))
            .len(),
        2,
        "two configured tenants stand behind one issuer"
    );

    let denied = authenticate(
        &projection,
        connection(1),
        &verifier,
        mint(
            &rsa,
            &with(claims(ISSUER_ONE, SUBJECT), "org", "acme".into()),
        ),
    )
    .expect_err("two configured tenants match");

    assert_eq!(denied.reason, DenialReason::TenantMismatch);
    assert_eq!(denied.clause, DenialClause::TenantAmbiguous);
}

/// `tenant-unverified`: the issuer signed the email domain and asserted nothing about
/// having verified it, so it is a hint and never a validated claim, and no tenant is
/// resolved from it.
///
/// Absence is not verification. Both spellings of "not verified" are driven: the
/// companion absent, which is the ordinary shape, and the companion present and false.
#[test]
fn tenant_unverified() {
    let rsa = keys(Algorithm::RS256, "one-2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&rsa]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), RS256)]);

    let log = vec![
        created(
            connection(1),
            organization(10),
            ISSUER_ONE,
            on_claim(organization(10), "email", EMAIL),
        ),
        linked(connection(1), organization(10), SUBJECT, principal(0x21)),
    ];
    let projection = Projection::fold(&log).expect("one connection, one link");

    for unverified in [
        with(claims(ISSUER_ONE, SUBJECT), "email", EMAIL.into()),
        with(
            with(claims(ISSUER_ONE, SUBJECT), "email", EMAIL.into()),
            "email_verified",
            false.into(),
        ),
        with(
            with(claims(ISSUER_ONE, SUBJECT), "email", EMAIL.into()),
            "email_verified",
            "true".into(),
        ),
    ] {
        let proof = mint(&rsa, &unverified);
        let validated = verifier
            .verify(&a_connection(ISSUER_ONE), &proof)
            .expect("the signature is valid; the address's standing is not the signature's");
        assert_eq!(
            validated.verified_claim("email"),
            None,
            "{unverified}: an address the issuer never asserted verified is not validated"
        );
        assert_eq!(
            validated.unverified_hint("email"),
            Some(EMAIL),
            "{unverified}: it is reachable only as a hint"
        );

        let denied = authenticate(&projection, connection(1), &verifier, proof)
            .expect_err("the selector arrived without a verified binding");
        assert_eq!(denied.reason, DenialReason::TenantMismatch, "{unverified}");
        assert_eq!(
            denied.clause,
            DenialClause::UnverifiedFallback,
            "{unverified}: the value that would have resolved the tenant was never validated"
        );
    }
}

// ======================================================= the algorithm policy

#[test]
fn an_empty_allowlist_is_refused_at_construction() {
    assert_eq!(
        AllowedAlgorithms::configured(&[]),
        Err(AlgorithmPolicyError::Unconfigured),
        "a deployment that configured no algorithm admits none"
    );
}

#[test]
fn an_unknown_name_and_a_shared_secret_family_are_refused_at_construction() {
    for name in ["RS257", "rs256", "", "HS256", "PS256", "EdDSA"] {
        assert_eq!(
            AllowedAlgorithms::configured(&[SigningAlgorithm::new(name)]),
            Err(AlgorithmPolicyError::Unadmitted(name.to_owned())),
            "{name} is not one of the two admitted names"
        );
    }
}

#[test]
fn the_unsigned_name_is_refused_at_construction_by_its_own_error() {
    assert_eq!(
        AllowedAlgorithms::configured(&[SigningAlgorithm::new("none")]),
        Err(AlgorithmPolicyError::Unsigned),
        "`none` is refused by name, and is named as what it is"
    );
}

#[test]
fn a_connection_the_deployment_configured_no_algorithm_for_is_refused_at_validation() {
    let rsa = keys(Algorithm::RS256, "one-2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&rsa]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[]);

    let denied = verifier
        .verify(
            &a_connection(ISSUER_ONE),
            &mint(&rsa, &claims(ISSUER_ONE, SUBJECT)),
        )
        .expect_err("no algorithm is configured for this connection");

    assert_eq!(denied.reason, DenialReason::InvalidCredential);
    assert_eq!(denied.clause, DenialClause::AlgorithmPolicy);
    assert_eq!(
        verifier.refusals(),
        vec![RefusalReason::ConnectionAlgorithmUnconfigured]
    );
    assert_eq!(
        source.fetches(),
        0,
        "no key set is read on a refused policy"
    );
}

#[test]
fn a_connection_may_not_be_configured_with_an_unadmitted_algorithm() {
    let source = InMemoryJwks::new();
    let clock = FixedClock::at(NOW);
    let refused = RealVerifier::new(allowlist(), source, clock)
        .configure_connection(connection(1), &SigningAlgorithm::new("ES384"))
        .expect_err("ES384 is outside the approved allowlist");

    assert_eq!(
        refused,
        AlgorithmPolicyError::Unadmitted("ES384".to_owned())
    );
}

/// A header naming an algorithm outside the policy is refused *with a valid signature*:
/// the case asserts the signature is good before asserting the refusal
/// (`../sources/original-design.md:2527`).
#[test]
fn a_header_algorithm_outside_the_policy_is_refused_though_its_signature_verifies() {
    let outside = keys(Algorithm::ES384, "one-2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&outside]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), RS256)]);
    let proof = mint(&outside, &claims(ISSUER_ONE, SUBJECT));
    let token = String::from_utf8(proof.expose_bytes().to_vec()).expect("a compact token");

    let mut validation = Validation::new(Algorithm::ES384);
    validation.validate_exp = false;
    validation.validate_aud = false;
    assert!(
        jsonwebtoken::decode::<serde_json::Value>(
            &token,
            &DecodingKey::from_jwk(&outside.published).expect("the published key"),
            &validation,
        )
        .is_ok(),
        "the premise: this token's ES384 signature is valid"
    );

    let denied = verifier
        .verify(&a_connection(ISSUER_ONE), &proof)
        .expect_err("the header names an algorithm the policy does not admit");

    assert_eq!(denied.reason, DenialReason::InvalidCredential);
    assert_eq!(denied.clause, DenialClause::AlgorithmPolicy);
    assert_eq!(
        verifier.refusals(),
        vec![RefusalReason::HeaderAlgorithmNotConfigured]
    );
    assert_eq!(
        source.fetches(),
        0,
        "the refusal happens before a key is ever selected"
    );
}

/// The same token, byte for byte, is accepted where its algorithm is the connection's
/// configured one and refused where it is not: the algorithm is never taken from the
/// header.
#[test]
fn an_admitted_algorithm_that_is_not_this_connections_is_refused() {
    let ec = keys(Algorithm::ES256, "one-2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&ec]));
    let clock = FixedClock::at(NOW);
    let proof = mint(&ec, &claims(ISSUER_ONE, SUBJECT));

    let configured_for_es256 = verifier(&source, &clock, &[(connection(1), ES256)]);
    let validated = configured_for_es256
        .verify(&a_connection(ISSUER_ONE), &proof)
        .expect("ES256 is this connection's configured algorithm");
    assert_eq!(validated.subject().as_str(), SUBJECT);

    let configured_for_rs256 = verifier(&source, &clock, &[(connection(1), RS256)]);
    let denied = configured_for_rs256
        .verify(&a_connection(ISSUER_ONE), &proof)
        .expect_err("the same token, under a connection configured for RS256");

    assert_eq!(denied.clause, DenialClause::AlgorithmPolicy);
    assert_eq!(
        configured_for_rs256.refusals(),
        vec![RefusalReason::HeaderAlgorithmNotConfigured]
    );
}

#[test]
fn an_unsigned_token_is_refused_and_named_as_unsigned() {
    let rsa = keys(Algorithm::RS256, "one-2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&rsa]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), RS256)]);

    let denied = verifier
        .verify(
            &a_connection(ISSUER_ONE),
            &unsigned("one-2026-09", &claims(ISSUER_ONE, SUBJECT)),
        )
        .expect_err("`none` is refused");

    assert_eq!(denied.reason, DenialReason::InvalidCredential);
    assert_eq!(denied.clause, DenialClause::AlgorithmPolicy);
    assert_eq!(verifier.refusals(), vec![RefusalReason::UnsignedAlgorithm]);
}

// ============================================================ keys and rollover

#[test]
fn two_keys_published_across_a_rotation_window_are_both_accepted() {
    let retiring = keys(Algorithm::ES256, "2026-08");
    let incoming = keys(Algorithm::ES256, "2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&retiring, &incoming]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), ES256)]);

    for signing in [&retiring, &incoming] {
        let validated = verifier
            .verify(
                &a_connection(ISSUER_ONE),
                &mint(signing, &claims(ISSUER_ONE, SUBJECT)),
            )
            .unwrap_or_else(|denied| {
                panic!(
                    "both keys of the window verify, {} did not: {denied}",
                    signing_kid(signing)
                )
            });
        assert_eq!(validated.subject().as_str(), SUBJECT);
    }
    assert_eq!(
        source.fetches(),
        1,
        "one read of the key set serves the whole window"
    );
    assert!(verifier.refusals().is_empty());
}

fn signing_kid(keys: &Keys) -> &str {
    &keys.kid
}

#[test]
fn a_kid_that_is_not_cached_is_found_on_one_refetch() {
    let first = keys(Algorithm::ES256, "2026-08");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&first]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), ES256)]);

    verifier
        .verify(
            &a_connection(ISSUER_ONE),
            &mint(&first, &claims(ISSUER_ONE, SUBJECT)),
        )
        .expect("the published key verifies");
    assert_eq!(source.fetches(), 1);

    let rotated = keys(Algorithm::ES256, "2026-09");
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&first, &rotated]));

    verifier
        .verify(
            &a_connection(ISSUER_ONE),
            &mint(&rotated, &claims(ISSUER_ONE, SUBJECT)),
        )
        .expect("an unknown kid is looked for once more before it is refused");
    assert_eq!(
        source.fetches(),
        2,
        "exactly one refetch, not one per verification"
    );

    verifier
        .verify(
            &a_connection(ISSUER_ONE),
            &mint(&first, &claims(ISSUER_ONE, SUBJECT)),
        )
        .expect("the retiring key is still in the window");
    assert_eq!(source.fetches(), 2, "the refreshed set is cached");
}

#[test]
fn a_kid_withdrawn_from_the_source_is_refused_once_the_cache_is_stale() {
    let revoked = keys(Algorithm::ES256, "2026-08");
    let replacement = keys(Algorithm::ES256, "2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&revoked, &replacement]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), ES256)]).with_key_max_age(600);
    // Both proofs outlive the revocation, so a refusal is the key's standing and not the
    // proof's age.
    let outliving = |signing: &Keys| {
        mint(
            signing,
            &with(claims(ISSUER_ONE, SUBJECT), "exp", (NOW + 3600).into()),
        )
    };

    verifier
        .verify(&a_connection(ISSUER_ONE), &outliving(&revoked))
        .expect("the key is published and the proof verifies");

    // The emergency revocation procedure: the compromised key leaves the published set.
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&replacement]));
    clock.advance(601);

    let denied = verifier
        .verify(&a_connection(ISSUER_ONE), &outliving(&revoked))
        .expect_err("a key the issuer withdrew verifies nothing");

    assert_eq!(denied.reason, DenialReason::InvalidCredential);
    assert_eq!(denied.clause, DenialClause::ProofInvalid);
    assert_eq!(verifier.refusals(), vec![RefusalReason::KeyIdUnknown]);
    verifier
        .verify(&a_connection(ISSUER_ONE), &outliving(&replacement))
        .expect("the replacement key still verifies");
}

#[test]
fn a_kid_that_no_published_set_holds_is_refused_after_one_refetch() {
    let published = keys(Algorithm::ES256, "2026-09");
    let forged = keys(Algorithm::ES256, "forged");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&published]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), ES256)]);
    verifier
        .verify(
            &a_connection(ISSUER_ONE),
            &mint(&published, &claims(ISSUER_ONE, SUBJECT)),
        )
        .expect("the published key verifies, and the set is now cached");
    assert_eq!(source.fetches(), 1);

    let denied = verifier
        .verify(
            &a_connection(ISSUER_ONE),
            &mint(&forged, &claims(ISSUER_ONE, SUBJECT)),
        )
        .expect_err("the kid resolves to no published key");

    assert_eq!(denied.clause, DenialClause::ProofInvalid);
    assert_eq!(verifier.refusals(), vec![RefusalReason::KeyIdUnknown]);
    assert_eq!(
        source.fetches(),
        2,
        "the cached read, and one refetch that did not find it either"
    );

    for _ in 0..20 {
        verifier
            .verify(
                &a_connection(ISSUER_ONE),
                &mint(&forged, &claims(ISSUER_ONE, SUBJECT)),
            )
            .expect_err("still unknown");
    }
    assert_eq!(
        source.fetches(),
        2,
        "one unknown kid costs one refetch per interval, not one read per presentation"
    );

    // The interval is a window on the clock, not a counter: once it has passed, a kid
    // that might have been published since is looked for again.
    clock.advance(61);
    verifier
        .verify(
            &a_connection(ISSUER_ONE),
            &mint(&forged, &claims(ISSUER_ONE, SUBJECT)),
        )
        .expect_err("still unknown, and looked for once more");
    assert_eq!(source.fetches(), 3);
}

#[test]
fn a_signature_under_a_key_the_issuer_never_published_is_refused() {
    let published = keys(Algorithm::ES256, "2026-09");
    let attacker = keys(Algorithm::ES256, "2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&published]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), ES256)]);

    let denied = verifier
        .verify(
            &a_connection(ISSUER_ONE),
            &mint(&attacker, &claims(ISSUER_ONE, SUBJECT)),
        )
        .expect_err("the kid resolves, the signature does not");

    assert_eq!(denied.reason, DenialReason::InvalidCredential);
    assert_eq!(denied.clause, DenialClause::ProofInvalid);
    assert_eq!(verifier.refusals(), vec![RefusalReason::SignatureInvalid]);
}

#[test]
fn an_issuer_with_no_published_key_set_is_refused() {
    let rsa = keys(Algorithm::RS256, "one-2026-09");
    let source = InMemoryJwks::new();
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), RS256)]);

    let denied = verifier
        .verify(
            &a_connection(ISSUER_ONE),
            &mint(&rsa, &claims(ISSUER_ONE, SUBJECT)),
        )
        .expect_err("a source that holds no key set for this issuer admits nothing");

    assert_eq!(denied.reason, DenialReason::InvalidCredential);
    assert_eq!(denied.clause, DenialClause::ProofInvalid);
    assert_eq!(verifier.refusals(), vec![RefusalReason::KeySetUnavailable]);
}

#[test]
fn a_discovery_document_that_names_another_issuer_is_refused() {
    let rsa = keys(Algorithm::RS256, "one-2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&rsa]));
    source.publish_discovery(
        &Issuer::new(ISSUER_ONE),
        serde_json::json!({ "issuer": ISSUER_TWO, "jwks_uri": "https://idp.example/two/jwks" }),
    );
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), RS256)]);

    let denied = verifier
        .verify(
            &a_connection(ISSUER_ONE),
            &mint(&rsa, &claims(ISSUER_ONE, SUBJECT)),
        )
        .expect_err("the document the issuer published names another issuer");

    assert_eq!(denied.reason, DenialReason::InvalidCredential);
    assert_eq!(denied.clause, DenialClause::IssuerMismatch);
    assert_eq!(
        verifier.refusals(),
        vec![RefusalReason::DiscoveryIssuerMismatch]
    );
}

// ================================================= the rest of the design's list

#[test]
fn an_expired_proof_is_refused_against_the_verifiers_own_clock() {
    let rsa = keys(Algorithm::RS256, "one-2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&rsa]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), RS256)]);
    let proof = mint(&rsa, &claims(ISSUER_ONE, SUBJECT));

    verifier
        .verify(&a_connection(ISSUER_ONE), &proof)
        .expect("inside its window");
    clock.advance(301);
    let denied = verifier
        .verify(&a_connection(ISSUER_ONE), &proof)
        .expect_err("past its expiry");

    assert_eq!(denied.reason, DenialReason::InvalidCredential);
    assert_eq!(denied.clause, DenialClause::ProofInvalid);
    assert_eq!(verifier.refusals(), vec![RefusalReason::Expired]);
}

#[test]
fn a_proof_that_is_not_yet_valid_is_refused() {
    let rsa = keys(Algorithm::RS256, "one-2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&rsa]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), RS256)]);
    let proof = mint(
        &rsa,
        &with(claims(ISSUER_ONE, SUBJECT), "nbf", (NOW + 60).into()),
    );

    let denied = verifier
        .verify(&a_connection(ISSUER_ONE), &proof)
        .expect_err("before its not-before");
    assert_eq!(denied.clause, DenialClause::ProofInvalid);
    assert_eq!(verifier.refusals(), vec![RefusalReason::NotYetValid]);

    clock.advance(60);
    verifier
        .verify(&a_connection(ISSUER_ONE), &proof)
        .expect("once the not-before has passed");
}

#[test]
fn a_proof_that_names_no_expiry_is_refused() {
    let rsa = keys(Algorithm::RS256, "one-2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&rsa]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), RS256)]);
    let mut without_expiry = claims(ISSUER_ONE, SUBJECT);
    without_expiry
        .as_object_mut()
        .expect("a claims object")
        .remove("exp");

    let denied = verifier
        .verify(&a_connection(ISSUER_ONE), &mint(&rsa, &without_expiry))
        .expect_err("a proof that never expires is not a proof this verifier admits");

    assert_eq!(denied.clause, DenialClause::ProofInvalid);
    assert_eq!(verifier.refusals(), vec![RefusalReason::ExpiryAbsent]);
}

#[test]
fn an_issuer_that_is_not_the_connections_is_refused_at_the_verifier() {
    let rsa = keys(Algorithm::RS256, "one-2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&rsa]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), RS256)]);

    let denied = verifier
        .verify(
            &a_connection(ISSUER_ONE),
            &mint(&rsa, &claims(ISSUER_TWO, SUBJECT)),
        )
        .expect_err("the token's issuer is not the connection's configured one");

    assert_eq!(denied.reason, DenialReason::InvalidCredential);
    assert_eq!(denied.clause, DenialClause::IssuerMismatch);
    assert_eq!(verifier.refusals(), vec![RefusalReason::IssuerMismatch]);
}

#[test]
fn an_audience_that_is_not_the_configured_client_is_refused_at_the_verifier() {
    let rsa = keys(Algorithm::RS256, "one-2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&rsa]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), RS256)]);

    let denied = verifier
        .verify(
            &a_connection(ISSUER_ONE),
            &mint(
                &rsa,
                &with(claims(ISSUER_ONE, SUBJECT), "aud", "another-client".into()),
            ),
        )
        .expect_err("the token was minted for another client");

    assert_eq!(denied.reason, DenialReason::AudienceMismatch);
    assert_eq!(denied.clause, DenialClause::AudienceBinding);
    assert_eq!(verifier.refusals(), vec![RefusalReason::AudienceMismatch]);
}

/// An `aud` naming a party beside this client is admitted only when `azp` names this one
/// (OIDC Core 3.1.3.7 steps 3 and 4).
#[test]
fn an_audience_naming_another_party_needs_an_azp_naming_this_client() {
    let rsa = keys(Algorithm::RS256, "one-2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&rsa]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), RS256)]);
    let several = with(
        claims(ISSUER_ONE, SUBJECT),
        "aud",
        serde_json::json!(["another-relying-party", CLIENT]),
    );

    let denied = verifier
        .verify(&a_connection(ISSUER_ONE), &mint(&rsa, &several))
        .expect_err("a token also addressed to a party this connection does not trust");
    assert_eq!(denied.reason, DenialReason::AudienceMismatch);
    assert_eq!(denied.clause, DenialClause::AudienceBinding);
    assert_eq!(verifier.refusals(), vec![RefusalReason::AudienceUntrusted]);

    let validated = verifier
        .verify(
            &a_connection(ISSUER_ONE),
            &mint(&rsa, &with(several.clone(), "azp", CLIENT.into())),
        )
        .expect("an `azp` naming this client is what admits the several");
    assert_eq!(validated.audience().as_str(), CLIENT);

    let denied = verifier
        .verify(
            &a_connection(ISSUER_ONE),
            &mint(&rsa, &with(several, "azp", "another-relying-party".into())),
        )
        .expect_err("the token was authorized to another party");
    assert_eq!(denied.reason, DenialReason::AudienceMismatch);
    assert_eq!(
        verifier.refusals().last(),
        Some(&RefusalReason::AuthorizedPartyMismatch)
    );
}

#[test]
fn a_token_type_that_is_not_a_jwt_is_refused() {
    let rsa = keys(Algorithm::RS256, "one-2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&rsa]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), RS256)]);
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(rsa.kid.clone());
    header.typ = Some("secevent+jwt".to_owned());
    let token =
        encode(&header, &claims(ISSUER_ONE, SUBJECT), &rsa.signing).expect("a signed token");

    let denied = verifier
        .verify(
            &a_connection(ISSUER_ONE),
            &CredentialProof::from_bytes(token.into_bytes()),
        )
        .expect_err("this is not the token type a login proof carries");

    assert_eq!(denied.clause, DenialClause::ProofInvalid);
    assert_eq!(
        verifier.refusals(),
        vec![RefusalReason::UnexpectedTokenType]
    );
}

#[test]
fn a_sender_constrained_proof_is_refused_because_nothing_here_checks_the_binding() {
    let rsa = keys(Algorithm::RS256, "one-2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&rsa]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), RS256)]);
    let constrained = with(
        claims(ISSUER_ONE, SUBJECT),
        "cnf",
        serde_json::json!({ "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" }),
    );

    let denied = verifier
        .verify(&a_connection(ISSUER_ONE), &mint(&rsa, &constrained))
        .expect_err("a constrained proof admitted as unconstrained is the constraint lost");

    assert_eq!(denied.clause, DenialClause::ProofInvalid);
    assert_eq!(
        verifier.refusals(),
        vec![RefusalReason::SenderConstraintUnverifiable]
    );
}

#[test]
fn a_proof_that_is_not_a_token_at_all_is_refused() {
    let source = InMemoryJwks::new();
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), RS256)]);

    let denied = verifier
        .verify(
            &a_connection(ISSUER_ONE),
            &CredentialProof::from_bytes(b"proof-material-marker".to_vec()),
        )
        .expect_err("material that is not a compact JWS is refused, not parsed");

    assert_eq!(denied.reason, DenialReason::InvalidCredential);
    assert_eq!(denied.clause, DenialClause::ProofInvalid);
    assert_eq!(verifier.refusals(), vec![RefusalReason::MalformedToken]);
}

#[test]
fn the_returned_proof_reports_only_what_the_issuer_signed_and_verified() {
    let rsa = keys(Algorithm::RS256, "one-2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&rsa]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), RS256)]);
    let full = with(
        with(
            with(
                claims(ISSUER_ONE, SUBJECT),
                "email",
                "person@example.test".into(),
            ),
            "email_verified",
            false.into(),
        ),
        "org",
        "acme".into(),
    );

    let validated = verifier
        .verify(&a_connection(ISSUER_ONE), &mint(&rsa, &full))
        .expect("the proof verifies");

    assert_eq!(validated.issuer().as_str(), ISSUER_ONE);
    assert_eq!(validated.subject().as_str(), SUBJECT);
    assert_eq!(validated.audience().as_str(), CLIENT);
    assert_eq!(validated.verified_claim("org"), Some("acme"));
    assert_eq!(
        validated.verified_claim("email"),
        None,
        "the issuer signed the address and said it had not verified it"
    );
    assert_eq!(
        validated.unverified_hint("email"),
        Some("person@example.test")
    );
    assert_eq!(
        validated.unverified_hint("org"),
        None,
        "a validated claim is not also a hint"
    );
}

#[test]
fn verification_is_a_function_of_the_clock_and_nothing_else() {
    let rsa = keys(Algorithm::RS256, "one-2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&rsa]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), RS256)]);
    let proof = mint(&rsa, &claims(ISSUER_ONE, SUBJECT));

    let first = verifier.verify(&a_connection(ISSUER_ONE), &proof);
    let second = verifier.verify(&a_connection(ISSUER_ONE), &proof);
    let third = verifier.verify(&a_connection(ISSUER_ONE), &proof);

    assert_eq!(first, second, "two verifications, one answer");
    assert_eq!(second, third);
    assert!(first.is_ok());
    assert_eq!(
        source.fetches(),
        1,
        "the answer did not come from a refetch"
    );

    clock.advance(301);
    assert!(
        verifier.verify(&a_connection(ISSUER_ONE), &proof).is_err(),
        "the clock is the only thing that moved"
    );
}

// ====================================================== the ureq source, locally

#[test]
fn the_ureq_source_reads_the_document_and_the_key_set_from_a_listener_the_test_owns() {
    let rsa = keys(Algorithm::RS256, "one-2026-09");
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port the test owns");
    let issuer = format!(
        "http://{}",
        listener.local_addr().expect("the bound address")
    );
    let discovery = serde_json::json!({
        "issuer": issuer,
        "jwks_uri": format!("{issuer}/jwks"),
    });
    let served = serve(listener, discovery, key_set(&[&rsa]), 2);

    let agent = ureq::Agent::new_with_config(
        ureq::config::Config::builder()
            .max_redirects(0)
            .proxy(None)
            .build(),
    );
    let source = UreqJwks::over(agent);
    let clock = FixedClock::at(NOW);
    let verifier = RealVerifier::new(allowlist(), source, clock)
        .configure_connection(connection(1), &SigningAlgorithm::new(RS256))
        .expect("an admitted algorithm");

    let validated = verifier
        .verify(
            &a_connection(&issuer),
            &mint(&rsa, &claims(&issuer, SUBJECT)),
        )
        .expect("the key set the listener served verifies the proof");

    assert_eq!(validated.subject().as_str(), SUBJECT);
    assert_eq!(
        served.join().expect("the listener thread"),
        vec![
            "/.well-known/openid-configuration".to_owned(),
            "/jwks".to_owned()
        ],
        "discovery, then the key set the document names"
    );
}

/// A `jwks_uri` that is neither under the issuer nor an absolute `https` URL is not
/// fetched at all: that is the shape an SSRF attempt against a link-local metadata
/// service takes (`../sources/original-design.md:2529-2535`).
#[test]
fn a_jwks_uri_off_the_issuers_own_prefix_and_off_https_is_never_fetched() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port the test owns");
    let issuer = format!(
        "http://{}",
        listener.local_addr().expect("the bound address")
    );
    let discovery = serde_json::json!({
        "issuer": issuer,
        "jwks_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials",
    });
    let served = serve(listener, discovery, serde_json::json!({ "keys": [] }), 1);

    let source = UreqJwks::over(ureq::Agent::new_with_config(
        ureq::config::Config::builder()
            .max_redirects(0)
            .proxy(None)
            .build(),
    ));

    assert!(
        source.jwks(&Issuer::new(issuer.as_str())).is_none(),
        "the source refuses the URI rather than fetching it"
    );
    assert_eq!(
        served.join().expect("the listener thread"),
        vec!["/.well-known/openid-configuration".to_owned()],
        "the document was read and the key set was not"
    );
}

/// The shipped configuration is the hardened one, read back field by field.
///
/// Driven through [`UreqJwks::hardened_config`] rather than inferred from a request that
/// happened not to be made: a case that only ever fetches over loopback exercises no
/// redirect ceiling, no timeout and no TLS provider, and deleting any of the three would
/// leave it green.
#[test]
fn the_shipped_configuration_bounds_redirects_time_and_the_tls_provider() {
    let config = UreqJwks::hardened_config();

    assert_eq!(
        config.max_redirects(),
        0,
        "a redirect is a destination nobody named"
    );
    assert!(
        config.proxy().is_none(),
        "ureq's default proxy is read from ALL_PROXY/HTTPS_PROXY/HTTP_PROXY, which would put \
         the key-set fetch through an egress nobody configured on the connection"
    );
    assert_eq!(
        config.timeouts().global,
        Some(std::time::Duration::from_secs(5)),
        "a JWKS read that never returns is a login that never returns"
    );
    assert_eq!(
        config.tls_config().provider(),
        ureq::tls::TlsProvider::NativeTls,
        "the provider is named: ureq's default is Rustls, which this workspace does not compile in"
    );
    assert!(
        matches!(
            config.tls_config().root_certs(),
            ureq::tls::RootCerts::PlatformVerifier
        ),
        "roots come from the host store, no set being bundled"
    );
}

/// The shipped source answers an `https` issuer with a refusal, not a panic.
///
/// Red until the workspace manifest carries `ureq`'s `native-tls` feature: the connector
/// is compiled behind that feature name, `native-tls-no-default` does not enable it, and
/// `ureq` answers an https URI under a provider it cannot supply by panicking. Selecting
/// the provider is this unit's half and is done; the feature is the coordinator's. The
/// panic is deliberately not caught here — catching it would turn the blocker into a
/// refusal and leave the shipped source unable to read from any real IdP.
#[test]
fn the_shipped_source_answers_an_https_issuer_without_panicking() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port the test owns");
    let address = listener.local_addr().expect("the bound address");
    std::thread::spawn(move || while listener.accept().is_ok() {});
    let source = UreqJwks::new();

    let issuer = Issuer::new(format!("https://{address}"));
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| source.jwks(&issuer)));

    assert!(
        outcome.is_ok(),
        "the shipped source panicked on an https issuer instead of refusing"
    );
    assert!(
        outcome.ok().flatten().is_none(),
        "a listener that speaks no TLS publishes no key set"
    );
}

/// Where the key set may be fetched from is bounded by parsing, never by a string prefix.
#[test]
fn the_jwks_uri_destination_is_bounded_by_origin_and_by_the_listed_hosts() {
    let issuer = Issuer::new("https://idp.example/tenant");
    let listed = ["keys.idp.example".to_owned()];

    for admitted in [
        "https://idp.example/tenant/jwks",
        "https://idp.example/keys",
        "https://IDP.example/keys",
        // The authority ends at the first `/` (RFC 3986 3.2), so an `@` after it is part
        // of the path and names nobody: this URI is fetched from `idp.example`, and the
        // path is unconstrained on a host that is admitted.
        "https://idp.example/tenant@attacker.example/jwks",
    ] {
        assert!(
            UreqJwks::admits(&issuer, admitted, &[]),
            "{admitted} is the issuer's own origin"
        );
    }

    for refused in [
        // A string prefix is not an origin: the userinfo spells the issuer and the host
        // after the `@` is somewhere else entirely.
        "https://idp.example@attacker.example/jwks",
        "https://idp.example:443@attacker.example/jwks",
        // Another host the deployment never listed.
        "https://keys.other.example/jwks",
        // The link-local metadata service, in both schemes.
        "http://169.254.169.254/latest/meta-data/iam/security-credentials",
        "https://169.254.169.254/jwks",
        // A downgrade, and a scheme that is not a fetch at all.
        "http://idp.example/tenant/jwks",
        "file:///etc/shadow",
        "not a uri",
        "",
    ] {
        assert!(
            !UreqJwks::admits(&issuer, refused, &listed),
            "{refused} was admitted as a key-set destination"
        );
    }

    assert!(
        UreqJwks::admits(&issuer, "https://keys.idp.example/jwks", &listed),
        "a second host the deployment listed is admitted: some IdPs publish keys off one"
    );
    assert!(
        !UreqJwks::admits(&issuer, "https://keys.idp.example/jwks", &[]),
        "and is admitted only because the deployment listed it"
    );
    for never_listable in ["https://127.0.0.1/jwks", "https://localhost/jwks"] {
        assert!(
            !UreqJwks::admits(
                &issuer,
                never_listable,
                &["127.0.0.1".to_owned(), "localhost".to_owned()]
            ),
            "{never_listable}: an address literal is not a host a deployment may list"
        );
    }
}

/// The hosts configured for a connection are the ones the source is given, and no
/// other connection's.
#[test]
fn the_verifier_passes_each_connections_own_listed_hosts_to_the_source() {
    #[derive(Debug, Default)]
    struct Recording {
        published: InMemoryJwks,
        asked: Arc<Mutex<Vec<Vec<String>>>>,
    }

    impl JwksSource for Recording {
        fn jwks(&self, issuer: &Issuer) -> Option<serde_json::Value> {
            self.published.jwks(issuer)
        }

        fn jwks_from(
            &self,
            issuer: &Issuer,
            allowed_hosts: &[String],
        ) -> Option<serde_json::Value> {
            self.asked
                .lock()
                .expect("the recorded asks")
                .push(allowed_hosts.to_vec());
            self.published.jwks(issuer)
        }
    }

    let rsa = keys(Algorithm::RS256, "one-2026-09");
    let source = Recording::default();
    let asked = Arc::clone(&source.asked);
    source
        .published
        .publish(&Issuer::new(ISSUER_ONE), key_set(&[&rsa]));
    source
        .published
        .publish(&Issuer::new(ISSUER_TWO), key_set(&[&rsa]));
    let verifier = RealVerifier::new(allowlist(), source, FixedClock::at(NOW))
        .configure_connection(connection(1), &SigningAlgorithm::new(RS256))
        .expect("an admitted algorithm")
        .allowing_jwks_hosts(connection(1), &["keys.idp.example"])
        .configure_connection(connection(2), &SigningAlgorithm::new(RS256))
        .expect("an admitted algorithm");

    verifier
        .verify(
            &a_connection_of(connection(1), ISSUER_ONE),
            &mint(&rsa, &claims(ISSUER_ONE, SUBJECT)),
        )
        .expect("the first connection's proof verifies");
    verifier
        .verify(
            &a_connection_of(connection(2), ISSUER_TWO),
            &mint(&rsa, &claims(ISSUER_TWO, SUBJECT)),
        )
        .expect("the second connection's proof verifies");

    assert_eq!(
        *asked.lock().expect("the recorded asks"),
        vec![vec!["keys.idp.example".to_owned()], Vec::new()],
        "each connection's own list, and an unlisted connection's is empty"
    );
}

/// The emergency path does not have to be waited out: `forget` drops the cached set at
/// once, and the withdrawn key stops verifying on the next proof.
#[test]
fn a_withdrawn_key_is_refused_at_once_when_the_cached_set_is_forgotten() {
    let revoked = keys(Algorithm::ES256, "2026-08");
    let replacement = keys(Algorithm::ES256, "2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&revoked, &replacement]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), ES256)]);

    verifier
        .verify(
            &a_connection(ISSUER_ONE),
            &mint(&revoked, &claims(ISSUER_ONE, SUBJECT)),
        )
        .expect("the key is published and the proof verifies");

    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&replacement]));
    verifier
        .verify(
            &a_connection(ISSUER_ONE),
            &mint(&revoked, &claims(ISSUER_ONE, SUBJECT)),
        )
        .expect("until the cache is dropped, the withdrawn key is still the cached one");

    verifier.forget(&Issuer::new(ISSUER_ONE));

    let denied = verifier
        .verify(
            &a_connection(ISSUER_ONE),
            &mint(&revoked, &claims(ISSUER_ONE, SUBJECT)),
        )
        .expect_err("the withdrawn key verifies nothing, and no clock had to move");
    assert_eq!(denied.reason, DenialReason::InvalidCredential);
    assert_eq!(
        verifier.refusals().last(),
        Some(&RefusalReason::KeyIdUnknown)
    );
    verifier
        .verify(
            &a_connection(ISSUER_ONE),
            &mint(&replacement, &claims(ISSUER_ONE, SUBJECT)),
        )
        .expect("the replacement key still verifies");
}

/// A `crit` header names an extension that changes what the token means, and nothing
/// here implements one.
#[test]
fn a_critical_header_extension_is_refused() {
    let rsa = keys(Algorithm::RS256, "one-2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&rsa]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), RS256)]);
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(rsa.kid.clone());
    header.crit = Some(vec!["urn:example:unread".to_owned()]);
    let token =
        encode(&header, &claims(ISSUER_ONE, SUBJECT), &rsa.signing).expect("a signed token");

    let denied = verifier
        .verify(
            &a_connection(ISSUER_ONE),
            &CredentialProof::from_bytes(token.into_bytes()),
        )
        .expect_err("RFC 7515 4.1.11: a critical parameter nothing understands is rejected");

    assert_eq!(denied.reason, DenialReason::InvalidCredential);
    assert_eq!(denied.clause, DenialClause::ProofInvalid);
    assert_eq!(
        verifier.refusals(),
        vec![RefusalReason::CriticalHeaderUnread]
    );
}

/// A subject longer than OIDC admits never becomes a key component.
#[test]
fn a_subject_beyond_the_declared_bound_is_refused() {
    let rsa = keys(Algorithm::RS256, "one-2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&rsa]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), RS256)]);

    let admitted = verifier
        .verify(
            &a_connection(ISSUER_ONE),
            &mint(
                &rsa,
                &with(claims(ISSUER_ONE, SUBJECT), "sub", "s".repeat(255).into()),
            ),
        )
        .expect("255 bytes is the bound, not beyond it");
    assert_eq!(admitted.subject().as_str().len(), 255);

    let denied = verifier
        .verify(
            &a_connection(ISSUER_ONE),
            &mint(
                &rsa,
                &with(claims(ISSUER_ONE, SUBJECT), "sub", "s".repeat(256).into()),
            ),
        )
        .expect_err("OIDC Core 2 bounds `sub` at 255 characters");
    assert_eq!(denied.reason, DenialReason::InvalidCredential);
    assert_eq!(verifier.refusals(), vec![RefusalReason::SubjectTooLong]);
}

/// An `exp` at the end of time is a field, not an expiry.
#[test]
fn a_proof_that_expires_at_the_end_of_time_is_refused() {
    let rsa = keys(Algorithm::RS256, "one-2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&rsa]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), RS256)]);

    for unbounded in [u64::MAX, NOW + 24 * 60 * 60 + 1] {
        let denied = verifier
            .verify(
                &a_connection(ISSUER_ONE),
                &mint(
                    &rsa,
                    &with(claims(ISSUER_ONE, SUBJECT), "exp", unbounded.into()),
                ),
            )
            .expect_err("a proof that outlives any login is refused");
        assert_eq!(
            denied.reason,
            DenialReason::InvalidCredential,
            "{unbounded}"
        );
        assert_eq!(
            verifier.refusals().last(),
            Some(&RefusalReason::ExpiryTooDistant),
            "{unbounded}"
        );
    }
}

/// The unknown-`kid` refetch is a bound on the *rate*, not on a sequence: callers arriving
/// together cost one read between them, and a cached `kid` is still served while that read
/// is in flight.
#[test]
fn one_unknown_kid_costs_one_read_however_many_callers_present_it_at_once() {
    /// A source whose read takes long enough for every caller to arrive inside it.
    struct Slow {
        published: InMemoryJwks,
        reads: Arc<AtomicUsize>,
    }

    impl JwksSource for Slow {
        fn jwks(&self, issuer: &Issuer) -> Option<serde_json::Value> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(150));
            self.published.jwks(issuer)
        }
    }

    const CALLERS: usize = 16;

    let published = keys(Algorithm::ES256, "2026-09");
    let unknown = keys(Algorithm::ES256, "attacker-chosen");
    let inner = InMemoryJwks::new();
    inner.publish(&Issuer::new(ISSUER_ONE), key_set(&[&published]));
    let reads = Arc::new(AtomicUsize::new(0));
    let verifier = RealVerifier::new(
        allowlist(),
        Slow {
            published: inner,
            reads: Arc::clone(&reads),
        },
        FixedClock::at(NOW),
    )
    .configure_connection(connection(1), &SigningAlgorithm::new(ES256))
    .expect("an admitted algorithm");
    verifier
        .verify(
            &a_connection(ISSUER_ONE),
            &mint(&published, &claims(ISSUER_ONE, SUBJECT)),
        )
        .expect("the published key verifies, and the set is now cached");
    let warm = reads.load(Ordering::SeqCst);

    let refused = AtomicUsize::new(0);
    let served = AtomicUsize::new(0);
    let unknown_proof = mint(&unknown, &claims(ISSUER_ONE, SUBJECT));
    let known_proof = mint(&published, &claims(ISSUER_ONE, SUBJECT));
    let start = Barrier::new(CALLERS + 1);
    std::thread::scope(|scope| {
        for _ in 0..CALLERS {
            scope.spawn(|| {
                start.wait();
                verifier
                    .verify(&a_connection(ISSUER_ONE), &unknown_proof)
                    .expect_err("no published key carries this kid");
                refused.fetch_add(1, Ordering::SeqCst);
            });
        }
        // A caller presenting a `kid` the cached set does hold must not be made to wait on
        // — or be refused by — a refetch it has nothing to do with.
        scope.spawn(|| {
            start.wait();
            verifier
                .verify(&a_connection(ISSUER_ONE), &known_proof)
                .expect("a cached kid is served while a refetch is in flight");
            served.fetch_add(1, Ordering::SeqCst);
        });
    });

    assert_eq!(
        reads.load(Ordering::SeqCst) - warm,
        1,
        "{CALLERS} simultaneous presentations of one unknown kid cost one read between them"
    );
    assert_eq!(refused.load(Ordering::SeqCst), CALLERS);
    assert_eq!(served.load(Ordering::SeqCst), 1);
    assert!(
        verifier
            .refusals()
            .iter()
            .all(|reason| *reason == RefusalReason::KeyIdUnknown),
        "every one of them is the same refusal: {:?}",
        verifier.refusals()
    );
}

/// The scheme's default port and an elided one are one origin (RFC 3986 6.2.3), whichever
/// side spells it.
#[test]
fn the_default_port_and_an_elided_one_are_one_origin() {
    for (issuer, uri) in [
        ("https://idp.example", "https://idp.example:443/jwks"),
        ("https://idp.example:443", "https://idp.example/jwks"),
        ("https://idp.example:443", "https://idp.example:443/jwks"),
        // The same normalization on the other scheme, which only a loopback issuer — a
        // test's own listener — ever reaches.
        ("http://127.0.0.1", "http://127.0.0.1:80/jwks"),
        ("http://127.0.0.1:80", "http://127.0.0.1/jwks"),
    ] {
        assert!(
            UreqJwks::admits(&Issuer::new(issuer), uri, &[]),
            "{uri} is the origin of {issuer}"
        );
    }

    assert!(
        !UreqJwks::admits(
            &Issuer::new("http://idp.example"),
            "http://idp.example:80/jwks",
            &[]
        ),
        "normalizing the port does not make a plaintext issuer off the loopback fetchable"
    );

    for (issuer, uri) in [
        ("https://idp.example", "https://idp.example:8443/jwks"),
        ("https://idp.example:8443", "https://idp.example/jwks"),
        // A port that is not a port is not a destination this parser guesses at.
        ("https://idp.example", "https://idp.example:65536/jwks"),
        ("https://idp.example", "https://idp.example:https/jwks"),
    ] {
        assert!(
            !UreqJwks::admits(&Issuer::new(issuer), uri, &[]),
            "{uri} is not the origin of {issuer}"
        );
    }
}

/// A host the deployment listed is admitted on the port listed beside it, and on no other.
#[test]
fn a_listed_jwks_host_admits_only_the_port_listed_beside_it() {
    let issuer = Issuer::new("https://idp.example");

    // No port listed: the scheme's default, and nothing else. 2375 is the Docker daemon.
    let bare = ["keys.idp.example".to_owned()];
    assert!(UreqJwks::admits(
        &issuer,
        "https://keys.idp.example/jwks",
        &bare
    ));
    assert!(UreqJwks::admits(
        &issuer,
        "https://keys.idp.example:443/jwks",
        &bare
    ));
    for elsewhere in [
        "https://keys.idp.example:2375/jwks",
        "https://keys.idp.example:8443/jwks",
    ] {
        assert!(
            !UreqJwks::admits(&issuer, elsewhere, &bare),
            "{elsewhere}: a host is a host, not every port on it"
        );
    }

    // A port listed: that one, and not the default.
    let with_port = ["keys.idp.example:8443".to_owned()];
    assert!(UreqJwks::admits(
        &issuer,
        "https://keys.idp.example:8443/jwks",
        &with_port
    ));
    for elsewhere in [
        "https://keys.idp.example/jwks",
        "https://keys.idp.example:443/jwks",
    ] {
        assert!(
            !UreqJwks::admits(&issuer, elsewhere, &with_port),
            "{elsewhere}: the deployment listed one port and this is not it"
        );
    }

    // An entry whose port is not a port names nothing at all.
    assert!(!UreqJwks::admits(
        &issuer,
        "https://keys.idp.example/jwks",
        &["keys.idp.example:https".to_owned()]
    ));
}

/// The loopback guard refuses a name class, not one string — and every spelling of a
/// member of that class, not one spelling of it.
///
/// All 25 rows of the module's own first table are here, and this case is what covers the
/// containment guard: deleting `!literal_address(host) && !loopback(host)` from `admits`
/// turns every one of the 25 red, because the `<host>:443` entry below reaches the list.
/// `127.0.0.1.` and its siblings are the rows that reached `allowed_hosts` before the fold
/// was computed once: `literal_address` trimmed no trailing dot and `loopback` trimmed one
/// for its name halves only, so a dotted literal was an address to neither of them.
#[test]
fn a_listed_host_that_spells_the_loopback_interface_is_refused() {
    let issuer = Issuer::new("https://idp.example");

    for spelling in [
        // The name class, absolute and relative, in either case.
        "localhost",
        "localhost.",
        "localhost..",
        "LOCALHOST",
        "LOCALHOST.",
        "localhost.localdomain",
        "localhost.localdomain.",
        "keys.localdomain",
        "keys.localdomain.",
        // The literal class. The dotted forms are the ones that were admitted.
        "127.0.0.1",
        "127.0.0.1.",
        "127.0.0.1..",
        "127.0.0.2",
        "127.0.0.2.",
        "127.255.255.254.",
        // IPv6 literals, bracketed, zero-compressed and IPv4-mapped. The containment
        // guard runs *before* `allowed_hosts` is consulted, and the `<host>:443` entry
        // built below is what lets these rows reach it at all: an entry without a port is
        // split on its last `:` and names the wrong host, so listing `::1` alone would
        // make every row here green whether or not the guard exists.
        "[::1]",
        "[::1.]",
        "[0:0:0:0:0:0:0:1]",
        "[0:0:0:0:0:0:0:1.]",
        "[0:0::0:1]",
        "[::ffff:127.0.0.1]",
        "[::ffff:127.0.0.1.]",
        "[::ffff:7f00:1]",
        "[::FFFF:7F00:1]",
        "[::127.0.0.1]",
    ] {
        let bare = spelling.trim_matches(|c| c == '[' || c == ']');
        let listed = [
            spelling.to_owned(),
            bare.to_owned(),
            // The only entry form that names an IPv6 destination, and it names every
            // other host here too. Deleting `!literal_address(host) && !loopback(host)`
            // from `admits` turns every row below red *because* of this entry.
            format!("{bare}:443"),
        ];
        assert!(
            !UreqJwks::admits(&issuer, &format!("https://{spelling}/jwks"), &listed),
            "{spelling} is the loopback interface, listed or not"
        );
    }
}

/// The absolute form of a host is the same host, so the destination guard answers the
/// same for both — at every comparison the guard makes about that host.
///
/// This is the class `story:host-spelling-folded` reports — *two checks over one host
/// that fold different spellings will disagree, and the disagreement is what gets
/// through*.
///
/// `admits` compares the destination host in **three** places, and a case that reaches
/// only one of them proves nothing about the other two:
///
/// | # | site | folded |
/// |---|---|---|
/// | 1 | the issuer's own `(host, port)` | yes |
/// | 2 | `literal_address` / `loopback` | yes |
/// | 3 | `listed(entry, &target)` | no, deliberately |
///
/// So every host below is asked twice: once at **site 1**, under the empty host list
/// `JwksSource::jwks` passes (`verifier_real.rs:400`) and under *both* spellings of the
/// issuer, and once at **sites 2 and 3**, against a third-party issuer with the host
/// listed. An earlier version of this case fixed the issuer at a third host and listed
/// both spellings, so every iteration left through sites 2 and 3 and none ever reached
/// site 1 — an enumeration wearing a property's clothes, which is how
/// `tests/adversary_host_spelling_1.rs` found the unfolded comparison. Site 3 is the
/// deliberate exception and is pinned by its own assertion at the end.
///
/// # Why each row states its answer instead of comparing the two spellings
///
/// An `assert_eq!(one_spelling, the_other)` holds when both are refusals, and for 14 of
/// the 16 rows below the containment comparison *is* two refusals — the nine `https` rows
/// whose host is a spelling of the loopback are refused by the guard before
/// `allowed_hosts` is read, and the five `http` rows are refused at
/// `target.scheme == "https"` before that. Only `keys.idp.example` and `idp.example` are
/// admitted there. So the two spellings agreeing would say nothing about the branch this
/// case names, which is what `tests/adversary_host_spelling_2.rs` reported.
///
/// Each row therefore carries the answer the guard owes it, and every comparison below is
/// against that answer rather than against the other spelling. Equality of the two
/// spellings follows, because both are asserted against one constant — and now a row
/// whose answer is a refusal fails when the refusal stops happening. The nine loopback
/// `https` rows die if `!literal_address(host) && !loopback(host)` is deleted, the five
/// `http` rows die if the scheme gate is, and the `("http", "idp.example")` row dies if
/// the loopback condition at `verifier_real.rs:347` is — it is the only row whose
/// own-origin answer is a refusal, which is the rule that plaintext survives on the
/// loopback interface and nowhere else.
#[test]
fn a_trailing_dot_does_not_change_what_the_jwks_destination_guard_answers() {
    let no_hosts_listed: [String; 0] = [];

    // (scheme, host, admitted as the issuer's own origin, admitted when a third party's
    // document names it and the deployment listed it)
    for (scheme, host, is_own_origin, is_admitted_when_listed) in [
        ("https", "localhost", true, false),
        ("https", "localhost.localdomain", true, false),
        ("https", "keys.localdomain", true, false),
        ("https", "127.0.0.1", true, false),
        ("https", "127.0.0.2", true, false),
        ("https", "127.255.255.254", true, false),
        ("https", "keys.idp.example", true, true),
        ("https", "idp.example", true, true),
        ("https", "[::1]", true, false),
        ("https", "[0:0:0:0:0:0:0:1]", true, false),
        ("https", "[::ffff:127.0.0.1]", true, false),
        ("http", "localhost", true, false),
        ("http", "localhost.localdomain", true, false),
        ("http", "127.0.0.1", true, false),
        ("http", "[::1]", true, false),
        // The only row that is neither a spelling of the loopback nor `https`: plaintext
        // off the loopback is not its own origin's key-set source either.
        ("http", "idp.example", false, false),
    ] {
        // The absolute form. For an IPv6 literal the dot goes inside the brackets: the
        // brackets belong to the URI's authority and not to the host.
        let dotted = match host.strip_suffix(']') {
            Some(inside) => format!("{inside}.]"),
            None => format!("{host}."),
        };

        // Site 1, every combination of the two spellings on both sides, so neither side
        // of the comparison is left standing on an unfolded name.
        for issuer_spelling in [host, dotted.as_str()] {
            let issuer = Issuer::new(format!("{scheme}://{issuer_spelling}"));
            for destination in [host, dotted.as_str()] {
                assert_eq!(
                    UreqJwks::admits(
                        &issuer,
                        &format!("{scheme}://{destination}/jwks"),
                        &no_hosts_listed
                    ),
                    is_own_origin,
                    "issuer {scheme}://{issuer_spelling}, destination \
                     {scheme}://{destination}: one host, and this is not the answer the \
                     guard owes it"
                );
            }
        }

        // Sites 2 and 3, against an issuer neither spelling belongs to. `<host>:<port>`
        // is the only entry form that names an IPv6 destination, and it names every
        // other host here too.
        let port = if scheme == "https" { 443 } else { 80 };
        let unbracket = |spelling: &str| spelling.trim_matches(|c| c == '[' || c == ']').to_owned();
        let listed = [
            format!("{}:{port}", unbracket(host)),
            format!("{}:{port}", unbracket(&dotted)),
        ];
        let elsewhere = Issuer::new(format!("{scheme}://third-party.example"));
        for destination in [host, dotted.as_str()] {
            assert_eq!(
                UreqJwks::admits(
                    &elsewhere,
                    &format!("{scheme}://{destination}/jwks"),
                    &listed
                ),
                is_admitted_when_listed,
                "listed {scheme}://{destination}: one host, and this is not the answer \
                 the guard owes it"
            );
        }
    }

    // Two refusals satisfy an equality, so the loopback issuer is asked positively as
    // well. A test's own listener is the only plaintext issuer there is, and the absolute
    // spelling of that listener is the same listener — crossed here, because the
    // discovery document writes `jwks_uri` and does not have to spell the host the way
    // the deployment spelled the issuer.
    for family in [
        ["localhost", "localhost."],
        ["localhost.localdomain", "localhost.localdomain."],
        ["127.0.0.1", "127.0.0.1."],
        ["[::1]", "[::1.]"],
    ] {
        for issuer_spelling in family {
            for target_spelling in family {
                assert!(
                    UreqJwks::admits(
                        &Issuer::new(format!("http://{issuer_spelling}")),
                        &format!("http://{target_spelling}/jwks"),
                        &no_hosts_listed
                    ),
                    "http://{issuer_spelling} and http://{target_spelling} are one \
                     loopback interface, and a plaintext issuer on it reads its own key \
                     set under either spelling"
                );
            }
        }
    }

    // Site 3, the deliberate exception. `allowed_hosts` reads a string an operator wrote
    // down, and it stays exact: folding it would make an entry admit a host it does not
    // name. This is the boundary `story:host-spelling-folded` puts out of scope, and it
    // is the reason the fold lives in `admits` and not in `origin`.
    assert!(
        !UreqJwks::admits(
            &Issuer::new("https://idp.example"),
            "https://keys.idp.example./jwks",
            &["keys.idp.example".to_owned()]
        ),
        "a listed host was widened to a spelling the deployment did not write"
    );
}

/// An `azp` in a shape OIDC does not define is still an `azp`, and it does not name this
/// client.
#[test]
fn an_azp_that_is_not_a_string_is_refused() {
    let rsa = keys(Algorithm::RS256, "one-2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&rsa]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), RS256)]);

    for shape in [
        serde_json::json!([CLIENT]),
        serde_json::json!({ "client": CLIENT }),
        serde_json::json!(42),
        serde_json::json!(null),
        serde_json::json!(true),
    ] {
        let denied = verifier
            .verify(
                &a_connection(ISSUER_ONE),
                &mint(
                    &rsa,
                    &with(claims(ISSUER_ONE, SUBJECT), "azp", shape.clone()),
                ),
            )
            .expect_err("an azp that is not a string does not name this client");
        assert_eq!(denied.reason, DenialReason::AudienceMismatch, "{shape}");
        assert_eq!(
            verifier.refusals().last(),
            Some(&RefusalReason::AuthorizedPartyMismatch),
            "{shape}"
        );
    }
}

/// An `aud` naming this client twice names no other party: the test is membership, not a
/// count.
#[test]
fn an_audience_naming_this_client_more_than_once_names_no_other_party() {
    let rsa = keys(Algorithm::RS256, "one-2026-09");
    let source = InMemoryJwks::new();
    source.publish(&Issuer::new(ISSUER_ONE), key_set(&[&rsa]));
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&source, &clock, &[(connection(1), RS256)]);

    for aud in [
        serde_json::json!([CLIENT]),
        serde_json::json!([CLIENT, CLIENT]),
        serde_json::json!([CLIENT, CLIENT, CLIENT]),
    ] {
        let validated = verifier
            .verify(
                &a_connection(ISSUER_ONE),
                &mint(&rsa, &with(claims(ISSUER_ONE, SUBJECT), "aud", aud.clone())),
            )
            .unwrap_or_else(|denied| {
                panic!("{aud} names this client and nobody else: {denied}");
            });
        assert_eq!(validated.audience().as_str(), CLIENT, "{aud}");
    }
    assert!(
        verifier.refusals().is_empty(),
        "no refusal at all: {:?}",
        verifier.refusals()
    );
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
