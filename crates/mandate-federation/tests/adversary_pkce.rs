//! Adversary pass 1 on `story:pkce-sessions`: the unit's own documents driven against
//! the code the same unit wrote.
//!
//! Three documents are treated as the specification they claim to be:
//!
//! * `crates/mandate-federation/src/pkce.rs:50-56` — `PkceDigest::challenge` "answers
//!   `BASE64URL-ENCODE(SHA256(ASCII(verifier)))` for the verifier it is given and nothing
//!   else", and `:38-39` declares `CHALLENGE_LENGTH` to be "a 32-byte digest in unpadded
//!   base64url".
//! * `systems/mandate/domains/federation.yaml:299-300` — the declared denial of
//!   `AuthorizePublicClient` names "target is unregistered/outside tenant".
//! * `.engineering/planning/story/pkce-sessions.md`, "ESS command realized" — this
//!   story's `authorize` unit realizes "every validation its denial clause names —
//!   session proof, registered public client, exact redirect, state and applicable
//!   nonce, S256 challenge, registered target inside the tenant".
//!
//! Nothing here consumes a code, creates a credential or writes to a read model, and no
//! value below is credential material: the one real verifier is RFC 7636 appendix B's
//! published test vector and the rest are synthetic markers in the declared form.

use mandate_federation::authorize::{
    AuthorizationCode, AuthorizationCodeState, PresentedRedemption, RequestBinding,
    ValidateAuthorizationCode, validate_authorization_code,
};
use mandate_federation::pkce::{
    PkceDigest, StandInDigest, challenge_is_well_formed, verifier_is_well_formed, verify_pkce,
};
use mandate_federation::publicclient::{RecordedClients, registered_public_client};
use mandate_federation::record::{OAuthClient, OAuthClientState};
use mandate_federation::{DenialClause, RequestContext};
use mandate_identity::{Generation, IdentityEvent, IdentityLog, SecurityEpochSnapshot, Session};
use mandate_types::value::Uuid;
use mandate_types::{
    Action, Audience, AuthorityScope, AuthorizationCodeId, CorrelationId, CredentialId,
    CredentialProof, DenialReason, OAuthClientId, OrganizationId, PkceChallenge, PkceMethod,
    PrincipalId, RedirectUri, ResourceServerId, SecurityEpochTarget, SessionId, Timestamp,
};

/// RFC 7636 appendix B: this verifier digests to this challenge under S256. A published
/// test vector, not credential material; `bins/mandate/tests/cli.rs:14-15` pins the same
/// pair against the binary's real `sha2` implementation.
const RFC_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const RFC_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// The unpadded base64url alphabet, in order (RFC 4648 section 5).
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Decode unpadded base64url, answering `None` for text that is the encoding of no value.
///
/// RFC 4648 section 3.5: the pad bits of the final quantum are zero. A 32-byte value is
/// 256 bits, its unpadded encoding is 43 characters — 258 bits — so the final character
/// carries four significant bits and two pad bits that must both be zero. A 43-character
/// base64url string whose final character has either pad bit set decodes to nothing at
/// all, and in particular is the S256 challenge of no verifier whatsoever.
fn decode_base64url(text: &str) -> Option<Vec<u8>> {
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    let mut bytes = Vec::new();
    for character in text.bytes() {
        let index = ALPHABET.iter().position(|entry| *entry == character)?;
        accumulator = (accumulator << 6) | u32::try_from(index).ok()?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push(u8::try_from((accumulator >> bits) & 0xff).ok()?);
        }
    }
    if bits >= 6 || accumulator & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(bytes)
}

/// A [`PkceDigest`] that answers the one published pair and a fixed well-formed value for
/// anything else: the appendix B vector carried through the predicate without this crate
/// linking `sha2`.
struct AppendixBDigest;

impl PkceDigest for AppendixBDigest {
    fn challenge(&self, verifier: &CredentialProof) -> PkceChallenge {
        if verifier.expose_bytes() == RFC_VERIFIER.as_bytes() {
            PkceChallenge::new(RFC_CHALLENGE)
        } else {
            // A well-formed challenge that decodes to 32 bytes and is not the vector's.
            PkceChallenge::new("DwBzhbb51LfusnSGBa_hqYSgo7-j8BTQnip4TOnlzRo")
        }
    }
}

fn rfc_verifier() -> CredentialProof {
    CredentialProof::from_bytes(RFC_VERIFIER.as_bytes().to_vec())
}

/// A synthetic marker in the declared form, built exactly as the unit's own fixtures are
/// (`crates/mandate-federation/tests/pkce.rs:26-32`).
fn verifier(name: &str) -> CredentialProof {
    let mut text = format!("mandate-test-verifier-{name}");
    while text.len() < 43 {
        text.push('~');
    }
    CredentialProof::from_bytes(text.into_bytes())
}

// ---------------------------------------------------------------------------
// The digest port's own contract, against the double the whole suite runs on.
// ---------------------------------------------------------------------------

/// The decoder above is checked against the one value both halves of this change agree
/// on, so that the red case below cannot be a bug in the decoder.
#[test]
fn the_appendix_b_challenge_decodes_to_a_thirty_two_byte_digest() {
    assert_eq!(
        decode_base64url(RFC_CHALLENGE).map(|bytes| bytes.len()),
        Some(32)
    );
    assert!(challenge_is_well_formed(&PkceChallenge::new(RFC_CHALLENGE)));
    assert!(verifier_is_well_formed(&rfc_verifier()));
}

/// `src/pkce.rs:50-56`: an implementation of [`PkceDigest`] "answers
/// `BASE64URL-ENCODE(SHA256(ASCII(verifier)))` for the verifier it is given and nothing
/// else". [`StandInDigest`] implements that trait and is the only implementation this
/// crate has, so every positive case in `tests/pkce.rs` and `tests/authorize.rs` records
/// its output as the challenge. Its output is not the base64url encoding of any 32-byte
/// value, and therefore is the S256 challenge of nothing.
#[test]
fn every_challenge_the_digest_port_answers_is_the_encoding_of_a_thirty_two_byte_digest() {
    for name in ["one", "two", "three", "four", "five", "six"] {
        let challenge = StandInDigest.challenge(&verifier(name));

        assert_eq!(
            decode_base64url(challenge.as_str()).map(|bytes| bytes.len()),
            Some(32),
            "the port answers BASE64URL-ENCODE(SHA256(..)) or it is not that port: {name} -> {challenge}"
        );
    }
}

/// `src/pkce.rs:38-39` declares the challenge form to be "a 32-byte digest in unpadded
/// base64url" and `challenge_is_well_formed` is the guard that decides it. Three of every
/// four 43-character base64url strings decode to no value at all; the guard admits them,
/// so a recorded challenge that no verifier on earth can redeem is carried past the
/// "S256 challenge is absent/invalid" refusal and into a digest comparison.
#[test]
fn a_challenge_that_is_the_encoding_of_nothing_is_refused_as_malformed() {
    // The appendix B challenge with its final character advanced one place along the
    // alphabet: still 43 characters of base64url, and now the encoding of no value.
    let impossible = PkceChallenge::new("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cN");
    assert_eq!(
        decode_base64url(impossible.as_str()),
        None,
        "the premise: this is the base64url encoding of nothing"
    );

    assert!(
        !challenge_is_well_formed(&impossible),
        "a value that is the encoding of no 32-byte digest is not an S256 challenge: {impossible}"
    );

    let denied = verify_pkce(
        &impossible,
        PkceMethod::S256,
        Some(&rfc_verifier()),
        &AppendixBDigest,
    )
    .expect_err("an impossible challenge is absent/invalid");
    assert_eq!(denied.clause, DenialClause::ChallengeMalformed);
}

/// The predicate admits the one pair that a real S256 implementation produces. This is
/// the only place in the change where the library predicate meets a challenge the binary
/// would actually print.
#[test]
fn the_predicate_admits_the_appendix_b_pair() {
    let admitted = verify_pkce(
        &PkceChallenge::new(RFC_CHALLENGE),
        PkceMethod::S256,
        Some(&rfc_verifier()),
        &AppendixBDigest,
    );

    assert_eq!(admitted, Ok(()));
}

/// `plain` smuggled through the one declared method: the recorded challenge is the
/// verifier itself, which is 43 characters of the base64url alphabet and so passes the
/// form guard. Presenting the verifier must still be refused.
#[test]
fn a_verifier_recorded_as_its_own_challenge_is_not_redeemed_by_presenting_it() {
    let plain = PkceChallenge::new(RFC_VERIFIER);
    assert!(
        challenge_is_well_formed(&plain),
        "the premise: a plain-method challenge passes the S256 form guard"
    );

    let denied = verify_pkce(
        &plain,
        PkceMethod::S256,
        Some(&rfc_verifier()),
        &AppendixBDigest,
    )
    .expect_err("`plain` is not a method this system has");

    assert_eq!(denied.clause, DenialClause::VerifierMismatch);
}

/// RFC 7636 section 4.1 gives the verifier length as 43 to 128 inclusive. The unit's own
/// cases exercise 0, 9 and 129; the two boundaries themselves and the value one below the
/// minimum are not exercised anywhere.
#[test]
fn the_verifier_length_boundaries_are_exactly_forty_three_and_one_hundred_and_twenty_eight() {
    for length in [43_usize, 128] {
        let admitted = CredentialProof::from_bytes(vec![b'a'; length]);
        assert!(
            verifier_is_well_formed(&admitted),
            "RFC 7636 section 4.1 admits a verifier of {length} characters"
        );
    }
    for length in [0_usize, 1, 42, 129, 256] {
        let refused = CredentialProof::from_bytes(vec![b'a'; length]);
        assert!(
            !verifier_is_well_formed(&refused),
            "RFC 7636 section 4.1 refuses a verifier of {length} characters"
        );
    }
}

/// A verifier carrying a byte outside the unreserved set is refused for its form, whether
/// the byte is at the end, in the middle, or is a NUL.
#[test]
fn a_verifier_carrying_a_byte_outside_the_unreserved_set_is_refused() {
    let base = [b'a'; 43];
    for (label, trailing) in [
        ("space", b' '),
        ("tab", b'\t'),
        ("newline", b'\n'),
        ("carriage return", b'\r'),
        ("nul", 0),
        ("plus", b'+'),
        ("slash", b'/'),
        ("equals", b'='),
        ("percent", b'%'),
    ] {
        let mut material = base.to_vec();
        material.push(trailing);
        assert!(
            !verifier_is_well_formed(&CredentialProof::from_bytes(material.clone())),
            "a trailing {label} is not in the unreserved set"
        );

        let mut interior = base.to_vec();
        interior[20] = trailing;
        assert!(
            !verifier_is_well_formed(&CredentialProof::from_bytes(interior)),
            "an interior {label} is not in the unreserved set"
        );
    }
}

// ---------------------------------------------------------------------------
// The command: the declared denial condition nothing decides.
// ---------------------------------------------------------------------------

const REGISTERED: &str = "https://app.example/callback";
const NOW: &str = "2026-09-18T12:00:00Z";
const LATER: &str = "2026-09-18T12:05:00Z";
const STATE: &str = "state-from-the-authorization-request";
const NONCE: &str = "nonce-from-the-authorization-request";

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(10))
}

fn principal() -> PrincipalId {
    PrincipalId::new(uuid(0xa1))
}

fn session_id() -> SessionId {
    SessionId::new(uuid(0x5e))
}

fn client_id() -> OAuthClientId {
    OAuthClientId::new(uuid(0x0c))
}

fn code_id() -> AuthorizationCodeId {
    AuthorizationCodeId::new(uuid(0xc0))
}

fn scope() -> AuthorityScope {
    AuthorityScope {
        actions: vec![Action::new("read")],
        resources: Vec::new(),
        space: None,
    }
}

fn request() -> RequestContext {
    RequestContext {
        audience: Audience::new("mandate"),
        correlation: CorrelationId::new("adversary-pkce"),
        credential: CredentialId::new(uuid(0xcd)),
        at: Timestamp::new(NOW),
    }
}

fn clients() -> RecordedClients {
    RecordedClients::new()
        .with_client(OAuthClient {
            id: client_id(),
            organization_id: organization(),
            public: true,
            redirect_uris: vec![RedirectUri::new(REGISTERED)],
            pkce_method: PkceMethod::S256,
            state: OAuthClientState::Recorded,
        })
        // Added by the correction round for F3: the double now answers the registered
        // target read model too, and `uuid(0x7a)` is the target the cases below expect to
        // validate. No assertion in this file is changed.
        .with_target(ResourceServerId::new(uuid(0x7a)), organization())
}

fn sessions() -> IdentityLog {
    let handle = mandate_types::EpochSnapshotRef::new(uuid(0x3e));
    let mut log = IdentityLog::new();
    log.record(IdentityEvent::SecurityEpochRecorded {
        target: SecurityEpochTarget::Principal(principal()),
        generation: Generation::new(3).expect("a declared generation"),
    });
    log.record(IdentityEvent::SecurityEpochRecorded {
        target: SecurityEpochTarget::Organization(organization()),
        generation: Generation::new(2).expect("a declared generation"),
    });
    log.record(IdentityEvent::EpochSnapshotRecorded(
        SecurityEpochSnapshot::new(
            handle,
            principal(),
            Generation::new(3).expect("a declared generation"),
            organization(),
            Generation::new(2).expect("a declared generation"),
        ),
    ));
    log.record(IdentityEvent::SessionOpened(Session::new(
        session_id(),
        principal(),
        organization(),
        handle,
        Timestamp::new("2026-12-31T00:00:00Z"),
    )));
    log
}

fn code(target: ResourceServerId) -> AuthorizationCode {
    AuthorizationCode {
        id: code_id(),
        client_id: client_id(),
        session_id: session_id(),
        challenge: PkceChallenge::new(RFC_CHALLENGE),
        method: PkceMethod::S256,
        redirect_uri: RedirectUri::new(REGISTERED),
        expires_at: Timestamp::new(LATER),
        target,
        scope: scope(),
        state: AuthorizationCodeState::Issued,
    }
}

fn input(target: ResourceServerId) -> ValidateAuthorizationCode {
    ValidateAuthorizationCode {
        code: code(target),
        binding: RequestBinding {
            state: STATE.to_owned(),
            // Added by the correction round for F8: the recorded nonce is a required
            // `String` (`federation.yaml:281-282`). No assertion in this file is changed.
            nonce: NONCE.to_owned(),
        },
        presented: PresentedRedemption {
            redirect_uri: RedirectUri::new(REGISTERED),
            verifier: Some(rfc_verifier()),
            state: STATE.to_owned(),
            nonce: Some(NONCE.to_owned()),
        },
    }
}

/// `federation.yaml:299-300` names "target is unregistered/outside tenant" among the
/// declared denial conditions of `AuthorizePublicClient`, and this story's "ESS command
/// realized" section claims its `authorize` unit realizes "every validation its denial
/// clause names ... registered target inside the tenant". Nothing reads `code.target`:
/// whatever it names is copied into `ValidationCandidate::issuance` unexamined, and every
/// `ResourceServerId` in existence validates.
#[test]
fn a_target_outside_the_verified_tenant_is_refused() {
    let unregistered = ResourceServerId::new(uuid(0xff));
    let input = input(unregistered);

    let outcome = validate_authorization_code(
        &input,
        &request(),
        &clients(),
        &clients(),
        &sessions(),
        &AppendixBDigest,
    );

    assert!(
        outcome.is_err(),
        "an unregistered target is a declared denial condition; instead the candidate carries it: {:?}",
        outcome.map(|candidate| candidate.issuance.target)
    );
}

/// The complement, so that the case above cannot be read as a fixture that happens not to
/// register anything: two targets that differ in every byte both validate, which is what
/// "nothing decides the target" looks like from the outside.
#[test]
fn two_different_targets_do_not_both_validate() {
    let first = validate_authorization_code(
        &input(ResourceServerId::new(uuid(0x7a))),
        &request(),
        &clients(),
        &clients(),
        &sessions(),
        &AppendixBDigest,
    );
    let second = validate_authorization_code(
        &input(ResourceServerId::new(uuid(0xff))),
        &request(),
        &clients(),
        &clients(),
        &sessions(),
        &AppendixBDigest,
    );

    assert!(
        !(first.is_ok() && second.is_ok()),
        "every target validates, so no target is decided"
    );
}

// ---------------------------------------------------------------------------
// Probes that hold. Kept so a reader can see what was attacked and did not move.
// ---------------------------------------------------------------------------

/// The exact-match rule under the comparisons an OAuth deployment most often relaxes.
#[test]
fn no_redirect_normalization_admits_an_unregistered_uri() {
    for presented in [
        "https://app.example/callback/",
        "https://app.example:443/callback",
        "HTTPS://app.example/callback",
        "https://App.Example/callback",
        "https://app.example/call%62ack",
        "https://app.example/callback?a=1&b=2",
        "https://app.example/callback?b=2&a=1",
        "https://app.example//callback",
        "https://app.example/./callback",
        "http://localhost/callback",
        "http://127.0.0.1/callback",
        "https://app.example/callback ",
        " https://app.example/callback",
        "https://app.example/callback\n",
    ] {
        let denied = registered_public_client(
            &clients(),
            &client_id(),
            &RedirectUri::new(presented),
            &organization(),
        )
        .expect_err("only a byte-identical redirect is registered");

        assert_eq!(denied.reason, DenialReason::Denied);
        assert_eq!(denied.clause, DenialClause::RedirectMismatch, "{presented}");
    }
}

/// A request instant that names no instant cannot date anything, and must not admit a
/// code. It fails closed, and names the code rather than the reader when it does.
#[test]
fn a_request_instant_that_names_no_instant_admits_nothing() {
    for at in ["", "not-a-timestamp", "2026-09-18", "2026-09-18T12:00:00"] {
        let request = RequestContext {
            at: Timestamp::new(at),
            ..request()
        };

        let denied = validate_authorization_code(
            &input(ResourceServerId::new(uuid(0x7a))),
            &request,
            &clients(),
            &clients(),
            &sessions(),
            &AppendixBDigest,
        )
        .expect_err("an undated reader cannot certify a code unexpired");

        assert_eq!(denied.clause, DenialClause::CodeExpired, "{at}");
    }
}

/// Non-consuming, twice over, and against a record another transaction has since moved:
/// the second validation of an unchanged record still succeeds, and the candidate names
/// the code identity the STS transaction needs to consume.
#[test]
fn a_candidate_survives_a_second_validation_and_names_the_code_it_validated() {
    let input = input(ResourceServerId::new(uuid(0x7a)));
    let first = validate_authorization_code(
        &input,
        &request(),
        &clients(),
        &clients(),
        &sessions(),
        &AppendixBDigest,
    )
    .expect("the first caller validates");
    let second = validate_authorization_code(
        &input,
        &request(),
        &clients(),
        &clients(),
        &sessions(),
        &AppendixBDigest,
    )
    .expect("the record is unchanged, so the second caller validates too");

    assert_eq!(first, second);
    assert_eq!(first.code_id, code_id());

    let consumed = ValidateAuthorizationCode {
        code: AuthorizationCode {
            state: AuthorizationCodeState::Consumed,
            ..input.code.clone()
        },
        ..input
    };
    let denied = validate_authorization_code(
        &consumed,
        &request(),
        &clients(),
        &clients(),
        &sessions(),
        &AppendixBDigest,
    )
    .expect_err("a consumed record is refused");

    assert_eq!(denied.clause, DenialClause::CodePreviouslyRedeemed);
}
