//! Adversary pass 2 on `story:pkce-sessions`: the corrections of round 1, driven against
//! the documents that justify them.
//!
//! What round 1 changed and what is asked of it here:
//!
//! * `pkce.rs` now decides the challenge form by decoding rather than by length. The
//!   guard is checked here against challenges computed outside this workspace, and
//!   against every one of the 64 possible final characters, so that it is pinned by
//!   something other than a second copy of its own decoder.
//! * `StandInDigest` now encodes 32 derived bytes. Its determinism and its separation of
//!   near-identical verifiers are exercised, and the size of the space it actually draws
//!   from is recorded.
//! * `authorize.rs` gained a `TargetRegistry` port and widened the command's read-model
//!   parameter to `impl OAuthClientStore + TargetRegistry`. The precedent the change
//!   cites — `authenticate_federation`'s `impl ConnectionStore + PrincipalStore` — is
//!   checked against the crate's own fold, and so is the new bound.
//!
//! Nothing here consumes a code, creates a credential or writes to a read model.

use mandate_federation::authorize::{
    AuthorizationCode, AuthorizationCodeState, PresentedRedemption, RequestBinding, TargetRegistry,
    ValidateAuthorizationCode, validate_authorization_code,
};
use mandate_federation::pkce::{PkceDigest, StandInDigest, challenge_is_well_formed};
use mandate_federation::publicclient::RecordedClients;
use mandate_federation::record::{OAuthClient, OAuthClientState, Projection};
use mandate_federation::{ConnectionStore, DenialClause, PrincipalStore, RequestContext};
use mandate_identity::{Generation, IdentityEvent, IdentityLog, SecurityEpochSnapshot, Session};
use mandate_types::value::Uuid;
use mandate_types::{
    Action, Audience, AuthorityScope, AuthorizationCodeId, CorrelationId, CredentialId,
    CredentialProof, DenialReason, OAuthClientId, OrganizationId, PkceChallenge, PkceMethod,
    PrincipalId, RedirectUri, ResourceServerId, SecurityEpochTarget, SessionId, Timestamp,
};

/// The unpadded base64url alphabet, in order (RFC 4648 section 5).
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// RFC 7636 appendix B's published pair.
const RFC_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const RFC_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// Verifier/challenge pairs computed outside this workspace with CPython's
/// `hashlib.sha256` and `base64.urlsafe_b64encode`. Every one of them is a value a real
/// S256 implementation answers, so every one of them must pass the form guard.
const REAL_CHALLENGES: &[&str] = &[
    RFC_CHALLENGE,
    "DwBzhbb51LfusnSGBa_hqYSgo7-j8BTQnip4TOnlzRo",
    "dOHT1ivLVSPsewADt8TAZF2T2lLYTZ4BymCwTRKpihg",
    "rpMOCY0WfS5THycY5m5x09DbL6TMXzEQKrMRc1ncehQ",
    "RXJXkcR7MmGMxXuIND4rzuw7CgG4O8l9FEosvBGiDD0",
    "mFVGhQ_rf1id3gzc0aGLOMRg2bZah_2Oh0gO3y_FwuY",
    "dk0JOgDnoRl5J0qSsTycnDIruUao-lgSVQf36xDyXaY",
    "Y70fIUCZbil-iISRzVlZiOsj2Wp7-t5aXMz2bKocmSg",
    "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
    "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0",
];

// ---------------------------------------------------------------------------
// Does the crate's own fold satisfy the bound the command now requires?
// ---------------------------------------------------------------------------

/// Whether a type implements [`TargetRegistry`], answered at compile time and returned at
/// run time.
///
/// Rust has no negative reasoning, so a test cannot say "this does not implement that"
/// without failing to compile — and a case that fails to compile takes the whole file
/// with it and reports nothing. Method resolution supplies the answer instead: the
/// receiver `&Probe<T>` is tried by value first, which reaches [`ImplementsRegistry`]
/// only when the bound holds, and otherwise autoref falls through to
/// [`RegistryUnimplemented`]. The type has to be named at the call site: inside a generic
/// function the bound is opaque and the fallback would always win.
mod registry_probe {
    use core::marker::PhantomData;

    use mandate_federation::authorize::TargetRegistry;
    use mandate_federation::publicclient::RecordedClients;
    use mandate_federation::record::Projection;

    pub struct Probe<T>(pub PhantomData<T>);

    pub trait ImplementsRegistry {
        fn answer(&self) -> bool;
    }

    impl<T: TargetRegistry> ImplementsRegistry for Probe<T> {
        fn answer(&self) -> bool {
            true
        }
    }

    // Lint-only, added by the correction round: with `TargetRegistry` implemented for
    // both probed types the fallback is never selected, and `-D warnings` refuses a trait
    // nothing reaches. The fallback is the half of the probe that would answer `false`,
    // so it is kept rather than deleted. No assertion is changed.
    #[allow(dead_code)]
    pub trait RegistryUnimplemented {
        fn answer(&self) -> bool;
    }

    impl<T> RegistryUnimplemented for &Probe<T> {
        fn answer(&self) -> bool {
            false
        }
    }

    /// Whether the crate's fold implements the new port.
    // Lint-only, added by the correction round: the borrow is the probe's mechanism —
    // method resolution tries the receiver by value first and autoref supplies the
    // fallback — so `clippy::needless_borrow` is answering a question this call is not
    // asking. No assertion is changed.
    #[allow(clippy::needless_borrow)]
    #[must_use]
    pub fn projection_is_a_target_registry() -> bool {
        (&Probe::<Projection>(PhantomData)).answer()
    }

    /// Whether the test double does — the probe's own sanity check.
    // Lint-only, added by the correction round; see the note above.
    #[allow(clippy::needless_borrow)]
    #[must_use]
    pub fn recorded_clients_is_a_target_registry() -> bool {
        (&Probe::<RecordedClients>(PhantomData)).answer()
    }
}

use registry_probe::{projection_is_a_target_registry, recorded_clients_is_a_target_registry};

/// The precedent the correction cites: `authenticate_federation` takes one argument bound
/// by two read models, and the crate's own fold satisfies both. This compiles, which is
/// the whole assertion.
fn accepts_the_precedents_bound(_read_model: &(impl ConnectionStore + PrincipalStore)) {}

/// `validate_authorization_code` now takes `&(impl OAuthClientStore + TargetRegistry)`,
/// citing `authenticate_federation`'s `&(impl ConnectionStore + PrincipalStore)` as the
/// shape. In the precedent the crate's fold satisfies the whole bound
/// (`record.rs:565`, `:584`); in the new one it implements `OAuthClientStore`
/// (`publicclient.rs:43`) and nothing implements `TargetRegistry` but the test double
/// (`publicclient.rs:162`), so the only read model that can reach the command is the
/// fixture, and the seam `tests/publicclient.rs` exists to demonstrate does not connect
/// to it.
#[test]
fn the_crates_own_fold_satisfies_the_bound_the_command_requires() {
    accepts_the_precedents_bound(&Projection::default());

    assert!(
        recorded_clients_is_a_target_registry(),
        "the probe itself: the double does implement TargetRegistry"
    );

    assert!(
        projection_is_a_target_registry(),
        "Projection implements OAuthClientStore but not TargetRegistry, so the real read \
         model cannot be passed to validate_authorization_code at all"
    );
}

// ---------------------------------------------------------------------------
// The challenge form guard, pinned by something other than its own decoder.
// ---------------------------------------------------------------------------

/// Ten challenges a real S256 implementation answered, computed outside this workspace.
#[test]
fn every_real_s256_challenge_passes_the_form_guard() {
    for challenge in REAL_CHALLENGES {
        assert!(
            challenge_is_well_formed(&PkceChallenge::new(*challenge)),
            "a value a real SHA-256 produced is an S256 challenge: {challenge}"
        );
    }
}

/// The guard's whole content, stated without reference to its implementation: of the 64
/// characters that may end a 43-character base64url string, exactly the 16 whose alphabet
/// index is a multiple of four leave the two pad bits of the final quantum zero, and only
/// those 16 are the encoding of a 32-byte value. This fails if the guard is loosened back
/// to a length check and also if it is tightened past the standard.
#[test]
fn exactly_sixteen_of_the_sixty_four_final_characters_are_admitted() {
    let prefix = &RFC_CHALLENGE[..42];
    let mut admitted = Vec::new();

    for (index, character) in ALPHABET.iter().enumerate() {
        let candidate = PkceChallenge::new(format!("{prefix}{}", char::from(*character)));
        let well_formed = challenge_is_well_formed(&candidate);

        assert_eq!(
            well_formed,
            index % 4 == 0,
            "final character {} at alphabet index {index}",
            char::from(*character)
        );
        if well_formed {
            admitted.push(index);
        }
    }

    assert_eq!(admitted.len(), 16);
}

/// Every shape that is not the unpadded base64url encoding of 32 bytes, including the
/// padded 44-character form, the standard alphabet's `+` and `/`, and lengths that decode
/// to 31 or 33 bytes.
#[test]
fn nothing_but_forty_three_canonical_characters_is_admitted() {
    let padded = format!("{RFC_CHALLENGE}=");
    let longer = format!("{RFC_CHALLENGE}AA");
    let shorter = &RFC_CHALLENGE[..41];
    let interior_padding = format!("{}={}", &RFC_CHALLENGE[..20], &RFC_CHALLENGE[21..]);
    let plus = RFC_CHALLENGE.replacen('-', "+", 1);
    // The appendix B challenge carries no `_`, so the standard alphabet's `/` is put in
    // by position rather than by replacing one.
    let slash = format!("{}/{}", &RFC_CHALLENGE[..10], &RFC_CHALLENGE[11..]);
    let spaced = format!(" {RFC_CHALLENGE}");
    let trailing_space = format!("{RFC_CHALLENGE} ");
    let newline = format!("{RFC_CHALLENGE}\n");
    let unicode = format!("{}é", &RFC_CHALLENGE[..42]);

    for malformed in [
        "",
        "=",
        padded.as_str(),
        longer.as_str(),
        shorter,
        interior_padding.as_str(),
        plus.as_str(),
        slash.as_str(),
        spaced.as_str(),
        trailing_space.as_str(),
        newline.as_str(),
        unicode.as_str(),
    ] {
        assert!(
            !challenge_is_well_formed(&PkceChallenge::new(malformed)),
            "not the encoding of a 32-byte digest: {malformed:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// The stand-in digest after the correction.
// ---------------------------------------------------------------------------

fn verifier(text: &str) -> CredentialProof {
    CredentialProof::from_bytes(text.as_bytes().to_vec())
}

/// One character changed, in each of the 43 positions, must give 43 distinct challenges,
/// every one of them in the declared form.
#[test]
fn near_identical_verifiers_get_distinct_well_formed_challenges() {
    let base = "a".repeat(43);
    let mut seen = Vec::new();

    for position in 0..43 {
        let mut material = base.clone().into_bytes();
        material[position] = b'b';
        let challenge = StandInDigest.challenge(&CredentialProof::from_bytes(material));

        assert!(
            challenge_is_well_formed(&challenge),
            "the port answers a challenge in the declared form: {challenge}"
        );
        assert!(
            !seen.contains(&challenge),
            "position {position} collides with an earlier one: {challenge}"
        );
        seen.push(challenge);
    }

    assert_eq!(seen.len(), 43);
}

#[test]
fn the_stand_in_digest_is_deterministic() {
    for text in [RFC_VERIFIER, &"z".repeat(128), &"-._~".repeat(11)] {
        assert_eq!(
            StandInDigest.challenge(&verifier(text)),
            StandInDigest.challenge(&verifier(text))
        );
    }
}

/// What the double actually draws from, recorded rather than refused: the challenge is a
/// function of `fnv1a(verifier) | 1` alone, so it carries 63 bits and not 256, and this
/// test predicts it exactly from a reimplementation of that one 64-bit state. A fixture
/// may be weak; a reader should not have to discover how weak by reading it.
#[test]
fn the_stand_in_digest_is_a_function_of_one_sixty_four_bit_state() {
    for text in [
        RFC_VERIFIER,
        "a".repeat(43).as_str(),
        "-._~".repeat(11).as_str(),
    ] {
        let mut state = fnv1a(text.as_bytes()) | 1;
        let mut derived = [0_u8; 32];
        for byte in &mut derived {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = u8::try_from(state & 0xff).expect("a masked byte");
        }

        assert_eq!(
            StandInDigest.challenge(&verifier(text)).as_str(),
            encode_base64url(&derived),
            "the challenge is determined by the 64-bit state alone"
        );
    }
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn encode_base64url(bytes: &[u8]) -> String {
    let mut text = String::new();
    for chunk in bytes.chunks(3) {
        let mut accumulator = 0_u32;
        for (index, byte) in chunk.iter().enumerate() {
            accumulator |= u32::from(*byte) << (16 - 8 * index);
        }
        for index in 0..=chunk.len() {
            text.push(char::from(
                ALPHABET[((accumulator >> (18 - 6 * index)) & 63) as usize],
            ));
        }
    }
    text
}

// ---------------------------------------------------------------------------
// The target registry, and the refusal order around it.
// ---------------------------------------------------------------------------

const REGISTERED: &str = "https://app.example/callback";
const OTHER_REGISTERED: &str = "https://app.example/other";
const NOW: &str = "2026-09-19T12:00:00Z";
const LATER: &str = "2026-09-19T12:05:00Z";
const STATE: &str = "state-from-the-authorization-request";
const NONCE: &str = "nonce-from-the-authorization-request";

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(10))
}

fn other_organization() -> OrganizationId {
    OrganizationId::new(uuid(11))
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

fn target() -> ResourceServerId {
    ResourceServerId::new(uuid(0x7a))
}

fn request() -> RequestContext {
    RequestContext {
        audience: Audience::new("mandate"),
        correlation: CorrelationId::new("adversary-pkce-2"),
        credential: CredentialId::new(uuid(0xcd)),
        at: Timestamp::new(NOW),
    }
}

fn client() -> OAuthClient {
    OAuthClient {
        id: client_id(),
        organization_id: organization(),
        public: true,
        redirect_uris: vec![
            RedirectUri::new(REGISTERED),
            RedirectUri::new(OTHER_REGISTERED),
        ],
        pkce_method: PkceMethod::S256,
        state: OAuthClientState::Recorded,
    }
}

fn read_model() -> RecordedClients {
    RecordedClients::new()
        .with_client(client())
        .with_target(target(), organization())
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
        Timestamp::new("2027-12-31T00:00:00Z"),
    )));
    log
}

fn code() -> AuthorizationCode {
    AuthorizationCode {
        id: AuthorizationCodeId::new(uuid(0xc0)),
        client_id: client_id(),
        session_id: session_id(),
        challenge: StandInDigest.challenge(&verifier(RFC_VERIFIER)),
        method: PkceMethod::S256,
        redirect_uri: RedirectUri::new(REGISTERED),
        expires_at: Timestamp::new(LATER),
        target: target(),
        scope: AuthorityScope {
            actions: vec![Action::new("read")],
            resources: Vec::new(),
            space: None,
        },
        state: AuthorizationCodeState::Issued,
    }
}

fn input() -> ValidateAuthorizationCode {
    ValidateAuthorizationCode {
        code: code(),
        binding: RequestBinding {
            state: STATE.to_owned(),
            nonce: NONCE.to_owned(),
        },
        presented: PresentedRedemption {
            redirect_uri: RedirectUri::new(REGISTERED),
            verifier: Some(verifier(RFC_VERIFIER)),
            state: STATE.to_owned(),
            nonce: Some(NONCE.to_owned()),
        },
    }
}

#[test]
fn the_corrected_command_admits_a_registered_target_of_the_verified_tenant() {
    let candidate = validate_authorization_code(
        &input(),
        &request(),
        &read_model(),
        &read_model(),
        &sessions(),
        &StandInDigest,
    )
    .expect("every declared condition is met");

    assert_eq!(candidate.issuance.target, target());
}

/// The two halves of "target is unregistered/outside tenant" carry different clauses and
/// different declared reasons.
#[test]
fn an_unregistered_target_and_a_foreign_one_are_refused_apart() {
    let unregistered = RecordedClients::new().with_client(client());
    let denied = validate_authorization_code(
        &input(),
        &request(),
        &unregistered,
        &unregistered,
        &sessions(),
        &StandInDigest,
    )
    .expect_err("a target the registry does not answer for is unregistered");
    assert_eq!(denied.reason, DenialReason::Denied);
    assert_eq!(denied.clause, DenialClause::TargetUnknown);

    let foreign = RecordedClients::new()
        .with_client(client())
        .with_target(target(), other_organization());
    let denied = validate_authorization_code(
        &input(),
        &request(),
        &foreign,
        &foreign,
        &sessions(),
        &StandInDigest,
    )
    .expect_err("a target registered to another organization is outside the tenant");
    assert_eq!(denied.reason, DenialReason::TenantMismatch);
    assert_eq!(denied.clause, DenialClause::TargetOutsideTenant);
}

/// Two conditions wrong at once: the order the refusals are decided in is fixed and is
/// the one the function documents, so a caller cannot learn about the target by choosing
/// a redirect that is also wrong.
#[test]
fn the_refusal_order_is_stable_when_two_conditions_fail_together() {
    let unregistered_target = RecordedClients::new().with_client(client());

    let wrong_redirect = ValidateAuthorizationCode {
        presented: PresentedRedemption {
            redirect_uri: RedirectUri::new(OTHER_REGISTERED),
            ..input().presented
        },
        ..input()
    };
    for _ in 0..3 {
        let denied = validate_authorization_code(
            &wrong_redirect,
            &request(),
            &unregistered_target,
            &unregistered_target,
            &sessions(),
            &StandInDigest,
        )
        .expect_err("both the redirect and the target are wrong");
        assert_eq!(denied.clause, DenialClause::RedirectMismatch);
    }

    let wrong_state = ValidateAuthorizationCode {
        presented: PresentedRedemption {
            state: "another-state".to_owned(),
            ..input().presented
        },
        ..input()
    };
    let denied = validate_authorization_code(
        &wrong_state,
        &request(),
        &unregistered_target,
        &unregistered_target,
        &sessions(),
        &StandInDigest,
    )
    .expect_err("both the state and the target are wrong");
    assert_eq!(
        denied.clause,
        DenialClause::TargetUnknown,
        "the target is decided before the state, as the function documents"
    );
}

/// The double admits one target twice and answers the first registration, silently. A
/// fixture that registers a target to two organizations gets a pass from whichever it
/// wrote first, which is not a property any real registry would have.
#[test]
fn the_double_answers_the_first_of_two_registrations_of_one_target() {
    let ambiguous = RecordedClients::new()
        .with_client(client())
        .with_target(target(), organization())
        .with_target(target(), other_organization());

    assert_eq!(
        ambiguous.target_organization(&target()),
        Some(organization())
    );

    let reversed = RecordedClients::new()
        .with_client(client())
        .with_target(target(), other_organization())
        .with_target(target(), organization());

    assert_eq!(
        reversed.target_organization(&target()),
        Some(other_organization()),
        "the answer depends only on which registration was written first"
    );
}

/// A recorded nonce of the empty string is not a nonce, and an empty presentation does
/// not match it — the same shape the state binding has.
#[test]
fn an_empty_recorded_nonce_is_not_matched_by_an_empty_presentation() {
    for presented_nonce in [Some(String::new()), None, Some(NONCE.to_owned())] {
        let empty_binding = ValidateAuthorizationCode {
            binding: RequestBinding {
                nonce: String::new(),
                ..input().binding
            },
            presented: PresentedRedemption {
                nonce: presented_nonce.clone(),
                ..input().presented
            },
            ..input()
        };

        let denied = validate_authorization_code(
            &empty_binding,
            &request(),
            &read_model(),
            &read_model(),
            &sessions(),
            &StandInDigest,
        )
        .expect_err("an empty recorded nonce binds nothing");

        assert_eq!(denied.reason, DenialReason::Denied);
        assert_eq!(
            denied.clause,
            DenialClause::NonceMismatch,
            "{presented_nonce:?}"
        );
    }
}

/// The correction for the undated reader: the declared reason is now `Unavailable` and no
/// longer reports the record as expired. The clause it travels with is still the one
/// named for the code's expiry.
#[test]
fn an_undated_request_denies_unavailable() {
    for at in ["", "not-a-timestamp", "2026-09-19", "2026-09-19T12:00:00"] {
        let request = RequestContext {
            at: Timestamp::new(at),
            ..request()
        };

        let denied = validate_authorization_code(
            &input(),
            &request,
            &read_model(),
            &read_model(),
            &sessions(),
            &StandInDigest,
        )
        .expect_err("an undated reader certifies nothing");

        assert_eq!(denied.reason, DenialReason::Unavailable, "{at}");
        assert_eq!(denied.clause, DenialClause::CodeExpired, "{at}");
    }
}
