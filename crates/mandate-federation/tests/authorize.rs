//! The non-consuming validation of an authorization code: the session/epoch read, the
//! read-only code record, expiry, state and applicable nonce, the client and redirect
//! binding, and the candidate the accepted outcome stops at.
//!
//! The corpus cases underwritten here are `story:oauth-integration`'s and are named per
//! test: `pkce-valid`'s candidate half (`tests/security/cases.json:335`),
//! `pkce-state-nonce` (`:419`), and `pkce-reuse`'s previously-redeemed refusal only
//! (`:391`) — the concurrent second redemption and "at most one issuance" are the STS
//! transaction's and are not claimed here.
//!
//! Nothing in this file consumes a code, creates a credential or commits a redemption:
//! every call takes shared references, and each test asserts the read models it ran
//! against are unchanged afterwards.

use mandate_federation::authorize::{
    AuthorizationCode, AuthorizationCodeState, PresentedRedemption, RequestBinding, TargetRegistry,
    ValidateAuthorizationCode, is_expired_at, validate_authorization_code,
};
use mandate_federation::pkce::{PkceDigest, StandInDigest};
use mandate_federation::publicclient::{OAuthClientStore, RecordedClients};
use mandate_federation::record::{OAuthClient, OAuthClientState, Projection};
use mandate_federation::register_client::{
    ConfiguredAdmission, RegisterOAuthClient, register_o_auth_client,
};
use mandate_federation::{DenialClause, RefusedOutcome, RequestContext, SequentialAllocator};
use mandate_identity::{
    EpochSnapshotRecorded, Generation, IdentityEvent, IdentityLog, SecurityEpochIncremented,
    SecurityEpochRecorded, Session, SessionOpened, SessionRevoked,
};
use mandate_types::value::Uuid;
use mandate_types::{
    Action, Audience, AuthorityScope, AuthorizationCodeId, CorrelationId, CredentialId,
    CredentialProof, DenialReason, OAuthClientId, OrganizationId, PkceMethod, PrincipalId,
    RedirectUri, ResourceServerId, SecurityEpochTarget, SessionId, Timestamp, VerifiedContext,
};

const REGISTERED: &str = "https://app.example/callback";
const SECOND_REGISTERED: &str = "https://app.example/other";
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

/// The verified context the two identity-domain events declare.
///
/// `mandate.identity.SessionRevoked` and `mandate.identity.SecurityEpochIncremented` each
/// declare a `mandate.core.VerifiedContext` (`context: input.context`), so a case that
/// records one carries it.
fn identity_context() -> VerifiedContext {
    VerifiedContext {
        subject: principal(),
        actor: None,
        organization: organization(),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("federation-alignment"),
    }
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

fn target() -> ResourceServerId {
    ResourceServerId::new(uuid(0x7a))
}

fn scope() -> AuthorityScope {
    AuthorityScope {
        actions: vec![Action::new("read")],
        resources: Vec::new(),
        space: None,
    }
}

/// The presented code verifier, `mandate.core.CredentialProof`
/// (`credential.yaml:205-206`). A synthetic marker in the declared form, never credential
/// material.
fn verifier(name: &str) -> CredentialProof {
    let mut text = format!("mandate-test-verifier-{name}");
    while text.len() < 43 {
        text.push('~');
    }
    CredentialProof::from_bytes(text.into_bytes())
}

fn request() -> RequestContext {
    RequestContext {
        audience: Audience::new("mandate"),
        correlation: CorrelationId::new("pkce-sessions"),
        credential: CredentialId::new(uuid(0xcd)),
        at: Timestamp::new(NOW),
    }
}

fn clients() -> RecordedClients {
    RecordedClients::new()
        .with_target(target(), organization())
        .with_client(OAuthClient {
            id: client_id(),
            organization_id: organization(),
            public: true,
            redirect_uris: vec![
                RedirectUri::new(REGISTERED),
                RedirectUri::new(SECOND_REGISTERED),
            ],
            pkce_method: PkceMethod::S256,
            state: OAuthClientState::Recorded,
        })
}

/// An identity log holding one active session of this principal and organization, issued
/// against the authoritative generations.
fn sessions() -> IdentityLog {
    let handle = mandate_types::EpochSnapshotRef::new(uuid(0x3e));
    let mut log = IdentityLog::new();
    log.record(IdentityEvent::SecurityEpochRecorded(
        SecurityEpochRecorded {
            target: SecurityEpochTarget::Principal(principal()),
            generation: Generation::new(3).expect("a declared generation"),
        },
    ));
    log.record(IdentityEvent::SecurityEpochRecorded(
        SecurityEpochRecorded {
            target: SecurityEpochTarget::Organization(organization()),
            generation: Generation::new(2).expect("a declared generation"),
        },
    ));
    log.record(IdentityEvent::EpochSnapshotRecorded(
        EpochSnapshotRecorded {
            id: handle,
            principal_id: principal(),
            organization_id: organization(),
            connection_id: None,
        },
    ));
    log.record(IdentityEvent::SessionOpened(SessionOpened {
        id: session_id(),
        principal_id: principal(),
        organization_id: organization(),
        connection_id: None,
        epochs: handle,
        expires_at: Timestamp::new("2026-12-31T00:00:00Z"),
    }));
    log
}

fn code() -> AuthorizationCode {
    AuthorizationCode {
        id: code_id(),
        client_id: client_id(),
        session_id: session_id(),
        challenge: StandInDigest.challenge(&verifier("one")),
        method: PkceMethod::S256,
        redirect_uri: RedirectUri::new(REGISTERED),
        expires_at: Timestamp::new(LATER),
        target: target(),
        scope: scope(),
        state: AuthorizationCodeState::Issued,
    }
}

fn presented() -> PresentedRedemption {
    PresentedRedemption {
        redirect_uri: RedirectUri::new(REGISTERED),
        verifier: Some(verifier("one")),
        state: STATE.to_owned(),
        nonce: Some(NONCE.to_owned()),
    }
}

fn binding() -> RequestBinding {
    RequestBinding {
        state: STATE.to_owned(),
        nonce: NONCE.to_owned(),
    }
}

fn input() -> ValidateAuthorizationCode {
    ValidateAuthorizationCode {
        code: code(),
        binding: binding(),
        presented: presented(),
    }
}

/// `pkce-valid` (`tests/security/cases.json:335`), candidate half only: the S256
/// challenge, matching verifier, exact redirect, fresh code and state/nonce yield a
/// validation candidate. No code is consumed and no credential is created here; the
/// atomic redemption is `story:oauth-integration`'s.
#[test]
fn a_valid_presentation_yields_a_non_consuming_validation_candidate() {
    let input = input();
    let registry = clients();
    let identity = sessions();

    let candidate = validate_authorization_code(
        &input,
        &request(),
        &registry,
        &registry,
        &identity,
        &StandInDigest,
    )
    .expect("every declared condition is met");

    assert_eq!(candidate.code_id, code_id());
    assert_eq!(candidate.client_id, client_id());
    assert_eq!(candidate.session_id, session_id());
    assert_eq!(candidate.principal_id, principal());
    assert_eq!(candidate.organization_id, organization());
    assert_eq!(
        input.code.state,
        AuthorizationCodeState::Issued,
        "validation does not consume the code record"
    );
    assert_eq!(
        identity,
        sessions(),
        "validation appends no event to the identity log"
    );
    assert_eq!(
        registry,
        clients(),
        "validation writes nothing to the client read model"
    );
}

/// Two concurrent callers each meeting every positive condition each obtain a candidate;
/// neither has authority to redeem, and only the later atomic STS transaction decides the
/// redemption winner.
#[test]
fn two_concurrent_callers_each_obtain_a_candidate() {
    let input = input();
    let registry = clients();
    let identity = sessions();

    let first = validate_authorization_code(
        &input,
        &request(),
        &registry,
        &registry,
        &identity,
        &StandInDigest,
    )
    .expect("the first caller validates");
    let second = validate_authorization_code(
        &input,
        &request(),
        &registry,
        &registry,
        &identity,
        &StandInDigest,
    )
    .expect("the second caller validates against the same unchanged read model");

    assert_eq!(first, second);
    assert_eq!(input.code.state, AuthorizationCodeState::Issued);
    assert_eq!(identity, sessions());
}

/// `pkce-reuse` (`tests/security/cases.json:391`), the previously-redeemed refusal only:
/// a code in the declared terminal `Consumed` state is refused. The concurrent second
/// redemption and "at most one issuance" belong to the STS transaction.
#[test]
fn a_previously_redeemed_code_is_refused() {
    let input = ValidateAuthorizationCode {
        code: AuthorizationCode {
            state: AuthorizationCodeState::Consumed,
            ..code()
        },
        ..input()
    };

    let denied = validate_authorization_code(
        &input,
        &request(),
        &clients(),
        &clients(),
        &sessions(),
        &StandInDigest,
    )
    .expect_err("`Consumed` is the declared terminal state");

    assert_eq!(denied.reason, DenialReason::Denied);
    assert_eq!(denied.clause, DenialClause::CodePreviouslyRedeemed);
    // The refusal names which declared outcome it is, and `AuthorizePublicClient` — the
    // element this handler realizes — declares `accepted` and `denied` alone, because it
    // is non-consuming and moves no record. The code record's own terminal state is
    // `mandate.credential.RedeemAuthorizationCode`'s `wrong-state` outcome, which the STS
    // transaction returns (`story:oauth-integration`).
    assert_eq!(denied.outcome, RefusedOutcome::Denied);
    assert_eq!(denied.outcome.ir_name(), "denied");
}

#[test]
fn a_code_whose_expiry_has_passed_is_refused() {
    for expires_at in [NOW, "2026-09-18T11:59:59Z", "not-a-timestamp", ""] {
        let input = ValidateAuthorizationCode {
            code: AuthorizationCode {
                expires_at: Timestamp::new(expires_at),
                ..code()
            },
            ..input()
        };

        let denied = validate_authorization_code(
            &input,
            &request(),
            &clients(),
            &clients(),
            &sessions(),
            &StandInDigest,
        )
        .expect_err("a code is redeemable strictly before the instant it expires at");

        assert_eq!(denied.reason, DenialReason::InvalidCredential);
        assert_eq!(denied.clause, DenialClause::CodeExpired, "{expires_at}");
    }
}

/// `pkce-state-nonce` (`tests/security/cases.json:419`): "State or applicable nonce does
/// not match" denies.
#[test]
fn a_state_that_is_not_the_one_the_authorization_request_recorded_is_refused() {
    for state in ["", "another-state", "State-From-The-Authorization-Request"] {
        let input = ValidateAuthorizationCode {
            presented: PresentedRedemption {
                state: state.to_owned(),
                ..presented()
            },
            ..input()
        };

        let denied = validate_authorization_code(
            &input,
            &request(),
            &clients(),
            &clients(),
            &sessions(),
            &StandInDigest,
        )
        .expect_err("the state binding is exact");

        assert_eq!(denied.reason, DenialReason::Denied);
        assert_eq!(denied.clause, DenialClause::StateMismatch, "{state}");
    }
}

/// `pkce-state-nonce` (`tests/security/cases.json:419`), the nonce half. The
/// authorization request always recorded a nonce — `AuthorizePublicClient` declares it as
/// `String` and not `Optional<String>` (`federation.yaml:281-282`) — so "applicable"
/// never means absent, and a recorded empty nonce is not a nonce.
#[test]
fn an_applicable_nonce_that_does_not_match_is_refused() {
    let unmatched = [
        (NONCE.to_owned(), Some("another-nonce".to_owned())),
        (String::new(), Some(NONCE.to_owned())),
        (NONCE.to_owned(), Some(String::new())),
    ];

    for (recorded, nonce) in unmatched {
        let input = ValidateAuthorizationCode {
            binding: RequestBinding {
                nonce: recorded.clone(),
                ..binding()
            },
            presented: PresentedRedemption {
                nonce,
                ..presented()
            },
            ..input()
        };

        let denied = validate_authorization_code(
            &input,
            &request(),
            &clients(),
            &clients(),
            &sessions(),
            &StandInDigest,
        )
        .expect_err("the applicable nonce binding is exact");

        assert_eq!(denied.reason, DenialReason::Denied);
        assert_eq!(denied.clause, DenialClause::NonceMismatch, "{recorded}");
    }
}

/// The successor of a case that admitted a presentation carrying no nonce against a
/// request that recorded none: the contract declares no such request, so the only
/// presentation without a nonce is one that dropped it.
#[test]
fn a_presentation_that_omits_the_nonce_is_refused() {
    let input = ValidateAuthorizationCode {
        presented: PresentedRedemption {
            nonce: None,
            ..presented()
        },
        ..input()
    };

    let denied = validate_authorization_code(
        &input,
        &request(),
        &clients(),
        &clients(),
        &sessions(),
        &StandInDigest,
    )
    .expect_err("the recorded nonce must be presented back");

    assert_eq!(denied.reason, DenialReason::Denied);
    assert_eq!(denied.clause, DenialClause::NonceMismatch);
}

/// "target is unregistered/outside tenant" (`federation.yaml:298`): a target the registry
/// answers nothing for is refused. The registry is a read port because
/// `mandate.credential.ResourceServer` is another domain's record;
/// `story:credential-profiles` supplies the real one.
#[test]
fn a_target_the_registry_does_not_answer_is_refused() {
    let input = ValidateAuthorizationCode {
        code: AuthorizationCode {
            target: ResourceServerId::new(uuid(0x7b)),
            ..code()
        },
        ..input()
    };

    let denied = validate_authorization_code(
        &input,
        &request(),
        &clients(),
        &clients(),
        &sessions(),
        &StandInDigest,
    )
    .expect_err("an unregistered target is a declared denial condition");

    assert_eq!(denied.reason, DenialReason::Denied);
    assert_eq!(denied.clause, DenialClause::TargetUnknown);
}

/// The other half of the same clause: registered, and registered to somebody else.
#[test]
fn a_target_registered_to_another_organization_is_refused() {
    let elsewhere = ResourceServerId::new(uuid(0x7c));
    let registry = clients().with_target(elsewhere, OrganizationId::new(uuid(11)));
    let input = ValidateAuthorizationCode {
        code: AuthorizationCode {
            target: elsewhere,
            ..code()
        },
        ..input()
    };

    let denied = validate_authorization_code(
        &input,
        &request(),
        &registry,
        &registry,
        &sessions(),
        &StandInDigest,
    )
    .expect_err("a target inside another tenant is outside this one");

    assert_eq!(denied.reason, DenialReason::TenantMismatch);
    assert_eq!(denied.clause, DenialClause::TargetOutsideTenant);
}

/// A request instant that names no instant cannot date anything. It fails closed, and it
/// says `Unavailable` rather than `InvalidCredential`: the reader cannot be dated, which
/// is not the record having expired — the distinction `mandate_identity` draws between a
/// malformed `expires_at` and a malformed `as_of`.
#[test]
fn a_request_instant_that_names_no_instant_denies_unavailable() {
    for at in ["", "not-a-timestamp", "2026-09-18", "2026-09-18T12:00:00"] {
        let request = RequestContext {
            at: Timestamp::new(at),
            ..request()
        };

        let denied = validate_authorization_code(
            &input(),
            &request,
            &clients(),
            &clients(),
            &sessions(),
            &StandInDigest,
        )
        .expect_err("an undated reader certifies nothing");

        assert_eq!(denied.reason, DenialReason::Unavailable, "{at}");
        assert_eq!(denied.clause, DenialClause::CodeExpired, "{at}");
    }
}

/// The redirect must be the exact one the code record bound, not merely one the client
/// registered: `pkce-redirect` names "exact registered/authorized URI".
#[test]
fn a_registered_redirect_that_is_not_the_one_the_code_bound_is_refused() {
    let input = ValidateAuthorizationCode {
        presented: PresentedRedemption {
            redirect_uri: RedirectUri::new(SECOND_REGISTERED),
            ..presented()
        },
        ..input()
    };

    let denied = validate_authorization_code(
        &input,
        &request(),
        &clients(),
        &clients(),
        &sessions(),
        &StandInDigest,
    )
    .expect_err("the code record's own redirect is the authorized one");

    assert_eq!(denied.reason, DenialReason::Denied);
    assert_eq!(denied.clause, DenialClause::RedirectMismatch);
}

#[test]
fn a_session_the_identity_read_does_not_resolve_is_refused() {
    let denied = validate_authorization_code(
        &input(),
        &request(),
        &clients(),
        &clients(),
        &IdentityLog::new(),
        &StandInDigest,
    )
    .expect_err("a code bound to a session that does not resolve is not redeemable");

    assert_eq!(denied.reason, DenialReason::InvalidCredential);
    assert_eq!(denied.clause, DenialClause::SessionUnknown);
}

#[test]
fn a_revoked_session_is_refused() {
    let mut identity = sessions();
    identity.record(IdentityEvent::SessionRevoked(SessionRevoked {
        context: identity_context(),
        id: session_id(),
    }));

    let denied = validate_authorization_code(
        &input(),
        &request(),
        &clients(),
        &clients(),
        &identity,
        &StandInDigest,
    )
    .expect_err("`Revoked` is the declared terminal session state");

    assert_eq!(denied.reason, DenialReason::InvalidCredential);
    assert_eq!(denied.clause, DenialClause::SessionRevoked);
}

#[test]
fn a_session_whose_epoch_snapshot_is_stale_is_refused() {
    let mut identity = sessions();
    identity.record(IdentityEvent::SecurityEpochIncremented(
        SecurityEpochIncremented::new(
            identity_context(),
            SecurityEpochTarget::Organization(organization()),
        ),
    ));

    let denied = validate_authorization_code(
        &input(),
        &request(),
        &clients(),
        &clients(),
        &identity,
        &StandInDigest,
    )
    .expect_err("a session issued against a superseded generation is stale");

    assert_eq!(denied.reason, DenialReason::StaleEpoch);
    assert_eq!(denied.clause, DenialClause::SessionStale);
}

#[test]
fn a_session_whose_own_expiry_has_passed_is_refused() {
    let request = RequestContext {
        at: Timestamp::new("2027-01-01T00:00:00Z"),
        ..request()
    };
    let input = ValidateAuthorizationCode {
        code: AuthorizationCode {
            expires_at: Timestamp::new("2027-06-01T00:00:00Z"),
            ..code()
        },
        ..input()
    };

    let denied = validate_authorization_code(
        &input,
        &request,
        &clients(),
        &clients(),
        &sessions(),
        &StandInDigest,
    )
    .expect_err("an expired session is not an authenticated one");

    assert_eq!(denied.reason, DenialReason::InvalidCredential);
    assert_eq!(denied.clause, DenialClause::SessionExpired);
}

#[test]
fn a_client_bound_to_another_organization_than_the_session_is_refused() {
    let clients = RecordedClients::new().with_client(OAuthClient {
        id: client_id(),
        organization_id: OrganizationId::new(uuid(11)),
        public: true,
        redirect_uris: vec![RedirectUri::new(REGISTERED)],
        pkce_method: PkceMethod::S256,
        state: OAuthClientState::Recorded,
    });

    let denied = validate_authorization_code(
        &input(),
        &request(),
        &clients,
        &clients,
        &sessions(),
        &StandInDigest,
    )
    .expect_err("the organization is the session's, never the caller's claim");

    assert_eq!(denied.reason, DenialReason::TenantMismatch);
    assert_eq!(denied.clause, DenialClause::OrganizationMismatch);
}

/// The PKCE predicate is composed, not re-implemented: `pkce-wrong` and `pkce-missing`
/// are executed against the predicate in `crates/mandate-federation/tests/pkce.rs`, and
/// what is shown here is that a refusal from it consumes nothing.
#[test]
fn a_verifier_that_does_not_redeem_the_recorded_challenge_is_refused_and_consumes_nothing() {
    for presented_verifier in [None, Some(verifier("two"))] {
        let input = ValidateAuthorizationCode {
            presented: PresentedRedemption {
                verifier: presented_verifier,
                ..presented()
            },
            ..input()
        };
        let identity = sessions();

        let denied = validate_authorization_code(
            &input,
            &request(),
            &clients(),
            &clients(),
            &identity,
            &StandInDigest,
        )
        .expect_err("a verifier that does not digest to the recorded challenge is refused");

        assert_eq!(denied.reason, DenialReason::InvalidCredential);
        assert_eq!(input.code.state, AuthorizationCodeState::Issued);
        assert_eq!(identity, sessions());
    }
}

/// The candidate stops at the input of `mandate.credential.IssueAuthorizationCode`
/// (`credential.yaml:363-381`): it names every value that call takes and does not make it.
/// No port for it is declared in this crate, so nothing here can.
#[test]
fn the_candidate_carries_the_issuance_input_and_invokes_nothing() {
    let candidate = validate_authorization_code(
        &input(),
        &request(),
        &clients(),
        &clients(),
        &sessions(),
        &StandInDigest,
    )
    .expect("every declared condition is met");
    let issuance = &candidate.issuance;

    assert_eq!(issuance.client_id, client_id());
    assert_eq!(issuance.session_id, session_id());
    assert_eq!(issuance.target, target());
    assert_eq!(issuance.requested_scope, scope());
    assert_eq!(issuance.challenge, code().challenge);
    assert_eq!(issuance.method, PkceMethod::S256);
    assert_eq!(issuance.redirect_uri, RedirectUri::new(REGISTERED));
    assert_eq!(issuance.expires_at, Timestamp::new(LATER));
    assert_eq!(issuance.context.subject, principal());
    assert_eq!(issuance.context.organization, organization());
    assert_eq!(issuance.context.audience, Audience::new("mandate"));
    assert_eq!(issuance.context.credential, CredentialId::new(uuid(0xcd)));
    assert_eq!(
        issuance.context.correlation,
        CorrelationId::new("pkce-sessions")
    );
    assert_eq!(issuance.context.actor, None);
    assert_eq!(issuance.context.delegation, None);
    assert_eq!(issuance.context.execution, None);
}

/// This crate reads the declared `date-time` form for the code record's expiry, and
/// `mandate_identity` reads it for the session's. Two readings of one declared form are
/// two chances to disagree, so they are pinned against each other here: for every
/// spelling, a code expiring at that instant is expired exactly when a session expiring at
/// it is.
#[test]
fn the_code_expiry_reading_agrees_with_the_session_expiry_reading() {
    let spellings = [
        "2026-09-18T12:05:00Z",
        "2026-09-18T11:55:00Z",
        "2026-09-18T12:00:00Z",
        "2026-09-18T14:05:00+02:00",
        "2026-09-18T06:30:00-05:30",
        "2026-09-18T12:00:00.000000001Z",
        "2026-09-18t12:05:00z",
        "2026-09-18T23:59:60Z",
        "2026-02-30T12:05:00Z",
        "2026-09-18 12:05:00Z",
        "not-a-timestamp",
        "",
    ];
    let handle = mandate_types::EpochSnapshotRef::new(uuid(0x3e));

    for spelling in spellings {
        let expires_at = Timestamp::new(spelling);
        let session = Session::new(
            session_id(),
            principal(),
            organization(),
            handle,
            expires_at.clone(),
        );

        assert_eq!(
            is_expired_at(&expires_at, &request().at),
            session.is_expired_at(&request().at),
            "the two readings disagree on {spelling}"
        );
    }
}

/// The epoch snapshot is resolved through the same read port, and a session whose handle
/// resolves to no record — or to one bound to another subject — is refused with the
/// identity crate's own declared reason. Every new denial clause this story adds is
/// asserted by a case; this is the one for the unresolved snapshot.
#[test]
fn a_session_whose_epoch_snapshot_does_not_resolve_is_refused() {
    let unrecorded = mandate_types::EpochSnapshotRef::new(uuid(0x3f));
    // `mandate_identity::IdentityLog` refuses an opening whose snapshot handle it does not
    // already record, so a dangling handle cannot be reached through *that* store. This
    // command reads a port, and an adapter over another store can answer a session that
    // fold would never have built, so the port is answered directly here. The refusal is
    // the command's, and it is the half this case is about.
    struct Dangling(mandate_identity::Session);

    impl mandate_identity::IdentityRead for Dangling {
        fn resolve(&self, id: &SessionId) -> Option<mandate_identity::Session> {
            (self.0.id() == id).then(|| self.0.clone())
        }

        /// This store holds one session and no principal record, which is the
        /// explicit-link path: `mandate.identity.Principal` is created by a seeding event
        /// no store here carries, and a session for a principal with no record is a
        /// session all the same.
        fn principal(&self, _id: &PrincipalId) -> Option<mandate_identity::Principal> {
            None
        }

        fn current(&self, _target: &SecurityEpochTarget) -> mandate_identity::EpochState {
            mandate_identity::EpochState::new(
                Generation::ZERO,
                mandate_identity::StreamVersion::INITIAL,
            )
        }

        fn snapshot(
            &self,
            _id: &mandate_types::EpochSnapshotRef,
        ) -> Option<mandate_identity::SecurityEpochSnapshot> {
            None
        }

        fn as_of(&self) -> Option<Timestamp> {
            Some(Timestamp::new(NOW))
        }
    }

    let dangling = Dangling(
        SessionOpened {
            id: session_id(),
            principal_id: principal(),
            organization_id: organization(),
            connection_id: None,
            epochs: unrecorded,
            expires_at: Timestamp::new("2026-12-31T00:00:00Z"),
        }
        .session(),
    );

    let mut misbound = IdentityLog::new();
    // The dimensions the snapshot names state their generation first: `IdentityLog`
    // refuses a recording whose dimensions the log has said nothing about.
    for target in [
        SecurityEpochTarget::Principal(PrincipalId::new(uuid(0xa2))),
        SecurityEpochTarget::Organization(organization()),
    ] {
        misbound.record(IdentityEvent::SecurityEpochRecorded(
            SecurityEpochRecorded {
                target,
                generation: Generation::ZERO,
            },
        ));
    }
    misbound.record(IdentityEvent::EpochSnapshotRecorded(
        EpochSnapshotRecorded {
            id: unrecorded,
            principal_id: PrincipalId::new(uuid(0xa2)),
            organization_id: organization(),
            connection_id: None,
        },
    ));
    misbound.record(IdentityEvent::SessionOpened(SessionOpened {
        id: session_id(),
        principal_id: principal(),
        organization_id: organization(),
        connection_id: None,
        epochs: unrecorded,
        expires_at: Timestamp::new("2026-12-31T00:00:00Z"),
    }));

    let unresolved = validate_authorization_code(
        &input(),
        &request(),
        &clients(),
        &clients(),
        &dangling,
        &StandInDigest,
    )
    .expect_err("a session whose snapshot does not resolve is not an eligible one");
    assert_eq!(unresolved.reason, DenialReason::Denied);
    assert_eq!(unresolved.clause, DenialClause::SessionEpochUnresolved);

    let bound_elsewhere = validate_authorization_code(
        &input(),
        &request(),
        &clients(),
        &clients(),
        &misbound,
        &StandInDigest,
    )
    .expect_err("a snapshot bound to another subject is not this session's");
    assert_eq!(bound_elsewhere.reason, DenialReason::TenantMismatch);
    assert_eq!(bound_elsewhere.clause, DenialClause::SessionEpochUnresolved);
}

/// The declared denial of `AuthorizePublicClient` (`federation.yaml:298`) names seven
/// conditions. This is the enumeration of all seven: six are decided here, each by a
/// clause a case below produces, and the seventh is the STS call this validation stops in
/// front of. The finding that produced this test was one phrase — "target is
/// unregistered/outside tenant" — that nothing read; the answer to it is the list, not the
/// one phrase.
#[test]
fn every_phrase_of_the_declared_denial_is_decided_here_or_assigned_to_sts() {
    let disabled = RecordedClients::new()
        .with_target(target(), organization())
        .with_client(OAuthClient {
            id: client_id(),
            organization_id: organization(),
            public: true,
            redirect_uris: vec![RedirectUri::new(REGISTERED)],
            pkce_method: PkceMethod::S256,
            state: OAuthClientState::Disabled,
        });
    let unregistered_target = ValidateAuthorizationCode {
        code: AuthorizationCode {
            target: ResourceServerId::new(uuid(0x7d)),
            ..code()
        },
        ..input()
    };
    let wrong_redirect = ValidateAuthorizationCode {
        presented: PresentedRedemption {
            redirect_uri: RedirectUri::new(SECOND_REGISTERED),
            ..presented()
        },
        ..input()
    };
    let wrong_state = ValidateAuthorizationCode {
        presented: PresentedRedemption {
            state: "another-state".to_owned(),
            ..presented()
        },
        ..input()
    };
    let no_nonce = ValidateAuthorizationCode {
        presented: PresentedRedemption {
            nonce: None,
            ..presented()
        },
        ..input()
    };
    let no_verifier = ValidateAuthorizationCode {
        presented: PresentedRedemption {
            verifier: None,
            ..presented()
        },
        ..input()
    };

    let decided: Vec<(&str, DenialClause)> = vec![
        (
            "Session proof is invalid/stale",
            validate_authorization_code(
                &input(),
                &request(),
                &clients(),
                &clients(),
                &IdentityLog::new(),
                &StandInDigest,
            )
            .expect_err("no session resolves")
            .clause,
        ),
        (
            "client is not a registered public client",
            validate_authorization_code(
                &input(),
                &request(),
                &RecordedClients::new().with_target(target(), organization()),
                &RecordedClients::new().with_target(target(), organization()),
                &sessions(),
                &StandInDigest,
            )
            .expect_err("no client is registered")
            .clause,
        ),
        (
            "the client is disabled",
            validate_authorization_code(
                &input(),
                &request(),
                &disabled,
                &disabled,
                &sessions(),
                &StandInDigest,
            )
            .expect_err("the client is disabled")
            .clause,
        ),
        (
            "exact redirect URI ... binding fails",
            validate_authorization_code(
                &wrong_redirect,
                &request(),
                &clients(),
                &clients(),
                &sessions(),
                &StandInDigest,
            )
            .expect_err("the redirect is not the authorized one")
            .clause,
        ),
        (
            "state ... binding fails",
            validate_authorization_code(
                &wrong_state,
                &request(),
                &clients(),
                &clients(),
                &sessions(),
                &StandInDigest,
            )
            .expect_err("the state is not the recorded one")
            .clause,
        ),
        (
            "applicable nonce binding fails",
            validate_authorization_code(
                &no_nonce,
                &request(),
                &clients(),
                &clients(),
                &sessions(),
                &StandInDigest,
            )
            .expect_err("the recorded nonce was not presented back")
            .clause,
        ),
        (
            "S256 challenge is absent/invalid",
            validate_authorization_code(
                &no_verifier,
                &request(),
                &clients(),
                &clients(),
                &sessions(),
                &StandInDigest,
            )
            .expect_err("no verifier was presented")
            .clause,
        ),
        (
            "target is unregistered/outside tenant",
            validate_authorization_code(
                &unregistered_target,
                &request(),
                &clients(),
                &clients(),
                &sessions(),
                &StandInDigest,
            )
            .expect_err("the target is not registered")
            .clause,
        ),
    ];

    assert_eq!(
        decided,
        vec![
            (
                "Session proof is invalid/stale",
                DenialClause::SessionUnknown
            ),
            (
                "client is not a registered public client",
                DenialClause::ClientUnknown
            ),
            ("the client is disabled", DenialClause::ClientDisabled),
            (
                "exact redirect URI ... binding fails",
                DenialClause::RedirectMismatch
            ),
            ("state ... binding fails", DenialClause::StateMismatch),
            (
                "applicable nonce binding fails",
                DenialClause::NonceMismatch
            ),
            (
                "S256 challenge is absent/invalid",
                DenialClause::VerifierMissing
            ),
            (
                "target is unregistered/outside tenant",
                DenialClause::TargetUnknown
            ),
        ]
    );

    // The seventh phrase, "STS code issuance/narrowing is refused", is not decided here
    // and must not be: the accepted outcome stops at the input of that call.
    let candidate = validate_authorization_code(
        &input(),
        &request(),
        &clients(),
        &clients(),
        &sessions(),
        &StandInDigest,
    )
    .expect("every condition this command decides is met");
    assert_eq!(candidate.issuance.target, target());
}

/// A registry that cannot answer has decided nothing, and "nothing" is not "unregistered".
/// The crate's own fold is that registry: `mandate.credential.ResourceServer` is another
/// domain's record and this fold holds none, so it refuses `Unavailable` — the same shape
/// as a request instant that names no instant — and never `Denied`.
#[test]
fn a_registry_that_cannot_answer_denies_unavailable() {
    let fold = Projection::default();

    let denied = validate_authorization_code(
        &input(),
        &request(),
        &clients(),
        &fold,
        &sessions(),
        &StandInDigest,
    )
    .expect_err("a registry that cannot answer certifies no target");

    assert_eq!(denied.reason, DenialReason::Unavailable);
    assert_eq!(denied.clause, DenialClause::TargetUnanswerable);

    // The distinction that makes the third answer worth having: a registry that *can*
    // answer and holds no such target refuses the same request as `Denied`.
    let empty = RecordedClients::new();
    let refused = validate_authorization_code(
        &input(),
        &request(),
        &clients(),
        &empty,
        &sessions(),
        &StandInDigest,
    )
    .expect_err("a registry with no such target answers that it is unregistered");

    assert_eq!(refused.reason, DenialReason::Denied);
    assert_eq!(refused.clause, DenialClause::TargetUnknown);
}

/// The seam `story:credential-profiles` attaches to, and the client seam beside it: the
/// crate's own fold satisfies both ports the command reads, so the real read model can be
/// passed to it — answering no client while no registration is in the log, and no target,
/// because that record is another domain's.
#[test]
fn the_folded_read_model_satisfies_both_ports_the_command_reads() {
    let fold = Projection::default();

    assert!(fold.client(&client_id()).is_none());
    assert!(!fold.can_answer(&target()));
    assert_eq!(fold.target_organization(&target()), None);

    let denied = validate_authorization_code(
        &input(),
        &request(),
        &fold,
        &fold,
        &sessions(),
        &StandInDigest,
    )
    .expect_err("a fold over no registration answers no registered client");

    assert_eq!(denied.clause, DenialClause::ClientUnknown);
}

/// The client `AuthorizePublicClient` reads is the one `RegisterOAuthClient` wrote.
///
/// Every other case in this file fixtures the client through the `pub` double, because
/// until the creating command was declared no event created one. This drives the real
/// registration handler, folds the event its accepted outcome emits, and validates a code
/// bound to the identity that outcome returned — so the client half of the candidate is
/// decided against the crate's own read model end to end.
#[test]
fn a_client_registered_through_the_real_command_is_what_the_validation_reads() {
    let mut allocator = SequentialAllocator::new();
    let registered = register_o_auth_client(
        &RegisterOAuthClient {
            context: identity_context(),
            public: true,
            redirect_uris: vec![RedirectUri::new(REGISTERED)],
            pkce_method: PkceMethod::S256,
        },
        &ConfiguredAdmission::new()
            .with_administrator(principal())
            .with_organization(organization())
            .with_redirect_uri(organization(), RedirectUri::new(REGISTERED)),
        &mut allocator,
    )
    .expect("an administrator of an admitted organization registering an admitted redirect");
    let fold = Projection::fold(&[registered.event]).expect("one creation");

    let input = ValidateAuthorizationCode {
        code: AuthorizationCode {
            client_id: registered.id,
            ..code()
        },
        ..input()
    };

    let candidate = validate_authorization_code(
        &input,
        &request(),
        &fold,
        &clients(),
        &sessions(),
        &StandInDigest,
    )
    .expect("every declared condition is met against the registered client");

    assert_eq!(candidate.client_id, registered.id);
    assert_eq!(candidate.organization_id, organization());
    assert_eq!(
        input.code.state,
        AuthorizationCodeState::Issued,
        "validation does not consume the code record"
    );
}
