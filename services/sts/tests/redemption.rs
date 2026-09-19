//! `mandate.credential.RedeemAuthorizationCode`: the transaction the acceptance is about.
//!
//! "Given a fresh authorization code issued through `IssueAuthorizationCode`, when the
//! public client redeems it through `RedeemAuthorizationCode` with the matching PKCE
//! verifier, client and redirect, then exactly one correctly scoped credential is issued and
//! recorded in the log, a second redemption of the same code is the declared wrong-state
//! outcome, and two concurrent redemptions issue at most one credential."
//!
//! The three halves are here: the accepted road, the second redemption, and the race. The
//! race is a compare-and-set on the expected stream version and not a lock — ADR 0009 makes
//! the aggregate append one — so it is decided by giving two deciders the same projection
//! and letting both append.
//!
//! Every fixture drives the real handlers: the target is registered through
//! `register_resource_server`, the code is issued through `issue_authorization_code`, and
//! the code proof is the secret that issuance returned. Nothing here constructs a code
//! record by hand, so a case cannot pass against a record no command could have written.

use mandate_sts::binding::{RecordedSessions, SessionBinding};
use mandate_sts::code::{
    AuthorizationCodeParts, CodeIssuance, CodeLifetime, IssueAuthorizationCode, RecordedClients,
};
use mandate_sts::issue::Sha256Digest;
use mandate_sts::redemption::{
    BoundReads, RedeemAuthorizationCode, RedemptionParts, RedemptionRefused, redeem_and_consume,
    redeem_authorization_code,
};
use mandate_sts::registry::{
    DisableResourceServer, RegisterResourceServer, disable_resource_server,
    register_resource_server,
};
use mandate_sts::store::{
    AppendRefused, AuthorizationCodeState, CodeProjection, InMemoryCodeLog, StreamVersion,
};
use mandate_sts::{CountingSecrets, RequestContext, SequentialAllocator};
use mandate_token::CredentialProfile;
use mandate_token::projection::{
    AccessCredentialState, DenialClause, Denied, Projection, RefusedOutcome,
};
use mandate_token::verifier::{CredentialDomain, verifier_in};
use mandate_types::{
    Audience, AuthorityScope, AuthorizationCodeId, CorrelationId, CredentialId, CredentialKind,
    CredentialProof, DenialReason, Duration, EpochSnapshotRef, OAuthClientId, OrganizationId,
    PkceChallenge, PkceMethod, PrincipalId, RedirectUri, ResourceServerId, RevocationGuarantee,
    SecurityEpochTarget, SessionId, Timestamp, Transient, Uuid, VerifiedContext,
};

/// RFC 7636 appendix B: the example code verifier and the S256 challenge it redeems.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
/// A second well-formed verifier, whose challenge is not [`CHALLENGE`].
const OTHER_VERIFIER: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization(tag: u8) -> OrganizationId {
    OrganizationId::new(uuid(tag))
}

fn client() -> OAuthClientId {
    OAuthClientId::new(uuid(0x0c))
}

fn session_id() -> SessionId {
    SessionId::new(uuid(0x5e))
}

fn snapshot() -> EpochSnapshotRef {
    EpochSnapshotRef::new(uuid(0x60))
}

fn subject() -> PrincipalId {
    PrincipalId::new(uuid(0x51))
}

fn redirect() -> RedirectUri {
    RedirectUri::new("https://client.example/callback")
}

fn context(organization_id: OrganizationId) -> VerifiedContext {
    VerifiedContext {
        subject: subject(),
        actor: None,
        organization: organization_id,
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("redemption"),
    }
}

fn request() -> RequestContext {
    RequestContext {
        correlation: CorrelationId::new("redemption"),
        at: Timestamp::new("2026-09-19T00:00:00Z"),
        epochs: None,
    }
}

fn scope() -> AuthorityScope {
    AuthorityScope {
        actions: Vec::new(),
        resources: Vec::new(),
        space: None,
    }
}

fn reference_profile() -> CredentialProfile {
    CredentialProfile {
        name: "reference".to_owned(),
        kind: CredentialKind::Reference,
        revocation: RevocationGuarantee::ImmediateOnline,
        max_ttl: Duration::new("PT1H"),
        positive_cache_ttl: Duration::new("PT30S"),
        requires_online_authorization: true,
    }
}

fn session() -> SessionBinding {
    SessionBinding {
        id: session_id(),
        subject: subject(),
        organization: organization(10),
        epochs: Some(snapshot()),
        expires_at: Timestamp::new("2026-09-19T12:00:00Z"),
        revoked: false,
    }
}

/// The redemption a public client presents for a code it holds.
fn redemption(code_id: AuthorizationCodeId, proof: &CredentialProof) -> RedeemAuthorizationCode {
    RedeemAuthorizationCode {
        code_id,
        client_id: client(),
        code: CredentialProof::from_bytes(proof.expose_material().to_vec()),
        pkce_verifier: CredentialProof::from_bytes(VERIFIER.as_bytes().to_vec()),
        redirect_uri: redirect(),
    }
}

fn sessions() -> RecordedSessions {
    RecordedSessions::new()
        .session(session())
        .current(snapshot())
}

fn clients() -> RecordedClients {
    RecordedClients::new()
        .enabled(client(), organization(10))
        .redirect(client(), redirect())
}

/// A deployment carrying the registration fold, the code log, and the doubles the redemption
/// reads through.
struct Deployment {
    servers: Projection,
    target: ResourceServerId,
    codes: InMemoryCodeLog,
    secrets: CountingSecrets,
    allocator: SequentialAllocator,
    credentials: Vec<mandate_token::projection::CredentialEvent>,
}

impl Deployment {
    fn new() -> Self {
        Self::with_audience("api-a")
    }

    fn with_audience(audience: &str) -> Self {
        let mut allocator = SequentialAllocator::new();
        let outcome = register_resource_server(
            &RegisterResourceServer {
                context: context(organization(10)),
                audience: Audience::new(audience),
                profile: reference_profile(),
                allowed_exchange_sources: Vec::new(),
            },
            &Projection::default(),
            &mut allocator,
        )
        .expect("a free audience");
        let target = outcome.resource_server_id;
        let servers = Projection::fold(std::slice::from_ref(&outcome.event)).expect("one creation");
        Self {
            servers,
            target,
            codes: InMemoryCodeLog::new(),
            secrets: CountingSecrets::new(),
            allocator,
            credentials: vec![outcome.event],
        }
    }

    /// One code, issued through the real handler and appended to its own stream, under a
    /// deployment code-lifetime ceiling of five minutes.
    fn issue(&mut self, expires_at: &str) -> (AuthorizationCodeId, CredentialProof) {
        self.issue_under("PT5M", expires_at)
    }

    /// The same, under a ceiling a case names — for the cases about what bounds the
    /// *credential*, which need a code that can outlive the registration's profile.
    fn issue_under(
        &mut self,
        ceiling: &str,
        expires_at: &str,
    ) -> (AuthorizationCodeId, CredentialProof) {
        let outcome = CodeIssuance::new(CodeLifetime::new(Duration::new(ceiling)))
            .issue(
                &IssueAuthorizationCode {
                    context: context(organization(10)),
                    client_id: client(),
                    session_id: session_id(),
                    target: self.target,
                    requested_scope: scope(),
                    challenge: PkceChallenge::new(CHALLENGE),
                    method: PkceMethod::S256,
                    redirect_uri: redirect(),
                    expires_at: Timestamp::new(expires_at),
                },
                &request(),
                &self.servers,
                &clients(),
                AuthorizationCodeParts {
                    digest: &Sha256Digest,
                    secrets: &mut self.secrets,
                    allocator: &mut self.allocator,
                },
            )
            .expect("a registered enabled target and client");
        let proof = CredentialProof::from_bytes(outcome.code.expose_material().to_vec());
        self.codes
            .append(
                &outcome.code_id,
                StreamVersion::INITIAL,
                std::slice::from_ref(&outcome.event),
            )
            .expect("an untouched stream");
        (outcome.code_id, proof)
    }

    /// The command path: decide against the log's own projection, append inside one group.
    fn redeem(
        &mut self,
        input: &RedeemAuthorizationCode,
        sessions: &RecordedSessions,
    ) -> Result<mandate_sts::redemption::AuthorizationCodeRedemption, RedemptionRefused> {
        let servers = self.servers.clone();
        let clients = clients();
        let outcome = redeem_and_consume(
            input,
            &request(),
            &mut self.codes,
            BoundReads {
                servers: &servers,
                clients: &clients,
                sessions,
            },
            RedemptionParts {
                digest: &Sha256Digest,
                secrets: &mut self.secrets,
                allocator: &mut self.allocator,
            },
        )?;
        if let Some(event) = outcome.event.credential_event() {
            self.credentials.push(event);
        }
        Ok(outcome)
    }

    /// The `mandate-token` credential fold, rebuilt from the credential log alone.
    fn credential_fold(&self) -> Projection {
        Projection::fold(&self.credentials).expect("a log of accepted events")
    }
}

#[test]
fn a_fresh_code_redeems_to_exactly_one_recorded_credential() {
    let mut deployment = Deployment::new();
    let (code_id, proof) = deployment.issue("2026-09-19T00:05:00Z");
    let input = redemption(code_id, &proof);

    let outcome = deployment
        .redeem(&input, &sessions())
        .expect("the matching verifier, client and redirect");

    assert_eq!(outcome.target, deployment.target);
    assert_eq!(
        deployment
            .codes
            .projection()
            .authorization_code(&code_id)
            .map(|code| code.state),
        Some(AuthorizationCodeState::Consumed),
        "the code is consumed"
    );
    let credentials = deployment.credential_fold();
    assert_eq!(credentials.credentials().len(), 1, "exactly one credential");
    let recorded = credentials
        .access_credential(&outcome.credential_id)
        .expect("the credential the redemption issued");
    assert_eq!(recorded.state, AccessCredentialState::Active);
    assert_eq!(recorded.descriptor, outcome.descriptor);
    assert_eq!(recorded.epochs, outcome.epochs);
    assert_eq!(recorded.target, deployment.target);
    assert_eq!(recorded.issued_at, request().at);
}

/// The credential is returned once and only its verifier is recorded: the same rule the
/// reference family keeps, in the reference family's own digest domain — which is the domain
/// an introspection resolves a presented proof in.
#[test]
fn the_credential_is_returned_once_and_only_its_verifier_is_recorded() {
    let mut deployment = Deployment::new();
    let (code_id, proof) = deployment.issue("2026-09-19T00:05:00Z");
    let input = redemption(code_id, &proof);

    let outcome = deployment
        .redeem(&input, &sessions())
        .expect("a fresh code");

    let recorded = deployment
        .credential_fold()
        .access_credential(&outcome.credential_id)
        .expect("the credential record")
        .reference_verifier
        .expect("the reference family records its verifier");
    assert_eq!(
        recorded,
        verifier_in(
            &Sha256Digest,
            CredentialDomain::ReferenceSecret,
            &outcome.credential
        )
    );
    let payload = serde_json::to_string(&outcome.event).expect("the payload encodes");
    assert!(
        !payload.contains(
            std::str::from_utf8(outcome.credential.expose_material())
                .expect("the fixture's secret is text")
        ),
        "the emitted payload does not carry the credential: {payload}"
    );
}

/// The generated context, exactly as the accepted summary states it: "its subject,
/// organization and audience from the code record and the session it names through the STS's
/// session port, its credential as the credential_id this outcome issues, its correlation as
/// the one the outcome mints for this request, and its actor, delegation and execution as
/// absent unless the code record names them. The audience is the one published by the
/// registration the code record's target names."
#[test]
fn the_generated_context_is_read_where_the_summary_says_it_is() {
    let mut deployment = Deployment::with_audience("api-published");
    let (code_id, proof) = deployment.issue("2026-09-19T00:05:00Z");
    let input = redemption(code_id, &proof);

    let outcome = deployment
        .redeem(&input, &sessions())
        .expect("a fresh code");

    let mandate_sts::store::AuthorizationCodeEvent::AuthorizationCodeRedeemed { context, .. } =
        &outcome.event
    else {
        panic!("the accepted outcome emits the redeemed event");
    };
    assert_eq!(context.subject, subject(), "from the session");
    assert_eq!(
        context.organization,
        organization(10),
        "from the session, never a caller-supplied selector"
    );
    assert_eq!(
        context.audience,
        Audience::new("api-published"),
        "the audience the registration published"
    );
    assert_eq!(
        context.credential, outcome.credential_id,
        "the credential this outcome issues"
    );
    assert_eq!(
        context.correlation,
        request().correlation,
        "the correlation the outcome mints for this request"
    );
    assert_eq!(context.actor, None);
    assert_eq!(context.delegation, None);
    assert_eq!(context.execution, None);
}

/// The epoch snapshot the response binds is the session's, because "a redemption presents no
/// source credential of its own". A session that names none binds none, and the declared
/// response field is `Optional` for that.
#[test]
fn the_epochs_are_the_sessions_own() {
    let mut deployment = Deployment::new();
    let (code_id, proof) = deployment.issue("2026-09-19T00:05:00Z");
    let input = redemption(code_id, &proof);

    let outcome = deployment
        .redeem(&input, &sessions())
        .expect("a fresh code");
    assert_eq!(outcome.epochs, Some(snapshot()));

    let mut deployment = Deployment::new();
    let (code_id, proof) = deployment.issue("2026-09-19T00:05:00Z");
    let input = redemption(code_id, &proof);
    let outcome = deployment
        .redeem(
            &input,
            &RecordedSessions::new().session(SessionBinding {
                epochs: None,
                ..session()
            }),
        )
        .expect("a live session that names no snapshot");
    assert_eq!(outcome.epochs, None);
}

/// **The credential remains bound to the code's target, scope and expiry.**
///
/// `credential.yaml`, the accepted summary. The target and the scope are the code record's.
/// The expiry is the earlier of the two bounds that exist: the profile's `max_ttl` from the
/// request instant — the bound every other issuance in this crate keeps — and the code's own
/// `expires_at`, which the summary names. Both halves are pinned: a short-lived code bounds
/// the credential below the profile, and a long-lived one does not raise it above.
#[test]
fn the_credential_is_bound_to_the_codes_target_scope_and_expiry() {
    let mut deployment = Deployment::new();
    let (code_id, proof) = deployment.issue("2026-09-19T00:05:00Z");
    let input = redemption(code_id, &proof);

    let outcome = deployment
        .redeem(&input, &sessions())
        .expect("a fresh code");

    assert_eq!(outcome.descriptor.scope, scope(), "the code's scope");
    assert_eq!(outcome.target, deployment.target, "the code's target");
    assert_eq!(
        outcome.descriptor.expires_at,
        Timestamp::new("2026-09-19T00:05:00Z"),
        "a code that expires before the profile's bound bounds the credential"
    );
    assert_eq!(outcome.descriptor.kind, CredentialKind::Reference);

    // A deployment whose code-lifetime ceiling is a day, so the code can outlive the
    // registration's one-hour profile and the other bound is the one that decides.
    let mut deployment = Deployment::new();
    let (code_id, proof) = deployment.issue_under("P1D", "2026-09-19T06:00:00Z");
    let input = redemption(code_id, &proof);
    let outcome = deployment
        .redeem(&input, &sessions())
        .expect("a fresh code");
    assert_eq!(
        outcome.descriptor.expires_at,
        Timestamp::new("2026-09-19T01:00:00Z"),
        "a code that outlives the profile's bound does not raise it"
    );
}

/// The second half of the acceptance: "a second redemption of the same code is the declared
/// wrong-state outcome".
#[test]
fn a_second_redemption_of_one_code_is_the_declared_wrong_state_outcome() {
    let mut deployment = Deployment::new();
    let (code_id, proof) = deployment.issue("2026-09-19T00:05:00Z");
    let input = redemption(code_id, &proof);

    deployment.redeem(&input, &sessions()).expect("the first");
    let refused = deployment
        .redeem(&input, &sessions())
        .expect_err("`consume` starts from `Issued` alone");

    assert_eq!(
        refused,
        RedemptionRefused::Denied(Denied::wrong_state(
            DenialReason::Denied,
            DenialClause::CodeConsumed
        ))
    );
    assert_eq!(
        deployment.credential_fold().credentials().len(),
        1,
        "the second redemption issues no credential"
    );
    assert_eq!(
        deployment.codes.events(&code_id).len(),
        2,
        "the refusal appends nothing"
    );
}

/// **The third half: two concurrent redemptions issue at most one credential.**
///
/// The race as ADR 0009 shapes it — no lock, a compare-and-set on the expected stream
/// version. Both readers take the version and decide against the same projection, so both
/// decisions are accepted; then both append, and the second presents a version the stream
/// has left. One `Ok`, one conflict, one credential, one consume in the log.
#[test]
fn two_concurrent_redemptions_of_one_code_issue_at_most_one_credential() {
    let mut deployment = Deployment::new();
    let (code_id, proof) = deployment.issue("2026-09-19T00:05:00Z");
    let input = redemption(code_id, &proof);
    let sessions = sessions();
    let servers = deployment.servers.clone();
    let clients = clients();
    let bound = || BoundReads {
        servers: &servers,
        clients: &clients,
        sessions: &sessions,
    };

    // Both readers read the same version and decide against the same projection.
    let expected = deployment.codes.version(&code_id);
    let one = redeem_authorization_code(
        &input,
        &request(),
        deployment.codes.projection(),
        bound(),
        RedemptionParts {
            digest: &Sha256Digest,
            secrets: &mut deployment.secrets,
            allocator: &mut deployment.allocator,
        },
    )
    .expect("the first decision");
    let two = redeem_authorization_code(
        &input,
        &request(),
        deployment.codes.projection(),
        bound(),
        RedemptionParts {
            digest: &Sha256Digest,
            secrets: &mut deployment.secrets,
            allocator: &mut deployment.allocator,
        },
    )
    .expect("the second decision, against the state the first read");
    assert_ne!(
        one.credential_id, two.credential_id,
        "two decisions minted two identities"
    );

    // Both append. Exactly one wins.
    let winner = deployment
        .codes
        .append(&code_id, expected, std::slice::from_ref(&one.event))
        .expect("the stream is still where it was read");
    let loser = deployment
        .codes
        .append(&code_id, expected, std::slice::from_ref(&two.event))
        .expect_err("the stream moved under the second writer");

    assert_eq!(
        loser,
        AppendRefused::Conflict {
            expected,
            actual: winner,
        }
    );
    assert_eq!(
        deployment.codes.events(&code_id).len(),
        2,
        "the issuance and one consume"
    );
    assert_eq!(
        deployment
            .codes
            .projection()
            .authorization_code(&code_id)
            .map(|code| code.state),
        Some(AuthorizationCodeState::Consumed)
    );

    // The log the credential fold reads carries the winner's credential and no other.
    deployment.credentials.push(
        one.event
            .credential_event()
            .expect("the redemption seeds a credential"),
    );
    let credentials = deployment.credential_fold();
    assert_eq!(credentials.credentials().len(), 1);
    assert!(credentials.access_credential(&one.credential_id).is_some());
    assert!(
        credentials.access_credential(&two.credential_id).is_none(),
        "the loser's credential never reaches a log"
    );
}

/// A transaction that loses its compare-and-set issues no credential, which is
/// `credential.yaml`'s "a failed or replayed transaction produces no credential" in the one
/// form a log can carry.
#[test]
fn a_redemption_that_loses_the_compare_and_set_writes_no_credential() {
    let mut deployment = Deployment::new();
    let (code_id, proof) = deployment.issue("2026-09-19T00:05:00Z");
    let input = redemption(code_id, &proof);
    deployment.codes.lose_the_next_append();

    let refused = deployment
        .redeem(&input, &sessions())
        .expect_err("the injected conflict");

    assert!(matches!(
        refused,
        RedemptionRefused::Append(AppendRefused::Conflict { .. })
    ));
    assert_eq!(deployment.credential_fold().credentials().len(), 0);
    assert_eq!(
        deployment
            .codes
            .projection()
            .authorization_code(&code_id)
            .map(|code| code.state),
        Some(AuthorizationCodeState::Issued),
        "the code is not consumed"
    );
    assert_eq!(deployment.codes.events(&code_id).len(), 1);
}

/// The command path appends the code's consume and nothing else in this crate's log: one
/// append group per boundary, on the code's own stream.
#[test]
fn the_command_path_appends_the_consume_and_nothing_else_in_this_crates_log() {
    let mut deployment = Deployment::new();
    let (code_id, proof) = deployment.issue("2026-09-19T00:05:00Z");
    let before = deployment.codes.version(&code_id);
    let input = redemption(code_id, &proof);

    let outcome = deployment
        .redeem(&input, &sessions())
        .expect("a fresh code");

    assert_eq!(deployment.codes.version(&code_id), before.advance());
    let appended = deployment.codes.events(&code_id);
    assert_eq!(appended.len(), 2);
    assert_eq!(appended[1], outcome.event);
    assert_eq!(
        appended[1].ess_name(),
        "mandate.credential.AuthorizationCodeRedeemed"
    );
}

/// Each way a redemption is refused, by the clause it names — and none of them writes
/// anything, consumes anything or issues a credential.
#[test]
fn each_declared_refusal_names_its_clause_and_writes_nothing() {
    let disabled_client = RecordedClients::new()
        .disabled(client(), organization(10))
        .redirect(client(), redirect());
    let stale_sessions = RecordedSessions::new()
        .session(session())
        .stale(snapshot(), SecurityEpochTarget::Principal(subject()));

    /// How a case shapes the redemption it presents, from the code it was issued.
    type Presentation = dyn Fn(AuthorizationCodeId, &CredentialProof) -> RedeemAuthorizationCode;

    struct Case {
        what: &'static str,
        input: Box<Presentation>,
        clients: RecordedClients,
        sessions: RecordedSessions,
        disable_target: bool,
        expected: Denied,
    }

    let matching = redemption;

    let cases = vec![
        Case {
            what: "a code no event created",
            input: Box::new(move |_, proof| RedeemAuthorizationCode {
                code_id: AuthorizationCodeId::new(uuid(0xad)),
                ..matching(AuthorizationCodeId::new(uuid(0xad)), proof)
            }),
            clients: clients(),
            sessions: sessions(),
            disable_target: false,
            expected: Denied::new(DenialReason::InvalidCredential, DenialClause::CodeUnknown),
        },
        Case {
            what: "a code proof that does not resolve to the named code",
            input: Box::new(move |code_id, _| RedeemAuthorizationCode {
                code: CredentialProof::from_bytes(b"not-the-code".to_vec()),
                ..matching(
                    code_id,
                    &CredentialProof::from_bytes(b"not-the-code".to_vec()),
                )
            }),
            clients: clients(),
            sessions: sessions(),
            disable_target: false,
            expected: Denied::new(
                DenialReason::InvalidCredential,
                DenialClause::CodeProofMismatch,
            ),
        },
        Case {
            what: "a redirect that is not the one the code authorized",
            input: Box::new(move |code_id, proof| RedeemAuthorizationCode {
                redirect_uri: RedirectUri::new("https://client.example/callback/"),
                ..matching(code_id, proof)
            }),
            clients: clients(),
            sessions: sessions(),
            disable_target: false,
            expected: Denied::new(DenialReason::Denied, DenialClause::RedirectMismatch),
        },
        Case {
            what: "a client that is not the one the code is bound to",
            input: Box::new(move |code_id, proof| RedeemAuthorizationCode {
                client_id: OAuthClientId::new(uuid(0x0d)),
                ..matching(code_id, proof)
            }),
            clients: clients(),
            sessions: sessions(),
            disable_target: false,
            expected: Denied::new(DenialReason::Denied, DenialClause::ClientMismatch),
        },
        Case {
            what: "a bound client that is disabled",
            input: Box::new(matching),
            clients: disabled_client,
            sessions: sessions(),
            disable_target: false,
            expected: Denied::new(DenialReason::Denied, DenialClause::ClientDisabled),
        },
        Case {
            what: "a session that resolves to nothing",
            input: Box::new(matching),
            clients: clients(),
            sessions: RecordedSessions::new(),
            disable_target: false,
            expected: Denied::new(
                DenialReason::InvalidCredential,
                DenialClause::SessionUnusable,
            ),
        },
        Case {
            what: "a stale session epoch",
            input: Box::new(matching),
            clients: clients(),
            sessions: stale_sessions,
            disable_target: false,
            expected: Denied::new(DenialReason::StaleEpoch, DenialClause::SessionEpochStale),
        },
        Case {
            what: "a registered target that has been disabled",
            input: Box::new(matching),
            clients: clients(),
            sessions: sessions(),
            disable_target: true,
            expected: Denied::new(DenialReason::Denied, DenialClause::TargetDisabled),
        },
        Case {
            what: "a verifier that does not redeem the recorded challenge",
            input: Box::new(move |code_id, proof| RedeemAuthorizationCode {
                pkce_verifier: CredentialProof::from_bytes(OTHER_VERIFIER.as_bytes().to_vec()),
                ..matching(code_id, proof)
            }),
            clients: clients(),
            sessions: sessions(),
            disable_target: false,
            expected: Denied::new(
                DenialReason::InvalidCredential,
                DenialClause::VerifierMismatch,
            ),
        },
        Case {
            what: "a verifier outside the form RFC 7636 declares",
            input: Box::new(move |code_id, proof| RedeemAuthorizationCode {
                pkce_verifier: CredentialProof::from_bytes(b"short".to_vec()),
                ..matching(code_id, proof)
            }),
            clients: clients(),
            sessions: sessions(),
            disable_target: false,
            expected: Denied::new(
                DenialReason::InvalidCredential,
                DenialClause::VerifierMalformed,
            ),
        },
    ];

    for case in cases {
        let mut deployment = Deployment::new();
        let (code_id, proof) = deployment.issue("2026-09-19T00:05:00Z");
        if case.disable_target {
            let event = disable_resource_server(
                &DisableResourceServer {
                    id: deployment.target,
                    context: context(organization(10)),
                },
                &deployment.servers,
            )
            .expect("an enabled registration");
            deployment.servers.apply(&event).expect("the disablement");
        }
        let minted = deployment.secrets.minted();
        let events = deployment.codes.events(&code_id).len();
        let input = (case.input)(code_id, &proof);
        let sessions = case.sessions;

        let refused = {
            let servers = deployment.servers.clone();
            let clients = case.clients;
            redeem_and_consume(
                &input,
                &request(),
                &mut deployment.codes,
                BoundReads {
                    servers: &servers,
                    clients: &clients,
                    sessions: &sessions,
                },
                RedemptionParts {
                    digest: &Sha256Digest,
                    secrets: &mut deployment.secrets,
                    allocator: &mut deployment.allocator,
                },
            )
            .expect_err(case.what)
        };

        assert_eq!(
            refused,
            RedemptionRefused::Denied(case.expected),
            "{}",
            case.what
        );
        assert_eq!(
            deployment.secrets.minted(),
            minted,
            "{}: a refusal mints no credential",
            case.what
        );
        assert_eq!(
            deployment.codes.events(&code_id).len(),
            events,
            "{}: a refusal appends nothing",
            case.what
        );
        assert_eq!(
            deployment
                .codes
                .projection()
                .authorization_code(&code_id)
                .map(|code| code.state),
            Some(AuthorizationCodeState::Issued),
            "{}: a refusal consumes nothing",
            case.what
        );
        assert_eq!(
            deployment.credential_fold().credentials().len(),
            0,
            "{}: a refusal issues no credential",
            case.what
        );
    }
}

/// An expired code is refused, and the instant is decided rather than the bytes compared:
/// the same code is admitted at an instant before its expiry and refused at one after.
#[test]
fn an_expired_code_is_refused_at_the_request_instant() {
    let mut deployment = Deployment::new();
    let (code_id, proof) = deployment.issue("2026-09-19T00:05:00Z");
    let input = redemption(code_id, &proof);
    let servers = deployment.servers.clone();
    let clients = clients();
    let sessions = sessions();

    let refused = redeem_authorization_code(
        &input,
        &RequestContext {
            at: Timestamp::new("2026-09-19T00:05:01Z"),
            ..request()
        },
        deployment.codes.projection(),
        BoundReads {
            servers: &servers,
            clients: &clients,
            sessions: &sessions,
        },
        RedemptionParts {
            digest: &Sha256Digest,
            secrets: &mut deployment.secrets,
            allocator: &mut deployment.allocator,
        },
    )
    .expect_err("the code expired a second ago");

    assert_eq!(
        refused,
        Denied::new(DenialReason::InvalidCredential, DenialClause::CodeExpired)
    );
    assert_eq!(refused.outcome, RefusedOutcome::Denied);
}

/// The wrong-state refusal is the one the contract renders differently, and it is the only
/// one this command takes: every other refusal here is the external `denied`.
#[test]
fn only_the_consumed_code_takes_the_wrong_state_outcome() {
    let mut deployment = Deployment::new();
    let (code_id, proof) = deployment.issue("2026-09-19T00:05:00Z");
    let input = redemption(code_id, &proof);
    deployment.redeem(&input, &sessions()).expect("the first");

    let RedemptionRefused::Denied(refused) = deployment
        .redeem(&input, &sessions())
        .expect_err("the code is consumed")
    else {
        panic!("a decision refusal, not an append refusal");
    };

    assert_eq!(refused.outcome, RefusedOutcome::WrongState);
    assert_eq!(refused.clause, DenialClause::CodeConsumed);
}

/// The fold and the live projection agree, and the whole road rebuilds from `&[]`.
#[test]
fn the_whole_transaction_rebuilds_from_an_empty_log() {
    let mut deployment = Deployment::new();
    let (code_id, proof) = deployment.issue("2026-09-19T00:05:00Z");
    let input = redemption(code_id, &proof);
    let outcome = deployment
        .redeem(&input, &sessions())
        .expect("a fresh code");

    let rebuilt =
        CodeProjection::fold(&deployment.codes.events(&code_id)).expect("a log of accepted events");

    assert_eq!(&rebuilt, deployment.codes.projection());
    assert_eq!(
        rebuilt.authorization_code(&code_id).map(|code| code.state),
        Some(AuthorizationCodeState::Consumed)
    );
    assert_eq!(
        deployment
            .credential_fold()
            .access_credential(&outcome.credential_id)
            .map(|record| record.state),
        Some(AccessCredentialState::Active)
    );
    assert_eq!(
        CodeProjection::fold(&[]).expect("an empty log"),
        CodeProjection::default()
    );
}

/// **Possession is decided before anything is read about the deployment.**
///
/// Adversary pass 2, F3. `mandate.credential.Denied` carries `DenialReason` on the wire, so
/// every refusal after possession is an *answer*: whether a session is live, whether a
/// client is registered and enabled, whether a target is inside a tenant. A caller holding a
/// stolen code and no PKCE verifier is not the client the code was issued to, and is told
/// one thing.
///
/// Each arrangement below would answer a different clause if the re-reads ran first — a
/// revoked session, a client of another organization, a disabled client, a disabled target —
/// and every one of them answers the verifier clause instead, with the same reason. The
/// class is enumerated rather than sampled: one case per re-read the ruling names.
#[test]
fn a_caller_without_the_verifier_learns_nothing_about_session_client_or_tenant() {
    let wrong_verifier = Denied::new(
        DenialReason::InvalidCredential,
        DenialClause::VerifierMismatch,
    );
    let revoked_session = RecordedSessions::new()
        .session(SessionBinding {
            revoked: true,
            ..session()
        })
        .current(snapshot());
    let stale_session = RecordedSessions::new()
        .session(session())
        .stale(snapshot(), SecurityEpochTarget::Principal(subject()));

    for (what, sessions, clients, disable_target) in [
        ("a revoked session", revoked_session, clients(), false),
        ("a stale session epoch", stale_session, clients(), false),
        (
            "no session at all",
            RecordedSessions::new(),
            clients(),
            false,
        ),
        (
            "a client of another organization",
            sessions(),
            RecordedClients::new()
                .enabled(client(), organization(11))
                .redirect(client(), redirect()),
            false,
        ),
        (
            "a disabled client",
            sessions(),
            RecordedClients::new()
                .disabled(client(), organization(10))
                .redirect(client(), redirect()),
            false,
        ),
        ("a disabled target", sessions(), clients(), true),
    ] {
        let mut deployment = Deployment::new();
        let (code_id, proof) = deployment.issue("2026-09-19T00:05:00Z");
        if disable_target {
            let event = disable_resource_server(
                &DisableResourceServer {
                    id: deployment.target,
                    context: context(organization(10)),
                },
                &deployment.servers,
            )
            .expect("an enabled registration");
            deployment.servers.apply(&event).expect("the disablement");
        }
        let servers = deployment.servers.clone();

        let refused = redeem_authorization_code(
            &RedeemAuthorizationCode {
                pkce_verifier: CredentialProof::from_bytes(OTHER_VERIFIER.as_bytes().to_vec()),
                ..redemption(code_id, &proof)
            },
            &request(),
            deployment.codes.projection(),
            BoundReads {
                servers: &servers,
                clients: &clients,
                sessions: &sessions,
            },
            RedemptionParts {
                digest: &Sha256Digest,
                secrets: &mut deployment.secrets,
                allocator: &mut deployment.allocator,
            },
        )
        .expect_err(what);

        assert_eq!(
            refused, wrong_verifier,
            "{what}: a caller without the verifier is told the verifier is wrong, and \
             nothing about the deployment"
        );
    }

    // And the verifier is not a way to probe the code space either: a `code_id` that
    // resolves to nothing carries the same wire reason as a proof that does not match one.
    let mut deployment = Deployment::new();
    let (code_id, proof) = deployment.issue("2026-09-19T00:05:00Z");
    let servers = deployment.servers.clone();
    let clients = clients();
    let sessions = sessions();
    let refuse = |deployment: &mut Deployment, input: &RedeemAuthorizationCode| {
        redeem_authorization_code(
            input,
            &request(),
            deployment.codes.projection(),
            BoundReads {
                servers: &servers,
                clients: &clients,
                sessions: &sessions,
            },
            RedemptionParts {
                digest: &Sha256Digest,
                secrets: &mut deployment.secrets,
                allocator: &mut deployment.allocator,
            },
        )
        .expect_err("a refusal")
    };
    let unknown = refuse(
        &mut deployment,
        &RedeemAuthorizationCode {
            code_id: AuthorizationCodeId::new(uuid(0xad)),
            ..redemption(code_id, &proof)
        },
    );
    let mismatch = refuse(
        &mut deployment,
        &RedeemAuthorizationCode {
            code: CredentialProof::from_bytes(b"not-the-code".to_vec()),
            ..redemption(code_id, &proof)
        },
    );
    assert_eq!(
        unknown.reason, mismatch.reason,
        "the declared wire field does not say whether a code_id exists"
    );
    assert_eq!(unknown.reason, DenialReason::InvalidCredential);
    assert_ne!(
        unknown.clause, mismatch.clause,
        "the crate-local clause still tells them apart, and no wire form carries it"
    );
}
