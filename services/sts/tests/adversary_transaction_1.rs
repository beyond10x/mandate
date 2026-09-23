//! Adversarial cases against `story:oauth-transaction`'s STS transaction.
//!
//! Written against `systems/mandate/domains/credential.yaml` (the two commands, their
//! denials and their accepted summaries), `docs/architecture/command-obligations.md:13,16`
//! and RFC 7636, and run against the handlers the unit shipped. Each case says in its own
//! documentation whether it holds against the tree or drives it from the document.
//!
//! Nothing here constructs a code record by hand: every code is issued through
//! `CodeIssuance::issue` and every redemption goes through the real decider or the real
//! command path, so a case cannot pass against a record no command could have written.

use std::cell::Cell;

use mandate_sts::binding::{RecordedSessions, SessionBinding};
use mandate_sts::code::{
    AuthorizationCodeParts, CodeIssuance, CodeLifetime, IssueAuthorizationCode, RecordedClients,
    challenge_is_well_formed, s256_challenge,
};
use mandate_sts::issue::{
    IssueReferenceCredential, ReferenceParts, Sha256Digest, issue_reference_credential,
};
use mandate_sts::redemption::{
    AuthorizationCodeRedemption, BoundReads, RedeemAuthorizationCode, RedemptionParts,
    RedemptionRefused, redeem_and_consume, redeem_authorization_code,
};
use mandate_sts::registry::{RegisterResourceServer, register_resource_server};
use mandate_sts::resolve::{
    IntrospectCredential, IntrospectionParts, RevokeAccessCredential, introspect_credential,
    revoke_access_credential,
};
use mandate_sts::store::{
    AppendRefused, AuthorizationCodeEvent, AuthorizationCodeLog, AuthorizationCodeState,
    CodeProjection, InMemoryCodeLog, StreamVersion,
};
use mandate_sts::{CountingSecrets, IdentityAllocator, RequestContext, SequentialAllocator};
use mandate_token::CredentialProfile;
use mandate_token::projection::{
    AccessCredentialState, CredentialEvent, DenialClause, Denied, Projection, RefusedOutcome,
};
use mandate_token::verifier::{CredentialDomain, verifier_in};
use mandate_types::{
    Audience, AuthorityScope, AuthorizationCodeId, CorrelationId, CredentialId, CredentialKind,
    CredentialProof, DenialReason, Duration, EpochSnapshotRef, OAuthClientId, OrganizationId,
    PkceChallenge, PkceMethod, PrincipalId, RedirectUri, ResourceServerId, RevocationGuarantee,
    SessionId, Timestamp, Transient, Uuid, VerifiedContext,
};

/// RFC 7636 appendix B: the example code verifier and the S256 challenge it redeems.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

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
        correlation: CorrelationId::new("adversary"),
    }
}

fn request() -> RequestContext {
    RequestContext {
        correlation: CorrelationId::new("adversary"),
        at: Timestamp::new("2026-09-19T00:00:00Z"),
        epochs: None,
    }
}

fn request_at(at: &str) -> RequestContext {
    RequestContext {
        at: Timestamp::new(at),
        ..request()
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

/// A registration, a code log and the doubles a redemption reads through.
struct Deployment {
    servers: Projection,
    target: ResourceServerId,
    codes: InMemoryCodeLog,
    secrets: CountingSecrets,
    allocator: SequentialAllocator,
    credentials: Vec<CredentialEvent>,
}

impl Deployment {
    fn new() -> Self {
        let mut allocator = SequentialAllocator::new();
        let outcome = register_resource_server(
            &RegisterResourceServer {
                context: context(organization(10)),
                audience: Audience::new("api-a"),
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

    /// One code, issued through the real handler with the challenge and expiry a case names,
    /// appended to its own stream.
    fn issue_with(
        &mut self,
        challenge: &PkceChallenge,
        redirect_uri: &RedirectUri,
        expires_at: &str,
    ) -> (AuthorizationCodeId, CredentialProof) {
        self.issue_under("PT5M", challenge, redirect_uri, expires_at)
    }

    /// The same, under a deployment code-lifetime ceiling a case names.
    fn issue_under(
        &mut self,
        ceiling: &str,
        challenge: &PkceChallenge,
        redirect_uri: &RedirectUri,
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
                    challenge: challenge.clone(),
                    method: PkceMethod::S256,
                    redirect_uri: redirect_uri.clone(),
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

    fn issue(&mut self) -> (AuthorizationCodeId, CredentialProof) {
        self.issue_with(
            &PkceChallenge::new(CHALLENGE),
            &redirect(),
            "2026-09-19T00:05:00Z",
        )
    }

    fn decide(
        &mut self,
        input: &RedeemAuthorizationCode,
        request: &RequestContext,
        sessions: &RecordedSessions,
    ) -> Result<AuthorizationCodeRedemption, Denied> {
        let servers = self.servers.clone();
        let clients = clients();
        redeem_authorization_code(
            input,
            request,
            self.codes.projection(),
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
        )
    }

    fn redeem(
        &mut self,
        input: &RedeemAuthorizationCode,
        sessions: &RecordedSessions,
        clients: &RecordedClients,
    ) -> Result<AuthorizationCodeRedemption, RedemptionRefused> {
        let servers = self.servers.clone();
        let outcome = redeem_and_consume(
            input,
            &request(),
            &mut self.codes,
            BoundReads {
                servers: &servers,
                clients,
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

    fn credential_fold(&self) -> Projection {
        Projection::fold(&self.credentials).expect("a log of accepted events")
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

// --- an independent S256 oracle ----------------------------------------------------------

/// Unpadded base64url (RFC 4648 section 5), written here and not shared with the code under
/// attack: `mandate-sts` and `mandate-federation` each carry their own copy of the encoder
/// (`services/sts/src/code.rs`, `crates/mandate-federation/src/pkce.rs`), so a case that
/// called either would be comparing a copy with itself.
fn base64url_oracle(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut text = String::new();
    let mut index = 0;
    while index < bytes.len() {
        let remaining = bytes.len() - index;
        let first = u32::from(bytes[index]);
        let second = if remaining > 1 {
            u32::from(bytes[index + 1])
        } else {
            0
        };
        let third = if remaining > 2 {
            u32::from(bytes[index + 2])
        } else {
            0
        };
        let block = (first << 16) | (second << 8) | third;
        text.push(char::from(ALPHABET[((block >> 18) & 63) as usize]));
        text.push(char::from(ALPHABET[((block >> 12) & 63) as usize]));
        if remaining > 1 {
            text.push(char::from(ALPHABET[((block >> 6) & 63) as usize]));
        }
        if remaining > 2 {
            text.push(char::from(ALPHABET[(block & 63) as usize]));
        }
        index += 3;
    }
    text
}

/// `BASE64URL-ENCODE(SHA256(ASCII(verifier)))`, through `aws-lc-rs` rather than `sha2`.
fn oracle_challenge(verifier: &[u8]) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, verifier);
    base64url_oracle(digest.as_ref())
}

/// A deterministic run of verifiers of every declared length, over the unreserved set.
fn verifiers_of_every_declared_length() -> Vec<Vec<u8>> {
    const UNRESERVED: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    let mut state: u64 = 0x2026_0919_0000_0001;
    let mut all = Vec::new();
    for length in 43..=128_usize {
        let mut verifier = Vec::with_capacity(length);
        for _ in 0..length {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            verifier.push(UNRESERVED[(state % UNRESERVED.len() as u64) as usize]);
        }
        all.push(verifier);
    }
    all
}

/// **The S256 half agrees with an independent implementation, over every declared verifier
/// length.**
///
/// `credential.yaml` declares the challenge as S256 and `crates/mandate-federation/src/pkce.rs`
/// builds the challenge the control plane validates; `services/sts/src/code.rs` builds the one
/// the STS compares against. The two are separate copies of one rule, and `mandate-sts` cannot
/// name `mandate-federation` (`dependency-boundaries.json`), so what is decided here is that the
/// STS copy is `BASE64URL-ENCODE(SHA256(ASCII(verifier)))` and nothing else — against a
/// different SHA-256 (`aws-lc-rs`) and a base64url encoder written here.
///
/// Holds against the tree.
#[test]
fn the_s256_challenge_agrees_with_an_independent_digest_and_encoder() {
    assert_eq!(
        s256_challenge(&CredentialProof::from_bytes(VERIFIER.as_bytes().to_vec())).as_str(),
        CHALLENGE,
        "RFC 7636 appendix B"
    );
    assert_eq!(oracle_challenge(VERIFIER.as_bytes()), CHALLENGE);

    for verifier in verifiers_of_every_declared_length() {
        let built = s256_challenge(&CredentialProof::from_bytes(verifier.clone()));
        assert_eq!(
            built.as_str(),
            oracle_challenge(&verifier),
            "the STS S256 challenge of a {}-byte verifier",
            verifier.len()
        );
        assert!(
            challenge_is_well_formed(&built),
            "a challenge this crate builds is one it admits"
        );
    }
}

/// **A challenge the control plane would build round-trips through issuance and redemption.**
///
/// The whole road for every declared verifier length: build the challenge, record it through
/// `IssueAuthorizationCode`, and redeem with the verifier it was built from.
///
/// Holds against the tree.
#[test]
fn every_declared_verifier_length_round_trips_through_issuance_and_redemption() {
    for verifier in verifiers_of_every_declared_length() {
        let challenge = PkceChallenge::new(oracle_challenge(&verifier));
        let mut deployment = Deployment::new();
        let (code_id, proof) =
            deployment.issue_with(&challenge, &redirect(), "2026-09-19T00:05:00Z");

        let outcome = deployment
            .redeem(
                &RedeemAuthorizationCode {
                    pkce_verifier: CredentialProof::from_bytes(verifier.clone()),
                    ..redemption(code_id, &proof)
                },
                &sessions(),
                &clients(),
            )
            .unwrap_or_else(|refused| {
                panic!(
                    "a {}-byte verifier that built the recorded challenge: {refused}",
                    verifier.len()
                )
            });
        assert_eq!(deployment.credential_fold().credentials().len(), 1);
        assert_eq!(outcome.target, deployment.target);
    }
}

/// **The declared verifier form is refused at both ends of the range, and the empty verifier
/// with it.**
///
/// RFC 7636 section 4.1: 43 to 128 characters of the unreserved set. 42 and 129 are the two
/// values a `<`/`<=` slip admits; the empty verifier is the third boundary.
///
/// Holds against the tree.
#[test]
fn the_verifier_form_is_refused_one_character_outside_the_declared_range() {
    for outside in [
        Vec::new(),
        vec![b'a'; 1],
        vec![b'a'; 42],
        vec![b'a'; 129],
        vec![b'a'; 1024],
    ] {
        let mut deployment = Deployment::new();
        let (code_id, proof) = deployment.issue();
        let refused = deployment
            .decide(
                &RedeemAuthorizationCode {
                    pkce_verifier: CredentialProof::from_bytes(outside.clone()),
                    ..redemption(code_id, &proof)
                },
                &request(),
                &sessions(),
            )
            .expect_err("a verifier outside the declared form");
        assert_eq!(
            refused.clause,
            DenialClause::VerifierMalformed,
            "a {}-byte verifier",
            outside.len()
        );
        assert_eq!(refused.reason, DenialReason::InvalidCredential);
    }

    // A character outside the unreserved set, at the declared minimum length.
    let mut outside = vec![b'a'; 43];
    outside[42] = b'!';
    let mut deployment = Deployment::new();
    let (code_id, proof) = deployment.issue();
    assert_eq!(
        deployment
            .decide(
                &RedeemAuthorizationCode {
                    pkce_verifier: CredentialProof::from_bytes(outside),
                    ..redemption(code_id, &proof)
                },
                &request(),
                &sessions(),
            )
            .expect_err("a character outside the unreserved set")
            .clause,
        DenialClause::VerifierMalformed
    );
}

/// **A verifier that redeems another code does not redeem this one.**
///
/// Two codes issued in one deployment under two challenges; each verifier redeems its own
/// code and neither redeems the other.
///
/// Holds against the tree.
#[test]
fn a_verifier_for_another_code_does_not_redeem_this_one() {
    let other_verifier = b"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ".to_vec();
    let other_challenge = PkceChallenge::new(oracle_challenge(&other_verifier));

    let mut deployment = Deployment::new();
    let (mine, my_proof) = deployment.issue();
    let (theirs, their_proof) =
        deployment.issue_with(&other_challenge, &redirect(), "2026-09-19T00:05:00Z");

    assert_eq!(
        deployment
            .decide(
                &RedeemAuthorizationCode {
                    pkce_verifier: CredentialProof::from_bytes(other_verifier.clone()),
                    ..redemption(mine, &my_proof)
                },
                &request(),
                &sessions(),
            )
            .expect_err("the other code's verifier")
            .clause,
        DenialClause::VerifierMismatch
    );
    assert_eq!(
        deployment
            .decide(
                &RedeemAuthorizationCode {
                    pkce_verifier: CredentialProof::from_bytes(VERIFIER.as_bytes().to_vec()),
                    ..redemption(theirs, &their_proof)
                },
                &request(),
                &sessions(),
            )
            .expect_err("this code's verifier against the other code")
            .clause,
        DenialClause::VerifierMismatch
    );
    // And the code proof of one code does not resolve the other.
    assert_eq!(
        deployment
            .decide(&redemption(mine, &their_proof), &request(), &sessions())
            .expect_err("another code's proof")
            .clause,
        DenialClause::CodeProofMismatch
    );
}

/// **The redirect comparison normalizes nothing.**
///
/// `binding.rs`'s module documentation enumerates what a normalizing comparison would admit:
/// the case of the scheme or the host, a trailing slash, a default port, a percent-encoding
/// of an unreserved character, a dot segment. Each is presented here, and a query string
/// with it, against a code issued for the bare authorized URI.
///
/// Holds against the tree.
#[test]
fn the_redirect_comparison_admits_none_of_the_normalizations_it_names() {
    for presented in [
        "https://client.example/callback/",
        "https://Client.Example/callback",
        "HTTPS://client.example/callback",
        "https://client.example:443/callback",
        "https://client.example/callback?code=1",
        "https://client.example/callback#fragment",
        "https://client.example/./callback",
        "https://client.example/other/../callback",
        "https://client.example/callb%61ck",
        "https://client.example/callback ",
        " https://client.example/callback",
        "https://client.example/CALLBACK",
    ] {
        let mut deployment = Deployment::new();
        let (code_id, proof) = deployment.issue();
        let refused = deployment
            .redeem(
                &RedeemAuthorizationCode {
                    redirect_uri: RedirectUri::new(presented),
                    ..redemption(code_id, &proof)
                },
                &sessions(),
                &clients(),
            )
            .expect_err(presented);
        assert_eq!(
            refused,
            RedemptionRefused::Denied(Denied::new(
                DenialReason::Denied,
                DenialClause::RedirectMismatch
            )),
            "{presented} is not the redirect the code authorized"
        );
        assert_eq!(deployment.credential_fold().credentials().len(), 0);
        assert_eq!(deployment.codes.events(&code_id).len(), 1);
    }
}

/// **A code is redeemable strictly before the instant it expires at, and not at it.**
///
/// The boundary a `<`/`<=` slip moves: one second before is accepted, the instant itself is
/// refused, one second after is refused. The same code, three request instants.
///
/// Holds against the tree.
#[test]
fn a_code_is_not_redeemable_at_the_instant_it_expires_at() {
    for (at, admitted) in [
        ("2026-09-19T00:04:59Z", true),
        ("2026-09-19T00:05:00Z", false),
        ("2026-09-19T00:05:01Z", false),
    ] {
        let mut deployment = Deployment::new();
        let (code_id, proof) = deployment.issue();
        let decided = deployment.decide(&redemption(code_id, &proof), &request_at(at), &sessions());
        match (admitted, decided) {
            (true, Ok(_)) => {}
            (false, Err(denied)) => {
                assert_eq!(denied.clause, DenialClause::CodeExpired, "at {at}");
                assert_eq!(denied.reason, DenialReason::InvalidCredential, "at {at}");
            }
            (true, Err(denied)) => panic!("at {at} the code is not yet expired: {denied}"),
            (false, Ok(_)) => panic!("at {at} the code has expired and was redeemed"),
        }
    }
}

/// **A code bound to a client of another organization than the session's is refused.**
///
/// "`registered target is disabled or outside the verified tenant`" has a client half:
/// `crate::code::admitted_client` is re-run at redemption against the organization the
/// session binds, never a caller-supplied one. The clause the refusal names is
/// `ClientOutsideOrganization` with `TenantMismatch`, which the unit's own refusal table in
/// `services/sts/tests/redemption.rs` does not cover.
///
/// Holds against the tree.
#[test]
fn a_client_registered_to_another_organization_than_the_sessions_is_refused() {
    let mut deployment = Deployment::new();
    let (code_id, proof) = deployment.issue();

    let refused = deployment
        .redeem(
            &redemption(code_id, &proof),
            &sessions(),
            &RecordedClients::new().enabled(client(), organization(11)),
        )
        .expect_err("the client belongs to another organization than the session");

    assert_eq!(
        refused,
        RedemptionRefused::Denied(Denied::new(
            DenialReason::TenantMismatch,
            DenialClause::ClientOutsideOrganization
        ))
    );
    assert_eq!(deployment.credential_fold().credentials().len(), 0);
    assert_eq!(deployment.codes.events(&code_id).len(), 1);

    // And a client no registration answers for at all.
    let mut deployment = Deployment::new();
    let (code_id, proof) = deployment.issue();
    assert_eq!(
        deployment
            .redeem(
                &redemption(code_id, &proof),
                &sessions(),
                &RecordedClients::new(),
            )
            .expect_err("the client is registered nowhere"),
        RedemptionRefused::Denied(Denied::new(
            DenialReason::Denied,
            DenialClause::ClientUnregistered
        ))
    );
}

/// **A session revoked, expired or unresolvable between issuance and redemption is refused,
/// and the refusal writes nothing.**
///
/// The three ways the session re-read fails that the unit's redemption refusal table does not
/// drive end to end: `SessionRevoked`, `SessionExpired`, and a snapshot the reader cannot
/// resolve — which must fail closed, because nothing established that it is current.
///
/// Holds against the tree.
#[test]
fn a_session_that_stopped_being_usable_between_issuance_and_redemption_is_refused() {
    let revoked = RecordedSessions::new()
        .session(SessionBinding {
            revoked: true,
            ..session()
        })
        .current(snapshot());
    let expired = RecordedSessions::new()
        .session(SessionBinding {
            expires_at: Timestamp::new("2026-09-18T23:59:59Z"),
            ..session()
        })
        .current(snapshot());
    // The snapshot is named by the session and recorded by nothing: the reader answers
    // `None`, which is not "current".
    let unresolvable = RecordedSessions::new().session(session());
    let undatable = RecordedSessions::new()
        .session(SessionBinding {
            expires_at: Timestamp::new("whenever"),
            ..session()
        })
        .current(snapshot());

    for (what, sessions, reason, clause) in [
        (
            "revoked",
            revoked,
            DenialReason::InvalidCredential,
            DenialClause::SessionUnusable,
        ),
        (
            "expired",
            expired,
            DenialReason::InvalidCredential,
            DenialClause::SessionUnusable,
        ),
        (
            "an unresolvable snapshot",
            unresolvable,
            DenialReason::Unavailable,
            DenialClause::SessionEpochStale,
        ),
        (
            "an expiry naming no instant",
            undatable,
            DenialReason::InvalidCredential,
            DenialClause::SessionUnusable,
        ),
    ] {
        let mut deployment = Deployment::new();
        let (code_id, proof) = deployment.issue();
        let refused = deployment
            .redeem(&redemption(code_id, &proof), &sessions, &clients())
            .expect_err(what);
        assert_eq!(
            refused,
            RedemptionRefused::Denied(Denied::new(reason, clause)),
            "a session that is {what}"
        );
        assert_eq!(
            deployment.credential_fold().credentials().len(),
            0,
            "{what}"
        );
        assert_eq!(deployment.codes.events(&code_id).len(), 1, "{what}");
        assert_eq!(
            deployment
                .codes
                .projection()
                .authorization_code(&code_id)
                .map(|code| code.state),
            Some(AuthorizationCodeState::Issued),
            "{what}: the code is not consumed"
        );
    }
}

/// A log that answers the true stream version once and a version the stream is not at every
/// time after, and records the version the command path presented to the append.
///
/// The probe for a dead compare-and-set: if `redeem_and_consume` read the version *after*
/// deciding, or presented anything but the version it read, the append would be handed 99
/// and refuse. Nothing else in the suite distinguishes the two orders.
struct VersionProbe {
    inner: InMemoryCodeLog,
    reads: Cell<u32>,
    presented: Cell<Option<StreamVersion>>,
}

impl VersionProbe {
    fn over(inner: InMemoryCodeLog) -> Self {
        Self {
            inner,
            reads: Cell::new(0),
            presented: Cell::new(None),
        }
    }
}

impl AuthorizationCodeLog for VersionProbe {
    fn version(&self, stream: &AuthorizationCodeId) -> StreamVersion {
        self.reads.set(self.reads.get() + 1);
        if self.reads.get() == 1 {
            self.inner.version(stream)
        } else {
            StreamVersion::new(99)
        }
    }

    fn projection(&self) -> &CodeProjection {
        self.inner.projection()
    }

    fn append(
        &mut self,
        stream: &AuthorizationCodeId,
        expected: StreamVersion,
        group: &[AuthorizationCodeEvent],
    ) -> Result<StreamVersion, AppendRefused> {
        self.presented.set(Some(expected));
        self.inner.append(stream, expected, group)
    }
}

/// **The command path presents the version it read before deciding, and the append consults
/// it.**
///
/// Two halves. First: the version the append is handed is the one read before the decision,
/// shown by a log that answers a different version on every later read. Second: the double's
/// compare-and-set refuses a version the stream is *ahead of* as well as one it has left —
/// the existing cases only present a stale version, so a guard written `expected < actual`
/// would keep them green.
///
/// Holds against the tree.
#[test]
fn the_command_path_presents_the_version_it_read_and_the_append_compares_it_both_ways() {
    let mut deployment = Deployment::new();
    let (code_id, proof) = deployment.issue();
    let before = deployment.codes.version(&code_id);
    let servers = deployment.servers.clone();
    let clients = clients();
    let sessions = sessions();
    let mut probe = VersionProbe::over(deployment.codes.clone());

    let outcome = redeem_and_consume(
        &redemption(code_id, &proof),
        &request(),
        &mut probe,
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
    .expect("the version read before the decision is the one the stream is at");

    assert_eq!(
        probe.presented.get(),
        Some(before),
        "the append is handed the version the command path read before it decided"
    );
    assert_eq!(probe.reads.get(), 1, "the version is read once");
    assert_eq!(
        probe.inner.projection().authorization_code(&code_id),
        outcome
            .event
            .credential_event()
            .map(|_| ())
            .and(probe.inner.projection().authorization_code(&code_id))
    );

    // The compare-and-set is an equality, not an ordering.
    let mut log = deployment.codes.clone();
    let actual = log.version(&code_id);
    let redeemed = outcome.event.clone();
    let ahead = StreamVersion::new(u64::try_from(actual.get()).expect("a small version") + 1);
    assert_eq!(
        log.append(&code_id, ahead, std::slice::from_ref(&redeemed))
            .expect_err("a version the stream has not reached"),
        AppendRefused::Conflict {
            expected: ahead,
            actual,
        },
        "an expected version ahead of the stream is refused, not only a stale one"
    );
    assert!(log.events(&code_id).len() == 1);
}

/// **A credential a redemption issued introspects active, and inactive once revoked.**
///
/// `story:credential-profiles`' acceptance, reached through the redemption road rather than
/// through `IssueReferenceCredential`: the record the `mandate-token` fold materialized from
/// `AuthorizationCodeRedeemed` resolves through the real `resolve` for the proof the
/// redemption returned, and answers inactive at the next authorized introspection after
/// `RevokeAccessCredential`.
///
/// Holds against the tree.
#[test]
fn a_redemption_issued_credential_introspects_active_and_then_inactive_after_revocation() {
    let mut deployment = Deployment::new();

    // A caller of the same registration, so the introspection is authorized.
    let caller = issue_reference_credential(
        &IssueReferenceCredential {
            context: context(organization(10)),
            target: deployment.target,
            requested_scope: scope(),
        },
        &request(),
        &deployment.servers,
        ReferenceParts {
            digest: &Sha256Digest,
            secrets: &mut deployment.secrets,
            allocator: &mut deployment.allocator,
        },
    )
    .expect("a registered enabled target of the caller's organization");
    let caller_proof = CredentialProof::from_bytes(caller.credential.expose_material().to_vec());
    deployment.credentials.push(caller.event);

    let (code_id, proof) = deployment.issue();
    let outcome = deployment
        .redeem(&redemption(code_id, &proof), &sessions(), &clients())
        .expect("a fresh code");
    let credential_proof =
        CredentialProof::from_bytes(outcome.credential.expose_material().to_vec());

    let held = deployment.credential_fold();
    let answer = introspect_credential(
        &IntrospectCredential {
            caller_proof: CredentialProof::from_bytes(caller_proof.expose_material().to_vec()),
            credential_proof: CredentialProof::from_bytes(
                credential_proof.expose_material().to_vec(),
            ),
        },
        &request(),
        &held,
        IntrospectionParts {
            digest: &Sha256Digest,
            resolution: &held,
        },
    )
    .expect("an authorized introspection");
    assert!(
        answer.active,
        "the credential the redemption issued is live"
    );
    assert_eq!(answer.credential_id, Some(outcome.credential_id));
    assert_eq!(answer.descriptor, Some(outcome.descriptor.clone()));
    assert_eq!(
        held.access_credential(&outcome.credential_id)
            .map(|record| record.state),
        Some(AccessCredentialState::Active)
    );

    // Revoked through the declared command, then introspected again.
    let revoked = revoke_access_credential(
        &RevokeAccessCredential {
            id: outcome.credential_id,
            context: context(organization(10)),
        },
        &held,
    )
    .expect("an active credential of the caller's own organization");
    deployment.credentials.push(revoked);
    let held = deployment.credential_fold();

    let answer = introspect_credential(
        &IntrospectCredential {
            caller_proof,
            credential_proof,
        },
        &request(),
        &held,
        IntrospectionParts {
            digest: &Sha256Digest,
            resolution: &held,
        },
    )
    .expect("an authorized introspection is still accepted");
    assert!(!answer.active, "the next introspection reports inactive");
    assert_eq!(answer.descriptor, None);
    assert_eq!(answer.credential_id, None);
}

/// **`IssueAuthorizationCode` bounds the code's expiry above by the deployment's ceiling.**
///
/// `credential.yaml`'s denial for this command names "bounded expiry validation fails" and
/// declares no ceiling anywhere — not on the entity, not on `mandate.core.CredentialProfile`,
/// not on any `mandate.core` type — so the ceiling is the deployment's, supplied as
/// `CodeLifetime` when the issuance is constructed (wave C, correction round 1, ruling 3).
/// An expiry beyond `request.at + ceiling` is refused with the declared phrase and nothing is
/// minted; an expiry exactly at the ceiling is admitted. Pass 1 of this adversary found the
/// handler bounded the expiry below only; this case now pins the ruled behaviour.
#[test]
fn an_authorization_code_expiry_has_no_declared_ceiling() {
    let mut deployment = Deployment::new();
    let before = deployment.secrets.minted();
    let refused = CodeIssuance::new(CodeLifetime::new(Duration::new("PT5M")))
        .issue(
            &IssueAuthorizationCode {
                context: context(organization(10)),
                client_id: client(),
                session_id: session_id(),
                target: deployment.target,
                requested_scope: scope(),
                challenge: PkceChallenge::new(CHALLENGE),
                method: PkceMethod::S256,
                redirect_uri: redirect(),
                expires_at: Timestamp::new("9999-12-31T23:59:59Z"),
            },
            &request(),
            &deployment.servers,
            &clients(),
            AuthorizationCodeParts {
                digest: &Sha256Digest,
                secrets: &mut deployment.secrets,
                allocator: &mut deployment.allocator,
            },
        )
        .expect_err("an expiry eight thousand years past the ceiling is refused");
    assert_eq!(
        refused.clause,
        DenialClause::ExpiryUnbounded,
        "the declared phrase: bounded expiry validation fails"
    );
    assert_eq!(
        deployment.secrets.minted(),
        before,
        "a refused issuance mints no code secret"
    );

    // Exactly at the ceiling the code is admitted: the request instant plus five minutes.
    let (code_id, _) = deployment.issue_under(
        "PT5M",
        &PkceChallenge::new(CHALLENGE),
        &redirect(),
        "2026-09-19T00:05:00Z",
    );
    assert_eq!(
        deployment
            .codes
            .projection()
            .authorization_code(&code_id)
            .map(|code| code.expires_at),
        Some(Timestamp::new("2026-09-19T00:05:00Z")),
        "an expiry at the ceiling is recorded"
    );
}

/// **The credential expiry a redemption decides is always a timestamp the crate can read
/// back.**
///
/// `instant::at` renders a year with four digits, so an instant past `9999-12-31T23:59:59Z`
/// would be written in a form `instant::seconds_of` refuses — a credential whose expiry no
/// later comparison can date. The property: over every combination of a profile `max_ttl`
/// and a code expiry that reach the accepted outcome, the decided expiry parses, is after
/// the request instant, and is at or before both bounds.
///
/// Holds against the tree.
#[test]
fn the_decided_credential_expiry_is_always_a_readable_bounded_instant() {
    for max_ttl in ["PT1S", "PT1H", "P1D", "P36500D", "P3650000D", "P999999999D"] {
        for code_expiry in [
            "2026-09-19T00:00:01Z",
            "2026-09-19T00:05:00Z",
            "2027-09-19T00:00:00Z",
            "9999-12-31T23:59:59Z",
        ] {
            let mut allocator = SequentialAllocator::new();
            let profile = CredentialProfile {
                max_ttl: Duration::new(max_ttl),
                // `PT0S`: `admits_profile` refuses a positive-cache window wider than the
                // profile's own `max_ttl`, and `PT1S` is one of the bounds this case walks.
                positive_cache_ttl: Duration::new("PT0S"),
                ..reference_profile()
            };
            let (event, target) = match register_resource_server(
                &RegisterResourceServer {
                    context: context(organization(10)),
                    audience: Audience::new("api-a"),
                    profile: profile.clone(),
                    allowed_exchange_sources: Vec::new(),
                },
                &Projection::default(),
                &mut allocator,
            ) {
                Ok(registration) => (registration.event, registration.resource_server_id),
                // `admits_profile` refuses a bound that lands past the last four-digit year
                // from `3000-01-01` (`story:sts-lifetime-bounds`), so a record carrying one is
                // another writer's — constructed, as `obligations.rs` constructs its
                // zero-span record — and the redemption still re-reads it.
                Err(denied) => {
                    assert!(
                        matches!(max_ttl, "P3650000D" | "P999999999D"),
                        "{max_ttl}: refused at registration as {denied}"
                    );
                    assert_eq!(denied.clause, DenialClause::ProfileUnadmitted, "{max_ttl}");
                    let id = allocator.next_resource_server_id();
                    (
                        CredentialEvent::ResourceServerRegistered {
                            context: context(organization(10)),
                            id,
                            audience: Audience::new("api-a"),
                            credential_profile: profile,
                            allowed_exchange_sources: Vec::new(),
                        },
                        id,
                    )
                }
            };
            let servers = Projection::fold(std::slice::from_ref(&event)).expect("one creation");
            let mut deployment = Deployment {
                servers,
                target,
                codes: InMemoryCodeLog::new(),
                secrets: CountingSecrets::new(),
                allocator,
                credentials: vec![event],
            };
            // The deployment's code-lifetime ceiling (wave C correction 1) admits each
            // arrangement this case walks; the property under test is the decided
            // credential expiry, not the ceiling.
            let (code_id, proof) = deployment.issue_under(
                "P9999999D",
                &PkceChallenge::new(CHALLENGE),
                &redirect(),
                code_expiry,
            );

            let outcome = deployment
                .decide(&redemption(code_id, &proof), &request(), &sessions())
                .unwrap_or_else(|denied| {
                    panic!("{max_ttl} / {code_expiry}: the accepted outcome: {denied}")
                });

            let decided = outcome.descriptor.expires_at.as_str();
            assert!(
                decided.len() == 20 && decided.as_bytes()[4] == b'-',
                "{max_ttl} / {code_expiry}: `{decided}` is not the declared date-time form"
            );
            assert!(
                decided <= "9999-12-31T23:59:59Z",
                "{max_ttl} / {code_expiry}: `{decided}` is past the form's last instant"
            );
            assert!(
                decided > "2026-09-19T00:00:00Z",
                "{max_ttl} / {code_expiry}: `{decided}` is not after the request instant"
            );
            assert!(
                decided <= code_expiry,
                "{max_ttl} / {code_expiry}: `{decided}` outlives the code"
            );
        }
    }
}

/// **`IssueAuthorizationCode` refuses a redirect the client's registration does not carry.**
///
/// `credential.yaml`'s denial for this command names "exact redirect URI". Pass 1 of this
/// adversary found the handler recorded whatever redirect the caller named; wave C correction
/// round 1 (ruling 2) gave `OAuthClientReads` the registered redirect set, byte-exact, and the
/// handler refuses an unregistered one with the declared phrase and mints nothing. The
/// adapter (`crates/mandate-federation/src/publicclient.rs:100`) checks the same thing first;
/// the STS is the second line. This case pins the ruled behaviour.
#[test]
fn an_issuance_binds_a_redirect_no_registration_was_consulted_for() {
    let attacker = RedirectUri::new("https://attacker.example/steal");
    let mut deployment = Deployment::new();
    let before = deployment.secrets.minted();
    let refused = CodeIssuance::new(CodeLifetime::new(Duration::new("PT5M")))
        .issue(
            &IssueAuthorizationCode {
                context: context(organization(10)),
                client_id: client(),
                session_id: session_id(),
                target: deployment.target,
                requested_scope: scope(),
                challenge: PkceChallenge::new(CHALLENGE),
                method: PkceMethod::S256,
                redirect_uri: attacker,
                expires_at: Timestamp::new("2026-09-19T00:05:00Z"),
            },
            &request(),
            &deployment.servers,
            &clients(),
            AuthorizationCodeParts {
                digest: &Sha256Digest,
                secrets: &mut deployment.secrets,
                allocator: &mut deployment.allocator,
            },
        )
        .expect_err("a redirect the registration does not carry is refused at issuance");
    assert_eq!(
        refused.clause,
        DenialClause::RedirectUnregistered,
        "the declared phrase: exact redirect URI"
    );
    assert_eq!(
        deployment.secrets.minted(),
        before,
        "a refused issuance mints no code secret"
    );
    assert!(
        deployment
            .codes
            .projection()
            .authorization_codes()
            .is_empty(),
        "nothing is recorded for a refused issuance"
    );
}

/// **The redeemed payload is one declaration read by two folds — with its optionals absent as
/// well as carried.**
///
/// `services/sts/tests/store.rs` decides that `AuthorizationCodeEvent` and the
/// `mandate_token::projection::CredentialEvent` it converts to encode identically, over a
/// payload carrying every optional. Both declarations skip an absent optional rather than
/// writing `null`, and nothing decides that for the bare form: a
/// `skip_serializing_if` dropped from one of the two would keep that case green.
///
/// Holds against the tree.
#[test]
fn the_redeemed_payload_encodes_identically_with_its_optionals_absent() {
    let mut deployment = Deployment::new();
    let (code_id, proof) = deployment.issue();
    let outcome = deployment
        .decide(
            &redemption(code_id, &proof),
            &request(),
            &RecordedSessions::new().session(SessionBinding {
                epochs: None,
                ..session()
            }),
        )
        .expect("a live session that names no snapshot");

    let code_half = serde_json::to_value(&outcome.event).expect("the code payload encodes");
    let credential_half = serde_json::to_value(
        outcome
            .event
            .credential_event()
            .expect("the redemption seeds a credential"),
    )
    .expect("the credential payload encodes");

    assert_eq!(
        code_half, credential_half,
        "one declared payload, read by two folds, with its optionals absent"
    );
    assert_eq!(
        code_half.get("epochs"),
        None,
        "an absent optional is absent and never null"
    );
    assert!(
        code_half.get("reference_verifier").is_some(),
        "the generated verifier is present"
    );
    assert!(
        !code_half.to_string().contains("REDACTED"),
        "no redaction marker reaches the payload: {code_half}"
    );
}

/// **A code the log records the consume of is not redeemable a second time, whichever path
/// asks.**
///
/// `pkce-reuse`'s sequential half through the deciding handler as well as the command path:
/// the deciding half must refuse a consumed code even when no append is attempted, because a
/// deployment that decided first and appended later would otherwise mint a second credential
/// identity before the compare-and-set refused it.
///
/// Holds against the tree.
#[test]
fn a_consumed_code_is_refused_by_the_deciding_half_as_well_as_the_command_path() {
    let mut deployment = Deployment::new();
    let (code_id, proof) = deployment.issue();
    let input = redemption(code_id, &proof);
    deployment
        .redeem(&input, &sessions(), &clients())
        .expect("the first redemption");
    let minted = deployment.secrets.minted();

    let refused = deployment
        .decide(&input, &request(), &sessions())
        .expect_err("`consume` starts from `Issued` alone");

    assert_eq!(refused.clause, DenialClause::CodeConsumed);
    assert_eq!(refused.outcome, RefusedOutcome::WrongState);
    assert_eq!(
        deployment.secrets.minted(),
        minted,
        "the deciding half mints nothing for a consumed code"
    );
    assert_eq!(deployment.credential_fold().credentials().len(), 1);
}

/// **Exactly one base64url character in four closes an S256 challenge, and `IssueAuthorization
/// Code` refuses the other three.**
///
/// `services/sts/src/code.rs`'s own statement: "a 43-character base64url string whose last
/// character carries either pad bit is the encoding of no value at all (three of every four
/// are), so it is the S256 challenge of no verifier that exists. Recording one would put a
/// code into the log that no redemption could ever satisfy." The arithmetic is 43 x 6 = 258
/// bits over a 256-bit digest, so the last character carries four value bits and two pad
/// bits: 16 of the 64 alphabet characters close a challenge and 48 do not. This walks all 64
/// through `challenge_is_well_formed` and through the real handler, and counts.
///
/// Holds against the tree.
#[test]
fn exactly_sixteen_of_the_sixty_four_last_characters_close_an_s256_challenge() {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut admitted = 0_u32;
    for last in ALPHABET {
        let mut text = CHALLENGE.to_owned();
        text.pop();
        text.push(char::from(*last));
        let challenge = PkceChallenge::new(text.clone());
        let well_formed = challenge_is_well_formed(&challenge);

        let mut deployment = Deployment::new();
        let issued = CodeIssuance::new(CodeLifetime::new(Duration::new("PT5M"))).issue(
            &IssueAuthorizationCode {
                context: context(organization(10)),
                client_id: client(),
                session_id: session_id(),
                target: deployment.target,
                requested_scope: scope(),
                challenge,
                method: PkceMethod::S256,
                redirect_uri: redirect(),
                expires_at: Timestamp::new("2026-09-19T00:05:00Z"),
            },
            &request(),
            &deployment.servers,
            &clients(),
            AuthorizationCodeParts {
                digest: &Sha256Digest,
                secrets: &mut deployment.secrets,
                allocator: &mut deployment.allocator,
            },
        );
        match (well_formed, issued) {
            (true, Ok(_)) => admitted += 1,
            (false, Err(denied)) => {
                assert_eq!(denied.clause, DenialClause::ChallengeMalformed, "`{text}`");
                assert_eq!(denied.reason, DenialReason::InvalidCredential, "`{text}`");
                assert_eq!(
                    deployment.secrets.minted(),
                    0,
                    "`{text}`: a refused issuance mints nothing"
                );
            }
            (true, Err(denied)) => {
                panic!("`{text}` is the declared form and was refused: {denied}")
            }
            (false, Ok(_)) => panic!("`{text}` is the challenge of no verifier and was recorded"),
        }
    }
    assert_eq!(
        admitted, 16,
        "one alphabet character in four closes a 43-character S256 challenge"
    );

    // And the forms that are not 43 characters of that alphabet at all.
    for text in [
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c",
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cMA",
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw+cM",
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw/cM",
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c=",
        "",
    ] {
        assert!(
            !challenge_is_well_formed(&PkceChallenge::new(text)),
            "`{text}` is not the declared S256 form"
        );
    }
}

/// **The compare-and-set key is never a fixed point.**
///
/// `services/sts/src/store.rs`: "A version is a compare-and-set key, so advancing one must
/// always produce a strictly greater value: the counter is wider than any version the public
/// constructor can name, so `StreamVersion::advance` of a constructible version is total and
/// strictly increasing." That is the whole of the one-winner guarantee: a key that saturated
/// at its own maximum would let a losing writer present the version the winner left and
/// commit a second consume. The existing cases only reach versions 0 and 1; this walks the
/// widest version the public constructor can name.
///
/// Holds against the tree.
#[test]
fn the_compare_and_set_key_is_strictly_increasing_at_the_widest_constructible_version() {
    for value in [0, 1, u64::from(u32::MAX), u64::MAX - 1, u64::MAX] {
        let version = StreamVersion::new(value);
        assert!(
            version.advance() > version,
            "advancing {value} must produce a strictly greater key"
        );
        assert_eq!(
            version.advance().get(),
            u128::from(value) + 1,
            "advancing {value} counts by one"
        );
    }
    assert_eq!(StreamVersion::INITIAL, StreamVersion::new(0));
    assert!(StreamVersion::new(1) > StreamVersion::INITIAL);
}

/// **A session that is both stale and expired is reported stale.**
///
/// `services/sts/src/binding.rs`: "The epoch is decided before the expiry because a stale
/// epoch is the condition the contract gives its own `DenialReason` to, and a session that is
/// both stale and expired is more usefully reported as stale." The two conditions are only
/// ever presented one at a time elsewhere, so the order the sentence names is decided by
/// nothing.
///
/// Holds against the tree.
#[test]
fn a_session_that_is_both_stale_and_expired_is_reported_stale() {
    let mut deployment = Deployment::new();
    let (code_id, proof) = deployment.issue();

    let refused = deployment
        .redeem(
            &redemption(code_id, &proof),
            &RecordedSessions::new()
                .session(SessionBinding {
                    expires_at: Timestamp::new("2026-09-18T23:59:59Z"),
                    ..session()
                })
                .stale(
                    snapshot(),
                    mandate_types::SecurityEpochTarget::Principal(subject()),
                ),
            &clients(),
        )
        .expect_err("a session that is both stale and expired");

    assert_eq!(
        refused,
        RedemptionRefused::Denied(Denied::new(
            DenialReason::StaleEpoch,
            DenialClause::SessionEpochStale
        )),
        "the epoch is decided before the expiry"
    );
}

/// **One piece of material, two indexes: a code and a credential minted from the same bytes
/// do not resolve to each other's record.**
///
/// `services/sts/src/code.rs`: "The verifier is derived in
/// `CredentialDomain::AuthorizationCodeVerifier`, its own digest space, so a code presented
/// where a credential proof is expected resolves to nothing." The fixture that makes that
/// non-trivial is the one the unit's suite never builds: two `CountingSecrets` mint
/// `secret-1` each, so the code a client holds and the credential a redemption returns are
/// *literally the same bytes*, and only the domain tag separates the two records.
///
/// Both directions are driven through the real handlers: the code's recorded verifier is not
/// the credential's, nothing in the credential log resolves the code's verifier, and the code
/// material presented to `IntrospectCredential` answers the inactive answer rather than the
/// credential the same bytes minted.
///
/// Holds against the tree.
#[test]
fn a_code_and_a_credential_minted_from_the_same_material_resolve_to_different_records() {
    let mut allocator = SequentialAllocator::new();
    let registration = register_resource_server(
        &RegisterResourceServer {
            context: context(organization(10)),
            audience: Audience::new("api-a"),
            profile: reference_profile(),
            allowed_exchange_sources: Vec::new(),
        },
        &Projection::default(),
        &mut allocator,
    )
    .expect("a free audience");
    let target = registration.resource_server_id;
    let servers =
        Projection::fold(std::slice::from_ref(&registration.event)).expect("one creation");
    let mut credentials = vec![registration.event];

    // The code, minted from a source that has minted nothing.
    let mut code_secrets = CountingSecrets::new();
    let issued = CodeIssuance::new(CodeLifetime::new(Duration::new("PT5M")))
        .issue(
            &IssueAuthorizationCode {
                context: context(organization(10)),
                client_id: client(),
                session_id: session_id(),
                target,
                requested_scope: scope(),
                challenge: PkceChallenge::new(CHALLENGE),
                method: PkceMethod::S256,
                redirect_uri: redirect(),
                expires_at: Timestamp::new("2026-09-19T00:05:00Z"),
            },
            &request(),
            &servers,
            &clients(),
            AuthorizationCodeParts {
                digest: &Sha256Digest,
                secrets: &mut code_secrets,
                allocator: &mut allocator,
            },
        )
        .expect("a registered enabled target and client");
    let code_material = issued.code.expose_material().to_vec();
    let mut codes = InMemoryCodeLog::new();
    codes
        .append(
            &issued.code_id,
            StreamVersion::INITIAL,
            std::slice::from_ref(&issued.event),
        )
        .expect("an untouched stream");

    // The credential, minted from another source that has also minted nothing: the same
    // bytes.
    let mut credential_secrets = CountingSecrets::new();
    let sessions = sessions();
    let recorded_clients = clients();
    let outcome = redeem_authorization_code(
        &redemption(
            issued.code_id,
            &CredentialProof::from_bytes(code_material.clone()),
        ),
        &request(),
        codes.projection(),
        BoundReads {
            servers: &servers,
            clients: &recorded_clients,
            sessions: &sessions,
        },
        RedemptionParts {
            digest: &Sha256Digest,
            secrets: &mut credential_secrets,
            allocator: &mut allocator,
        },
    )
    .expect("the matching verifier, client and redirect");
    assert_eq!(
        outcome.credential.expose_material(),
        code_material.as_slice(),
        "the fixture mints one piece of material into two indexes"
    );
    credentials.push(
        outcome
            .event
            .credential_event()
            .expect("the redemption seeds a credential"),
    );
    let held = Projection::fold(&credentials).expect("a log of accepted events");

    let code_verifier = codes
        .projection()
        .authorization_code(&issued.code_id)
        .expect("the code record")
        .verifier;
    let credential_verifier = held
        .access_credential(&outcome.credential_id)
        .expect("the credential record")
        .reference_verifier
        .expect("the reference family records its verifier");
    assert_ne!(
        code_verifier, credential_verifier,
        "one material, two domains, two verifiers"
    );
    assert_eq!(
        code_verifier,
        verifier_in(
            &Sha256Digest,
            CredentialDomain::AuthorizationCodeVerifier,
            &CredentialProof::from_bytes(code_material.clone()),
        )
    );
    assert!(
        held.credentials()
            .iter()
            .all(|record| record.reference_verifier.as_ref() != Some(&code_verifier)),
        "nothing in the credential log resolves the code's verifier"
    );

    // And through `IntrospectCredential`: a caller of this registration presenting the code's
    // verifier gets the inactive answer, not the credential the same bytes minted.
    let caller = issue_reference_credential(
        &IssueReferenceCredential {
            context: context(organization(10)),
            target,
            requested_scope: scope(),
        },
        &request(),
        &servers,
        ReferenceParts {
            digest: &Sha256Digest,
            secrets: &mut credential_secrets,
            allocator: &mut allocator,
        },
    )
    .expect("a registered enabled target of the caller's organization");
    let caller_proof = CredentialProof::from_bytes(caller.credential.expose_material().to_vec());
    credentials.push(caller.event);
    let held = Projection::fold(&credentials).expect("a log of accepted events");

    let answer = introspect_credential(
        &IntrospectCredential {
            caller_proof,
            // The code's own material, in the domain a credential proof is resolved in.
            credential_proof: CredentialProof::from_bytes(code_material),
        },
        &request(),
        &held,
        IntrospectionParts {
            digest: &Sha256Digest,
            resolution: &held,
        },
    )
    .expect("an authorized introspection");
    assert!(
        answer.active,
        "the fixture's code and credential are the same bytes, so this resolves the \
         credential record and not the code's"
    );
    assert_eq!(answer.credential_id, Some(outcome.credential_id));
}
