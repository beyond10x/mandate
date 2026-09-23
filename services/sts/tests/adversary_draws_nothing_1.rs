//! Adversary pass 1 — `story:sts-refusal-draws-nothing`.
//!
//! The unit splits a redemption into a refusing `decide` and a drawing `mint`, runs the
//! draw inside `AuthorizationCodeLog::append_built` once the compare-and-set is won, and
//! gives the self-contained issuance a `reserve_credential_id` / `commit_credential_id`
//! pair on `IdentityAllocator`. These cases take the documents the unit wrote about those
//! seams at their word.
//!
//! - [`a_reservation_a_draw_overtook_is_not_signed_into_a_second_credential`] — the
//!   reservation "held for a transaction that can still refuse — and not handed out"
//!   (`services/sts/src/lib.rs:197-198`). `SequentialAllocator` holds nothing: a draw after
//!   the reservation hands out the reserved identity, and the commit that follows is a silent
//!   no-op (`lib.rs:276-280`), so the signed token and the drawn credential share one
//!   identity.
//! - [`a_counting_allocator_that_only_implements_the_required_methods_draws_on_a_signer_refusal`]
//!   — the trait default reserves by drawing (`lib.rs:210-212`). An allocator that counts and
//!   implements the four required methods, the shape `tests/adversary_profiles_2.rs`'s
//!   `ChosenServers` already has, compiles and draws on the refusal the story is about.
//! - [`a_log_that_refuses_after_the_build_has_drawn_pending_epoch_atomicity`] — the trait
//!   contract of `append_built` names `AppendRefused::Unreadable` as a refusal decided
//!   *after* `build` runs (`services/sts/src/store.rs:545-548`); `redeem_and_consume` then
//!   returns a refusal having drawn. Ruled outside the story's guarantee by the coordinator
//!   (correction round 1, F3): it needs the kit's transaction, which is
//!   `decision-blocker:epoch-atomicity`'s. Pins today's behaviour.
//! - [`a_redemption_behind_a_genuinely_stale_version_draws_nothing`] — the lost
//!   compare-and-set without the injection: a version that is really stale. Green.

use mandate_sts::binding::{RecordedSessions, SessionBinding};
use mandate_sts::code::{
    AuthorizationCodeParts, CodeIssuance, CodeLifetime, IssueAuthorizationCode, RecordedClients,
};
use mandate_sts::issue::{
    IssuanceSigner, IssueSelfContainedCredential, SelfContainedParts, Sha256Digest,
    issue_self_contained_credential,
};
use mandate_sts::redemption::{
    BoundReads, RedeemAuthorizationCode, RedemptionParts, RedemptionRefused, redeem_and_consume,
};
use mandate_sts::registry::{RegisterResourceServer, register_resource_server};
use mandate_sts::store::{
    AppendRefused, AuthorizationCodeEvent, AuthorizationCodeLog, CodeFoldError, CodeProjection,
    InMemoryCodeLog, StreamVersion,
};
use mandate_sts::{CountingSecrets, IdentityAllocator, RequestContext, SequentialAllocator};
use mandate_token::projection::{DenialClause, Denied, Projection};
use mandate_token::signing_real::{SignedCredential, SigningError, StandardClaims};
use mandate_token::{CredentialDescriptor, CredentialProfile};
use mandate_types::{
    Audience, AuthorityScope, AuthorizationCodeId, CorrelationId, CredentialId, CredentialKind,
    CredentialProof, DenialReason, Duration, EpochSnapshotRef, Issuer, OAuthClientId,
    OrganizationId, PkceChallenge, PkceMethod, PrincipalId, RedirectUri, ResourceServerId,
    RevocationGuarantee, SessionId, SigningKeyId, Timestamp, Transient, Uuid, VerifiedContext,
};

const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const REDIRECT: &str = "https://client.example/callback";

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization(tag: u8) -> OrganizationId {
    OrganizationId::new(uuid(tag))
}

fn oauth_client() -> OAuthClientId {
    OAuthClientId::new(uuid(0x0c))
}

fn oauth_session() -> SessionId {
    SessionId::new(uuid(0x5e))
}

fn subject() -> PrincipalId {
    PrincipalId::new(uuid(0x51))
}

fn snapshot() -> EpochSnapshotRef {
    EpochSnapshotRef::new(uuid(0x60))
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
        correlation: CorrelationId::new("adversary-draws-1"),
    }
}

fn request() -> RequestContext {
    RequestContext {
        correlation: CorrelationId::new("adversary-draws-1"),
        at: Timestamp::new("2026-09-19T00:00:00Z"),
        epochs: Some(snapshot()),
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
        revocation: RevocationGuarantee::BoundedOffline,
        max_ttl: Duration::new("PT1H"),
        positive_cache_ttl: Duration::new("PT0S"),
        requires_online_authorization: false,
    }
}

fn self_contained_profile() -> CredentialProfile {
    CredentialProfile {
        name: "self-contained".to_owned(),
        kind: CredentialKind::SelfContained,
        revocation: RevocationGuarantee::BoundedOffline,
        max_ttl: Duration::new("PT15M"),
        positive_cache_ttl: Duration::new("PT0S"),
        requires_online_authorization: false,
    }
}

fn registered(profile: CredentialProfile) -> (Projection, ResourceServerId) {
    let mut allocator = SequentialAllocator::new();
    let outcome = register_resource_server(
        &RegisterResourceServer {
            context: context(organization(10)),
            audience: Audience::new("api-a"),
            profile,
            allowed_exchange_sources: Vec::new(),
        },
        &Projection::default(),
        &mut allocator,
    )
    .expect("a free audience in the caller's own organization");
    let id = outcome.resource_server_id;
    (
        Projection::fold(&[outcome.event]).expect("one creation"),
        id,
    )
}

fn clients() -> RecordedClients {
    RecordedClients::new()
        .enabled(oauth_client(), organization(10))
        .redirect(oauth_client(), RedirectUri::new(REDIRECT))
}

fn sessions() -> RecordedSessions {
    RecordedSessions::new()
        .session(SessionBinding {
            id: oauth_session(),
            subject: subject(),
            organization: organization(10),
            epochs: Some(snapshot()),
            expires_at: Timestamp::new("2026-09-19T12:00:00Z"),
            revoked: false,
        })
        .current(snapshot())
}

fn issued_code(
    servers: &Projection,
    target: ResourceServerId,
) -> (AuthorizationCodeEvent, AuthorizationCodeId, CredentialProof) {
    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();
    let outcome = CodeIssuance::new(CodeLifetime::new(Duration::new("PT5M")))
        .issue(
            &IssueAuthorizationCode {
                context: context(organization(10)),
                client_id: oauth_client(),
                session_id: oauth_session(),
                target,
                requested_scope: scope(),
                challenge: PkceChallenge::new(PKCE_CHALLENGE),
                method: PkceMethod::S256,
                redirect_uri: RedirectUri::new(REDIRECT),
                expires_at: Timestamp::new("2026-09-19T00:05:00Z"),
            },
            &request(),
            servers,
            &clients(),
            AuthorizationCodeParts {
                digest: &Sha256Digest,
                secrets: &mut secrets,
                allocator: &mut allocator,
            },
        )
        .expect("a registered enabled target and a registered public client");
    let proof = CredentialProof::from_bytes(outcome.code.expose_material().to_vec());
    (outcome.event, outcome.code_id, proof)
}

fn redemption(code_id: AuthorizationCodeId, proof: &CredentialProof) -> RedeemAuthorizationCode {
    RedeemAuthorizationCode {
        code_id,
        client_id: oauth_client(),
        code: CredentialProof::from_bytes(proof.expose_material().to_vec()),
        pkce_verifier: CredentialProof::from_bytes(PKCE_VERIFIER.as_bytes().to_vec()),
        redirect_uri: RedirectUri::new(REDIRECT),
    }
}

/// A log holding one freshly issued code.
fn log_with_code() -> (
    InMemoryCodeLog,
    Projection,
    AuthorizationCodeId,
    CredentialProof,
) {
    let (servers, target) = registered(reference_profile());
    let (issued, code_id, proof) = issued_code(&servers, target);
    let mut log = InMemoryCodeLog::new();
    log.append(
        &code_id,
        StreamVersion::INITIAL,
        std::slice::from_ref(&issued),
    )
    .expect("an empty stream takes its creation");
    (log, servers, code_id, proof)
}

struct NoKeySigner;

impl IssuanceSigner for NoKeySigner {
    fn sign_credential(
        &self,
        _: &CredentialDescriptor,
        _: &StandardClaims,
    ) -> Result<SignedCredential, SigningError> {
        Err(SigningError::NoActiveKey)
    }

    fn ttl_seconds(&self) -> u64 {
        900
    }
}

/// **A reservation is held: a draw after it does not hand the reserved identity out
/// again.**
///
/// `reserve_credential_id` is documented as "the credential identity the next draw would
/// hand out, held for a transaction that can still refuse — and not handed out"
/// (`services/sts/src/lib.rs:197-198`), and `commit_credential_id` as handing out "the
/// identity `reserve_credential_id` held". `SequentialAllocator` peeks rather than holds:
/// a draw between the two returns the reserved identity, and the commit then finds a
/// mismatch and does nothing, silently (`lib.rs:276-280`). The token the reservation was
/// signed into and the credential the draw minted carry one identity.
///
/// Built: the only caller, `issue_self_contained_credential`, holds `&mut` across the pair,
/// so nothing in-process draws between them.
#[test]
fn a_reservation_a_draw_overtook_is_not_signed_into_a_second_credential() {
    let mut allocator = SequentialAllocator::new();
    let reserved = allocator.reserve_credential_id();
    let drawn = allocator.next_credential_id();
    allocator.commit_credential_id(reserved);

    assert_ne!(
        reserved, drawn,
        "a draw after the reservation handed out the identity the reservation held; the \
         commit that followed changed nothing and said nothing"
    );
}

/// A counting allocator that implements the trait's four required methods and nothing else
/// — the shape `services/sts/tests/adversary_profiles_2.rs`'s `ChosenServers` has today.
struct DelegatingCounter {
    inner: SequentialAllocator,
}

impl IdentityAllocator for DelegatingCounter {
    fn next_resource_server_id(&mut self) -> ResourceServerId {
        self.inner.next_resource_server_id()
    }

    fn next_credential_id(&mut self) -> CredentialId {
        self.inner.next_credential_id()
    }

    fn next_signing_key_id(&mut self) -> SigningKeyId {
        self.inner.next_signing_key_id()
    }

    fn next_authorization_code_id(&mut self) -> AuthorizationCodeId {
        self.inner.next_authorization_code_id()
    }

    fn reserve_credential_id(&mut self) -> CredentialId {
        self.inner.reserve_credential_id()
    }

    fn commit_credential_id(&mut self, reserved: CredentialId) {
        self.inner.commit_credential_id(reserved);
    }

    fn release_credential_id(&mut self, reserved: CredentialId) {
        self.inner.release_credential_id(reserved);
    }
}

/// **A self-contained issuance the signer refuses draws nothing, whatever allocator it is
/// handed.**
///
/// The story's Outcome: "a signer-refused issuance leave[s] both untouched". The trait's
/// default `reserve_credential_id` draws (`services/sts/src/lib.rs:210-212`), so an
/// allocator that counts and does not override the pair — a wrapper that delegates to the
/// crate's own fixture — draws on exactly this refusal, and nothing makes it override.
///
/// Built: no allocator that counts and lacks the override reaches this handler today
/// (`SequentialAllocator` overrides; `SystemAllocator` draws from a CSPRNG).
#[test]
fn a_counting_allocator_that_only_implements_the_required_methods_draws_on_a_signer_refusal() {
    let (servers, target) = registered(self_contained_profile());
    let mut allocator = DelegatingCounter {
        inner: SequentialAllocator::new(),
    };

    let denied = issue_self_contained_credential(
        &IssueSelfContainedCredential {
            context: context(organization(10)),
            target,
            requested_scope: scope(),
        },
        &request(),
        &servers,
        SelfContainedParts {
            digest: &Sha256Digest,
            allocator: &mut allocator,
            signer: &NoKeySigner,
            issuer: &Issuer::new("https://sts.example"),
        },
    )
    .expect_err("a deployment with no active signing key");
    assert_eq!(
        denied,
        Denied::new(DenialReason::Denied, DenialClause::SigningRefused)
    );

    assert_eq!(
        allocator.next_credential_id(),
        SequentialAllocator::new().next_credential_id(),
        "the issuance the signer refused drew a credential identity through the trait's \
         default reservation"
    );
}

/// A log that honours `append_built`'s documented contract to the letter: the compare is
/// decided before `build`, and `Unreadable` — "when the built event is not a history the
/// fold can read" — is decided after it, as it has to be.
struct RefusesAfterTheBuild {
    inner: InMemoryCodeLog,
}

impl AuthorizationCodeLog for RefusesAfterTheBuild {
    fn version(&self, stream: &AuthorizationCodeId) -> StreamVersion {
        self.inner.version(stream)
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
        self.inner.append(stream, expected, group)
    }

    fn append_built<T>(
        &mut self,
        stream: &AuthorizationCodeId,
        expected: StreamVersion,
        build: impl FnOnce() -> (AuthorizationCodeEvent, T),
    ) -> Result<T, AppendRefused> {
        let actual = self.inner.version(stream);
        if actual != expected {
            return Err(AppendRefused::Conflict { expected, actual });
        }
        let _built = build();
        Err(AppendRefused::Unreadable(
            CodeFoldError::UnknownAuthorizationCode { id: *stream },
        ))
    }
}

/// **A redemption the log refuses after the build has drawn a secret and an identity — the
/// residue `decision-blocker:epoch-atomicity` holds.**
///
/// The story's Outcome: "every refusal a handler can still make precedes any draw".
/// `redeem_and_consume` returns `RedemptionRefused::Append` for both `AppendRefused`
/// variants, and `append_built`'s own contract (`services/sts/src/store.rs:545-548`) places
/// `Unreadable` after `build` has run — so a log that obeys it returns a refusal from a
/// transaction that has drawn a secret and an identity.
///
/// Built: `InMemoryCodeLog`, the only implementor any caller uses (control-plane and
/// conformance both hold one), cannot fail the fold of a redemption `decide` accepted.
///
/// Pinned by the coordinator to the shipped behaviour (correction round 1, F3): a refusal
/// decided after the build is outside `story:sts-refusal-draws-nothing`'s guarantee, and
/// both `append_built` and `redeem_and_consume` say so. The assertion flips when the kit's
/// transaction spans the draw and the commit.
#[test]
fn a_log_that_refuses_after_the_build_has_drawn_pending_epoch_atomicity() {
    let (inner, servers, code_id, proof) = log_with_code();
    let mut log = RefusesAfterTheBuild { inner };
    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();

    let refused = redeem_and_consume(
        &redemption(code_id, &proof),
        &request(),
        &mut log,
        BoundReads {
            servers: &servers,
            clients: &clients(),
            sessions: &sessions(),
        },
        RedemptionParts {
            digest: &Sha256Digest,
            secrets: &mut secrets,
            allocator: &mut allocator,
        },
    )
    .expect_err("the log refuses the built event");
    assert!(
        matches!(
            refused,
            RedemptionRefused::Append(AppendRefused::Unreadable(_))
        ),
        "{refused:?}"
    );

    let mut fresh = SequentialAllocator::new();
    fresh.next_credential_id();
    assert_eq!(
        (secrets.minted(), allocator.next_credential_id()),
        (1, fresh.next_credential_id()),
        "a refusal the log decides after the build has drawn exactly one secret and one \
         identity; that residue is decision-blocker:epoch-atomicity's, and this pin is stale \
         once the kit's transaction spans the draw and the commit"
    );
}

/// A log whose version read is one event behind the stream: the compare-and-set loses for
/// real, not by injection.
struct StaleRead {
    inner: InMemoryCodeLog,
}

impl AuthorizationCodeLog for StaleRead {
    fn version(&self, _: &AuthorizationCodeId) -> StreamVersion {
        StreamVersion::INITIAL
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
        self.inner.append(stream, expected, group)
    }

    fn append_built<T>(
        &mut self,
        stream: &AuthorizationCodeId,
        expected: StreamVersion,
        build: impl FnOnce() -> (AuthorizationCodeEvent, T),
    ) -> Result<T, AppendRefused> {
        self.inner.append_built(stream, expected, build)
    }
}

/// **A genuinely lost compare-and-set draws nothing.** Green: the case that would catch a
/// double whose `append_built` built before comparing on the non-injected branch.
#[test]
fn a_redemption_behind_a_genuinely_stale_version_draws_nothing() {
    let (inner, servers, code_id, proof) = log_with_code();
    let mut log = StaleRead { inner };
    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();

    let refused = redeem_and_consume(
        &redemption(code_id, &proof),
        &request(),
        &mut log,
        BoundReads {
            servers: &servers,
            clients: &clients(),
            sessions: &sessions(),
        },
        RedemptionParts {
            digest: &Sha256Digest,
            secrets: &mut secrets,
            allocator: &mut allocator,
        },
    )
    .expect_err("the stream is one event ahead of the version read");
    assert!(
        matches!(
            refused,
            RedemptionRefused::Append(AppendRefused::Conflict { .. })
        ),
        "{refused:?}"
    );
    assert_eq!(secrets.minted(), 0, "the losing half drew a secret");
    assert_eq!(
        allocator.next_credential_id(),
        SequentialAllocator::new().next_credential_id(),
        "the losing half drew an identity"
    );
}
