//! Adversary pass 2 — `story:obligations-sts`, after correction 1.
//!
//! The unit's new `services/sts/tests/obligations.rs` states a standard for a refusal and
//! publishes it as the `no_state_change` evidence of
//! `mandate.credential.RedeemAuthorizationCode`: *"a refusal mints no credential material"*
//! and *"a refusal mints no credential identity: the allocator is where it was"*, decided
//! **through `redeem_and_consume`, which is the one function in this crate that writes**.
//!
//! These cases take that standard at its word and apply it to the refusals the unit's case
//! does not reach.
//!
//! - [`a_redemption_that_loses_its_compare_and_set_mints_no_credential_material`] —
//!   `redeem_and_consume` returns two refusals, not one
//!   (`services/sts/src/redemption.rs:164-169`). The unit's case decides
//!   `RedemptionRefused::Denied`. The other, `RedemptionRefused::Append`, is the losing half
//!   of two concurrent redemptions, and it refuses **after** the decision has drawn a secret
//!   from the deployment's source and an identity from its allocator
//!   (`services/sts/src/redemption.rs:354-357`, then `:436-440`). The contract states of this
//!   command that *"a failed or replayed transaction produces no credential"*
//!   (`systems/mandate/domains/credential.yaml:245`), and the crate states what that means
//!   for a source that counts what it handed out (`services/sts/src/issue.rs:363-365`).
//! - [`a_self_contained_issuance_refused_by_the_signer_mints_no_credential_identity`] —
//!   `issue_self_contained_credential` is the one handler in this crate that draws an
//!   identity **before** a refusal it can still make: `next_credential_id` at
//!   `services/sts/src/issue.rs:424`, `SigningRefused` at `:436`. Every other handler in the
//!   crate draws last, under the comment "Nothing above this line mints anything: a refusal
//!   leaves the deployment exactly as it was" — which `issue_self_contained_credential`
//!   alone does not carry. The command's `no_state_change` row names
//!   `emitted_events::a_refused_self_contained_issuance_emits_nothing_and_leaves_the_fold_unchanged`,
//!   which refuses on the profile bound, *above* the draw, and inspects no allocator.
//! - [`a_zero_span_profile_bound_refuses_the_redemption_rather_than_dating_it_now`] — the
//!   third condition of the clause the unit bound. `services/sts/src/redemption.rs:346`
//!   filters the profile span to `> 0`; `instant::span_of` never answers negative, so that
//!   filter decides exactly one input — a span of zero — and no case in this crate's suite
//!   builds one against a redemption. This case builds it. It is **green as the tree
//!   stands** and is here as the case that would catch the mutant.

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
    redeem_authorization_code,
};
use mandate_sts::registry::{RegisterResourceServer, register_resource_server};
use mandate_sts::store::{
    AppendRefused, AuthorizationCodeEvent, CodeProjection, InMemoryCodeLog, StreamVersion,
};
use mandate_sts::{CountingSecrets, IdentityAllocator, RequestContext, SequentialAllocator};
use mandate_token::projection::{CredentialEvent, DenialClause, Denied, Projection};
use mandate_token::signing_real::{SignedCredential, SigningError, StandardClaims};
use mandate_token::{CredentialDescriptor, CredentialProfile};
use mandate_types::{
    Audience, AuthorityScope, AuthorizationCodeId, CorrelationId, CredentialId, CredentialKind,
    CredentialProof, DenialReason, Duration, EpochSnapshotRef, Issuer, OAuthClientId,
    OrganizationId, PkceChallenge, PkceMethod, PrincipalId, RedirectUri, ResourceServerId,
    RevocationGuarantee, SessionId, Timestamp, Transient, Uuid, VerifiedContext,
};

/// RFC 7636 appendix B: the example code verifier and the S256 challenge it redeems.
const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// The redirect the client registers and the code is bound to.
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
        correlation: CorrelationId::new("adversary-2"),
    }
}

fn request() -> RequestContext {
    RequestContext {
        correlation: CorrelationId::new("adversary-2"),
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

/// The ordinary reference profile this deployment registers, which `admits_profile` admits.
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

/// A self-contained profile whose `max_ttl` covers [`RefusingSigner`]'s own lifetime, so the
/// expiry bound is decided and the signing refusal is what the handler reaches.
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

/// One registered target, through the real registration handler.
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

/// One code, minted through the real issuance handler, with the proof of holding it.
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

/// **The losing half of two concurrent redemptions draws a credential secret and a
/// credential identity, and then refuses.**
///
/// `redeem_and_consume` reads the stream's version, decides against the projection at that
/// version — which mints the reference secret and the credential identity
/// (`services/sts/src/redemption.rs:354-357`) — and only then appends under a compare-and-set.
/// A stream another writer moved first refuses the append, and the draw has already happened.
///
/// The race is the one this crate names: "its concurrent half is the compare-and-set in
/// [`redeem_and_consume`]" (`services/sts/src/redemption.rs`), and
/// `InMemoryCodeLog::lose_the_next_append` exists as "the injection a race case needs: it is
/// the losing half of two concurrent writers" (`services/sts/src/store.rs`). Nothing here is
/// constructed beyond that injection: the registration, the code and the redemption are the
/// shipped handlers'.
///
/// What it is measured against is the standard the unit publishes for this very command:
/// `mandate-sts::obligations::a_redemption_refused_on_the_narrowing_clause_moves_neither_log_nor_fold`
/// is a `no_state_change` row of `mandate.credential.RedeemAuthorizationCode` in
/// `contracts/obligations/sts.json`, and it asserts `secrets.minted() == 0` and an unmoved
/// allocator "through `redeem_and_consume`, which is the one function in this crate that
/// writes". That function has two refusals; the row's case decides one of them.
///
/// Pinned by the coordinator to the shipped behaviour on 2026-09-21 (`review-result:wave-d-obligations-sts-adversary-2` F1): the
/// losing half had already drawn a secret and an identity when the append refused.
/// `story:sts-refusal-draws-nothing` flipped it: the compare-and-set is decided before the
/// draw, and the losing half draws nothing. The name is the one the story's acceptance
/// cites, kept so the citation resolves; it records the finding, not the behaviour.
#[test]
fn a_redemption_that_loses_its_compare_and_set_has_already_drawn_credential_material() {
    let (servers, target) = registered(reference_profile());
    let (issued, code_id, proof) = issued_code(&servers, target);
    let mut log = InMemoryCodeLog::new();
    log.append(
        &code_id,
        StreamVersion::INITIAL,
        std::slice::from_ref(&issued),
    )
    .expect("an empty stream takes its creation");

    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();
    // The second writer commits first, between this transaction's read and its append.
    log.lose_the_next_append();

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
    .expect_err("the compare-and-set the other writer already moved");

    assert!(
        matches!(
            refused,
            RedemptionRefused::Append(AppendRefused::Conflict { .. })
        ),
        "the refusal under test is the lost compare-and-set, and it is {refused:?}"
    );

    let mut moved: Vec<String> = Vec::new();
    if secrets.minted() != 0 {
        moved.push(format!(
            "the deployment's secret source handed out {} credential secret(s) to a \
             transaction that refused; `systems/mandate/domains/credential.yaml:245` states \
             that \"a failed or replayed transaction produces no credential\", and \
             `services/sts/src/issue.rs:363-365` states what that means \"for a source that \
             counts what it handed out\"",
            secrets.minted()
        ));
    }
    let untouched = SequentialAllocator::new().next_credential_id();
    let next = allocator.next_credential_id();
    if next != untouched {
        moved.push(format!(
            "the identity allocator moved: the next credential identity is {next:?} and an \
             allocator this transaction never reached answers {untouched:?}"
        ));
    }
    assert!(
        moved.is_empty(),
        "the losing half of the compare-and-set drew from the deployment: {moved:?}"
    );
    assert_eq!(
        log.events(&code_id),
        vec![issued],
        "the losing half appended nothing"
    );
}

/// An [`IssuanceSigner`] with nothing to sign under.
///
/// `SigningError::NoActiveKey` is the crate's own name for "every key has been revoked;
/// there is nothing to sign under" (`crates/mandate-token/src/signing_real.rs:226-227`) — a
/// deployment state `RevokeSigningKey` reaches, not an invented one. `ttl_seconds` is the
/// profile's own 900, so the expiry bound is decided and the signing refusal is what the
/// handler reaches.
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

/// **A self-contained issuance the signer refuses has already drawn a credential identity.**
///
/// `services/sts/src/issue.rs:424` draws the identity; `:425-436` signs, and maps a refusing
/// signer to `DenialClause::SigningRefused`. Every other handler in this crate draws last:
/// `issue_reference_credential` (`:366-369`), `redeem_authorization_code` (`:354-357`),
/// `CodeIssuance::issue` (`code.rs:663-669`) and `register_signing_key` (`keys.rs:234`) each
/// carry or follow the comment "Nothing above this line mints anything: a refusal leaves the
/// deployment exactly as it was". `issue_self_contained_credential` is the one that does not.
///
/// `contracts/obligations/sts.json` publishes this command's `no_state_change` obligation as
/// decided on the real path by
/// `mandate-sts::emitted_events::a_refused_self_contained_issuance_emits_nothing_and_leaves_the_fold_unchanged`,
/// which refuses on the profile bound — above the draw — and inspects no allocator, so the
/// column carries no statement about this path.
///
/// Pinned by the coordinator to the shipped behaviour on 2026-09-21 (`review-result:wave-d-obligations-sts-adversary-2` F2): the
/// identity was drawn before the signer refused. `story:sts-refusal-draws-nothing` flipped
/// it: the identity is reserved for the signature and handed out only when the signer
/// signs. The name is the one the story's acceptance cites, kept so the citation resolves.
#[test]
fn a_self_contained_issuance_refused_by_the_signer_has_already_drawn_a_credential_identity() {
    let (servers, target) = registered(self_contained_profile());
    let mut allocator = SequentialAllocator::new();

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
        Denied::new(DenialReason::Denied, DenialClause::SigningRefused),
        "the refusal under test is the signer's, and it is {denied:?}"
    );

    let untouched = SequentialAllocator::new().next_credential_id();
    let next = allocator.next_credential_id();
    assert_eq!(
        next, untouched,
        "the issuance the signer refused drew a credential identity from the allocator"
    );
}

/// **A profile whose `max_ttl` names a span of zero refuses the redemption rather than
/// dating the credential at the instant it was issued.**
///
/// Green as the tree stands, and here as the case that would catch the mutant: dropping
/// `.filter(|span| *span > 0)` from `services/sts/src/redemption.rs:346` leaves every other
/// case in this crate's suite passing, because `instant::span_of` never answers a negative
/// span and no other case in `services/sts/tests/` builds a zero one against a redemption —
/// the spans reaching a redemption are `PT1H`, `PT15M`, `whenever` (which names no span at
/// all) and `PT9223372036854775807S` (which overflows the addition). Without the filter a
/// zero span dates the credential at `issued_at`, so the handler issues a credential that
/// expired at the instant it was minted rather than refusing.
///
/// The registration is constructed, as
/// `declared_denials::unbounded_profile_target` is and for the same stated reason:
/// `register_resource_server` refuses a zero `max_ttl` (`registry.rs:146`), so the record is
/// one another writer put in the log, which is what the redemption's re-read of the
/// registration exists for.
#[test]
fn a_zero_span_profile_bound_refuses_the_redemption_rather_than_dating_it_now() {
    let (servers, target) = registered(reference_profile());
    let (issued, code_id, proof) = issued_code(&servers, target);
    let zero_span = Projection::fold(&[CredentialEvent::ResourceServerRegistered {
        context: context(organization(10)),
        id: target,
        audience: Audience::new("api-a"),
        credential_profile: CredentialProfile {
            max_ttl: Duration::new("PT0S"),
            ..reference_profile()
        },
        allowed_exchange_sources: Vec::new(),
    }])
    .expect("one creation");
    let codes = CodeProjection::fold(std::slice::from_ref(&issued)).expect("one creation");
    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();

    let denied = redeem_authorization_code(
        &redemption(code_id, &proof),
        &request(),
        &codes,
        BoundReads {
            servers: &zero_span,
            clients: &clients(),
            sessions: &sessions(),
        },
        RedemptionParts {
            digest: &Sha256Digest,
            secrets: &mut secrets,
            allocator: &mut allocator,
        },
    )
    .expect_err("a profile bound of zero names no instant the narrowing can date to");

    assert_eq!(
        denied,
        Denied::new(DenialReason::Denied, DenialClause::ExpiryUnbounded),
        "a zero profile span is the narrowing failing, not a credential dated at its own \
         issuance"
    );
    assert_eq!(
        secrets.minted(),
        0,
        "a refusal mints no credential material"
    );
}
