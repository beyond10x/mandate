//! The five credential cases and the four `pkce` cases of `tests/security/cases.json`,
//! executed.
//!
//! Each case here is named for its id, reads that case out of the corpus, and drives the
//! commands the corpus says it names. The corpus file is a contract corpus and not runtime
//! evidence on its own — the entry is a sentence about what a deployment must do — so each
//! case asserts both halves: that the entry still says what this test was written against,
//! and that the handlers do it.
//!
//! **Two commands are named by entries here and driven by none of them**, and each case says
//! so rather than quietly executing part of an entry and reporting the entry as passed:
//!
//! - `mandate.authorization.Check`, named by all five credential entries, belongs to
//!   `story:check-api` and is realized by no crate in this workspace yet.
//! - `mandate.federation.AuthorizePublicClient`, named by all four `pkce` entries, is
//!   realized by `crates/mandate-federation` and is unreachable from here:
//!   `dependency-boundaries.json` admits no `mandate-federation` to `mandate-sts`, and the
//!   command is non-consuming — it validates and stops at the `IssueAuthorizationCode` input
//!   the STS decides (`crates/mandate-federation/src/authorize.rs`).
//!
//! **What is unrepresentable rather than refused.** `pkce-plain` and `pkce-missing` are
//! `story:protocol-adapters`' rows and could not be written here in any case:
//! `mandate.core.PkceMethod` declares exactly one variant, so RFC 7636's `plain` has no Rust
//! value to construct, and `RedeemAuthorizationCode.pkce_verifier` is non-optional, so an
//! omitted verifier is not an input this command accepts. Both refusals belong to the wire
//! adapter. `pkce-state-nonce` is `story:oauth-integration`'s: neither STS command takes a
//! state or a nonce.

use std::cell::Cell;

use mandate_sts::binding::{RecordedSessions, SessionBinding};
use mandate_sts::code::{
    AuthorizationCodeParts, CodeIssuance, CodeLifetime, IssueAuthorizationCode, RecordedClients,
};
use mandate_sts::issue::{
    IssueReferenceCredential, IssueSelfContainedCredential, ReferenceParts, SelfContainedParts,
    Sha256Digest, StaticSigner, issue_reference_credential, issue_self_contained_credential,
};
use mandate_sts::redemption::{
    BoundReads, RedeemAuthorizationCode, RedemptionParts, RedemptionRefused, redeem_and_consume,
    redeem_authorization_code,
};
use mandate_sts::registry::{RegisterResourceServer, register_resource_server};
use mandate_sts::resolve::{
    CredentialResolution, IntrospectCredential, IntrospectionParts, ResolutionUnavailable,
    RevokeAccessCredential, introspect_credential, revoke_access_credential,
};
use mandate_sts::store::{AppendRefused, AuthorizationCodeState, InMemoryCodeLog, StreamVersion};
use mandate_sts::{CountingSecrets, RequestContext, SequentialAllocator};
use mandate_token::CredentialProfile;
use mandate_token::projection::{
    AccessCredential, AccessCredentialState, CredentialEvent, DenialClause, Denied, Projection,
};
use mandate_token::verifier::{CredentialDomain, verifier_for, verifier_in};
use mandate_types::{
    Audience, AuthorityScope, AuthorizationCodeId, CorrelationId, CredentialId, CredentialKind,
    CredentialProof, CredentialVerifier, DenialReason, Duration, EpochSnapshotRef, Issuer,
    OAuthClientId, OrganizationId, PkceChallenge, PkceMethod, PrincipalId, RedirectUri,
    ResourceServerId, RevocationGuarantee, SessionId, Timestamp, Transient, Uuid, VerifiedContext,
};
use serde_json::Value;

const CORPUS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/security/cases.json"
);

const ISSUE_REFERENCE: &str = "mandate.credential.IssueReferenceCredential";
const ISSUE_SELF_CONTAINED: &str = "mandate.credential.IssueSelfContainedCredential";
const INTROSPECT: &str = "mandate.credential.IntrospectCredential";
const ISSUE_CODE: &str = "mandate.credential.IssueAuthorizationCode";
const REDEEM_CODE: &str = "mandate.credential.RedeemAuthorizationCode";
/// `story:check-api`'s port. Named by every credential case here and driven by none of them.
const CHECK: &str = "mandate.authorization.Check";
/// `crates/mandate-federation`'s command. Named by every `pkce` case here and driven by none
/// of them; see the module documentation.
const AUTHORIZE: &str = "mandate.federation.AuthorizePublicClient";

/// One corpus entry, read out of the file by id.
fn case(id: &str) -> Value {
    let text = std::fs::read_to_string(CORPUS).expect("the corpus is readable");
    let document: Value = serde_json::from_str(&text).expect("the corpus is JSON");
    document["cases"]
        .as_array()
        .expect("the corpus declares a case list")
        .iter()
        .find(|case| case["id"] == id)
        .unwrap_or_else(|| panic!("{id} is declared by no case in tests/security/cases.json"))
        .clone()
}

/// The entry still says what the case below was written against: this story owns it, and it
/// names exactly these commands.
fn names(id: &str, commands: &[&str]) -> Value {
    let case = case(id);
    assert_eq!(
        case["story"], "story:credential-profiles",
        "{id} is another story's case"
    );
    let declared: Vec<&str> = case["commands"]
        .as_array()
        .expect("a case names its commands")
        .iter()
        .map(|command| command.as_str().expect("a command name is a string"))
        .collect();
    assert_eq!(declared, commands, "{id} names other commands");
    assert!(
        declared.contains(&CHECK),
        "{id} is expected to name the authorization check this story does not realize"
    );
    case
}

/// The same, for a `pkce` entry: this story owns it, it names exactly these commands, and
/// the control-plane command it names is not one this crate can drive.
fn pkce_names(id: &str) -> Value {
    let case = case(id);
    assert_eq!(
        case["story"], "story:oauth-transaction",
        "{id} is another story's case"
    );
    let declared: Vec<&str> = case["commands"]
        .as_array()
        .expect("a case names its commands")
        .iter()
        .map(|command| command.as_str().expect("a command name is a string"))
        .collect();
    assert_eq!(
        declared,
        [AUTHORIZE, ISSUE_CODE, REDEEM_CODE],
        "{id} names other commands"
    );
    assert!(
        declared.contains(&AUTHORIZE),
        "{id} is expected to name the control-plane command this crate cannot reach"
    );
    case
}

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(10))
}

fn context(principal: PrincipalId) -> VerifiedContext {
    VerifiedContext {
        subject: principal,
        actor: None,
        organization: organization(),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("corpus"),
    }
}

fn request_at(at: &str) -> RequestContext {
    RequestContext {
        correlation: CorrelationId::new("corpus"),
        at: Timestamp::new(at),
        epochs: None,
    }
}

fn request() -> RequestContext {
    request_at("2026-09-19T00:00:00Z")
}

fn scope() -> AuthorityScope {
    AuthorityScope {
        actions: Vec::new(),
        resources: Vec::new(),
        space: None,
    }
}

/// The `ImmediateOnline` reference profile of `crates/mandate-token/src/lib.rs`'s own sample.
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

/// The `BoundedOffline` self-contained profile, whose bound `profile-offline-bound` is about.
///
/// `positive_cache_ttl` is a real window and not `PT0S`. A profile that publishes no window
/// admits no cached positive answer at all — which is a bound, and is pinned by
/// `services/sts/tests/adversary_profiles_1.rs` — so a fixture carrying `PT0S` could not
/// show that the *bound* is what decides rather than the guarantee alone. This one can: the
/// same cached answer is admitted inside the window and refused outside it.
fn self_contained_profile() -> CredentialProfile {
    CredentialProfile {
        name: "self-contained".to_owned(),
        kind: CredentialKind::SelfContained,
        revocation: RevocationGuarantee::BoundedOffline,
        max_ttl: Duration::new("PT15M"),
        positive_cache_ttl: Duration::new("PT30S"),
        requires_online_authorization: false,
    }
}

/// A resolver that answers from the fold and holds positive answers it took earlier, each
/// with the instant it was taken at, counting every time the cache is asked.
struct CachingResolver {
    fold: Projection,
    cached: Vec<(CredentialVerifier, AccessCredential, Timestamp)>,
    consulted: Cell<usize>,
}

impl CachingResolver {
    fn over(fold: Projection) -> Self {
        Self {
            fold,
            cached: Vec::new(),
            consulted: Cell::new(0),
        }
    }

    /// Prime the cache with a positive answer taken at an instant.
    fn holding(
        mut self,
        verifier: CredentialVerifier,
        record: AccessCredential,
        taken: &str,
    ) -> Self {
        self.cached.push((verifier, record, Timestamp::new(taken)));
        self
    }

    fn consulted(&self) -> usize {
        self.consulted.get()
    }
}

impl CredentialResolution for CachingResolver {
    fn resolve(
        &self,
        verifier: &CredentialVerifier,
    ) -> Result<Option<AccessCredential>, ResolutionUnavailable> {
        self.fold.resolve(verifier)
    }

    fn cached(&self, verifier: &CredentialVerifier) -> Option<AccessCredential> {
        self.consulted.set(self.consulted.get() + 1);
        self.cached
            .iter()
            .find(|(held, _, _)| held == verifier)
            .map(|(_, record, _)| record.clone())
    }

    fn cached_at(&self, verifier: &CredentialVerifier) -> Option<Timestamp> {
        self.cached
            .iter()
            .find(|(held, _, _)| held == verifier)
            .map(|(_, _, taken)| taken.clone())
    }
}

/// The deployment a case builds on: the registered targets, folded, and the allocators.
struct Deployment {
    log: Vec<CredentialEvent>,
    allocator: SequentialAllocator,
    secrets: CountingSecrets,
}

impl Deployment {
    fn new() -> Self {
        Self {
            log: Vec::new(),
            allocator: SequentialAllocator::new(),
            secrets: CountingSecrets::new(),
        }
    }

    fn held(&self) -> Projection {
        Projection::fold(&self.log).expect("a log of accepted events")
    }

    fn register(&mut self, audience: &str, profile: CredentialProfile) -> ResourceServerId {
        let outcome = register_resource_server(
            &RegisterResourceServer {
                context: context(PrincipalId::new(uuid(0x51))),
                audience: Audience::new(audience),
                profile,
                allowed_exchange_sources: Vec::new(),
            },
            &self.held(),
            &mut self.allocator,
        )
        .expect("a free audience in the caller's own organization");
        self.log.push(outcome.event);
        outcome.resource_server_id
    }

    /// `IssueReferenceCredential`, returning what the holder received and the identity.
    fn issue(
        &mut self,
        target: ResourceServerId,
        principal: PrincipalId,
        at: &RequestContext,
    ) -> (CredentialProof, CredentialId) {
        let held = self.held();
        let outcome = issue_reference_credential(
            &IssueReferenceCredential {
                context: context(principal),
                target,
                requested_scope: scope(),
            },
            at,
            &held,
            ReferenceParts {
                digest: &Sha256Digest,
                secrets: &mut self.secrets,
                allocator: &mut self.allocator,
            },
        )
        .expect("a registered, enabled target of the caller's organization");
        let proof = CredentialProof::from_bytes(outcome.credential.expose_material().to_vec());
        let id = outcome.credential_id;
        self.log.push(outcome.event);
        (proof, id)
    }

    /// `IssueSelfContainedCredential`, returning the whole outcome so a case can read the
    /// `kid` and the descriptor the signer decided.
    fn sign(
        &mut self,
        target: ResourceServerId,
        principal: PrincipalId,
        signer: &StaticSigner,
    ) -> Result<mandate_sts::issue::CredentialIssued, mandate_token::projection::Denied> {
        let held = self.held();
        issue_self_contained_credential(
            &IssueSelfContainedCredential {
                context: context(principal),
                target,
                requested_scope: scope(),
            },
            &request(),
            &held,
            SelfContainedParts {
                digest: &Sha256Digest,
                allocator: &mut self.allocator,
                signer,
                issuer: &Issuer::new("https://sts.example"),
            },
        )
    }
}

/// `reference-persistence`: "Reference issuance succeeds ... only non-reversible verifier
/// persists; raw secret returned once."
#[test]
fn reference_persistence() {
    let case = names(
        "reference-persistence",
        &[ISSUE_REFERENCE, INTROSPECT, CHECK],
    );
    assert_eq!(
        case["expected"],
        "only non-reversible verifier persists; raw secret returned once"
    );

    let mut deployment = Deployment::new();
    let target = deployment.register("api-a", reference_profile());
    let before = deployment.secrets.minted();
    let (proof, id) = deployment.issue(target, PrincipalId::new(uuid(0x52)), &request());

    // Returned once: the source minted exactly one secret, and nothing asks it for another.
    assert_eq!(deployment.secrets.minted(), before + 1);

    // What persists is the verifier the material derives, and the material derives it.
    let held = deployment.held();
    let record = held
        .access_credential(&id)
        .expect("the credential the issuance created");
    assert_eq!(
        record.reference_verifier,
        Some(verifier_for(&Sha256Digest, &proof))
    );

    // And nothing in the whole log is the material. The check is over every event, not over
    // the record alone: a secret laundered onto an event is a secret in the durable log.
    let material = String::from_utf8(proof.expose_material().to_vec()).expect("text");
    let log = serde_json::to_string(&deployment.log).expect("the log encodes as JSON");
    assert!(
        !log.contains(&material),
        "the log carries the secret: {log}"
    );
    assert!(
        !serde_json::to_string(&record)
            .expect("the record encodes as JSON")
            .contains(&material)
    );

    // The credential the record keeps is usable, which is what makes the persistence claim
    // about a credential and not about an empty row: the verifier alone resolves the
    // material the holder was handed.
    let (caller, _) = deployment.issue(target, PrincipalId::new(uuid(0x51)), &request());
    let held = deployment.held();
    let answer = introspect_credential(
        &IntrospectCredential {
            caller_proof: caller,
            credential_proof: proof,
        },
        &request(),
        &held,
        IntrospectionParts {
            digest: &Sha256Digest,
            resolution: &CachingResolver::over(held.clone()),
        },
    )
    .expect("an authorized introspection");
    assert!(answer.active);
    assert_eq!(answer.credential_id, Some(id));
}

/// `reference-revoked`: "ImmediateOnline profile credential has been revoked ... resolve with
/// prior positive cache ... inactive; stale positive cache never authorizes."
#[test]
fn reference_revoked() {
    let case = names("reference-revoked", &[ISSUE_REFERENCE, INTROSPECT, CHECK]);
    assert_eq!(
        case["expected"],
        "inactive; stale positive cache never authorizes"
    );

    let mut deployment = Deployment::new();
    let target = deployment.register("api-a", reference_profile());
    let (caller, _) = deployment.issue(target, PrincipalId::new(uuid(0x51)), &request());
    let (proof, id) = deployment.issue(target, PrincipalId::new(uuid(0x52)), &request());
    let held = deployment.held();
    let record = held
        .access_credential(&id)
        .expect("the credential the issuance created");

    deployment.log.push(
        revoke_access_credential(
            &RevokeAccessCredential {
                id,
                context: context(PrincipalId::new(uuid(0x51))),
            },
            &held,
        )
        .expect("an active credential of the caller's own organization"),
    );
    let held = deployment.held();
    assert_eq!(
        held.access_credential(&id).map(|record| record.state),
        Some(AccessCredentialState::Revoked)
    );

    // The cache holds the positive answer it took while the credential was live — recent
    // enough to be inside any window this profile could publish.
    let resolver = CachingResolver::over(held.clone()).holding(
        verifier_for(&Sha256Digest, &proof),
        record,
        "2026-09-19T00:00:00Z",
    );
    let answer = introspect_credential(
        &IntrospectCredential {
            caller_proof: caller,
            credential_proof: proof,
        },
        &request(),
        &held,
        IntrospectionParts {
            digest: &Sha256Digest,
            resolution: &resolver,
        },
    )
    .expect("an authorized introspection is still accepted");

    assert!(!answer.active);
    assert_eq!(answer.descriptor, None);
    assert_eq!(answer.credential_id, None);
    assert_eq!(
        resolver.consulted(),
        0,
        "a stale positive cache never authorizes: under this guarantee it is not even asked"
    );
}

/// `reference-audience`: "Credential targets API A ... present to API B ... deny audience
/// mismatch."
#[test]
fn reference_audience() {
    let case = names("reference-audience", &[ISSUE_REFERENCE, INTROSPECT, CHECK]);
    assert_eq!(case["expected"], "deny audience mismatch");

    let mut deployment = Deployment::new();
    let api_a = deployment.register("api-a", reference_profile());
    let api_b = deployment.register("api-b", reference_profile());
    let (for_api_a, _) = deployment.issue(api_a, PrincipalId::new(uuid(0x52)), &request());
    // The caller is API B: a credential whose descriptor names that audience.
    let (api_b_caller, _) = deployment.issue(api_b, PrincipalId::new(uuid(0x53)), &request());
    let held = deployment.held();

    let denied = introspect_credential(
        &IntrospectCredential {
            caller_proof: api_b_caller,
            credential_proof: for_api_a,
        },
        &request(),
        &held,
        IntrospectionParts {
            digest: &Sha256Digest,
            resolution: &CachingResolver::over(held.clone()),
        },
    )
    .expect_err("the credential targets another audience");

    assert_eq!(denied.reason, DenialReason::AudienceMismatch);
    assert_eq!(denied.clause, DenialClause::AudienceMismatch);
}

/// `reference-expired`: "Credential expiry has passed ... resolve credential ... inactive."
#[test]
fn reference_expired() {
    let case = names("reference-expired", &[ISSUE_REFERENCE, INTROSPECT, CHECK]);
    assert_eq!(case["expected"], "inactive");

    let mut deployment = Deployment::new();
    let target = deployment.register("api-a", reference_profile());
    // Issued a day earlier: the profile bounds it to an hour, so it has expired by the time
    // the caller — whose own credential has not — presents it.
    let (stale, id) = deployment.issue(
        target,
        PrincipalId::new(uuid(0x52)),
        &request_at("2026-09-18T00:00:00Z"),
    );
    let (caller, _) = deployment.issue(target, PrincipalId::new(uuid(0x51)), &request());
    let held = deployment.held();
    assert_eq!(
        held.access_credential(&id)
            .expect("the credential")
            .descriptor
            .expires_at,
        Timestamp::new("2026-09-18T01:00:00Z")
    );
    assert_eq!(
        held.access_credential(&id).map(|record| record.state),
        Some(AccessCredentialState::Active),
        "nothing revoked it: what makes it unusable is its own expiry"
    );

    let answer = introspect_credential(
        &IntrospectCredential {
            caller_proof: caller,
            credential_proof: stale,
        },
        &request(),
        &held,
        IntrospectionParts {
            digest: &Sha256Digest,
            resolution: &CachingResolver::over(held.clone()),
        },
    )
    .expect("an expired credential is an accepted answer");

    assert!(!answer.active);
    assert_eq!(answer.descriptor, None);
    assert_eq!(answer.credential_id, None);
}

/// `profile-offline-bound`: "BoundedOffline profile and recent signed credential ... revoke
/// centrally while verifier offline ... validity cannot exceed documented TTL/skew bound; no
/// immediate claim."
///
/// Two halves, and the second is the one that is easy to miss. The bound: a signer whose own
/// TTL exceeds the profile's `max_ttl` is refused, so no credential this deployment issues
/// under that profile outlives the documented bound — and the descriptor's expiry is the
/// signer's, because the `exp` the signer wrote is what an offline verifier reads. The claim:
/// a central revocation of a `BoundedOffline` credential changes the record at once and makes
/// no promise about the offline verifier, which is why the profile's own guarantee is not
/// `ImmediateOnline` and why a cached resolution is admitted under it.
#[test]
fn profile_offline_bound() {
    let case = names(
        "profile-offline-bound",
        &[ISSUE_SELF_CONTAINED, INTROSPECT, CHECK],
    );
    assert_eq!(
        case["expected"],
        "validity cannot exceed documented TTL/skew bound; no immediate claim"
    );
    assert_eq!(
        case["given"],
        "BoundedOffline profile and recent signed credential"
    );

    let mut deployment = Deployment::new();
    let target = deployment.register("api-b", self_contained_profile());

    // The bound, from the other side: a signer configured beyond `PT15M` is refused rather
    // than silently shortened, because the token would outlive whatever the descriptor said.
    let beyond = StaticSigner::new("kid-one", 901);
    let denied = deployment.sign(target, PrincipalId::new(uuid(0x52)), &beyond);
    let denied = denied.expect_err("the signer would outlive the profile's documented bound");
    assert_eq!(denied.clause, DenialClause::ExpiryUnbounded);

    let signer = StaticSigner::new("kid-one", 900);
    let caller = deployment
        .sign(target, PrincipalId::new(uuid(0x51)), &signer)
        .expect("a registered, enabled target of the caller's organization");
    let caller_proof = CredentialProof::from_bytes(caller.credential.expose_material().to_vec());
    deployment.log.push(caller.event);

    let issued = deployment
        .sign(target, PrincipalId::new(uuid(0x52)), &signer)
        .expect("a registered, enabled target of the caller's organization");
    assert_eq!(issued.kid.as_deref(), Some("kid-one"));
    assert_eq!(
        issued.descriptor.expires_at,
        Timestamp::new("2026-09-19T00:15:00Z"),
        "the descriptor's expiry is the signer's TTL, which is what an offline verifier reads"
    );
    let proof = CredentialProof::from_bytes(issued.credential.expose_material().to_vec());
    let id = issued.credential_id;
    deployment.log.push(issued.event);

    // Revoked centrally, while a verifier is offline.
    let held = deployment.held();
    let record = held.access_credential(&id).expect("the credential");
    deployment.log.push(
        revoke_access_credential(
            &RevokeAccessCredential {
                id,
                context: context(PrincipalId::new(uuid(0x51))),
            },
            &held,
        )
        .expect("an active credential of the caller's own organization"),
    );
    let held = deployment.held();
    assert_eq!(
        held.access_credential(&id).map(|record| record.state),
        Some(AccessCredentialState::Revoked),
        "the central record moves at once; what is bounded is the offline verifier"
    );

    // "No immediate claim": this profile's guarantee is `BoundedOffline`, and a deployment
    // resolving under it is allowed the cached positive answer it took before the
    // revocation — which is exactly the promise an `ImmediateOnline` profile makes and this
    // one does not. The cache is consulted, and it answers.
    //
    // The profile publishes `positive_cache_ttl: PT30S`, so "before the revocation" is not
    // enough on its own: the answer has to be inside that window. This one was taken 10
    // seconds before the request.
    let verifier = verifier_in(&Sha256Digest, CredentialDomain::SelfContainedToken, &proof);
    let inside = CachingResolver::over(held.clone()).holding(
        verifier.clone(),
        record.clone(),
        "2026-09-19T00:00:50Z",
    );
    let answer = introspect_credential(
        &IntrospectCredential {
            caller_proof: caller_proof.clone(),
            credential_proof: proof.clone(),
        },
        &request_at("2026-09-19T00:01:00Z"),
        &held,
        IntrospectionParts {
            digest: &Sha256Digest,
            resolution: &inside,
        },
    )
    .expect("an authorized introspection");

    assert!(
        answer.active,
        "the profile makes no immediate claim: a cached positive answer is what \
         BoundedOffline admits, inside its own positive_cache_ttl"
    );
    assert_eq!(inside.consulted(), 1);
    assert_eq!(
        self_contained_profile().revocation,
        RevocationGuarantee::BoundedOffline,
        "the guarantee is what admits the cache; ImmediateOnline would not"
    );

    // **The bound itself.** The same cache, the same answer, the same request — taken 31
    // seconds earlier instead of 10. `PT30S` is a bound on the age of a positive answer, so
    // this one is outside it and the authoritative record decides, which says revoked.
    let outside =
        CachingResolver::over(held.clone()).holding(verifier, record, "2026-09-19T00:00:29Z");
    let answer = introspect_credential(
        &IntrospectCredential {
            caller_proof,
            credential_proof: proof,
        },
        &request_at("2026-09-19T00:01:00Z"),
        &held,
        IntrospectionParts {
            digest: &Sha256Digest,
            resolution: &outside,
        },
    )
    .expect("an authorized introspection");

    assert!(
        !answer.active,
        "a positive answer older than the profile's documented bound authorized a revoked \
         credential"
    );
    assert_eq!(answer.descriptor, None);
    assert_eq!(
        outside.consulted(),
        1,
        "the cache was asked and its answer was refused by the bound, which is the \
         difference this case is about"
    );
}

// --- the `pkce` entries -----------------------------------------------------------------

/// RFC 7636 appendix B: the example code verifier and the S256 challenge it redeems.
const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
/// A second well-formed verifier, whose S256 challenge is not [`PKCE_CHALLENGE`].
const OTHER_PKCE_VERIFIER: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn oauth_client() -> OAuthClientId {
    OAuthClientId::new(uuid(0x0c))
}

fn oauth_session() -> SessionId {
    SessionId::new(uuid(0x5e))
}

fn authorized_redirect_uri() -> RedirectUri {
    RedirectUri::new("https://client.example/callback")
}

/// The whole authorization-code road a `pkce` entry runs on: a registered target, a
/// registered enabled client, an authenticated session, the code log, and the credential log
/// the redemption seeds a record in.
struct OAuthDeployment {
    deployment: Deployment,
    target: ResourceServerId,
    codes: InMemoryCodeLog,
    clients: RecordedClients,
    sessions: RecordedSessions,
}

impl OAuthDeployment {
    fn new() -> Self {
        let mut deployment = Deployment::new();
        let target = deployment.register("api-a", reference_profile());
        let snapshot = EpochSnapshotRef::new(uuid(0x60));
        Self {
            deployment,
            target,
            codes: InMemoryCodeLog::new(),
            clients: RecordedClients::new()
                .enabled(oauth_client(), organization())
                .redirect(oauth_client(), authorized_redirect_uri()),
            sessions: RecordedSessions::new()
                .session(SessionBinding {
                    id: oauth_session(),
                    subject: PrincipalId::new(uuid(0x51)),
                    organization: organization(),
                    epochs: Some(snapshot),
                    expires_at: Timestamp::new("2026-09-19T12:00:00Z"),
                    revoked: false,
                })
                .current(snapshot),
        }
    }

    /// `IssueAuthorizationCode`, appended to the code's own stream.
    fn issue_code(&mut self) -> (AuthorizationCodeId, CredentialProof) {
        let held = self.deployment.held();
        let outcome = CodeIssuance::new(CodeLifetime::new(Duration::new("PT5M")))
            .issue(
                &IssueAuthorizationCode {
                    context: context(PrincipalId::new(uuid(0x51))),
                    client_id: oauth_client(),
                    session_id: oauth_session(),
                    target: self.target,
                    requested_scope: scope(),
                    challenge: PkceChallenge::new(PKCE_CHALLENGE),
                    method: PkceMethod::S256,
                    redirect_uri: authorized_redirect_uri(),
                    expires_at: Timestamp::new("2026-09-19T00:05:00Z"),
                },
                &request(),
                &held,
                &self.clients,
                AuthorizationCodeParts {
                    digest: &Sha256Digest,
                    secrets: &mut self.deployment.secrets,
                    allocator: &mut self.deployment.allocator,
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

    /// `RedeemAuthorizationCode` through the command path, recording the credential the
    /// accepted outcome seeds in the credential log.
    fn redeem(
        &mut self,
        input: &RedeemAuthorizationCode,
    ) -> Result<mandate_sts::redemption::AuthorizationCodeRedemption, RedemptionRefused> {
        let servers = self.deployment.held();
        let outcome = redeem_and_consume(
            input,
            &request(),
            &mut self.codes,
            BoundReads {
                servers: &servers,
                clients: &self.clients,
                sessions: &self.sessions,
            },
            RedemptionParts {
                digest: &Sha256Digest,
                secrets: &mut self.deployment.secrets,
                allocator: &mut self.deployment.allocator,
            },
        )?;
        if let Some(event) = outcome.event.credential_event() {
            self.deployment.log.push(event);
        }
        Ok(outcome)
    }

    /// How many `AccessCredential` records the credential log holds.
    fn credentials(&self) -> usize {
        self.deployment.held().credentials().len()
    }
}

fn presented(code_id: AuthorizationCodeId, proof: &CredentialProof) -> RedeemAuthorizationCode {
    RedeemAuthorizationCode {
        code_id,
        client_id: oauth_client(),
        code: CredentialProof::from_bytes(proof.expose_material().to_vec()),
        pkce_verifier: CredentialProof::from_bytes(PKCE_VERIFIER.as_bytes().to_vec()),
        redirect_uri: authorized_redirect_uri(),
    }
}

/// `pkce-valid`: "S256 challenge, matching verifier, exact redirect, fresh code and
/// state/nonce" → "one credential; code consumed atomically".
///
/// The state and the nonce are `AuthorizePublicClient`'s inputs and neither STS command takes
/// one, so the half of the `given` this crate can execute is the challenge, the verifier, the
/// redirect and the freshness. "Atomically" is the append: one group on the code's own
/// stream, compare-and-set on the version the decision was read at.
#[test]
fn pkce_valid() {
    let case = pkce_names("pkce-valid");
    assert_eq!(case["expected"], "one credential; code consumed atomically");

    let mut deployment = OAuthDeployment::new();
    let (code_id, proof) = deployment.issue_code();
    let version = deployment.codes.version(&code_id);

    let outcome = deployment
        .redeem(&presented(code_id, &proof))
        .expect("the matching verifier, client and redirect");

    assert_eq!(deployment.credentials(), 1, "one credential");
    assert_eq!(
        deployment
            .codes
            .projection()
            .authorization_code(&code_id)
            .map(|code| code.state),
        Some(AuthorizationCodeState::Consumed),
        "the code is consumed"
    );
    assert_eq!(
        deployment.codes.version(&code_id),
        version.advance(),
        "one append group, on the code's own stream"
    );
    assert_eq!(
        deployment
            .deployment
            .held()
            .access_credential(&outcome.credential_id)
            .map(|record| record.state),
        Some(AccessCredentialState::Active)
    );
}

/// `pkce-wrong`: "Wrong verifier" → "deny; no credential".
#[test]
fn pkce_wrong() {
    let case = pkce_names("pkce-wrong");
    assert_eq!(case["expected"], "deny; no credential");

    let mut deployment = OAuthDeployment::new();
    let (code_id, proof) = deployment.issue_code();
    let minted = deployment.deployment.secrets.minted();

    let refused = deployment
        .redeem(&RedeemAuthorizationCode {
            pkce_verifier: CredentialProof::from_bytes(OTHER_PKCE_VERIFIER.as_bytes().to_vec()),
            ..presented(code_id, &proof)
        })
        .expect_err("the verifier does not redeem the recorded challenge");

    assert_eq!(
        refused,
        RedemptionRefused::Denied(Denied::new(
            DenialReason::InvalidCredential,
            DenialClause::VerifierMismatch
        ))
    );
    assert_eq!(deployment.credentials(), 0, "no credential");
    assert_eq!(
        deployment.deployment.secrets.minted(),
        minted,
        "the refusal mints nothing"
    );
    assert_eq!(
        deployment
            .codes
            .projection()
            .authorization_code(&code_id)
            .map(|code| code.state),
        Some(AuthorizationCodeState::Issued),
        "the code is not consumed"
    );
}

/// `pkce-redirect`: "Redirect differs from exact registered/authorized URI" → "deny".
///
/// The redirect presented here is the authorized one with a trailing slash — the shape a
/// normalizing comparison would admit. `services/sts/tests/binding.rs` enumerates the rest of
/// that class.
#[test]
fn pkce_redirect() {
    let case = pkce_names("pkce-redirect");
    assert_eq!(case["expected"], "deny");

    let mut deployment = OAuthDeployment::new();
    let (code_id, proof) = deployment.issue_code();

    let refused = deployment
        .redeem(&RedeemAuthorizationCode {
            redirect_uri: RedirectUri::new("https://client.example/callback/"),
            ..presented(code_id, &proof)
        })
        .expect_err("not the exact redirect the code authorized");

    assert_eq!(
        refused,
        RedemptionRefused::Denied(Denied::new(
            DenialReason::Denied,
            DenialClause::RedirectMismatch
        ))
    );
    assert_eq!(deployment.credentials(), 0);
    assert_eq!(
        deployment
            .codes
            .projection()
            .authorization_code(&code_id)
            .map(|code| code.state),
        Some(AuthorizationCodeState::Issued)
    );
}

/// `pkce-reuse`: "Previously redeemed code **or concurrent second redemption**" → "deny; at
/// most one issuance".
///
/// Both halves of the `given`, because they are refused by different mechanisms and either
/// one alone would leave the entry half-executed. The sequential half is the declared
/// `wrong-state` outcome, read off the record. The concurrent half is the compare-and-set:
/// two deciders read the same version and the same projection, both decide `accepted`, both
/// append, and the second presents a version the stream has left.
#[test]
fn pkce_reuse() {
    let case = pkce_names("pkce-reuse");
    assert_eq!(case["expected"], "deny; at most one issuance");

    // The sequential half.
    let mut deployment = OAuthDeployment::new();
    let (code_id, proof) = deployment.issue_code();
    deployment
        .redeem(&presented(code_id, &proof))
        .expect("the first redemption");

    let refused = deployment
        .redeem(&presented(code_id, &proof))
        .expect_err("the code is already consumed");

    assert_eq!(
        refused,
        RedemptionRefused::Denied(Denied::wrong_state(
            DenialReason::Denied,
            DenialClause::CodeConsumed
        ))
    );
    assert_eq!(deployment.credentials(), 1, "at most one issuance");

    // The concurrent half.
    let mut deployment = OAuthDeployment::new();
    let (code_id, proof) = deployment.issue_code();
    let input = presented(code_id, &proof);
    let expected = deployment.codes.version(&code_id);
    let servers = deployment.deployment.held();
    let decide = |secrets: &mut CountingSecrets, allocator: &mut SequentialAllocator| {
        redeem_authorization_code(
            &input,
            &request(),
            deployment.codes.projection(),
            BoundReads {
                servers: &servers,
                clients: &deployment.clients,
                sessions: &deployment.sessions,
            },
            RedemptionParts {
                digest: &Sha256Digest,
                secrets,
                allocator,
            },
        )
    };
    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();
    let one = decide(&mut secrets, &mut allocator).expect("the first decision");
    let two = decide(&mut secrets, &mut allocator).expect("the second, against the same state");

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
            actual: winner
        }
    );
    deployment.deployment.log.push(
        one.event
            .credential_event()
            .expect("the redemption seeds a credential"),
    );
    assert_eq!(deployment.credentials(), 1, "at most one issuance");
    assert!(
        deployment
            .deployment
            .held()
            .access_credential(&two.credential_id)
            .is_none(),
        "the loser's credential never reaches a log"
    );
}
