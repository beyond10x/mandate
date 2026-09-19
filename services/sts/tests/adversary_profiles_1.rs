//! Adversarial cases against `story:credential-profiles`, `resolve` unit.
//!
//! The acceptance, verbatim:
//!
//! > Given a newly issued reference credential under ImmediateOnline, when it is revoked,
//! > then its next authorized introspection reports inactive even if an earlier resolution
//! > was cached.
//!
//! `introspect_credential` decides whether a cached resolution may answer from
//! `server.credential_profile`, where `server` is the registration the **caller's** own
//! credential resolves to *now* — `resolve.rs`, `servers.registered(&caller.descriptor
//! .organization, &caller.descriptor.audience)`. It is not the registration the presented
//! credential was issued under, and the two come apart the moment an audience changes hands,
//! which `services/sts/src/registry.rs` documents as ordinary ("it also stops holding its
//! audience, which is what lets the deployment register that audience again") and
//! `services/sts/tests/registry.rs` covers with
//! `a_disabled_registration_releases_its_audience`.
//!
//! The second case is the other half of the same field: `mandate.core.CredentialProfile
//! .positive_cache_ttl` is read once, by `registry::admits_profile`, and by nothing that
//! decides anything afterwards — while `services/sts/src/resolve.rs` states that a cached
//! answer under `BoundedOffline` is "bounded by the profile's `positive_cache_ttl`".

use std::cell::Cell;

use mandate_sts::issue::{
    IssueReferenceCredential, ReferenceParts, Sha256Digest, issue_reference_credential,
};
use mandate_sts::registry::{
    DisableResourceServer, RegisterResourceServer, disable_resource_server,
    register_resource_server,
};
use mandate_sts::resolve::{
    CredentialIntrospection, CredentialResolution, IntrospectCredential, IntrospectionParts,
    ResolutionUnavailable, RevokeAccessCredential, introspect_credential, revoke_access_credential,
};
use mandate_sts::{CountingSecrets, RequestContext, SequentialAllocator};
use mandate_token::CredentialProfile;
use mandate_token::projection::{AccessCredential, CredentialEvent, Denied, Projection};
use mandate_token::verifier::verifier_for;
use mandate_types::{
    Audience, AuthorityScope, CorrelationId, CredentialId, CredentialKind, CredentialProof,
    CredentialVerifier, Duration, OrganizationId, PrincipalId, ResourceServerId,
    RevocationGuarantee, Timestamp, Transient, Uuid, VerifiedContext,
};

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(10))
}

fn principal(tag: u8) -> PrincipalId {
    PrincipalId::new(uuid(tag))
}

fn context(who: PrincipalId) -> VerifiedContext {
    VerifiedContext {
        subject: who,
        actor: None,
        organization: organization(),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("adversary-profiles-1"),
    }
}

fn request() -> RequestContext {
    RequestContext {
        correlation: CorrelationId::new("adversary-profiles-1"),
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

/// A reference profile, over the guarantee and the positive-cache bound a case names.
fn reference_profile(
    revocation: RevocationGuarantee,
    positive_cache_ttl: &str,
) -> CredentialProfile {
    CredentialProfile {
        name: "reference".to_owned(),
        kind: CredentialKind::Reference,
        revocation,
        max_ttl: Duration::new("PT1H"),
        positive_cache_ttl: Duration::new(positive_cache_ttl),
        requires_online_authorization: revocation == RevocationGuarantee::ImmediateOnline,
    }
}

/// A resolver that answers authoritatively from the fold and holds positive answers it took
/// earlier, counting every time its cache is asked.
struct CachingResolver {
    fold: Projection,
    cached: Vec<(CredentialVerifier, AccessCredential)>,
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

    fn holding(mut self, verifier: CredentialVerifier, record: AccessCredential) -> Self {
        self.cached.push((verifier, record));
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
            .find(|(held, _)| held == verifier)
            .map(|(_, record)| record.clone())
    }
}

/// A deployment driven through the real handlers alone: every event in the log is an
/// accepted outcome of a command this story realizes.
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
                context: context(principal(0x51)),
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

    fn disable(&mut self, id: ResourceServerId) {
        let event = disable_resource_server(
            &DisableResourceServer {
                id,
                context: context(principal(0x51)),
            },
            &self.held(),
        )
        .expect("an enabled registration of the caller's own organization");
        self.log.push(event);
    }

    fn issue(
        &mut self,
        target: ResourceServerId,
        who: PrincipalId,
    ) -> (CredentialProof, CredentialId) {
        let held = self.held();
        let outcome = issue_reference_credential(
            &IssueReferenceCredential {
                context: context(who),
                target,
                requested_scope: scope(),
            },
            &request(),
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

    fn revoke(&mut self, id: CredentialId) {
        let event = revoke_access_credential(
            &RevokeAccessCredential {
                id,
                context: context(principal(0x51)),
            },
            &self.held(),
        )
        .expect("an active credential of the caller's own organization");
        self.log.push(event);
    }
}

fn introspect(
    caller: &CredentialProof,
    presented: &CredentialProof,
    held: &Projection,
    resolution: &impl CredentialResolution,
) -> Result<CredentialIntrospection, Denied> {
    introspect_credential(
        &IntrospectCredential {
            caller_proof: caller.clone(),
            credential_proof: presented.clone(),
        },
        &request(),
        held,
        IntrospectionParts {
            digest: &Sha256Digest,
            resolution,
        },
    )
}

/// **The acceptance, after an ordinary re-registration of the same audience.**
///
/// The credential is issued under an `ImmediateOnline` profile and revoked. The audience it
/// names is then disabled and registered again — the path `registry.rs` documents and
/// `tests/registry.rs::a_disabled_registration_releases_its_audience` covers — this time
/// under a `BoundedOffline` profile. The credential's own guarantee did not change; it was
/// issued under `ImmediateOnline` and the acceptance is a sentence about it.
#[test]
fn a_revoked_immediate_online_credential_reports_active_once_its_audience_is_re_registered() {
    let mut deployment = Deployment::new();
    let first = deployment.register(
        "api-a",
        reference_profile(RevocationGuarantee::ImmediateOnline, "PT30S"),
    );
    let (caller_proof, _) = deployment.issue(first, principal(0x51));
    let (proof, id) = deployment.issue(first, principal(0x52));

    // The answer the deployment's cache took while the credential was live.
    let cached = deployment
        .held()
        .access_credential(&id)
        .expect("the credential the issuance created");
    let verifier = verifier_for(&Sha256Digest, &proof);

    deployment.revoke(id);
    // Ordinary administration: the audience changes hands.
    deployment.disable(first);
    let second = deployment.register(
        "api-a",
        reference_profile(RevocationGuarantee::BoundedOffline, "PT30S"),
    );
    assert_ne!(first, second, "the audience is held by a new registration");

    let held = deployment.held();
    let resolver = CachingResolver::over(held.clone()).holding(verifier, cached);
    let answer = introspect(&caller_proof, &proof, &held, &resolver)
        .expect("an authorized introspection is still accepted");

    assert!(
        !answer.active,
        "the credential was issued under ImmediateOnline and revoked; its next authorized \
         introspection answered active from a cache, because the guarantee `resolve.rs` \
         applies is the caller's current registration's and not the one the credential was \
         issued under (cache consulted {} time(s))",
        resolver.consulted()
    );
    assert_eq!(answer.descriptor, None);
    assert_eq!(answer.credential_id, None);
}

/// A `BoundedOffline` profile that declares it caches a positive answer for no time at all.
///
/// `registry::admits_profile` admits `PT0S` — it refuses only a negative span and one longer
/// than `max_ttl` — and the unit's own corpus fixture
/// (`services/sts/tests/corpus.rs`, `self_contained_profile`) is registered with exactly
/// that value. Nothing downstream reads the field again, so the bound the profile publishes
/// to the holder of the resource is not a bound on anything this handler decides.
#[test]
fn a_bounded_offline_profile_that_caches_for_no_time_still_answers_from_the_cache() {
    let mut deployment = Deployment::new();
    let target = deployment.register(
        "api-b",
        reference_profile(RevocationGuarantee::BoundedOffline, "PT0S"),
    );
    let (caller_proof, _) = deployment.issue(target, principal(0x51));
    let (proof, id) = deployment.issue(target, principal(0x52));

    let cached = deployment
        .held()
        .access_credential(&id)
        .expect("the credential the issuance created");
    let verifier = verifier_for(&Sha256Digest, &proof);

    deployment.revoke(id);

    let held = deployment.held();
    let resolver = CachingResolver::over(held.clone()).holding(verifier, cached);
    let answer =
        introspect(&caller_proof, &proof, &held, &resolver).expect("an authorized introspection");

    assert_eq!(
        resolver.consulted(),
        0,
        "the registered profile publishes `positive_cache_ttl: PT0S`, so no cached positive \
         answer is inside its bound; `resolve.rs` consults the cache on the guarantee alone \
         and reads the field nowhere"
    );
    assert!(
        !answer.active,
        "a positive answer older than the profile's whole positive-cache bound authorized a \
         revoked credential"
    );
}

/// The control: the acceptance exactly as written, with the audience in the same hands
/// throughout.
///
/// It passes, which is what makes the first case a statement about which registration
/// `resolve.rs` reads the guarantee from, and not about this file's doubles.
#[test]
fn the_acceptance_holds_while_the_audience_keeps_its_registration() {
    let mut deployment = Deployment::new();
    let target = deployment.register(
        "api-a",
        reference_profile(RevocationGuarantee::ImmediateOnline, "PT30S"),
    );
    let (caller_proof, _) = deployment.issue(target, principal(0x51));
    let (proof, id) = deployment.issue(target, principal(0x52));

    let cached = deployment
        .held()
        .access_credential(&id)
        .expect("the credential the issuance created");
    let verifier = verifier_for(&Sha256Digest, &proof);

    deployment.revoke(id);

    let held = deployment.held();
    let resolver = CachingResolver::over(held.clone()).holding(verifier, cached);
    let answer =
        introspect(&caller_proof, &proof, &held, &resolver).expect("an authorized introspection");

    assert!(!answer.active);
    assert_eq!(answer.descriptor, None);
    assert_eq!(answer.credential_id, None);
    assert_eq!(resolver.consulted(), 0);
}
