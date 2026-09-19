//! `IntrospectCredential` and `RevokeAccessCredential`, and the story's acceptance.
//!
//! > Given a newly issued reference credential under ImmediateOnline, when it is revoked,
//! > then its next authorized introspection reports inactive even if an earlier resolution
//! > was cached.
//!
//! [`a_revoked_immediate_online_credential_reports_inactive_and_no_cache_is_consulted`] is
//! that sentence. The case owns a resolver that caches positive answers and counts every
//! time it is asked for one; the cache is primed with the answer the *first* introspection
//! would have produced, the credential is revoked, and the second introspection is asserted
//! inactive with the counter still at zero. A counter that never moves would prove nothing
//! on its own, so [`the_same_cache_is_consulted_under_a_profile_that_admits_one`] shows the
//! same double being asked under a `BoundedOffline` profile: the difference is the profile's
//! guarantee, not the double's wiring.
//!
//! The introspection answer itself follows the contract's own summary
//! (`credential.yaml`, `IntrospectCredential`): a credential this deployment revoked, one
//! whose expiry has passed, and a well-formed proof that resolves to no record "are one
//! answer here and not three" — `accepted`, `active: false`, no descriptor and no
//! `credential_id`. A caller holding a well-formed proof learns only whether it is usable.

use std::cell::Cell;

use mandate_sts::issue::{
    IssueReferenceCredential, ReferenceParts, Sha256Digest, issue_reference_credential,
};
use mandate_sts::registry::{RegisterResourceServer, register_resource_server};
use mandate_sts::resolve::{
    CredentialResolution, IntrospectCredential, IntrospectionParts, ResolutionUnavailable,
    RevokeAccessCredential, introspect_credential, revoke_access_credential,
};
use mandate_sts::{
    CountingSecrets, IdentityAllocator, RequestContext, SecretSource, SequentialAllocator,
};
use mandate_token::CredentialProfile;
use mandate_token::projection::{
    AccessCredential, AccessCredentialState, CredentialEvent, DenialClause, Projection,
    RefusedOutcome,
};
use mandate_token::verifier::verifier_for;
use mandate_types::{
    Audience, AuthorityScope, CorrelationId, CredentialId, CredentialKind, CredentialProof,
    CredentialVerifier, DenialReason, Duration, OrganizationId, PrincipalId, RevocationGuarantee,
    Timestamp, Transient, Uuid, VerifiedContext,
};

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization(tag: u8) -> OrganizationId {
    OrganizationId::new(uuid(tag))
}

fn subject(tag: u8) -> PrincipalId {
    PrincipalId::new(uuid(tag))
}

fn context(organization_id: OrganizationId, principal: PrincipalId) -> VerifiedContext {
    VerifiedContext {
        subject: principal,
        actor: None,
        organization: organization_id,
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("resolve"),
    }
}

fn request_at(at: &str) -> RequestContext {
    RequestContext {
        correlation: CorrelationId::new("resolve"),
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

fn profile(revocation: RevocationGuarantee) -> CredentialProfile {
    CredentialProfile {
        name: "reference".to_owned(),
        kind: CredentialKind::Reference,
        revocation,
        max_ttl: Duration::new("PT1H"),
        positive_cache_ttl: Duration::new("PT30S"),
        requires_online_authorization: revocation == RevocationGuarantee::ImmediateOnline,
    }
}

/// A resolver that answers from the fold, and *also* holds positive answers it saw earlier.
///
/// The deployment's cache, as a double: [`CachingResolver::consulted`] counts every time the
/// cache was asked, which is what the acceptance is about. `resolve` is the authoritative
/// answer and is always the fold's.
struct CachingResolver {
    fold: Projection,
    cached: Vec<(CredentialVerifier, AccessCredential, Timestamp)>,
    consulted: Cell<usize>,
    available: bool,
}

impl CachingResolver {
    fn over(fold: Projection) -> Self {
        Self {
            fold,
            cached: Vec::new(),
            consulted: Cell::new(0),
            available: true,
        }
    }

    /// Prime the cache with a positive answer taken at an instant, as a deployment's cache
    /// would hold one. The instant is what the profile's `positive_cache_ttl` bounds.
    fn holding(
        mut self,
        verifier: CredentialVerifier,
        record: AccessCredential,
        taken: &str,
    ) -> Self {
        self.cached.push((verifier, record, Timestamp::new(taken)));
        self
    }

    /// The authoritative resolution is unreachable.
    fn unavailable(mut self) -> Self {
        self.available = false;
        self
    }

    /// How many times the cache was asked.
    fn consulted(&self) -> usize {
        self.consulted.get()
    }
}

impl CredentialResolution for CachingResolver {
    fn resolve(
        &self,
        verifier: &CredentialVerifier,
    ) -> Result<Option<AccessCredential>, ResolutionUnavailable> {
        if !self.available {
            return Err(ResolutionUnavailable);
        }
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

/// What one issuance leaves behind: the log, the material the holder received, and the
/// identity of the credential.
struct Issued {
    log: Vec<CredentialEvent>,
    proof: CredentialProof,
    credential_id: CredentialId,
}

/// A registered target and one credential issued for it, both through the real handlers.
fn issued_for(
    organization_id: OrganizationId,
    audience: &str,
    principal: PrincipalId,
    revocation: RevocationGuarantee,
    held: &Projection,
    allocator: &mut SequentialAllocator,
    secrets: &mut CountingSecrets,
) -> Issued {
    let registration = register_resource_server(
        &RegisterResourceServer {
            context: context(organization_id, principal),
            audience: Audience::new(audience),
            profile: profile(revocation),
            allowed_exchange_sources: Vec::new(),
        },
        held,
        allocator,
    )
    .expect("a free audience in the caller's own organization");
    let mut log = vec![registration.event];
    let folded = Projection::fold(&log).expect("one creation");
    let issued = issue_reference_credential(
        &IssueReferenceCredential {
            context: context(organization_id, principal),
            target: registration.resource_server_id,
            requested_scope: scope(),
        },
        &request(),
        &folded,
        ReferenceParts {
            digest: &Sha256Digest,
            secrets,
            allocator,
        },
    )
    .expect("a registered, enabled target of the caller's organization");
    let proof = CredentialProof::from_bytes(issued.credential.expose_material().to_vec());
    log.push(issued.event);
    Issued {
        log,
        proof,
        credential_id: issued.credential_id,
    }
}

/// The ordinary setup: one organization, one registered audience, one caller credential and
/// one credential the caller introspects, both for that audience.
fn deployment(revocation: RevocationGuarantee) -> (Vec<CredentialEvent>, CredentialProof, Issued) {
    let mut allocator = SequentialAllocator::new();
    let mut secrets = CountingSecrets::new();
    let caller = issued_for(
        organization(10),
        "api-a",
        subject(0x51),
        revocation,
        &Projection::default(),
        &mut allocator,
        &mut secrets,
    );
    let held = Projection::fold(&caller.log).expect("a registration and an issuance");
    // The credential under test is issued for the same audience: the caller is the resource
    // server that audience names, and it introspects what was presented to it.
    let subject_credential = {
        let folded = held.clone();
        let issued = issue_reference_credential(
            &IssueReferenceCredential {
                context: context(organization(10), subject(0x52)),
                target: folded
                    .registered(&organization(10), &Audience::new("api-a"))
                    .expect("the registration")
                    .id,
                requested_scope: scope(),
            },
            &request(),
            &folded,
            ReferenceParts {
                digest: &Sha256Digest,
                secrets: &mut secrets,
                allocator: &mut allocator,
            },
        )
        .expect("a registered, enabled target of the caller's organization");
        Issued {
            log: vec![issued.event],
            proof: CredentialProof::from_bytes(issued.credential.expose_material().to_vec()),
            credential_id: issued.credential_id,
        }
    };
    let mut log = caller.log;
    log.extend(subject_credential.log.iter().cloned());
    (log, caller.proof, subject_credential)
}

/// One introspection through the real handler, against a resolver the case supplies.
fn introspect(
    caller: &CredentialProof,
    presented: &CredentialProof,
    held: &Projection,
    resolution: &impl CredentialResolution,
    at: &RequestContext,
) -> Result<mandate_sts::resolve::CredentialIntrospection, mandate_token::projection::Denied> {
    introspect_credential(
        &IntrospectCredential {
            caller_proof: caller.clone(),
            credential_proof: presented.clone(),
        },
        at,
        held,
        IntrospectionParts {
            digest: &Sha256Digest,
            resolution,
        },
    )
}

/// **The story's acceptance.**
#[test]
fn a_revoked_immediate_online_credential_reports_inactive_and_no_cache_is_consulted() {
    let (log, caller, subject_credential) = deployment(RevocationGuarantee::ImmediateOnline);
    let held = Projection::fold(&log).expect("two issuances against one registration");
    let record = held
        .access_credential(&subject_credential.credential_id)
        .expect("the credential the issuance created");
    let verifier = verifier_for(&Sha256Digest, &subject_credential.proof);

    // Before the revocation the answer is active, and the deployment's cache now holds it.
    let resolver = CachingResolver::over(held.clone());
    let before = introspect(
        &caller,
        &subject_credential.proof,
        &held,
        &resolver,
        &request(),
    )
    .expect("an authorized introspection of a live credential");
    assert!(before.active);
    assert_eq!(before.credential_id, Some(subject_credential.credential_id));

    let revoked = revoke_access_credential(
        &RevokeAccessCredential {
            id: subject_credential.credential_id,
            context: context(organization(10), subject(0x51)),
        },
        &held,
    )
    .expect("an active credential of the caller's own organization");
    let mut log = log;
    log.push(revoked);
    let held = Projection::fold(&log).expect("the revocation moves the record");

    // The cache still holds the positive answer it took before the revocation, taken just
    // now — inside any window this profile could publish, so nothing but the guarantee
    // keeps it out of the answer.
    let resolver =
        CachingResolver::over(held.clone()).holding(verifier, record, "2026-09-19T00:00:00Z");
    let after = introspect(
        &caller,
        &subject_credential.proof,
        &held,
        &resolver,
        &request(),
    )
    .expect("an authorized introspection is still accepted");

    assert!(!after.active, "a revoked credential is not usable");
    assert_eq!(after.descriptor, None);
    assert_eq!(after.credential_id, None);
    assert_eq!(
        resolver.consulted(),
        0,
        "an ImmediateOnline profile never reads a cached resolution"
    );
}

/// The counter above is not stuck at zero, and the cache is not answering for nothing: the
/// same double, under a profile whose guarantee admits a cached positive answer, is asked
/// **and its answer stands** — against a credential the authoritative record says is
/// revoked. Nothing but the cache could produce `active` here.
#[test]
fn the_same_cache_is_consulted_under_a_profile_that_admits_one() {
    let (log, caller, subject_credential) = deployment(RevocationGuarantee::BoundedOffline);
    let held = Projection::fold(&log).expect("two issuances against one registration");
    let record = held
        .access_credential(&subject_credential.credential_id)
        .expect("the credential the issuance created");
    let verifier = verifier_for(&Sha256Digest, &subject_credential.proof);
    let mut log = log;
    log.push(
        revoke_access_credential(
            &RevokeAccessCredential {
                id: subject_credential.credential_id,
                context: context(organization(10), subject(0x51)),
            },
            &held,
        )
        .expect("an active credential of the caller's own organization"),
    );
    let held = Projection::fold(&log).expect("the revocation moves the record");

    // Taken 10 seconds before the request; the profile publishes `PT30S`.
    let resolver =
        CachingResolver::over(held.clone()).holding(verifier, record, "2026-09-19T00:00:50Z");
    let answer = introspect(
        &caller,
        &subject_credential.proof,
        &held,
        &resolver,
        &request_at("2026-09-19T00:01:00Z"),
    )
    .expect("an authorized introspection");

    assert!(
        answer.active,
        "the cached answer stands under BoundedOffline: the fold says revoked"
    );
    assert_eq!(
        resolver.consulted(),
        1,
        "a BoundedOffline profile is what a cached resolution is for"
    );
}

/// **The bound is an age, and it is enforced.** The same profile, the same double, the same
/// revoked credential — with the cached answer taken 31 seconds before the request instead
/// of 10, against a `positive_cache_ttl` of `PT30S`. The cache is asked, its answer is
/// outside the window, and the authoritative record decides.
#[test]
fn a_cached_answer_older_than_the_profiles_bound_does_not_authorize() {
    let (log, caller, subject_credential) = deployment(RevocationGuarantee::BoundedOffline);
    let held = Projection::fold(&log).expect("two issuances against one registration");
    let record = held
        .access_credential(&subject_credential.credential_id)
        .expect("the credential the issuance created");
    let verifier = verifier_for(&Sha256Digest, &subject_credential.proof);
    let mut log = log;
    log.push(
        revoke_access_credential(
            &RevokeAccessCredential {
                id: subject_credential.credential_id,
                context: context(organization(10), subject(0x51)),
            },
            &held,
        )
        .expect("an active credential of the caller's own organization"),
    );
    let held = Projection::fold(&log).expect("the revocation moves the record");

    let resolver =
        CachingResolver::over(held.clone()).holding(verifier, record, "2026-09-19T00:00:29Z");
    let answer = introspect(
        &caller,
        &subject_credential.proof,
        &held,
        &resolver,
        &request_at("2026-09-19T00:01:00Z"),
    )
    .expect("an authorized introspection");

    assert!(
        !answer.active,
        "a stale positive answer authorized a revocation"
    );
    assert_eq!(answer.descriptor, None);
    assert_eq!(resolver.consulted(), 1, "the cache was asked and refused");
}

/// A cache that cannot say when it took its answer is a cache whose answer cannot be shown
/// to be inside any bound, so it is not used — whatever the guarantee.
#[test]
fn a_cache_that_cannot_date_its_answer_does_not_authorize() {
    struct UndatedCache {
        fold: Projection,
        cached: Vec<(CredentialVerifier, AccessCredential)>,
    }

    impl CredentialResolution for UndatedCache {
        fn resolve(
            &self,
            verifier: &CredentialVerifier,
        ) -> Result<Option<AccessCredential>, ResolutionUnavailable> {
            self.fold.resolve(verifier)
        }

        fn cached(&self, verifier: &CredentialVerifier) -> Option<AccessCredential> {
            self.cached
                .iter()
                .find(|(held, _)| held == verifier)
                .map(|(_, record)| record.clone())
        }
        // `cached_at` is left at its default, which is the refusal this case is about.
    }

    let (log, caller, subject_credential) = deployment(RevocationGuarantee::BoundedOffline);
    let held = Projection::fold(&log).expect("two issuances against one registration");
    let record = held
        .access_credential(&subject_credential.credential_id)
        .expect("the credential the issuance created");
    let mut log = log;
    log.push(
        revoke_access_credential(
            &RevokeAccessCredential {
                id: subject_credential.credential_id,
                context: context(organization(10), subject(0x51)),
            },
            &held,
        )
        .expect("an active credential of the caller's own organization"),
    );
    let held = Projection::fold(&log).expect("the revocation moves the record");
    let resolver = UndatedCache {
        fold: held.clone(),
        cached: vec![(
            verifier_for(&Sha256Digest, &subject_credential.proof),
            record,
        )],
    };

    let answer = introspect(
        &caller,
        &subject_credential.proof,
        &held,
        &resolver,
        &request(),
    )
    .expect("an authorized introspection");

    assert!(!answer.active);
}

/// **The guarantee is the credential's, not the audience's current holder's.**
///
/// The audience changes hands between two registrations — which `registry.rs` documents as
/// ordinary — and the new one publishes `BoundedOffline` where the old published
/// `ImmediateOnline`. A credential issued under the old one is still an `ImmediateOnline`
/// credential, so a cached positive answer about it is refused even though the registration
/// holding its audience now would admit one.
#[test]
fn a_credential_keeps_the_guarantee_it_was_issued_under() {
    let (log, caller, subject_credential) = deployment(RevocationGuarantee::ImmediateOnline);
    let held = Projection::fold(&log).expect("two issuances against one registration");
    let record = held
        .access_credential(&subject_credential.credential_id)
        .expect("the credential the issuance created");
    let verifier = verifier_for(&Sha256Digest, &subject_credential.proof);
    let first = held
        .registered(&organization(10), &Audience::new("api-a"))
        .expect("the registration")
        .id;

    let mut log = log;
    log.push(
        revoke_access_credential(
            &RevokeAccessCredential {
                id: subject_credential.credential_id,
                context: context(organization(10), subject(0x51)),
            },
            &held,
        )
        .expect("an active credential of the caller's own organization"),
    );
    // The audience changes hands, to a registration that admits a cached answer.
    log.push(CredentialEvent::ResourceServerDisabled {
        context: context(organization(10), subject(0x51)),
        id: first,
    });
    let held = Projection::fold(&log).expect("the disablement");
    let mut allocator = SequentialAllocator::new();
    for _ in 0..4 {
        let _ = allocator.next_resource_server_id();
    }
    let second = register_resource_server(
        &RegisterResourceServer {
            context: context(organization(10), subject(0x51)),
            audience: Audience::new("api-a"),
            profile: profile(RevocationGuarantee::BoundedOffline),
            allowed_exchange_sources: Vec::new(),
        },
        &held,
        &mut allocator,
    )
    .expect("the audience is free again");
    assert_ne!(second.resource_server_id, first);
    log.push(second.event);
    let held = Projection::fold(&log).expect("the second registration");

    let resolver =
        CachingResolver::over(held.clone()).holding(verifier, record, "2026-09-19T00:00:00Z");
    let answer = introspect(
        &caller,
        &subject_credential.proof,
        &held,
        &resolver,
        &request(),
    )
    .expect("an authorized introspection is still accepted");

    assert!(
        !answer.active,
        "the credential was issued under ImmediateOnline and revoked"
    );
    assert_eq!(answer.credential_id, None);
}

#[test]
fn an_active_answer_carries_the_descriptor_and_the_credential_it_names() {
    let (log, caller, subject_credential) = deployment(RevocationGuarantee::ImmediateOnline);
    let held = Projection::fold(&log).expect("two issuances");
    let resolver = CachingResolver::over(held.clone());

    let answer = introspect(
        &caller,
        &subject_credential.proof,
        &held,
        &resolver,
        &request(),
    )
    .expect("an authorized introspection");

    assert!(answer.active);
    assert_eq!(answer.credential_id, Some(subject_credential.credential_id));
    let descriptor = answer
        .descriptor
        .clone()
        .expect("an active answer's descriptor");
    assert_eq!(descriptor.subject, subject(0x52));
    assert_eq!(descriptor.audience, Audience::new("api-a"));

    assert_eq!(
        answer.event,
        CredentialEvent::CredentialIntrospected {
            context: VerifiedContext {
                subject: subject(0x51),
                actor: None,
                organization: organization(10),
                audience: Audience::new("api-a"),
                // The generated context names the caller's own credential, which is what
                // the caller's proof resolved to.
                credential: held
                    .resolve(&verifier_for(&Sha256Digest, &caller))
                    .expect("the fold is authoritative")
                    .expect("the caller's own credential")
                    .id,
                delegation: None,
                execution: None,
                correlation: CorrelationId::new("resolve"),
            },
            descriptor: Some(descriptor),
            active: true,
            credential_id: Some(subject_credential.credential_id),
        }
    );
}

/// The three answers the contract makes one: revoked, expired, and resolving to no record.
#[test]
fn every_unusable_credential_is_one_inactive_answer_and_not_three() {
    let (log, caller, subject_credential) = deployment(RevocationGuarantee::ImmediateOnline);
    let held = Projection::fold(&log).expect("two issuances");
    let resolver = CachingResolver::over(held.clone());

    // A well-formed proof this deployment never issued.
    let unknown = introspect(
        &caller,
        &CredentialProof::from_bytes(b"a-proof-from-another-deployment".to_vec()),
        &held,
        &resolver,
        &request(),
    )
    .expect("a well-formed proof is an accepted answer, whatever it resolves to");
    assert!(!unknown.active);
    assert_eq!(unknown.descriptor, None);
    assert_eq!(unknown.credential_id, None);

    // A credential of the same registration issued a day earlier, whose own hour has passed
    // by the time the caller — whose credential has not — presents it. The instant is the
    // request's, so the two are decided against one clock.
    let mut allocator = SequentialAllocator::new();
    let mut secrets = CountingSecrets::new();
    for _ in 0..8 {
        let _ = secrets.next_secret();
        let _ = allocator.next_credential_id();
    }
    let stale = issue_reference_credential(
        &IssueReferenceCredential {
            context: context(organization(10), subject(0x54)),
            target: held
                .registered(&organization(10), &Audience::new("api-a"))
                .expect("the registration")
                .id,
            requested_scope: scope(),
        },
        &request_at("2026-09-18T00:00:00Z"),
        &held,
        ReferenceParts {
            digest: &Sha256Digest,
            secrets: &mut secrets,
            allocator: &mut allocator,
        },
    )
    .expect("a registered, enabled target of the caller's organization");
    let stale_proof = CredentialProof::from_bytes(stale.credential.expose_material().to_vec());
    let mut with_stale = log.clone();
    with_stale.push(stale.event);
    let held_with_stale = Projection::fold(&with_stale).expect("a third issuance");
    let stale_resolver = CachingResolver::over(held_with_stale.clone());

    let expired = introspect(
        &caller,
        &stale_proof,
        &held_with_stale,
        &stale_resolver,
        &request(),
    )
    .expect("an expired credential is an accepted answer");
    assert!(!expired.active);
    assert_eq!(expired.descriptor, None);
    assert_eq!(expired.credential_id, None);

    // And revoked, which the acceptance case decides in full.
    let mut log = log;
    log.push(
        revoke_access_credential(
            &RevokeAccessCredential {
                id: subject_credential.credential_id,
                context: context(organization(10), subject(0x51)),
            },
            &held,
        )
        .expect("an active credential of the caller's own organization"),
    );
    let held = Projection::fold(&log).expect("the revocation");
    let resolver = CachingResolver::over(held.clone());
    let revoked = introspect(
        &caller,
        &subject_credential.proof,
        &held,
        &resolver,
        &request(),
    )
    .expect("a revoked credential is an accepted answer");
    assert!(!revoked.active);

    // One answer, not three: nothing in the three distinguishes them.
    assert_eq!(unknown.active, expired.active);
    assert_eq!(unknown.descriptor, revoked.descriptor);
    assert_eq!(unknown.credential_id, revoked.credential_id);
}

/// `reference-audience`: a credential issued for one audience, presented to another, is a
/// denial and not an inactive answer.
#[test]
fn a_credential_for_another_audience_is_refused() {
    let mut allocator = SequentialAllocator::new();
    let mut secrets = CountingSecrets::new();
    let first = issued_for(
        organization(10),
        "api-a",
        subject(0x51),
        RevocationGuarantee::ImmediateOnline,
        &Projection::default(),
        &mut allocator,
        &mut secrets,
    );
    let held = Projection::fold(&first.log).expect("one registration and one issuance");
    let second = issued_for(
        organization(10),
        "api-b",
        subject(0x53),
        RevocationGuarantee::ImmediateOnline,
        &held,
        &mut allocator,
        &mut secrets,
    );
    let mut log = first.log;
    log.extend(second.log);
    let held = Projection::fold(&log).expect("two registrations and two issuances");
    let resolver = CachingResolver::over(held.clone());

    // The caller speaks for `api-b`; the credential presented names `api-a`.
    let denied = introspect(&second.proof, &first.proof, &held, &resolver, &request())
        .expect_err("the presented credential names another audience");

    assert_eq!(denied.reason, DenialReason::AudienceMismatch);
    assert_eq!(denied.clause, DenialClause::AudienceMismatch);
    assert_eq!(denied.outcome, RefusedOutcome::Denied);
}

#[test]
fn a_malformed_presented_proof_is_refused() {
    let (log, caller, _) = deployment(RevocationGuarantee::ImmediateOnline);
    let held = Projection::fold(&log).expect("two issuances");
    let resolver = CachingResolver::over(held.clone());

    let denied = introspect(
        &caller,
        &CredentialProof::from_bytes(Vec::new()),
        &held,
        &resolver,
        &request(),
    )
    .expect_err("a proof carrying no material is malformed");

    assert_eq!(denied.clause, DenialClause::ProofMalformed);
    assert_eq!(denied.outcome, RefusedOutcome::Denied);
}

/// "Caller proof ... is itself invalid, revoked or expired": three refusals, and none of
/// them is an inactive answer about the credential the caller asked about.
#[test]
fn a_caller_whose_own_proof_is_unusable_is_refused() {
    let (log, caller, subject_credential) = deployment(RevocationGuarantee::ImmediateOnline);
    let held = Projection::fold(&log).expect("two issuances");
    let resolver = CachingResolver::over(held.clone());

    for (caller_proof, at) in [
        // Invalid: a proof this deployment never issued.
        (
            CredentialProof::from_bytes(b"not-a-credential".to_vec()),
            request(),
        ),
        // Malformed, which is the same refusal on the caller's side.
        (CredentialProof::from_bytes(Vec::new()), request()),
        // Expired: the caller's own credential, after its hour.
        (caller.clone(), request_at("2026-09-19T01:00:01Z")),
    ] {
        let denied = introspect(
            &caller_proof,
            &subject_credential.proof,
            &held,
            &resolver,
            &at,
        )
        .expect_err("the caller's own proof is not usable");
        assert_eq!(denied.clause, DenialClause::CallerProofInvalid);
        assert_eq!(denied.reason, DenialReason::InvalidCredential);
    }

    // Revoked: the caller's own credential, after it was revoked.
    let caller_id = held
        .resolve(&verifier_for(&Sha256Digest, &caller))
        .expect("the fold is authoritative")
        .expect("the caller's own credential")
        .id;
    let mut log = log;
    log.push(
        revoke_access_credential(
            &RevokeAccessCredential {
                id: caller_id,
                context: context(organization(10), subject(0x51)),
            },
            &held,
        )
        .expect("an active credential of the caller's own organization"),
    );
    let held = Projection::fold(&log).expect("the revocation");
    let resolver = CachingResolver::over(held.clone());

    let denied = introspect(
        &caller,
        &subject_credential.proof,
        &held,
        &resolver,
        &request(),
    )
    .expect_err("the caller's own credential is revoked");
    assert_eq!(denied.clause, DenialClause::CallerProofInvalid);
}

/// A caller whose own registration was disabled keeps authority over **its own**
/// credentials: they are the ones presented to it before the handover, and it is the
/// registration that issued them.
///
/// The answer is the inactive one — the presented credential's issuing registration is
/// disabled too — and that is the point: a refusal here would tell the caller less than the
/// accepted answer does, and `credential.yaml`'s summary says a caller "learns only whether
/// it is usable".
#[test]
fn a_caller_whose_registration_is_disabled_keeps_authority_over_its_own_credentials() {
    let (log, caller, subject_credential) = deployment(RevocationGuarantee::ImmediateOnline);
    let held = Projection::fold(&log).expect("two issuances");
    let target = held
        .registered(&organization(10), &Audience::new("api-a"))
        .expect("the registration")
        .id;
    let mut log = log;
    log.push(CredentialEvent::ResourceServerDisabled {
        context: context(organization(10), subject(0x51)),
        id: target,
    });
    let held = Projection::fold(&log).expect("the disablement");
    let resolver = CachingResolver::over(held.clone());

    let answer = introspect(
        &caller,
        &subject_credential.proof,
        &held,
        &resolver,
        &request(),
    )
    .expect("a caller's own registration's credentials are its own to introspect");

    assert!(
        !answer.active,
        "the presented credential's registration is disabled, so it is not usable"
    );
    assert_eq!(answer.descriptor, None);
    assert_eq!(answer.credential_id, None);
}

/// **"Caller proof lacks introspection authority for the registered server/tenant."**
///
/// The direction that leaks: a caller whose registration was disabled and whose audience has
/// been taken over, asking about a credential of the *successor's* registration. It is
/// refused, where a credential of its own registration is answered for.
#[test]
fn a_caller_has_no_authority_over_the_registration_that_took_its_audience() {
    let (log, caller, _) = deployment(RevocationGuarantee::ImmediateOnline);
    let held = Projection::fold(&log).expect("two issuances");
    let first = held
        .registered(&organization(10), &Audience::new("api-a"))
        .expect("the registration")
        .id;
    let mut log = log;
    log.push(CredentialEvent::ResourceServerDisabled {
        context: context(organization(10), subject(0x51)),
        id: first,
    });
    let held = Projection::fold(&log).expect("the disablement");

    // The audience changes hands, and the successor issues a credential of its own.
    let mut allocator = SequentialAllocator::new();
    let mut secrets = CountingSecrets::new();
    for _ in 0..8 {
        let _ = allocator.next_resource_server_id();
        let _ = allocator.next_credential_id();
        let _ = secrets.next_secret();
    }
    let second = register_resource_server(
        &RegisterResourceServer {
            context: context(organization(10), subject(0x51)),
            audience: Audience::new("api-a"),
            profile: profile(RevocationGuarantee::ImmediateOnline),
            allowed_exchange_sources: Vec::new(),
        },
        &held,
        &mut allocator,
    )
    .expect("the audience is free again");
    log.push(second.event);
    let held = Projection::fold(&log).expect("the second registration");
    let successors = issue_reference_credential(
        &IssueReferenceCredential {
            context: context(organization(10), subject(0x54)),
            target: second.resource_server_id,
            requested_scope: scope(),
        },
        &request(),
        &held,
        ReferenceParts {
            digest: &Sha256Digest,
            secrets: &mut secrets,
            allocator: &mut allocator,
        },
    )
    .expect("a registered, enabled target of the caller's organization");
    let presented = CredentialProof::from_bytes(successors.credential.expose_material().to_vec());
    log.push(successors.event);
    let held = Projection::fold(&log).expect("the successor's issuance");
    let resolver = CachingResolver::over(held.clone());

    let denied = introspect(&caller, &presented, &held, &resolver, &request())
        .expect_err("the caller's registration no longer holds the audience");

    assert_eq!(denied.clause, DenialClause::IntrospectionAuthority);
    assert_eq!(denied.outcome, RefusedOutcome::Denied);
}

#[test]
fn an_unavailable_authoritative_resolution_is_refused_and_not_answered() {
    let (log, caller, subject_credential) = deployment(RevocationGuarantee::ImmediateOnline);
    let held = Projection::fold(&log).expect("two issuances");
    // The caller's own proof still resolves; what is unreachable is the resolution of the
    // presented credential, which is the clause the contract names.
    let resolver = CachingResolver::over(held.clone()).unavailable();

    let denied = introspect(
        &caller,
        &subject_credential.proof,
        &held,
        &resolver,
        &request(),
    )
    .expect_err("authoritative online resolution is unavailable");

    assert_eq!(denied.reason, DenialReason::Unavailable);
    assert_eq!(denied.clause, DenialClause::ResolutionUnavailable);
}

/// The event this outcome emits "folds into no record": applying it leaves the projection
/// exactly as it was, whatever it says.
#[test]
fn an_accepted_introspection_emits_an_event_that_changes_nothing() {
    let (log, caller, subject_credential) = deployment(RevocationGuarantee::ImmediateOnline);
    let held = Projection::fold(&log).expect("two issuances");
    let resolver = CachingResolver::over(held.clone());

    let answer = introspect(
        &caller,
        &subject_credential.proof,
        &held,
        &resolver,
        &request(),
    )
    .expect("an authorized introspection");

    let mut log = log;
    log.push(answer.event);
    assert_eq!(
        Projection::fold(&log).expect("an introspection is readable against any log"),
        held
    );
}

#[test]
fn revocation_emits_the_declared_event_and_moves_the_record() {
    let (log, _, subject_credential) = deployment(RevocationGuarantee::ImmediateOnline);
    let held = Projection::fold(&log).expect("two issuances");

    let event = revoke_access_credential(
        &RevokeAccessCredential {
            id: subject_credential.credential_id,
            context: context(organization(10), subject(0x51)),
        },
        &held,
    )
    .expect("an active credential of the caller's own organization");

    assert_eq!(
        event,
        CredentialEvent::AccessCredentialRevoked {
            context: context(organization(10), subject(0x51)),
            id: subject_credential.credential_id,
        }
    );

    let mut log = log;
    log.push(event);
    assert_eq!(
        Projection::fold(&log)
            .expect("the revocation")
            .access_credential(&subject_credential.credential_id)
            .map(|record| record.state),
        Some(AccessCredentialState::Revoked)
    );
}

#[test]
fn revoking_a_credential_no_event_created_is_refused() {
    let denied = revoke_access_credential(
        &RevokeAccessCredential {
            id: CredentialId::new(uuid(0x99)),
            context: context(organization(10), subject(0x51)),
        },
        &Projection::default(),
    )
    .expect_err("no event issued it");

    assert_eq!(denied.clause, DenialClause::CredentialUnknown);
    assert_eq!(denied.outcome, RefusedOutcome::Denied);
}

#[test]
fn revoking_another_organizations_credential_is_refused() {
    let (log, _, subject_credential) = deployment(RevocationGuarantee::ImmediateOnline);
    let held = Projection::fold(&log).expect("two issuances");

    let denied = revoke_access_credential(
        &RevokeAccessCredential {
            id: subject_credential.credential_id,
            context: context(organization(11), subject(0x51)),
        },
        &held,
    )
    .expect_err("the credential is another organization's");

    assert_eq!(denied.reason, DenialReason::TenantMismatch);
    assert_eq!(denied.clause, DenialClause::OrganizationMismatch);
}

#[test]
fn revoking_an_already_revoked_credential_is_the_wrong_state_outcome() {
    let (log, _, subject_credential) = deployment(RevocationGuarantee::ImmediateOnline);
    let held = Projection::fold(&log).expect("two issuances");
    let mut log = log;
    log.push(
        revoke_access_credential(
            &RevokeAccessCredential {
                id: subject_credential.credential_id,
                context: context(organization(10), subject(0x51)),
            },
            &held,
        )
        .expect("the first revocation"),
    );
    let held = Projection::fold(&log).expect("the revocation");

    let denied = revoke_access_credential(
        &RevokeAccessCredential {
            id: subject_credential.credential_id,
            context: context(organization(10), subject(0x51)),
        },
        &held,
    )
    .expect_err("`revoke` starts from `Active` alone");

    assert_eq!(denied.outcome, RefusedOutcome::WrongState);
    assert_eq!(denied.clause, DenialClause::CredentialRevoked);
}

/// A deployment of one registration under a profile a case chose, with a caller credential
/// and one credential to introspect, driven through the real handlers.
fn deployment_under(
    profile: CredentialProfile,
) -> (
    Projection,
    CredentialProof,
    CredentialProof,
    AccessCredential,
) {
    let mut allocator = SequentialAllocator::new();
    let mut secrets = CountingSecrets::new();
    let registered = register_resource_server(
        &RegisterResourceServer {
            context: context(organization(10), subject(0x51)),
            audience: Audience::new("api-a"),
            profile,
            allowed_exchange_sources: Vec::new(),
        },
        &Projection::default(),
        &mut allocator,
    )
    .expect("a free audience in the caller's own organization");
    let mut log = vec![registered.event];

    let issue = |log: &mut Vec<CredentialEvent>,
                 who: PrincipalId,
                 allocator: &mut SequentialAllocator,
                 secrets: &mut CountingSecrets| {
        let held = Projection::fold(log).expect("a log of accepted events");
        let issued = issue_reference_credential(
            &IssueReferenceCredential {
                context: context(organization(10), who),
                target: registered.resource_server_id,
                requested_scope: scope(),
            },
            &request(),
            &held,
            ReferenceParts {
                digest: &Sha256Digest,
                secrets,
                allocator,
            },
        )
        .expect("a registered, enabled target of the caller's organization");
        let proof = CredentialProof::from_bytes(issued.credential.expose_material().to_vec());
        let id = issued.credential_id;
        log.push(issued.event);
        (proof, id)
    };
    let (caller, _) = issue(&mut log, subject(0x51), &mut allocator, &mut secrets);
    let (presented, id) = issue(&mut log, subject(0x52), &mut allocator, &mut secrets);

    let held = Projection::fold(&log).expect("two issuances");
    // The record as the deployment's cache took it: live, before the revocation.
    let cached = held
        .access_credential(&id)
        .expect("the credential the issuance created");
    log.push(
        revoke_access_credential(
            &RevokeAccessCredential {
                id,
                context: context(organization(10), subject(0x51)),
            },
            &held,
        )
        .expect("an active credential of the caller's own organization"),
    );
    (
        Projection::fold(&log).expect("the revocation"),
        caller,
        presented,
        cached,
    )
}

/// **A profile that requires online authorization never answers from a cache**, whatever its
/// revocation guarantee says.
///
/// `BoundedOffline` admits a cached positive answer; `requires_online_authorization: true`
/// withdraws it. The two fields are separate — a profile may require online authorization
/// without promising immediate revocation — and `mandate_token::CredentialProfile` says what
/// the second one means: "whether authorization must be resolved online". A deployment that
/// published it and then answered from a cache would be keeping a different rule from the one
/// it published.
#[test]
fn a_profile_that_requires_online_authorization_never_reads_the_cache() {
    let profile = CredentialProfile {
        requires_online_authorization: true,
        ..profile(RevocationGuarantee::BoundedOffline)
    };
    let (held, caller, presented, record) = deployment_under(profile);
    let resolver = CachingResolver::over(held.clone()).holding(
        verifier_for(&Sha256Digest, &presented),
        record,
        "2026-09-19T00:00:50Z",
    );

    let answer = introspect(
        &caller,
        &presented,
        &held,
        &resolver,
        &request_at("2026-09-19T00:01:00Z"),
    )
    .expect("an authorized introspection");

    assert!(
        !answer.active,
        "a cached answer authorized a revoked credential"
    );
    assert_eq!(
        resolver.consulted(),
        0,
        "the profile requires online authorization, so the cache is not even asked"
    );
}

/// **The bound, at its edges.** `positive_cache_ttl` is `PT30S`, so an answer aged exactly
/// 30 seconds is inside it (the documentation says the comparison is inclusive), an answer
/// aged nothing is inside it, and an answer from the future is not an answer whose age is
/// known.
#[test]
fn the_cache_bound_admits_its_own_edge_and_refuses_the_future() {
    let profile = profile(RevocationGuarantee::BoundedOffline);
    assert_eq!(profile.positive_cache_ttl, Duration::new("PT30S"));

    for (taken, admitted, what) in [
        ("2026-09-19T00:00:30Z", true, "aged exactly the bound"),
        ("2026-09-19T00:01:00Z", true, "aged nothing"),
        (
            "2026-09-19T00:00:29Z",
            false,
            "aged one second past the bound",
        ),
        ("2026-09-19T00:01:01Z", false, "taken one second from now"),
        ("2026-09-19T12:00:00Z", false, "taken hours from now"),
    ] {
        let (held, caller, presented, record) = deployment_under(profile.clone());
        let resolver = CachingResolver::over(held.clone()).holding(
            verifier_for(&Sha256Digest, &presented),
            record,
            taken,
        );

        let answer = introspect(
            &caller,
            &presented,
            &held,
            &resolver,
            &request_at("2026-09-19T00:01:00Z"),
        )
        .expect("an authorized introspection");

        assert_eq!(
            answer.active,
            admitted,
            "a cached answer {what} was {}",
            if answer.active { "used" } else { "refused" }
        );
        assert_eq!(
            resolver.consulted(),
            1,
            "the cache is asked in every one of these"
        );
    }
}
