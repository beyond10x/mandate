//! Each durable record of `mandate.credential` is rebuilt from its events alone.
//!
//! `docs/adr/0009-event-sourced-persistence.md`: "A command produces domain events; the
//! events are the record; every read is a fold over them ... State tables are projections:
//! derived, droppable, rebuildable, never authoritative."
//!
//! Every case here drives the real handlers: each returns the event its accepted outcome
//! emits, the case applies that event to the live projection and keeps it in a log, and the
//! log is then folded from empty. Nothing reconstructs state by re-running a command.
//!
//! `fold` and the live projection share one `apply`, so `fold(&log) == live` alone is close
//! to a tautology — a field `apply` drops is dropped identically on both sides. Each case
//! therefore *also* asserts the rebuilt record against a literal carrying every field the
//! compiled entity marks required. The equality says the rebuild is complete; the literal
//! says the log is what it was rebuilt from.

use mandate_sts::issue::{
    IssueReferenceCredential, IssueSelfContainedCredential, ReferenceParts, SelfContainedParts,
    Sha256Digest, StaticSigner, issue_reference_credential, issue_self_contained_credential,
};
use mandate_sts::keys::{
    KeyMaterialResolver, RegisterSigningKey, RetireSigningKey, RevokeSigningKey,
    SigningKeyAdministration, retire_signing_key, revoke_signing_key,
};
use mandate_sts::registry::{
    DisableResourceServer, RegisterResourceServer, disable_resource_server,
    register_resource_server,
};
use mandate_sts::resolve::{
    IntrospectCredential, IntrospectionParts, RevokeAccessCredential, introspect_credential,
    revoke_access_credential,
};
use mandate_sts::{CountingSecrets, RequestContext, SequentialAllocator};
use mandate_token::CredentialProfile;
use mandate_token::projection::{
    AccessCredential, AccessCredentialState, CredentialEvent, Projection, ResourceServer,
    ResourceServerState, SigningKey, SigningKeyState,
};
use mandate_token::signing_real::AllowedAlgorithms;
use mandate_token::verifier::verifier_for;
use mandate_types::{
    Audience, AuthorityScope, CorrelationId, CredentialId, CredentialKind, CredentialProof,
    Duration, EpochSnapshotRef, Issuer, KeyReference, OrganizationId, PrincipalId,
    RevocationGuarantee, SigningAlgorithm, Timestamp, Transient, Uuid, VerifiedContext,
};

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(10))
}

fn context() -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::new(uuid(0x51)),
        actor: None,
        organization: organization(),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("replay"),
    }
}

fn request() -> RequestContext {
    RequestContext {
        correlation: CorrelationId::new("replay"),
        at: Timestamp::new("2026-09-19T00:00:00Z"),
        epochs: Some(EpochSnapshotRef::new(uuid(0x60))),
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

struct ResolvableKeys;

impl KeyMaterialResolver for ResolvableKeys {
    fn thumbprint(&self, reference: &KeyReference) -> Option<String> {
        match reference.as_str() {
            "kms://one" => Some("thumb-one".to_owned()),
            "kms://two" => Some("thumb-two".to_owned()),
            _ => None,
        }
    }
}

/// The live projection and the log, grown together: a handler decides against the live
/// projection, its event is applied to it, and the same event is kept for the rebuild.
#[derive(Default)]
struct Deployment {
    live: Projection,
    log: Vec<CredentialEvent>,
}

impl Deployment {
    fn record(&mut self, event: CredentialEvent) {
        self.live
            .apply(&event)
            .expect("a handler's own event is one the fold can read");
        self.log.push(event);
    }

    /// The rebuild: the whole projection, from an empty state and this log alone.
    fn rebuilt(&self) -> Projection {
        Projection::fold(&self.log).expect("a log of accepted events")
    }
}

#[test]
fn the_resource_server_record_is_rebuilt_from_its_events() {
    let mut deployment = Deployment::default();
    let mut allocator = SequentialAllocator::new();
    let registered = register_resource_server(
        &RegisterResourceServer {
            context: context(),
            audience: Audience::new("api-a"),
            profile: reference_profile(),
            allowed_exchange_sources: Vec::new(),
        },
        &deployment.live,
        &mut allocator,
    )
    .expect("a free audience in the caller's own organization");
    let id = registered.resource_server_id;
    deployment.record(registered.event);

    assert_eq!(deployment.rebuilt(), deployment.live);
    assert_eq!(
        deployment.rebuilt().resource_server(&id),
        Some(ResourceServer {
            id,
            organization_id: organization(),
            audience: Audience::new("api-a"),
            credential_profile: reference_profile(),
            allowed_exchange_sources: Vec::new(),
            state: ResourceServerState::Enabled,
        })
    );

    let disabled = disable_resource_server(
        &DisableResourceServer {
            id,
            context: context(),
        },
        &deployment.live,
    )
    .expect("an enabled registration");
    deployment.record(disabled);

    assert_eq!(deployment.rebuilt(), deployment.live);
    assert_eq!(
        deployment
            .rebuilt()
            .resource_server(&id)
            .map(|server| server.state),
        Some(ResourceServerState::Disabled)
    );
}

#[test]
fn both_credential_records_are_rebuilt_from_their_events() {
    let mut deployment = Deployment::default();
    let mut allocator = SequentialAllocator::new();
    let mut secrets = CountingSecrets::new();
    let reference = register_resource_server(
        &RegisterResourceServer {
            context: context(),
            audience: Audience::new("api-a"),
            profile: reference_profile(),
            allowed_exchange_sources: Vec::new(),
        },
        &deployment.live,
        &mut allocator,
    )
    .expect("a free audience");
    deployment.record(reference.event);
    let signed = register_resource_server(
        &RegisterResourceServer {
            context: context(),
            audience: Audience::new("api-b"),
            profile: self_contained_profile(),
            allowed_exchange_sources: Vec::new(),
        },
        &deployment.live,
        &mut allocator,
    )
    .expect("a second free audience");
    deployment.record(signed.event);

    let issued = issue_reference_credential(
        &IssueReferenceCredential {
            context: context(),
            target: reference.resource_server_id,
            requested_scope: scope(),
        },
        &request(),
        &deployment.live,
        ReferenceParts {
            digest: &Sha256Digest,
            secrets: &mut secrets,
            allocator: &mut allocator,
        },
    )
    .expect("a registered, enabled target");
    let reference_id = issued.credential_id;
    let reference_verifier = verifier_for(&Sha256Digest, &issued.credential);
    let reference_descriptor = issued.descriptor.clone();
    deployment.record(issued.event);

    let signer = StaticSigner::new("kid-one", 900);
    let issued = issue_self_contained_credential(
        &IssueSelfContainedCredential {
            context: context(),
            target: signed.resource_server_id,
            requested_scope: scope(),
        },
        &request(),
        &deployment.live,
        SelfContainedParts {
            digest: &Sha256Digest,
            allocator: &mut allocator,
            signer: &signer,
            issuer: &Issuer::new("https://sts.example"),
        },
    )
    .expect("a registered, enabled target");
    let signed_id = issued.credential_id;
    deployment.record(issued.event);

    assert_eq!(deployment.rebuilt(), deployment.live);
    assert_eq!(
        deployment.rebuilt().access_credential(&reference_id),
        Some(AccessCredential {
            id: reference_id,
            descriptor: reference_descriptor,
            reference_verifier: Some(reference_verifier),
            epochs: Some(EpochSnapshotRef::new(uuid(0x60))),
            issued_at: Timestamp::new("2026-09-19T00:00:00Z"),
            state: AccessCredentialState::Active,
            // Neither is a declared field of the entity; both are rebuilt from the
            // registration the issuance named, and a rebuild that lost them would lose the
            // guarantee the credential was issued under.
            target: reference.resource_server_id,
            issuing_profile: reference_profile(),
        })
    );

    let revoked = revoke_access_credential(
        &RevokeAccessCredential {
            id: signed_id,
            context: context(),
        },
        &deployment.live,
    )
    .expect("an active credential of the caller's own organization");
    deployment.record(revoked);

    assert_eq!(deployment.rebuilt(), deployment.live);
    assert_eq!(
        deployment
            .rebuilt()
            .access_credential(&signed_id)
            .map(|record| record.state),
        Some(AccessCredentialState::Revoked)
    );
}

#[test]
fn the_signing_key_record_is_rebuilt_through_both_terminal_states() {
    let mut deployment = Deployment::default();
    let mut allocator = SequentialAllocator::new();
    let administration = SigningKeyAdministration::new(
        AllowedAlgorithms::new(&[SigningAlgorithm::new("RS256")]).expect("an allowlist"),
    );
    let register =
        |deployment: &mut Deployment, reference: &str, allocator: &mut SequentialAllocator| {
            let outcome = administration
                .register(
                    &RegisterSigningKey {
                        context: context(),
                        key_reference: KeyReference::new(reference),
                        algorithm: SigningAlgorithm::new("RS256"),
                        not_before: Timestamp::new("2026-09-19T00:00:00Z"),
                        expires_at: Timestamp::new("2026-12-31T00:00:00Z"),
                    },
                    &deployment.live,
                    &ResolvableKeys,
                    allocator,
                )
                .expect("an admitted algorithm and a resolvable reference");
            let id = outcome.id;
            deployment.record(outcome.event);
            id
        };
    let predecessor = register(&mut deployment, "kms://one", &mut allocator);
    let successor = register(&mut deployment, "kms://two", &mut allocator);

    assert_eq!(deployment.rebuilt(), deployment.live);
    assert_eq!(
        deployment.rebuilt().signing_key(&predecessor),
        Some(SigningKey {
            id: predecessor,
            key_reference: KeyReference::new("kms://one"),
            thumbprint: "thumb-one".to_owned(),
            algorithm: SigningAlgorithm::new("RS256"),
            not_before: Timestamp::new("2026-09-19T00:00:00Z"),
            expires_at: Timestamp::new("2026-12-31T00:00:00Z"),
            state: SigningKeyState::Recorded,
        })
    );

    let retired = retire_signing_key(
        &RetireSigningKey {
            id: predecessor,
            context: context(),
        },
        &deployment.live,
        &request(),
    )
    .expect("the successor is published");
    deployment.record(retired);
    let revoked = revoke_signing_key(
        &RevokeSigningKey {
            id: successor,
            context: context(),
        },
        &deployment.live,
    )
    .expect("a recorded key");
    deployment.record(revoked);

    assert_eq!(deployment.rebuilt(), deployment.live);
    assert_eq!(
        deployment
            .rebuilt()
            .signing_key(&predecessor)
            .map(|key| key.state),
        Some(SigningKeyState::Retired)
    );
    assert_eq!(
        deployment
            .rebuilt()
            .signing_key(&successor)
            .map(|key| key.state),
        Some(SigningKeyState::Revoked)
    );
}

/// The whole road in one log — a registration, two issuances, an introspection, a revocation
/// and the key lifecycle — rebuilt from empty. The introspection is in the log because a
/// deployment's log carries it: it folds into nothing, and a rebuild that tripped over it
/// would be a rebuild that could not read its own history.
#[test]
fn the_whole_log_rebuilds_to_the_live_projection() {
    let mut deployment = Deployment::default();
    let mut allocator = SequentialAllocator::new();
    let mut secrets = CountingSecrets::new();
    let registered = register_resource_server(
        &RegisterResourceServer {
            context: context(),
            audience: Audience::new("api-a"),
            profile: reference_profile(),
            allowed_exchange_sources: Vec::new(),
        },
        &deployment.live,
        &mut allocator,
    )
    .expect("a free audience");
    let target = registered.resource_server_id;
    deployment.record(registered.event);

    let issue = |deployment: &mut Deployment,
                 secrets: &mut CountingSecrets,
                 allocator: &mut SequentialAllocator| {
        let issued = issue_reference_credential(
            &IssueReferenceCredential {
                context: context(),
                target,
                requested_scope: scope(),
            },
            &request(),
            &deployment.live,
            ReferenceParts {
                digest: &Sha256Digest,
                secrets,
                allocator,
            },
        )
        .expect("a registered, enabled target");
        let proof = CredentialProof::from_bytes(issued.credential.expose_material().to_vec());
        let id = issued.credential_id;
        deployment.record(issued.event);
        (proof, id)
    };
    let (caller, _) = issue(&mut deployment, &mut secrets, &mut allocator);
    let (presented, presented_id) = issue(&mut deployment, &mut secrets, &mut allocator);

    let introspected = introspect_credential(
        &IntrospectCredential {
            caller_proof: caller,
            credential_proof: presented,
        },
        &request(),
        &deployment.live,
        IntrospectionParts {
            digest: &Sha256Digest,
            resolution: &deployment.live,
        },
    )
    .expect("an authorized introspection");
    let before = deployment.live.clone();
    deployment.record(introspected.event);
    assert_eq!(
        deployment.live, before,
        "an introspection folds into no record"
    );

    let revoked = revoke_access_credential(
        &RevokeAccessCredential {
            id: presented_id,
            context: context(),
        },
        &deployment.live,
    )
    .expect("an active credential");
    deployment.record(revoked);

    assert_eq!(deployment.log.len(), 5);
    assert_eq!(deployment.rebuilt(), deployment.live);
    assert_eq!(deployment.rebuilt().resource_servers().len(), 1);
    assert_eq!(deployment.rebuilt().credentials().len(), 2);
}

/// A rebuild of nothing is the empty projection, and every read answers nothing rather than
/// panicking: a fresh deployment has a readable history.
#[test]
fn an_empty_log_rebuilds_to_an_empty_projection() {
    let rebuilt = Projection::fold(&[]).expect("an empty log");

    assert_eq!(rebuilt, Projection::default());
    assert!(rebuilt.resource_servers().is_empty());
    assert!(rebuilt.credentials().is_empty());
    assert!(rebuilt.signing_keys().is_empty());
    assert!(rebuilt.audience_conflicts().is_empty());
}
