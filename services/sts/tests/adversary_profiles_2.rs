//! Adversary pass 2 against `story:credential-profiles`, `resolve` unit.
//!
//! Correction 1 moved the *presented* credential's usability onto the registration it was
//! issued under: `AccessCredential::target` and `AccessCredential::issuing_profile` are kept
//! outside the wire form and `resolve::usable` reads both, so "a credential issued under a
//! registration this deployment disabled is not usable" is now decided from the record's own
//! target (`services/sts/src/registry.rs`, `disable_resource_server`).
//!
//! The *caller's* half of the same handler was not moved with it. `introspect_credential`
//! decides the caller's own proof by `resolve::live` alone — state and expiry — and then
//! grants introspection authority from `servers.registered(&caller.descriptor.organization,
//! &caller.descriptor.audience)`, which is whatever registration holds that audience **now**.
//! The two readings come apart on exactly the path `registry.rs` documents as ordinary: a
//! registration is disabled, it stops holding its audience, and the deployment registers that
//! audience again.
//!
//! `credential.yaml`'s `IntrospectCredential` denies a caller whose proof "lacks introspection
//! authority for the registered server/tenant **or is itself invalid, revoked or expired**".
//! A credential the same handler answers `active: false` for, in the same fold, is not a valid
//! caller proof by any reading of that clause — and `services/sts/src/registry.rs:219` is the
//! unit's own statement that such a credential "is not usable".
//!
//! The second case is the other side of `usable`'s audience test. It compares the record's
//! `target` against the registration that holds the audience today, which is the smallest
//! enabled identity on the key — and issuance (`issue::admitted_target`) never asks that
//! question at all. The two disagree for a registration that is enabled, is the one the
//! deployment handed the caller, and does not hold its key.

use mandate_sts::issue::{
    IssueReferenceCredential, ReferenceParts, Sha256Digest, issue_reference_credential,
};
use mandate_sts::registry::{
    DisableResourceServer, RegisterResourceServer, ResourceServerReads, disable_resource_server,
    register_resource_server,
};
use mandate_sts::resolve::{
    CredentialResolution, IntrospectCredential, IntrospectionParts, introspect_credential,
};
use mandate_sts::{
    CountingSecrets, IdentityAllocator, RequestContext, SecretSource, SequentialAllocator,
};
use mandate_token::CredentialProfile;
use mandate_token::projection::{CredentialEvent, DenialClause, Projection};
use mandate_types::{
    Audience, AuthorityScope, AuthorizationCodeId, CorrelationId, CredentialId, CredentialKind,
    CredentialProof, Duration, OrganizationId, PrincipalId, ResourceServerId, RevocationGuarantee,
    SigningKeyId, Timestamp, Transient, Uuid, VerifiedContext,
};

fn tagged(prefix: u8, ordinal: u8) -> Uuid {
    Uuid::from_bytes([
        prefix, ordinal, 0x28, 0xba, 0x2f, 0xa1, 0x4d, 0x8e, 0xb1, 0xb0, 0x8c, 0x1d, 0x4e, 0x5f,
        0x6a, 0x7b,
    ])
}

fn organization() -> OrganizationId {
    OrganizationId::new(tagged(0x0a, 0))
}

fn subject(ordinal: u8) -> PrincipalId {
    PrincipalId::new(tagged(0x51, ordinal))
}

fn context(principal: PrincipalId) -> VerifiedContext {
    VerifiedContext {
        subject: principal,
        actor: None,
        organization: organization(),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(tagged(0xcd, 0)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("adversary-profiles-2"),
    }
}

fn request() -> RequestContext {
    RequestContext {
        correlation: CorrelationId::new("adversary-profiles-2"),
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

fn profile() -> CredentialProfile {
    CredentialProfile {
        name: "reference".to_owned(),
        kind: CredentialKind::Reference,
        revocation: RevocationGuarantee::ImmediateOnline,
        max_ttl: Duration::new("PT1H"),
        positive_cache_ttl: Duration::new("PT30S"),
        requires_online_authorization: true,
    }
}

fn registration(principal: PrincipalId, audience: &str) -> RegisterResourceServer {
    RegisterResourceServer {
        context: context(principal),
        audience: Audience::new(audience),
        profile: profile(),
        allowed_exchange_sources: Vec::new(),
    }
}

/// One issuance through the real handler: the material the holder received and the identity.
struct Issued {
    event: CredentialEvent,
    proof: CredentialProof,
    credential_id: CredentialId,
}

fn issue(
    target: ResourceServerId,
    principal: PrincipalId,
    held: &Projection,
    allocator: &mut impl IdentityAllocator,
    secrets: &mut impl SecretSource,
) -> Issued {
    let issued = issue_reference_credential(
        &IssueReferenceCredential {
            context: context(principal),
            target,
            requested_scope: scope(),
        },
        &request(),
        held,
        ReferenceParts {
            digest: &Sha256Digest,
            secrets,
            allocator,
        },
    )
    .expect("a registered, enabled target of the caller's own organization");
    Issued {
        proof: CredentialProof::from_bytes(issued.credential.expose_material().to_vec()),
        credential_id: issued.credential_id,
        event: issued.event,
    }
}

fn introspect(
    caller: &CredentialProof,
    presented: &CredentialProof,
    held: &Projection,
    resolution: &impl CredentialResolution,
) -> Result<mandate_sts::resolve::CredentialIntrospection, mandate_token::projection::Denied> {
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

/// What a disablement and a re-registration of one audience leaves standing.
struct Succession {
    log: Vec<CredentialEvent>,
    /// A credential issued under the registration that was then disabled.
    old: Issued,
    /// A credential issued under the registration that took the audience over.
    fresh: Issued,
    disabled: ResourceServerId,
    successor: ResourceServerId,
}

/// The path `services/sts/src/registry.rs` documents as ordinary, driven through the real
/// handlers alone: register, issue, disable, register the same audience again, issue.
fn succession() -> Succession {
    let mut allocator = SequentialAllocator::new();
    let mut secrets = CountingSecrets::new();

    let first = register_resource_server(
        &registration(subject(0x51), "api-a"),
        &Projection::default(),
        &mut allocator,
    )
    .expect("a free audience in the caller's own organization");
    let mut log = vec![first.event];

    let held = Projection::fold(&log).expect("one registration");
    let old = issue(
        first.resource_server_id,
        subject(0x51),
        &held,
        &mut allocator,
        &mut secrets,
    );
    log.push(old.event.clone());

    let held = Projection::fold(&log).expect("one registration and one issuance");
    log.push(
        disable_resource_server(
            &DisableResourceServer {
                id: first.resource_server_id,
                context: context(subject(0x51)),
            },
            &held,
        )
        .expect("an enabled registration of the caller's own organization"),
    );

    let held = Projection::fold(&log).expect("the disablement");
    let second =
        register_resource_server(&registration(subject(0x51), "api-a"), &held, &mut allocator)
            .expect("a disabled registration holds no audience, so the audience is free again");
    log.push(second.event);

    let held = Projection::fold(&log).expect("the second registration");
    let fresh = issue(
        second.resource_server_id,
        subject(0x52),
        &held,
        &mut allocator,
        &mut secrets,
    );
    log.push(fresh.event.clone());

    Succession {
        log,
        old,
        fresh,
        disabled: first.resource_server_id,
        successor: second.resource_server_id,
    }
}

/// The premise, and it holds: the deployment answers that the old credential is unusable.
///
/// `usable` reads the record's own `target`, finds the registration disabled, and answers
/// `active: false` with no descriptor — which is what correction 1 landed and what
/// `registry.rs:219` promises.
#[test]
fn the_handler_reports_the_disabled_registrations_credential_unusable() {
    let succession = succession();
    let held = Projection::fold(&succession.log).expect("the whole log");
    assert_eq!(held.is_enabled(&succession.disabled), Some(false));

    let answer = introspect(&succession.fresh.proof, &succession.old.proof, &held, &held)
        .expect("an authorized introspection is accepted");

    assert!(!answer.active);
    assert_eq!(answer.descriptor, None);
    assert_eq!(answer.credential_id, None);
}

/// **The same credential, used as the caller proof, is accepted — and reads the successor's.**
///
/// Nothing about the old credential changed between this case and the one above: the same
/// fold, the same instant, the same record whose issuing registration is disabled. Swapping
/// which side of `IntrospectCredential` it appears on turns "unusable" into "authorized",
/// because the caller's half is decided by `resolve::live` and by whichever registration
/// holds the audience now, and neither reads `AccessCredential::target`.
///
/// What it buys the holder of a resource server the operator shut down: the full
/// `mandate.core.CredentialDescriptor` of the credentials of the resource server that took
/// its audience over — subject, actor, scope, delegation, execution and expiry — plus the
/// `credential_id` it would need to name one in `RevokeAccessCredential`.
#[test]
fn a_disabled_registrations_credential_is_still_accepted_as_the_caller_proof() {
    let succession = succession();
    let held = Projection::fold(&succession.log).expect("the whole log");
    assert_eq!(held.is_enabled(&succession.disabled), Some(false));
    assert_eq!(
        held.access_credential(&succession.old.credential_id)
            .map(|record| record.target),
        Some(succession.disabled),
        "the caller's own credential was issued under the registration that is now disabled"
    );
    assert_eq!(
        held.registered(&organization(), &Audience::new("api-a"))
            .map(|holder| holder.id),
        Some(succession.successor)
    );

    let denied = introspect(&succession.old.proof, &succession.fresh.proof, &held, &held)
        .expect_err(
            "the credential of a disabled registration — the one this same handler answers \
         `active: false` for — was accepted as the caller proof and answered with the \
         successor registration's credential",
        );

    assert!(
        matches!(
            denied.clause,
            DenialClause::IntrospectionAuthority | DenialClause::CallerProofInvalid
        ),
        "refused for {:?}, which is neither caller clause",
        denied.clause
    );
}

/// An allocator that hands out resource-server identities a case chose, so two concurrent
/// registrations can be given the order `Projection::registered` decides on.
///
/// Credential, signing-key and authorization-code identities come from the ordinary
/// fixture, so two issuances are two credentials.
struct ChosenServers {
    servers: Vec<ResourceServerId>,
    rest: SequentialAllocator,
}

impl IdentityAllocator for ChosenServers {
    fn next_resource_server_id(&mut self) -> ResourceServerId {
        self.servers.remove(0)
    }

    fn next_credential_id(&mut self) -> CredentialId {
        self.rest.next_credential_id()
    }

    fn next_signing_key_id(&mut self) -> SigningKeyId {
        self.rest.next_signing_key_id()
    }

    fn next_authorization_code_id(&mut self) -> AuthorizationCodeId {
        self.rest.next_authorization_code_id()
    }

    fn reserve_credential_id(&mut self) -> CredentialId {
        self.rest.reserve_credential_id()
    }

    fn commit_credential_id(&mut self, reserved: CredentialId) {
        self.rest.commit_credential_id(reserved);
    }

    fn release_credential_id(&mut self, reserved: CredentialId) {
        self.rest.release_credential_id(reserved);
    }
}

/// **Issuance accepts for a registration whose credentials introspect inactive at once.**
///
/// The two registrations are the pair `crates/mandate-token/src/projection.rs` documents:
/// two writers that each read a free `(organization_id, audience)` and each append to their
/// own aggregate, so neither compare-and-set sees the other and "the log is the record of
/// both registrations". `Projection::registered` resolves the key to the smaller identity;
/// the other is reported by `audience_conflicts` and is still `Enabled`.
///
/// `issue::admitted_target` never asks whether the target holds its audience — it asks for
/// the record, the organization, the state and the family — so an issuance against the
/// registration that lost the key is accepted, a secret is minted and handed out, and the
/// event is emitted. `resolve::usable` then asks exactly that question and answers
/// `active: false` for the credential, at the same instant, with nothing having been revoked
/// and nothing having expired.
///
/// One of the two has to move: either the issuance is refused under
/// "target/profile is unregistered/disabled/outside tenant", or the credential it accepted
/// is usable. Shipping both is a deployment that mints credentials its own introspection
/// reports dead.
#[test]
fn a_credential_the_deployment_just_issued_is_reported_unusable_at_once() {
    let mut allocator = ChosenServers {
        // The second writer's identity sorts first, so it is the one that holds the key.
        servers: vec![
            ResourceServerId::new(tagged(0x40, 2)),
            ResourceServerId::new(tagged(0x40, 1)),
        ],
        rest: SequentialAllocator::new(),
    };
    let mut secrets = CountingSecrets::new();

    // Two concurrent `RegisterResourceServer`, each deciding against a state without the
    // other's append.
    let loser = register_resource_server(
        &registration(subject(0x51), "api-a"),
        &Projection::default(),
        &mut allocator,
    )
    .expect("a free audience in the caller's own organization");
    let holder = register_resource_server(
        &registration(subject(0x51), "api-a"),
        &Projection::default(),
        &mut allocator,
    )
    .expect("the same free audience, read by a writer that did not see the first append");

    let mut log = vec![loser.event, holder.event];
    let held = Projection::fold(&log).expect("the log is the record of both registrations");
    assert_eq!(
        held.registered(&organization(), &Audience::new("api-a"))
            .map(|server| server.id),
        Some(holder.resource_server_id)
    );
    assert_eq!(
        held.audience_conflicts()
            .iter()
            .map(|conflict| conflict.id)
            .collect::<Vec<_>>(),
        vec![loser.resource_server_id],
        "the registration that lost the key is enabled and recorded"
    );
    assert_eq!(held.is_enabled(&loser.resource_server_id), Some(true));

    // The deployment issues against the identity it handed that caller back.
    let presented = issue(
        loser.resource_server_id,
        subject(0x52),
        &held,
        &mut allocator,
        &mut secrets,
    );
    log.push(presented.event.clone());

    // The caller speaks for the registration that does hold the audience, so nothing about
    // the caller's own half is in question here.
    let held = Projection::fold(&log).expect("one issuance");
    let caller = issue(
        holder.resource_server_id,
        subject(0x53),
        &held,
        &mut allocator,
        &mut secrets,
    );
    log.push(caller.event.clone());
    let held = Projection::fold(&log).expect("two issuances");

    let answer = introspect(&caller.proof, &presented.proof, &held, &held)
        .expect("an authorized introspection is accepted");

    assert!(
        answer.active,
        "the issuance was accepted and a secret handed out, and the credential it created \
         is reported unusable by the same deployment at the same instant: nothing revoked \
         it and nothing expired"
    );
    assert_eq!(answer.credential_id, Some(presented.credential_id));
}
