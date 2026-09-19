//! The four linking cases of `tests/security/cases.json` that name
//! `story:federation-linking`: `issuer-isolation`, `email-isolation`, `explicit-link`
//! and `link-conflict`. Each test is named for the case it executes.
//!
//! Each case names `mandate.federation.LinkExternalPrincipal` and
//! `mandate.federation.AuthenticateFederation`, so each test drives both.

use mandate_federation::authenticate::{
    AuthenticateFederation, Authenticated, authenticate_federation,
};
use mandate_federation::link::{LinkExternalPrincipal, Linked, link_external_principal};
use mandate_federation::record::{
    ExternalKey, ExternalPrincipal, FederationEvent, LinkState, Projection,
};
use mandate_federation::verifier::{ConstructedVerifier, VerifiedProof};
use mandate_federation::{
    DenialClause, Denied, LinkStore, PrincipalState, PrincipalStore, RecordedPrincipals,
    RecordingSessionIssuer, RequestContext, SequentialAllocator,
};
use mandate_model::TenantResolutionRule;
use mandate_types::value::Uuid;
use mandate_types::{
    Audience, ClientId, CorrelationId, CredentialId, CredentialProof, DenialReason,
    ExternalLinkMethod, ExternalPrincipalId, ExternalSubject, FederationConnectionId, Issuer,
    OrganizationId, PrincipalId, REDACTED, SigningAlgorithm, Timestamp, VerifiedContext,
};

const ISSUER_ONE: &str = "https://idp.example/one";
const ISSUER_TWO: &str = "https://idp.example/two";
const CLIENT: &str = "configured-client";

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization(tag: u8) -> OrganizationId {
    OrganizationId::new(uuid(tag))
}

fn connection(tag: u8) -> FederationConnectionId {
    FederationConnectionId::new(uuid(tag))
}

fn principal(tag: u8) -> PrincipalId {
    PrincipalId::new(uuid(tag))
}

fn context(organization_id: OrganizationId) -> VerifiedContext {
    VerifiedContext {
        subject: principal(0x51),
        actor: None,
        organization: organization_id,
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("federation-linking"),
    }
}

fn created(
    connection_id: FederationConnectionId,
    organization_id: OrganizationId,
    issuer: &str,
) -> FederationEvent {
    FederationEvent::FederationConnectionCreated {
        context: context(organization_id),
        connection_id,
        issuer: Issuer::new(issuer),
        client_id: ClientId::new(CLIENT),
        tenant_resolution: TenantResolutionRule {
            configured_organization: organization_id,
            verified_claim_name: None,
            verified_claim_value: None,
        },
        jit_provisioning: false,
    }
}

fn request() -> RequestContext {
    RequestContext {
        audience: Audience::new("mandate"),
        correlation: CorrelationId::new("federation-linking"),
        credential: CredentialId::new(uuid(0xcd)),
        at: Timestamp::new("2026-09-18T00:00:00Z"),
    }
}

fn presented() -> CredentialProof {
    CredentialProof::from_bytes(b"proof-material-marker".to_vec())
}

fn verifier(issuer: &str, subject: &str, email: Option<&str>) -> ConstructedVerifier {
    let mut proof = VerifiedProof::new(
        Issuer::new(issuer),
        ExternalSubject::new(subject),
        ClientId::new(CLIENT),
    );
    if let Some(email) = email {
        proof = proof.with_verified_claim("email", email);
    }
    ConstructedVerifier::admitting(&[SigningAlgorithm::new("configured-by-deployment")], proof)
        .expect("a non-empty allowlist is admitted")
}

fn link(
    projection: &Projection,
    allocator: &mut SequentialAllocator,
    organization_id: OrganizationId,
    connection_id: FederationConnectionId,
    subject: &str,
    principal_id: PrincipalId,
    method: ExternalLinkMethod,
) -> Result<Linked, Denied> {
    // The ordinary administrative case: the target principal is recorded in the
    // caller's own organization by `mandate.identity`, and has no federation link yet.
    let links = RecordedPrincipals::over(projection.clone()).with_principal(
        principal_id,
        organization_id,
        PrincipalState::Active,
    );
    let input = LinkExternalPrincipal {
        context: context(organization_id),
        connection_id,
        external_subject: ExternalSubject::new(subject),
        principal_id,
        method,
    };
    link_external_principal(&input, &request(), projection, &links, allocator)
}

fn authenticate(
    projection: &Projection,
    connection_id: FederationConnectionId,
    issuer: &str,
    subject: &str,
    email: Option<&str>,
) -> Result<Authenticated, Denied> {
    let input = AuthenticateFederation {
        connection_id,
        proof: presented(),
    };
    let mut sessions = RecordingSessionIssuer::new();
    authenticate_federation(
        &input,
        &request(),
        &verifier(issuer, subject, email),
        projection,
        projection,
        &mut sessions,
    )
}

/// `issuer-isolation`: equal subjects under distinct issuers resolve distinct external
/// keys and no principal is merged.
#[test]
fn issuer_isolation() {
    let mut log = vec![
        created(connection(1), organization(10), ISSUER_ONE),
        created(connection(2), organization(10), ISSUER_TWO),
    ];
    let projection = Projection::fold(&log).expect("two connections");
    let mut allocator = SequentialAllocator::new();

    let first = link(
        &projection,
        &mut allocator,
        organization(10),
        connection(1),
        "shared-subject",
        principal(0x21),
        ExternalLinkMethod::Administrator,
    )
    .expect("no link exists for this key");
    log.push(first.event);
    let projection = Projection::fold(&log).expect("one link");

    let second = link(
        &projection,
        &mut allocator,
        organization(10),
        connection(2),
        "shared-subject",
        principal(0x22),
        ExternalLinkMethod::Administrator,
    )
    .expect("the same subject under another issuer is another key, not a conflict");
    log.push(second.event);
    let projection = Projection::fold(&log).expect("two links, two keys");

    assert_eq!(projection.links().len(), 2, "two distinct external keys");
    assert_ne!(
        first.external_principal_id, second.external_principal_id,
        "no merge: two records"
    );

    let one = authenticate(
        &projection,
        connection(1),
        ISSUER_ONE,
        "shared-subject",
        None,
    )
    .expect("the link under issuer one resolves");
    let two = authenticate(
        &projection,
        connection(2),
        ISSUER_TWO,
        "shared-subject",
        None,
    )
    .expect("the link under issuer two resolves");
    assert_eq!(one.principal_id, principal(0x21));
    assert_eq!(two.principal_id, principal(0x22));
    assert_ne!(
        one.principal_id, two.principal_id,
        "equal subjects under distinct issuers are distinct accounts"
    );
}

/// `email-isolation`: an equal verified email under distinct issuers merges no
/// principal, and linking is never authorized by email equality.
#[test]
fn email_isolation() {
    let shared_email = "person@example.test";
    let mut log = vec![
        created(connection(1), organization(10), ISSUER_ONE),
        created(connection(2), organization(10), ISSUER_TWO),
    ];
    let projection = Projection::fold(&log).expect("two connections");
    let mut allocator = SequentialAllocator::new();

    let first = link(
        &projection,
        &mut allocator,
        organization(10),
        connection(1),
        "subject-under-one",
        principal(0x21),
        ExternalLinkMethod::Administrator,
    )
    .expect("no link exists for this key");
    log.push(first.event);
    let projection = Projection::fold(&log).expect("one link");

    let denied = authenticate(
        &projection,
        connection(2),
        ISSUER_TWO,
        "subject-under-two",
        Some(shared_email),
    )
    .expect_err("the same verified email under another issuer is not a link");
    assert_eq!(denied.reason, DenialReason::Denied);
    assert_eq!(
        denied.clause,
        DenialClause::LinkAbsent,
        "no automatic principal merge on equal email"
    );

    let second = link(
        &projection,
        &mut allocator,
        organization(10),
        connection(2),
        "subject-under-two",
        principal(0x22),
        ExternalLinkMethod::Administrator,
    )
    .expect("an explicit link is the only route");
    log.push(second.event);
    let projection = Projection::fold(&log).expect("two links");

    let one = authenticate(
        &projection,
        connection(1),
        ISSUER_ONE,
        "subject-under-one",
        Some(shared_email),
    )
    .expect("the explicit link under issuer one resolves");
    let two = authenticate(
        &projection,
        connection(2),
        ISSUER_TWO,
        "subject-under-two",
        Some(shared_email),
    )
    .expect("the explicit link under issuer two resolves");
    assert_ne!(
        one.principal_id, two.principal_id,
        "an equal verified email merged nothing"
    );
}

/// `explicit-link`: an authorized same-organization administrator with no conflicting
/// link produces one link and an audit record carrying no credential material.
#[test]
fn explicit_link() {
    let mut log = vec![created(connection(1), organization(10), ISSUER_ONE)];
    let projection = Projection::fold(&log).expect("one connection");
    let mut allocator = SequentialAllocator::new();

    let accepted = link(
        &projection,
        &mut allocator,
        organization(10),
        connection(1),
        "subject-one",
        principal(0x21),
        ExternalLinkMethod::Administrator,
    )
    .expect("a same-organization administrator with no conflicting link");

    let FederationEvent::ExternalPrincipalLinked { context, .. } = &accepted.event else {
        panic!("the accepted outcome emits ExternalPrincipalLinked");
    };
    assert_eq!(
        context.credential,
        CredentialId::new(uuid(0xcd)),
        "the audit record names the credential the caller was validated from"
    );
    let rendering = format!("{:?}", accepted.event);
    assert!(
        !rendering.contains(REDACTED),
        "the audit record carries no transient value at all: {rendering}"
    );
    assert!(
        !rendering.contains("proof-material-marker"),
        "the audit record carries no credential material: {rendering}"
    );

    log.push(accepted.event);
    let projection = Projection::fold(&log).expect("one link");
    assert_eq!(projection.links().len(), 1, "exactly one link");
    let key = ExternalKey {
        organization_id: organization(10),
        issuer: Issuer::new(ISSUER_ONE),
        subject: ExternalSubject::new("subject-one"),
    };
    let recorded = projection.link(&key).expect("the exact key resolves");
    assert_eq!(recorded.id, accepted.external_principal_id);
    assert_eq!(recorded.principal_id, principal(0x21));
    assert_eq!(recorded.link_method, ExternalLinkMethod::Administrator);

    let authenticated = authenticate(&projection, connection(1), ISSUER_ONE, "subject-one", None)
        .expect("the new link resolves");
    assert_eq!(authenticated.principal_id, principal(0x21));
}

/// `link-conflict`: the exact key is already linked to another principal, so the second
/// link is denied and the existing mapping is unchanged.
#[test]
fn link_conflict() {
    let mut log = vec![created(connection(1), organization(10), ISSUER_ONE)];
    let projection = Projection::fold(&log).expect("one connection");
    let mut allocator = SequentialAllocator::new();
    let accepted = link(
        &projection,
        &mut allocator,
        organization(10),
        connection(1),
        "subject-one",
        principal(0x21),
        ExternalLinkMethod::Administrator,
    )
    .expect("no link exists for this key");
    log.push(accepted.event);
    let projection = Projection::fold(&log).expect("one link");
    let before = log.len();

    let denied = link(
        &projection,
        &mut allocator,
        organization(10),
        connection(1),
        "subject-one",
        principal(0x22),
        ExternalLinkMethod::Administrator,
    )
    .expect_err("the exact key is already linked to another principal");

    assert_eq!(denied.reason, DenialReason::Denied);
    assert_eq!(denied.clause, DenialClause::LinkConflict);
    assert_eq!(log.len(), before, "a denial emits no event");
    let projection = Projection::fold(&log).expect("still one link");
    assert_eq!(projection.links().len(), 1);
    let key = ExternalKey {
        organization_id: organization(10),
        issuer: Issuer::new(ISSUER_ONE),
        subject: ExternalSubject::new("subject-one"),
    };
    assert_eq!(
        projection.link(&key).map(|link| link.principal_id),
        Some(principal(0x21)),
        "the existing mapping is unchanged"
    );
    let authenticated = authenticate(&projection, connection(1), ISSUER_ONE, "subject-one", None)
        .expect("the surviving link resolves");
    assert_eq!(authenticated.principal_id, principal(0x21));
}

/// `LinkExternalPrincipal` is the administrative path; the method reserved to
/// just-in-time provisioning is not one a caller may name here
/// (`federation.yaml:277-283`: the link that command creates carries
/// `ExternalLinkMethod::ConfiguredFederation`).
#[test]
fn the_configured_federation_method_is_reserved_to_provisioning() {
    let log = vec![created(connection(1), organization(10), ISSUER_ONE)];
    let projection = Projection::fold(&log).expect("one connection");
    let mut allocator = SequentialAllocator::new();

    let denied = link(
        &projection,
        &mut allocator,
        organization(10),
        connection(1),
        "subject-one",
        principal(0x21),
        ExternalLinkMethod::ConfiguredFederation,
    )
    .expect_err("this method is created by ProvisionExternalPrincipal alone");

    assert_eq!(denied.clause, DenialClause::LinkingAuthority);
}

/// A caller verified in another organization may not link through this connection
/// (`federation.yaml:166`: "organization or target principal mismatches").
#[test]
fn a_foreign_organization_may_not_link_through_this_connection() {
    let log = vec![created(connection(1), organization(10), ISSUER_ONE)];
    let projection = Projection::fold(&log).expect("one connection");
    let mut allocator = SequentialAllocator::new();

    let denied = link(
        &projection,
        &mut allocator,
        organization(11),
        connection(1),
        "subject-one",
        principal(0x21),
        ExternalLinkMethod::Administrator,
    )
    .expect_err("the caller is not verified in the connection's organization");

    assert_eq!(denied.clause, DenialClause::OrganizationMismatch);
}

/// `federation.yaml:166`: "organization or target principal mismatches". The caller's
/// organization is one half; this is the other.
#[test]
fn a_target_principal_recorded_in_another_organization_is_refused() {
    let log = vec![created(connection(1), organization(10), ISSUER_ONE)];
    let projection = Projection::fold(&log).expect("one connection");
    let mut allocator = SequentialAllocator::new();
    let links = RecordedPrincipals::over(projection.clone()).with_principal(
        principal(0x21),
        organization(11),
        PrincipalState::Active,
    );
    let input = LinkExternalPrincipal {
        context: context(organization(10)),
        connection_id: connection(1),
        external_subject: ExternalSubject::new("subject-one"),
        principal_id: principal(0x21),
        method: ExternalLinkMethod::Administrator,
    };

    let denied = link_external_principal(&input, &request(), &projection, &links, &mut allocator)
        .expect_err("the target principal belongs to another organization");

    assert_eq!(denied.reason, DenialReason::TenantMismatch);
    assert_eq!(denied.clause, DenialClause::PrincipalMismatch);
}

/// A target principal no read model records is refused rather than admitted: this path
/// fails closed.
#[test]
fn a_target_principal_that_is_not_recorded_is_refused() {
    let log = vec![created(connection(1), organization(10), ISSUER_ONE)];
    let projection = Projection::fold(&log).expect("one connection");
    let mut allocator = SequentialAllocator::new();
    let links = RecordedPrincipals::over(projection.clone());
    let input = LinkExternalPrincipal {
        context: context(organization(10)),
        connection_id: connection(1),
        external_subject: ExternalSubject::new("subject-one"),
        principal_id: principal(0x21),
        method: ExternalLinkMethod::Administrator,
    };

    let denied = link_external_principal(&input, &request(), &projection, &links, &mut allocator)
        .expect_err("no read model records this principal");

    assert_eq!(denied.clause, DenialClause::PrincipalMismatch);
}

/// J5: `federation.yaml:166` denies when "proof/connection trust is invalid", and a
/// disabled connection is not trusted.
#[test]
fn a_disabled_connection_may_not_be_linked_through() {
    let log = vec![
        created(connection(1), organization(10), ISSUER_ONE),
        FederationEvent::FederationConnectionDisabled {
            context: context(organization(10)),
            id: connection(1),
        },
    ];
    let projection = Projection::fold(&log).expect("one disabled connection");
    let mut allocator = SequentialAllocator::new();

    let denied = link(
        &projection,
        &mut allocator,
        organization(10),
        connection(1),
        "subject-one",
        principal(0x21),
        ExternalLinkMethod::Administrator,
    )
    .expect_err("the connection is disabled");

    assert_eq!(denied.clause, DenialClause::ConnectionDisabled);
}

/// The empty string is not a key component here either: `LinkExternalPrincipal` takes
/// the subject straight from the caller.
#[test]
fn an_empty_external_subject_is_refused() {
    let log = vec![created(connection(1), organization(10), ISSUER_ONE)];
    let projection = Projection::fold(&log).expect("one connection");
    let mut allocator = SequentialAllocator::new();

    for subject in ["", "   "] {
        let denied = link(
            &projection,
            &mut allocator,
            organization(10),
            connection(1),
            subject,
            principal(0x21),
            ExternalLinkMethod::Administrator,
        )
        .expect_err("an empty subject collapses the canonical key");

        assert_eq!(denied.clause, DenialClause::EmptySubject);
    }
}

/// A link that reached its terminal `Unlinked` state does not hold the key: relinking
/// the same subject is admitted, and is not reported as a conflict.
#[test]
fn a_terminal_unlinked_row_does_not_hold_the_key() {
    struct UnlinkedRow(ExternalPrincipal);

    impl LinkStore for UnlinkedRow {
        fn link(&self, _key: &ExternalKey) -> Option<ExternalPrincipal> {
            Some(self.0.clone())
        }
    }

    impl PrincipalStore for UnlinkedRow {
        fn organization_of(&self, _principal_id: &PrincipalId) -> Option<OrganizationId> {
            Some(organization(10))
        }
    }

    let log = vec![created(connection(1), organization(10), ISSUER_ONE)];
    let projection = Projection::fold(&log).expect("one connection");
    let mut allocator = SequentialAllocator::new();
    let links = UnlinkedRow(ExternalPrincipal {
        id: ExternalPrincipalId::new(uuid(0x71)),
        organization_id: organization(10),
        subject: ExternalSubject::new("subject-one"),
        principal_id: principal(0x21),
        connection_id: connection(1),
        link_method: ExternalLinkMethod::Administrator,
        linked_at: Timestamp::new("2026-09-18T00:00:00Z"),
        state: LinkState::Unlinked,
    });
    let input = LinkExternalPrincipal {
        context: context(organization(10)),
        connection_id: connection(1),
        external_subject: ExternalSubject::new("subject-one"),
        principal_id: principal(0x22),
        method: ExternalLinkMethod::Administrator,
    };

    link_external_principal(&input, &request(), &projection, &links, &mut allocator)
        .expect("a terminal Unlinked row is not a conflicting link");
}

/// J1: `mandate.identity.Principal` declares a `Disabled` terminal state. Binding an
/// external subject to a disabled principal would mint it a session on the next
/// federated login.
#[test]
fn a_disabled_target_principal_is_refused() {
    let log = vec![created(connection(1), organization(10), ISSUER_ONE)];
    let projection = Projection::fold(&log).expect("one connection");
    let mut allocator = SequentialAllocator::new();
    let links = RecordedPrincipals::over(projection.clone()).with_principal(
        principal(0x21),
        organization(10),
        PrincipalState::Disabled,
    );
    let input = LinkExternalPrincipal {
        context: context(organization(10)),
        connection_id: connection(1),
        external_subject: ExternalSubject::new("subject-one"),
        principal_id: principal(0x21),
        method: ExternalLinkMethod::Administrator,
    };

    let denied = link_external_principal(&input, &request(), &projection, &links, &mut allocator)
        .expect_err("the target principal is disabled");

    assert_eq!(denied.reason, DenialReason::Denied);
    assert_eq!(denied.clause, DenialClause::PrincipalDisabled);
}

/// R3/J4: a subject that is not its own trim is refused, and nothing is canonicalized —
/// the trimmed form is not silently substituted.
#[test]
fn an_external_subject_that_is_not_its_own_trim_is_refused() {
    let log = vec![created(connection(1), organization(10), ISSUER_ONE)];
    let projection = Projection::fold(&log).expect("one connection");
    let mut allocator = SequentialAllocator::new();

    for subject in [" subject-one", "subject-one ", "subject-one\t"] {
        let denied = link(
            &projection,
            &mut allocator,
            organization(10),
            connection(1),
            subject,
            principal(0x21),
            ExternalLinkMethod::Administrator,
        )
        .expect_err("the subject is not the subject the issuer issued");

        assert_eq!(
            denied.clause,
            DenialClause::SubjectNotTrimmed,
            "subject {subject:?}"
        );
    }

    // The trimmed form is a different subject, and it is admitted on its own terms.
    link(
        &projection,
        &mut allocator,
        organization(10),
        connection(1),
        "subject-one",
        principal(0x21),
        ExternalLinkMethod::Administrator,
    )
    .expect("the subject as issued is admitted");
}
