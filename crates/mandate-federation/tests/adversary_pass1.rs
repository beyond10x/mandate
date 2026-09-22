//! Adversarial cases against `story:federation-linking`, pass 1.
//!
//! Every case here asserts a statement `systems/mandate/domains/federation.yaml`,
//! `docs/architecture/command-obligations.md` or the story's own `## Acceptance` makes,
//! against the implementation the same unit wrote. Nothing in this file edits or weakens
//! an existing case; the doubles it builds stand in for a state the crate's own ports
//! admit.

use mandate_federation::authenticate::{
    AuthenticateFederation, Authenticated, ProvisionExternalPrincipal, authenticate_federation,
    provision_external_principal,
};
use mandate_federation::link::{LinkExternalPrincipal, link_external_principal};
use mandate_federation::record::{
    ExternalKey, ExternalPrincipal, FederationEvent, LinkState, Projection,
};
use mandate_federation::verifier::{ConstructedVerifier, VerifiedProof};
use mandate_federation::{
    Denied, LinkStore, RecordingSessionIssuer, RequestContext, SequentialAllocator,
};
use mandate_model::TenantResolutionRule;
use mandate_types::value::Uuid;
use mandate_types::{
    Audience, ClientId, CorrelationId, CredentialId, CredentialProof, ExternalLinkMethod,
    ExternalPrincipalId, ExternalSubject, FederationConnectionId, Issuer, OrganizationId,
    PrincipalId, PrincipalKind, SigningAlgorithm, Timestamp, VerifiedContext,
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

fn context(organization_id: OrganizationId) -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::new(uuid(0x51)),
        actor: None,
        organization: organization_id,
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("adversary-federation-linking"),
    }
}

fn unconditional(organization_id: OrganizationId) -> TenantResolutionRule {
    TenantResolutionRule {
        configured_organization: organization_id,
        verified_claim_name: None,
        verified_claim_value: None,
    }
}

fn on_claim(organization_id: OrganizationId, name: &str, value: &str) -> TenantResolutionRule {
    TenantResolutionRule {
        configured_organization: organization_id,
        verified_claim_name: Some(name.to_owned()),
        verified_claim_value: Some(value.to_owned()),
    }
}

fn created(
    connection_id: FederationConnectionId,
    organization_id: OrganizationId,
    issuer: &str,
    tenant_resolution: TenantResolutionRule,
    jit_provisioning: bool,
) -> FederationEvent {
    FederationEvent::FederationConnectionCreated {
        context: context(organization_id),
        connection_id,
        issuer: Issuer::new(issuer),
        client_id: ClientId::new(CLIENT),
        tenant_resolution,
        jit_provisioning,
    }
}

fn at() -> Timestamp {
    Timestamp::new("2026-09-18T00:00:00Z")
}

fn request() -> RequestContext {
    RequestContext {
        audience: Audience::new("mandate"),
        correlation: CorrelationId::new("adversary-federation-linking"),
        credential: CredentialId::new(uuid(0xcd)),
        at: at(),
    }
}

fn presented() -> CredentialProof {
    CredentialProof::from_bytes(b"proof-material-marker".to_vec())
}

fn admitting(proof: VerifiedProof) -> ConstructedVerifier {
    ConstructedVerifier::admitting(&[SigningAlgorithm::new("configured-by-deployment")], proof)
        .expect("a non-empty allowlist is admitted")
}

fn proof_for(issuer: &str, subject: &str) -> VerifiedProof {
    VerifiedProof::new(
        Issuer::new(issuer),
        ExternalSubject::new(subject),
        ClientId::new(CLIENT),
    )
}

fn authenticate(
    connections: &Projection,
    links: &impl LinkStore,
    connection_id: FederationConnectionId,
    verifier: &ConstructedVerifier,
    sessions: &mut RecordingSessionIssuer,
) -> Result<Authenticated, Denied> {
    let input = AuthenticateFederation {
        connection_id,
        proof: presented(),
    };
    authenticate_federation(&input, &request(), verifier, connections, links, sessions)
}

fn provision(
    projection: &Projection,
    allocator: &mut SequentialAllocator,
    connection_id: FederationConnectionId,
    verifier: &ConstructedVerifier,
) -> Result<mandate_federation::authenticate::Provisioned, Denied> {
    let input = ProvisionExternalPrincipal {
        connection_id,
        proof: presented(),
    };
    provision_external_principal(
        &input,
        &request(),
        verifier,
        projection,
        projection,
        allocator,
    )
}

/// Step 6 of the mandated resolution order is "validate configured organization/tenant
/// claim or binding" for the trust relationship step 1 selected
/// (`docs/architecture/federated-login.md`, `architecture-addendum.md:344-360`), and
/// `mandate.core.TenantResolutionRule` is the only source of a tenant
/// (`docs/architecture/federated-login.md`, "What the contract refuses, and where").
///
/// `src/authenticate.rs:235-281` never consults the selected connection's own rule. It
/// collects the organizations of *every* enabled connection configured for the issuer
/// whose rule matches, and admits the request when that set has one element. So a proof
/// that fails the selected connection's configured claim rule authenticates through that
/// connection anyway, as long as some other connection of the same organization matches.
/// The configured rule is then advisory, not a binding.
///
/// A fix that requires the selected connection's own rule to match, and keeps the
/// existing cross-connection zero/multiple count, leaves `tenant-valid`, `tenant-zero`,
/// `tenant-ambiguous` and `tenant-unverified` green.
#[test]
fn a_proof_that_fails_the_selected_connections_tenant_rule_still_authenticates() {
    // One organization, one issuer, two enabled connections with different rules — the
    // configuration `ConnectionStore::enabled_for_issuer` exists to serve.
    let log = vec![
        created(
            connection(1),
            organization(10),
            ISSUER_ONE,
            on_claim(organization(10), "org", "acme"),
            false,
        ),
        created(
            connection(2),
            organization(10),
            ISSUER_ONE,
            on_claim(organization(10), "dept", "engineering"),
            false,
        ),
        FederationEvent::ExternalPrincipalLinked {
            context: context(organization(10)),
            connection_id: connection(1),
            principal_id: PrincipalId::new(uuid(0x21)),
            external_principal_id: ExternalPrincipalId::new(uuid(0x71)),
            subject: ExternalSubject::new("subject-one"),
            link_method: ExternalLinkMethod::Administrator,
            linked_at: at(),
        },
    ];
    let projection = Projection::fold(&log).expect("two connections, one link");
    let mut sessions = RecordingSessionIssuer::new();

    // The proof carries `dept=engineering`. Connection 1's configured rule requires
    // `org=acme`, which this proof does not carry.
    let verifier =
        admitting(proof_for(ISSUER_ONE, "subject-one").with_verified_claim("dept", "engineering"));
    let outcome = authenticate(
        &projection,
        &projection,
        connection(1),
        &verifier,
        &mut sessions,
    );

    assert!(
        outcome.is_err(),
        "connection 1 is configured to resolve its tenant from the verified claim \
         org=acme; this proof does not carry it, and the only rule that matched belongs \
         to connection 2. The authentication was admitted anyway: {outcome:?}, sessions \
         issued: {:?}",
        sessions.issued()
    );
}

/// `federation.yaml:166` and `command-obligations.md:28` declare that
/// `LinkExternalPrincipal` denies when "organization or **target principal**
/// mismatches". `src/link.rs:61-66` checks the caller's organization against the
/// connection's and stops there; the crate declares no read of the target principal, so
/// the second half of the clause is not realized.
///
/// The ground truth here is the crate's own projection: principal `P` exists only
/// because `ProvisionExternalPrincipal` created it through organization 11's connection,
/// and the fold records its link under organization 11. Organization 10's administrator
/// then binds an external subject of *its* connection to `P`, and the resulting
/// authenticated context names organization 10 with organization 11's principal.
#[test]
fn a_target_principal_recorded_in_another_organization_is_linked_without_refusal() {
    let mut log = vec![
        // Organization 11's connection, which provisions the principal.
        created(
            connection(2),
            organization(11),
            ISSUER_TWO,
            unconditional(organization(11)),
            true,
        ),
        // Organization 10's connection, through which the link is attempted.
        created(
            connection(1),
            organization(10),
            ISSUER_ONE,
            unconditional(organization(10)),
            false,
        ),
    ];
    let projection = Projection::fold(&log).expect("two connections");
    let mut allocator = SequentialAllocator::new();
    let foreign = provision(
        &projection,
        &mut allocator,
        connection(2),
        &admitting(proof_for(ISSUER_TWO, "subject-of-eleven")),
    )
    .expect("organization 11 admits just-in-time provisioning");
    log.push(foreign.event);
    let projection = Projection::fold(&log).expect("one link, in organization 11");
    assert_eq!(
        projection
            .links()
            .iter()
            .find(|link| link.principal_id == foreign.principal_id)
            .map(|link| link.organization_id),
        Some(organization(11)),
        "the projection records this principal in organization 11 and nowhere else"
    );

    let input = LinkExternalPrincipal {
        // A caller verified in organization 10, the connection's own organization.
        context: context(organization(10)),
        connection_id: connection(1),
        external_subject: ExternalSubject::new("subject-of-ten"),
        principal_id: foreign.principal_id,
        method: ExternalLinkMethod::Administrator,
    };
    let outcome =
        link_external_principal(&input, &request(), &projection, &projection, &mut allocator);

    let consequence = match &outcome {
        Err(denied) => format!("refused: {denied:?}"),
        Ok(accepted) => {
            log.push(accepted.event.clone());
            let projection = Projection::fold(&log).expect("two links");
            let mut sessions = RecordingSessionIssuer::new();
            let authenticated = authenticate(
                &projection,
                &projection,
                connection(1),
                &admitting(proof_for(ISSUER_ONE, "subject-of-ten")),
                &mut sessions,
            );
            format!(
                "the authenticated context is {:?}",
                authenticated.map(|ok| (ok.organization_id, ok.principal_id))
            )
        }
    };

    assert!(
        outcome.is_err(),
        "the target principal is recorded in organization 11 and the connection is \
         organization 10's, which `federation.yaml:166` denies as \"organization or \
         target principal mismatches\"; {consequence}"
    );
}

/// The story's `## Acceptance` requires an "explicitly linked principal", and
/// `mandate.federation.ExternalPrincipal` declares `Unlinked` as a terminal lifecycle
/// state (`federation.yaml:23-34`).
///
/// `authenticate_federation` never reads `ExternalPrincipal.state`
/// (`src/authenticate.rs:80-88`). The only place the terminal state is honoured is
/// `Projection`'s own `LinkStore` impl (`src/record.rs:403-410`), so the guard is a
/// property of one implementation of the port rather than of the command. The port's
/// documentation — "The link recorded for this exact key, if there is one"
/// (`src/lib.rs:228-231`) — asks no implementor to filter, and the value it returns
/// carries the state, which invites the implementor to assume the caller reads it.
#[test]
fn an_unlinked_external_principal_returned_by_the_port_still_issues_a_session() {
    struct RecordedRow {
        key: ExternalKey,
        row: ExternalPrincipal,
    }

    impl LinkStore for RecordedRow {
        fn records_on_key(&self, key: &ExternalKey) -> Vec<ExternalPrincipal> {
            if *key == self.key {
                vec![self.row.clone()]
            } else {
                Vec::new()
            }
        }
    }

    let log = vec![created(
        connection(1),
        organization(10),
        ISSUER_ONE,
        unconditional(organization(10)),
        false,
    )];
    let connections = Projection::fold(&log).expect("one connection");
    let key = ExternalKey {
        organization_id: organization(10),
        issuer: Issuer::new(ISSUER_ONE),
        subject: ExternalSubject::new("subject-one"),
    };
    // An adapter's projection row for a link that has reached its terminal state.
    let links = RecordedRow {
        key: key.clone(),
        row: ExternalPrincipal {
            id: ExternalPrincipalId::new(uuid(0x71)),
            organization_id: key.organization_id,
            subject: key.subject.clone(),
            principal_id: PrincipalId::new(uuid(0x21)),
            connection_id: connection(1),
            link_method: ExternalLinkMethod::Administrator,
            linked_at: at(),
            state: LinkState::Unlinked,
        },
    };
    let mut sessions = RecordingSessionIssuer::new();

    let outcome = authenticate(
        &connections,
        &links,
        connection(1),
        &admitting(proof_for(ISSUER_ONE, "subject-one")),
        &mut sessions,
    );

    assert!(
        outcome.is_err(),
        "the external principal is in the terminal Unlinked state, so there is no \
         explicitly linked principal to form a context with: {outcome:?}, sessions \
         issued: {:?}",
        sessions.issued()
    );
}

/// The canonical key is `(organization, connection.issuer, external subject)`
/// (`federation.yaml:1`) and `mandate.core.ExternalSubject` is an unconstrained string
/// (`crates/mandate-types/src/macros.rs:89-140`), so the empty string is a subject the
/// type admits.
///
/// Neither `provision_external_principal` nor `link_external_principal` requires a
/// subject. An empty validated subject therefore becomes a whole key component, and
/// every external identity from that issuer whose validated subject is empty resolves to
/// the first principal provisioned under it.
#[test]
fn an_empty_validated_subject_collapses_two_external_identities() {
    let mut log = vec![created(
        connection(1),
        organization(10),
        ISSUER_ONE,
        unconditional(organization(10)),
        true,
    )];
    let projection = Projection::fold(&log).expect("one connection");
    let mut allocator = SequentialAllocator::new();

    let outcome = provision(
        &projection,
        &mut allocator,
        connection(1),
        &admitting(proof_for(ISSUER_ONE, "")),
    );

    let consequence = match &outcome {
        Err(denied) => format!("refused: {denied:?}"),
        Ok(provisioned) => {
            log.push(provisioned.event.clone());
            let projection = Projection::fold(&log).expect("one link");
            let mut sessions = RecordingSessionIssuer::new();
            // A second, different person from the same issuer, also with an empty
            // validated subject.
            let authenticated = authenticate(
                &projection,
                &projection,
                connection(1),
                &admitting(proof_for(ISSUER_ONE, "")),
                &mut sessions,
            );
            format!(
                "a second identity with an empty subject authenticated as {:?}, the \
                 principal provisioned for the first ({:?})",
                authenticated.map(|ok| ok.principal_id),
                provisioned.principal_id
            )
        }
    };

    assert!(
        outcome.is_err(),
        "the empty string is not an external subject: it makes the canonical key \
         collapse across identities; {consequence}"
    );
}

/// `federation.yaml` pins the payload of `ExternalPrincipalProvisioned` to the literal
/// `link_method: ConfiguredFederation`, and `federation.yaml:4` states that "the link
/// that command creates carries `ExternalLinkMethod::ConfiguredFederation`". The event
/// this crate declares carries `link_method` as a free field
/// (`src/record.rs:151-171`), and the fold copies whatever it finds there
/// (`src/record.rs:274-295`), so a log can record a just-in-time link under an
/// administrative method — a provenance the audit trail then reports wrongly.
///
/// This is a hand-built log: the only in-crate producer, `provision_external_principal`,
/// writes the literal. The finding is that nothing but that one call site holds the
/// contract's literal.
#[test]
fn the_fold_admits_a_provisioned_link_whose_method_is_not_configured_federation() {
    let log = vec![
        created(
            connection(1),
            organization(10),
            ISSUER_ONE,
            unconditional(organization(10)),
            true,
        ),
        FederationEvent::ExternalPrincipalProvisioned {
            organization_id: organization(10),
            correlation: CorrelationId::new("adversary-federation-linking"),
            connection_id: connection(1),
            principal_id: PrincipalId::new(uuid(0x21)),
            kind: PrincipalKind::User,
            display_name: String::from("subject-one"),
            external_principal_id: ExternalPrincipalId::new(uuid(0x71)),
            subject: ExternalSubject::new("subject-one"),
            // Not the literal the contract pins.
            link_method: ExternalLinkMethod::SecuritySupport,
            linked_at: at(),
        },
    ];

    let recorded = match Projection::fold(&log) {
        // A fold that refuses the event enforces the literal; that is a fix.
        Err(_) => Vec::new(),
        Ok(projection) => projection
            .links()
            .iter()
            .map(|link| link.link_method)
            .collect::<Vec<_>>(),
    };

    assert!(
        recorded
            .iter()
            .all(|method| *method == ExternalLinkMethod::ConfiguredFederation),
        "ExternalPrincipalProvisioned pins link_method to ConfiguredFederation, and the \
         fold recorded {recorded:?}"
    );
}
