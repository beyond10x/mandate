//! The four tenancy cases of `tests/security/cases.json` that name
//! `story:federation-linking` — `tenant-valid`, `tenant-zero`, `tenant-ambiguous`,
//! `tenant-unverified` — and the three just-in-time cases that name it as well:
//! `jit-first-login`, `jit-disabled`, `jit-conflict`. Each test is named for the case it
//! executes.
//!
//! `jit-conflict` says "two simultaneous first logins". What executes here is the
//! single-writer conflict path only: two callers evaluate against one read model, the
//! writer appends one event, and the second command re-evaluated against the updated
//! read model returns the declared denial. Two writers racing on one storage engine is
//! not expressible in this crate and belongs to the storage adapter
//! (`docs/architecture/runtime-decisions.md`, `decision-blocker:identity-uniqueness`).

use mandate_federation::authenticate::{
    AuthenticateFederation, Authenticated, ProvisionExternalPrincipal, authenticate_federation,
    provision_external_principal,
};
use mandate_federation::record::{
    ExternalKey, ExternalPrincipal, FederationEvent, LinkState, Projection,
};
use mandate_federation::verifier::{ConstructedVerifier, VerifiedProof};
use mandate_federation::{
    ConnectionStore, DenialClause, Denied, LinkStore, PrincipalState, RecordedPrincipals,
    RecordingSessionIssuer, RequestContext, SequentialAllocator,
};
use mandate_model::TenantResolutionRule;
use mandate_types::value::Uuid;
use mandate_types::{
    Audience, ClientId, CorrelationId, CredentialId, CredentialProof, DenialReason,
    ExternalLinkMethod, ExternalSubject, FederationConnectionId, Issuer, OrganizationId,
    PrincipalId, SigningAlgorithm, Timestamp, VerifiedContext,
};

const ISSUER_ONE: &str = "https://idp.example/one";
const ISSUER_TWO: &str = "https://idp.example/two";
const CLIENT: &str = "configured-client";
const SUBJECT: &str = "subject-one";

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

fn linked(
    connection_id: FederationConnectionId,
    organization_id: OrganizationId,
    subject: &str,
    principal_id: PrincipalId,
) -> FederationEvent {
    FederationEvent::ExternalPrincipalLinked {
        context: context(organization_id),
        connection_id,
        principal_id,
        external_principal_id: mandate_types::ExternalPrincipalId::new(uuid(0x71)),
        subject: ExternalSubject::new(subject),
        link_method: ExternalLinkMethod::Administrator,
        linked_at: linked_at(),
    }
}

fn linked_at() -> Timestamp {
    Timestamp::new("2026-09-18T00:00:00Z")
}

fn request() -> RequestContext {
    RequestContext {
        audience: Audience::new("mandate"),
        correlation: CorrelationId::new("federation-linking"),
        credential: CredentialId::new(uuid(0xcd)),
        at: linked_at(),
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
    projection: &Projection,
    connection_id: FederationConnectionId,
    verifier: &ConstructedVerifier,
    sessions: &mut RecordingSessionIssuer,
) -> Result<Authenticated, Denied> {
    let input = AuthenticateFederation {
        connection_id,
        proof: presented(),
    };
    authenticate_federation(
        &input,
        &request(),
        verifier,
        projection,
        projection,
        sessions,
    )
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

/// `tenant-valid`: configured trust with one tenant match establishes the exact
/// configured organization.
#[test]
fn tenant_valid() {
    let log = vec![
        created(
            connection(1),
            organization(10),
            ISSUER_ONE,
            on_claim(organization(10), "org", "acme"),
            false,
        ),
        linked(connection(1), organization(10), SUBJECT, principal(0x21)),
    ];
    let projection = Projection::fold(&log).expect("one connection, one link");
    let mut sessions = RecordingSessionIssuer::new();

    let authenticated = authenticate(
        &projection,
        connection(1),
        &admitting(proof_for(ISSUER_ONE, SUBJECT).with_verified_claim("org", "acme")),
        &mut sessions,
    )
    .expect("exactly one configured tenant matches");

    assert_eq!(
        authenticated.organization_id,
        organization(10),
        "the exact configured organization"
    );
    assert_eq!(authenticated.principal_id, principal(0x21));
    assert_eq!(sessions.issued().len(), 1, "one session");
    assert_eq!(sessions.issued()[0].1, organization(10));
    assert!(matches!(
        authenticated.event,
        FederationEvent::FederationAuthenticated { .. }
    ));
}

/// `tenant-zero`: a verified proof that matches no configured tenant is denied and no
/// session is issued.
#[test]
fn tenant_zero() {
    let log = vec![
        created(
            connection(1),
            organization(10),
            ISSUER_ONE,
            on_claim(organization(10), "org", "acme"),
            false,
        ),
        linked(connection(1), organization(10), SUBJECT, principal(0x21)),
    ];
    let projection = Projection::fold(&log).expect("one connection, one link");
    let mut sessions = RecordingSessionIssuer::new();

    let denied = authenticate(
        &projection,
        connection(1),
        &admitting(proof_for(ISSUER_ONE, SUBJECT).with_verified_claim("org", "another")),
        &mut sessions,
    )
    .expect_err("no configured tenant matches");

    assert_eq!(denied.reason, DenialReason::TenantMismatch);
    assert_eq!(denied.clause, DenialClause::TenantZero);
    assert!(sessions.issued().is_empty(), "no session");
}

/// `tenant-ambiguous`: a verified proof matching two configured tenants is denied; no
/// tenant is guessed.
#[test]
fn tenant_ambiguous() {
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
            organization(11),
            ISSUER_ONE,
            on_claim(organization(11), "org", "acme"),
            false,
        ),
        linked(connection(1), organization(10), SUBJECT, principal(0x21)),
    ];
    let projection = Projection::fold(&log).expect("two connections, one link");
    assert_eq!(
        projection
            .enabled_for_issuer(&Issuer::new(ISSUER_ONE))
            .len(),
        2,
        "two configured tenants stand behind one issuer"
    );
    let mut sessions = RecordingSessionIssuer::new();

    let denied = authenticate(
        &projection,
        connection(1),
        &admitting(proof_for(ISSUER_ONE, SUBJECT).with_verified_claim("org", "acme")),
        &mut sessions,
    )
    .expect_err("two configured tenants match");

    assert_eq!(denied.reason, DenialReason::TenantMismatch);
    assert_eq!(denied.clause, DenialClause::TenantAmbiguous);
    assert!(
        sessions.issued().is_empty(),
        "no guessed tenant, no session"
    );
}

/// `tenant-unverified`: an organization selector supplied without a verified binding is
/// denied rather than used as a fallback.
#[test]
fn tenant_unverified() {
    let log = vec![
        created(
            connection(1),
            organization(10),
            ISSUER_ONE,
            on_claim(organization(10), "org", "acme"),
            false,
        ),
        linked(connection(1), organization(10), SUBJECT, principal(0x21)),
    ];
    let projection = Projection::fold(&log).expect("one connection, one link");
    let mut sessions = RecordingSessionIssuer::new();

    let denied = authenticate(
        &projection,
        connection(1),
        &admitting(proof_for(ISSUER_ONE, SUBJECT).with_unverified_hint("org", "acme")),
        &mut sessions,
    )
    .expect_err("the selector arrived without a verified binding");

    assert_eq!(denied.reason, DenialReason::TenantMismatch);
    assert_eq!(
        denied.clause,
        DenialClause::UnverifiedFallback,
        "the value that would have resolved the tenant was never validated"
    );
    assert!(sessions.issued().is_empty(), "no fallback, no session");
}

/// `jit-first-login`: a verified proof for a subject with no `ExternalPrincipal` on a
/// connection that admits provisioning yields one principal, one link with method
/// `ConfiguredFederation`, and one session.
#[test]
fn jit_first_login() {
    let mut log = vec![created(
        connection(1),
        organization(10),
        ISSUER_ONE,
        unconditional(organization(10)),
        true,
    )];
    let projection = Projection::fold(&log).expect("one connection");
    let verifier = admitting(proof_for(ISSUER_ONE, SUBJECT));
    let mut allocator = SequentialAllocator::new();
    let mut sessions = RecordingSessionIssuer::new();

    let absent = authenticate(&projection, connection(1), &verifier, &mut sessions)
        .expect_err("no link exists for this key yet");
    assert_eq!(
        absent.clause,
        DenialClause::LinkAbsent,
        "the adapter provisions on this denial and no other"
    );
    assert!(
        sessions.issued().is_empty(),
        "the first attempt issued none"
    );

    let provisioned = provision(&projection, &mut allocator, connection(1), &verifier)
        .expect("the connection admits JIT");
    log.push(provisioned.event.clone());
    let projection = Projection::fold(&log).expect("one link");

    assert_eq!(provisioned.subject, ExternalSubject::new(SUBJECT));
    assert!(matches!(
        provisioned.event,
        FederationEvent::ExternalPrincipalProvisioned { .. }
    ));
    let links = projection.links();
    assert_eq!(links.len(), 1, "one link");
    assert_eq!(links[0].principal_id, provisioned.principal_id);
    assert_eq!(
        links[0].link_method,
        ExternalLinkMethod::ConfiguredFederation
    );

    let authenticated = authenticate(&projection, connection(1), &verifier, &mut sessions)
        .expect("the retried authentication resolves the new link");
    assert_eq!(authenticated.principal_id, provisioned.principal_id);
    assert_eq!(authenticated.organization_id, organization(10));
    assert_eq!(sessions.issued().len(), 1, "one session");
}

/// `jit-disabled`: a connection that does not admit provisioning denies the first login
/// and creates nothing.
#[test]
fn jit_disabled() {
    let log = vec![created(
        connection(1),
        organization(10),
        ISSUER_ONE,
        unconditional(organization(10)),
        false,
    )];
    let projection = Projection::fold(&log).expect("one connection");
    let verifier = admitting(proof_for(ISSUER_ONE, SUBJECT));
    let mut allocator = SequentialAllocator::new();

    let denied = provision(&projection, &mut allocator, connection(1), &verifier)
        .expect_err("this connection does not admit provisioning");

    assert_eq!(denied.reason, DenialReason::Denied);
    assert_eq!(denied.clause, DenialClause::ProvisioningNotAdmitted);
    assert_eq!(log.len(), 1, "a denial emits no event");
    let projection = Projection::fold(&log).expect("still one connection");
    assert!(
        projection.links().is_empty(),
        "no principal and no link were created"
    );
}

/// `jit-conflict`: two first logins for one `(organization, issuer, subject)` leave one
/// record and one declared denial, and the denied caller's retried authentication
/// succeeds. Single-writer path; see this file's module documentation.
#[test]
fn jit_conflict() {
    let mut log = vec![created(
        connection(1),
        organization(10),
        ISSUER_ONE,
        unconditional(organization(10)),
        true,
    )];
    let before = Projection::fold(&log).expect("one connection");
    let verifier = admitting(proof_for(ISSUER_ONE, SUBJECT));
    let mut allocator = SequentialAllocator::new();

    // Both callers evaluate against the same read model, in which no link exists.
    let first =
        provision(&before, &mut allocator, connection(1), &verifier).expect("no link exists yet");
    let second =
        provision(&before, &mut allocator, connection(1), &verifier).expect("no link exists yet");

    // The index on the projection is why the writer cannot accept both. It is
    // first-wins: appending both leaves one record and records the loser as a conflict,
    // rather than failing every read of the log that follows the race.
    let both = vec![log[0].clone(), first.event.clone(), second.event.clone()];
    let poisoned = Projection::fold(&both).expect("a race does not make the log unreadable");
    let key = ExternalKey {
        organization_id: organization(10),
        issuer: Issuer::new(ISSUER_ONE),
        subject: ExternalSubject::new(SUBJECT),
    };
    assert_eq!(
        poisoned.links().len(),
        2,
        "both records are materialized; the key resolves to one of them"
    );
    assert_eq!(
        poisoned.link(&key).map(|link| link.principal_id),
        Some(first.principal_id),
        "the first writer's record is the one that resolves"
    );
    assert_eq!(poisoned.conflicts().len(), 1);
    assert_eq!(poisoned.conflicts()[0].key, key);
    assert_eq!(
        poisoned.conflicts()[0].external_principal_id,
        second.external_principal_id
    );

    // The writer appends the first and re-evaluates the second against what it wrote.
    log.push(first.event);
    let after = Projection::fold(&log).expect("one link");
    let denied = provision(&after, &mut allocator, connection(1), &verifier)
        .expect_err("the composite key already exists");
    assert_eq!(denied.reason, DenialReason::Denied);
    assert_eq!(denied.clause, DenialClause::ExternalKeyExists);
    assert_eq!(after.links().len(), 1, "one record");

    // The denied caller retries authentication and succeeds against the survivor.
    let mut sessions = RecordingSessionIssuer::new();
    let authenticated = authenticate(&after, connection(1), &verifier, &mut sessions)
        .expect("the retried authentication resolves the surviving record");
    assert_eq!(authenticated.principal_id, first.principal_id);
    assert_ne!(
        first.external_principal_id, second.external_principal_id,
        "the two callers minted distinct identities; only one is recorded"
    );
    assert_eq!(sessions.issued().len(), 1);
}

/// A revoked link still holds its composite key.
///
/// `DenialClause::LinkAbsent` names two conditions — never linked, and linked and then
/// revoked — and `decision-blocker:jit-provisioning`'s composition provisions on it. The
/// two are told apart by what `ProvisionExternalPrincipal` decides: `ExternalKeyExists`
/// is refused for a key **any** record holds, in any lifecycle state, so the composition
/// that provisions on the clause creates nothing on a key whose record reached the
/// terminal `Unlinked` state of `mandate.federation.UnlinkExternalPrincipal`.
///
/// Without it the next login after an unlink mints a **new** `PrincipalId` for the same
/// external subject: the revoked caller returns as a different principal, which is not a
/// revocation and which nothing downstream can correlate to the principal that was
/// revoked.
#[test]
fn a_revoked_link_still_holds_its_key_at_provisioning() {
    let log = vec![
        created(
            connection(1),
            organization(10),
            ISSUER_ONE,
            unconditional(organization(10)),
            true,
        ),
        linked(connection(1), organization(10), SUBJECT, principal(0x21)),
        FederationEvent::ExternalPrincipalUnlinked {
            context: context(organization(10)),
            id: mandate_types::ExternalPrincipalId::new(uuid(0x71)),
        },
    ];
    let projection = Projection::fold(&log).expect("one connection, one revoked link");
    let verifier = admitting(proof_for(ISSUER_ONE, SUBJECT));
    let mut sessions = RecordingSessionIssuer::new();
    let mut allocator = SequentialAllocator::new();

    // The login the composition provisions on: the revoked record is not an explicitly
    // linked principal, so the clause is the same one a never-linked subject gets.
    let denied = authenticate(&projection, connection(1), &verifier, &mut sessions)
        .expect_err("the link reached its terminal state");
    assert_eq!(denied.reason, DenialReason::Denied);
    assert_eq!(denied.clause, DenialClause::LinkAbsent);
    assert!(sessions.issued().is_empty(), "no session was issued");

    // And the provisioning that composition would reach for is refused.
    let refused = provision(&projection, &mut allocator, connection(1), &verifier)
        .expect_err("a record holds this key, whatever state it is in");
    assert_eq!(refused.reason, DenialReason::Denied);
    assert_eq!(refused.clause, DenialClause::ExternalKeyExists);
    assert_eq!(
        projection.links().len(),
        1,
        "the revoked record is the only record on the key, and no second was created"
    );
}

/// Every lifecycle state `mandate.federation.ExternalPrincipal.State` declares, as the
/// [`LinkState`] value this crate holds for it.
///
/// **Read off the contract, not written out here.** A list written out here is extended by
/// widening a `match` arm — which satisfies the compiler and covers nothing, because the
/// loop that drives the command still iterates the old list. Reading the declaration means
/// a state added to it arrives in that loop without anyone remembering to add it, and the
/// mapping below refuses the run *by name* until the case says which value the state is.
/// The guard has to force the coverage, not the edit.
fn declared_link_states() -> Vec<LinkState> {
    const IR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../generated/ir/system.json"
    );
    const ELEMENT: &str = "mandate.federation.ExternalPrincipal.State";

    let text = std::fs::read_to_string(IR).expect("the generated IR is readable");
    let ir: serde_json::Value = serde_json::from_str(&text).expect("the generated IR is JSON");
    let body = &ir["types"][ELEMENT]["body"];
    assert_eq!(
        body["kind"], "enum",
        "{ELEMENT} is an enum in the generated IR"
    );
    let declared = body["variants"]
        .as_array()
        .unwrap_or_else(|| panic!("{ELEMENT} declares a variant list"));
    let states: Vec<LinkState> = declared
        .iter()
        .map(|variant| {
            let name = variant
                .as_str()
                .unwrap_or_else(|| panic!("{ELEMENT}: a declared variant name is a string"));
            match name {
                "Linked" => LinkState::Linked,
                "Unlinked" => LinkState::Unlinked,
                other => panic!(
                    "{ELEMENT} declares `{other}`, which this case holds no `LinkState` for. \
                     Name it here and every loop driven off this list covers it; leaving it \
                     out is how a state escapes a guard that only forces an edit."
                ),
            }
        })
        .collect();
    assert!(
        states.len() >= 2,
        "{ELEMENT} declares at least the initial and terminal states, got {states:?}"
    );
    states
}

/// A record in **any** lifecycle state holds its key at provisioning.
///
/// The loop is driven by [`declared_link_states`], so the states it covers are the states
/// the contract declares. `ProvisionExternalPrincipal` asks whether the key is free to
/// create a record on, and no lifecycle state makes a key that has a record free — the
/// terminal `Unlinked` one least of all, since that is the state
/// `mandate.federation.UnlinkExternalPrincipal` moves a revoked link to.
#[test]
fn a_record_in_any_lifecycle_state_holds_the_key_at_provisioning() {
    /// A store that answers one record for every key, in whatever state the case built.
    /// `LinkStore::records_on_key` requires exactly this: every record on the key, in
    /// every lifecycle state.
    struct OneRow(ExternalPrincipal);

    impl LinkStore for OneRow {
        fn records_on_key(&self, _key: &ExternalKey) -> Vec<ExternalPrincipal> {
            vec![self.0.clone()]
        }
    }

    let states = declared_link_states();

    let log = vec![created(
        connection(1),
        organization(10),
        ISSUER_ONE,
        unconditional(organization(10)),
        true,
    )];
    let projection = Projection::fold(&log).expect("one connection");
    let verifier = admitting(proof_for(ISSUER_ONE, SUBJECT));

    for state in states {
        let links = OneRow(ExternalPrincipal {
            id: mandate_types::ExternalPrincipalId::new(uuid(0x71)),
            organization_id: organization(10),
            subject: ExternalSubject::new(SUBJECT),
            principal_id: principal(0x21),
            connection_id: connection(1),
            link_method: ExternalLinkMethod::Administrator,
            linked_at: linked_at(),
            state,
        });
        let mut allocator = SequentialAllocator::new();

        let outcome = provision_external_principal(
            &ProvisionExternalPrincipal {
                connection_id: connection(1),
                proof: presented(),
            },
            &request(),
            &verifier,
            &projection,
            &links,
            &mut allocator,
        );
        let refused = match outcome {
            Ok(provisioned) => {
                panic!("a record in state {state:?} holds this key: {provisioned:?}")
            }
            Err(refused) => refused,
        };

        assert_eq!(refused.reason, DenialReason::Denied, "state {state:?}");
        assert_eq!(
            refused.clause,
            DenialClause::ExternalKeyExists,
            "state {state:?}"
        );
    }
}

/// `federation.yaml:210`: "Connection is disabled/untrusted". No corpus case covers it;
/// the branch exists because `FederationConnection` declares the state.
#[test]
fn a_disabled_connection_denies() {
    let log = vec![
        created(
            connection(1),
            organization(10),
            ISSUER_ONE,
            unconditional(organization(10)),
            true,
        ),
        linked(connection(1), organization(10), SUBJECT, principal(0x21)),
        FederationEvent::FederationConnectionDisabled {
            context: context(organization(10)),
            id: connection(1),
        },
    ];
    let projection = Projection::fold(&log).expect("one connection, one link");
    let verifier = admitting(proof_for(ISSUER_ONE, SUBJECT));
    let mut allocator = SequentialAllocator::new();
    let mut sessions = RecordingSessionIssuer::new();

    let denied = authenticate(&projection, connection(1), &verifier, &mut sessions)
        .expect_err("the connection is disabled");
    assert_eq!(denied.clause, DenialClause::ConnectionDisabled);
    assert!(sessions.issued().is_empty());

    let refused = provision(&projection, &mut allocator, connection(1), &verifier)
        .expect_err("the connection is disabled");
    assert_eq!(refused.clause, DenialClause::ConnectionDisabled);
}

/// A connection the command names and the read model does not hold resolves nothing.
#[test]
fn an_unresolved_connection_denies() {
    let projection = Projection::fold(&[]).expect("an empty log");
    let mut sessions = RecordingSessionIssuer::new();

    let denied = authenticate(
        &projection,
        connection(1),
        &admitting(proof_for(ISSUER_ONE, SUBJECT)),
        &mut sessions,
    )
    .expect_err("there is no such connection");

    assert_eq!(denied.clause, DenialClause::ConnectionUnknown);
}

/// A proof the verifier refuses stops the resolution order at step 3.
#[test]
fn a_refused_proof_denies() {
    let log = vec![created(
        connection(1),
        organization(10),
        ISSUER_ONE,
        unconditional(organization(10)),
        true,
    )];
    let projection = Projection::fold(&log).expect("one connection");
    let verifier =
        ConstructedVerifier::refusing(&[SigningAlgorithm::new("configured-by-deployment")])
            .expect("a non-empty allowlist is admitted");
    let mut sessions = RecordingSessionIssuer::new();

    let denied = authenticate(&projection, connection(1), &verifier, &mut sessions)
        .expect_err("the verifier refused the proof");

    assert_eq!(denied.reason, DenialReason::InvalidCredential);
    assert_eq!(denied.clause, DenialClause::ProofInvalid);
    assert!(sessions.issued().is_empty());
}

/// Step 2: the validated issuer must be the connection's configured issuer.
#[test]
fn an_issuer_that_is_not_the_connections_denies() {
    let log = vec![created(
        connection(1),
        organization(10),
        ISSUER_ONE,
        unconditional(organization(10)),
        true,
    )];
    let projection = Projection::fold(&log).expect("one connection");
    let mut sessions = RecordingSessionIssuer::new();

    let denied = authenticate(
        &projection,
        connection(1),
        &admitting(proof_for(ISSUER_TWO, SUBJECT)),
        &mut sessions,
    )
    .expect_err("the validated issuer is another issuer");

    assert_eq!(denied.reason, DenialReason::InvalidCredential);
    assert_eq!(denied.clause, DenialClause::IssuerMismatch);
}

/// Step 4: the validated audience must be the connection's configured client.
#[test]
fn an_audience_that_is_not_the_configured_client_denies() {
    let log = vec![created(
        connection(1),
        organization(10),
        ISSUER_ONE,
        unconditional(organization(10)),
        true,
    )];
    let projection = Projection::fold(&log).expect("one connection");
    let mut sessions = RecordingSessionIssuer::new();
    let proof = VerifiedProof::new(
        Issuer::new(ISSUER_ONE),
        ExternalSubject::new(SUBJECT),
        ClientId::new("another-client"),
    );

    let denied = authenticate(&projection, connection(1), &admitting(proof), &mut sessions)
        .expect_err("the validated audience is another client");

    assert_eq!(denied.reason, DenialReason::AudienceMismatch);
    assert_eq!(denied.clause, DenialClause::AudienceBinding);
}

/// The link the authentication resolves must be one the same key resolves.
#[test]
fn a_link_under_another_subject_is_not_this_subjects_link() {
    let log = vec![
        created(
            connection(1),
            organization(10),
            ISSUER_ONE,
            unconditional(organization(10)),
            false,
        ),
        linked(
            connection(1),
            organization(10),
            "another-subject",
            principal(0x21),
        ),
    ];
    let projection = Projection::fold(&log).expect("one connection, one link");
    let key = ExternalKey {
        organization_id: organization(10),
        issuer: Issuer::new(ISSUER_ONE),
        subject: ExternalSubject::new(SUBJECT),
    };
    assert!(projection.link(&key).is_none());
    let mut sessions = RecordingSessionIssuer::new();

    let denied = authenticate(
        &projection,
        connection(1),
        &admitting(proof_for(ISSUER_ONE, SUBJECT)),
        &mut sessions,
    )
    .expect_err("this subject has no link");

    assert_eq!(denied.clause, DenialClause::LinkAbsent);
    assert!(sessions.issued().is_empty());
}

/// The empty string is not an external subject. `provision_external_principal` is the
/// adversary's case; the same key component reaches `authenticate_federation`.
#[test]
fn an_empty_validated_subject_is_refused_at_authentication() {
    let log = vec![created(
        connection(1),
        organization(10),
        ISSUER_ONE,
        unconditional(organization(10)),
        true,
    )];
    let projection = Projection::fold(&log).expect("one connection");
    let mut sessions = RecordingSessionIssuer::new();

    for subject in ["", "   "] {
        let denied = authenticate(
            &projection,
            connection(1),
            &admitting(proof_for(ISSUER_ONE, subject)),
            &mut sessions,
        )
        .expect_err("an empty validated subject collapses the canonical key");

        assert_eq!(denied.reason, DenialReason::InvalidCredential);
        assert_eq!(denied.clause, DenialClause::EmptySubject);
    }
    assert!(sessions.issued().is_empty());
}

/// The selected connection's own rule is the binding, not any rule of any connection on
/// the issuer. The adversary's case proves the hole; this one pins the boundary that a
/// second matching connection of the *same* organization does not rescue a proof.
#[test]
fn the_selected_connections_rule_must_match_even_when_a_sibling_matches() {
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
        linked(connection(1), organization(10), SUBJECT, principal(0x21)),
    ];
    let projection = Projection::fold(&log).expect("two connections, one link");
    let mut sessions = RecordingSessionIssuer::new();

    let denied = authenticate(
        &projection,
        connection(1),
        &admitting(proof_for(ISSUER_ONE, SUBJECT).with_verified_claim("dept", "engineering")),
        &mut sessions,
    )
    .expect_err("connection 1 requires org=acme, which this proof does not carry");

    assert_eq!(denied.reason, DenialReason::TenantMismatch);
    assert_eq!(denied.clause, DenialClause::TenantZero);
    assert!(sessions.issued().is_empty());

    // The sibling connection, whose rule the proof does satisfy, still authenticates.
    let through_sibling = authenticate(
        &projection,
        connection(2),
        &admitting(proof_for(ISSUER_ONE, SUBJECT).with_verified_claim("dept", "engineering")),
        &mut sessions,
    );
    assert!(
        through_sibling.is_ok(),
        "the connection whose rule matches resolves: {through_sibling:?}"
    );
}

/// J1: an explicitly linked principal that the identity domain has disabled is not an
/// authenticated context. The link survives disablement; the session must not.
#[test]
fn a_disabled_linked_principal_is_denied_a_session() {
    let log = vec![
        created(
            connection(1),
            organization(10),
            ISSUER_ONE,
            unconditional(organization(10)),
            false,
        ),
        linked(connection(1), organization(10), SUBJECT, principal(0x21)),
    ];
    let projection = Projection::fold(&log).expect("one connection, one link");
    let connections = RecordedPrincipals::over(projection.clone()).with_principal(
        principal(0x21),
        organization(10),
        PrincipalState::Disabled,
    );
    let mut sessions = RecordingSessionIssuer::new();

    let denied = authenticate_federation(
        &AuthenticateFederation {
            connection_id: connection(1),
            proof: presented(),
        },
        &request(),
        &admitting(proof_for(ISSUER_ONE, SUBJECT)),
        &connections,
        &projection,
        &mut sessions,
    )
    .expect_err("the linked principal is disabled");

    assert_eq!(denied.reason, DenialReason::Denied);
    assert_eq!(denied.clause, DenialClause::PrincipalDisabled);
    assert!(
        sessions.issued().is_empty(),
        "no session for a disabled principal"
    );
}

/// R3/J4: the validated subject is refused when it is not its own trim, on the
/// proof-driven path as well.
#[test]
fn a_validated_subject_that_is_not_its_own_trim_is_refused() {
    let log = vec![created(
        connection(1),
        organization(10),
        ISSUER_ONE,
        unconditional(organization(10)),
        true,
    )];
    let projection = Projection::fold(&log).expect("one connection");
    let mut sessions = RecordingSessionIssuer::new();
    let mut allocator = SequentialAllocator::new();

    for subject in [" subject-one", "subject-one "] {
        let denied = authenticate(
            &projection,
            connection(1),
            &admitting(proof_for(ISSUER_ONE, subject)),
            &mut sessions,
        )
        .expect_err("the validated subject is not the subject as issued");
        assert_eq!(denied.reason, DenialReason::InvalidCredential);
        assert_eq!(denied.clause, DenialClause::SubjectNotTrimmed);

        let refused = provision(
            &projection,
            &mut allocator,
            connection(1),
            &admitting(proof_for(ISSUER_ONE, subject)),
        )
        .expect_err("the validated subject is not the subject as issued");
        assert_eq!(refused.clause, DenialClause::SubjectNotTrimmed);
    }
    assert!(sessions.issued().is_empty());
}

/// R2: `jit_provisioning` gates creation only. An existing link authenticates through
/// any enabled connection of the organization on that issuer whose rule the proof
/// satisfies, including one that refuses provisioning.
#[test]
fn a_jit_refusing_connection_still_authenticates_an_existing_link() {
    let log = vec![
        created(
            connection(1),
            organization(10),
            ISSUER_ONE,
            unconditional(organization(10)),
            false,
        ),
        linked(connection(1), organization(10), SUBJECT, principal(0x21)),
    ];
    let projection = Projection::fold(&log).expect("one connection, one link");
    let verifier = admitting(proof_for(ISSUER_ONE, SUBJECT));
    let mut sessions = RecordingSessionIssuer::new();
    let mut allocator = SequentialAllocator::new();

    let authenticated = authenticate(&projection, connection(1), &verifier, &mut sessions)
        .expect("an existing link is not a first login");
    assert_eq!(authenticated.principal_id, principal(0x21));

    let refused = provision(&projection, &mut allocator, connection(1), &verifier)
        .expect_err("this connection creates nothing");
    assert_eq!(refused.clause, DenialClause::ProvisioningNotAdmitted);
}
