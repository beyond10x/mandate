//! What each handler emits, decided against the contract rather than against this file.
//!
//! Every accepted outcome is put through the three checks
//! `crates/mandate-testkit/src/contract.rs` performs, each reading a generated projection
//! and nothing else:
//!
//! - `assert_event_conforms` validates the emitted payload against
//!   `generated/schema/events/<name>.schema.json`, which closes the key set and decides
//!   every declared lexical form.
//! - `assert_single_emission` reads `generated/ir/system.json`: an accepted outcome emits
//!   exactly the one event the contract declares for it, and an error outcome emits none.
//! - `assert_payload_sources` reads the same file and decides every payload field against
//!   the source the contract declares for it — `input_field` against the command input,
//!   `response_field` against what the handler returned, `literal` against the value the
//!   contract names.
//!
//! The denied paths are checked the same way and in the same breath: the refusal names
//! the outcome it is ([`mandate_federation::RefusedOutcome`]), that outcome is looked up
//! in the IR, and the emission list handed to the harness is empty — so "a denial emits
//! nothing" is decided against the contract's declaration of that outcome and not against
//! a sentence here. Each denied case also folds the log again and asserts the projection
//! is the one it was before, which is `mandate.federation.Denied`'s "no credential,
//! authority or lifecycle mutation on refusal" in the only form a fold can carry.

use mandate_federation::authenticate::{
    AuthenticateFederation, ProvisionExternalPrincipal, authenticate_federation,
    provision_external_principal,
};
use mandate_federation::disable::{
    DisableFederationConnection, DisableOAuthClient, UnlinkExternalPrincipal,
    disable_federation_connection, disable_oauth_client, unlink_external_principal,
};
use mandate_federation::link::{LinkExternalPrincipal, link_external_principal};
use mandate_federation::publicclient::RecordedClients;
use mandate_federation::record::{
    FederationEvent, OAuthClient, OAuthClientState, Projection, RegisterFederationConnection,
    register_federation_connection,
};
use mandate_federation::verifier::{ConstructedVerifier, VerifiedProof};
use mandate_federation::{
    Denied, PrincipalState, RecordedPrincipals, RecordingSessionIssuer, RequestContext,
    SequentialAllocator,
};
use mandate_model::TenantResolutionRule;
use mandate_testkit::contract::{
    assert_event_conforms, assert_payload_sources, assert_single_emission,
};
use mandate_types::value::Uuid;
use mandate_types::{
    Audience, ClientId, CorrelationId, CredentialId, CredentialProof, ExternalLinkMethod,
    ExternalPrincipalId, ExternalSubject, FederationConnectionId, Issuer, OAuthClientId,
    OrganizationId, PkceMethod, PrincipalId, RedirectUri, SigningAlgorithm, Timestamp,
    VerifiedContext,
};
use serde::Serialize;
use serde_json::{Value, json};

const REGISTER: &str = "mandate.federation.RegisterFederationConnection";
const LINK: &str = "mandate.federation.LinkExternalPrincipal";
const AUTHENTICATE: &str = "mandate.federation.AuthenticateFederation";
const PROVISION: &str = "mandate.federation.ProvisionExternalPrincipal";
const DISABLE_CONNECTION: &str = "mandate.federation.DisableFederationConnection";
const UNLINK: &str = "mandate.federation.UnlinkExternalPrincipal";
const DISABLE_CLIENT: &str = "mandate.federation.DisableOAuthClient";

const ISSUER: &str = "https://idp.example";
const SUBJECT: &str = "subject-one";

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization(tag: u8) -> OrganizationId {
    OrganizationId::new(uuid(tag))
}

fn principal(tag: u8) -> PrincipalId {
    PrincipalId::new(uuid(tag))
}

fn external_principal(tag: u8) -> ExternalPrincipalId {
    ExternalPrincipalId::new(uuid(tag))
}

fn client(tag: u8) -> OAuthClientId {
    OAuthClientId::new(uuid(tag))
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
        correlation: CorrelationId::new("federation-alignment"),
    }
}

fn request() -> RequestContext {
    RequestContext {
        audience: Audience::new("mandate"),
        correlation: CorrelationId::new("federation-alignment"),
        credential: CredentialId::new(uuid(0xcd)),
        at: Timestamp::new("2026-09-19T00:00:00Z"),
    }
}

fn unconditional(organization_id: OrganizationId) -> TenantResolutionRule {
    TenantResolutionRule {
        configured_organization: organization_id,
        verified_claim_name: None,
        verified_claim_value: None,
    }
}

fn encoded<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("a declared value encodes as JSON")
}

/// The one admitted proof every proof-driven case here is verified with.
fn admitting() -> ConstructedVerifier {
    ConstructedVerifier::admitting(
        &[SigningAlgorithm::new("declared-by-deployment")],
        VerifiedProof::new(
            Issuer::new(ISSUER),
            ExternalSubject::new(SUBJECT),
            ClientId::new("configured-client"),
        ),
    )
    .expect("a non-empty allowlist")
}

/// One accepted outcome, through all three checks.
///
/// `response` is built from what the handler returned, never from the event: the whole
/// point of the source check is that the two agree.
fn accepted(command: &str, input: &Value, response: Option<&Value>, event: &FederationEvent) {
    let payload = encoded(event);
    let name = event.ess_name();
    assert_single_emission(command, "accepted", &[(name, &payload)]);
    assert_event_conforms(name, &payload);
    assert_payload_sources(command, input, response, name, &payload);
}

/// One refused outcome: the outcome the refusal names is declared by the contract, and
/// it emitted nothing.
fn refused(command: &str, denied: &Denied) {
    assert_single_emission(command, denied.outcome.ir_name(), &[]);
}

/// A connection registered by the real handler: the fold, the log its event makes, and
/// the identity the allocator minted for it — which is the response field the event's
/// `connection_id` is sourced from, so no case may name an identity of its own.
fn registered(
    organization_id: OrganizationId,
) -> (Projection, Vec<FederationEvent>, FederationConnectionId) {
    let mut allocator = SequentialAllocator::new();
    let input = RegisterFederationConnection {
        context: context(organization_id),
        issuer: Issuer::new(ISSUER),
        client_id: ClientId::new("configured-client"),
        tenant_resolution: unconditional(organization_id),
        jit_provisioning: true,
    };
    let outcome = register_federation_connection(&input, &Projection::default(), &mut allocator)
        .expect("the organization binding is the caller's own");
    let log = vec![outcome.event];
    (
        Projection::fold(&log).expect("one creation"),
        log,
        outcome.connection_id,
    )
}

#[test]
fn register_federation_connection_emits_exactly_the_declared_event() {
    let mut allocator = SequentialAllocator::new();
    let input = RegisterFederationConnection {
        context: context(organization(10)),
        issuer: Issuer::new(ISSUER),
        client_id: ClientId::new("configured-client"),
        tenant_resolution: unconditional(organization(10)),
        jit_provisioning: true,
    };

    let outcome = register_federation_connection(&input, &Projection::default(), &mut allocator)
        .expect("the organization binding is the caller's own");

    accepted(
        REGISTER,
        &encoded(&input),
        Some(&json!({"connection_id": encoded(&outcome.connection_id)})),
        &outcome.event,
    );
}

#[test]
fn a_refused_registration_emits_nothing_and_leaves_the_fold_unchanged() {
    let (held, log, _) = registered(organization(10));
    let mut allocator = SequentialAllocator::new();
    // "organization binding is invalid": the rule resolves to an organization other than
    // the caller's verified one.
    let input = RegisterFederationConnection {
        context: context(organization(10)),
        issuer: Issuer::new(ISSUER),
        client_id: ClientId::new("configured-client"),
        tenant_resolution: unconditional(organization(11)),
        jit_provisioning: true,
    };

    let denied = register_federation_connection(&input, &held, &mut allocator)
        .expect_err("the rule names another organization");

    refused(REGISTER, &denied);
    assert_eq!(
        Projection::fold(&log).expect("the same log"),
        held,
        "a refusal writes no event, so the fold is the one it was"
    );
}

#[test]
fn link_external_principal_emits_exactly_the_declared_event() {
    let (held, _, connection_id) = registered(organization(10));
    let links = RecordedPrincipals::over(held).with_principal(
        principal(0x21),
        organization(10),
        PrincipalState::Active,
    );
    let mut allocator = SequentialAllocator::new();
    let input = LinkExternalPrincipal {
        context: context(organization(10)),
        connection_id,
        external_subject: ExternalSubject::new(SUBJECT),
        principal_id: principal(0x21),
        method: ExternalLinkMethod::Administrator,
    };

    let outcome = link_external_principal(&input, &request(), &links, &links, &mut allocator)
        .expect("an administrative link inside the connection's organization");

    accepted(
        LINK,
        &encoded(&input),
        Some(&json!({"external_principal_id": encoded(&outcome.external_principal_id)})),
        &outcome.event,
    );
}

#[test]
fn a_refused_link_emits_nothing_and_leaves_the_fold_unchanged() {
    let (held, log, connection_id) = registered(organization(10));
    let links = RecordedPrincipals::over(held.clone()).with_principal(
        principal(0x21),
        organization(10),
        PrincipalState::Active,
    );
    let mut allocator = SequentialAllocator::new();
    // "Caller/method lacks linking authority": `ConfiguredFederation` is the method the
    // provisioning command writes, and a caller may not name it here.
    let input = LinkExternalPrincipal {
        context: context(organization(10)),
        connection_id,
        external_subject: ExternalSubject::new(SUBJECT),
        principal_id: principal(0x21),
        method: ExternalLinkMethod::ConfiguredFederation,
    };

    let denied = link_external_principal(&input, &request(), &links, &links, &mut allocator)
        .expect_err("the method is not one this command may use");

    refused(LINK, &denied);
    assert_eq!(Projection::fold(&log).expect("the same log"), held);
}

#[test]
fn authenticate_federation_emits_exactly_the_declared_event() {
    let (held, log, connection_id) = registered(organization(10));
    let mut allocator = SequentialAllocator::new();
    let principals = RecordedPrincipals::over(held).with_principal(
        principal(0x21),
        organization(10),
        PrincipalState::Active,
    );
    let link = link_external_principal(
        &LinkExternalPrincipal {
            context: context(organization(10)),
            connection_id,
            external_subject: ExternalSubject::new(SUBJECT),
            principal_id: principal(0x21),
            method: ExternalLinkMethod::Administrator,
        },
        &request(),
        &principals,
        &principals,
        &mut allocator,
    )
    .expect("the link is recorded first");
    let mut log = log;
    log.push(link.event);
    let held = Projection::fold(&log).expect("a creation and a link");
    let mut sessions = RecordingSessionIssuer::new();
    let input = AuthenticateFederation {
        connection_id,
        proof: CredentialProof::from_bytes(b"proof".to_vec()),
    };

    let outcome = authenticate_federation(
        &input,
        &request(),
        &admitting(),
        &RecordedPrincipals::over(held),
        &Projection::fold(&log).expect("the same log"),
        &mut sessions,
    )
    .expect("a validated proof resolving to an explicit link");

    accepted(
        AUTHENTICATE,
        &encoded(&input),
        Some(&json!({
            "session_id": encoded(&outcome.session_id),
            "principal_id": encoded(&outcome.principal_id),
            "organization_id": encoded(&outcome.organization_id),
            "epochs": encoded(&outcome.epochs),
            "expires_at": encoded(&outcome.expires_at),
        })),
        &outcome.event,
    );
}

#[test]
fn a_refused_authentication_emits_nothing_issues_no_session_and_leaves_the_fold_unchanged() {
    let (held, log, connection_id) = registered(organization(10));
    let mut sessions = RecordingSessionIssuer::new();
    let input = AuthenticateFederation {
        connection_id,
        proof: CredentialProof::from_bytes(b"proof".to_vec()),
    };

    // "principal linking is absent/conflicting": nothing linked this subject.
    let denied = authenticate_federation(
        &input,
        &request(),
        &admitting(),
        &RecordedPrincipals::over(held.clone()),
        &held,
        &mut sessions,
    )
    .expect_err("no link resolves the composite key");

    refused(AUTHENTICATE, &denied);
    assert!(
        sessions.issued().is_empty(),
        "a denial mints no session (`mandate.federation.Denied`)"
    );
    assert_eq!(Projection::fold(&log).expect("the same log"), held);
}

#[test]
fn provision_external_principal_emits_exactly_the_declared_event() {
    let (held, _, connection_id) = registered(organization(10));
    let mut allocator = SequentialAllocator::new();
    let input = ProvisionExternalPrincipal {
        connection_id,
        proof: CredentialProof::from_bytes(b"proof".to_vec()),
    };

    let outcome = provision_external_principal(
        &input,
        &request(),
        &admitting(),
        &held,
        &held,
        &mut allocator,
    )
    .expect("the connection admits provisioning and the key is free");

    accepted(
        PROVISION,
        &encoded(&input),
        Some(&json!({
            "external_principal_id": encoded(&outcome.external_principal_id),
            "principal_id": encoded(&outcome.principal_id),
            "organization_id": encoded(&organization(10)),
            "subject": encoded(&outcome.subject),
            "display_name": outcome.display_name,
        })),
        &outcome.event,
    );
}

#[test]
fn a_refused_provisioning_emits_nothing_and_leaves_the_fold_unchanged() {
    // A connection that does not admit provisioning "denies the first login and creates
    // nothing" (`federation.yaml:4`).
    let mut allocator = SequentialAllocator::new();
    let registration = register_federation_connection(
        &RegisterFederationConnection {
            context: context(organization(10)),
            issuer: Issuer::new(ISSUER),
            client_id: ClientId::new("configured-client"),
            tenant_resolution: unconditional(organization(10)),
            jit_provisioning: false,
        },
        &Projection::default(),
        &mut allocator,
    )
    .expect("the organization binding is the caller's own");
    let log = vec![registration.event];
    let held = Projection::fold(&log).expect("one creation");
    let input = ProvisionExternalPrincipal {
        connection_id: registration.connection_id,
        proof: CredentialProof::from_bytes(b"proof".to_vec()),
    };

    let denied = provision_external_principal(
        &input,
        &request(),
        &admitting(),
        &held,
        &held,
        &mut allocator,
    )
    .expect_err("the connection does not admit provisioning");

    refused(PROVISION, &denied);
    assert_eq!(Projection::fold(&log).expect("the same log"), held);
}

#[test]
fn disable_federation_connection_emits_exactly_the_declared_event() {
    let (held, _, connection_id) = registered(organization(10));
    let input = DisableFederationConnection {
        context: context(organization(10)),
        id: connection_id,
    };

    let event =
        disable_federation_connection(&input, &held).expect("an enabled connection of this tenant");

    accepted(DISABLE_CONNECTION, &encoded(&input), None, &event);
}

#[test]
fn a_refused_disable_emits_nothing_and_leaves_the_fold_unchanged() {
    let (held, log, connection_id) = registered(organization(10));

    // The declared `denied` outcome: the connection is outside the verified organization.
    let outside = disable_federation_connection(
        &DisableFederationConnection {
            context: context(organization(11)),
            id: connection_id,
        },
        &held,
    )
    .expect_err("the connection belongs to another organization");
    refused(DISABLE_CONNECTION, &outside);

    // The declared `wrong-state` outcome: `disable` starts from `Enabled` alone, so a
    // connection already in the terminal state is in a state no declared move leaves.
    let disabled = disable_federation_connection(
        &DisableFederationConnection {
            context: context(organization(10)),
            id: connection_id,
        },
        &held,
    )
    .expect("the first disable is accepted");
    let mut moved = log.clone();
    moved.push(disabled);
    let moved_fold = Projection::fold(&moved).expect("a creation and a disable");

    let again = disable_federation_connection(
        &DisableFederationConnection {
            context: context(organization(10)),
            id: connection_id,
        },
        &moved_fold,
    )
    .expect_err("`Disabled` is terminal");

    refused(DISABLE_CONNECTION, &again);
    assert_eq!(
        Projection::fold(&moved).expect("the same log"),
        moved_fold,
        "a refusal writes no event, so the fold is the one it was"
    );
}

#[test]
fn unlink_external_principal_emits_exactly_the_declared_event() {
    let (held, log, connection_id) = registered(organization(10));
    let mut allocator = SequentialAllocator::new();
    let principals = RecordedPrincipals::over(held).with_principal(
        principal(0x21),
        organization(10),
        PrincipalState::Active,
    );
    let link = link_external_principal(
        &LinkExternalPrincipal {
            context: context(organization(10)),
            connection_id,
            external_subject: ExternalSubject::new(SUBJECT),
            principal_id: principal(0x21),
            method: ExternalLinkMethod::Administrator,
        },
        &request(),
        &principals,
        &principals,
        &mut allocator,
    )
    .expect("the link is recorded first");
    let mut log = log;
    log.push(link.event);
    let held = Projection::fold(&log).expect("a creation and a link");
    let input = UnlinkExternalPrincipal {
        context: context(organization(10)),
        id: link.external_principal_id,
    };

    let event = unlink_external_principal(&input, &held).expect("a linked record of this tenant");

    accepted(UNLINK, &encoded(&input), None, &event);
}

#[test]
fn a_refused_unlink_emits_nothing_and_leaves_the_fold_unchanged() {
    let (held, log, _) = registered(organization(10));

    // The declared `denied` outcome: the link is not recorded at all.
    let unknown = unlink_external_principal(
        &UnlinkExternalPrincipal {
            context: context(organization(10)),
            id: external_principal(0x71),
        },
        &held,
    )
    .expect_err("no event created this link");

    refused(UNLINK, &unknown);
    assert_eq!(Projection::fold(&log).expect("the same log"), held);
}

#[test]
fn disable_oauth_client_emits_exactly_the_declared_event() {
    let clients = RecordedClients::new().with_client(OAuthClient {
        id: client(0x0c),
        organization_id: organization(10),
        public: true,
        redirect_uris: vec![RedirectUri::new("https://app.example/callback")],
        pkce_method: PkceMethod::S256,
        state: OAuthClientState::Recorded,
    });
    let input = DisableOAuthClient {
        context: context(organization(10)),
        id: client(0x0c),
    };

    let event = disable_oauth_client(&input, &clients).expect("a recorded client of this tenant");

    accepted(DISABLE_CLIENT, &encoded(&input), None, &event);
}

#[test]
fn a_refused_client_disable_emits_nothing() {
    let clients = RecordedClients::new().with_client(OAuthClient {
        id: client(0x0c),
        organization_id: organization(10),
        public: true,
        redirect_uris: vec![RedirectUri::new("https://app.example/callback")],
        pkce_method: PkceMethod::S256,
        state: OAuthClientState::Disabled,
    });

    // The declared `wrong-state` outcome: `disable` starts from `Recorded` alone.
    let again = disable_oauth_client(
        &DisableOAuthClient {
            context: context(organization(10)),
            id: client(0x0c),
        },
        &clients,
    )
    .expect_err("`Disabled` is terminal");
    refused(DISABLE_CLIENT, &again);

    // The declared `denied` outcome: the client is outside the verified organization.
    let outside = disable_oauth_client(
        &DisableOAuthClient {
            context: context(organization(11)),
            id: client(0x0c),
        },
        &clients,
    )
    .expect_err("the client belongs to another organization");
    refused(DISABLE_CLIENT, &outside);
}
