//! Adversary pass **2** over the realization round of `story:declared-writers`, units A3
//! and A4, taken after correction round 1.
//!
//! Two lines of attack, and three probes that held.
//!
//! * **The two folds over one log, at the field the correction did not reach.** Pass 1's
//!   F3 was one half of this: `mandate_federation::record::Projection::apply` refused a
//!   `link_method` the contract does not pin and `mandate_identity`'s new arm did not, so
//!   one payload was "not the declared seeding event" to one fold and the seeding event to
//!   the other. The correction made `principal_of` enforce both pinned literals and closed
//!   that instance. It did not close the class: `record_link` in the same federation file
//!   reads an empty or untrimmed `subject` as a **corrupt log** — "an empty key component
//!   is not a key component; the commands refuse one, and a log written before they did is
//!   read as corrupt rather than collapsed" — and refuses the whole fold, while the
//!   identity fold materializes a `mandate.identity.Principal` out of the same event.
//!   `principal_of`'s own doc states the rule this breaks: "a payload that one fold calls
//!   'not the declared seeding event' is not a payload the other may materialize a record
//!   out of". This file is where that case can be written, because only
//!   `mandate-federation` can see both crates (`dependency-boundaries.json`).
//!
//! * **`public: false`.** Every case the unit wrote registers a public client. The
//!   contract sources `OAuthClientRegistered.public` from `input.public`, and
//!   `assert_payload_sources` decides that against the input a case supplies — so with
//!   `public: true` in every case, an implementation that wrote the literal `true` into
//!   the event instead of the input would pass the suite the unit shipped. This probe is
//!   the input value nothing in the tree supplies, carried through the real handler, the
//!   contract's own source check, the fold and the authorization refusal.
//!
//! The other probes are the surfaces correction 1 created: insert-if-absent answered with
//! a *differing* payload, the allocator after a refusal, and the cross-crate registry
//! claim the correction rests on.

use mandate_contract::events::MandateFederationExternalPrincipalProvisioned;
use mandate_contract::types::{
    MandateCoreCorrelationId, MandateCoreExternalLinkMethod, MandateCoreExternalPrincipalId,
    MandateCoreExternalSubject, MandateCoreFederationConnectionId, MandateCoreOrganizationId,
    MandateCorePrincipalId, MandateCorePrincipalKind,
};
use mandate_federation::publicclient::registered_public_client;
use mandate_federation::record::{FederationEvent, FoldError, OAuthClient, Projection};
use mandate_federation::register_client::{
    ConfiguredAdmission, OAuthClientRegistered, RegisterOAuthClient, register_o_auth_client,
};
use mandate_federation::{DenialClause, IdentityAllocator, SequentialAllocator};
use mandate_identity::{IdentityEvent, IdentityLog, IdentityRead};
use mandate_model::TenantResolutionRule;
use mandate_testkit::contract::{check_event_conforms, check_payload_sources};
use mandate_types::value::Uuid;
use mandate_types::{
    Audience, ClientId, CorrelationId, CredentialId, ExternalLinkMethod, ExternalPrincipalId,
    ExternalSubject, FederationConnectionId, Issuer, OrganizationId, PkceMethod, PrincipalId,
    PrincipalKind, RedirectUri, Timestamp, VerifiedContext,
};
use serde::Serialize;
use serde_json::{Value, json};

const REGISTER_CLIENT: &str = "mandate.federation.RegisterOAuthClient";
const REDIRECT: &str = "https://app.example/callback";
const DISPLAY_NAME: &str = "subject-one";
const AS_OF: &str = "2026-09-19T00:00:00Z";

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn declared(tag: u8) -> String {
    uuid(tag).to_string()
}

fn organization(tag: u8) -> OrganizationId {
    OrganizationId::new(uuid(tag))
}

fn administrator() -> PrincipalId {
    PrincipalId::new(uuid(0x51))
}

fn principal() -> PrincipalId {
    PrincipalId::new(uuid(1))
}

fn connection() -> FederationConnectionId {
    FederationConnectionId::new(uuid(4))
}

fn external_principal() -> ExternalPrincipalId {
    ExternalPrincipalId::new(uuid(0x71))
}

fn context(organization_id: OrganizationId) -> VerifiedContext {
    VerifiedContext {
        subject: administrator(),
        actor: None,
        organization: organization_id,
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("adversary-writers-2"),
    }
}

fn encoded<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("a declared value encodes as JSON")
}

/// The connection every provisioning below names, so the fold reaches the subject guard
/// rather than refusing for an unknown connection.
fn connection_created(organization_id: OrganizationId) -> FederationEvent {
    FederationEvent::FederationConnectionCreated {
        context: context(organization_id),
        connection_id: connection(),
        issuer: Issuer::new("https://idp.example"),
        client_id: ClientId::new("configured-client"),
        tenant_resolution: TenantResolutionRule {
            configured_organization: organization_id,
            verified_claim_name: None,
            verified_claim_value: None,
        },
        jit_provisioning: true,
    }
}

/// The seeding event as `mandate-federation` folds it: the crate's own typed payload.
fn provisioned_here(subject: &str) -> FederationEvent {
    FederationEvent::ExternalPrincipalProvisioned {
        organization_id: organization(2),
        correlation: CorrelationId::new("adversary-writers-2"),
        connection_id: connection(),
        principal_id: principal(),
        kind: PrincipalKind::User,
        display_name: DISPLAY_NAME.to_owned(),
        external_principal_id: external_principal(),
        subject: ExternalSubject::new(subject),
        link_method: ExternalLinkMethod::ConfiguredFederation,
        linked_at: Timestamp::new(AS_OF),
    }
}

/// The same event as `mandate-identity` folds it: the generated shape, carrying the same
/// values field for field.
fn provisioned_there(subject: &str) -> MandateFederationExternalPrincipalProvisioned {
    MandateFederationExternalPrincipalProvisioned {
        organization_id: MandateCoreOrganizationId(declared(2)),
        correlation: MandateCoreCorrelationId("adversary-writers-2".to_owned()),
        connection_id: MandateCoreFederationConnectionId(declared(4)),
        principal_id: MandateCorePrincipalId(declared(1)),
        kind: MandateCorePrincipalKind::User,
        display_name: DISPLAY_NAME.to_owned(),
        external_principal_id: MandateCoreExternalPrincipalId(declared(0x71)),
        subject: MandateCoreExternalSubject(subject.to_owned()),
        link_method: MandateCoreExternalLinkMethod::ConfiguredFederation,
        linked_at: AS_OF.to_owned(),
    }
}

/// An admission that admits the administrator, the organization and the one redirect URI.
fn admission(organization_id: OrganizationId) -> ConfiguredAdmission {
    ConfiguredAdmission::new()
        .with_administrator(administrator())
        .with_organization(organization_id)
        .with_redirect_uri(organization_id, RedirectUri::new(REDIRECT))
}

/// One accepted `RegisterOAuthClient`, through the real handler.
fn registered(
    organization_id: OrganizationId,
    public: bool,
    allocator: &mut SequentialAllocator,
) -> (RegisterOAuthClient, OAuthClientRegistered) {
    let input = RegisterOAuthClient {
        context: context(organization_id),
        public,
        redirect_uris: vec![RedirectUri::new(REDIRECT)],
        pkce_method: PkceMethod::S256,
    };
    let outcome = register_o_auth_client(&input, &admission(organization_id), allocator)
        .expect("an administrator of an admitted organization registering an admitted redirect");
    (input, outcome)
}

/// A payload one fold reads as a corrupt log is not a payload the other materializes a
/// record out of.
///
/// `crates/mandate-identity/src/port.rs`'s `principal_of` states exactly that, as the
/// reason it enforces the two pinned literals: "This fold reads the same log, so it
/// decides the same two: a payload that one fold calls 'not the declared seeding event' is
/// not a payload the other may materialize a record out of."
///
/// `mandate_federation::record::Projection::apply` refuses two more things about this
/// payload, in `record_link`, which the provisioning arm routes straight through: an empty
/// `subject` (`FoldError::EmptySubject`) and an untrimmed one
/// (`FoldError::SubjectNotTrimmed`). Either makes the whole federation log unreadable —
/// every connection, link and client in it — and neither is decided by the identity fold,
/// which appends the event and answers a `mandate.identity.Principal` for it.
///
/// The federation half is the oracle: the case asserts the refusal it claims before it
/// asks the identity log anything.
#[test]
fn a_provisioning_one_fold_reads_as_corrupt_materializes_no_principal_in_the_other() {
    for (why, subject) in [
        ("an empty subject", ""),
        ("an untrimmed subject", "  subject-one  "),
    ] {
        let log = vec![
            connection_created(organization(2)),
            provisioned_here(subject),
        ];

        let refused =
            Projection::fold(&log).expect_err("this domain's own fold reads the log as corrupt");
        assert!(
            matches!(
                refused,
                FoldError::EmptySubject { .. } | FoldError::SubjectNotTrimmed { .. }
            ),
            "{why}: the federation fold refused for {refused:?}, not for the subject, so \
             there is nothing here to measure"
        );

        let mut identity = IdentityLog::new();
        let appended = identity.try_record(IdentityEvent::ExternalPrincipalProvisioned(
            provisioned_there(subject),
        ));

        assert!(
            appended.is_err(),
            "{why}: mandate_federation::record::Projection::fold reads this log as \
             corrupt ({refused:?}) and mandate_identity::IdentityLog appends the same \
             event — `principal_of` decides the two pinned literals and nothing else, \
             against its own statement that a payload one fold calls not the declared \
             seeding event is not a payload the other may materialize a record out of"
        );
        assert_eq!(
            identity.principal(&principal()),
            None,
            "{why}: a payload this domain's fold cannot read materializes no principal"
        );
    }
}

/// Probe, and it holds: a confidential client is registrable, and it is refused at
/// authorization.
///
/// `public: false` is supplied by no case in either crate. The contract sources
/// `OAuthClientRegistered.public` from `input.public`
/// (`systems/mandate/domains/federation.yaml`, `RegisterOAuthClient`), and
/// `check_payload_sources` decides that against the input a case supplies — so a handler
/// that wrote the literal `true` into the event would be green against every case the unit
/// shipped. This carries the other value through the real handler, the contract's own
/// source check, the schema, the fold and the declared refusal.
#[test]
fn probe_a_confidential_client_is_registrable_and_refused_at_authorization() {
    let mut allocator = SequentialAllocator::new();
    let (input, outcome) = registered(organization(10), false, &mut allocator);

    let payload = encoded(&outcome.event);
    check_event_conforms(outcome.event.ess_name(), &payload)
        .expect("the emitted payload conforms to its generated schema");
    check_payload_sources(
        REGISTER_CLIENT,
        &encoded(&input),
        Some(&json!({
            "id": encoded(&outcome.id),
            "organization_id": encoded(&outcome.organization_id),
        })),
        outcome.event.ess_name(),
        &payload,
    )
    .expect("every payload field is the source the contract declares for it");
    assert_eq!(
        payload.get("public"),
        Some(&Value::Bool(false)),
        "the event carries the `public` the input named, not a literal"
    );

    let fold = Projection::fold(&[outcome.event]).expect("one creation");
    assert!(
        !fold.clients()[0].public,
        "the fold materializes the `public` the event carried"
    );

    let denied = registered_public_client(
        &fold,
        &outcome.id,
        &RedirectUri::new(REDIRECT),
        &organization(10),
    )
    .expect_err("a confidential client is not a registered public client");
    assert_eq!(denied.clause, DenialClause::ClientNotPublic);
}

/// Probe, and it holds: insert-if-absent keeps the *first* record, field for field, when
/// the repeat disagrees with it.
///
/// Pass 1 decided `fold([e, e]) == fold([e])`, which is the redelivery at-least-once
/// delivery produces. Correction 1 made the arm insert-if-absent, and insert-if-absent has
/// a second surface nothing asks about: a second creation under one identity whose payload
/// is *different*. `crates/mandate-model/src/tenancy.rs`'s `or_insert_with` answers it the
/// same way — the first one for an identity is the one that stands — and this asks the new
/// arm the same question with every field of the record changed at once.
#[test]
fn probe_a_second_registration_under_one_identity_leaves_the_first_record_standing() {
    let mut allocator = SequentialAllocator::new();
    let (_, first) = registered(organization(10), true, &mut allocator);
    let held = Projection::fold(std::slice::from_ref(&first.event)).expect("one creation");

    // The same identity, and nothing else the same.
    let conflicting = FederationEvent::OAuthClientRegistered {
        context: context(organization(11)),
        id: first.id,
        organization_id: organization(11),
        public: false,
        redirect_uris: vec![RedirectUri::new("https://other.example/callback")],
        pkce_method: PkceMethod::S256,
    };

    let replayed =
        Projection::fold(&[first.event, conflicting]).expect("a second creation writes nothing");

    assert_eq!(
        replayed, held,
        "insert-if-absent: the first creation of an identity is the one that stands, \
         organization, `public` and redirect set included"
    );
    assert_eq!(
        replayed.clients(),
        held.clients(),
        "no field of the first record was overwritten"
    );
    let standing: &OAuthClient = &replayed.clients()[0];
    assert_eq!(standing.organization_id, organization(10));
    assert!(standing.public);
    assert_eq!(standing.redirect_uris, vec![RedirectUri::new(REDIRECT)]);
}

/// Probe, and it holds: a refused registration mints no client identity.
///
/// The identity is the accepted outcome's response field and the event's `id` is sourced
/// from it, so an identity burned on a refusal is an identity no record will ever carry
/// and a gap in the sequence an operator reads as a lost event. Every guard in the handler
/// runs before the allocator is touched; nothing in the suite says so, and moving the
/// mint above the guards leaves every case the unit shipped green.
#[test]
fn probe_a_denied_registration_burns_no_client_identity() {
    let mut allocator = SequentialAllocator::new();
    let input = RegisterOAuthClient {
        context: context(organization(10)),
        public: true,
        redirect_uris: vec![RedirectUri::new(REDIRECT)],
        pkce_method: PkceMethod::S256,
    };

    for (admission, why) in [
        (
            ConfiguredAdmission::new()
                .with_organization(organization(10))
                .with_redirect_uri(organization(10), RedirectUri::new(REDIRECT)),
            "the caller lacks client-administration authority",
        ),
        (
            ConfiguredAdmission::new()
                .with_administrator(administrator())
                .with_redirect_uri(organization(10), RedirectUri::new(REDIRECT)),
            "the organization binding is invalid",
        ),
        (
            ConfiguredAdmission::new()
                .with_administrator(administrator())
                .with_organization(organization(10)),
            "a redirect URI is unadmitted",
        ),
    ] {
        register_o_auth_client(&input, &admission, &mut allocator).expect_err(why);
    }

    let mut untouched = SequentialAllocator::new();
    assert_eq!(
        allocator.next_o_auth_client_id(),
        untouched.next_o_auth_client_id(),
        "three refusals minted no client identity: the first accepted registration after \
         them carries the identity an allocator that saw none would have minted"
    );
}

/// Probe, and it holds: one declared element, one realizer, across the two crates.
///
/// Pass 1's F5 recorded that `mandate.identity.Principal.State` was named by both crates'
/// registries and that "no test compares registries across crates". Correction 1 answered
/// it by deleting the element from `mandate_federation::ESS_REALIZATIONS` and adding it to
/// `mandate_identity`'s — a move nothing checks, in either direction: federation carries no
/// `ESS_UNREALIZED` and no exhaustiveness case, so an element dropped from its registry and
/// picked up by nobody is invisible. This is the comparison pass 1 named, and it is the one
/// file in the workspace that can make it: `mandate-federation` sees `mandate-identity` and
/// never the reverse (`dependency-boundaries.json`).
#[test]
fn probe_one_declared_element_has_one_realizer_across_the_two_crates() {
    let shared: Vec<(&str, &str, &str)> = mandate_federation::ESS_REALIZATIONS
        .iter()
        .filter_map(|(element, federation_symbol)| {
            mandate_identity::ESS_REALIZATIONS
                .iter()
                .find(|(other, _)| other == element)
                .map(|(_, identity_symbol)| (*element, *federation_symbol, *identity_symbol))
        })
        .collect();

    assert_eq!(
        shared,
        Vec::<(&str, &str, &str)>::new(),
        "an element realized by two crates is realized by neither unambiguously"
    );

    assert!(
        mandate_identity::ESS_REALIZATIONS
            .iter()
            .any(|(element, _)| *element == "mandate.identity.Principal.State"),
        "the element federation stopped realizing is realized by the crate that folds the \
         record"
    );
    assert!(
        !mandate_federation::ESS_REALIZATIONS
            .iter()
            .any(|(element, _)| *element == "mandate.identity.Principal.State"),
        "the port's view is not a second realization of the element"
    );
}
