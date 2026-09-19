//! Every event, command input and entity record this crate holds agrees with the
//! generated contract shape it names, field for field.
//!
//! The check is a round trip through the generated shape and not a comparison of two
//! Rust structs: `serde_json::to_value` of the domain value, `from_value` into the
//! `mandate_contract` shape, `to_value` again, and the two documents compared. The
//! generated shapes carry `#[serde(deny_unknown_fields)]` and declare every non-optional
//! key required, so a field this crate renamed, added or dropped fails at `from_value`
//! naming the key, and a field whose *value* is written differently fails at the
//! comparison. Nothing here restates the contract: the shapes are generated from
//! `systems/mandate`, and the only names written out are the ESS element names, which
//! `mandate_testkit::contract::assert_event_conforms` refuses if the contract does not
//! declare them.
//!
//! Absence is checked in both directions. The contract spells an absent optional by
//! leaving the key out and declares no nullable type (`crates/mandate-contract/src/lib.rs`),
//! so every payload is built twice — once with every optional carried, once with none —
//! and the all-absent form is asserted to contain no `null` anywhere, at any depth.

use mandate_contract::{commands, entities, events};
use mandate_federation::PrincipalState;
use mandate_federation::authenticate::{AuthenticateFederation, ProvisionExternalPrincipal};
use mandate_federation::authorize::AuthorizationCodeState;
use mandate_federation::disable::{
    DisableFederationConnection, DisableOAuthClient, UnlinkExternalPrincipal,
};
use mandate_federation::link::LinkExternalPrincipal;
use mandate_federation::record::{
    ConnectionState, ExternalPrincipal, FederationConnection, FederationEvent, LinkState,
    OAuthClient, OAuthClientState, RegisterFederationConnection,
};
use mandate_model::TenantResolutionRule;
use mandate_testkit::contract::assert_event_conforms;
use mandate_types::{
    Audience, ClientId, CorrelationId, CredentialId, CredentialProof, DelegationId,
    EpochSnapshotRef, ExecutionId, ExternalLinkMethod, ExternalPrincipalId, ExternalSubject,
    FederationConnectionId, Issuer, OAuthClientId, OrganizationId, PkceMethod, PrincipalId,
    PrincipalKind, RedirectUri, SessionId, Timestamp, Uuid, VerifiedContext,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::collections::BTreeSet;

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

/// A verified context carrying every optional the declaration admits.
fn populated_context() -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::new(uuid(1)),
        actor: Some(PrincipalId::new(uuid(2))),
        organization: OrganizationId::new(uuid(3)),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(4)),
        delegation: Some(DelegationId::new(uuid(5))),
        execution: Some(ExecutionId::new(uuid(6))),
        correlation: CorrelationId::new("correlation"),
    }
}

/// The same context with every optional absent.
fn bare_context() -> VerifiedContext {
    VerifiedContext {
        actor: None,
        delegation: None,
        execution: None,
        ..populated_context()
    }
}

/// A tenant rule carrying both optional claim halves.
fn populated_rule() -> TenantResolutionRule {
    TenantResolutionRule {
        configured_organization: OrganizationId::new(uuid(3)),
        verified_claim_name: Some("tenant".to_owned()),
        verified_claim_value: Some("acme".to_owned()),
    }
}

/// The unconditional rule: neither optional carried.
fn bare_rule() -> TenantResolutionRule {
    TenantResolutionRule {
        configured_organization: OrganizationId::new(uuid(3)),
        verified_claim_name: None,
        verified_claim_value: None,
    }
}

fn connection_id() -> FederationConnectionId {
    FederationConnectionId::new(uuid(0xc1))
}

fn external_principal_id() -> ExternalPrincipalId {
    ExternalPrincipalId::new(uuid(0xe1))
}

fn client() -> OAuthClientId {
    OAuthClientId::new(uuid(0x0c))
}

fn subject() -> ExternalSubject {
    ExternalSubject::new("subject-1")
}

fn linked_at() -> Timestamp {
    Timestamp::new("2026-09-19T00:00:00Z")
}

/// One round trip: the domain value's own JSON, read as the generated shape it names and
/// written back. The returned document is the domain value's JSON, for the absence check.
fn agrees<D, C>(domain: &D, element: &str) -> Value
where
    D: Serialize,
    C: Serialize + DeserializeOwned,
{
    let encoded = serde_json::to_value(domain).expect("a domain value encodes as JSON");
    let shape: C = serde_json::from_value(encoded.clone())
        .unwrap_or_else(|error| panic!("{element}: the generated shape refuses it: {error}"));
    let round_tripped = serde_json::to_value(&shape).expect("a generated shape encodes as JSON");
    assert_eq!(
        round_tripped, encoded,
        "{element}: the round trip through the generated shape is not the identity"
    );
    encoded
}

/// Every key of a document, at every depth, carries a value the contract declares. The
/// contract declares no nullable type, so a `null` anywhere is a form it refuses.
fn carries_no_null(document: &Value, path: &str) {
    match document {
        Value::Null => panic!("{path} is null; the contract spells absence by omitting the key"),
        Value::Object(fields) => {
            for (key, value) in fields {
                carries_no_null(value, &format!("{path}.{key}"));
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                carries_no_null(item, &format!("{path}[{index}]"));
            }
        }
        _ => {}
    }
}

/// The seven `mandate.federation` event payloads this crate holds, over one context and
/// one tenant rule.
///
/// `mandate.federation.AuthorizationCodeIssued` is the contract's eighth. No handler in
/// this crate emits it — `crate::authorize` is non-consuming and returns a validation
/// candidate carrying no event — so the crate holds no shape for it and this list does
/// not invent one.
fn events(context: &VerifiedContext, rule: &TenantResolutionRule) -> Vec<FederationEvent> {
    vec![
        FederationEvent::FederationConnectionCreated {
            context: context.clone(),
            connection_id: connection_id(),
            issuer: Issuer::new("https://idp.example"),
            client_id: ClientId::new("client-1"),
            tenant_resolution: rule.clone(),
            jit_provisioning: true,
        },
        FederationEvent::FederationConnectionDisabled {
            context: context.clone(),
            id: connection_id(),
        },
        FederationEvent::ExternalPrincipalLinked {
            context: context.clone(),
            connection_id: connection_id(),
            principal_id: PrincipalId::new(uuid(1)),
            external_principal_id: external_principal_id(),
            subject: subject(),
            link_method: ExternalLinkMethod::Administrator,
            linked_at: linked_at(),
        },
        FederationEvent::ExternalPrincipalUnlinked {
            context: context.clone(),
            id: external_principal_id(),
        },
        FederationEvent::ExternalPrincipalProvisioned {
            organization_id: OrganizationId::new(uuid(3)),
            correlation: CorrelationId::new("correlation"),
            connection_id: connection_id(),
            principal_id: PrincipalId::new(uuid(1)),
            kind: PrincipalKind::User,
            display_name: "subject-1".to_owned(),
            external_principal_id: external_principal_id(),
            subject: subject(),
            link_method: ExternalLinkMethod::ConfiguredFederation,
            linked_at: linked_at(),
        },
        FederationEvent::FederationAuthenticated {
            session_id: SessionId::new(uuid(0x5e)),
            principal_id: PrincipalId::new(uuid(1)),
            audience: Audience::new("mandate"),
            correlation: CorrelationId::new("correlation"),
            connection_id: connection_id(),
            organization_id: OrganizationId::new(uuid(3)),
            epochs: EpochSnapshotRef::new(uuid(0x3e)),
            expires_at: Timestamp::new("2026-12-31T00:00:00Z"),
        },
        FederationEvent::OAuthClientDisabled {
            context: context.clone(),
            id: client(),
        },
    ]
}

/// One round trip per event, each into the generated payload of the element the event
/// names itself as.
fn each_event_agrees(context: &VerifiedContext, rule: &TenantResolutionRule) -> Vec<Value> {
    let held = events(context, rule);
    let mut encoded = Vec::new();
    for event in &held {
        let element = event.ess_name();
        let document = match event {
            FederationEvent::FederationConnectionCreated { .. } => {
                agrees::<_, events::MandateFederationFederationConnectionCreated>(event, element)
            }
            FederationEvent::FederationConnectionDisabled { .. } => {
                agrees::<_, events::MandateFederationFederationConnectionDisabled>(event, element)
            }
            FederationEvent::ExternalPrincipalLinked { .. } => {
                agrees::<_, events::MandateFederationExternalPrincipalLinked>(event, element)
            }
            FederationEvent::ExternalPrincipalUnlinked { .. } => {
                agrees::<_, events::MandateFederationExternalPrincipalUnlinked>(event, element)
            }
            FederationEvent::ExternalPrincipalProvisioned { .. } => {
                agrees::<_, events::MandateFederationExternalPrincipalProvisioned>(event, element)
            }
            FederationEvent::FederationAuthenticated { .. } => {
                agrees::<_, events::MandateFederationFederationAuthenticated>(event, element)
            }
            FederationEvent::OAuthClientDisabled { .. } => {
                agrees::<_, events::MandateFederationOAuthClientDisabled>(event, element)
            }
        };
        // The name the event answers is decided against the contract's own event index,
        // and the payload against the generated schema of that element: a name this
        // crate invented is refused as undeclared before any file is read.
        assert_event_conforms(element, &document);
        encoded.push(document);
    }
    assert_eq!(
        held.len(),
        7,
        "every event shape this crate holds is round-tripped"
    );
    encoded
}

#[test]
fn every_event_round_trips_with_every_optional_carried() {
    each_event_agrees(&populated_context(), &populated_rule());
}

#[test]
fn every_event_round_trips_with_every_optional_absent_and_spells_absence_by_omission() {
    for document in each_event_agrees(&bare_context(), &bare_rule()) {
        carries_no_null(&document, "payload");
    }
}

/// The compiled contract, read once per case that needs it.
fn system_ir() -> Value {
    const IR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../generated/ir/system.json"
    );
    let text = std::fs::read_to_string(IR).expect("the generated IR is readable");
    serde_json::from_str(&text).expect("the generated IR is JSON")
}

/// The variant names the contract declares for an enum element.
fn declared_variants(element: &str) -> BTreeSet<String> {
    let ir = system_ir();
    let node = &ir["types"][element]["body"];
    assert_eq!(
        node["kind"], "enum",
        "{element} is not an enum in generated/ir/system.json"
    );
    node["variants"]
        .as_array()
        .unwrap_or_else(|| panic!("{element} declares a variant list"))
        .iter()
        .map(|variant| {
            variant
                .as_str()
                .expect("a declared variant name is a string")
                .to_owned()
        })
        .collect()
}

/// The generated Rust name an ESS element derives: each dot-separated segment with its
/// first character upper-cased, concatenated.
fn derived_name(element: &str) -> String {
    element
        .split('.')
        .map(|segment| {
            let mut characters = segment.chars();
            match characters.next() {
                Some(first) => first.to_uppercase().collect::<String>() + characters.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

/// One lifecycle enum, decided against the `.State` element it names.
///
/// Three things, and the pairing is one of them: a generated shape is *not* named by the
/// case, it is derived from the element name, so a case that reaches for the wrong shape
/// fails here rather than passing against a sibling enum with the same variant names —
/// `mandate.identity.Principal.State` and `mandate.identity.Session.State` both spell
/// `Active`, and four of this contract's lifecycle enums are two-variant enums over names
/// another one also uses.
///
/// Then every variant round-trips through that shape, whose `deny_unknown_fields`-closed
/// enum refuses a name the contract does not declare; and the set of variants the crate
/// holds is compared against the set the contract declares, which is the other direction:
/// a variant the contract declares and the crate does not hold fails here.
fn state_agrees<D, C>(element: &str, held: &[D])
where
    D: Serialize,
    C: Serialize + DeserializeOwned,
{
    let derived = derived_name(element);
    let shape = std::any::type_name::<C>();
    assert!(
        shape.ends_with(&derived),
        "{element} derives the shape `{derived}`, but the case decided it against `{shape}`"
    );

    let mut encoded = BTreeSet::new();
    for variant in held {
        let document = agrees::<_, C>(variant, element);
        let name = document
            .as_str()
            .unwrap_or_else(|| panic!("{element}: a declared variant encodes as a string"))
            .to_owned();
        assert!(
            encoded.insert(name.clone()),
            "{element}: `{name}` is held twice"
        );
    }
    assert_eq!(
        encoded,
        declared_variants(element),
        "{element}: the variants this crate holds are not the ones the contract declares"
    );
}

/// Every lifecycle enum this crate holds, each listed by an exhaustive match so a variant
/// added to one and not listed here does not compile.
#[test]
fn every_lifecycle_enum_agrees_with_the_state_element_it_names() {
    let connections = [ConnectionState::Enabled, ConnectionState::Disabled];
    for state in connections {
        match state {
            ConnectionState::Enabled | ConnectionState::Disabled => {}
        }
    }
    state_agrees::<_, entities::MandateFederationFederationConnectionState>(
        "mandate.federation.FederationConnection.State",
        &connections,
    );

    let links = [LinkState::Linked, LinkState::Unlinked];
    for state in links {
        match state {
            LinkState::Linked | LinkState::Unlinked => {}
        }
    }
    state_agrees::<_, entities::MandateFederationExternalPrincipalState>(
        "mandate.federation.ExternalPrincipal.State",
        &links,
    );

    let clients = [OAuthClientState::Recorded, OAuthClientState::Disabled];
    for state in clients {
        match state {
            OAuthClientState::Recorded | OAuthClientState::Disabled => {}
        }
    }
    state_agrees::<_, entities::MandateFederationOAuthClientState>(
        "mandate.federation.OAuthClient.State",
        &clients,
    );

    // The two lifecycle enums this crate holds for another domain's record; see the
    // registry in `src/lib.rs` for why they are realized here.
    let principals = [PrincipalState::Active, PrincipalState::Disabled];
    for state in principals {
        match state {
            PrincipalState::Active | PrincipalState::Disabled => {}
        }
    }
    state_agrees::<_, entities::MandateIdentityPrincipalState>(
        "mandate.identity.Principal.State",
        &principals,
    );

    let codes = [
        AuthorizationCodeState::Issued,
        AuthorizationCodeState::Consumed,
    ];
    for state in codes {
        match state {
            AuthorizationCodeState::Issued | AuthorizationCodeState::Consumed => {}
        }
    }
    state_agrees::<_, entities::MandateCredentialAuthorizationCodeState>(
        "mandate.credential.AuthorizationCode.State",
        &codes,
    );
}

/// Every element the crate registers as realized is one the contract declares.
///
/// The registry's other half is the compiler's: `mandate_types::realizes!` expands each
/// entry into a `use` of the symbol on the right, so a symbol that moved does not build.
/// What no compiler can check is the string on the left, which is the half a coverage
/// report is read through — an element this crate named and the contract does not declare
/// is a realization of nothing. This reads the contract's own index rather than a list
/// written here, so a renamed element fails here as well as in the generated shapes.
#[test]
fn every_realized_element_is_one_the_contract_declares() {
    let ir = system_ir();
    let kinds = ["commands", "events", "entities", "errors", "types"];
    // The two elements of another domain this crate realizes, because it holds the
    // lifecycle enum of a record it reads through a port; see the registry in `src/lib.rs`.
    let cross_domain = [
        "mandate.identity.Principal.State",
        "mandate.credential.AuthorizationCode.State",
    ];

    assert!(
        !mandate_federation::ESS_REALIZATIONS.is_empty(),
        "the crate registers what it realizes"
    );
    for (element, symbol) in mandate_federation::ESS_REALIZATIONS {
        assert!(
            kinds
                .iter()
                .any(|kind| ir[kind].get(element).is_some_and(|node| !node.is_null())),
            "{element} (realized by {symbol}) is declared by no commands, events, \
             entities, errors or types index of generated/ir/system.json"
        );
        assert!(
            element.starts_with("mandate.federation.") || cross_domain.contains(element),
            "{element} (realized by {symbol}) is neither an element of this crate's domain \
             nor one of the lifecycle enums it holds for another domain's record"
        );
    }
}

#[test]
fn every_command_input_round_trips_into_its_generated_shape() {
    for (context, rule) in [
        (populated_context(), populated_rule()),
        (bare_context(), bare_rule()),
    ] {
        let register = RegisterFederationConnection {
            context: context.clone(),
            issuer: Issuer::new("https://idp.example"),
            client_id: ClientId::new("client-1"),
            tenant_resolution: rule,
            jit_provisioning: false,
        };
        agrees::<_, commands::MandateFederationRegisterFederationConnectionInput>(
            &register,
            "mandate.federation.RegisterFederationConnection",
        );

        let link = LinkExternalPrincipal {
            context,
            connection_id: connection_id(),
            external_subject: subject(),
            principal_id: PrincipalId::new(uuid(1)),
            method: ExternalLinkMethod::Administrator,
        };
        agrees::<_, commands::MandateFederationLinkExternalPrincipalInput>(
            &link,
            "mandate.federation.LinkExternalPrincipal",
        );
    }

    for context in [populated_context(), bare_context()] {
        let disable_connection = DisableFederationConnection {
            id: connection_id(),
            context: context.clone(),
        };
        agrees::<_, commands::MandateFederationDisableFederationConnectionInput>(
            &disable_connection,
            "mandate.federation.DisableFederationConnection",
        );

        let unlink = UnlinkExternalPrincipal {
            id: external_principal_id(),
            context: context.clone(),
        };
        agrees::<_, commands::MandateFederationUnlinkExternalPrincipalInput>(
            &unlink,
            "mandate.federation.UnlinkExternalPrincipal",
        );

        let disable_client = DisableOAuthClient {
            id: client(),
            context,
        };
        agrees::<_, commands::MandateFederationDisableOAuthClientInput>(
            &disable_client,
            "mandate.federation.DisableOAuthClient",
        );
    }

    // Both proof-driven inputs carry a `mandate.core.CredentialProof`, which renders the
    // redaction marker rather than the material (`mandate_types::REDACTED`). The contract
    // declares the field as a string, so the round trip decides the key set here and the
    // credential boundary is decided where it is enforced, in `mandate-types`.
    let authenticate = AuthenticateFederation {
        connection_id: connection_id(),
        proof: CredentialProof::from_bytes(b"proof".to_vec()),
    };
    agrees::<_, commands::MandateFederationAuthenticateFederationInput>(
        &authenticate,
        "mandate.federation.AuthenticateFederation",
    );

    let provision = ProvisionExternalPrincipal {
        connection_id: connection_id(),
        proof: CredentialProof::from_bytes(b"proof".to_vec()),
    };
    agrees::<_, commands::MandateFederationProvisionExternalPrincipalInput>(
        &provision,
        "mandate.federation.ProvisionExternalPrincipal",
    );
}

#[test]
fn every_entity_record_round_trips_into_its_generated_shape_in_every_declared_state() {
    for (rule, state) in [
        (populated_rule(), ConnectionState::Enabled),
        (bare_rule(), ConnectionState::Disabled),
    ] {
        let connection = FederationConnection {
            id: connection_id(),
            organization_id: OrganizationId::new(uuid(3)),
            issuer: Issuer::new("https://idp.example"),
            client_id: ClientId::new("client-1"),
            tenant_resolution: rule,
            jit_provisioning: true,
            state,
        };
        let document = agrees::<_, entities::MandateFederationFederationConnection>(
            &connection,
            "mandate.federation.FederationConnection",
        );
        carries_no_null(&document, "mandate.federation.FederationConnection");
    }

    for state in [LinkState::Linked, LinkState::Unlinked] {
        let link = ExternalPrincipal {
            id: external_principal_id(),
            organization_id: OrganizationId::new(uuid(3)),
            subject: subject(),
            principal_id: PrincipalId::new(uuid(1)),
            connection_id: connection_id(),
            link_method: ExternalLinkMethod::ConfiguredFederation,
            linked_at: linked_at(),
            state,
        };
        let document = agrees::<_, entities::MandateFederationExternalPrincipal>(
            &link,
            "mandate.federation.ExternalPrincipal",
        );
        carries_no_null(&document, "mandate.federation.ExternalPrincipal");
    }

    for state in [OAuthClientState::Recorded, OAuthClientState::Disabled] {
        let oauth_client = OAuthClient {
            id: client(),
            organization_id: OrganizationId::new(uuid(3)),
            public: true,
            redirect_uris: vec![RedirectUri::new("https://app.example/callback")],
            pkce_method: PkceMethod::S256,
            state,
        };
        let document = agrees::<_, entities::MandateFederationOAuthClient>(
            &oauth_client,
            "mandate.federation.OAuthClient",
        );
        carries_no_null(&document, "mandate.federation.OAuthClient");
    }
}
