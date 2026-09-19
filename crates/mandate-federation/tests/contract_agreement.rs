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
use mandate_federation::register_client::RegisterOAuthClient;
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

/// The eight `mandate.federation` event payloads this crate holds, over one context and
/// one tenant rule.
///
/// `mandate.federation.AuthorizationCodeIssued` is the contract's ninth. No handler in
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
        FederationEvent::OAuthClientRegistered {
            context: context.clone(),
            id: client(),
            organization_id: OrganizationId::new(uuid(3)),
            public: true,
            redirect_uris: vec![RedirectUri::new("https://app.example/callback")],
            pkce_method: PkceMethod::S256,
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
            FederationEvent::OAuthClientRegistered { .. } => {
                agrees::<_, events::MandateFederationOAuthClientRegistered>(event, element)
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
        8,
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

    // The two lifecycle enums this crate holds for another domain's record. **Neither is
    // realized here** (`src/lib.rs`): `PrincipalState` is the view `PrincipalStore` is
    // answered through, and `AuthorizationCodeState` is the view the non-consuming
    // `AuthorizePublicClient` validation reads a caller-supplied code record through —
    // `mandate_sts::store` folds that record and realizes both the entity and its state.
    // Both are decided against the generated shape all the same: an unrealized type that
    // disagrees with the contract is still a type that disagrees with the contract.
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
        // This crate realizes elements of its own domain and of no other. Both cross-domain
        // lifecycle enums it holds are port views of records other crates fold —
        // `PrincipalState` since `story:declared-writers`' realization round,
        // `AuthorizationCodeState` since `story:oauth-transaction` — and one declared
        // element has one realizer. An allowance for a cross-domain realization would be an
        // allowance for a second one.
        assert!(
            element.starts_with("mandate.federation."),
            "{element} (realized by {symbol}) is not an element of this crate's domain"
        );
    }
}

/// The registry and the list of what it does not cover account for every declared element
/// of this domain, once each.
///
/// The reverse direction of the case above: that one asks whether every registered element
/// is declared, this one asks whether every *declared* element is accounted for — by
/// `ESS_REALIZATIONS` or by `ESS_UNREALIZED`, never by both and never by neither. A
/// registry read as coverage is read as a statement about the whole domain, and an element
/// nobody named is the one shape of drift a list of what *is* covered cannot show. This is
/// the pair `crates/mandate-identity/tests/contract_agreement.rs` established for its
/// domain; a cross-crate realization this crate drops and nobody picks up is invisible
/// without it.
///
/// The comparison is over this crate's own domain prefix. The lifecycle enum it holds for
/// another domain's record is not a realization of that element (`src/lib.rs`) and is
/// decided by the case above.
#[test]
fn every_declared_element_of_this_domain_is_realized_or_named_as_unrealized() {
    let ir = system_ir();
    let realized: BTreeSet<&str> = mandate_federation::ESS_REALIZATIONS
        .iter()
        .map(|(element, _)| *element)
        .filter(|element| element.starts_with("mandate.federation."))
        .collect();
    let unrealized: BTreeSet<&str> = mandate_federation::ESS_UNREALIZED
        .iter()
        .map(|(element, _)| *element)
        .collect();

    let mut declared: BTreeSet<String> = BTreeSet::new();
    for kind in ["commands", "events", "entities", "errors", "types"] {
        let Some(index) = ir[kind].as_object() else {
            continue;
        };
        declared.extend(
            index
                .keys()
                .filter(|element| element.starts_with("mandate.federation."))
                .cloned(),
        );
    }

    let accounted: BTreeSet<String> = realized
        .iter()
        .chain(unrealized.iter())
        .map(|element| (*element).to_owned())
        .collect();
    assert_eq!(
        declared, accounted,
        "every declared element of this domain is named by ESS_REALIZATIONS or by \
         ESS_UNREALIZED"
    );
    assert!(
        realized.is_disjoint(&unrealized),
        "an element is realized or it is not: {:?}",
        realized.intersection(&unrealized).collect::<Vec<_>>()
    );
    for (element, reason) in mandate_federation::ESS_UNREALIZED {
        assert!(
            !reason.trim().is_empty(),
            "{element} is named as unrealized with no reason"
        );
        assert!(
            element.starts_with("mandate.federation."),
            "{element} is not an element of this crate's domain"
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
            context: context.clone(),
        };
        agrees::<_, commands::MandateFederationDisableOAuthClientInput>(
            &disable_client,
            "mandate.federation.DisableOAuthClient",
        );

        // Both redirect sets the command admits: the registered one and the empty one,
        // which `federation.yaml` declares is not a denial.
        for redirect_uris in [
            vec![RedirectUri::new("https://app.example/callback")],
            Vec::new(),
        ] {
            let register_client = RegisterOAuthClient {
                context: context.clone(),
                public: true,
                redirect_uris,
                pkce_method: PkceMethod::S256,
            };
            agrees::<_, commands::MandateFederationRegisterOAuthClientInput>(
                &register_client,
                "mandate.federation.RegisterOAuthClient",
            );
        }
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

/// The coverage manifest's account of this crate is exactly this crate's registry, element
/// and symbol both.
///
/// `contracts/coverage.json` maps every element of the contract to what implements it, and
/// nothing in the manifest is compiled: a symbol there is a string. This is the case that
/// makes the string answerable — the registry's right-hand sides are expanded into `use`
/// declarations by `mandate_types::realizes!`, so they exist or the crate does not build, and
/// the manifest is asserted equal to them here. An entry claiming this crate realizes an
/// element it does not, or realizes it with a symbol it does not name, fails in this crate's
/// own suite rather than in a reader of the manifest.
///
/// `cargo xtask coverage` decides the complementary half: that every `implemented` entry of
/// the manifest names a crate which runs a case like this one. An entry naming a crate that
/// runs none would be a coverage claim nothing reconciles.
#[test]
fn the_coverage_manifest_names_exactly_what_this_crate_realizes() {
    let registered: BTreeSet<(String, String)> = mandate_federation::ESS_REALIZATIONS
        .iter()
        .map(|(element, symbol)| ((*element).to_owned(), (*symbol).to_owned()))
        .collect();
    assert_eq!(
        registered.len(),
        mandate_federation::ESS_REALIZATIONS.len(),
        "the registry holds no duplicate pair"
    );
    assert_eq!(
        coverage_manifest_entries(env!("CARGO_PKG_NAME")),
        registered,
        "the coverage manifest's implemented entries for this crate are not its registry"
    );
    no_unrealized_element_contradicts_the_coverage_manifest(mandate_federation::ESS_UNREALIZED);
}

/// Every `implemented` entry of the coverage manifest that names `crate_name`, as the element
/// and the single symbol it pairs with.
fn coverage_manifest_entries(crate_name: &str) -> BTreeSet<(String, String)> {
    const MANIFEST: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contracts/coverage.json");
    let text = std::fs::read_to_string(MANIFEST).unwrap_or_else(|error| {
        panic!("{MANIFEST}: {error}");
    });
    let manifest: Value = serde_json::from_str(&text).expect("the coverage manifest is JSON");
    assert_eq!(
        manifest["format"], "mandate-coverage/1",
        "unknown coverage manifest format"
    );
    let mut entries = BTreeSet::new();
    for entry in manifest["entries"]
        .as_array()
        .expect("the coverage manifest states its entries")
    {
        if entry["crate"] != crate_name {
            continue;
        }
        let element = entry["element"]
            .as_str()
            .expect("an entry states an element");
        assert_eq!(
            entry["status"], "implemented",
            "{element}: an entry names a crate and is not implemented"
        );
        let symbols = entry["impl"]
            .as_array()
            .unwrap_or_else(|| panic!("{element}: the entry states no impl list"));
        assert_eq!(
            symbols.len(),
            1,
            "{element}: one element has one realizer, and one realizer names one symbol"
        );
        entries.insert((
            element.to_owned(),
            symbols[0]
                .as_str()
                .unwrap_or_else(|| panic!("{element}: the symbol is no path"))
                .to_owned(),
        ));
    }
    assert!(
        !entries.is_empty(),
        "the coverage manifest names no entry for {crate_name}, so this case decides nothing"
    );
    entries
}

/// Every entry of the coverage manifest, as `(status, crate, the first impl symbol)`.
fn coverage_manifest_claims() -> std::collections::BTreeMap<String, (String, String, String)> {
    const MANIFEST: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contracts/coverage.json");
    let text = std::fs::read_to_string(MANIFEST).unwrap_or_else(|error| {
        panic!("{MANIFEST}: {error}");
    });
    let manifest: Value = serde_json::from_str(&text).expect("the coverage manifest is JSON");
    let mut claims = std::collections::BTreeMap::new();
    for entry in manifest["entries"]
        .as_array()
        .expect("the coverage manifest states its entries")
    {
        let element = entry["element"]
            .as_str()
            .expect("an entry states an element");
        claims.insert(
            element.to_owned(),
            (
                entry["status"].as_str().unwrap_or_default().to_owned(),
                entry["crate"].as_str().unwrap_or_default().to_owned(),
                entry["impl"][0].as_str().unwrap_or_default().to_owned(),
            ),
        );
    }
    assert_eq!(claims.len(), 292, "the coverage manifest's element count");
    claims
}

/// The symbol an `ESS_UNREALIZED` reason names as the realizer, when it names one.
fn named_realizer(reason: &str) -> Option<String> {
    let (_, named) = reason.split_once("realized by ")?;
    let named = named.trim_start_matches('`');
    let claimed: String = named
        .chars()
        .take_while(|character| {
            character.is_ascii_alphanumeric() || *character == '_' || *character == ':'
        })
        .collect();
    (!claimed.is_empty()).then_some(claimed)
}

/// A manifest symbol as an absolute path: `crate::` is the crate the entry names.
fn absolute(holder: &str, symbol: &str) -> String {
    match symbol.strip_prefix("crate::") {
        Some(tail) => format!("{}::{tail}", holder.replace('-', "_")),
        None => symbol.to_owned(),
    }
}

/// Nothing this crate registers as **unrealized** is reported implemented by the coverage
/// manifest — unless this crate's own reason names the realizer, and then the manifest names
/// that same symbol.
///
/// `ESS_UNREALIZED` is this crate's statement, in the crate's own source, that it realizes an
/// element it declares nothing for. The manifest is a second account of the same question,
/// and until this check nothing in the tree compared them: `cargo xtask coverage` reads only
/// the manifest, and the equality above reads only `ESS_REALIZATIONS`. That gap let 23
/// derived `.State` entries be reported implemented by the generated contract shape, six of
/// them while the crate that owns the domain said in its own registry that nothing realizes
/// them.
///
/// The exemption is not a hole: a reason of the form "realized by `<symbol>`" is this crate
/// naming **another crate's** realization, and the assertion on that branch is stronger than
/// the refusal — the manifest has to report the element implemented by exactly that symbol.
/// One declared element still has one realizer; this says the two documents agree on which.
fn no_unrealized_element_contradicts_the_coverage_manifest(unrealized: &[(&str, &str)]) {
    assert!(
        !unrealized.is_empty(),
        "this crate registers no unrealized element, so this check reads nothing"
    );
    let claims = coverage_manifest_claims();
    let mut contradictions = Vec::new();
    for (element, reason) in unrealized {
        let (status, holder, symbol) = claims
            .get(*element)
            .unwrap_or_else(|| panic!("{element}: the coverage manifest has no entry"));
        match named_realizer(reason) {
            None => {
                if status == "implemented" {
                    contradictions.push(format!(
                        "  {element}: this crate registers it as an element it does not \
                         realize and names no realizer, and the coverage manifest reports it \
                         implemented by {holder} as {symbol}"
                    ));
                }
            }
            Some(named) if status != "implemented" => contradictions.push(format!(
                "  {element}: this crate's reason names {named} as its realizer and the \
                 coverage manifest reports it {status}"
            )),
            Some(named) => {
                let resolved = absolute(holder, symbol);
                if resolved != named {
                    contradictions.push(format!(
                        "  {element}: this crate's reason names {named} as its realizer and \
                         the coverage manifest names {resolved}"
                    ));
                }
            }
        }
    }
    assert!(
        contradictions.is_empty(),
        "this crate's ESS_UNREALIZED registry and the coverage manifest disagree about {} \
         element(s):\n{}",
        contradictions.len(),
        contradictions.join("\n")
    );
}
