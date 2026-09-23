//! Every event payload and entity record this crate projects agrees with the generated
//! contract shape it names, field for field.
//!
//! The check is a round trip through the generated shape and not a comparison of two Rust
//! structs: `serde_json::to_value` of the domain value, `from_value` into the
//! `mandate_contract` shape, `to_value` again, and the two documents compared. The
//! generated shapes carry `#[serde(deny_unknown_fields)]` and declare every non-optional
//! key required, so a field this crate renamed, added or dropped fails at `from_value`
//! naming the key, and a field whose *value* is written differently fails at the
//! comparison.
//!
//! Absence is checked in both directions. The contract spells an absent optional by leaving
//! the key out and declares no nullable type, so every shape with an optional is built
//! twice — once carrying it, once without — and the second form is asserted to contain no
//! `null` anywhere, at any depth.
//!
//! # What this crate holds no shape for
//!
//! `mandate.credential.AuthorizationCode`, the `AuthorizationCodeIssued` that creates it,
//! and the two token-exchange events. `services/sts` owns the code record and folds it
//! (`services/sts/src/store.rs`), and `story:constrained-exchange` lands the exchange; a
//! shape here would be a payload nothing in this crate can fill.
//!
//! `mandate.credential.AuthorizationCodeRedeemed` **is** here, and it is the one payload of
//! this domain two folds read. `credential.yaml`'s header declares that it "also seeds a
//! `mandate.credential.AccessCredential`" and "carries the whole AccessCredential record",
//! so the code fold in `services/sts` consumes the code with it and this crate materializes
//! the credential from it. `services/sts/tests/store.rs` decides that the two declarations
//! encode identically.

use mandate_contract::{entities, events};
use mandate_token::projection::{
    AccessCredential, AccessCredentialState, CredentialEvent, ResourceServer, ResourceServerState,
    SigningKey, SigningKeyState,
};
use mandate_token::{CredentialDescriptor, CredentialProfile};
use mandate_types::{
    Action, Audience, AuthorityScope, AuthorizationCodeId, CorrelationId, CredentialId,
    CredentialKind, CredentialVerifier, DelegationId, Duration, EpochSnapshotRef, ExecutionId,
    KeyReference, OrganizationId, PrincipalId, ResourceRef, ResourceServerId, ResourceType,
    RevocationGuarantee, SigningAlgorithm, SigningKeyId, Timestamp, Uuid, VerifiedContext,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::collections::BTreeSet;

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn principal() -> PrincipalId {
    PrincipalId::new(uuid(1))
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(2))
}

fn target() -> ResourceServerId {
    ResourceServerId::new(uuid(0x30))
}

fn credential_id() -> CredentialId {
    CredentialId::new(uuid(0x40))
}

fn signing_key_id() -> SigningKeyId {
    SigningKeyId::new(uuid(0x70))
}

/// A verified context carrying every optional the declaration admits.
fn populated_context() -> VerifiedContext {
    VerifiedContext {
        subject: principal(),
        actor: Some(PrincipalId::new(uuid(3))),
        organization: organization(),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(5)),
        delegation: Some(DelegationId::new(uuid(6))),
        execution: Some(ExecutionId::new(uuid(7))),
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

fn populated_scope() -> AuthorityScope {
    AuthorityScope {
        actions: vec![Action::new("read")],
        resources: vec![ResourceRef {
            resource_type: ResourceType::new("document"),
            resource_id: mandate_types::ResourceId::new(uuid(8)),
        }],
        space: Some(mandate_types::SpaceId::new(uuid(9))),
    }
}

fn bare_scope() -> AuthorityScope {
    AuthorityScope {
        actions: Vec::new(),
        resources: Vec::new(),
        space: None,
    }
}

fn populated_descriptor() -> CredentialDescriptor {
    CredentialDescriptor {
        kind: CredentialKind::Reference,
        subject: principal(),
        actor: Some(PrincipalId::new(uuid(3))),
        organization: organization(),
        audience: Audience::new("api-a"),
        scope: populated_scope(),
        delegation: Some(DelegationId::new(uuid(6))),
        execution: Some(ExecutionId::new(uuid(7))),
        expires_at: Timestamp::new("2026-09-19T01:00:00Z"),
    }
}

fn bare_descriptor() -> CredentialDescriptor {
    CredentialDescriptor {
        actor: None,
        delegation: None,
        execution: None,
        scope: bare_scope(),
        ..populated_descriptor()
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

/// The ten `mandate.credential` payloads this crate folds, over one context and one
/// descriptor — carrying every optional, or none of them.
fn folded_events(carried: bool) -> Vec<CredentialEvent> {
    let context = if carried {
        populated_context()
    } else {
        bare_context()
    };
    let descriptor = if carried {
        populated_descriptor()
    } else {
        bare_descriptor()
    };
    let scope = if carried {
        populated_scope()
    } else {
        bare_scope()
    };
    vec![
        CredentialEvent::ResourceServerRegistered {
            context: context.clone(),
            id: target(),
            audience: Audience::new("api-a"),
            credential_profile: profile(),
            allowed_exchange_sources: if carried {
                vec![ResourceServerId::new(uuid(0x31))]
            } else {
                Vec::new()
            },
        },
        CredentialEvent::ResourceServerDisabled {
            context: context.clone(),
            id: target(),
        },
        CredentialEvent::CredentialReferenceIssued {
            context: context.clone(),
            credential_id: credential_id(),
            reference_verifier: carried.then(|| CredentialVerifier::new("digest")),
            epochs: carried.then(|| EpochSnapshotRef::new(uuid(0x60))),
            issued_at: Timestamp::new("2026-09-19T00:00:00Z"),
            descriptor: descriptor.clone(),
            target: target(),
            requested_scope: scope.clone(),
        },
        CredentialEvent::CredentialSelfContainedIssued {
            context: context.clone(),
            credential_id: credential_id(),
            reference_verifier: carried.then(|| CredentialVerifier::new("digest")),
            epochs: carried.then(|| EpochSnapshotRef::new(uuid(0x60))),
            issued_at: Timestamp::new("2026-09-19T00:00:00Z"),
            descriptor: descriptor.clone(),
            target: target(),
            requested_scope: scope.clone(),
        },
        CredentialEvent::AccessCredentialRevoked {
            context: context.clone(),
            id: credential_id(),
        },
        CredentialEvent::CredentialIntrospected {
            context: context.clone(),
            descriptor: carried.then(|| descriptor.clone()),
            active: carried,
            credential_id: carried.then(credential_id),
        },
        CredentialEvent::SigningKeyRegistered {
            context: context.clone(),
            id: signing_key_id(),
            key_reference: KeyReference::new("kms://one"),
            thumbprint: "thumb-one".to_owned(),
            algorithm: SigningAlgorithm::new("declared-by-deployment"),
            not_before: Timestamp::new("2026-09-19T00:00:00Z"),
            expires_at: Timestamp::new("2026-12-31T00:00:00Z"),
        },
        CredentialEvent::SigningKeyRetired {
            context: context.clone(),
            id: signing_key_id(),
        },
        CredentialEvent::SigningKeyRevoked {
            context: context.clone(),
            id: signing_key_id(),
        },
        // The one payload of this domain two folds read; see the module documentation.
        CredentialEvent::AuthorizationCodeRedeemed {
            context: context.clone(),
            code_id: AuthorizationCodeId::new(uuid(0xac)),
            credential_id: credential_id(),
            reference_verifier: carried.then(|| CredentialVerifier::new("digest")),
            epochs: carried.then(|| EpochSnapshotRef::new(uuid(0x60))),
            issued_at: Timestamp::new("2026-09-19T00:00:00Z"),
            descriptor: descriptor.clone(),
            target: target(),
        },
        CredentialEvent::TokenExchangeAllowed {
            context: context.clone(),
            credential_id: credential_id(),
            reference_verifier: carried.then(|| CredentialVerifier::new("digest")),
            epochs: carried.then(|| EpochSnapshotRef::new(uuid(0x60))),
            issued_at: Timestamp::new("2026-09-19T00:00:00Z"),
            descriptor,
            target: target(),
            requested_scope: scope.clone(),
        },
        CredentialEvent::TokenExchangeDenied {
            context: carried.then_some(context),
            requested_target: target(),
            requested_scope: scope,
        },
    ]
}

/// One round trip per event, each into the generated payload of the element the event
/// names itself as.
fn each_event_agrees(carried: bool) -> Vec<Value> {
    let held = folded_events(carried);
    let mut encoded = Vec::new();
    for event in &held {
        let element = event.ess_name();
        let document = match event {
            CredentialEvent::ResourceServerRegistered { .. } => {
                agrees::<_, events::MandateCredentialResourceServerRegistered>(event, element)
            }
            CredentialEvent::ResourceServerDisabled { .. } => {
                agrees::<_, events::MandateCredentialResourceServerDisabled>(event, element)
            }
            CredentialEvent::CredentialReferenceIssued { .. } => {
                agrees::<_, events::MandateCredentialCredentialReferenceIssued>(event, element)
            }
            CredentialEvent::CredentialSelfContainedIssued { .. } => {
                agrees::<_, events::MandateCredentialCredentialSelfContainedIssued>(event, element)
            }
            CredentialEvent::AccessCredentialRevoked { .. } => {
                agrees::<_, events::MandateCredentialAccessCredentialRevoked>(event, element)
            }
            CredentialEvent::CredentialIntrospected { .. } => {
                agrees::<_, events::MandateCredentialCredentialIntrospected>(event, element)
            }
            CredentialEvent::SigningKeyRegistered { .. } => {
                agrees::<_, events::MandateCredentialSigningKeyRegistered>(event, element)
            }
            CredentialEvent::SigningKeyRetired { .. } => {
                agrees::<_, events::MandateCredentialSigningKeyRetired>(event, element)
            }
            CredentialEvent::SigningKeyRevoked { .. } => {
                agrees::<_, events::MandateCredentialSigningKeyRevoked>(event, element)
            }
            CredentialEvent::AuthorizationCodeRedeemed { .. } => {
                agrees::<_, events::MandateCredentialAuthorizationCodeRedeemed>(event, element)
            }
            CredentialEvent::TokenExchangeAllowed { .. } => {
                agrees::<_, events::MandateCredentialTokenExchangeAllowed>(event, element)
            }
            CredentialEvent::TokenExchangeDenied { .. } => {
                agrees::<_, events::MandateCredentialTokenExchangeDenied>(event, element)
            }
        };
        encoded.push(document);
    }
    assert_eq!(
        encoded.len(),
        12,
        "every event payload this crate declares is round-tripped"
    );
    encoded
}

#[test]
fn every_event_round_trips_with_every_optional_carried() {
    each_event_agrees(true);
}

#[test]
fn every_event_round_trips_with_every_optional_absent_and_spells_absence_by_omission() {
    for document in each_event_agrees(false) {
        carries_no_null(&document, "payload");
    }
}

#[test]
fn the_resource_server_record_round_trips_in_every_declared_state() {
    for state in [ResourceServerState::Enabled, ResourceServerState::Disabled] {
        for sources in [vec![ResourceServerId::new(uuid(0x31))], Vec::new()] {
            let server = ResourceServer {
                id: target(),
                organization_id: organization(),
                audience: Audience::new("api-a"),
                credential_profile: profile(),
                allowed_exchange_sources: sources,
                state,
            };
            let document = agrees::<_, entities::MandateCredentialResourceServer>(
                &server,
                "mandate.credential.ResourceServer",
            );
            carries_no_null(&document, "mandate.credential.ResourceServer");
        }
    }
}

#[test]
fn the_access_credential_record_round_trips_in_every_declared_state() {
    for state in [
        AccessCredentialState::Active,
        AccessCredentialState::Revoked,
    ] {
        for carried in [true, false] {
            let credential = AccessCredential {
                id: credential_id(),
                descriptor: if carried {
                    populated_descriptor()
                } else {
                    bare_descriptor()
                },
                reference_verifier: carried.then(|| CredentialVerifier::new("digest")),
                epochs: carried.then(|| EpochSnapshotRef::new(uuid(0x60))),
                issued_at: Timestamp::new("2026-09-19T00:00:00Z"),
                state,
                target: target(),
                issuing_profile: profile(),
            };
            let document = agrees::<_, entities::MandateCredentialAccessCredential>(
                &credential,
                "mandate.credential.AccessCredential",
            );
            if !carried {
                carries_no_null(&document, "mandate.credential.AccessCredential");
            }
        }
    }
}

/// The two fields the projection holds and the contract does not declare, stated and pinned.
///
/// `mandate.credential.AccessCredential` declares `descriptor`, `reference_verifier`,
/// `epochs` and `issued_at`, and **nothing that says which registration issued the
/// credential** — while both issuance events carry a `target`
/// (`CredentialReferenceIssued`, `CredentialSelfContainedIssued`). A credential's
/// revocation guarantee is the one its issuing registration published, and an audience
/// changes hands, so the projection keeps `target` and the `CredentialProfile` that
/// registration held; `services/sts/src/resolve.rs` decides the guarantee from them.
///
/// This is the residue named rather than hidden: the two fields carry `#[serde(skip)]`, the
/// declared subset above round-trips, and this case is what fails if either ever reaches the
/// wire form of the declared record. The gap is a contract observation routed to the
/// coordinator, not a decision taken here.
#[test]
fn the_credential_projection_keeps_an_issuing_registration_the_contract_does_not_declare() {
    let credential = AccessCredential {
        id: credential_id(),
        descriptor: populated_descriptor(),
        reference_verifier: Some(CredentialVerifier::new("digest")),
        epochs: None,
        issued_at: Timestamp::new("2026-09-19T00:00:00Z"),
        state: AccessCredentialState::Active,
        target: target(),
        issuing_profile: profile(),
    };

    let document = serde_json::to_value(&credential).expect("the record encodes as JSON");
    let keys: BTreeSet<&str> = document
        .as_object()
        .expect("a record encodes as an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "id",
            "descriptor",
            "reference_verifier",
            "issued_at",
            "state",
        ]),
        "the declared record is what reaches the wire; `target` and `issuing_profile` are \
         the projection's own"
    );
    // And they are on the record, which is the half that makes the residue worth keeping.
    assert_eq!(credential.target, target());
    assert_eq!(credential.issuing_profile, profile());
}

#[test]
fn the_signing_key_record_round_trips_in_every_declared_state() {
    for state in [
        SigningKeyState::Recorded,
        SigningKeyState::Retired,
        SigningKeyState::Revoked,
    ] {
        let key = SigningKey {
            id: signing_key_id(),
            key_reference: KeyReference::new("kms://one"),
            thumbprint: "thumb-one".to_owned(),
            algorithm: SigningAlgorithm::new("declared-by-deployment"),
            not_before: Timestamp::new("2026-09-19T00:00:00Z"),
            expires_at: Timestamp::new("2026-12-31T00:00:00Z"),
            state,
        };
        let document = agrees::<_, entities::MandateCredentialSigningKey>(
            &key,
            "mandate.credential.SigningKey",
        );
        carries_no_null(&document, "mandate.credential.SigningKey");
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
/// The pairing is derived from the element name rather than named by the case, so a case
/// that reaches for the wrong generated shape fails here rather than passing against a
/// sibling enum with the same variant names — `mandate.credential.SigningKey.State` and
/// `mandate.credential.AccessCredential.State` both spell `Revoked`. Then every variant
/// round-trips through that shape, and the set the crate holds is compared against the set
/// the contract declares, which is the other direction.
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

/// Every lifecycle enum this crate holds, listed by an exhaustive match so a variant added
/// and not listed here does not compile.
///
/// `mandate.credential.AuthorizationCode.State` is declared by this domain and held by no
/// type here — the code record is `services/sts`' — and is realized by
/// `mandate_federation::authorize::AuthorizationCodeState` for the read-only input that
/// crate validates.
#[test]
fn every_lifecycle_enum_agrees_with_the_state_element_it_names() {
    let servers = [ResourceServerState::Enabled, ResourceServerState::Disabled];
    for state in servers {
        match state {
            ResourceServerState::Enabled | ResourceServerState::Disabled => {}
        }
    }
    state_agrees::<_, entities::MandateCredentialResourceServerState>(
        "mandate.credential.ResourceServer.State",
        &servers,
    );

    let credentials = [
        AccessCredentialState::Active,
        AccessCredentialState::Revoked,
    ];
    for state in credentials {
        match state {
            AccessCredentialState::Active | AccessCredentialState::Revoked => {}
        }
    }
    state_agrees::<_, entities::MandateCredentialAccessCredentialState>(
        "mandate.credential.AccessCredential.State",
        &credentials,
    );

    let keys = [
        SigningKeyState::Recorded,
        SigningKeyState::Retired,
        SigningKeyState::Revoked,
    ];
    for state in keys {
        match state {
            SigningKeyState::Recorded | SigningKeyState::Retired | SigningKeyState::Revoked => {}
        }
    }
    state_agrees::<_, entities::MandateCredentialSigningKeyState>(
        "mandate.credential.SigningKey.State",
        &keys,
    );
}

/// The coverage manifest's account of this crate is exactly this crate's registry, element
/// and symbol both.
///
/// `contracts/coverage.json` maps every element of the contract to what implements it, and
/// nothing in the manifest is compiled: a symbol there is a string. This is the case that
/// makes the string answerable — the registry's right-hand sides are expanded into `use`
/// declarations by `mandate_types::realizes!`, so they exist or the crate does not build, and
/// the manifest is asserted equal to them here.
///
/// `cargo xtask coverage` decides the complementary half twice over: that every `implemented`
/// entry names a crate which runs a case like this one, and — since this crate is what taught
/// it the rule — that every crate holding a `tests/contract_agreement.rs` reconciles its own
/// entries or is named, with a reason, as one that deliberately does not.
#[test]
fn the_coverage_manifest_names_exactly_what_this_crate_realizes() {
    let registered: BTreeSet<(String, String)> = mandate_token::ESS_REALIZATIONS
        .iter()
        .map(|(element, symbol)| ((*element).to_owned(), (*symbol).to_owned()))
        .collect();
    assert_eq!(
        registered.len(),
        mandate_token::ESS_REALIZATIONS.len(),
        "the registry holds no duplicate pair"
    );
    assert_eq!(
        coverage_manifest_entries(env!("CARGO_PKG_NAME")),
        registered,
        "the coverage manifest's implemented entries for this crate are not its registry"
    );
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
