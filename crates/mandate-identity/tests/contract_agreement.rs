//! Every event, command input and entity record this crate holds agrees with the
//! generated contract shape it names, field for field.
//!
//! The check is a round trip through the generated shape and not a comparison of two Rust
//! structs: `serde_json::to_value` of the domain value, `from_value` into the
//! `mandate_contract` shape, `to_value` again, and the two documents compared. The
//! generated shapes carry `#[serde(deny_unknown_fields)]` and declare every non-optional
//! key required, so a field this crate renamed, added or dropped fails at `from_value`
//! naming the key, and a field whose *value* is written differently fails at the
//! comparison.
//!
//! Absence is checked in both directions. The contract spells an absent optional by
//! leaving the key out and declares no nullable type, so every shape with an optional is
//! built twice — once carrying it, once without — and the second form is asserted to
//! contain no `null` anywhere, at any depth.
//!
//! # What this crate does not hold a shape for
//!
//! `mandate.identity.PrincipalDisabled` and `mandate.identity.RefreshCredentialRevoked`,
//! and the `mandate.identity.RefreshCredential` record the second one moves. No handler
//! here emits either event and the refresh-credential record is not projected here, so a
//! shape for them would be a payload nothing in this crate can fill. The
//! `mandate.identity.Principal` record *is* projected here — the fold materializes it from
//! its declared seeding event — and is round-tripped below.
//!
//! `mandate.identity.SecurityEpochSnapshot` is held and is **not** round-tripped, which
//! is a recorded gap rather than an omission:
//! [`the_snapshot_projection_carries_generations_the_contract_does_not_declare`] states
//! it and pins it.

use mandate_contract::{commands, entities, events};
use mandate_identity::{
    EpochSnapshotRecorded, Generation, IdentityEvent, IncrementSecurityEpoch, Principal,
    PrincipalState, SecurityEpochIncremented, SecurityEpochRecorded, SecurityEpochSnapshot,
    Session, SessionOpened, SessionRevoked, SessionState,
};
use mandate_types::{
    Audience, CorrelationId, CredentialId, DelegationId, EpochSnapshotRef, ExecutionId,
    FederationConnectionId, OrganizationId, PrincipalId, PrincipalKind, SecurityEpochTarget,
    SessionId, Timestamp, Uuid, VerifiedContext,
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

fn connection() -> FederationConnectionId {
    FederationConnectionId::new(uuid(4))
}

fn handle() -> EpochSnapshotRef {
    EpochSnapshotRef::new(uuid(10))
}

fn session_id() -> SessionId {
    SessionId::new(uuid(20))
}

fn expires_at() -> Timestamp {
    Timestamp::new("2026-12-31T00:00:00Z")
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

/// The five `mandate.identity` event payloads this crate folds, over one context and one
/// federation binding.
fn folded_events(
    context: &VerifiedContext,
    from: Option<FederationConnectionId>,
) -> Vec<IdentityEvent> {
    vec![
        IdentityEvent::SessionOpened(SessionOpened {
            id: session_id(),
            principal_id: principal(),
            organization_id: organization(),
            connection_id: from,
            epochs: handle(),
            expires_at: expires_at(),
        }),
        IdentityEvent::SessionRevoked(SessionRevoked {
            context: context.clone(),
            id: session_id(),
        }),
        IdentityEvent::EpochSnapshotRecorded(EpochSnapshotRecorded {
            id: handle(),
            principal_id: principal(),
            organization_id: organization(),
            connection_id: from,
        }),
        IdentityEvent::SecurityEpochRecorded(SecurityEpochRecorded {
            target: SecurityEpochTarget::Principal(principal()),
            generation: Generation::new(41).expect("a non-negative generation"),
        }),
        IdentityEvent::SecurityEpochIncremented(SecurityEpochIncremented::new(
            context.clone(),
            SecurityEpochTarget::Organization(organization()),
        )),
    ]
}

/// One round trip per event, each into the generated payload of the element the event
/// names itself as.
fn each_event_agrees(
    context: &VerifiedContext,
    from: Option<FederationConnectionId>,
) -> Vec<Value> {
    let held = folded_events(context, from);
    let mut encoded = Vec::new();
    for event in &held {
        let element = event.ess_name();
        let document = match event {
            IdentityEvent::SessionOpened(_) => {
                agrees::<_, events::MandateIdentitySessionOpened>(event, element)
            }
            IdentityEvent::SessionRevoked(_) => {
                agrees::<_, events::MandateIdentitySessionRevoked>(event, element)
            }
            IdentityEvent::EpochSnapshotRecorded(_) => {
                agrees::<_, events::MandateIdentityEpochSnapshotRecorded>(event, element)
            }
            IdentityEvent::SecurityEpochRecorded(_) => {
                agrees::<_, events::MandateIdentitySecurityEpochRecorded>(event, element)
            }
            IdentityEvent::SecurityEpochIncremented(_) => {
                agrees::<_, events::MandateIdentitySecurityEpochIncremented>(event, element)
            }
            // The two `mandate.federation` payloads this crate folds are the generated
            // shapes themselves rather than copies of them, because the direction is
            // `mandate-federation → mandate-identity` and never the reverse. There is
            // nothing here to round-trip *into* — each event already is the contract's own
            // type.
            IdentityEvent::FederationAuthenticated(_)
            | IdentityEvent::ExternalPrincipalProvisioned(_) => continue,
        };
        encoded.push(document);
    }
    assert_eq!(
        encoded.len(),
        5,
        "every event payload this crate declares is round-tripped"
    );
    encoded
}

#[test]
fn every_event_round_trips_with_every_optional_carried() {
    each_event_agrees(&populated_context(), Some(connection()));
}

#[test]
fn every_event_round_trips_with_every_optional_absent_and_spells_absence_by_omission() {
    for document in each_event_agrees(&bare_context(), None) {
        carries_no_null(&document, "payload");
    }
}

#[test]
fn every_command_input_round_trips_into_its_generated_shape() {
    for context in [populated_context(), bare_context()] {
        let increment =
            IncrementSecurityEpoch::new(context, SecurityEpochTarget::Federation(connection()));
        agrees::<_, commands::MandateIdentityIncrementSecurityEpochInput>(
            &increment,
            "mandate.identity.IncrementSecurityEpoch",
        );
    }
}

#[test]
fn the_session_record_round_trips_into_its_generated_shape_in_every_declared_state() {
    for from in [Some(connection()), None] {
        for revoked in [false, true] {
            let session = Session::new(
                session_id(),
                principal(),
                organization(),
                handle(),
                expires_at(),
            );
            let session = match from {
                Some(connection_id) => session.with_connection(connection_id),
                None => session,
            };
            let session = if revoked { session.revoke() } else { session };
            assert_eq!(
                session.state(),
                if revoked {
                    SessionState::Revoked
                } else {
                    SessionState::Active
                }
            );

            let document =
                agrees::<_, entities::MandateIdentitySession>(&session, "mandate.identity.Session");
            if from.is_none() {
                carries_no_null(&document, "mandate.identity.Session");
            }
        }
    }
}

/// `mandate.identity.Principal`, the record the fold materializes from its declared
/// seeding event, against the generated entity shape.
///
/// The record carries the three declared fields and the lifecycle state, and the round
/// trip closes the key set: a field this crate renamed, added or dropped fails at
/// `from_value` naming the key.
#[test]
fn the_principal_record_round_trips_into_its_generated_shape() {
    let record = Principal::new(principal(), PrincipalKind::User, "subject-one".to_owned());

    assert_eq!(record.id(), &principal());
    assert_eq!(record.kind(), PrincipalKind::User);
    assert_eq!(record.display_name(), "subject-one");
    assert_eq!(record.state(), PrincipalState::Active);

    let document =
        agrees::<_, entities::MandateIdentityPrincipal>(&record, "mandate.identity.Principal");
    carries_no_null(&document, "mandate.identity.Principal");
}

/// The one held record that does not round-trip, and why.
///
/// `mandate.identity.SecurityEpochSnapshot` declares an identity, a principal, an
/// organization and an optional connection, and **no generation**: "EpochSnapshotRef is
/// only an immutable record handle, never an epoch number" (`identity.yaml`,
/// `UNMAPPED-EPOCH`). The per-dimension generations the architecture addendum requires
/// live on this crate's projection of that record and have no declared home, so the
/// crate's record is a superset of the contract's and cannot be its round trip.
///
/// This states the gap rather than hiding it: the declared subset — which is exactly what
/// `mandate.identity.EpochSnapshotRecorded` carries, and what a replay rebuilds the
/// record from — is round-tripped through the event's own shape above, and the residue is
/// named here.
#[test]
fn the_snapshot_projection_carries_generations_the_contract_does_not_declare() {
    let snapshot = SecurityEpochSnapshot::new(
        handle(),
        principal(),
        Generation::new(41).expect("a non-negative generation"),
        organization(),
        Generation::new(7).expect("a non-negative generation"),
    );

    assert_eq!(
        snapshot.recorded(&SecurityEpochTarget::Principal(principal())),
        Generation::new(41),
        "the addendum's per-dimension value, which the declared record has no field for"
    );
    assert_eq!(snapshot.id(), &handle());
    assert_eq!(snapshot.principal(), &principal());
    assert_eq!(snapshot.organization(), &organization());
    assert_eq!(snapshot.connection(), None);

    // The declared record's own fields, which the event carries and a fold rebuilds the
    // projection from.
    let declared = EpochSnapshotRecorded {
        id: *snapshot.id(),
        principal_id: *snapshot.principal(),
        organization_id: *snapshot.organization(),
        connection_id: snapshot.connection().copied(),
    };
    agrees::<_, events::MandateIdentityEpochSnapshotRecorded>(
        &declared,
        "mandate.identity.EpochSnapshotRecorded",
    );
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
/// sibling enum with the same variant names — `mandate.identity.Session.State` and
/// `mandate.identity.Principal.State` both spell `Active`. Then every variant round-trips
/// through that shape, and the set the crate holds is compared against the set the
/// contract declares, which is the other direction.
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
/// There are two: the session's and the principal's, both records this crate folds.
/// `mandate.identity.RefreshCredential.State` is declared by this domain and held by no
/// type here — that record is not projected by this crate — and the three generation
/// records declare a single-state lifecycle (`Recorded`) that no enum here names either,
/// because `EpochState` carries a generation and a stream version rather than a lifecycle.
/// `mandate-federation` holds its own `mandate.identity.Principal.State` for the port it
/// reads the principal record through, and decides it in its own agreement case; the two
/// are one declared lifecycle held by two readers, and both are decided against the same
/// generated shape.
#[test]
fn every_lifecycle_enum_agrees_with_the_state_element_it_names() {
    let sessions = [SessionState::Active, SessionState::Revoked];
    for state in sessions {
        match state {
            SessionState::Active | SessionState::Revoked => {}
        }
    }
    state_agrees::<_, entities::MandateIdentitySessionState>(
        "mandate.identity.Session.State",
        &sessions,
    );

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
}

/// The registry and the list of what it does not cover account for every declared element
/// of this domain, once each.
///
/// The reverse direction of the case above: that one asks whether every registered element
/// is declared, this one asks whether every *declared* element is accounted for — by
/// `ESS_REALIZATIONS` or by `ESS_UNREALIZED`, never by both and never by neither. A
/// registry read as coverage is read as a statement about the whole domain, and an element
/// nobody named is the one shape of drift a list of what *is* covered cannot show.
#[test]
fn every_declared_element_of_this_domain_is_realized_or_named_as_unrealized() {
    let ir = system_ir();
    let realized: BTreeSet<&str> = mandate_identity::ESS_REALIZATIONS
        .iter()
        .map(|(element, _)| *element)
        .collect();
    let unrealized: BTreeSet<&str> = mandate_identity::ESS_UNREALIZED
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
                .filter(|element| element.starts_with("mandate.identity."))
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
    for (element, reason) in mandate_identity::ESS_UNREALIZED {
        assert!(
            !reason.trim().is_empty(),
            "{element} is named as unrealized with no reason"
        );
    }
}

/// Every element the crate registers as realized is one the contract declares.
///
/// The registry's other half is the compiler's: `mandate_types::realizes!` expands each
/// entry into a `use` of the symbol on the right, so a symbol that moved does not build.
/// What no compiler can check is the string on the left, which is the half a coverage
/// report is read through.
#[test]
fn every_realized_element_is_one_the_contract_declares() {
    let ir = system_ir();
    let kinds = ["commands", "events", "entities", "errors", "types"];

    assert!(
        !mandate_identity::ESS_REALIZATIONS.is_empty(),
        "the crate registers what it realizes"
    );
    for (element, symbol) in mandate_identity::ESS_REALIZATIONS {
        assert!(
            kinds
                .iter()
                .any(|kind| ir[kind].get(element).is_some_and(|node| !node.is_null())),
            "{element} (realized by {symbol}) is declared by no commands, events, \
             entities, errors or types index of generated/ir/system.json"
        );
        assert!(
            element.starts_with("mandate.identity."),
            "{element} (realized by {symbol}) is not an element of this crate's domain"
        );
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
    let registered: BTreeSet<(String, String)> = mandate_identity::ESS_REALIZATIONS
        .iter()
        .map(|(element, symbol)| ((*element).to_owned(), (*symbol).to_owned()))
        .collect();
    assert_eq!(
        registered.len(),
        mandate_identity::ESS_REALIZATIONS.len(),
        "the registry holds no duplicate pair"
    );
    assert_eq!(
        coverage_manifest_entries(env!("CARGO_PKG_NAME")),
        registered,
        "the coverage manifest's implemented entries for this crate are not its registry"
    );
    no_unrealized_element_contradicts_the_coverage_manifest(mandate_identity::ESS_UNREALIZED);
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
