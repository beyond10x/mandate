//! Every projection and every declared payload agrees with its generated contract shape.
//!
//! The claim is a **round trip**, not a key-set comparison: a domain value serializes,
//! the generated `mandate_contract` shape reads that document back, and re-serializing
//! the shape produces the same document. Reading it back refuses a key the contract does
//! not declare and refuses a document missing a key it requires, because every generated
//! shape carries `#[serde(deny_unknown_fields)]` and declares every non-optional key
//! required. It also refuses every *value* the contract does not declare — a state string
//! that is no variant of the compiled state enum, a field whose JSON type differs — and
//! that is what the one-directional check this file retires from
//! `crates/mandate-model/tests/projections.rs` could not see: that check compared the
//! emitted key set against the entity's `properties` and `required` lists and read no
//! value at all. Re-serializing and comparing then refuses a shape that reads a document
//! and renders it back differently.
//!
//! What this file does **not** see, measured rather than assumed: a projection that never
//! writes a *declared optional* key. An absent optional is a document the contract admits,
//! so the round trip is a fixed point either way, and dropping `Resource::space_id` from
//! the serialization leaves all five cases here green. `projections.rs`
//! `an_absent_optional_field_is_not_written_and_a_present_one_round_trips` is what turns
//! red for that, and it is one of the cases kept there.
//!
//! Four things are decided here, for the six projections and the twelve payloads:
//!
//! * the round trip itself, over every state each projection can hold and over the
//!   present and absent form of every optional either side declares;
//! * that the set of states a projection holds is exactly the `enum` its generated
//!   `<Entity>.State` declares, so a renamed variant or a moved string is a failure
//!   rather than a silently different wire form;
//! * that an absent optional is an absent key and never `null`, at every depth of the
//!   emitted document, and that the generated shape refuses `null` at every key it
//!   declares — walked off the compiled schema, so a key added to the contract is
//!   covered without this file being edited;
//! * that each element is paired with the generated shape **its own name derives to**,
//!   by ESS's `declaration_name` rule — the round trip cannot do this, because the six
//!   `{context, id}` payloads are structurally identical and reproduce each other's
//!   documents exactly;
//! * that [`mandate_model::ESS_REALIZATIONS`] names exactly the 39 elements this crate
//!   implements — these eighteen and the four accepted `mandate.core` records — that each
//!   is a compiled declaration under `generated/schema`, and that each symbol is the one
//!   its element name says it should be.
//!
//! The samples are built here rather than by driving the fold: `tests/replay.rs` decides
//! what the commands produce, and this file decides what the produced shapes *are*.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use mandate_contract::entities;
use mandate_contract::events;

use mandate_model::graph::{Resource, ResourceEvent, ResourceState};
use mandate_model::tenancy::{
    Organization, OrganizationMembership, OrganizationMembershipState, OrganizationState, Space,
    SpaceState, Team, TeamMembership, TeamMembershipState, TeamState, TenancyEvent,
};
use mandate_types::{
    Audience, CorrelationId, CredentialId, DelegationId, ExecutionId, MembershipContributionId,
    OrganizationId, OrganizationMembershipId, PrincipalId, ResourceId, ResourceRef, ResourceType,
    SpaceId, TeamId, TeamMembershipId, VerifiedContext,
};

const SCHEMA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../generated/schema");

/// The six entities this crate projects.
const PROJECTED: [&str; 6] = [
    "mandate.tenancy.Organization",
    "mandate.tenancy.OrganizationMembership",
    "mandate.tenancy.Team",
    "mandate.tenancy.TeamMembership",
    "mandate.tenancy.Space",
    "mandate.graph.Resource",
];

fn uuid(tag: u16) -> String {
    format!("1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f{tag:04x}")
}

fn organization(tag: u16) -> OrganizationId {
    OrganizationId::parse(&uuid(tag)).expect("organization identity")
}

fn principal(tag: u16) -> PrincipalId {
    PrincipalId::parse(&uuid(tag)).expect("principal identity")
}

fn resource(tag: u16) -> ResourceId {
    ResourceId::parse(&uuid(tag)).expect("resource identity")
}

/// The compiled declaration of one element.
fn schema(directory: &str, ess_name: &str) -> Value {
    let path = format!("{SCHEMA}/{directory}/{ess_name}.schema.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
    serde_json::from_str(&text).expect("the compiled declaration is JSON")
}

/// Every element the compiled model declares in one directory.
/// The tenancy commands `Tenancy::decide_*` decides, and the domain's refusal.
const TENANCY_COMMANDS: [&str; 11] = [
    "mandate.tenancy.CreateOrganization",
    "mandate.tenancy.CloseOrganization",
    "mandate.tenancy.AddOrganizationMembership",
    "mandate.tenancy.RemoveOrganizationMembership",
    "mandate.tenancy.CreateTeam",
    "mandate.tenancy.RetireTeam",
    "mandate.tenancy.AddTeamMembership",
    "mandate.tenancy.RemoveTeamMembership",
    "mandate.tenancy.CreateSpace",
    "mandate.tenancy.RetireSpace",
    "mandate.tenancy.Denied",
];

fn schema_names(directory: &str) -> BTreeSet<String> {
    let path = format!("{SCHEMA}/{directory}");
    std::fs::read_dir(&path)
        .unwrap_or_else(|error| panic!("{path}: {error}"))
        .map(|entry| entry.expect("directory entry").file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .filter_map(|name| name.strip_suffix(".schema.json").map(str::to_owned))
        .collect()
}

/// One domain value that agreed with its generated shape, and the document it emitted.
struct Agreement {
    /// The element the value realizes.
    ess_name: &'static str,
    /// Where the compiled declaration of that element lives.
    directory: &'static str,
    /// The generated shape the element was paired with, as `std::any::type_name` writes it.
    rust_name: &'static str,
    /// What the domain value serialized to, which the generated shape reproduced exactly.
    emitted: Value,
    /// Whether the generated shape reads a document back. Used to decide the refusals.
    accepts: fn(Value) -> bool,
}

/// ESS's `declaration_name`, the rule that decides which Rust name an element takes.
///
/// Reproduced from `xtask/src/emit.rs:266-279`, which reproduces ESS 0.26.0's own
/// `declaration_name`: split on every character Rust cannot carry, upper-case the first
/// letter of each part, and join. `mandate.tenancy.OrganizationClosed` becomes
/// `MandateTenancyOrganizationClosed`; only the first letter of a part is touched.
fn declaration_name(ess_name: &str) -> String {
    let mut derived = String::new();
    for part in ess_name
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
    {
        let mut characters = part.chars();
        if let Some(first) = characters.next() {
            derived.push(first.to_ascii_uppercase());
            derived.push_str(characters.as_str());
        }
    }
    derived
}

fn accepts_as<C: DeserializeOwned>(value: Value) -> bool {
    serde_json::from_value::<C>(value).is_ok()
}

/// Serialize the domain value, read it back as the generated shape, and serialize that.
///
/// Panics with the element's name on any of the three failures: the domain value does not
/// serialize, the generated shape refuses the document, or the document the shape emits
/// differs from the one it was read from.
fn round_trip<D: Serialize, C: Serialize + DeserializeOwned>(ess_name: &str, domain: &D) -> Value {
    let emitted = serde_json::to_value(domain)
        .unwrap_or_else(|error| panic!("{ess_name}: the domain value does not serialize: {error}"));
    let shape: C = serde_json::from_value(emitted.clone()).unwrap_or_else(|error| {
        panic!("{ess_name}: the generated shape refuses {emitted}: {error}")
    });
    let again = serde_json::to_value(&shape).unwrap_or_else(|error| {
        panic!("{ess_name}: the generated shape does not serialize: {error}")
    });
    assert_eq!(
        emitted, again,
        "{ess_name}: the round trip through the generated shape is not a fixed point"
    );
    emitted
}

/// One projection beside the generated entity record it must agree with.
macro_rules! projection {
    ($ess:literal, $shape:ty, $domain:expr $(,)?) => {
        Agreement {
            ess_name: $ess,
            directory: "entities",
            rust_name: std::any::type_name::<$shape>(),
            emitted: round_trip::<_, $shape>($ess, &$domain),
            accepts: accepts_as::<$shape>,
        }
    };
}

/// One event beside the generated payload it must agree with.
///
/// The element name is the event's own [`TenancyEvent::ess_name`] rather than a literal,
/// so the payload each variant claims to be is the payload it is decided against. That on
/// its own binds the *left* side only: the generated shape on the right is a hand-typed
/// path, and the round trip cannot tell two structurally identical payloads apart — the
/// six `{context, id}` payloads reproduce each other's documents exactly.
/// `every_pairing_is_the_generated_shape_its_element_name_derives_to` is what compares the
/// two sides, by ESS's own `declaration_name` rule, and `rust_name` is what it reads.
macro_rules! payload {
    ($shape:ty, $domain:expr $(,)?) => {{
        let event = $domain;
        let ess_name = event.ess_name();
        Agreement {
            ess_name,
            directory: "events",
            rust_name: std::any::type_name::<$shape>(),
            emitted: round_trip::<_, $shape>(ess_name, &event),
            accepts: accepts_as::<$shape>,
        }
    }};
}

/// Every variant of one domain state enum, with a wildcard-free `match` beside it.
///
/// The `match` is the compile-time half: a variant added to the enum and not named here
/// does not compile, so a state loop cannot silently fall behind the enum it loops over.
/// The runtime half is
/// `every_state_a_projection_holds_is_exactly_what_its_generated_state_enum_declares`,
/// which compares what the loops produced against the compiled `enum` — so a variant named
/// in the `match` but left out of the list is red there.
macro_rules! domain_states {
    ($name:ident, $enum:ty, [$($variant:path),+ $(,)?]) => {
        fn $name() -> Vec<$enum> {
            let all = vec![$($variant),+];
            for state in &all {
                match state {
                    $($variant => {})+
                }
            }
            all
        }
    };
}

domain_states!(
    organization_states,
    OrganizationState,
    [OrganizationState::Recorded, OrganizationState::Closed]
);
domain_states!(
    organization_membership_states,
    OrganizationMembershipState,
    [
        OrganizationMembershipState::Active,
        OrganizationMembershipState::Removed
    ]
);
domain_states!(
    team_states,
    TeamState,
    [TeamState::Recorded, TeamState::Retired]
);
domain_states!(
    team_membership_states,
    TeamMembershipState,
    [TeamMembershipState::Recorded, TeamMembershipState::Removed]
);
domain_states!(
    space_states,
    SpaceState,
    [SpaceState::Recorded, SpaceState::Retired]
);
domain_states!(
    resource_states,
    ResourceState,
    [ResourceState::Recorded, ResourceState::Deregistered]
);

/// Every projection, in every state it holds and in the present and absent form of every
/// optional it declares.
fn projection_agreements() -> Vec<Agreement> {
    let organization_id = organization(1);
    let principal_id = principal(0x10);
    let team_id = TeamId::parse(&uuid(0x30)).expect("team identity");
    let space_id = SpaceId::parse(&uuid(0x40)).expect("space identity");
    let mut agreements = Vec::new();

    for state in organization_states() {
        agreements.push(projection!(
            "mandate.tenancy.Organization",
            entities::MandateTenancyOrganization,
            Organization {
                id: organization_id,
                display_name: "Acme".to_owned(),
                state,
            },
        ));
    }

    for state in organization_membership_states() {
        agreements.push(projection!(
            "mandate.tenancy.OrganizationMembership",
            entities::MandateTenancyOrganizationMembership,
            OrganizationMembership {
                id: OrganizationMembershipId::parse(&uuid(0x20)).expect("membership identity"),
                organization_id,
                principal_id,
                state,
            },
        ));
    }

    for state in team_states() {
        agreements.push(projection!(
            "mandate.tenancy.Team",
            entities::MandateTenancyTeam,
            Team {
                id: team_id,
                organization_id,
                display_name: "Platform".to_owned(),
                state,
            },
        ));
    }

    for state in team_membership_states() {
        agreements.push(projection!(
            "mandate.tenancy.TeamMembership",
            entities::MandateTenancyTeamMembership,
            TeamMembership {
                id: TeamMembershipId::parse(&uuid(0x50)).expect("team membership identity"),
                organization_id,
                team_id,
                principal_id,
                state,
            },
        ));
    }

    for state in space_states() {
        agreements.push(projection!(
            "mandate.tenancy.Space",
            entities::MandateTenancySpace,
            Space {
                id: space_id,
                organization_id,
                display_name: "Production".to_owned(),
                state,
            },
        ));
    }

    // `mandate.graph.Resource` is the only projection with optional keys: both present,
    // one present, and both absent.
    for state in resource_states() {
        for (parent, space) in [
            (Some(resource(0x101)), Some(space_id)),
            (Some(resource(0x101)), None),
            (None, None),
        ] {
            agreements.push(projection!(
                "mandate.graph.Resource",
                entities::MandateGraphResource,
                Resource {
                    id: resource(0x100),
                    organization_id,
                    resource_type: ResourceType::new("document"),
                    parent,
                    space_id: space,
                    state,
                },
            ));
        }
    }

    agreements
}

/// The verified context every payload carries, fully populated or with every optional
/// absent.
fn context(populated: bool) -> VerifiedContext {
    VerifiedContext {
        subject: principal(0x10),
        actor: populated.then(|| principal(0x11)),
        organization: organization(1),
        audience: Audience::new("mandate"),
        credential: CredentialId::parse(&uuid(0xff00)).expect("credential identity"),
        delegation: populated
            .then(|| DelegationId::parse(&uuid(0xff01)).expect("delegation identity")),
        execution: populated
            .then(|| ExecutionId::parse(&uuid(0xff02)).expect("execution identity")),
        correlation: CorrelationId::new("correlation"),
    }
}

/// Every declared payload, with the verified context populated and with it all-absent.
fn payload_agreements() -> Vec<Agreement> {
    let organization_id = organization(1);
    let principal_id = principal(0x10);
    let team_id = TeamId::parse(&uuid(0x30)).expect("team identity");
    let space_id = SpaceId::parse(&uuid(0x40)).expect("space identity");
    let mut agreements = Vec::new();

    for populated in [true, false] {
        let context = context(populated);
        agreements.extend([
            payload!(
                events::MandateTenancyOrganizationCreated,
                TenancyEvent::OrganizationCreated {
                    context: context.clone(),
                    organization_id,
                    display_name: "Acme".to_owned(),
                },
            ),
            payload!(
                events::MandateTenancyOrganizationClosed,
                TenancyEvent::OrganizationClosed {
                    context: context.clone(),
                    id: organization_id,
                },
            ),
            payload!(
                events::MandateTenancyOrganizationMembershipAdded,
                TenancyEvent::OrganizationMembershipAdded {
                    context: context.clone(),
                    organization_id,
                    principal_id,
                    membership_id: OrganizationMembershipId::parse(&uuid(0x20))
                        .expect("membership identity"),
                },
            ),
            payload!(
                events::MandateTenancyOrganizationMembershipRemoved,
                TenancyEvent::OrganizationMembershipRemoved {
                    context: context.clone(),
                    id: OrganizationMembershipId::parse(&uuid(0x20)).expect("membership identity"),
                },
            ),
            payload!(
                events::MandateTenancyTeamCreated,
                TenancyEvent::TeamCreated {
                    context: context.clone(),
                    team_id,
                    display_name: "Platform".to_owned(),
                },
            ),
            payload!(
                events::MandateTenancyTeamRetired,
                TenancyEvent::TeamRetired {
                    context: context.clone(),
                    id: team_id,
                },
            ),
            payload!(
                events::MandateTenancyTeamMembershipAdded,
                TenancyEvent::TeamMembershipAdded {
                    context: context.clone(),
                    team_id,
                    principal_id,
                    team_membership_id: TeamMembershipId::parse(&uuid(0x50))
                        .expect("team membership identity"),
                    contribution_id: MembershipContributionId::parse(&uuid(0x60))
                        .expect("contribution identity"),
                },
            ),
            payload!(
                events::MandateTenancyTeamMembershipRemoved,
                TenancyEvent::TeamMembershipRemoved {
                    context: context.clone(),
                    id: TeamMembershipId::parse(&uuid(0x50)).expect("team membership identity"),
                },
            ),
            payload!(
                events::MandateTenancySpaceCreated,
                TenancyEvent::SpaceCreated {
                    context: context.clone(),
                    space_id,
                    display_name: "Production".to_owned(),
                },
            ),
            payload!(
                events::MandateTenancySpaceRetired,
                TenancyEvent::SpaceRetired {
                    context: context.clone(),
                    id: space_id,
                },
            ),
            payload!(
                events::MandateGraphResourceDeregistered,
                ResourceEvent::Deregistered {
                    context: context.clone(),
                    id: resource(0x100),
                },
            ),
        ]);

        // `parent` is the only optional either event enum declares; both forms are
        // crossed with both forms of the context.
        for parent in [Some(resource(0x101)), None] {
            agreements.push(payload!(
                events::MandateGraphResourceRegistered,
                ResourceEvent::Registered {
                    context: context.clone(),
                    resource_id: resource(0x100),
                    resource: ResourceRef {
                        resource_type: ResourceType::new("document"),
                        resource_id: resource(0x100),
                    },
                    parent,
                },
            ));
        }
    }

    agreements
}

/// The twelve payloads the compiled model declares for this crate's two event enums.
fn declared_payloads() -> BTreeSet<String> {
    schema_names("events")
        .into_iter()
        .filter(|name| {
            name.starts_with("mandate.tenancy.") || name.starts_with("mandate.graph.Resource")
        })
        .collect()
}

/// Resolve a schema property to the node that declares it.
fn resolve(document: &Value, property: &Value) -> Value {
    match property["$ref"].as_str() {
        Some(reference) => document["$defs"][reference.trim_start_matches("#/$defs/")].clone(),
        None => property.clone(),
    }
}

/// The document with `null` written at `path`, creating the key when it is absent.
fn with_null(root: &Value, path: &[String]) -> Value {
    let mut document = root.clone();
    let mut cursor = &mut document;
    for (index, key) in path.iter().enumerate() {
        let object = cursor
            .as_object_mut()
            .expect("a declared key sits inside an object");
        if index + 1 == path.len() {
            object.insert(key.clone(), Value::Null);
            break;
        }
        cursor = object
            .get_mut(key)
            .expect("the path was walked over present keys only");
    }
    document
}

/// No emitted document carries `null` anywhere: an absent optional is an absent key.
fn assert_no_null(ess_name: &str, path: &str, value: &Value) {
    match value {
        Value::Null => panic!("{ess_name}: an absent optional was written as null at {path}"),
        Value::Object(object) => {
            for (key, child) in object {
                assert_no_null(ess_name, &format!("{path}.{key}"), child);
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                assert_no_null(ess_name, &format!("{path}[{index}]"), item);
            }
        }
        _ => {}
    }
}

/// Every key the compiled declaration names — present in the emitted document or absent
/// from it — is refused as `null` by the generated shape, at every depth.
fn assert_null_is_refused(
    agreement: &Agreement,
    document: &Value,
    node: &Value,
    path: &[String],
    value: &Value,
) {
    let Some(properties) = node["properties"].as_object() else {
        return;
    };
    for (key, property) in properties {
        let mut at = path.to_vec();
        at.push(key.clone());
        let mutated = with_null(&agreement.emitted, &at);
        assert!(
            !(agreement.accepts)(mutated.clone()),
            "{}: the generated shape accepted an explicit null at {}: {mutated}",
            agreement.ess_name,
            at.join("."),
        );
        if let Some(child) = value.get(key) {
            assert_null_is_refused(
                agreement,
                document,
                &resolve(document, property),
                &at,
                child,
            );
        }
    }
}

#[test]
fn every_projection_round_trips_exactly_into_its_generated_entity_shape() {
    let agreements = projection_agreements();
    let covered: BTreeSet<&str> = agreements
        .iter()
        .map(|agreement| agreement.ess_name)
        .collect();
    assert_eq!(
        covered,
        PROJECTED.into_iter().collect::<BTreeSet<&str>>(),
        "every projection this crate writes has a round trip",
    );
    for agreement in &agreements {
        assert!(
            agreement.emitted.is_object(),
            "{}: a projection encodes as a JSON object",
            agreement.ess_name
        );
    }
}

#[test]
fn every_declared_payload_round_trips_exactly_into_its_generated_event_shape() {
    let declared = declared_payloads();
    assert_eq!(declared.len(), 12, "declared payloads: {declared:?}");
    let covered: BTreeSet<String> = payload_agreements()
        .iter()
        .map(|agreement| agreement.ess_name.to_owned())
        .collect();
    assert_eq!(
        covered, declared,
        "every payload this crate's event enums declare has a round trip",
    );
}

#[test]
fn every_state_a_projection_holds_is_exactly_what_its_generated_state_enum_declares() {
    let mut held: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for agreement in projection_agreements() {
        let state = agreement.emitted["state"]
            .as_str()
            .unwrap_or_else(|| panic!("{}: the state is not a string", agreement.ess_name))
            .to_owned();
        held.entry(agreement.ess_name).or_default().insert(state);
    }
    for name in PROJECTED {
        let document = schema("entities", name);
        let declared: BTreeSet<String> = document["$defs"][format!("{name}.State")]["enum"]
            .as_array()
            .unwrap_or_else(|| panic!("{name}: no compiled state enum"))
            .iter()
            .map(|variant| {
                variant
                    .as_str()
                    .unwrap_or_else(|| panic!("{name}: a declared variant is not a string"))
                    .to_owned()
            })
            .collect();
        assert_eq!(
            held[name], declared,
            "{name}: the states the projection holds are not the declared variants",
        );
    }
}

#[test]
fn an_absent_optional_is_an_absent_key_and_never_null() {
    let agreements: Vec<Agreement> = projection_agreements()
        .into_iter()
        .chain(payload_agreements())
        .collect();
    assert_eq!(agreements.len(), 42, "cases: {}", agreements.len());
    for agreement in &agreements {
        assert_no_null(agreement.ess_name, "", &agreement.emitted);
        let document = schema(agreement.directory, agreement.ess_name);
        assert_null_is_refused(agreement, &document, &document, &[], &agreement.emitted);
    }
}

/// The generated shape each element is paired with is the one its name derives to.
///
/// Neither half of the agreement can see a wrong pairing on its own. `ess_name()` binds
/// the element to the domain value, and the round trip binds the document to the generated
/// shape, but the shape is a hand-typed path: the six `{context, id}` payloads and the 23
/// state enums that share a variant list are structurally interchangeable, so every
/// cross-pairing among them survives the whole procedure. This is the case that compares
/// the two sides, by ESS's own rule, and it is why `rust_name` exists.
#[test]
fn every_pairing_is_the_generated_shape_its_element_name_derives_to() {
    let agreements: Vec<Agreement> = projection_agreements()
        .into_iter()
        .chain(payload_agreements())
        .collect();
    for agreement in &agreements {
        let derived = declaration_name(agreement.ess_name);
        let declared = agreement
            .rust_name
            .rsplit("::")
            .next()
            .expect("a Rust type path");
        assert_eq!(
            declared, derived,
            "{}: paired with {}, which is not the {derived} its name derives to",
            agreement.ess_name, agreement.rust_name,
        );
        assert!(
            agreement.rust_name.ends_with(&derived),
            "{}: {} does not end with {derived}",
            agreement.ess_name,
            agreement.rust_name,
        );
        let document = schema(agreement.directory, agreement.ess_name);
        assert_eq!(
            document["x-ess-name"].as_str(),
            Some(agreement.ess_name),
            "{}: the compiled declaration this case reads names {}",
            agreement.ess_name,
            document["x-ess-name"],
        );
    }

    // The rule has to discriminate to be evidence: two elements deriving to one Rust name
    // would make the check above pass for a swap between them. ESS refuses that itself
    // (`name_collision`, reproduced at `xtask/src/emit.rs:505-528`); this is that refusal
    // over the eighteen elements here.
    let elements: BTreeSet<&str> = agreements
        .iter()
        .map(|agreement| agreement.ess_name)
        .collect();
    let derived: BTreeSet<String> = elements
        .iter()
        .map(|element| declaration_name(element))
        .collect();
    assert_eq!(elements.len(), 18, "elements paired");
    assert_eq!(
        derived.len(),
        elements.len(),
        "two of these elements derive to one Rust name, so the pairing check cannot \
         discriminate between them",
    );
}

#[test]
fn the_realization_registry_names_exactly_the_projections_payloads_and_records_this_crate_writes() {
    let registered: BTreeSet<&str> = mandate_model::ESS_REALIZATIONS
        .iter()
        .map(|(element, _)| *element)
        .collect();
    assert_eq!(
        registered.len(),
        mandate_model::ESS_REALIZATIONS.len(),
        "the registry holds no duplicate",
    );

    // The lifecycle enum of every projection, derived from `PROJECTED` rather than
    // repeated: a record this crate folds holds a state, and the element that names it is
    // the record's own name with `.State`. Registering the record and leaving its state to
    // the generated contract shape is what put six `.State` elements in the coverage
    // manifest as implemented by a shape ESS emits for every declared entity.
    let states: Vec<String> = PROJECTED
        .iter()
        .map(|record| format!("{record}.State"))
        .collect();
    let mut expected: BTreeSet<&str> = PROJECTED.into_iter().collect();
    expected.extend(states.iter().map(String::as_str));
    let payloads = payload_agreements();
    expected.extend(payloads.iter().map(|agreement| agreement.ess_name));
    // The four accepted `mandate.core` records, taken from this crate's own conformance
    // registry rather than repeated here: a record added there and not registered is red.
    expected.extend(
        mandate_model::conformance::entries()
            .iter()
            .map(|entry| entry.ess_name),
    );
    // The ten tenancy commands this crate decides and the domain's refusal, registered as
    // `@ Tenancy::decide_*` and `Denied` since wave D's second correction round.
    expected.extend(TENANCY_COMMANDS);
    assert_eq!(
        registered, expected,
        "the registry is not every element this crate implements: six projections and their \
         six lifecycle enums, twelve payloads and four accepted records",
    );
    assert_eq!(
        mandate_model::ESS_REALIZATIONS.len(),
        39,
        "the registry pins 39 elements: 22 as it stood, the six lifecycle enums wave D's \
         first correction round moved off the generated shapes, and the ten tenancy \
         commands this crate decides plus the domain's refusal, registered by the second",
    );

    let entities = schema_names("entities");
    let events = schema_names("events");
    let types = schema_names("types");
    let commands = schema_names("commands");
    let errors = schema_names("errors");
    for (element, symbol) in mandate_model::ESS_REALIZATIONS {
        assert!(
            entities.contains(*element)
                || events.contains(*element)
                || types.contains(*element)
                || commands.contains(*element)
                || errors.contains(*element),
            "{element}: the registry names an element the compiled model does not declare",
        );
        assert!(
            symbol.starts_with("crate::"),
            "{element}: the registry names {symbol}, which is not a symbol of this crate",
        );

        let mut parts = element.splitn(3, '.');
        assert_eq!(
            parts.next(),
            Some("mandate"),
            "{element}: not a mandate element"
        );
        let domain = parts.next().expect("a domain");
        let local = parts.next().expect("a local name");

        if events.contains(*element) {
            // An event payload is realized by a **variant**, and a variant name is not
            // derivable from the element: `mandate.graph.ResourceRegistered` is
            // `ResourceEvent::Registered`. What is decidable by name is the module the
            // domain names and that the symbol is a variant of an event enum in it. The
            // variant itself is decided elsewhere and not by name:
            // `every_declared_payload_round_trips_exactly_into_its_generated_event_shape`
            // takes each element name from `ess_name()` on the variant, and
            // `every_pairing_is_the_generated_shape_its_element_name_derives_to` pairs that
            // name with the generated payload shape by derivation.
            let module = format!("crate::{domain}::");
            assert!(
                symbol.starts_with(&module) && symbol.contains("Event::"),
                "{element}: the registry names {symbol}, not a variant of an event enum in \
                 {module}",
            );
        } else if TENANCY_COMMANDS.contains(element) && !element.ends_with(".Denied") {
            // A tenancy command is decided by the `Tenancy` aggregate: registered as the
            // deciding function where the compiler can take it as a value, and as the
            // aggregate itself where the function takes an `impl Trait` argument.
            assert!(
                *symbol == "crate::tenancy::Tenancy"
                    || symbol.starts_with("crate::tenancy::Tenancy::decide_"),
                "{element}: the registry names {symbol}, not the aggregate that decides it",
            );
        } else {
            // A record is realized by a type, and the type's own name is the element's
            // local part: `mandate.core.*` is declared at the crate root, every other
            // domain in the module that domain names. A lifecycle enum is the one place the
            // element's name and the Rust name differ by a rule rather than by identity —
            // `mandate.graph.Resource.State` is `ResourceState`, beside the record — and the
            // rule is written here so a state enum registered against the wrong record is
            // red.
            let local = match local.strip_suffix(".State") {
                Some(record) => format!("{record}State"),
                None => local.to_owned(),
            };
            let expected = if domain == "core" {
                format!("crate::{local}")
            } else {
                format!("crate::{domain}::{local}")
            };
            assert_eq!(
                *symbol, expected,
                "{element}: the registry names {symbol}, and the element's own name says \
                 {expected}",
            );
        }
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
    let registered: BTreeSet<(String, String)> = mandate_model::ESS_REALIZATIONS
        .iter()
        .map(|(element, symbol)| ((*element).to_owned(), (*symbol).to_owned()))
        .collect();
    assert_eq!(
        registered.len(),
        mandate_model::ESS_REALIZATIONS.len(),
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
