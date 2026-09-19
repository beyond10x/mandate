//! Adversary pass 2 against `story:model-agreement`, the `mandate-model` half.
//!
//! Four cases, none of which edits anything the unit owns:
//!
//! * the count of shared variant lists `contract_agreement.rs` states about itself, read
//!   back against `generated/schema/types` — red, the file states one fewer than there are;
//! * the variant-to-element pin taken off the variant's own name rather than off a literal
//!   beside it, which is the one edge of the agreement the round trip cannot decide;
//! * every declared payload through the contract's own Draft 2020-12 validator, which
//!   decides `pattern` and `format` where `serde` decides neither;
//! * every compiled `required` key removed from an emitted projection in turn, which is the
//!   half of the retired `projections.rs` key-set case that read the schema.

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

/// The file whose own prose this pass reads back against the compiled model.
const AGREEMENT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/contract_agreement.rs");

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

fn team() -> TeamId {
    TeamId::parse(&uuid(0x30)).expect("team identity")
}

fn space() -> SpaceId {
    SpaceId::parse(&uuid(0x40)).expect("space identity")
}

fn membership() -> OrganizationMembershipId {
    OrganizationMembershipId::parse(&uuid(0x20)).expect("membership identity")
}

fn team_membership() -> TeamMembershipId {
    TeamMembershipId::parse(&uuid(0x50)).expect("team membership identity")
}

/// The compiled declaration of one element.
fn schema(directory: &str, ess_name: &str) -> Value {
    let path = format!("{SCHEMA}/{directory}/{ess_name}.schema.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
    serde_json::from_str(&text).expect("the compiled declaration is JSON")
}

/// ESS's `declaration_name`, as ESS 0.26.0 and `xtask/src/emit.rs` write it.
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

/// The verified context every payload carries.
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

/// One declared payload: the element the variant claims, the variant, and the document.
struct Payload {
    /// The element the variant's own `ess_name()` names.
    ess_name: &'static str,
    /// The Rust variant that produced it, as `Debug` writes its name.
    variant: String,
    /// What the variant serialized to.
    value: Value,
}

/// The name of the variant a `Debug` rendering opens with.
fn variant_of<E: std::fmt::Debug>(event: &E) -> String {
    format!("{event:?}")
        .chars()
        .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
        .collect()
}

/// Every payload this crate's two event enums declare, with both forms of the context and
/// both forms of the one optional either enum carries.
fn payloads() -> Vec<Payload> {
    let mut built: Vec<Payload> = Vec::new();
    for populated in [true, false] {
        let caller = context(populated);
        let mut events: Vec<TenancyEvent> = vec![
            TenancyEvent::OrganizationCreated {
                context: caller.clone(),
                organization_id: organization(1),
                display_name: "Acme".to_owned(),
            },
            TenancyEvent::OrganizationClosed {
                context: caller.clone(),
                id: organization(1),
            },
            TenancyEvent::OrganizationMembershipAdded {
                context: caller.clone(),
                organization_id: organization(1),
                principal_id: principal(0x10),
                membership_id: membership(),
            },
            TenancyEvent::OrganizationMembershipRemoved {
                context: caller.clone(),
                id: membership(),
            },
            TenancyEvent::TeamCreated {
                context: caller.clone(),
                team_id: team(),
                display_name: "Platform".to_owned(),
            },
            TenancyEvent::TeamRetired {
                context: caller.clone(),
                id: team(),
            },
            TenancyEvent::TeamMembershipAdded {
                context: caller.clone(),
                team_id: team(),
                principal_id: principal(0x10),
                team_membership_id: team_membership(),
                contribution_id: MembershipContributionId::parse(&uuid(0x60))
                    .expect("contribution identity"),
            },
            TenancyEvent::TeamMembershipRemoved {
                context: caller.clone(),
                id: team_membership(),
            },
            TenancyEvent::SpaceCreated {
                context: caller.clone(),
                space_id: space(),
                display_name: "Production".to_owned(),
            },
        ];
        events.push(TenancyEvent::SpaceRetired {
            context: caller.clone(),
            id: space(),
        });
        for event in &events {
            built.push(Payload {
                ess_name: event.ess_name(),
                variant: variant_of(event),
                value: serde_json::to_value(event).expect("the payload serializes"),
            });
        }

        let deregistered = ResourceEvent::Deregistered {
            context: caller.clone(),
            id: resource(0x100),
        };
        built.push(Payload {
            ess_name: deregistered.ess_name(),
            variant: variant_of(&deregistered),
            value: serde_json::to_value(&deregistered).expect("the payload serializes"),
        });
        for parent in [Some(resource(0x101)), None] {
            let registered = ResourceEvent::Registered {
                context: caller.clone(),
                resource_id: resource(0x100),
                resource: ResourceRef {
                    resource_type: ResourceType::new("document"),
                    resource_id: resource(0x100),
                },
                parent,
            };
            built.push(Payload {
                ess_name: registered.ess_name(),
                variant: variant_of(&registered),
                value: serde_json::to_value(&registered).expect("the payload serializes"),
            });
        }
    }
    built
}

/// The whole procedure `contract_agreement.rs` applies to one pairing, as a yes or no.
///
/// The round trip through the generated shape, the `declaration_name` derivation of the
/// element against the shape's own Rust name, and the compiled declaration's `x-ess-name`.
fn procedure_accepts<D, C>(ess_name: &str, directory: &str, domain: &D) -> bool
where
    D: Serialize,
    C: Serialize + DeserializeOwned,
{
    let Ok(emitted) = serde_json::to_value(domain) else {
        return false;
    };
    let Ok(shape) = serde_json::from_value::<C>(emitted.clone()) else {
        return false;
    };
    let Ok(again) = serde_json::to_value(&shape) else {
        return false;
    };
    if again != emitted {
        return false;
    }
    let derived = declaration_name(ess_name);
    if std::any::type_name::<C>().rsplit("::").next() != Some(derived.as_str()) {
        return false;
    }
    schema(directory, ess_name)["x-ess-name"].as_str() == Some(ess_name)
}

/// Every key the compiled entity requires is refused by the generated shape when absent.
fn assert_required_keys_are_refused_when_absent<D, C>(ess_name: &str, domain: &D)
where
    D: Serialize,
    C: Serialize + DeserializeOwned,
{
    let emitted = serde_json::to_value(domain).expect("the domain value serializes");
    let document = schema("entities", ess_name);
    let required = document["required"]
        .as_array()
        .expect("the declared required list");
    assert!(!required.is_empty(), "{ess_name}: no required key");
    for name in required {
        let name = name.as_str().expect("a required name");
        let mut reduced = emitted.clone();
        reduced
            .as_object_mut()
            .expect("a projection encodes as a JSON object")
            .remove(name);
        assert!(
            serde_json::from_value::<C>(reduced.clone()).is_err(),
            "{ess_name}: the generated shape read a document with the required {name} \
             removed: {reduced}",
        );
    }
}

/// How many `.State` declarations share their whole variant list with another of the 36.
fn declarations_sharing_a_variant_list() -> usize {
    let path = format!("{SCHEMA}/types");
    let mut lists: BTreeMap<Vec<String>, usize> = BTreeMap::new();
    let entries = std::fs::read_dir(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
    for entry in entries {
        let file = entry.expect("directory entry").file_name();
        let file = file.to_string_lossy().into_owned();
        let Some(ess_name) = file.strip_suffix(".schema.json") else {
            continue;
        };
        if !ess_name.ends_with(".State") {
            continue;
        }
        let document = schema("types", ess_name);
        let variants: Vec<String> = document["$defs"][ess_name]["enum"]
            .as_array()
            .unwrap_or_else(|| panic!("{ess_name}: no declared variants"))
            .iter()
            .map(|variant| {
                variant
                    .as_str()
                    .unwrap_or_else(|| panic!("{ess_name}: a declared variant is not a string"))
                    .to_owned()
            })
            .collect();
        *lists.entry(variants).or_default() += 1;
    }
    lists.values().filter(|count| **count > 1).sum()
}

/// Every count a `share a variant list` sentence in `source` states.
///
/// The claim is written `N of the 36 … share a variant list` or `the N … that share a
/// variant list`, so 36 is the denominator and the other number in the window is the
/// count. A sentence that no longer parses is reported as a missing claim rather than as
/// agreement.
fn stated_shared_counts(source: &str) -> Vec<usize> {
    let prose: Vec<String> = source
        .lines()
        .map(|line| {
            let line = line.trim_start();
            line.strip_prefix("//!")
                .or_else(|| line.strip_prefix("///"))
                .unwrap_or("")
                .to_owned()
        })
        .collect();
    let joined = prose.join(" ");
    let tokens: Vec<&str> = joined.split_whitespace().collect();
    let mut stated = Vec::new();
    for (index, window) in tokens.windows(4).enumerate() {
        if window != ["share", "a", "variant", "list"] {
            continue;
        }
        let mut back = index;
        while back > 0 && index - back < 8 {
            back -= 1;
            let digits = tokens[back].trim_matches(|character: char| !character.is_ascii_digit());
            if let Ok(number) = digits.parse::<usize>()
                && number != 36
            {
                stated.push(number);
                break;
            }
        }
    }
    stated
}

/// Every variant names the element its own variant name derives into, with no literal.
///
/// The procedure `contract_agreement.rs` applies cannot do this: the six `{context, id}`
/// payloads reproduce each other's documents, so the round trip, the `declaration_name`
/// derivation and the `x-ess-name` read all stay green when `ess_name()` and the hand-typed
/// shape are swapped together between two of them. What catches that today is a hand-typed
/// literal beside each variant — `replay.rs:1165` and `adversary_events_1.rs:1082` — and a
/// literal is the thing pass 1 refused as evidence. This is the same pin taken off the
/// variant's own name instead: the element's local part must end with the variant's name,
/// which `mandate.graph.ResourceRegistered`/`Registered` satisfies and a swap does not.
#[test]
fn every_variant_names_the_element_its_own_name_derives_into_and_not_a_literal_beside_it() {
    let built = payloads();
    let covered: BTreeSet<&str> = built.iter().map(|payload| payload.ess_name).collect();
    assert_eq!(covered.len(), 12, "payloads covered: {covered:?}");
    for payload in &built {
        assert!(
            !payload.variant.is_empty(),
            "{}: no variant name to pin it to",
            payload.ess_name,
        );
        let local = payload
            .ess_name
            .rsplit('.')
            .next()
            .expect("an element local name");
        assert!(
            local.ends_with(payload.variant.as_str()),
            "{}: the element this variant claims ends with {local}, and the variant is \
             {}, so the variant names a payload its own name does not derive into",
            payload.ess_name,
            payload.variant,
        );
    }

    // The control: the pin discriminates, which is the whole reason it is worth having.
    let retired = TenancyEvent::TeamRetired {
        context: context(true),
        id: team(),
    };
    assert!(
        procedure_accepts::<_, events::MandateTenancySpaceRetired>(
            "mandate.tenancy.SpaceRetired",
            "events",
            &retired,
        ),
        "the procedure in contract_agreement.rs is expected to accept the swap this pin \
         refuses; if it now refuses it, this case no longer measures what it says it does",
    );
    assert!(
        !"SpaceRetired".ends_with("TeamRetired"),
        "the pin above does not discriminate the swap the procedure accepts",
    );
}

/// Every declared payload conforms to its compiled schema under the contract's validator.
#[test]
fn every_declared_payload_conforms_under_the_contract_validator_and_not_only_under_serde() {
    let built = payloads();
    let covered: BTreeSet<&str> = built.iter().map(|payload| payload.ess_name).collect();
    assert_eq!(covered.len(), 12, "payloads covered: {covered:?}");
    for payload in &built {
        mandate_testkit::contract::check_event_conforms(payload.ess_name, &payload.value)
            .unwrap_or_else(|failure| panic!("{failure}"));
    }
}

/// The generated entity shape refuses a document missing a key its declaration requires.
#[test]
fn every_generated_entity_shape_refuses_a_document_missing_a_required_key() {
    assert_required_keys_are_refused_when_absent::<_, entities::MandateTenancyOrganization>(
        "mandate.tenancy.Organization",
        &Organization {
            id: organization(1),
            display_name: "Acme".to_owned(),
            state: OrganizationState::Recorded,
        },
    );
    assert_required_keys_are_refused_when_absent::<_, entities::MandateTenancyOrganizationMembership>(
        "mandate.tenancy.OrganizationMembership",
        &OrganizationMembership {
            id: membership(),
            organization_id: organization(1),
            principal_id: principal(0x10),
            state: OrganizationMembershipState::Active,
        },
    );
    assert_required_keys_are_refused_when_absent::<_, entities::MandateTenancyTeam>(
        "mandate.tenancy.Team",
        &Team {
            id: team(),
            organization_id: organization(1),
            display_name: "Platform".to_owned(),
            state: TeamState::Recorded,
        },
    );
    assert_required_keys_are_refused_when_absent::<_, entities::MandateTenancyTeamMembership>(
        "mandate.tenancy.TeamMembership",
        &TeamMembership {
            id: team_membership(),
            organization_id: organization(1),
            team_id: team(),
            principal_id: principal(0x10),
            state: TeamMembershipState::Recorded,
        },
    );
    assert_required_keys_are_refused_when_absent::<_, entities::MandateTenancySpace>(
        "mandate.tenancy.Space",
        &Space {
            id: space(),
            organization_id: organization(1),
            display_name: "Production".to_owned(),
            state: SpaceState::Recorded,
        },
    );
    assert_required_keys_are_refused_when_absent::<_, entities::MandateGraphResource>(
        "mandate.graph.Resource",
        &Resource {
            id: resource(0x100),
            organization_id: organization(1),
            resource_type: ResourceType::new("document"),
            parent: Some(resource(0x101)),
            space_id: Some(space()),
            state: ResourceState::Recorded,
        },
    );
}

/// The count of shared variant lists this file states is the count the model declares.
#[test]
fn the_shared_variant_list_count_this_file_states_is_the_count_the_compiled_model_has() {
    let source = std::fs::read_to_string(AGREEMENT).unwrap_or_else(|error| {
        panic!("crates/mandate-model/tests/contract_agreement.rs: {error}")
    });
    let stated = stated_shared_counts(&source);
    assert!(
        !stated.is_empty(),
        "contract_agreement.rs no longer states how many state enums share a variant list; \
         the claim this case pins is gone rather than agreed with",
    );
    let declared = declarations_sharing_a_variant_list();
    for number in stated {
        assert_eq!(
            number, declared,
            "contract_agreement.rs states that {number} state enums share a variant list \
             with another; generated/schema/types declares {declared} of the 36 that do, \
             so the justification the derivation check rests on undercounts the pairings \
             it cannot discriminate between",
        );
    }
}
