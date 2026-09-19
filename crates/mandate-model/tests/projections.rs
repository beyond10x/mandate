//! The six records this story adds are projections, not accepted canonical types.
//!
//! `crates/mandate-types/src/macros.rs` hardcodes the `mandate.core.` prefix in
//! `canonical_record!`, and every one of these six is a `mandate.tenancy.*` or
//! `mandate.graph.*` entity, so none of them can be declared through that macro and none
//! enters `conformance::entries()`. What holds that claim up is here: the registry is
//! still exactly wave 1's four records, `Owner::Model` is still 4, and each projection is
//! checked against the compiled entity in `generated/schema/entities` instead.
//!
//! The key-set comparison this file used to carry —
//! `every_projection_encodes_exactly_the_fields_its_compiled_entity_declares` — read the
//! emitted keys against the compiled entity's `properties` and `required` lists and read
//! no value at all. `crates/mandate-model/tests/contract_agreement.rs` decides the same
//! six against the generated `mandate_contract` record as a round trip, which refuses the
//! same two things and every undeclared *value* besides, over every state each projection
//! holds rather than one sample each. The `x-ess-kind`, `additionalProperties` and
//! sample-coverage assertions that case also carried are kept, in
//! `every_projected_state_is_a_variant_the_compiled_state_enum_declares` below.
//!
//! Everything else here stays, and one of them is what the round trip cannot see: a
//! declared optional the projection never writes is a document the contract admits, so
//! `an_absent_optional_field_is_not_written_and_a_present_one_round_trips` is the only
//! case in this crate that turns red for it.

use mandate_model::conformance;
use mandate_model::graph::{Resource, ResourceState};
use mandate_model::tenancy::{
    Organization, OrganizationMembership, OrganizationMembershipState, OrganizationState, Space,
    SpaceState, Team, TeamMembership, TeamMembershipState, TeamState,
};
use mandate_types::inventory::{ACCEPTED, Owner};
use mandate_types::{
    OrganizationId, OrganizationMembershipId, PrincipalId, ResourceId, ResourceType, SpaceId,
    TeamId, TeamMembershipId,
};

const ENTITIES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../generated/schema/entities"
);

/// The six entities this story projects.
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

fn entity(ess_name: &str) -> serde_json::Value {
    let path = format!("{ENTITIES}/{ess_name}.schema.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
    serde_json::from_str(&text).expect("the compiled entity is JSON")
}

/// One sample of every projection, encoded, beside the entity it projects.
fn encoded_samples() -> Vec<(&'static str, String)> {
    let organization = OrganizationId::parse(&uuid(1)).expect("organization identity");
    let principal = PrincipalId::parse(&uuid(10)).expect("principal identity");
    let team = TeamId::parse(&uuid(30)).expect("team identity");
    vec![
        (
            "mandate.tenancy.Organization",
            serde_json::to_string(&Organization {
                id: organization,
                display_name: "Acme".to_owned(),
                state: OrganizationState::Recorded,
            })
            .expect("encode"),
        ),
        (
            "mandate.tenancy.OrganizationMembership",
            serde_json::to_string(&OrganizationMembership {
                id: OrganizationMembershipId::parse(&uuid(20)).expect("membership identity"),
                organization_id: organization,
                principal_id: principal,
                state: OrganizationMembershipState::Active,
            })
            .expect("encode"),
        ),
        (
            "mandate.tenancy.Team",
            serde_json::to_string(&Team {
                id: team,
                organization_id: organization,
                display_name: "Platform".to_owned(),
                state: TeamState::Recorded,
            })
            .expect("encode"),
        ),
        (
            "mandate.tenancy.TeamMembership",
            serde_json::to_string(&TeamMembership {
                id: TeamMembershipId::parse(&uuid(50)).expect("team membership identity"),
                organization_id: organization,
                team_id: team,
                principal_id: principal,
                state: TeamMembershipState::Recorded,
            })
            .expect("encode"),
        ),
        (
            "mandate.tenancy.Space",
            serde_json::to_string(&Space {
                id: SpaceId::parse(&uuid(40)).expect("space identity"),
                organization_id: organization,
                display_name: "Production".to_owned(),
                state: SpaceState::Recorded,
            })
            .expect("encode"),
        ),
        (
            "mandate.graph.Resource",
            serde_json::to_string(&Resource {
                id: ResourceId::parse(&uuid(100)).expect("resource identity"),
                organization_id: organization,
                resource_type: ResourceType::new("document"),
                parent: Some(ResourceId::parse(&uuid(101)).expect("parent identity")),
                space_id: None,
                state: ResourceState::Recorded,
            })
            .expect("encode"),
        ),
    ]
}

#[test]
fn the_conformance_registry_is_still_exactly_the_four_records_wave_one_realized() {
    let realized: Vec<&str> = conformance::cases()
        .iter()
        .map(|case| case.ess_name)
        .collect();
    assert_eq!(
        realized,
        vec![
            "mandate.core.TenantResolutionRule",
            "mandate.core.DecisionChallenge",
            "mandate.core.Decision",
            "mandate.core.AuditRecord",
        ]
    );
}

#[test]
fn the_model_owned_share_of_the_accepted_account_is_still_four() {
    let owned: Vec<&str> = ACCEPTED
        .iter()
        .filter(|accepted| accepted.owner == Owner::Model)
        .map(|accepted| accepted.ess_name)
        .collect();
    assert_eq!(owned.len(), 4, "accepted types owned by mandate-model");
    for name in &owned {
        assert!(
            name.starts_with("mandate.core."),
            "an accepted type outside mandate.core: {name}"
        );
    }
}

#[test]
fn no_projection_this_story_declares_is_an_accepted_type() {
    for projected in PROJECTED {
        let local = projected.rsplit('.').next().expect("a local name");
        let core = format!("mandate.core.{local}");
        assert!(
            !ACCEPTED
                .iter()
                .any(|accepted| accepted.ess_name == core || accepted.ess_name == projected),
            "{projected} entered the accepted account"
        );
    }
    assert!(
        !ACCEPTED
            .iter()
            .any(|accepted| accepted.ess_name.ends_with(".State")),
        "a derived state enum entered the accepted account"
    );
}

#[test]
fn every_projected_state_is_a_variant_the_compiled_state_enum_declares() {
    let samples = encoded_samples();
    let names: Vec<&str> = samples.iter().map(|(name, _)| *name).collect();
    assert_eq!(names, PROJECTED, "every projected entity has a sample");

    for (ess_name, encoded) in samples {
        let schema = entity(ess_name);
        assert_eq!(schema["x-ess-kind"], "entity", "{ess_name}");
        assert_eq!(
            schema["additionalProperties"],
            serde_json::Value::Bool(false),
            "{ess_name}"
        );
        let declared = schema["$defs"][format!("{ess_name}.State")]["enum"]
            .as_array()
            .unwrap_or_else(|| panic!("{ess_name}: no compiled state enum"))
            .clone();
        let value: serde_json::Value = serde_json::from_str(&encoded).expect("the encoded form");
        assert!(
            declared.contains(&value["state"]),
            "{ess_name}: state {} is not a declared variant of {declared:?}",
            value["state"]
        );
    }
}

#[test]
fn a_projection_refuses_a_field_its_entity_does_not_declare() {
    let (_, encoded) = encoded_samples()
        .into_iter()
        .find(|(name, _)| *name == "mandate.tenancy.OrganizationMembership")
        .expect("the membership sample");
    let decoded: OrganizationMembership = serde_json::from_str(&encoded).expect("round trip");
    assert_eq!(decoded.state, OrganizationMembershipState::Active);

    let mut value: serde_json::Value = serde_json::from_str(&encoded).expect("the encoded form");
    value["global_role"] = serde_json::Value::String("administrator".to_owned());
    assert!(serde_json::from_str::<OrganizationMembership>(&value.to_string()).is_err());

    let (_, encoded) = encoded_samples()
        .into_iter()
        .find(|(name, _)| *name == "mandate.graph.Resource")
        .expect("the resource sample");
    let mut value: serde_json::Value = serde_json::from_str(&encoded).expect("the encoded form");
    value["owner"] = serde_json::Value::String("someone".to_owned());
    assert!(serde_json::from_str::<Resource>(&value.to_string()).is_err());
}

#[test]
fn an_absent_optional_field_is_not_written_and_a_present_one_round_trips() {
    let resource = Resource {
        id: ResourceId::parse(&uuid(100)).expect("resource identity"),
        organization_id: OrganizationId::parse(&uuid(1)).expect("organization identity"),
        resource_type: ResourceType::new("document"),
        parent: None,
        space_id: None,
        state: ResourceState::Recorded,
    };
    let encoded = serde_json::to_string(&resource).expect("encode");
    assert!(
        !encoded.contains("parent") && !encoded.contains("space_id"),
        "an absent optional must not be written: {encoded}"
    );
    assert_eq!(
        serde_json::from_str::<Resource>(&encoded).expect("decode"),
        resource
    );

    let child = Resource {
        parent: Some(ResourceId::parse(&uuid(101)).expect("parent identity")),
        space_id: Some(SpaceId::parse(&uuid(40)).expect("space identity")),
        ..resource
    };
    let encoded = serde_json::to_string(&child).expect("encode");
    assert!(encoded.contains("parent") && encoded.contains("space_id"));
    assert_eq!(
        serde_json::from_str::<Resource>(&encoded).expect("decode"),
        child
    );
}
