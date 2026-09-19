//! Adversary pass 1 against `story:model-agreement`, `model` unit.
//!
//! Four things `crates/mandate-model/tests/contract_agreement.rs` states about itself, put
//! to a program rather than read. Two hold and two do not; none of the cases here reads a
//! value the agreement file already reads.
//!
//! * The agreement file round-trips domain -> document -> generated shape -> document. The
//!   other direction — a document the *generated* shape emits, read back by the domain
//!   projection — is never taken, and it is the direction a log reader takes. The six
//!   projections derive `Deserialize`, so it can be taken; it is, below.
//! * `contract_agreement.rs:157-158` says the `payload!` macro binds a variant to the
//!   payload it claims to be, because the element name is `ess_name()` rather than a
//!   literal. The generated *shape* on the other side of that macro is still a literal,
//!   and nothing compares the two.
//! * `crates/mandate-model/src/graph.rs:133` and
//!   `crates/mandate-model/tests/replay.rs:1085` both state that the compiled
//!   `mandate.graph.ResourceRegistered` on this branch declares no `resource_id`. It does,
//!   and it declares it required; the agreement file's round trip only passes because it
//!   does.

use std::collections::BTreeSet;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use mandate_contract::entities;
use mandate_contract::events;
use mandate_contract::types::{
    MandateCoreOrganizationId, MandateCoreOrganizationMembershipId, MandateCorePrincipalId,
    MandateCoreResourceId, MandateCoreResourceType, MandateCoreSpaceId, MandateCoreTeamId,
    MandateCoreTeamMembershipId, Presence,
};

use mandate_model::graph::{Resource, ResourceEvent};
use mandate_model::tenancy::{
    Organization, OrganizationMembership, Space, Team, TeamMembership, TenancyEvent,
};
use mandate_types::{
    Audience, CorrelationId, CredentialId, DelegationId, ExecutionId, OrganizationId,
    OrganizationMembershipId, PrincipalId, ResourceId, SpaceId, TeamId, TeamMembershipId,
    VerifiedContext,
};

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

fn uuid(tag: u16) -> String {
    format!("1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f{tag:04x}")
}

fn schema(directory: &str, ess_name: &str) -> Value {
    let path = format!("{ROOT}/generated/schema/{directory}/{ess_name}.schema.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
    serde_json::from_str(&text).expect("the compiled declaration is JSON")
}

/// Read `document` back as the generated shape `C` and re-emit it, exactly as
/// `contract_agreement.rs::round_trip` does, answering whether the two agree.
fn reproduces_as<C: Serialize + DeserializeOwned>(document: &Value) -> bool {
    match serde_json::from_value::<C>(document.clone()) {
        Ok(shape) => serde_json::to_value(&shape)
            .map(|again| &again == document)
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// Read `document` back as the *domain* value `D` and re-emit it: the log-reader direction.
fn domain_reproduces<D: Serialize + DeserializeOwned>(
    ess_name: &str,
    document: &Value,
) -> Result<(), String> {
    let domain: D = serde_json::from_value(document.clone())
        .map_err(|error| format!("{ess_name}: the projection refuses {document}: {error}"))?;
    let again = serde_json::to_value(&domain)
        .map_err(|error| format!("{ess_name}: the projection does not serialize: {error}"))?;
    if &again == document {
        Ok(())
    } else {
        Err(format!(
            "{ess_name}: the projection re-emitted {again} for the generated document {document}"
        ))
    }
}

fn generated_entity_documents() -> Vec<(&'static str, Value)> {
    let organization = || MandateCoreOrganizationId(uuid(1));
    let principal = || MandateCorePrincipalId(uuid(0x10));
    let team = || MandateCoreTeamId(uuid(0x30));
    let space = || MandateCoreSpaceId(uuid(0x40));
    let mut documents: Vec<(&'static str, Value)> = Vec::new();

    for state in [
        entities::MandateTenancyOrganizationState::Recorded,
        entities::MandateTenancyOrganizationState::Closed,
    ] {
        documents.push((
            "mandate.tenancy.Organization",
            serde_json::to_value(entities::MandateTenancyOrganization {
                id: organization(),
                display_name: "Acme".to_owned(),
                state,
            })
            .expect("the generated shape serializes"),
        ));
    }

    for state in [
        entities::MandateTenancyOrganizationMembershipState::Active,
        entities::MandateTenancyOrganizationMembershipState::Removed,
    ] {
        documents.push((
            "mandate.tenancy.OrganizationMembership",
            serde_json::to_value(entities::MandateTenancyOrganizationMembership {
                id: MandateCoreOrganizationMembershipId(uuid(0x20)),
                organization_id: organization(),
                principal_id: principal(),
                state,
            })
            .expect("the generated shape serializes"),
        ));
    }

    for state in [
        entities::MandateTenancyTeamState::Recorded,
        entities::MandateTenancyTeamState::Retired,
    ] {
        documents.push((
            "mandate.tenancy.Team",
            serde_json::to_value(entities::MandateTenancyTeam {
                id: team(),
                organization_id: organization(),
                display_name: "Platform".to_owned(),
                state,
            })
            .expect("the generated shape serializes"),
        ));
    }

    for state in [
        entities::MandateTenancyTeamMembershipState::Recorded,
        entities::MandateTenancyTeamMembershipState::Removed,
    ] {
        documents.push((
            "mandate.tenancy.TeamMembership",
            serde_json::to_value(entities::MandateTenancyTeamMembership {
                id: MandateCoreTeamMembershipId(uuid(0x50)),
                organization_id: organization(),
                team_id: team(),
                principal_id: principal(),
                state,
            })
            .expect("the generated shape serializes"),
        ));
    }

    for state in [
        entities::MandateTenancySpaceState::Recorded,
        entities::MandateTenancySpaceState::Retired,
    ] {
        documents.push((
            "mandate.tenancy.Space",
            serde_json::to_value(entities::MandateTenancySpace {
                id: space(),
                organization_id: organization(),
                display_name: "Production".to_owned(),
                state,
            })
            .expect("the generated shape serializes"),
        ));
    }

    // Every combination of the two declared optionals, at both states.
    for state in [
        entities::MandateGraphResourceState::Recorded,
        entities::MandateGraphResourceState::Deregistered,
    ] {
        for parent in [
            Presence::Present(MandateCoreResourceId(uuid(0x101))),
            Presence::Absent,
        ] {
            for space_id in [Presence::Present(space()), Presence::Absent] {
                documents.push((
                    "mandate.graph.Resource",
                    serde_json::to_value(entities::MandateGraphResource {
                        id: MandateCoreResourceId(uuid(0x100)),
                        organization_id: organization(),
                        resource_type: MandateCoreResourceType("document".to_owned()),
                        parent: parent.clone(),
                        space_id,
                        state: state.clone(),
                    })
                    .expect("the generated shape serializes"),
                ));
            }
        }
    }

    documents
}

fn context(populated: bool) -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::parse(&uuid(0x10)).expect("principal identity"),
        actor: populated.then(|| PrincipalId::parse(&uuid(0x11)).expect("actor identity")),
        organization: OrganizationId::parse(&uuid(1)).expect("organization identity"),
        audience: Audience::new("mandate"),
        credential: CredentialId::parse(&uuid(0xff00)).expect("credential identity"),
        delegation: populated
            .then(|| DelegationId::parse(&uuid(0xff01)).expect("delegation identity")),
        execution: populated
            .then(|| ExecutionId::parse(&uuid(0xff02)).expect("execution identity")),
        correlation: CorrelationId::new("correlation"),
    }
}

/// The six payloads that serialize to `{context, id}` and nothing else.
fn terminal_payload_documents() -> Vec<(&'static str, Value)> {
    let caller = context(true);
    let built: Vec<(&'static str, Value)> = vec![
        {
            let event = TenancyEvent::OrganizationClosed {
                context: caller.clone(),
                id: OrganizationId::parse(&uuid(1)).expect("organization identity"),
            };
            (
                event.ess_name(),
                serde_json::to_value(&event).expect("encode"),
            )
        },
        {
            let event = TenancyEvent::OrganizationMembershipRemoved {
                context: caller.clone(),
                id: OrganizationMembershipId::parse(&uuid(0x20)).expect("membership identity"),
            };
            (
                event.ess_name(),
                serde_json::to_value(&event).expect("encode"),
            )
        },
        {
            let event = TenancyEvent::TeamRetired {
                context: caller.clone(),
                id: TeamId::parse(&uuid(0x30)).expect("team identity"),
            };
            (
                event.ess_name(),
                serde_json::to_value(&event).expect("encode"),
            )
        },
        {
            let event = TenancyEvent::TeamMembershipRemoved {
                context: caller.clone(),
                id: TeamMembershipId::parse(&uuid(0x50)).expect("team membership identity"),
            };
            (
                event.ess_name(),
                serde_json::to_value(&event).expect("encode"),
            )
        },
        {
            let event = TenancyEvent::SpaceRetired {
                context: caller.clone(),
                id: SpaceId::parse(&uuid(0x40)).expect("space identity"),
            };
            (
                event.ess_name(),
                serde_json::to_value(&event).expect("encode"),
            )
        },
        {
            let event = ResourceEvent::Deregistered {
                context: caller.clone(),
                id: ResourceId::parse(&uuid(0x100)).expect("resource identity"),
            };
            (
                event.ess_name(),
                serde_json::to_value(&event).expect("encode"),
            )
        },
    ];
    built
}

/// Reads a payload document back as one generated shape and answers whether it reproduces.
type PayloadReader = fn(&Value) -> bool;

/// The same six payloads on the generated side, each with the reader the macro would pair.
fn terminal_payload_readers() -> Vec<(&'static str, PayloadReader)> {
    vec![
        (
            "mandate.tenancy.OrganizationClosed",
            reproduces_as::<events::MandateTenancyOrganizationClosed> as PayloadReader,
        ),
        (
            "mandate.tenancy.OrganizationMembershipRemoved",
            reproduces_as::<events::MandateTenancyOrganizationMembershipRemoved>,
        ),
        (
            "mandate.tenancy.TeamRetired",
            reproduces_as::<events::MandateTenancyTeamRetired>,
        ),
        (
            "mandate.tenancy.TeamMembershipRemoved",
            reproduces_as::<events::MandateTenancyTeamMembershipRemoved>,
        ),
        (
            "mandate.tenancy.SpaceRetired",
            reproduces_as::<events::MandateTenancySpaceRetired>,
        ),
        (
            "mandate.graph.ResourceDeregistered",
            reproduces_as::<events::MandateGraphResourceDeregistered>,
        ),
    ]
}

/// A document the generated entity shape emits is read back by the domain projection unchanged.
#[test]
fn every_generated_entity_document_reads_back_into_its_domain_projection() {
    let documents = generated_entity_documents();
    let covered: BTreeSet<&str> = documents.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        covered.len(),
        6,
        "every projection has a document: {covered:?}"
    );

    let mut failures: Vec<String> = Vec::new();
    for (ess_name, document) in &documents {
        let outcome = match *ess_name {
            "mandate.tenancy.Organization" => domain_reproduces::<Organization>(ess_name, document),
            "mandate.tenancy.OrganizationMembership" => {
                domain_reproduces::<OrganizationMembership>(ess_name, document)
            }
            "mandate.tenancy.Team" => domain_reproduces::<Team>(ess_name, document),
            "mandate.tenancy.TeamMembership" => {
                domain_reproduces::<TeamMembership>(ess_name, document)
            }
            "mandate.tenancy.Space" => domain_reproduces::<Space>(ess_name, document),
            "mandate.graph.Resource" => domain_reproduces::<Resource>(ess_name, document),
            other => panic!("no projection for {other}"),
        };
        if let Err(problem) = outcome {
            failures.push(problem);
        }
    }
    assert!(
        failures.is_empty(),
        "the log-reader direction fails for {} of {} documents:\n{}",
        failures.len(),
        documents.len(),
        failures.join("\n")
    );
}

/// Every key the compiled entity declares is written by the projection when every optional is set.
#[test]
fn every_declared_entity_key_is_written_when_every_optional_is_present() {
    let fully_populated: Vec<(&str, Value)> = vec![
        (
            "mandate.tenancy.Organization",
            serde_json::to_value(Organization {
                id: OrganizationId::parse(&uuid(1)).expect("organization identity"),
                display_name: "Acme".to_owned(),
                state: mandate_model::tenancy::OrganizationState::Recorded,
            })
            .expect("encode"),
        ),
        (
            "mandate.tenancy.OrganizationMembership",
            serde_json::to_value(OrganizationMembership {
                id: OrganizationMembershipId::parse(&uuid(0x20)).expect("membership identity"),
                organization_id: OrganizationId::parse(&uuid(1)).expect("organization identity"),
                principal_id: PrincipalId::parse(&uuid(0x10)).expect("principal identity"),
                state: mandate_model::tenancy::OrganizationMembershipState::Active,
            })
            .expect("encode"),
        ),
        (
            "mandate.tenancy.Team",
            serde_json::to_value(Team {
                id: TeamId::parse(&uuid(0x30)).expect("team identity"),
                organization_id: OrganizationId::parse(&uuid(1)).expect("organization identity"),
                display_name: "Platform".to_owned(),
                state: mandate_model::tenancy::TeamState::Recorded,
            })
            .expect("encode"),
        ),
        (
            "mandate.tenancy.TeamMembership",
            serde_json::to_value(TeamMembership {
                id: TeamMembershipId::parse(&uuid(0x50)).expect("team membership identity"),
                organization_id: OrganizationId::parse(&uuid(1)).expect("organization identity"),
                team_id: TeamId::parse(&uuid(0x30)).expect("team identity"),
                principal_id: PrincipalId::parse(&uuid(0x10)).expect("principal identity"),
                state: mandate_model::tenancy::TeamMembershipState::Recorded,
            })
            .expect("encode"),
        ),
        (
            "mandate.tenancy.Space",
            serde_json::to_value(Space {
                id: SpaceId::parse(&uuid(0x40)).expect("space identity"),
                organization_id: OrganizationId::parse(&uuid(1)).expect("organization identity"),
                display_name: "Production".to_owned(),
                state: mandate_model::tenancy::SpaceState::Recorded,
            })
            .expect("encode"),
        ),
        (
            "mandate.graph.Resource",
            serde_json::to_value(Resource {
                id: ResourceId::parse(&uuid(0x100)).expect("resource identity"),
                organization_id: OrganizationId::parse(&uuid(1)).expect("organization identity"),
                resource_type: mandate_types::ResourceType::new("document"),
                parent: Some(ResourceId::parse(&uuid(0x101)).expect("parent identity")),
                space_id: Some(SpaceId::parse(&uuid(0x40)).expect("space identity")),
                state: mandate_model::graph::ResourceState::Recorded,
            })
            .expect("encode"),
        ),
    ];

    for (ess_name, emitted) in &fully_populated {
        let document = schema("entities", ess_name);
        let declared: BTreeSet<String> = document["properties"]
            .as_object()
            .expect("the declared properties")
            .keys()
            .cloned()
            .collect();
        let written: BTreeSet<String> = emitted
            .as_object()
            .expect("a projection encodes as an object")
            .keys()
            .cloned()
            .collect();
        assert_eq!(
            written, declared,
            "{ess_name}: a declared key the projection never writes, or a key it writes that \
             the entity does not declare"
        );
    }
}

/// The six terminal payloads share one declared shape (`{context, id}`), so each is reproduced
/// by every one of the six generated shapes; the pairing between an element and its shape is
/// therefore evidence by name derivation, not by shape.
///
/// Coordinator ruling after adversary pass 1 (A1-1): the original case demanded that a payload
/// be reproduced only by its own shape, which the contract makes impossible for these six. The
/// pairing defect it found is closed in `contract_agreement.rs` by asserting the generated type
/// name derives from the ESS name; this case pins the shared-shape fact, so a payload that
/// gains a field turns it red and the pairing evidence is re-examined.
#[test]
fn the_six_terminal_payloads_share_one_declared_shape() {
    let documents = terminal_payload_documents();
    let readers = terminal_payload_readers();
    let mut substitutions: Vec<String> = Vec::new();
    for (ess_name, document) in &documents {
        for (shape, reproduces) in &readers {
            if shape == ess_name {
                assert!(
                    reproduces(document),
                    "{ess_name}: its own generated shape does not reproduce it"
                );
                continue;
            }
            if reproduces(document) {
                substitutions.push(format!("{ess_name} is reproduced by the shape of {shape}"));
            }
        }
    }
    assert_eq!(
        substitutions.len(),
        documents.len() * (readers.len() - 1),
        "a terminal payload no longer shares the {{context, id}} shape with the others; \
         re-examine the pairing evidence in contract_agreement.rs:\n{}",
        substitutions.join("\n")
    );
}

/// No source in this crate states that the compiled `ResourceRegistered` omits `resource_id`.
#[test]
fn no_source_here_claims_the_compiled_resource_registered_payload_omits_resource_id() {
    let declared: BTreeSet<String> =
        schema("events", "mandate.graph.ResourceRegistered")["required"]
            .as_array()
            .expect("the declared required list")
            .iter()
            .map(|name| name.as_str().expect("a required name").to_owned())
            .collect();
    assert_eq!(
        declared,
        BTreeSet::from([
            "context".to_owned(),
            "resource_id".to_owned(),
            "resource".to_owned(),
        ]),
        "the compiled payload is not the one this case was written against"
    );

    let stale: [(&str, &str); 2] = [
        (
            "crates/mandate-model/src/graph.rs",
            "an optional `parent` and no `resource_id`",
        ),
        (
            "crates/mandate-model/tests/replay.rs",
            "declares `required: [context, resource]`",
        ),
    ];
    let mut found: Vec<String> = Vec::new();
    for (relative, phrase) in stale {
        let path = format!("{ROOT}/{relative}");
        let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
        for (index, line) in text.lines().enumerate() {
            if line.contains(phrase) {
                found.push(format!("{relative}:{}: {}", index + 1, line.trim()));
            }
        }
    }
    assert!(
        found.is_empty(),
        "the compiled payload declares resource_id required, and {} line(s) still say it does \
         not; replay.rs:1090 weakens the ResourceRegistered key check to a ruled literal on \
         that ground:\n{}",
        found.len(),
        found.join("\n")
    );
}

/// A state string the compiled enum does not declare is refused on both sides.
#[test]
fn an_undeclared_state_string_is_refused_by_the_projection_and_by_the_generated_shape() {
    let emitted = serde_json::to_value(Organization {
        id: OrganizationId::parse(&uuid(1)).expect("organization identity"),
        display_name: "Acme".to_owned(),
        state: mandate_model::tenancy::OrganizationState::Recorded,
    })
    .expect("encode");

    for undeclared in ["recorded", "RECORDED", "", "Retired", "Recorded "] {
        let mut mutated = emitted.clone();
        mutated["state"] = Value::String(undeclared.to_owned());
        assert!(
            serde_json::from_value::<Organization>(mutated.clone()).is_err(),
            "the projection accepted the undeclared state {undeclared:?}"
        );
        assert!(
            serde_json::from_value::<entities::MandateTenancyOrganization>(mutated).is_err(),
            "the generated shape accepted the undeclared state {undeclared:?}"
        );
    }
}
