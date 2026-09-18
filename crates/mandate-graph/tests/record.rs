//! `mandate.graph.Relation` and `mandate.graph.Grant` as projections of the graph fold.
//!
//! The contract declares both entities and their lifecycles in
//! `systems/mandate/domains/graph.yaml:49-116`. `docs/adr/0009-event-sourced-persistence.md`
//! makes the projection derived: a lifecycle change is a recorded move, so a repeat of a
//! move already recorded changes nothing.

use mandate_graph::port::MutationOutcome;
use mandate_graph::record::{Grant, GrantState, Relation, RelationState};
use mandate_types::{
    Action, AuthorityScope, AuthoritySubject, GrantId, OrganizationId, PersistedValue, PrincipalId,
    RelationId, ResourceId, ResourceType, TeamId, Uuid,
};

fn uuid(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(1))
}

fn principal() -> AuthoritySubject {
    AuthoritySubject::Principal(PrincipalId::new(uuid(2)))
}

fn team() -> AuthoritySubject {
    AuthoritySubject::Team(TeamId::new(uuid(3)))
}

fn relation() -> Relation {
    Relation::recorded(
        RelationId::new(uuid(4)),
        organization(),
        principal(),
        "viewer",
        ResourceId::new(uuid(5)),
    )
}

fn grant() -> Grant {
    Grant::recorded(
        GrantId::new(uuid(6)),
        organization(),
        team(),
        AuthorityScope {
            actions: vec![Action::new("read")],
            resources: Vec::new(),
            space: None,
        },
        "editor",
    )
}

fn relation_state_index(state: RelationState) -> usize {
    match state {
        RelationState::Active => 0,
        RelationState::Removed => 1,
    }
}

fn grant_state_index(state: GrantState) -> usize {
    match state {
        GrantState::Active => 0,
        GrantState::Revoked => 1,
    }
}

#[test]
fn a_relation_projects_the_fields_the_contract_declares() {
    let relation = relation();

    assert_eq!(relation.id, RelationId::new(uuid(4)));
    assert_eq!(relation.organization_id, organization());
    assert_eq!(relation.subject, principal());
    assert_eq!(relation.relation, "viewer");
    assert_eq!(relation.resource_id, ResourceId::new(uuid(5)));
    assert_eq!(relation.state, RelationState::Active);
}

#[test]
fn a_grant_projects_the_fields_the_contract_declares() {
    let grant = grant();

    assert_eq!(grant.id, GrantId::new(uuid(6)));
    assert_eq!(grant.organization_id, organization());
    assert_eq!(grant.subject, team());
    assert_eq!(grant.scope.actions, vec![Action::new("read")]);
    assert_eq!(grant.role, "editor");
    assert_eq!(grant.state, GrantState::Active);
}

#[test]
fn removing_a_relation_twice_records_one_move() {
    let mut relation = relation();

    assert_eq!(relation.remove(), MutationOutcome::Recorded);
    assert_eq!(relation.state, RelationState::Removed);
    assert!(!relation.active());

    assert_eq!(relation.remove(), MutationOutcome::AlreadyRecorded);
    assert_eq!(relation.state, RelationState::Removed);
}

#[test]
fn revoking_a_grant_twice_records_one_move() {
    let mut grant = grant();

    assert_eq!(grant.revoke(), MutationOutcome::Recorded);
    assert_eq!(grant.state, GrantState::Revoked);
    assert!(!grant.active());

    assert_eq!(grant.revoke(), MutationOutcome::AlreadyRecorded);
    assert_eq!(grant.state, GrantState::Revoked);
}

#[test]
fn the_declared_states_are_exactly_the_states_the_contract_names() {
    assert_eq!(RelationState::ALL.len(), 2);
    assert_eq!(GrantState::ALL.len(), 2);

    for (position, state) in RelationState::ALL.iter().enumerate() {
        assert_eq!(relation_state_index(*state), position);
    }
    for (position, state) in GrantState::ALL.iter().enumerate() {
        assert_eq!(grant_state_index(*state), position);
    }

    assert!(!RelationState::Active.terminal());
    assert!(RelationState::Removed.terminal());
    assert!(!GrantState::Active.terminal());
    assert!(GrantState::Revoked.terminal());
}

#[test]
fn every_projection_field_may_be_persisted() {
    fn persistable<T: PersistedValue>() {}

    persistable::<Relation>();
    persistable::<Grant>();
    persistable::<RelationId>();
    persistable::<GrantId>();
    persistable::<OrganizationId>();
    persistable::<AuthoritySubject>();
    persistable::<AuthorityScope>();
    persistable::<ResourceId>();
    persistable::<ResourceType>();
    persistable::<RelationState>();
    persistable::<GrantState>();
    persistable::<String>();
}
