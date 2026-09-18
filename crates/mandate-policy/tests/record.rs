//! `mandate.policy.Policy` and `mandate.policy.AuthorizationModel` as projections.
//!
//! The contract declares both entities and their lifecycles in
//! `systems/mandate/domains/policy.yaml:6-63`. Its own header states the rule the
//! projection has to keep: a published version is immutable, a changed policy is a new
//! version record, and no superseded record is ever reactivated or deleted.

use mandate_policy::port::MutationOutcome;
use mandate_policy::record::{AuthorizationModel, AuthorizationModelState, Policy, PolicyState};
use mandate_types::{
    AuthorizationModelId, OrganizationId, PersistedValue, PolicyId, PolicyVersion, Uuid,
};

fn uuid(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(1))
}

fn policy() -> Policy {
    Policy::recorded(
        PolicyId::new(uuid(4)),
        organization(),
        PolicyVersion::new("2026-09-18.1"),
        "permit(principal, action, resource);",
    )
}

fn model() -> AuthorizationModel {
    AuthorizationModel::recorded(
        AuthorizationModelId::new(uuid(5)),
        organization(),
        PolicyVersion::new("2026-09-18.1"),
        "type document relations { viewer, editor }",
    )
}

fn policy_state_index(state: PolicyState) -> usize {
    match state {
        PolicyState::Recorded => 0,
        PolicyState::Superseded => 1,
    }
}

fn model_state_index(state: AuthorizationModelState) -> usize {
    match state {
        AuthorizationModelState::Recorded => 0,
        AuthorizationModelState::Superseded => 1,
    }
}

#[test]
fn a_policy_projects_the_fields_the_contract_declares() {
    let policy = policy();

    assert_eq!(policy.id, PolicyId::new(uuid(4)));
    assert_eq!(policy.organization_id, organization());
    assert_eq!(policy.version, PolicyVersion::new("2026-09-18.1"));
    assert_eq!(policy.source, "permit(principal, action, resource);");
    assert_eq!(policy.state, PolicyState::Recorded);
    assert!(policy.current());
}

#[test]
fn an_authorization_model_projects_the_fields_the_contract_declares() {
    let model = model();

    assert_eq!(model.id, AuthorizationModelId::new(uuid(5)));
    assert_eq!(model.organization_id, organization());
    assert_eq!(model.version, PolicyVersion::new("2026-09-18.1"));
    assert_eq!(model.schema, "type document relations { viewer, editor }");
    assert_eq!(model.state, AuthorizationModelState::Recorded);
    assert!(model.current());
}

#[test]
fn superseding_a_policy_twice_records_one_move_and_keeps_its_source() {
    let mut policy = policy();

    assert_eq!(policy.supersede(), MutationOutcome::Recorded);
    assert_eq!(policy.state, PolicyState::Superseded);
    assert!(!policy.current());

    assert_eq!(policy.supersede(), MutationOutcome::AlreadyRecorded);
    assert_eq!(policy.state, PolicyState::Superseded);
    assert_eq!(policy.source, "permit(principal, action, resource);");
}

#[test]
fn superseding_a_model_twice_records_one_move_and_keeps_its_schema() {
    let mut model = model();

    assert_eq!(model.supersede(), MutationOutcome::Recorded);
    assert_eq!(model.state, AuthorizationModelState::Superseded);
    assert!(!model.current());

    assert_eq!(model.supersede(), MutationOutcome::AlreadyRecorded);
    assert_eq!(model.state, AuthorizationModelState::Superseded);
    assert_eq!(model.schema, "type document relations { viewer, editor }");
}

#[test]
fn the_declared_states_are_exactly_the_states_the_contract_names() {
    assert_eq!(PolicyState::ALL.len(), 2);
    assert_eq!(AuthorizationModelState::ALL.len(), 2);

    for (position, state) in PolicyState::ALL.iter().enumerate() {
        assert_eq!(policy_state_index(*state), position);
    }
    for (position, state) in AuthorizationModelState::ALL.iter().enumerate() {
        assert_eq!(model_state_index(*state), position);
    }

    assert!(!PolicyState::Recorded.terminal());
    assert!(PolicyState::Superseded.terminal());
    assert!(!AuthorizationModelState::Recorded.terminal());
    assert!(AuthorizationModelState::Superseded.terminal());
}

#[test]
fn every_projection_field_may_be_persisted() {
    fn persistable<T: PersistedValue>() {}

    persistable::<Policy>();
    persistable::<AuthorizationModel>();
    persistable::<PolicyId>();
    persistable::<AuthorizationModelId>();
    persistable::<OrganizationId>();
    persistable::<PolicyVersion>();
    persistable::<PolicyState>();
    persistable::<AuthorizationModelState>();
    persistable::<String>();
}
