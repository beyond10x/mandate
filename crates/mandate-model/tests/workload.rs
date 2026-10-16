//! The record half of `mandate.workload.RevokeWorkloadIdentity`.
//!
//! Every rule asserted here is read off `systems/mandate/domains/workload.yaml`: one entity,
//! `WorkloadIdentity`, moving `Recorded` to `Revoked` along `revoke`, and one command whose
//! accepted outcome emits `WorkloadIdentityRevoked` with `{context, id}` and whose refusals
//! carry `mandate.workload.Denied`. Whether a caller holds workload-identity administration
//! authority is `mandate-authz`'s and is never decided here.

use mandate_model::workload::{
    Denied, Refused, RefusedAs, WorkloadEvent, WorkloadIdentities, WorkloadIdentity,
    WorkloadIdentityRead, WorkloadIdentityState, decide_revoke_workload_identity,
};
use mandate_types::{
    Audience, CorrelationId, CredentialId, DenialReason, ExternalSubject, OrganizationId,
    PrincipalId, TrustDomain, VerifiedContext, WorkloadIdentityId,
};

fn uuid(tag: u16) -> String {
    format!("1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f{tag:04x}")
}

fn organization(tag: u16) -> OrganizationId {
    OrganizationId::parse(&uuid(tag)).expect("organization identity")
}

fn principal(tag: u16) -> PrincipalId {
    PrincipalId::parse(&uuid(tag)).expect("principal identity")
}

fn workload(tag: u16) -> WorkloadIdentityId {
    WorkloadIdentityId::parse(&uuid(tag)).expect("workload identity")
}

fn context(organization: OrganizationId) -> VerifiedContext {
    VerifiedContext {
        subject: principal(0x10),
        actor: None,
        organization,
        audience: Audience::new("mandate"),
        credential: CredentialId::parse(&uuid(0xffff)).expect("credential identity"),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("correlation"),
    }
}

/// A `Recorded` workload identity in `organization`.
///
/// No command in `systems/mandate` creates a `WorkloadIdentity` (`story:declared-writers`),
/// so a record is arranged here as the read port would answer it.
fn recorded(id: WorkloadIdentityId, organization: OrganizationId) -> WorkloadIdentity {
    WorkloadIdentity {
        id,
        organization_id: organization,
        principal_id: principal(0x20),
        trust_domain: TrustDomain::new("spiffe://cluster.example"),
        external_subject: ExternalSubject::new("spiffe://cluster.example/ns/jobs/sa/runner"),
        state: WorkloadIdentityState::Recorded,
    }
}

/// The hand-written projection is the generated entity shape, in both states: the record
/// serializes, `mandate_contract`'s shape (`deny_unknown_fields`, every required key) reads it
/// back, and re-serializing gives the same document.
#[test]
fn the_projection_round_trips_into_its_generated_entity_shape_in_every_state() {
    for state in [
        WorkloadIdentityState::Recorded,
        WorkloadIdentityState::Revoked,
    ] {
        let record = WorkloadIdentity {
            state,
            ..recorded(workload(0x30), organization(1))
        };
        let emitted = serde_json::to_value(&record).expect("the record serializes");
        let shape: mandate_contract::entities::MandateWorkloadWorkloadIdentity =
            serde_json::from_value(emitted.clone()).expect("the generated shape reads it");
        assert_eq!(
            serde_json::to_value(&shape).expect("the shape serializes"),
            emitted
        );
    }
}

/// `workload.yaml`, RevokeWorkloadIdentity accepted: emits `WorkloadIdentityRevoked` with
/// `context: input.context` and `id: input.id`, and moves the record along `revoke`.
#[test]
fn a_recorded_workload_identity_is_revoked_and_the_record_is_kept_in_revoked() {
    let acme = organization(1);
    let id = workload(0x30);
    let mut identities = WorkloadIdentities::holding([recorded(id, acme)]);
    let caller = context(acme);

    let event = decide_revoke_workload_identity(&identities, &caller, id)
        .expect("a recorded identity in the verified organization is revoked");
    assert_eq!(
        event,
        WorkloadEvent::IdentityRevoked {
            context: caller.clone(),
            id,
        }
    );
    assert_eq!(event.ess_name(), "mandate.workload.WorkloadIdentityRevoked");

    identities.apply(&event);
    let kept = identities
        .workload_identity(&id)
        .expect("the record is kept, never destroyed");
    assert_eq!(kept.state, WorkloadIdentityState::Revoked);
    assert_eq!(kept.organization_id, acme);

    // The projection is a fold: the arranged records with the log applied, from scratch.
    let rebuilt = WorkloadIdentities::fold([recorded(id, acme)], std::slice::from_ref(&event));
    assert_eq!(rebuilt, identities);
}

/// `workload.yaml`: `Revoked` is terminal, and `revoke` leaves only `Recorded`. A second
/// revocation of an identity of the caller's own organization takes the declared `wrong-state`
/// branch, emits nothing and moves no record.
#[test]
fn a_second_revocation_answers_wrong_state_and_emits_nothing() {
    let acme = organization(1);
    let id = workload(0x30);
    let mut identities = WorkloadIdentities::holding([recorded(id, acme)]);
    let caller = context(acme);
    let first = decide_revoke_workload_identity(&identities, &caller, id).expect("first");
    identities.apply(&first);

    let before = identities.clone();
    let refused = decide_revoke_workload_identity(&identities, &caller, id)
        .expect_err("a revoked identity is not revoked again");
    assert_eq!(
        refused,
        Refused {
            outcome: RefusedAs::WrongState,
            denied: Denied {
                reason: DenialReason::Denied
            },
        }
    );
    assert_eq!(refused.outcome.outcome(), "wrong-state");
    assert_eq!(identities, before, "a refusal moves no record");
}

/// The `wrong-state` branch is the caller's own organization's alone: a revoked identity of
/// another organization answers `denied`, exactly as an identity no record carries does, so the
/// branch discloses nothing about records elsewhere.
#[test]
fn a_revoked_identity_of_another_organization_answers_denied_like_an_unknown_one() {
    let acme = organization(1);
    let other = organization(2);
    let id = workload(0x30);
    let mut identities = WorkloadIdentities::holding([recorded(id, acme)]);
    let first = decide_revoke_workload_identity(&identities, &context(acme), id).expect("first");
    identities.apply(&first);

    let outsider = context(other);
    let elsewhere = decide_revoke_workload_identity(&identities, &outsider, id)
        .expect_err("a revoked identity in another organization");
    let unrecorded = decide_revoke_workload_identity(&identities, &outsider, workload(0x31))
        .expect_err("an identity no record carries");
    assert_eq!(elsewhere, unrecorded);
    assert_eq!(elsewhere.outcome, RefusedAs::Denied);
    assert_eq!(elsewhere.outcome.outcome(), "denied");
}

/// `workload.yaml`, RevokeWorkloadIdentity denied: "the identity is outside the verified
/// organization". It refuses exactly as an identity no record carries does — one reason, no
/// state moved — so a caller cannot tell "not yours" from "no such identity".
#[test]
fn a_workload_identity_of_another_organization_refuses_like_an_unknown_one() {
    let acme = organization(1);
    let other = organization(2);
    let id = workload(0x30);
    let identities = WorkloadIdentities::holding([recorded(id, acme)]);
    let outsider = context(other);
    let before = identities.clone();

    let elsewhere = decide_revoke_workload_identity(&identities, &outsider, id)
        .expect_err("an identity in another organization");
    let unrecorded = decide_revoke_workload_identity(&identities, &outsider, workload(0x31))
        .expect_err("an identity no record carries");
    assert_eq!(elsewhere, unrecorded);
    assert_eq!(elsewhere.outcome, RefusedAs::Denied);
    assert_eq!(elsewhere.denied.reason, DenialReason::Denied);
    assert_eq!(identities, before, "a refusal moves no record");
    assert_eq!(
        identities
            .workload_identity(&id)
            .expect("the record is still held")
            .state,
        WorkloadIdentityState::Recorded
    );
}
