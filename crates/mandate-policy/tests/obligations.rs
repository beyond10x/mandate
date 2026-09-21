//! The denial clauses of `mandate.policy` that `contracts/obligations/policy.json` carried
//! unbound, and the two commands' no-state-change obligations.
//!
//! `story:obligation-registry` split each implemented command's declared `condition.cause`
//! into its clauses. Two were left `blocked_on: story:obligations-policy` — the two
//! authority clauses — and neither command named a no-state-change case. What this file
//! adds is six cases. What the document alongside it does is re-point the four clauses that
//! no code in this workspace decides, move two model-command rows off cases that drive the
//! policy command, and split each later-version clause into the two conditions it publishes,
//! which takes this crate from eight clauses to ten.
//!
//! # Every row here is on the `double` path, and that is not a defect of this file
//!
//! `crates/mandate-policy/src/lib.rs:64` realizes both supersede commands by
//! [`mandate_policy::port::PolicyAdministration`], "not by a handler: this crate chooses no
//! policy engine (`story:graph-policy-adapter` does)" (`lib.rs:72`). The only implementor of
//! that port in a library target is [`PolicyDouble`] — `src/double.rs:239`; the other
//! `impl` in the workspace is `tests/port.rs:203`, a stub declared inside a test binary. A
//! `double` value is an item path of a library target — `contracts/obligations/README.md:90`
//! writes one as `mandate_graph::double::GraphDouble`, and `:101` calls it the stand-in for
//! the deciding code itself — and a type declared in a test binary has no such path to name.
//! So what decides these refusals is a stand-in for the deciding
//! code, the document publishes every row `path: "double"`, and each clause keeps a
//! `blocked_on` naming `story:graph-policy-adapter`, which owns the port's shipped
//! implementation. A double row never covers; that is the point of it.
//!
//! # What these cases are for
//!
//! Two of the six `double` rows the registry already carried named a case that never calls
//! the command's own path. `mandate.policy.SupersedeAuthorizationModel`'s tenant and
//! no-later-version clauses both named
//! `mandate-policy::double::another_organizations_policy_is_a_tenant_mismatch` and
//! `mandate-policy::double::a_version_with_no_later_version_recorded_cannot_be_superseded`,
//! and both of those drive [`PolicyAdministration::supersede_policy`] — the *policy*
//! command. `supersede_authorization_model` reaches its own guards, at `src/double.rs:288`
//! and `src/double.rs:299`, and until this file nothing drove either. A row is evidence of a
//! command only where the command's own path calls the deciding function, so the two model
//! clauses now name the two cases below.
//!
//! The two no-state-change cases assert the whole fold, by value: [`PolicyDouble`] derives
//! `PartialEq`, so a clone taken before the refused call and compared after it says that no
//! version, rule, role or trusted attribute moved — not merely that the one record under
//! test kept its state.
//!
//! # Both halves of the later-version clause, and a case that binds each
//!
//! "no later policy version is recorded **for that organization**" is two conditions, so
//! `contracts/obligations/policy.json` publishes it as two clauses — the rule
//! `contracts/obligations/README.md:77` states, one clause per condition the cause
//! enumerates. `src/double.rs:264` decides both together: a record after the one under test
//! satisfies the guard only if it is `current()` **and** `organization_id == organization`
//! (`src/double.rs:301` for the model command). Before the last two cases below, every fold
//! in this file held one later record, this organization's and current, so neither conjunct
//! had to be true for any case here to pass and the published words "for that organization"
//! were bound by nothing.
//!
//! Each of the last two cases folds two later records instead: one held by this organization
//! and already superseded, and one current but held by `another_organization()`. Neither
//! satisfies the conjunction, so the refusal stands, and the two records fail different
//! conjuncts. Each case then repeats the call against the same fold with that second record
//! recorded for this organization, which accepts. The organization field of that record is
//! the only difference between the refused call and the accepted one, and the superseded
//! record is the only thing `current()` answers about —
//! so dropping either half of the predicate fells the case.
//!
//! No fold the shipped writer produces reaches a refusal that turns on `current()`:
//! `src/record.rs:23-25` declares `Superseded` to mean a later version is current, so a fold
//! whose later same-organization records are all superseded contradicts its own projection.
//! These two cases build that fold through `record_policy` and `record_model` directly, which
//! is the only way the conjunct decides a refusal at all.
//!
//! # What is not here, and why no case could put it here
//!
//! Four clauses stay deferred and none for want of a case.
//!
//! The two authority clauses — "Caller lacks authorization-model administration authority"
//! and "Caller lacks policy-administration authority" — name a decision nothing in this
//! workspace makes. The port takes the caller as a `mandate.core.VerifiedContext`
//! (`src/port.rs:347`), and that record carries subject, actor, organization, audience,
//! credential, delegation, execution and correlation (`mandate-types/src/record.rs:63`) —
//! no authority, role or scope an administration check could read. There is no admission
//! port to hand the question to either, as `mandate-federation` has at
//! `register_client.rs:93`. `docs/architecture/unmapped.md:19` is where that sits: ESS
//! command outcomes "describe authoritative external validation, not executable
//! cryptographic, graph or policy predicates". The document defers both to
//! `decision-blocker:guards`, with the authority clauses of
//! `contracts/obligations/sts.json`.
//!
//! The other two name an engine's knowledge. "the relationship revision the later version
//! requires is not yet observable" is a staleness the double never consults —
//! `supersede_authorization_model` reads `self.models` and nothing else — and the one place
//! this crate produces that reason is `PolicyEvaluator::evaluate` (`src/double.rs:171`),
//! which is a different command's path. "decisions in flight cannot remain attributable to
//! the version that made them" is a condition the shipped shape cannot reach at all: a
//! superseded version is kept rather than deleted precisely so that attribution survives
//! (`src/port.rs:220`), so there is no in-flight state for a refusal to be about. Both defer
//! to `story:graph-policy-adapter`.

use mandate_policy::double::PolicyDouble;
use mandate_policy::port::{PolicyAdministration, PolicyError};
use mandate_policy::record::{AuthorizationModel, AuthorizationModelState, Policy, PolicyState};
use mandate_types::{
    Audience, AuthorizationModelId, CorrelationId, CredentialId, DenialReason, OrganizationId,
    PolicyId, PolicyVersion, PrincipalId, Uuid, VerifiedContext,
};

fn uuid(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(1))
}

/// An organization that is not [`organization`], and holds no record any case under test
/// resolves an id in.
fn another_organization() -> OrganizationId {
    OrganizationId::new(uuid(9))
}

fn context() -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::new(uuid(2)),
        actor: None,
        organization: organization(),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(7)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("correlation"),
    }
}

fn policy_of(held_by: OrganizationId, byte: u8, version: &str) -> Policy {
    Policy::recorded(
        PolicyId::new(uuid(byte)),
        held_by,
        PolicyVersion::new(version),
        "permit(principal, action, resource);",
    )
}

fn model_of(held_by: OrganizationId, byte: u8, version: &str) -> AuthorizationModel {
    AuthorizationModel::recorded(
        AuthorizationModelId::new(uuid(byte)),
        held_by,
        PolicyVersion::new(version),
        "type document relations { viewer, editor }",
    )
}

fn policy(byte: u8, version: &str) -> Policy {
    policy_of(organization(), byte, version)
}

fn model(byte: u8, version: &str) -> AuthorizationModel {
    model_of(organization(), byte, version)
}

/// A record of [`organization`], folded after the one under test and already superseded.
///
/// `src/double.rs:264` accepts a later record only if it is `current()`, so a record in this
/// state is what the `current()` conjunct — rather than the organization comparison — refuses.
fn superseded_policy(byte: u8, version: &str) -> Policy {
    let mut policy = policy_of(organization(), byte, version);
    policy.supersede();
    policy
}

/// [`superseded_policy`] for the model command's guard at `src/double.rs:301`.
fn superseded_model(byte: u8, version: &str) -> AuthorizationModel {
    let mut model = model_of(organization(), byte, version);
    model.supersede();
    model
}

/// One policy version and one model version, both current and both this organization's.
fn published() -> PolicyDouble {
    let mut double = PolicyDouble::new();
    double.record_policy(policy(4, "2026-09-18.1"));
    double.record_model(model(5, "2026-09-18.1"));
    double
}

/// `mandate.policy.SupersedeAuthorizationModel`, "the model is outside the verified
/// organization".
///
/// The tenant guard of the *model* command is `src/double.rs:288`, and it is its own
/// comparison — the policy command's guard at `src/double.rs:251` reads a different list and
/// answers for a different id. A later version is recorded here so that the call would
/// otherwise be accepted: what refuses it is the organization the context carries and
/// nothing else.
#[test]
fn another_organizations_model_is_a_tenant_mismatch() {
    let mut double = published();
    double.record_model(model(6, "2026-09-18.2"));

    let mut elsewhere = context();
    elsewhere.organization = OrganizationId::new(uuid(9));

    let refusal = double
        .supersede_authorization_model(&elsewhere, &AuthorizationModelId::new(uuid(5)))
        .expect_err("another tenant's authorization model");

    assert_eq!(refusal, PolicyError::Denied(DenialReason::TenantMismatch));
    assert_eq!(refusal.denial_reason(), DenialReason::TenantMismatch);
    assert!(
        refusal.is_denial(),
        "the caller is told a decision, not an absence"
    );
}

/// `mandate.policy.SupersedeAuthorizationModel`, "no later model version is recorded for
/// that organization".
///
/// Superseding the only current version would leave the organization with no model to
/// attribute an answer to, so `src/double.rs:299` refuses it. The context is this
/// organization's and the id resolves: the later-version guard is the only one left to fire.
#[test]
fn a_model_version_with_no_later_version_recorded_cannot_be_superseded() {
    let mut double = published();

    let refusal = double
        .supersede_authorization_model(&context(), &AuthorizationModelId::new(uuid(5)))
        .expect_err("nothing later is recorded");

    assert_eq!(refusal, PolicyError::Denied(DenialReason::Denied));
    assert_eq!(double.models()[0].state, AuthorizationModelState::Recorded);
}

/// `mandate.policy.SupersedePolicy` refuses without moving its projection.
///
/// Both of the refusals the shipped shape can produce are driven, and the fold is compared
/// by value across each: a refusal that recorded the move would differ, and so would one
/// that recorded anything else.
#[test]
fn a_refused_policy_supersede_leaves_the_policy_fold_unmoved() {
    let mut elsewhere = context();
    elsewhere.organization = OrganizationId::new(uuid(9));

    for (context, id, reason) in [
        (context(), uuid(4), DenialReason::Denied),
        (elsewhere, uuid(4), DenialReason::TenantMismatch),
        (context(), uuid(3), DenialReason::Denied),
    ] {
        let mut double = published();
        if reason == DenialReason::TenantMismatch {
            double.record_policy(policy(6, "2026-09-18.2"));
        }
        let before = double.clone();

        let refusal = double
            .supersede_policy(&context, &PolicyId::new(id))
            .expect_err("each of these refuses");

        assert_eq!(refusal, PolicyError::Denied(reason));
        assert_eq!(double, before, "a refusal records nothing");
        assert_eq!(double.policies()[0].state, PolicyState::Recorded);
    }
}

/// `mandate.policy.SupersedeAuthorizationModel` refuses without moving its projection.
#[test]
fn a_refused_model_supersede_leaves_the_model_fold_unmoved() {
    let mut elsewhere = context();
    elsewhere.organization = OrganizationId::new(uuid(9));

    for (context, id, reason) in [
        (context(), uuid(5), DenialReason::Denied),
        (elsewhere, uuid(5), DenialReason::TenantMismatch),
        (context(), uuid(3), DenialReason::Denied),
    ] {
        let mut double = published();
        if reason == DenialReason::TenantMismatch {
            double.record_model(model(6, "2026-09-18.2"));
        }
        let before = double.clone();

        let refusal = double
            .supersede_authorization_model(&context, &AuthorizationModelId::new(id))
            .expect_err("each of these refuses");

        assert_eq!(refusal, PolicyError::Denied(reason));
        assert_eq!(double, before, "a refusal records nothing");
        assert_eq!(double.models()[0].state, AuthorizationModelState::Recorded);
    }
}

/// `mandate.policy.SupersedePolicy`, the "for that organization" half of "no later policy
/// version is recorded for that organization".
///
/// The guard at `src/double.rs:262-264` asks two things of every record folded after the one
/// under test — that it is `current()`, and that its `organization_id` is the organization
/// that record is held by — and a fold whose later records all satisfy one of them leaves the
/// other bound by nothing. This fold carries one later record that fails each: `uuid(8)`, this
/// organization's and already superseded, and `uuid(6)`, current and `another_organization()`'s.
/// So the refusal cannot come from the version being absent — there are two later versions —
/// and it cannot come from either conjunct alone, because each record satisfies the one the
/// other fails. The second half of the case is the same fold with `uuid(6)` recorded for this
/// organization, which accepts, so the organization field of that record is the only
/// difference between a call that is refused and one that is not, while dropping
/// `policy.current()` from the guard would let `uuid(8)` accept the first call.
#[test]
fn a_later_policy_version_of_another_organization_is_not_one_for_this_organization() {
    let mut double = published();
    double.record_policy(superseded_policy(8, "2026-09-18.2"));
    double.record_policy(policy_of(another_organization(), 6, "2026-09-18.3"));
    let before = double.clone();

    let refusal = double
        .supersede_policy(&context(), &PolicyId::new(uuid(4)))
        .expect_err("no later version is both current and recorded for this organization");

    assert_eq!(refusal, PolicyError::Denied(DenialReason::Denied));
    assert_eq!(double, before, "a refusal records nothing");
    assert_eq!(double.policies()[0].state, PolicyState::Recorded);
    assert_eq!(
        double.policies()[1].state,
        PolicyState::Superseded,
        "the one later record this organization holds is not a current version"
    );
    assert_eq!(
        double.policies()[2].state,
        PolicyState::Recorded,
        "and least of all another organization's record"
    );

    let mut held_here = published();
    held_here.record_policy(superseded_policy(8, "2026-09-18.2"));
    held_here.record_policy(policy_of(organization(), 6, "2026-09-18.3"));

    let accepted = held_here
        .supersede_policy(&context(), &PolicyId::new(uuid(4)))
        .expect("the same later version, recorded for this organization, is a later version");

    assert!(accepted.outcome.changed());
    assert_eq!(held_here.policies()[0].state, PolicyState::Superseded);
}

/// `mandate.policy.SupersedeAuthorizationModel`, the "for that organization" half of "no later
/// model version is recorded for that organization".
///
/// The model command reaches its own guard, at `src/double.rs:299-301`, which reads
/// `self.models` and asks the same conjunction of each later record for itself. The shape is
/// the one above: two later records, one superseded and this organization's and one current
/// and `another_organization()`'s, refused; and accepted once the current one is this
/// organization's.
#[test]
fn a_later_model_version_of_another_organization_is_not_one_for_this_organization() {
    let mut double = published();
    double.record_model(superseded_model(8, "2026-09-18.2"));
    double.record_model(model_of(another_organization(), 6, "2026-09-18.3"));
    let before = double.clone();

    let refusal = double
        .supersede_authorization_model(&context(), &AuthorizationModelId::new(uuid(5)))
        .expect_err("no later version is both current and recorded for this organization");

    assert_eq!(refusal, PolicyError::Denied(DenialReason::Denied));
    assert_eq!(double, before, "a refusal records nothing");
    assert_eq!(double.models()[0].state, AuthorizationModelState::Recorded);
    assert_eq!(
        double.models()[1].state,
        AuthorizationModelState::Superseded,
        "the one later record this organization holds is not a current version"
    );
    assert_eq!(
        double.models()[2].state,
        AuthorizationModelState::Recorded,
        "and least of all another organization's record"
    );

    let mut held_here = published();
    held_here.record_model(superseded_model(8, "2026-09-18.2"));
    held_here.record_model(model_of(organization(), 6, "2026-09-18.3"));

    let accepted = held_here
        .supersede_authorization_model(&context(), &AuthorizationModelId::new(uuid(5)))
        .expect("the same later version, recorded for this organization, is a later version");

    assert!(accepted.outcome.changed());
    assert_eq!(
        held_here.models()[0].state,
        AuthorizationModelState::Superseded
    );
}
