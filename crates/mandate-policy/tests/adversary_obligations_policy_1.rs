//! Adversary pass 1 on `story:obligations-policy`: the two supersede commands driven against
//! the documents that publish them, rather than against the behaviour the crate happens to
//! have.
//!
//! `contracts/obligations/policy.json` calls itself "the clause-level map from **every**
//! external denial an implemented command can produce" (`contracts/obligations/README.md:3`).
//! `mandate_policy::double::PolicyDouble` is the only implementor of
//! [`mandate_policy::port::PolicyAdministration`] in a library target, so it is the code those
//! rows stand for. Three things the published contracts say are not what that code does, and
//! one guard the whole suite leaves undecided.
//!
//! Nothing here rewrites, weakens or skips an existing case. Every fixture is built in this
//! file.

use mandate_policy::double::PolicyDouble;
use mandate_policy::port::{
    AttributeSet, Evaluation, PolicyAdministration, PolicyError, PolicyEvaluator, PolicyRequest,
};
use mandate_policy::record::{AuthorizationModel, Policy, PolicyState};
use mandate_types::{
    Action, Audience, AuthoritySubject, AuthorizationModelId, CorrelationId, CredentialId,
    DenialReason, OrganizationId, PolicyId, PolicyVersion, PrincipalId, ResourceId, ResourceRef,
    ResourceType, Uuid, VerifiedContext,
};

/// The compiled model, read where the registry step reads it.
const IR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../generated/ir/system.json"
);

/// The published HTTP contract for `mandate.policy`, generated from the same model.
const OPENAPI: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../generated/openapi/mandate-authorization.yaml"
);

/// `mandate.policy.SupersedeAuthorizationModel`'s declared `condition.cause`, verbatim.
///
/// Pinned rather than parsed: the case asserts the compiled model still carries it, so a
/// contract that moves reds this file instead of quietly changing what it is measured against.
const MODEL_CAUSE: &str = "Caller lacks authorization-model administration authority, the model \
                           is outside the verified organization, no later model version is \
                           recorded for that organization, or the relationship revision the \
                           later version requires is not yet observable.";

fn uuid(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(1))
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

fn policy_of(organization: OrganizationId, byte: u8, version: &str) -> Policy {
    Policy::recorded(
        PolicyId::new(uuid(byte)),
        organization,
        PolicyVersion::new(version),
        "permit(principal, action, resource);",
    )
}

fn policy(byte: u8, version: &str) -> Policy {
    policy_of(organization(), byte, version)
}

fn model(byte: u8, version: &str) -> AuthorizationModel {
    AuthorizationModel::recorded(
        AuthorizationModelId::new(uuid(byte)),
        organization(),
        PolicyVersion::new(version),
        "type document relations { viewer, editor }",
    )
}

/// One policy version and one model version, both current and both this organization's.
fn published() -> PolicyDouble {
    let mut double = PolicyDouble::new();
    double.record_policy(policy(4, "2026-09-18.1"));
    double.record_model(model(5, "2026-09-18.1"));
    double
}

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|error| panic!("{path}: {error}"))
}

fn subject() -> AuthoritySubject {
    AuthoritySubject::Principal(PrincipalId::new(uuid(2)))
}

fn resource() -> ResourceRef {
    ResourceRef {
        resource_type: ResourceType::new("document"),
        resource_id: ResourceId::new(uuid(5)),
    }
}

/// One policy version, one model version carrying `schema`, and one rule that names the
/// request [`evaluate`] asks.
fn folded_with_schema(schema: &str) -> PolicyDouble {
    let mut double = PolicyDouble::new();
    double.record_policy(policy(4, "2026-09-18.1"));
    double.record_model(AuthorizationModel::recorded(
        AuthorizationModelId::new(uuid(5)),
        organization(),
        PolicyVersion::new("2026-09-18.1"),
        schema,
    ));
    double.allow(organization(), subject(), Action::new("read"), resource());
    double
}

fn evaluate(double: &PolicyDouble) -> Result<Evaluation, PolicyError> {
    let context = context();
    let subject = subject();
    let action = Action::new("read");
    let resource = resource();
    let attributes = AttributeSet::new();

    double.evaluate(&PolicyRequest {
        context: &context,
        subject: &subject,
        action: &action,
        resource: &resource,
        attributes: &attributes,
    })
}

/// The declared `wrong-state` outcome of `mandate.policy.SupersedePolicy` is answered as an
/// accepted repeat, not as the refusal the published contract carries.
///
/// `generated/openapi/mandate-authorization.yaml:251-256` publishes HTTP 409 for this command,
/// and `:903-912` fixes that response to `error: mandate.policy.Denied`, `outcome: wrong-state`,
/// "Taken when the subject is in a state none of this command's declared moves start from".
/// `mandate.policy.Policy`'s lifecycle gives `supersede` `from: ["Recorded"]`, so a policy
/// already `Superseded` is exactly that subject.
///
/// `PolicyDouble::supersede_policy` (`src/double.rs:254-259`) answers
/// `Ok(Superseded { outcome: AlreadyRecorded })` for it. So the one implementor of the port
/// returns the accepted branch where two generated documents publish a refusal, and
/// `contracts/obligations/policy.json` — which this unit rewrote — says nothing about it,
/// because the registry reads only the `external` cause.
///
/// `src/port.rs:296-303` is the crate's own reason (`docs/adr/0009-event-sourced-persistence.md`,
/// a repeated move is accepted and records nothing further). That reason is not in either
/// generated document, and it is the documents a consumer reads. The reconciliation is not this
/// case's to make; the disagreement is.
#[test]
fn the_published_wrong_state_refusal_is_answered_as_an_accepted_repeat() {
    let published_contract = read(OPENAPI);
    assert!(
        published_contract.contains("mandate.policy.SupersedePolicy.wrong-state.Response:"),
        "the generated OpenAPI no longer publishes a wrong-state response for the command"
    );

    let mut double = published();
    double.record_policy(policy(6, "2026-09-18.2"));

    let first = double
        .supersede_policy(&context(), &PolicyId::new(uuid(4)))
        .expect("a later version is recorded, so the first call is accepted");
    assert!(first.outcome.changed());
    assert_eq!(double.policies()[0].state, PolicyState::Superseded);

    let repeat = double.supersede_policy(&context(), &PolicyId::new(uuid(4)));

    // Pinned by the coordinator (`review-result:wave-d-obligations-policy-adversary-1` F1) to the
    // behaviour that ships. The finding is upheld and is pre-existing: two generated documents
    // publish a 409 `wrong-state` refusal and the only implementor answers the accepted branch.
    // Reconciling them is a `systems/mandate/domains/policy.yaml` decision, not a registry row,
    // and the registry cannot see the disagreement either way because it reads the `denied` cause
    // and not the `wrong-state` outcome. The gap is recorded on `story:unpublished-refusals`;
    // this case fails the day that story changes either side, which is what it is here for.
    assert_eq!(
        repeat
            .as_ref()
            .map(|superseded| superseded.outcome.changed()),
        Ok(false),
        "the shipped answer to a repeated supersede changed. It was \
         `Ok(Superseded {{ outcome: AlreadyRecorded }})` — accepted and recording nothing further, \
         per `src/port.rs:296-303` and `docs/adr/0009-event-sourced-persistence.md`. Two generated \
         documents publish a refusal for this subject instead: \
         `generated/openapi/mandate-authorization.yaml:251-256` (HTTP 409) and `:903-912` \
         (`error: mandate.policy.Denied`, `outcome: wrong-state`). `story:unpublished-refusals` \
         owns reconciling them; when it does, this pin is what tells you to re-read the clause."
    );
}

/// "no later policy version is recorded for that organization" is decided by the order records
/// were folded in, and `Policy::version` is read by nothing that decides it.
///
/// The clause the registry publishes says *version*. `PolicyDouble::supersede_policy` searches
/// `self.policies[position + 1..]` (`src/double.rs:262-264`) — every record folded in after this
/// one — and compares no `PolicyVersion` anywhere. So a fold holding `2026-09-18.2` and then
/// `2026-09-18.1` supersedes the newer version on the strength of the older one, and the
/// organization is left with `2026-09-18.1` current while `2026-09-18.2` sits in `Superseded`,
/// whose own declaration is "a later version is current and this one is kept for attribution"
/// (`src/record.rs:23-25`).
///
/// What reaches it: `record_policy` is `pub` and the order is its caller's; no shipped caller of
/// it exists, so this is a state this case builds and not one anybody was shown to reach.
#[test]
fn the_later_version_guard_reads_recording_order_and_never_the_version_field() {
    let mut double = PolicyDouble::new();
    double.record_policy(policy(4, "2026-09-18.2"));
    double.record_policy(policy(6, "2026-09-18.1"));

    let outcome = double.supersede_policy(&context(), &PolicyId::new(uuid(4)));
    let left: Vec<(String, PolicyState)> = double
        .policies()
        .iter()
        .map(|policy| (policy.version.as_str().to_owned(), policy.state))
        .collect();

    assert_eq!(
        outcome
            .as_ref()
            .map(|superseded| superseded.outcome.changed()),
        Ok(true),
        "the shipped guard stopped deciding by fold order. It searched \
         `self.policies[position + 1..]` (`src/double.rs:262-264`) and compared no \
         `PolicyVersion`, so recording 2026-09-18.1 after 2026-09-18.2 satisfied \"no later \
         policy version is recorded for that organization\" on the strength of the *older* \
         record and left the fold {left:?}. Pinned by the coordinator \
         (`review-result:wave-d-obligations-policy-adversary-1` F2) as INFEASIBLE today — \
         `record_policy` is `pub` and no shipped caller produces this order — and recorded on \
         `story:unpublished-refusals`, because it becomes reachable the moment a real adapter \
         folds from a store."
    );
}

/// The port refuses an id it holds no record of, and the declared cause publishes no clause
/// for that condition — while the registry row this unit added binds the *same* error value to
/// a clause that names a different condition.
///
/// `supersede_authorization_model` answers `PolicyError::Denied(DenialReason::Denied)` twice
/// over: once at `src/double.rs:282-286`, for an id no `AuthorizationModel` in the fold carries,
/// and once at `src/double.rs:302-304`, for the declared clause "no later model version is
/// recorded for that organization". The first condition appears in no clause of
/// `MODEL_CAUSE`, so `contracts/obligations/policy.json` — "the clause-level map from every
/// external denial an implemented command can produce" — publishes nothing for a refusal the
/// only implementor of the port produces on its first branch.
///
/// The unit's own `no_state_change` case drives that undeclared branch
/// (`tests/obligations.rs:209`, `AuthorizationModelId::new(uuid(3))`) without the document
/// naming it.
///
/// What reaches it: `id` is caller input on both commands
/// (`generated/ir/system.json`, `mandate.policy.SupersedeAuthorizationModel.input`), and an id
/// that resolves to no record is the port's first branch.
#[test]
fn the_declared_cause_publishes_no_clause_for_the_id_the_port_refuses_first() {
    assert!(
        read(IR).contains(MODEL_CAUSE),
        "the compiled model no longer declares the cause this case is measured against"
    );

    let mut double = published();

    let unresolved = double
        .supersede_authorization_model(&context(), &AuthorizationModelId::new(uuid(0x33)))
        .expect_err("no AuthorizationModel in the fold carries this id");
    let no_later = double
        .supersede_authorization_model(&context(), &AuthorizationModelId::new(uuid(5)))
        .expect_err("the only recorded version has nothing later");

    assert_eq!(unresolved, PolicyError::Denied(DenialReason::Denied));
    assert_eq!(no_later, PolicyError::Denied(DenialReason::Denied));

    let names_the_condition = [
        "unresolved",
        "does not resolve",
        "no such",
        "is not recorded",
        "no authorization model is recorded",
        "unknown",
    ]
    .iter()
    .any(|phrase| MODEL_CAUSE.contains(phrase));

    // Pinned by the coordinator (`review-result:wave-d-obligations-policy-adversary-1` F3) to the
    // contract that ships. The finding is upheld and pre-existing: the port's first branch refuses
    // an unresolved id with the same `Denied(Denied)` that witnesses a published clause, and the
    // declared cause enumerates no condition for it — so the registry publishes nothing for a
    // refusal the shipped port produces on caller input. Publishing the condition is a
    // `policy.yaml` change, not a registry row, and it is the fourth instance of the class this
    // half; `story:unpublished-refusals` owns it. This case flips when the cause grows the clause.
    assert!(
        !names_the_condition,
        "the declared cause now enumerates a condition for an id the fold holds no record of, so \
         the refusal `src/double.rs:282-286` produces is publishable and \
         `contracts/obligations/policy.json` should carry a clause for it. \
         `story:unpublished-refusals` recorded it as unpublished; re-read that story and this \
         document together. Declared cause: {MODEL_CAUSE:?}"
    );
}

/// The organization predicate inside the later-version guard is decided by no case in this
/// workspace — this one decides it.
///
/// `src/double.rs:299-301` requires the later record to belong to the same organization. Every
/// `record_policy`/`record_model` call in `crates/mandate-policy/tests/` and in
/// `crates/mandate-authz/tests/` folds in a record of the *same* organization, so dropping
/// `model.organization_id == organization` from that predicate leaves the whole suite green,
/// including the row this unit added for "no later model version is recorded **for that
/// organization**".
///
/// This case is green against the tree as it stands. It is here because it is the case that
/// would fall under that mutation, and the four the unit added would not.
#[test]
fn a_later_version_of_another_organization_does_not_satisfy_the_later_version_guard() {
    let mut double = PolicyDouble::new();
    double.record_model(model(5, "2026-09-18.1"));
    double.record_model(AuthorizationModel::recorded(
        AuthorizationModelId::new(uuid(6)),
        OrganizationId::new(uuid(9)),
        PolicyVersion::new("2026-09-18.2"),
        "type document relations { viewer, editor }",
    ));

    assert_eq!(
        double.supersede_authorization_model(&context(), &AuthorizationModelId::new(uuid(5))),
        Err(PolicyError::Denied(DenialReason::Denied)),
        "the later version belongs to another organization, and the clause is \"no later model \
         version is recorded for that organization\""
    );
}

/// `mandate.graph.WriteRelationship`'s clause "the relationship is not admitted by the
/// authorization model" is not decided by `mandate-policy` either, so the crate it was routed
/// to cannot bind it.
///
/// `crates/mandate-graph/src/relationship.rs:10` says "The fourth, admission by the
/// authorization model, is `mandate-policy`'s", and on the strength of that
/// `contracts/obligations/graph.json` withdrew the row and deferred it to
/// `story:cross-crate-clauses`, whose remedy is a `decided_in: <crate>` field naming the crate
/// that decides it. This case asks whether `mandate-policy` is that crate.
///
/// `AuthorizationModel::schema` (`src/record.rs:130-131`, "kept after superseding so decisions
/// stay attributable") is written by `record_model` and read by nothing.
/// `PolicyEvaluator::evaluate` consults `current_model(organization).is_none()`
/// (`src/double.rs:171`) — the *presence* of a version, never its content — and then folds
/// `self.rules`, which are told to the double directly and are not derived from any model. So
/// a fold whose model declares the relation and one whose model declares nothing at all answer
/// the same request identically, and no row `mandate-policy` could carry would cover that
/// clause.
#[test]
fn the_authorization_model_schema_decides_nothing_in_this_crate() {
    let declares_the_relation = folded_with_schema("type document relations { viewer, editor }");
    let declares_nothing = folded_with_schema("");

    let admitted = evaluate(&declares_the_relation);
    let unadmitted = evaluate(&declares_nothing);

    // Pinned by the coordinator (`review-result:wave-d-obligations-policy-adversary-1` F4) to the
    // behaviour that ships — and this case changed a ruling. `mandate.graph.WriteRelationship`'s
    // clause "the relationship is not admitted by the authorization model" had been re-pointed to
    // `story:cross-crate-clauses` on the strength of `crates/mandate-graph/src/relationship.rs:10`
    // saying the refusal is `mandate-policy`'s. This measurement says `mandate-policy` does not
    // make it: `AuthorizationModel::schema` (`src/record.rs:130-131`) is written by `record_model`
    // and read by nothing, and `evaluate` consults only `current_model(..).is_none()`
    // (`src/double.rs:171`). The clause now defers to `story:graph-policy-adapter` (alignment
    // commit `237d93e`). A module doc naming another crate is a hypothesis about where a decision
    // lives, not a measurement of it.
    assert_eq!(
        admitted, unadmitted,
        "an authorization model declaring the relation now answers differently from one declaring \
         nothing, so something in this crate has begun to decide admission by the authorization \
         model. If that is `AuthorizationModel::schema` finally being read, \
         `mandate.graph.WriteRelationship`'s clause \"the relationship is not admitted by the \
         authorization model\" may be bindable here after all, and its deferral to \
         `story:graph-policy-adapter` should be re-read."
    );
}

/// The same predicate on the policy command, for the same reason.
///
/// `src/double.rs:262-264`. Green against the tree as it stands.
#[test]
fn a_later_policy_version_of_another_organization_does_not_satisfy_the_guard() {
    let mut double = PolicyDouble::new();
    double.record_policy(policy(4, "2026-09-18.1"));
    double.record_policy(policy_of(OrganizationId::new(uuid(9)), 6, "2026-09-18.2"));

    assert_eq!(
        double.supersede_policy(&context(), &PolicyId::new(uuid(4))),
        Err(PolicyError::Denied(DenialReason::Denied)),
        "the later version belongs to another organization, and the clause is \"no later policy \
         version is recorded for that organization\""
    );
}
