//! Adversary pass 1 on `story:obligations-authz`: the nine-clause
//! `contracts/obligations/authz.json` read as the specification it claims to be, and driven
//! against the code the same unit wrote.
//!
//! `contracts/obligations/README.md` states what the file is for: "whether *each* condition
//! the contract publishes as a refusal is one something actually refuses on". Every case
//! here takes one condition `mandate.authorization.Check`'s declared
//! `condition.cause` publishes, drives it through the shipped path, and then asks the
//! document whether it names a test that decides it.
//!
//! The document is read by hand rather than with `serde_json`: `mandate-authz` declares no
//! `[dev-dependencies]` (`crates/mandate-authz/Cargo.toml:14-18`) and an adversary pass may
//! not add one. Each caller that requires rows asserts [`clause_rows`] found some, so a parse
//! that misses is loud and is not mistaken for a finding — and a clause that is correctly
//! deferred, and therefore names none, is not mistaken for a parse that missed.

use std::fs;
use std::path::{Path, PathBuf};

use mandate_authz::context::{Binding, bind};
use mandate_authz::decision::{Denied, FixedChallenge, SequentialDecisionIds};
use mandate_authz::evaluate::Ceiling;
use mandate_authz::{CheckRequest, Pdp, check};
use mandate_graph::double::GraphDouble;
use mandate_graph::record::Grant;
use mandate_graph::topology::ResourceRegistry;
use mandate_model::Decision;
use mandate_model::graph::Topology;
use mandate_model::tenancy::{MembershipAuthority, Tenancy};
use mandate_policy::double::PolicyDouble;
use mandate_policy::port::AttributeSet;
use mandate_policy::record::{AuthorizationModel, Policy};
use mandate_types::{
    Action, ActionPattern, Audience, AuthorityScope, AuthoritySubject, AuthorizationModelId,
    AuthzRevision, CorrelationId, CredentialId, DenialReason, GrantId, OrganizationId,
    OrganizationMembershipId, PolicyId, PolicyVersion, PrincipalId, ResourceId, ResourceRef,
    ResourceType, Timestamp, Uuid, VerifiedContext,
};

// ---------------------------------------------------------------------------------------
// The world every case is driven in.
// ---------------------------------------------------------------------------------------

fn uuid(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(1))
}

/// The agent's own principal: the subject `autonomous-ceiling` is checked under.
fn agent() -> PrincipalId {
    PrincipalId::new(uuid(2))
}

/// A second member of the same organization, holding the same authority and no agency.
fn colleague() -> PrincipalId {
    PrincipalId::new(uuid(5))
}

fn resource() -> ResourceRef {
    ResourceRef {
        resource_type: ResourceType::new("document"),
        resource_id: ResourceId::new(uuid(10)),
    }
}

fn action() -> Action {
    Action::new("deployment.restart")
}

fn audience() -> Audience {
    Audience::new("mandate")
}

fn context_of(principal: PrincipalId) -> VerifiedContext {
    VerifiedContext {
        subject: principal,
        actor: None,
        organization: organization(),
        audience: audience(),
        credential: CredentialId::new(uuid(7)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("correlation"),
    }
}

/// The organization, with both principals members of it.
fn tenancy() -> Tenancy {
    let mut tenancy = Tenancy::new();
    tenancy
        .create_organization(&context_of(agent()), organization(), "acme")
        .expect("the organization is recorded");
    for (index, principal) in [agent(), colleague()].into_iter().enumerate() {
        let membership = OrganizationMembershipId::new(uuid(3 + u8::try_from(index).expect("two")));
        tenancy
            .add_organization_membership(
                &context_of(agent()),
                MembershipAuthority::VerifiedOrganization,
                membership,
                organization(),
                principal,
            )
            .expect("the subject is a member");
    }
    tenancy
}

/// The graph: the resource registered, and a persistent `operator` grant over the requested
/// action for each principal. Nothing here refuses, so nothing but a ceiling can.
fn graph() -> (GraphDouble, AuthzRevision) {
    let mut graph = GraphDouble::new();
    let mut revision = AuthzRevision::new("0");
    graph
        .register_resource(&context_of(agent()), &resource(), None)
        .expect("the resource is registered");
    for (index, principal) in [agent(), colleague()].into_iter().enumerate() {
        let subject = AuthoritySubject::Principal(principal);
        graph.admit_subject(organization(), subject.clone());
        revision = graph.record_grant(Grant::recorded(
            GrantId::new(uuid(30 + u8::try_from(index).expect("two"))),
            organization(),
            subject,
            AuthorityScope {
                actions: vec![action()],
                resources: vec![resource()],
                space: None,
            },
            "operator",
        ));
    }
    (graph, revision)
}

/// Policy allows both principals the action, and `operator` carries it.
fn policy() -> PolicyDouble {
    let mut policy = PolicyDouble::new();
    policy.record_policy(Policy::recorded(
        PolicyId::new(uuid(40)),
        organization(),
        PolicyVersion::new("v1"),
        "source",
    ));
    policy.record_model(AuthorizationModel::recorded(
        AuthorizationModelId::new(uuid(41)),
        organization(),
        PolicyVersion::new("v1"),
        "schema",
    ));
    policy.record_role(organization(), "operator", vec![action()]);
    for principal in [agent(), colleague()] {
        policy.allow(
            organization(),
            AuthoritySubject::Principal(principal),
            action(),
            resource(),
        );
    }
    policy
}

/// The platform ceiling of `tests/security/cases.json:544`: `organization: None` applies to
/// every organization (`systems/mandate/domains/delegation.yaml:5`) and it admits the action.
fn platform() -> Ceiling {
    Ceiling {
        organization: None,
        allowed_actions: vec![ActionPattern::new("deployment.*")],
        denied_actions: Vec::new(),
    }
}

/// The ceiling `crates/mandate-authz/tests/obligations.rs:150-157` calls "the installation
/// ceiling": recorded for the organization, refusing the action the grant carries.
fn installation() -> Ceiling {
    Ceiling {
        organization: Some(organization()),
        allowed_actions: vec![ActionPattern::new("deployment.*")],
        denied_actions: vec![ActionPattern::new("deployment.restart")],
    }
}

/// One `mandate.authorization.Check` for `principal`, at `minimum`, under `ceilings`.
fn check_for(
    principal: PrincipalId,
    minimum: &AuthzRevision,
    ceilings: &[Ceiling],
) -> Result<Decision, Denied> {
    let (graph, _) = graph();
    let policy = policy();
    let tenancy = tenancy();
    let topology = Topology::new();
    let issuer = FixedChallenge {
        expires_at: Timestamp::new("2026-09-18T00:00:00Z"),
        approver_policy: Some(PolicyId::new(uuid(40))),
    };
    let pdp = Pdp {
        graph: &graph,
        policy: &policy,
        catalog: &policy,
        issuer: &issuer,
        tenancy: &tenancy,
        topology: &topology,
    };

    check(
        &pdp,
        &mut SequentialDecisionIds::new(),
        &CheckRequest {
            context: &context_of(principal),
            action: &action(),
            resource: &resource(),
            expected_audience: &audience(),
            relation: "operator",
            minimum,
            attributes: &AttributeSet::new(),
            scope: None,
            ceilings,
        },
    )
}

/// The revision the graph has issued, which a read of it is caught up to.
fn issued() -> AuthzRevision {
    graph().1
}

// ---------------------------------------------------------------------------------------
// Reading the obligations document.
// ---------------------------------------------------------------------------------------

fn document_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/obligations/authz.json")
}

/// Every `id` a clause of `mandate.authorization.Check` names, in document order.
///
/// The segment a clause owns runs from its own `"clause"` key to the next one, or to the
/// `no_state_change` or `cases` key that ends the command's clause list — without that
/// bound the last clause of the command would absorb the `cases` rows below it.
///
/// A clause the document states and defers names no row at all, which is a state of the
/// document and not a fault of this reader — six of the fifteen clauses of
/// `mandate.authorization.Check` are in it after the rulings on adversary passes 1 and 2. So
/// the empty answer is returned, and the reader self-check the module header describes is
/// made by each caller that requires rows, where it can tell the two apart.
fn clause_rows(clause: &str) -> Vec<String> {
    let text = fs::read_to_string(document_path()).expect("the obligations document is readable");
    let needle = format!("\"clause\": \"{clause}\"");
    let start = text
        .find(&needle)
        .unwrap_or_else(|| panic!("the document states no clause {clause:?}"));
    let rest = &text[start + needle.len()..];
    let end = ["\"clause\":", "\"no_state_change\":", "\"cases\":"]
        .iter()
        .filter_map(|marker| rest.find(marker))
        .min()
        .unwrap_or(rest.len());

    let segment = &rest[..end];
    let marker = "\"id\": \"";
    let rows: Vec<String> = segment
        .match_indices(marker)
        .map(|(at, _)| {
            let tail = &segment[at + marker.len()..];
            let close = tail.find('"').expect("an id is a closed string");
            tail[..close].to_owned()
        })
        .collect();

    rows
}

/// Whether the document states a clause with exactly this text.
///
/// Separate from [`clause_rows`], whose empty-row assertion is a check on this file's own reader:
/// it would fire on a clause that is correctly deferred and therefore carries no row at all, which
/// is the state four of this document's fifteen clauses are in after the splits ruled on
/// `review-result:wave-d-obligations-authz-adversary-1`.
fn clause_exists(clause: &str) -> bool {
    let text = fs::read_to_string(document_path()).expect("the obligations document is readable");
    text.contains(&format!("\"clause\": \"{clause}\""))
}

// ---------------------------------------------------------------------------------------
// The cases.
// ---------------------------------------------------------------------------------------

/// RED. The clause `Credential-derived context is invalid/revoked/expired/stale` is counted
/// `real_covered` on three rows, and none of them decides any of the four conditions it
/// publishes.
///
/// All three — `context::a_context_that_is_not_direct_is_refused`,
/// `context::a_delegated_request_is_refused_closed_and_reads_nothing` and
/// `context::a_context_naming_a_delegation_or_an_execution_is_refused_closed` — drive
/// `crates/mandate-authz/src/context.rs:109-111`, the `direct` guard, which answers
/// [`DenialReason::Denied`]. "Not direct" is not "invalid", and it is not a condition the
/// declared cause publishes at all.
///
/// The `invalid` half *is* reachable and *is* decided, at
/// `crates/mandate-authz/src/context.rs:103-105`, which answers
/// [`DenialReason::InvalidCredential`] — and the one test that drives it,
/// `context::an_organization_that_admits_no_authority_refuses_the_context`
/// (`crates/mandate-authz/tests/context.rs:134`), is named by no clause of the document.
///
/// This case drives both paths and then asserts the clause names something other than the
/// three `direct` refusals. It is red because it does not.
#[test]
fn the_credential_clause_publishes_four_conditions_and_names_no_row_that_decides_one() {
    // `invalid`: the organization the context was validated against admits no authority.
    let invalid = bind(
        &Tenancy::new(),
        &Topology::new(),
        &GraphDouble::new(),
        &Binding {
            context: &context_of(agent()),
            resource: &resource(),
            expected_audience: &audience(),
            scope: None,
        },
    )
    .expect_err("an organization that admits no authority stands behind nothing");
    assert_eq!(
        invalid,
        DenialReason::InvalidCredential,
        "context.rs:103-105 decides the `invalid` condition of the clause"
    );

    // What the clause's three rows actually decide: a context that is not direct.
    let mut indirect = context_of(agent());
    indirect.actor = Some(colleague());
    let (graph, _) = graph();
    let not_direct = bind(
        &tenancy(),
        &Topology::new(),
        &graph,
        &Binding {
            context: &indirect,
            resource: &resource(),
            expected_audience: &audience(),
            scope: None,
        },
    )
    .expect_err("a request under another actor is not direct");
    assert_eq!(
        not_direct,
        DenialReason::Denied,
        "context.rs:109-111 is what the clause's three rows drive, and it is neither \
         invalid nor revoked nor expired nor stale"
    );

    let direct_refusals = [
        "mandate-authz::context::a_context_that_is_not_direct_is_refused",
        "mandate-authz::context::a_delegated_request_is_refused_closed_and_reads_nothing",
        "mandate-authz::context::a_context_naming_a_delegation_or_an_execution_is_refused_closed",
    ];
    // Amended by the coordinator to ruling F1 (`review-result:wave-d-obligations-authz-adversary-1`).
    // The finding was upheld and the document moved: the one clause that published four conditions
    // on three rows deciding none of them is now four clauses, one per condition. `invalid` takes
    // the test that actually decides it at `context.rs:103-105` — which no clause had named —
    // and `revoked`, `expired` and `stale` defer to `decision-blocker:guards`, because
    // `VerifiedContext` carries no validity, expiry or revocation field for a guard to read.
    // Each `clause_rows` call below is itself an assertion: the helper panics if the document
    // states no such clause, so re-merging the four conditions into one fells this case.
    for condition in [
        "Credential-derived context is invalid",
        "revoked",
        "expired",
        "stale",
    ] {
        assert!(
            clause_exists(condition),
            "the document states no clause {condition:?}. The four conditions the declared cause \
             publishes were one clause carrying three rows that decided none of them; ruling F1 \
             split them so each condition is published on its own and can be counted. Merging \
             them back hides three undecided conditions behind one covered row."
        );
    }

    let rows = clause_rows("Credential-derived context is invalid");

    assert!(
        rows.iter()
            .all(|id| !direct_refusals.contains(&id.as_str())),
        "the clause \"Credential-derived context is invalid\" names one of the three `direct` \
         refusals {direct_refusals:?} again. Those tests drive `context.rs:109-111`, which \
         refuses a delegated or execution-bearing context and decides none of invalid, revoked, \
         expired or stale; the guard that decides `invalid` is at `context.rs:103-105`. Rows \
         read: {rows:?}"
    );
}

/// RED. The `cases` row the unit added for `autonomous-ceiling` binds a ceiling that is not
/// an agent's.
///
/// `tests/security/cases.json:541-551` gives the scenario as "Agent persistent grant exceeds
/// platform/installation ceiling", checked "under own subject", expecting "deny outside
/// ceiling". `mandate.delegation.AgentCapabilityCeiling` declares `agent_id` as its first
/// field (`generated/ir/system.json`), and `mandate_authz::evaluate::Ceiling`
/// (`crates/mandate-authz/src/evaluate.rs:73-81`) carries `organization`,
/// `allowed_actions` and `denied_actions` and no agent at all;
/// `Ceiling::applies` (`crates/mandate-authz/src/evaluate.rs:86-90`) keys on the
/// organization alone.
///
/// So the "installation ceiling" of
/// `obligations::an_agent_grant_outside_the_installation_ceiling_is_denied_under_its_own_subject`
/// bounds every member of the organization equally, and the denial it asserts is not
/// attributable to the agent's grant exceeding the agent's ceiling. This case builds the
/// discrimination the corpus scenario requires: two members of one organization holding the
/// same persistent grant, and a ceiling recorded to bound one of them. It is red because the
/// colleague, who is no agent and has no ceiling of its own, is refused by the agent's.
#[test]
fn the_ceiling_the_autonomous_ceiling_row_binds_is_not_bound_to_an_agent() {
    let minimum = issued();

    // The control: under the platform ceiling alone both principals are allowed, so
    // whatever the installation ceiling changes below is the ceiling's and not an absent
    // grant, an unbound context or a policy that refuses.
    for principal in [agent(), colleague()] {
        let allowed = check_for(principal, &minimum, &[platform()])
            .expect("the platform ceiling admits the action the grant carries");
        assert!(allowed.allowed);
    }

    let agent_refusal = check_for(agent(), &minimum, &[platform(), installation()])
        .expect_err("the agent's own ceiling does not admit the action");
    assert_eq!(agent_refusal.reason, DenialReason::Denied);

    let colleague_decision = check_for(colleague(), &minimum, &[platform(), installation()]);

    // Pinned by the coordinator to ruling F2 (`review-result:wave-d-obligations-authz-adversary-1`),
    // which upheld this as a blocker and reverted the row: `autonomous-ceiling` is back to
    // `"tests": []`, `"blocked_on": "story:agent-authority-kernel"`. No edit to the document could
    // have turned this case green, because what it measures is a fact about the crate and not
    // about the document — `mandate.delegation.AgentCapabilityCeiling` is identified by `agent_id`
    // in `generated/ir/system.json`, `mandate_authz::evaluate::Ceiling` carries no agent field and
    // `applies()` keys on organization alone. So a ceiling recorded for the organization refuses a
    // second member who is no agent and holds the same grant, and the corpus scenario — an agent's
    // grant against an agent's ceiling — cannot be expressed here. `crates/mandate-authz/src/lib.rs:46-49`
    // already names `story:agent-authority-kernel` as the owner of the `agent_id` binding.
    //
    // The case now asserts the shipped shape. It fells the day `Ceiling` learns about agents,
    // which is the day `autonomous-ceiling` becomes bindable and its deferral should be re-read.
    assert!(
        colleague_decision.is_err(),
        "a second organization member who is no agent and holds the same grant is no longer \
         refused by the installation ceiling, so `mandate_authz::evaluate::Ceiling` has stopped \
         keying on organization alone. If it now carries `agent_id`, the corpus scenario \
         `autonomous-ceiling` is expressible in this crate for the first time and its deferral to \
         `story:agent-authority-kernel` in `contracts/obligations/authz.json` should be re-read. \
         Colleague got: {colleague_decision:?}"
    );
}

/// RED. The clause `the required PDP/graph/credential authority is unavailable` publishes
/// three authorities and names two tests, both of which take down the same one.
///
/// `check_contract::a_decision_point_that_cannot_answer_denies_and_invents_no_permission`
/// (`crates/mandate-authz/tests/check_contract.rs:249`) passes an empty
/// `mandate_policy::double::PolicyDouble`, and
/// `evaluate::a_policy_decision_point_that_cannot_answer_denies_a_request_the_graph_allows`
/// (`crates/mandate-authz/tests/evaluate.rs:365`) does the same — both are PDP outages, and
/// the second says so in its own name.
///
/// The **graph** half is reachable and produces the declared reason by a different route:
/// `mandate_graph::double::GraphDouble` refuses a read below the required revision as
/// `GraphError::CouldNotAnswer(Unanswered::NotCaughtUp)`, which
/// `crates/mandate-authz/src/evaluate.rs:273` folds in as
/// [`DenialReason::Unavailable`] — a path neither named row touches, and which the one test
/// that does reach it,
/// `evaluate::only_a_covering_grant_and_a_policy_allow_inside_every_ceiling_is_an_allow`
/// (`crates/mandate-authz/tests/evaluate.rs:663`), asserts nothing about beyond
/// `allowed() == false`.
///
/// This case drives the graph half end to end through [`mandate_authz::check`] and then
/// asserts the clause names a row beyond the two PDP outages. It is red because it does not.
#[test]
fn the_unavailable_clause_publishes_a_graph_outage_and_names_only_pdp_outages() {
    let refusal = check_for(agent(), &AuthzRevision::new("never-issued"), &[platform()])
        .expect_err("a graph that has not caught up to the required revision denies");

    assert!(!refusal.decision.allowed);
    assert_eq!(
        refusal.reason,
        DenialReason::Unavailable,
        "an unavailable graph is the declared reason of the same clause, reached through \
         evaluate.rs:273 and not through the policy port"
    );

    let pdp_outages = [
        "mandate-authz::check_contract::a_decision_point_that_cannot_answer_denies_and_invents_no_permission",
        "mandate-authz::evaluate::a_policy_decision_point_that_cannot_answer_denies_a_request_the_graph_allows",
    ];
    // Amended by the coordinator to ruling F3 (`review-result:wave-d-obligations-authz-adversary-1`).
    // The finding was upheld and the document moved: the one clause that published three
    // authorities on two rows both taking the policy port down is now three clauses. The graph
    // half is decidable — this case drove it to `DenialReason::Unavailable` through
    // `evaluate.rs:273` above — and is bound; the credential half is decided by nothing and
    // defers to `decision-blocker:guards`. Each `clause_rows` call is an assertion: the helper
    // panics if the document states no such clause, so re-merging the three fells this case.
    for authority in [
        "the required PDP",
        "graph",
        "credential authority is unavailable",
    ] {
        assert!(
            clause_exists(authority),
            "the document states no clause {authority:?}. The three authorities the declared \
             cause publishes were one clause carrying two rows that both took the policy port \
             down; ruling F3 split them so the graph half could be bound and the credential half \
             could be seen to be decided by nothing."
        );
    }

    let graph_rows = clause_rows("graph");

    assert!(
        !graph_rows.is_empty(),
        "the clause \"graph\" was found and no row was read from it, so this file's reader is \
         wrong and nothing below it is a finding"
    );

    assert!(
        graph_rows
            .iter()
            .any(|id| !pdp_outages.contains(&id.as_str())),
        "the clause \"graph\" names only the policy-port outages {pdp_outages:?}. The graph \
         outage this case just drove reaches `DenialReason::Unavailable` through \
         `evaluate.rs:273`, a different arm from the policy port's, and a row that takes the \
         policy port down is not evidence that the graph half is decided. Rows read: \
         {graph_rows:?}"
    );
}
