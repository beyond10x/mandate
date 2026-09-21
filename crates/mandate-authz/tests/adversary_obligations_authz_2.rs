//! Adversary pass 2 on `story:obligations-authz`: the fifteen-clause
//! `contracts/obligations/authz.json` as correction 1 left it, driven against the crate the
//! same unit documents.
//!
//! Pass 1 attacked two clauses that published four and three conditions on rows deciding one
//! of them. Correction 1 split both. This pass reads what the splits left: three of the
//! fifteen clauses are examined as the specification they now claim to be, each case driving
//! the deciding function the clause's own row names, and a fourth case measures whether a row
//! the correction added decides the condition its name states.
//!
//! The document is read by hand rather than with `serde_json`: `mandate-authz` declares no
//! `[dev-dependencies]` (`crates/mandate-authz/Cargo.toml:12-17`) and an adversary pass may
//! not add one. Each reader asserts it found what it was looking for, so a parse that misses
//! is loud and is not mistaken for a finding.
//!
//! Every source file these cases measure is byte-identical to the unit's base commit
//! `a2a55c3` (`crates/mandate-authz/src/context.rs`, `crates/mandate-model/src/graph.rs`,
//! `crates/mandate-authz/tests/context.rs`). What this unit's diff changed is the document:
//! which conditions it publishes, and which rows it counts as deciding them.

use std::fs;
use std::path::{Path, PathBuf};

use mandate_authz::context::{Binding, Bound, bind};
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
    ResourceType, SpaceId, Timestamp, Uuid, VerifiedContext,
};

// ---------------------------------------------------------------------------------------
// The world every case is driven in. The same shape as `crates/mandate-authz/tests/context.rs`,
// so a refusal here is comparable with the rows the document names out of that file.
// ---------------------------------------------------------------------------------------

fn uuid(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(1))
}

fn principal() -> PrincipalId {
    PrincipalId::new(uuid(2))
}

fn resource() -> ResourceRef {
    ResourceRef {
        resource_type: ResourceType::new("document"),
        resource_id: ResourceId::new(uuid(10)),
    }
}

fn space() -> SpaceId {
    SpaceId::new(uuid(20))
}

fn audience() -> Audience {
    Audience::new("mandate")
}

/// The verified context, with the credential it was validated from as a parameter: the one
/// field `an_organization_that_admits_no_authority_refuses_the_context` holds fixed and the
/// clause it is named by is about.
fn context_from(credential: u8) -> VerifiedContext {
    VerifiedContext {
        subject: principal(),
        actor: None,
        organization: organization(),
        audience: audience(),
        credential: CredentialId::new(uuid(credential)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("correlation"),
    }
}

fn context() -> VerifiedContext {
    context_from(7)
}

/// An organization that admits authority, with the context's subject a member of it.
fn tenancy() -> Tenancy {
    let mut tenancy = Tenancy::new();
    tenancy
        .create_organization(&context(), organization(), "acme")
        .expect("the organization is recorded");
    tenancy
        .add_organization_membership(
            &context(),
            MembershipAuthority::VerifiedOrganization,
            OrganizationMembershipId::new(uuid(3)),
            organization(),
            principal(),
        )
        .expect("the subject is a member");
    tenancy
}

/// The lookup half: the resource registered by the organization the context names, so
/// `ResourceLookup::placement` answers and the space branch below it is reached.
fn graph() -> GraphDouble {
    let mut graph = GraphDouble::new();
    graph
        .register_resource(&context(), &resource(), None)
        .expect("the resource is registered");
    graph
}

/// One `bind`, under `tenancy`, against `topology`, made under `scope`.
fn bind_under(
    tenancy: &Tenancy,
    topology: &Topology,
    context: &VerifiedContext,
    scope: Option<&AuthorityScope>,
) -> Result<Bound, DenialReason> {
    bind(
        tenancy,
        topology,
        &graph(),
        &Binding {
            context,
            resource: &resource(),
            expected_audience: &audience(),
            scope,
        },
    )
}

fn scope_naming(named: Option<SpaceId>) -> AuthorityScope {
    AuthorityScope {
        actions: vec![Action::new("deployment.restart")],
        resources: vec![resource()],
        space: named,
    }
}

// ---------------------------------------------------------------------------------------
// Reading the documents.
// ---------------------------------------------------------------------------------------

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(relative: &str) -> String {
    let path = repository().join(relative);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("{relative} is readable: {error}"))
}

/// The slice of `contracts/obligations/authz.json` that one clause of
/// `mandate.authorization.Check` owns: from its own `"clause"` key to the next one, or to
/// the `no_state_change` or `cases` key that ends the command's clause list.
///
/// `None` when the document states no such clause, which is a finding being fixed rather
/// than this reader being wrong — each caller says so at its own gate.
fn clause_segment(clause: &str) -> Option<String> {
    let text = read("contracts/obligations/authz.json");
    let needle = format!("\"clause\": \"{clause}\"");
    let start = text.find(&needle)?;
    let rest = &text[start + needle.len()..];
    let end = ["\"clause\":", "\"no_state_change\":", "\"cases\":"]
        .iter()
        .filter_map(|marker| rest.find(marker))
        .min()
        .unwrap_or(rest.len());
    Some(rest[..end].to_owned())
}

/// Every `id` a clause names, in document order.
fn clause_rows(clause: &str) -> Vec<String> {
    let Some(segment) = clause_segment(clause) else {
        return Vec::new();
    };
    let marker = "\"id\": \"";
    segment
        .match_indices(marker)
        .map(|(at, _)| {
            let tail = &segment[at + marker.len()..];
            let close = tail.find('"').expect("an id is a closed string");
            tail[..close].to_owned()
        })
        .collect()
}

/// The declared identity field of one entity of `generated/ir/system.json`.
///
/// Hand-rolled for the reason the module header gives. The entity key is matched in its
/// object-key form, `"<name>": {`, so that neither the `elements` list that names the entity
/// nor the sibling entities whose names extend it — `…AgentCapabilityCeiling.State`,
/// `…AgentCapabilityCeilingSuperseded` — can be read instead.
fn declared_identity(entity: &str) -> String {
    let text = read("generated/ir/system.json");
    let key = format!("\"{entity}\": {{");
    let at = text
        .find(&key)
        .unwrap_or_else(|| panic!("the IR declares the entity {entity}"));
    let rest = &text[at + key.len()..];
    let identity = rest
        .find("\"identity\"")
        .unwrap_or_else(|| panic!("{entity} declares an identity"));
    let marker = "\"name\": \"";
    let name_at = rest[identity..]
        .find(marker)
        .unwrap_or_else(|| panic!("{entity}'s identity is named"));
    let tail = &rest[identity + name_at + marker.len()..];
    let close = tail.find('"').expect("a name is a closed string");
    tail[..close].to_owned()
}

// ---------------------------------------------------------------------------------------
// The cases.
// ---------------------------------------------------------------------------------------

/// RED. The clause `space binding mismatches` is counted `real_covered` on two rows, and no
/// input reaches the branch either of them claims to decide: every request whose scope names
/// a space is refused, whatever the tenancy, the space and the resource are.
///
/// `mandate.graph.Resource.space_id` has no writer. `crates/mandate-model/src/graph.rs:250`
/// is the one place a `Resource` is constructed and it writes `space_id: None` as a literal,
/// because — the module says so at `:35-42` — "no command in `systems/mandate` carries a
/// space into it". So `crates/mandate-authz/src/context.rs:135-137` reads `None` for every
/// resource that has ever been folded, and `:138`'s `recorded != Some(named)` is true for
/// every `named`.
///
/// Two mutants follow, and the document counts the rows that both survive:
///
/// * delete the `resolve_space` guard at `context.rs:126-128` — the row
///   `context::a_scope_naming_a_space_the_organization_does_not_hold_is_a_tenant_mismatch`
///   (`tests/context.rs:240`) stays green, because `:138` refuses with the same
///   `TenantMismatch` one branch later. The premise below measures exactly that: the world
///   where the organization holds the space and the world where it does not are
///   indistinguishable in `bind`'s whole observable output.
/// * replace `context.rs:135-140` with an unconditional `return Err(TenantMismatch)` — the
///   row `context::a_scope_naming_a_space_the_resource_is_not_bound_to_is_a_tenant_mismatch`
///   (`tests/context.rs:271`, added to the document by this unit) stays green, because that
///   is already the only thing those lines can do.
///
/// The case builds the most favourable world the crate's public API admits — the
/// organization holds the space, the resource is registered through `Topology::register`,
/// which is the only writer of the projection `bind` reads — and asserts it binds. It is red
/// because nothing binds.
#[test]
fn no_scope_naming_a_space_can_bind_so_the_space_clause_decides_nothing() {
    let context = context();

    // The control: the same request under a scope that names no space binds, so what the
    // worlds below change is the space and not the scope, the resource or the tenancy.
    let unscoped = bind_under(
        &tenancy(),
        &Topology::new(),
        &context,
        Some(&scope_naming(None)),
    )
    .expect("a scope naming no space binds");
    assert_eq!(unscoped.space, None);

    // The world `tests/context.rs:240` builds: the organization holds no such space.
    let not_held = bind_under(
        &tenancy(),
        &Topology::new(),
        &context,
        Some(&scope_naming(Some(space()))),
    );

    // The best case the public API admits: the organization holds the space, and the
    // resource is registered through `Topology::register` — `crates/mandate-model/src/graph.rs:311`,
    // the record half of the one declared command that writes a resource.
    let mut held_tenancy = tenancy();
    held_tenancy
        .create_space(&context, space(), "engineering")
        .expect("the space is recorded");
    let mut topology = Topology::new();
    topology
        .register(&held_tenancy, &context, &resource(), None)
        .expect("the resource is recorded");
    let held = bind_under(
        &held_tenancy,
        &topology,
        &context,
        Some(&scope_naming(Some(space()))),
    );

    // Premise, and the first mutant in one line: holding the space changes nothing a caller
    // can observe, so no case can tell whether `context.rs:126` or `context.rs:138` refused.
    assert_eq!(
        held, not_held,
        "a space the organization holds and a space it does not hold are one refusal, so the \
         `resolve_space` guard the clause's first row names is not what decides it"
    );

    // Pinned by the coordinator to ruling F1 (`review-result:wave-d-obligations-authz-adversary-2`).
    // The finding was upheld and the document moved: `"space binding mismatches"` lost both rows
    // and now defers to `story:declared-writers`, the live owner of a declared element no code
    // writes. No edit to the contract could have turned this assertion green, because what it
    // measures is a fact about `crates/mandate-model/src/graph.rs` — `Topology::apply` writes
    // `space_id: None` as a literal and is the only constructor of a `Resource`, so no reachable
    // world binds a scope that names a space and `context.rs:138` refuses every scoped request.
    //
    // The case now asserts that shipped fact. It fells the day a resource can carry a space, which
    // is the day the clause becomes bindable and its deferral should be re-read.
    assert!(
        held.is_err(),
        "a scope naming a space now binds, so `crates/mandate-model/src/graph.rs:250` has stopped \
         writing `space_id: None` as a literal and a `Resource` can carry a space. The clause \
         \"space binding mismatches\" is deferred to `story:declared-writers` on the ground that \
         nothing writes that field; re-read the deferral. Original finding, still true of the \
         evidence the clause used to carry: it was counted `real_covered` on two rows that assert \
         a refusal no input can avoid, while `tests/context.rs:266-269` calls the same \
         condition \"the record of a contract gap that `story:event-payloads-for-folds` owns\" \
         — a covered obligation is not also a gap. Got: {held:?}"
    );
}

/// RED. The clause `Credential-derived context is invalid` is counted `real_covered` on one
/// row, and nothing this crate decides depends on the credential the context was validated
/// from.
///
/// `VerifiedContext::credential` (`crates/mandate-types/src/record.rs:77-78`) is read at no
/// point in `crates/mandate-authz/src`: the word occurs there thirteen times and every
/// occurrence is a doc comment. The row the clause names,
/// `context::an_organization_that_admits_no_authority_refuses_the_context`
/// (`crates/mandate-authz/tests/context.rs:134`), closes the organization
/// (`tests/context.rs:139-141`) and drives `Tenancy::admits`
/// (`crates/mandate-model/src/tenancy.rs:1196`, "whether the organization resolves and still
/// admits authority") — a fact about the tenancy projection's lifecycle state, decided from
/// `context.organization`, which is the same field the sibling clause `tenant` is bound
/// through `Tenancy::is_member`.
///
/// The three conditions the split put beside it — `revoked`, `expired`, `stale` — defer to
/// `decision-blocker:guards` on the stated ground that `VerifiedContext` carries no validity,
/// expiry or revocation field for a guard to read. It carries no validity field for `invalid`
/// either, and this case measures that: four contexts differing in nothing but `credential`,
/// against the world the row builds. It is red because `bind` answers all four alike.
#[test]
fn the_invalid_clause_is_bound_to_a_refusal_no_value_of_the_credential_changes() {
    let rows = clause_rows("Credential-derived context is invalid");
    if rows.is_empty() {
        // The clause carries no row: either it was deferred beside its three siblings, which
        // is the finding being fixed, or the document no longer states it, which pass 1's
        // `the_credential_clause_publishes_four_conditions…` already refuses. Nothing to
        // measure here either way.
        return;
    }
    assert_eq!(
        rows,
        vec![
            "mandate-authz::context::an_organization_that_admits_no_authority_refuses_the_context"
        ],
        "this case measures the row the clause names; it changed, so read it before the \
         assertion below"
    );

    // Premise: the refusal tracks the tenancy. One credential, two organizations.
    let open = bind_under(&tenancy(), &Topology::new(), &context(), None)
        .expect("an organization that admits authority binds");
    assert_eq!(open.organization, organization());

    let mut closed = tenancy();
    closed
        .close_organization(&context(), organization())
        .expect("the organization is closed");
    assert_eq!(
        bind_under(&closed, &Topology::new(), &context(), None),
        Err(DenialReason::InvalidCredential),
        "the row's world: a closed organization, refused as `InvalidCredential`"
    );

    // The measurement: four credentials, one closed organization, nothing else varied.
    let outcomes: Vec<Result<Bound, DenialReason>> = [0_u8, 7, 128, 255]
        .into_iter()
        .map(|credential| bind_under(&closed, &Topology::new(), &context_from(credential), None))
        .collect();

    assert!(
        outcomes.windows(2).any(|pair| pair[0] != pair[1]),
        "no value of `VerifiedContext::credential` changes what `bind` decides — all four \
         gave {:?}. The clause \"Credential-derived context is invalid\" is published as \
         decided on the real path by a row whose refusal is a function of \
         `Tenancy::admits(context.organization)` alone. `revoked`, `expired` and `stale` were \
         deferred to `decision-blocker:guards` because `VerifiedContext` carries no field for \
         a guard to read; it carries none for `invalid` either, so the fourth condition of the \
         same slash-list is counted `real_covered` on the same evidence the other three were \
         deferred for.",
        outcomes[0]
    );
}

/// RED. The unit's own evidence file states a fact about `generated/ir/system.json` that
/// `generated/ir/system.json` contradicts.
///
/// `crates/mandate-authz/tests/obligations.rs:15-16` reads
/// "`mandate.delegation.AgentCapabilityCeiling` is identified by `agent_id` in
/// `generated/ir/system.json`", and that sentence is the whole of the argument the file gives
/// for deferring the `autonomous-ceiling` corpus case to `story:agent-authority-kernel`. The
/// IR declares that entity's identity as `id`, of type
/// `mandate.core.AgentCapabilityCeilingId` (`generated/ir/system.json:3128-3135`); `agent_id`
/// is its first *field* (`:3138`), which is what pass 1 wrote and what the argument needs.
///
/// The gate below is the fix: correct the sentence and this case goes green without anything
/// else moving. It is red while the sentence stands.
#[test]
fn the_agent_ceiling_identity_the_unit_cites_is_not_the_one_the_ir_declares() {
    let claim = "`mandate.delegation.AgentCapabilityCeiling` is identified by `agent_id`";
    let evidence = read("crates/mandate-authz/tests/obligations.rs");
    if !evidence.contains(claim) {
        // The sentence is gone or reworded: nothing to check against the IR.
        return;
    }

    let identity = declared_identity("mandate.delegation.AgentCapabilityCeiling");

    assert_eq!(
        identity, "agent_id",
        "`crates/mandate-authz/tests/obligations.rs:15` states that \
         `mandate.delegation.AgentCapabilityCeiling` is identified by `agent_id`, and the IR \
         it cites declares the identity as {identity:?} with `agent_id` as the first field. A \
         re-pointing's citation has to contain the statement it is cited for; this one states \
         the opposite of it, in the file the unit added as the evidence for deferring \
         `autonomous-ceiling`."
    );
}

// ---------------------------------------------------------------------------------------
// The `check`-level world, for the row this unit added to `ceilings deny`. It is the world
// `crates/mandate-authz/tests/obligations.rs:172-213` builds, with the one field under test
// as a parameter.
// ---------------------------------------------------------------------------------------

fn action_checked() -> Action {
    Action::new("deployment.restart")
}

fn subject() -> AuthoritySubject {
    AuthoritySubject::Principal(principal())
}

/// The grant, the catalog and the policy all carry the action, so nothing but a ceiling can
/// refuse.
fn granting_graph() -> (GraphDouble, AuthzRevision) {
    let mut graph = GraphDouble::new();
    graph.admit_subject(organization(), subject());
    graph
        .register_resource(&context(), &resource(), None)
        .expect("the resource is registered");
    let revision = graph.record_grant(Grant::recorded(
        GrantId::new(uuid(30)),
        organization(),
        subject(),
        AuthorityScope {
            actions: vec![action_checked()],
            resources: vec![resource()],
            space: None,
        },
        "operator",
    ));
    (graph, revision)
}

fn allowing_policy() -> PolicyDouble {
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
    policy.record_role(organization(), "operator", vec![action_checked()]);
    policy.allow(organization(), subject(), action_checked(), resource());
    policy
}

/// A ceiling that admits the action, recorded for nobody.
fn permissive() -> Ceiling {
    Ceiling {
        organization: None,
        allowed_actions: vec![ActionPattern::new("deployment.*")],
        denied_actions: Vec::new(),
    }
}

/// The refusing ceiling of `tests/obligations.rs:164-170`, with the field its test's name is
/// about — the organization it is recorded for — as a parameter.
fn refusing(recorded_for: Option<OrganizationId>) -> Ceiling {
    Ceiling {
        organization: recorded_for,
        allowed_actions: vec![ActionPattern::new("deployment.*")],
        denied_actions: vec![ActionPattern::new("deployment.restart")],
    }
}

fn check_under(ceilings: &[Ceiling]) -> Result<Decision, Denied> {
    let (graph, revision) = granting_graph();
    let policy = allowing_policy();
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
            context: &context(),
            action: &action_checked(),
            resource: &resource(),
            expected_audience: &audience(),
            relation: "operator",
            minimum: &revision,
            attributes: &AttributeSet::new(),
            scope: None,
            ceilings,
        },
    )
}

/// RED. The row this unit added to the clause `ceilings deny` does not decide the condition
/// its own name states, and the clause was already covered without it.
///
/// `obligations::a_ceiling_recorded_for_the_organization_refuses_an_action_the_grant_carries`
/// builds one refusing ceiling with `organization: Some(organization())` and asserts a
/// refusal. `Ceiling::applies` (`crates/mandate-authz/src/evaluate.rs:86-90`) is the only
/// reader of that field, and a ceiling recorded for nobody applies to every organization —
/// so the same world with `organization: None` refuses identically, and the row's evidence
/// is the same whether or not the ceiling was recorded for the organization its name says.
///
/// The clause's other row,
/// `evaluate::a_ceiling_that_does_not_admit_the_action_refuses_an_otherwise_allowed_request`,
/// already covered `ceilings deny` on the real path; and the world the new row builds —
/// permissive platform ceiling plus refusing tenant ceiling over `deployment.restart`, with
/// the platform-only control — is the world `evaluate::every_applicable_ceiling_intersects`
/// (`crates/mandate-authz/tests/evaluate.rs:431-451`) already builds, one entry point down
/// and with the foreign-organization ceiling that discriminates `applies` left out. That
/// test, not this row, is what decides which ceilings apply, and no row of the document
/// names it.
///
/// This case asserts the field is load-bearing. It is red because it is not.
#[test]
fn the_organization_the_new_ceiling_row_records_its_ceiling_for_decides_nothing() {
    let allowed = check_under(&[permissive()]).expect("a ceiling admitting the action allows");
    assert!(allowed.allowed);

    let recorded_for_the_organization =
        check_under(&[permissive(), refusing(Some(organization()))]);
    let recorded_for_nobody = check_under(&[permissive(), refusing(None)]);

    // Premise: both refuse, so the row's assertions hold of either ceiling.
    assert!(recorded_for_the_organization.is_err() && recorded_for_nobody.is_err());

    // Pinned by the coordinator to ruling F4 (`review-result:wave-d-obligations-authz-adversary-2`).
    // The finding was upheld and the correction took the fix that adds evidence: the row's case now
    // runs the foreign-organization ceiling of `crates/mandate-authz/tests/evaluate.rs:447-451` at
    // the `check` entry point, which `evaluate.rs` does not exercise, and two mutations fell it —
    // forcing `Ceiling::applies` true, and moving the ceiling to another organization. So the
    // `organization` field does decide.
    //
    // This particular pair stays **equal**, and honestly so: `Ceiling::applies` is `is_none_or`,
    // and `systems/mandate/domains/delegation.yaml:5` says "organization_id absent means a platform
    // ceiling", which applies to every organization by contract. A ceiling recorded for nobody and
    // one recorded for this organization therefore both bound this request, and no `src` change
    // could separate them without contradicting the declared model. The assertion is inverted to
    // record that, rather than deleted — the original finding was right that this pair proves
    // nothing, and the evidence for the row is the other two mutations.
    assert_eq!(
        recorded_for_the_organization, recorded_for_nobody,
        "a ceiling recorded for no organization and one recorded for this organization now differ. \
         `Ceiling::applies` is `is_none_or` and `systems/mandate/domains/delegation.yaml:5` makes an \
         absent `organization_id` a platform ceiling that applies to every organization, so these \
         two bounded this request identically. If that has changed, the declared model and \
         `crates/mandate-authz/src/evaluate.rs` have parted company. Got: \
         {recorded_for_the_organization:?} and {recorded_for_nobody:?}"
    );
}
