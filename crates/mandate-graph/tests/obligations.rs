//! The clauses of this crate's commands that `contracts/obligations/graph.json` binds here.
//!
//! One case per clause the shipped path decides, naming the declared reason and the
//! discriminator `mandate.graph.Denied` carries, plus one `no-state-change` case per
//! command. The registry is the reader: every id below is named by a row of
//! `contracts/obligations/graph.json`, and `cargo xtask obligations-registry` refuses a row
//! whose test no binary lists and runs.
//!
//! What "real" means for this crate is narrow, and after
//! `review-result:wave-d-obligations-graph-adversary-2` **no** row of
//! `contracts/obligations/graph.json` states it. `graph.yaml`'s commands are realized by
//! ports (`crates/mandate-graph/src/lib.rs:70-84`), and the only implementation of those
//! ports in the workspace is [`mandate_graph::double::GraphDouble`] — so a refusal the
//! double's own code makes is a `double` row deferred to `story:graph-policy-adapter`, not
//! evidence about an adapter nobody has written.
//! [`mandate_graph::relationship::admit`] decides one thing of its own, the relation name
//! (`crates/mandate-graph/src/relationship.rs:112-114`); after that it propagates
//! `lookup.placement(organization, write.resource)?` (`:117`) and
//! `admission.admits(organization, write.subject)?` (`:118`), and
//! [`GraphDouble`] is the only implementor of either port. So the write's resource tenancy
//! and its tenant membership are `double` rows too.
//!
//! Four cases here are named by **no** row, and say so in their own doc comment.
//!
//! [`require_revision_refuses_a_view_that_has_not_applied_the_minimum`] and
//! [`require_revision_refuses_a_view_that_never_issued_the_revision_named`] were rows
//! for the two revocation commands' clause "required graph revocation visibility cannot be
//! satisfied" until `review-result:wave-d-obligations-graph-adversary-1` F1 and F2 withdrew
//! them: neither `RevocationWriter::remove_relation` nor `RevocationWriter::revoke_grant`
//! takes a minimum revision or consults a [`RevisionView`], so calling the free function
//! decides nothing about either command. They are kept as what they always were — tests of
//! the free function — because [`Reader`] is this crate's only [`RevisionView`] that is not
//! [`GraphDouble`], so they are the only evidence that the rule reads the trait rather than
//! the double's own list of issued revisions.
//!
//! [`declared_name_refuses_a_relation_name_that_is_blank`] and
//! [`declared_name_refuses_a_relation_name_that_differs_from_its_trim`] were the rows for
//! `mandate.graph.WriteRelationship`'s clause "the relationship is not admitted by the
//! authorization model" until `review-result:wave-d-obligations-graph-adversary-2` F2
//! withdrew them, on `crates/mandate-graph/src/relationship.rs:10`, which says of that
//! refusal that it "is `mandate-policy`'s". They are kept for the same reason: the name rule
//! is the one decision `admit` makes itself, and no clause of this command's declared cause
//! publishes it.

use mandate_graph::double::GraphDouble;
use mandate_graph::port::{GraphError, MutationOutcome, Unanswered};
use mandate_graph::record::{Grant, GrantState, RelationState};
use mandate_graph::relationship::{
    RelationshipWrite, RelationshipWriter, SubjectAdmission, admit, declared_name,
};
use mandate_graph::revocation::{RevisionView, RevocationWriter, require_revision};
use mandate_graph::topology::{ResourceLookup, ResourceRegistry};
use mandate_types::{
    Action, Audience, AuthorityScope, AuthoritySubject, AuthzRevision, CorrelationId, CredentialId,
    DenialReason, GrantId, OrganizationId, PrincipalId, ResourceId, ResourceRef, ResourceType,
    Uuid, VerifiedContext,
};

fn uuid(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(1))
}

fn other_organization() -> OrganizationId {
    OrganizationId::new(uuid(9))
}

fn subject() -> AuthoritySubject {
    AuthoritySubject::Principal(PrincipalId::new(uuid(2)))
}

fn resource(byte: u8) -> ResourceRef {
    ResourceRef {
        resource_type: ResourceType::new("document"),
        resource_id: ResourceId::new(uuid(byte)),
    }
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

fn elsewhere() -> VerifiedContext {
    VerifiedContext {
        organization: other_organization(),
        ..context()
    }
}

/// A parent resource `10`, a child `11` under it, and the subject admitted.
fn seeded() -> GraphDouble {
    let mut graph = GraphDouble::new();
    let context = context();

    graph.admit_subject(organization(), subject());
    graph
        .register_resource(&context, &resource(10), None)
        .expect("the parent registers");
    graph
        .register_resource(&context, &resource(11), Some(&ResourceId::new(uuid(10))))
        .expect("the child registers under it");

    graph
}

/// A grant of `role` over the parent resource.
fn grant(role: &str) -> Grant {
    Grant::recorded(
        GrantId::new(uuid(6)),
        organization(),
        subject(),
        AuthorityScope {
            actions: vec![Action::new("read")],
            resources: vec![resource(10)],
            space: None,
        },
        role,
    )
}

/// A reader written outside the crate: it has applied exactly the revisions it names.
///
/// The decision under test is [`require_revision`]'s; this supplies the one fact it reads,
/// the way an adapter's own consistency token would.
struct Reader {
    applied: Vec<AuthzRevision>,
}

impl RevisionView for Reader {
    fn caught_up_to(&self, minimum: &AuthzRevision) -> bool {
        self.applied.contains(minimum)
    }

    fn observed(&self) -> AuthzRevision {
        self.applied
            .last()
            .cloned()
            .unwrap_or_else(|| AuthzRevision::new("0"))
    }
}

fn write<'a>(
    context: &'a VerifiedContext,
    subject: &'a AuthoritySubject,
    resource: &'a ResourceRef,
    relation: &'a str,
) -> RelationshipWrite<'a> {
    RelationshipWrite {
        context,
        subject,
        resource,
        relation,
    }
}

/// [`require_revision`] alone: a view that has not applied the minimum is refused.
///
/// **Named by no row of `contracts/obligations/graph.json`** — see the module doc. This is
/// the free function's own rule, read against a [`RevisionView`] written outside the crate,
/// and it is a claim about no command: it is refused before any authority is looked at and
/// told as an absence of knowledge, never as a decision about the caller.
#[test]
fn require_revision_refuses_a_view_that_has_not_applied_the_minimum() {
    let reader = Reader {
        applied: vec![AuthzRevision::new("0"), AuthzRevision::new("1")],
    };

    let refusal = require_revision(&reader, &AuthzRevision::new("2"))
        .expect_err("the reader has not applied the revision it was asked for");

    assert_eq!(refusal, GraphError::CouldNotAnswer(Unanswered::NotCaughtUp));
    assert_eq!(refusal.denial_reason(), DenialReason::Unavailable);
    assert!(refusal.is_could_not_answer());
    assert!(!refusal.is_denial());

    // The same reader, asked for a revision it has applied, answers with the revision it
    // actually reached: the refusal above is the visibility rule and not a constant.
    assert_eq!(
        require_revision(&reader, &AuthzRevision::new("1")).expect("the reader applied it"),
        AuthzRevision::new("1")
    );
}

/// [`require_revision`] alone: a view asked for a revision it never issued is refused.
///
/// **Named by no row of `contracts/obligations/graph.json`** — see the module doc. The same
/// rule as the case above, against a view holding a different set of applied revisions, so
/// the refusal is the comparison and not the shape of the fixture.
#[test]
fn require_revision_refuses_a_view_that_never_issued_the_revision_named() {
    let reader = Reader {
        applied: vec![AuthzRevision::new("0")],
    };

    let refusal = require_revision(&reader, &AuthzRevision::new("never-issued"))
        .expect_err("the reader never issued the revision it was asked for");

    assert_eq!(refusal, GraphError::CouldNotAnswer(Unanswered::NotCaughtUp));
    assert_eq!(refusal.denial_reason(), DenialReason::Unavailable);
    assert!(refusal.is_could_not_answer());
    assert!(!refusal.is_denial());

    assert_eq!(
        require_revision(&reader, &AuthzRevision::new("0")).expect("the reader applied it"),
        AuthzRevision::new("0")
    );
}

/// `mandate.graph.RemoveRelation`: the refusal moves nothing.
///
/// Driven through the command itself, under a condition the shipped writer actually refuses
/// on: the caller is verified in another organization, so
/// [`RevocationWriter::remove_relation`] answers `TenantMismatch` before it touches the
/// relation. The assertion is on the **whole fold** — [`GraphDouble`] is `PartialEq`, so
/// `graph == before` is every projection and the issued-revision list at once, not the one
/// field this case happened to look at afterwards.
///
/// A `double` row: the refusal is the double's own code, the only implementation of
/// [`RevocationWriter`] in the workspace, so the command's `blocked_on` defers to
/// `story:graph-policy-adapter`, which owns the adapter this would be evidence about.
#[test]
fn a_relation_removal_refused_for_tenancy_removes_nothing_and_issues_no_revision() {
    let mut graph = seeded();
    let context = context();
    let subject = subject();
    let parent = resource(10);
    let written = graph
        .write_relationship(&write(&context, &subject, &parent, "viewer"))
        .expect("the relationship writes");
    let before = graph.clone();

    let refusal = graph
        .remove_relation(&elsewhere(), &written.relation.id)
        .expect_err("the caller is verified in another organization");

    assert_eq!(refusal, GraphError::Denied(DenialReason::TenantMismatch));
    assert!(refusal.is_denial());
    assert_eq!(graph, before);
    assert_eq!(graph.observed(), written.revision);
    assert_eq!(graph.relations().len(), 1);
    assert_eq!(graph.relations()[0].state, RelationState::Active);
}

/// `mandate.graph.RevokeGrant`: the refusal moves nothing.
///
/// The same rule for the other revocation command, driven through the command and asserted
/// on the whole fold. A `double` row for the same reason.
#[test]
fn a_grant_revocation_refused_for_tenancy_revokes_nothing_and_issues_no_revision() {
    let mut graph = seeded();
    let recorded = graph.record_grant(grant("editor"));
    let before = graph.clone();

    let refusal = graph
        .revoke_grant(&elsewhere(), &GrantId::new(uuid(6)))
        .expect_err("the caller is verified in another organization");

    assert_eq!(refusal, GraphError::Denied(DenialReason::TenantMismatch));
    assert!(refusal.is_denial());
    assert_eq!(graph, before);
    assert_eq!(graph.observed(), recorded);
    assert_eq!(graph.grants().len(), 1);
    assert_eq!(graph.grants()[0].state, GrantState::Active);
}

/// `mandate.graph.WriteRelationship`: the refusal moves nothing.
///
/// The admission rule refuses a relation name that is not the name it prints as, and the
/// port runs that rule before it records anything, so nothing is recorded and the fold
/// issues no revision.
///
/// A `double` row, like its four siblings: what this case measures is an **ordering**, and
/// the ordering is [`GraphDouble::write_relationship`]'s — `admit` is called from inside it
/// (`crates/mandate-graph/src/double.rs:363-367`) and only the double's own code decides
/// whether the relation is pushed before or after that `?`. Move the push above the call
/// and this case goes red while `admit` is untouched
/// (`review-result:wave-d-obligations-graph-adversary-2` F3). The command's `blocked_on`
/// therefore defers to `story:graph-policy-adapter`, which owns the writer this would be
/// evidence about.
#[test]
fn a_relationship_write_refused_at_admission_records_no_relation_and_issues_no_revision() {
    let mut graph = seeded();
    let context = context();
    let subject = subject();
    let parent = resource(10);
    let before = graph.clone();
    let padded = write(&context, &subject, &parent, " viewer ");

    let decided = admit(&graph, &graph, &padded)
        .expect_err("the shipped admission rule refuses a name that is not its own trim");
    let refusal = graph
        .write_relationship(&padded)
        .expect_err("and the port that runs that rule first refuses the write");

    assert_eq!(decided, GraphError::Denied(DenialReason::Denied));
    assert_eq!(refusal, decided);
    assert_eq!(refusal.denial_reason(), DenialReason::Denied);
    assert!(refusal.is_denial());
    assert_eq!(graph, before);
    assert!(graph.relations().is_empty());
}

/// `mandate.graph.RegisterResource`: "belongs to another organization".
///
/// Driven through the command. The parent id resolves, under another tenant, and the
/// double's own registry answers `TenantMismatch` before anything is recorded — the second
/// half of the same check refuses a re-registration of a resource another tenant holds.
///
/// A `double` row: the refusal is the double's registry code, the only implementation of
/// [`ResourceRegistry`] in the workspace.
#[test]
fn a_registration_under_another_organizations_parent_is_a_tenant_mismatch() {
    let mut graph = GraphDouble::new();
    graph
        .register_resource(&elsewhere(), &resource(10), None)
        .expect("the other tenant registers the parent");
    let before = graph.clone();

    let refusal = graph
        .register_resource(&context(), &resource(11), Some(&ResourceId::new(uuid(10))))
        .expect_err("the parent belongs to another organization");

    assert_eq!(refusal, GraphError::Denied(DenialReason::TenantMismatch));
    assert_eq!(refusal.denial_reason(), DenialReason::TenantMismatch);
    assert!(refusal.is_denial());
    assert_eq!(graph, before);

    // The other half of the same check: the identity itself is another tenant's.
    assert_eq!(
        graph
            .register_resource(&context(), &resource(10), None)
            .expect_err("the resource belongs to another organization"),
        GraphError::Denied(DenialReason::TenantMismatch)
    );
    assert_eq!(graph, before);
}

/// `mandate.graph.DeregisterResource`: "the resource is outside the verified organization".
///
/// Decided by the double's own registry code, which is the only implementation of
/// [`ResourceRegistry`] there is — hence a `double` row, deferred to the story that ships
/// an adapter.
#[test]
fn a_deregistration_of_another_organizations_resource_is_a_tenant_mismatch() {
    let mut graph = GraphDouble::new();
    graph
        .register_resource(&elsewhere(), &resource(10), None)
        .expect("the other tenant registers it");

    let refusal = graph
        .deregister_resource(&context(), &ResourceId::new(uuid(10)))
        .expect_err("this tenant does not own it");

    assert_eq!(refusal, GraphError::Denied(DenialReason::TenantMismatch));
    assert_eq!(refusal.denial_reason(), DenialReason::TenantMismatch);
    assert!(refusal.is_denial());
    graph
        .placement(&other_organization(), &resource(10))
        .expect("and its owner's record still resolves");
}

/// `mandate.graph.RemoveRelation`: "relation/resource is outside the verified
/// organization".
///
/// Decided by the double's own revocation code, the only implementation of
/// [`RevocationWriter`] there is.
#[test]
fn a_relation_removal_in_another_organization_is_a_tenant_mismatch() {
    let mut graph = seeded();
    let context = context();
    let subject = subject();
    let parent = resource(10);
    let written = graph
        .write_relationship(&write(&context, &subject, &parent, "viewer"))
        .expect("the relationship writes");

    let refusal = graph
        .remove_relation(&elsewhere(), &written.relation.id)
        .expect_err("another tenant's relation");

    assert_eq!(refusal, GraphError::Denied(DenialReason::TenantMismatch));
    assert!(refusal.is_denial());
    assert_eq!(graph.relations()[0].state, RelationState::Active);
    assert_eq!(
        graph
            .remove_relation(&context, &written.relation.id)
            .expect("its own organization removes it")
            .outcome,
        MutationOutcome::Recorded
    );
}

/// `mandate.graph.RegisterResource`: the refusal moves nothing.
///
/// A parent that does not resolve is refused by the double's registry, and the resource it
/// was asked for is not recorded: the fold is exactly what it was.
#[test]
fn a_refused_registration_records_no_resource_and_issues_no_revision() {
    let mut graph = GraphDouble::new();
    let before = graph.clone();

    let refusal = graph
        .register_resource(&context(), &resource(11), Some(&ResourceId::new(uuid(10))))
        .expect_err("no such parent");

    assert_eq!(refusal, GraphError::Denied(DenialReason::Denied));
    assert_eq!(graph, before);
    assert_eq!(graph.observed(), before.observed());
    assert_eq!(
        graph
            .placement(&organization(), &resource(11))
            .expect_err("nothing was recorded"),
        GraphError::CouldNotAnswer(Unanswered::ResourceUnresolved)
    );
}

/// `mandate.graph.DeregisterResource`: the refusal moves nothing.
///
/// A resource a child still resolves through is refused, and it keeps resolving: a refused
/// deregistration is not a half-applied one.
#[test]
fn a_refused_deregistration_leaves_the_record_resolving_and_issues_no_revision() {
    let mut graph = seeded();
    let before = graph.clone();

    let refusal = graph
        .deregister_resource(&context(), &ResourceId::new(uuid(10)))
        .expect_err("a child still resolves through it");

    assert_eq!(refusal, GraphError::Denied(DenialReason::Denied));
    assert_eq!(graph, before);
    assert_eq!(graph.observed(), before.observed());
    graph
        .placement(&organization(), &resource(10))
        .expect("the parent still resolves");
}

/// `mandate.graph.WriteRelationship`: "resource tenancy mismatches".
///
/// A `double` row. [`admit`] compares no organization: it reads
/// `lookup.placement(organization, write.resource)?`
/// (`crates/mandate-graph/src/relationship.rs:117`) and propagates whatever the
/// [`ResourceLookup`] implementor answered, and [`GraphDouble`] is the only implementor of
/// that port in the workspace (`crates/mandate-graph/src/double.rs:208-233`). The row named
/// a case driving `Tree`, a stub declared inside `crates/mandate-graph/tests/relationship.rs`,
/// whose own comparison produced the denial; this case drives the double the row now names
/// (`review-result:wave-d-obligations-graph-adversary-2` F1) — as the lookup directly, and
/// through the command, which calls [`admit`] with itself in both positions.
#[test]
fn a_relationship_write_on_another_organizations_resource_is_a_tenant_mismatch() {
    let mut graph = GraphDouble::new();
    graph.admit_subject(organization(), subject());
    graph
        .register_resource(&elsewhere(), &resource(10), None)
        .expect("the other tenant registers the resource");
    let before = graph.clone();
    let context = context();
    let subject = subject();
    let held = resource(10);
    let attempt = write(&context, &subject, &held, "viewer");

    // The double as the ResourceLookup: the port whose answer this clause is.
    let looked_up = ResourceLookup::placement(&graph, &organization(), &held)
        .expect_err("the resource is held by another organization");
    let decided = admit(&graph, &graph, &attempt).expect_err("another tenant's resource");
    let refusal = graph
        .write_relationship(&attempt)
        .expect_err("and the command refuses the write");

    assert_eq!(looked_up, GraphError::Denied(DenialReason::TenantMismatch));
    assert_eq!(decided, looked_up);
    assert_eq!(refusal, looked_up);
    assert_eq!(refusal.denial_reason(), DenialReason::TenantMismatch);
    assert!(refusal.is_denial());
    assert_eq!(graph, before);
    assert!(graph.relations().is_empty());

    // The same relation, written by the organization that holds the resource, is recorded:
    // the refusal is the tenancy comparison and not the shape of the fixture.
    graph.admit_subject(other_organization(), subject.clone());
    assert_eq!(
        graph
            .write_relationship(&write(&elsewhere(), &subject, &held, "viewer"))
            .expect("its own organization writes it")
            .outcome,
        MutationOutcome::Recorded
    );
}

/// `mandate.graph.WriteRelationship`: "outside tenant membership".
///
/// A `double` row. [`admit`] decides no membership: it propagates
/// `admission.admits(organization, write.subject)?`
/// (`crates/mandate-graph/src/relationship.rs:118`), and [`GraphDouble`] is the only
/// implementor of [`SubjectAdmission`] in the workspace outside a test binary
/// (`crates/mandate-graph/src/double.rs:345-360`). The row named a case driving `Members`,
/// a stub declared inside `crates/mandate-graph/tests/relationship.rs`, which answers a
/// discriminator no shipped code produces; this case drives the double the row now names
/// (`review-result:wave-d-obligations-graph-adversary-2` F4), and the double answers
/// `Denied(Denied)` — one answer for "never heard of it" and for "held under another
/// organization", so the port is no existence oracle for another tenant's subjects.
#[test]
fn a_relationship_write_for_a_subject_outside_tenant_membership_is_denied() {
    let mut graph = GraphDouble::new();
    let context = context();
    graph
        .register_resource(&context, &resource(10), None)
        .expect("the resource registers");
    let before = graph.clone();
    let subject = subject();
    let held = resource(10);
    let attempt = write(&context, &subject, &held, "viewer");

    // The double as the SubjectAdmission: this subject was never admitted anywhere.
    let admission = SubjectAdmission::admits(&graph, &organization(), &subject)
        .expect_err("a subject outside tenant membership");
    let decided = admit(&graph, &graph, &attempt).expect_err("a non-member subject");
    let refusal = graph
        .write_relationship(&attempt)
        .expect_err("and the command refuses the write");

    assert_eq!(admission, GraphError::Denied(DenialReason::Denied));
    assert_eq!(decided, admission);
    assert_eq!(refusal, admission);
    assert_eq!(refusal.denial_reason(), DenialReason::Denied);
    assert!(refusal.is_denial());
    assert_eq!(graph, before);
    assert!(graph.relations().is_empty());

    // Admitted into the organization, the same write is recorded: the refusal is the
    // membership comparison and not a constant.
    graph.admit_subject(organization(), subject.clone());
    assert_eq!(
        graph
            .write_relationship(&attempt)
            .expect("an admitted subject writes")
            .outcome,
        MutationOutcome::Recorded
    );
}

/// [`declared_name`] alone: a relation name that is blank is refused.
///
/// **Named by no row of `contracts/obligations/graph.json`** — see the module doc. It was a
/// row for `mandate.graph.WriteRelationship`'s clause "the relationship is not admitted by
/// the authorization model" until `review-result:wave-d-obligations-graph-adversary-2` F2
/// withdrew it: `crates/mandate-graph/src/relationship.rs:10` says of that refusal that it
/// "is `mandate-policy`'s", and this rule answers a different question — whether the relation
/// name names anything at all. It is the one decision [`admit`] makes itself, and the
/// declared cause of `mandate.graph.WriteRelationship` publishes **no clause for it**;
/// `story:unpublished-refusals` carries that observation.
///
/// The double holds nothing, so an unresolved resource would answer `ResourceUnresolved`: a
/// denial is evidence the name rule decided first and alone.
#[test]
fn declared_name_refuses_a_relation_name_that_is_blank() {
    let graph = GraphDouble::new();
    let context = context();
    let subject = subject();
    let held = resource(10);

    for blank in ["", " ", "   ", "\t", "\n"] {
        assert!(!declared_name(blank));

        let refusal = admit(&graph, &graph, &write(&context, &subject, &held, blank))
            .expect_err("a blank relation name");

        assert_eq!(refusal, GraphError::Denied(DenialReason::Denied));
        assert_eq!(refusal.denial_reason(), DenialReason::Denied);
        assert!(refusal.is_denial());
    }

    assert!(declared_name("viewer"));
}

/// [`declared_name`] alone: a relation name that is not its own trim is refused.
///
/// **Named by no row of `contracts/obligations/graph.json`** — the same rule, the same
/// withdrawal, read against names that are not empty. The closing assertion is what makes
/// this the name rule and not a constant: the trimmed name gets past it, and what refuses
/// then is the other port's answer about a resource this empty double does not hold.
#[test]
fn declared_name_refuses_a_relation_name_that_differs_from_its_trim() {
    let graph = GraphDouble::new();
    let context = context();
    let subject = subject();
    let held = resource(10);

    for padded in [" viewer", "viewer ", " viewer ", "viewer\t", "\nviewer"] {
        assert!(!declared_name(padded));

        let refusal = admit(&graph, &graph, &write(&context, &subject, &held, padded))
            .expect_err("a name that is not the name it prints as");

        assert_eq!(refusal, GraphError::Denied(DenialReason::Denied));
        assert!(refusal.is_denial());
    }

    assert!(declared_name("viewer"));
    assert_eq!(
        admit(&graph, &graph, &write(&context, &subject, &held, "viewer"))
            .expect_err("the name is admitted, and the empty double resolves no resource"),
        GraphError::CouldNotAnswer(Unanswered::ResourceUnresolved)
    );
}
