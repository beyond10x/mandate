//! Adversary pass 2 on `story:obligations-graph`: the rows correction 1 left on the real
//! path, the `double` value it wrote, and the two documents its diff left disagreeing.
//!
//! `contracts/obligations/README.md:100-105` defines the classification this unit's
//! document turns on: "`real` is the crate's own shipped decision path — a handler, a fold,
//! a validator … `double` is a stand-in **for the deciding code itself** … An in-memory
//! port that merely *supplies* input to a real handler leaves the row `real`: **what is
//! classified is the code that makes the decision**, not the code that holds the data."
//! `review-result:wave-d-obligations-graph-adversary-1` F5 applied that rule to
//! `mandate.graph.WriteRelationship`'s membership clause and demoted it to `double`,
//! because `admit` propagates whatever the `SubjectAdmission` port answered.
//!
//! Every case below reads one claim of `contracts/obligations/graph.json` or of the README
//! it is written against, and asks the code the claim is about for it. None of them states
//! a new rule.

use std::fs;
use std::path::{Path, PathBuf};

use mandate_graph::port::GraphError;
use mandate_graph::relationship::{RelationshipWrite, SubjectAdmission, admit};
use mandate_graph::topology::{Placement, ResourceLookup};
use mandate_types::{
    Audience, AuthoritySubject, CorrelationId, CredentialId, OrganizationId, PrincipalId,
    ResourceId, ResourceRef, ResourceType, Uuid, VerifiedContext,
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

/// A membership port that admits: the subject half of `admit` is not what is under test.
struct Admitting;

impl SubjectAdmission for Admitting {
    fn admits(
        &self,
        _organization: &OrganizationId,
        _subject: &AuthoritySubject,
    ) -> Result<(), GraphError> {
        Ok(())
    }
}

/// A lookup that resolves the one resource it holds and decides **no** tenancy.
///
/// This is `crates/mandate-graph/tests/relationship.rs`'s `Tree` with its organization
/// comparison (`:72-74`) removed, which is the mutation that answers who decides the
/// clause: if the refusal is `admit`'s, removing the port's comparison changes nothing.
/// It asserts that the state it builds really is the cross-tenant one, so the case cannot
/// pass by constructing the wrong scenario.
struct ResolvesWithoutDecidingTenancy {
    holder: OrganizationId,
    resource: ResourceRef,
}

impl ResourceLookup for ResolvesWithoutDecidingTenancy {
    fn placement(
        &self,
        organization: &OrganizationId,
        resource: &ResourceRef,
    ) -> Result<Placement, GraphError> {
        assert_eq!(resource, &self.resource, "the fixture holds this resource");
        assert_ne!(
            &self.holder, organization,
            "the fixture holds it for another organization: the write is cross-tenant"
        );

        Ok(Placement {
            resource: self.resource.clone(),
            parent: None,
        })
    }
}

/// A lookup that resolves the one resource it holds, in the organization that holds it.
struct Resolves {
    holder: OrganizationId,
    resource: ResourceRef,
}

impl ResourceLookup for Resolves {
    fn placement(
        &self,
        organization: &OrganizationId,
        resource: &ResourceRef,
    ) -> Result<Placement, GraphError> {
        assert_eq!(resource, &self.resource, "the fixture holds this resource");
        assert_eq!(
            &self.holder, organization,
            "the fixture holds it for this organization"
        );

        Ok(Placement {
            resource: self.resource.clone(),
            parent: None,
        })
    }
}

/// `mandate.graph.WriteRelationship`, clause "resource tenancy mismatches", which
/// `contracts/obligations/graph.json:226-235` counts in `real_covered` on
/// `mandate-graph::relationship::a_resource_in_another_organization_is_denied_as_a_tenant_mismatch`.
///
/// That case builds `Tree`, a stub declared inside
/// `crates/mandate-graph/tests/relationship.rs:58-81`, and the
/// `Denied(TenantMismatch)` it asserts is produced by the stub's own comparison at `:72-74`.
/// `mandate_graph::relationship::admit` compares no organization: it reads
/// `lookup.placement(organization, write.resource)?` (`src/relationship.rs:117`) and
/// propagates. So the row classifies the test file's code as the crate's shipped decision
/// path — the same defect `review-result:wave-d-obligations-graph-adversary-1` F5 found in
/// the clause immediately above it, which correction 1 demoted to `double`.
///
/// This case asks for the row's claim: `admit` is handed a lookup that makes no tenancy
/// decision, the write is cross-tenant, and the clause's denial is asked for.
///
/// Pinned by the coordinator to the shipped behaviour on 2026-09-21
/// (`review-result:wave-d-obligations-graph-adversary-2` F1): `admit` admits the
/// cross-tenant write, because the only tenancy comparison on that path is the
/// `ResourceLookup` implementor's. The row is a `double` row on
/// `mandate_graph::double::GraphDouble` deferring to `story:graph-policy-adapter`, whose
/// adapter decides the clause; the assertion flips there.
#[test]
fn admit_decides_the_resource_tenancy_mismatch_the_registry_counts_on_the_real_path() {
    let context = context();
    let subject = subject();
    let held = resource(10);
    let lookup = ResolvesWithoutDecidingTenancy {
        holder: other_organization(),
        resource: held.clone(),
    };

    let decision = admit(
        &Admitting,
        &lookup,
        &write(&context, &subject, &held, "viewer"),
    );

    assert_eq!(
        decision,
        Ok(held.clone()),
        "admit refused a cross-tenant write on its own ({:?}); it compares no organization \
         today, so story:graph-policy-adapter landed and this pin is stale",
        decision.as_ref().err()
    );
}

/// `mandate.graph.WriteRelationship`, clause "the relationship is not admitted by the
/// authorization model", which `contracts/obligations/graph.json:236-250` counts in
/// `real_covered` on two cases that drive
/// [`mandate_graph::relationship::declared_name`] — a blank name and a name that is not its
/// own trim.
///
/// `declared_name` is a string-format predicate (`src/relationship.rs:91-93`) and it runs
/// before either port is consulted (`:112-114`). `admit` takes a `SubjectAdmission` and a
/// `ResourceLookup` and nothing else; neither is an authorization model, and
/// `src/relationship.rs:10` says of this very refusal that it "is `mandate-policy`'s".
///
/// This case asks for the row's claim: with both ports admitting and every name well
/// formed, some relationship the authorization model does not admit is refused.
///
/// Pinned by the coordinator to the shipped behaviour on 2026-09-21
/// (`review-result:wave-d-obligations-graph-adversary-2` F2): `admit` admits every one of
/// them. The clause defers to `story:cross-crate-clauses`, which carries the field that
/// names the crate a clause is decided in; the assertion flips when a model admission runs
/// on this path.
#[test]
fn admit_refuses_a_relationship_the_authorization_model_does_not_admit() {
    let context = context();
    let subject = subject();
    let held = resource(10);
    let lookup = Resolves {
        holder: organization(),
        resource: held.clone(),
    };

    // Well-formed names — `declared_name` admits every one of them — that no authorization
    // model in this workspace declares as a relation.
    let names = [
        "not-a-relation-any-model-declares",
        "relation with spaces inside it",
        "DROP TABLE relations",
        "zzzzzzzz",
    ];
    let admitted: Vec<&str> = names
        .into_iter()
        .filter(|name| admit(&Admitting, &lookup, &write(&context, &subject, &held, name)).is_ok())
        .collect();

    assert_eq!(
        admitted, names,
        "admit refused a well-formed relation name no model declares; its only rule of its \
         own is the name's format (crates/mandate-graph/src/relationship.rs:91-93), and \
         :10 says this refusal is mandate-policy's, so a model admission now runs on this \
         path and this pin is stale"
    );
}

/// The `double` values correction 1 wrote, read as the reader of the registry reads them.
///
/// `contracts/obligations/README.md:88-91,102` gives the form — a Rust path to the deciding
/// code, `mandate_graph::double::GraphDouble` — and `xtask` checks only that the field is
/// non-empty (`xtask/src/obligations_registry.rs:880-887`), so nothing else compares the
/// value with anything.
#[test]
fn every_double_the_registry_names_is_a_path_a_reader_can_resolve() {
    let directory = workspace().join("contracts").join("obligations");
    let mut documents: Vec<PathBuf> = fs::read_dir(&directory)
        .expect("the registry directory is readable")
        .map(|entry| entry.expect("a directory entry").path())
        .filter(|path| path.extension().is_some_and(|kind| kind == "json"))
        .collect();
    documents.sort();
    assert!(!documents.is_empty(), "the registry holds documents");

    let mut malformed: Vec<String> = Vec::new();
    for document in &documents {
        let text = fs::read_to_string(document).expect("a registry document is readable");
        let name = document
            .file_name()
            .expect("a file name")
            .to_string_lossy()
            .into_owned();
        for value in values_of(&text, "double") {
            if !resolvable_rust_path(value) {
                malformed.push(format!("{name}: {value:?}"));
            }
        }
    }

    assert!(
        malformed.is_empty(),
        "a `double` value names the deciding code so a reader can find it, and these are no \
         Rust path at all: {malformed:?}. The one in graph.json means the stub declared at \
         crates/mandate-graph/tests/relationship.rs:85, which lives in a test binary: there \
         is no `mandate_graph::relationship::Members`, and `mandate-graph` is not a path \
         segment. Every other row in the directory names a type by its real path"
    );
}

/// The five `no_state_change` rows of `contracts/obligations/graph.json`, which are one
/// obligation read five times: the command refuses without moving its projection.
///
/// All five drive a [`mandate_graph::double::GraphDouble`] and assert its fold is unchanged
/// (`crates/mandate-graph/tests/obligations.rs:219,246,269,386,410`), and `GraphDouble` is
/// the only implementor of `RelationshipWriter`, `ResourceRegistry` and `RevocationWriter`
/// in the workspace outside a test file. Correction 1 filed four of them as `double` on
/// `mandate_graph::double::GraphDouble` — `review-result:wave-d-obligations-graph-adversary-1`
/// F3 is the ruling that put two of them there — and left the fifth on the real path, which
/// also drops `mandate.graph.WriteRelationship`'s command-level `blocked_on`.
#[test]
fn the_no_state_change_rows_agree_on_what_decides_that_a_refusal_moves_nothing() {
    let document = fs::read_to_string(
        workspace()
            .join("contracts")
            .join("obligations")
            .join("graph.json"),
    )
    .expect("the graph registry document is readable");

    let rows = rows_of_kind(&document, "no-state-change");
    assert_eq!(
        rows.len(),
        5,
        "one no-state-change row per implemented command"
    );

    let disagreeing: Vec<&(&str, &str)> =
        rows.iter().filter(|(_, path)| *path != rows[0].1).collect();

    assert!(
        disagreeing.is_empty(),
        "every no-state-change row of this crate is decided by a call on GraphDouble, the \
         only implementor of these ports outside a test file, and the rows disagree about \
         it: {rows:?}. The four `double` rows are the classification \
         contracts/obligations/README.md:100-105 gives — the code that makes the decision is \
         the double's, not a handler's — and {disagreeing:?} states the shipped path decides \
         it"
    );
}

/// `contracts/obligations/README.md` may not state a count of the double-backed clauses, and
/// the report is the only place that count is kept.
///
/// This case was written to compare a count the README stated with the count the report
/// counted, and it was red: the README said "eight" and the report counted 13. The
/// coordinator's ruling (`review-result:wave-d-obligations-graph-adversary-2` F5, and
/// `…-identity-adversary-2` F2, which is the same defect found from the other side) was that
/// the count being *wrong* was the smaller half. A count written into this file is stale at
/// the next merge that adds a document — it was true at `181e6c0`, false two units later —
/// and so is a closed list of what the double-backed clauses defer to, which named one story
/// while `decision-blocker:epoch-atomicity` was already a second. Nothing compares either
/// with the directory, because `xtask/src/obligations_registry.rs` never reads the README.
///
/// So the case asserts what a README can hold: **no number stands in front of a claim about
/// double-backed clauses**, and every deferral the directory's double-backed clauses actually
/// name is one of the two kinds the README admits — a `story:` or a `decision-blocker:`. The
/// count lives in `contracts/conformance/obligations-report.json`, and this case checks that
/// it is not zero, so that the invariant has a subject.
#[test]
fn the_registry_readme_states_no_count_of_double_backed_clauses_a_merge_can_falsify() {
    let readme = fs::read_to_string(
        workspace()
            .join("contracts")
            .join("obligations")
            .join("README.md"),
    )
    .expect("the registry README is readable");
    let report = fs::read_to_string(
        workspace()
            .join("contracts")
            .join("conformance")
            .join("obligations-report.json"),
    )
    .expect("the conformance report is readable");

    let flat = readme.split_whitespace().collect::<Vec<_>>().join(" ");
    let subject = "double-backed clause";

    let mut counted_claims: Vec<String> = Vec::new();
    let mut rest = flat.as_str();
    let mut consumed = 0_usize;
    while let Some(at) = rest.find(subject) {
        let absolute = consumed + at;
        if let Some(word) = flat[..absolute].split_whitespace().next_back()
            && number_word(word).is_some()
        {
            let tail: String = flat[absolute..].chars().take(70).collect();
            counted_claims.push(format!("  \"{word} {tail}…\""));
        }
        consumed = absolute + subject.len();
        rest = &flat[consumed..];
    }

    let totals = &report[report.find("\"totals\"").expect("the report totals")..];
    let counted = number_of(totals, "double_only");

    assert!(
        counted > 0,
        "the report counts {counted} double-backed clauses, so this case has no subject; \
         contracts/conformance/obligations-report.json is where the count belongs"
    );
    assert!(
        counted_claims.is_empty(),
        "contracts/obligations/README.md states a count of double-backed clauses, and the \
         report counts {counted} of them today. A count written into the README is stale at \
         the next merge that adds a document — it said \"eight\" at 181e6c0 and the report \
         counted 13 two units later. The count belongs in \
         contracts/conformance/obligations-report.json, which the step rewrites. Claims \
         found:\n{}",
        counted_claims.join("\n")
    );

    for kind in ["story:", "decision-blocker:"] {
        assert!(
            flat.contains(kind),
            "contracts/obligations/README.md no longer admits {kind} as a thing a \
             double-backed clause may defer to, and the directory carries deferrals of both \
             kinds; the rule a later author reads out of this file would refuse what the \
             step accepts"
        );
    }
}

/// The workspace root: two above this crate's manifest.
fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the workspace root is two directories above this crate")
        .to_path_buf()
}

/// Every value of `"<key>": "<value>"` in a pretty-printed registry document, in order.
fn values_of<'a>(text: &'a str, key: &str) -> Vec<&'a str> {
    let needle = format!("\"{key}\": \"");
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find(&needle) {
        let after = &rest[at + needle.len()..];
        let end = after.find('"').expect("a JSON string is closed");
        found.push(&after[..end]);
        rest = &after[end..];
    }
    found
}

/// The unquoted number `"<key>": <n>` states, from the first occurrence.
fn number_of(text: &str, key: &str) -> usize {
    let needle = format!("\"{key}\": ");
    let at = text
        .find(&needle)
        .unwrap_or_else(|| panic!("{key} is stated"));
    let after = &text[at + needle.len()..];
    let end = after
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(after.len());
    after[..end].parse().expect("a count")
}

/// Every `(id, path)` of the rows of one `kind` in a registry document, in order.
fn rows_of_kind<'a>(text: &'a str, kind: &str) -> Vec<(&'a str, &'a str)> {
    let needle = format!("\"kind\": \"{kind}\"");
    let mut rows = Vec::new();
    let mut cursor = 0_usize;
    while let Some(at) = text[cursor..].find(&needle) {
        let at = cursor + at;
        let id = *values_of(&text[..at], "id")
            .last()
            .expect("a row states its id before its kind");
        let path = *values_of(&text[at..], "path")
            .first()
            .expect("a row states its path after its kind");
        rows.push((id, path));
        cursor = at + needle.len();
    }
    rows
}

/// Whether a `double` value is a path a reader can follow: `::`-separated Rust identifiers.
fn resolvable_rust_path(value: &str) -> bool {
    !value.is_empty()
        && value.split("::").all(|segment| {
            let mut characters = segment.chars();
            characters
                .next()
                .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
                && characters.all(|rest| rest.is_ascii_alphanumeric() || rest == '_')
        })
}

/// A written-out number the README may state, as a count.
fn number_word(word: &str) -> Option<usize> {
    const WORDS: [&str; 21] = [
        "zero",
        "one",
        "two",
        "three",
        "four",
        "five",
        "six",
        "seven",
        "eight",
        "nine",
        "ten",
        "eleven",
        "twelve",
        "thirteen",
        "fourteen",
        "fifteen",
        "sixteen",
        "seventeen",
        "eighteen",
        "nineteen",
        "twenty",
    ];

    WORDS
        .iter()
        .position(|candidate| *candidate == word)
        .or_else(|| word.parse().ok())
}
