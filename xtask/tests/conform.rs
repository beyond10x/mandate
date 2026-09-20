//! The conformance gate's cases, decided against the committed corpus and doctored copies of
//! it.
//!
//! The green case drives [`conform::decide`] over this checkout, so what is proved here is
//! proved about the same suite, the same target binary, the same two ledgers and the same
//! stories the gate reads. Every red case copies what the step reads from a root —
//! `systems/mandate`, `generated/{conformance,schema,coverage}`, `contracts/` and, for the
//! release cases, the AEP artifact and the journal — into a scratch root under `target/`,
//! changes exactly one thing, and drives the same entry point at that root.
//!
//! # The three seams, and why the cases need them
//!
//! [`conform::Seams`] names what a copy must not answer for itself: the **stories** whose rung
//! decides whether an attribution is live, the **sources** the implementation digest is taken
//! over, and a **doctor** for the report, which no fixture can otherwise produce because the
//! report is written by a run of the real target.
//!
//! The story directory these cases pass is a copy of this workspace's, plus the two stories the
//! ledger now names — `story:ess-synthesizer-prerequisites` and
//! `story:conformance-denial-reasons`, created in the planning store after this unit tree was
//! cut (`review-result:wave-d-conform-gate-adversary-1` F6/F7). A tree whose store predates the
//! stories its ledger names is exactly what the seam is for; the wired gate passes
//! [`conform::Seams::workspace`] and reads this checkout's own store.
#![allow(dead_code)] // the binary target uses the whole of each module; a case here uses part.
#[path = "../src/documents.rs"]
mod documents;
#[path = "../src/emit.rs"]
mod emit;

#[path = "../src/conform.rs"]
mod conform;
#[path = "../src/coverage.rs"]
mod coverage;

use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_owned()
}

/// Everything the step reads from a root, copied into a scratch root of its own.
///
/// `systems/mandate` is copied because the step re-synthesizes the suite from it; the three
/// `generated/` directories because it byte-compares the suite and reads the projections'
/// provenance and the coverage receipt; `contracts/` because it holds both ledgers.
fn fixture(name: &str) -> PathBuf {
    let root = repo().join("target/xtask-conform-cases").join(name);
    if root.exists() {
        fs::remove_dir_all(&root).expect("clear the fixture");
    }
    fs::create_dir_all(&root).expect("fixture root");
    for directory in [
        "systems/mandate",
        "generated/conformance",
        "generated/schema",
        "generated/coverage",
        "contracts",
    ] {
        copy(&repo().join(directory), &root.join(directory));
    }
    root
}

fn copy(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("fixture directory");
    for entry in fs::read_dir(from).expect("read the source directory") {
        let path = entry.expect("a source entry").path();
        let target = to.join(path.file_name().expect("a named entry"));
        if path.is_dir() {
            copy(&path, &target);
        } else {
            fs::copy(&path, &target).expect("copy a source file");
        }
    }
}

/// This workspace's stories, plus the two the ledger names that its store does not hold yet.
///
/// Built once into a directory of its own and shared by every case: what a rung decides does
/// not vary between them. The two written here carry the frontmatter the store renders —
/// `id`, `kind`, `status` — because the rung is all this step reads.
fn stories() -> PathBuf {
    let directory = repo().join("target/xtask-conform-store/story");
    if !directory.join("conform-gate.md").is_file() {
        copy(&repo().join(".engineering/planning/story"), &directory);
    }
    for (name, title) in [
        (
            "ess-synthesizer-prerequisites",
            "Scenarios blocked on the synthesizer arranging no prerequisite",
        ),
        (
            "conformance-denial-reasons",
            "The conformance run records the reason and clause of every denial",
        ),
    ] {
        fs::write(
            directory.join(format!("{name}.md")),
            format!(
                "---\nformat: aep.planning-md/1\nid: story:{name}\nkind: story\n\
                 status: draft\ntitle: {title}\nrevision: 1\n---\n"
            ),
        )
        .expect("write a fixture story");
    }
    directory
}

/// The seams a case drives the step with: the stories above, and this checkout's own sources.
///
/// The sources are this workspace's because a fixture root holds none — it carries the
/// artifacts the step reads, not a copy of the workspace — and an implementation digest over
/// nothing is refused (`review-result:wave-d-conform-gate-adversary-1` F5).
fn seams() -> conform::Seams {
    conform::Seams {
        stories: stories(),
        sources: repo(),
        doctor: None,
    }
}

fn outcomes(root: &Path) -> String {
    fs::read_to_string(root.join("contracts/expected-outcomes.json")).expect("the fixture ledger")
}

fn write_outcomes(root: &Path, body: &str) {
    fs::write(root.join("contracts/expected-outcomes.json"), body).expect("write the ledger");
}

/// The one line of the ledger whose row names `id`.
fn row(body: &str, id: &str) -> String {
    let needle = format!("{{\"id\":\"{id}\",");
    let found: Vec<&str> = body
        .lines()
        .filter(|line| line.starts_with(&needle))
        .collect();
    assert_eq!(found.len(), 1, "{id}: one row in the ledger");
    // Without its trailing comma: a case that removes a row appends the comma back, and one
    // that rewrites a row matches the same text whether or not it is the last.
    found[0].trim_end_matches(',').to_owned()
}

fn failure(root: &Path, release: bool) -> String {
    failure_with(root, release, seams())
}

fn failure_with(root: &Path, release: bool, seams: conform::Seams) -> String {
    match conform::decide(root, release, &seams) {
        Ok(report) => panic!("the doctored corpus was accepted:\n{report}"),
        Err(error) => error.to_string(),
    }
}

/// The whole gate over the committed corpus: the suite, the run, both ledgers, the
/// attribution and the two tables.
#[test]
fn the_committed_corpus_is_accepted() {
    let report = conform::decide(&repo(), false, &seams()).expect("the committed corpus conforms");
    // The step's own caller — `Action::Conform { root, release }` — is the coordinator's
    // wiring, so until it lands this is the only place the tables a reader of conformance
    // sees are produced. They go on stdout rather than being asserted about and discarded.
    println!("{report}");
    for column in [
        "total",
        "passed",
        "failed",
        "error",
        "unsupported",
        "skipped",
    ] {
        assert!(report.contains(column), "the counts table states {column}");
    }
    assert!(
        report.contains("146"),
        "the counts table states the scenario total:\n{report}"
    );
    for story in [
        "story:ess-synthesizer-prerequisites",
        "story:refusal-discriminators",
        "story:testkit-doubles",
        "story:directory-provenance",
    ] {
        assert!(
            report.contains(story),
            "the attribution table names {story}:\n{report}"
        );
    }
}

/// A scenario the run carries and the ledger does not: the account is short by one and the
/// refusal names it.
#[test]
fn a_vanished_scenario_is_refused_by_name() {
    let root = fixture("vanished-scenario");
    let body = outcomes(&root);
    let vanished = row(&body, "mandate.tenancy.CreateOrganization/outcome/accepted");
    let doctored = body.replace(&format!("{vanished},\n"), "");
    assert_ne!(doctored, body, "the row was removed");
    write_outcomes(&root, &doctored);
    let error = failure(&root, false);
    assert!(
        error.contains("mandate.tenancy.CreateOrganization/outcome/accepted"),
        "the refusal names the vanished scenario: {error}"
    );
}

/// A ledger row naming a scenario the run does not carry: the count moved the other way.
#[test]
fn a_scenario_the_run_does_not_carry_is_refused_by_name() {
    let root = fixture("added-scenario");
    let body = outcomes(&root);
    let first = row(
        &body,
        "mandate.audit.AuditEvent/state/Redacted/refuses/mandate.audit.RedactAuditEvent",
    );
    let invented =
        "{\"id\":\"mandate.audit.NoSuchScenario/outcome/accepted\",\"outcome\":\"passed\"}";
    write_outcomes(
        &root,
        &body.replace(&first, &format!("{invented},\n{first}")),
    );
    let error = failure(&root, false);
    assert!(
        error.contains("mandate.audit.NoSuchScenario/outcome/accepted"),
        "the refusal names the scenario no run carries: {error}"
    );
}

/// The outcome of a scenario changed in the ledger and not in the implementation.
#[test]
fn a_changed_outcome_is_refused_by_name() {
    let root = fixture("changed-outcome");
    let body = outcomes(&root);
    let passing = row(&body, "mandate.tenancy.CreateOrganization/outcome/accepted");
    let claimed = passing.replace("\"outcome\":\"passed\"", "\"outcome\":\"failed\"");
    assert_ne!(claimed, passing, "the outcome was changed");
    write_outcomes(&root, &body.replace(&passing, &claimed));
    let error = failure(&root, false);
    assert!(
        error.contains("mandate.tenancy.CreateOrganization/outcome/accepted"),
        "the refusal names the scenario whose outcome moved: {error}"
    );
    assert!(
        error.contains("passed") && error.contains("failed"),
        "the refusal states both outcomes: {error}"
    );
}

/// The suite is not what `ess verify conform synthesize` writes from these sources today.
#[test]
fn a_suite_that_is_not_a_fresh_synthesis_is_refused() {
    let root = fixture("suite-drift");
    let suite = root.join("generated/conformance/suite.json");
    let body = fs::read_to_string(&suite).expect("the fixture suite");
    let doctored = body.replacen("\"purpose\"", "\"purpose \"", 1);
    assert_ne!(doctored, body, "the suite was doctored");
    fs::write(&suite, doctored).expect("write the fixture suite");
    let error = failure(&root, false);
    assert!(
        error.contains("generated/conformance/suite.json"),
        "the refusal names the committed suite: {error}"
    );
}

/// The specification's own scenario list is read, so an authored scenario reaches the corpus.
///
/// `ess-inputs.yaml` carries `scenarios: []` today and `story:authored-denial-scenarios` fills
/// it. The step passes `--scenarios` exactly when that list is non-empty — ESS refuses the flag
/// against an empty list — so the case that decides it lists a file the synthesizer cannot
/// parse and asks the gate what it noticed
/// (`review-result:wave-d-conform-gate-adversary-1` F2).
#[test]
fn the_specifications_scenario_list_is_read_when_it_is_not_empty() {
    let root = fixture("listed-scenario");
    let scenarios = root.join("systems/mandate/scenarios");
    fs::create_dir_all(&scenarios).expect("the fixture scenarios directory");
    fs::write(
        scenarios.join("unparseable.yaml"),
        "this is not a scenario: [\n",
    )
    .expect("write the fixture scenario");
    let inputs = root.join("systems/mandate/ess-inputs.yaml");
    let listed = fs::read_to_string(&inputs)
        .expect("the fixture inputs")
        .replace("scenarios: []", "scenarios:\n- scenarios/unparseable.yaml");
    fs::write(&inputs, listed).expect("write the fixture inputs");
    let error = failure(&root, false);
    assert!(
        error.contains("synthesize"),
        "the refusal comes from the synthesis that read the list: {error}"
    );
}

/// One byte of the honesty ledger moved: a double or an arming changed and was not recorded.
#[test]
fn a_moved_injections_byte_is_refused() {
    let root = fixture("moved-injection");
    let ledger = root.join("contracts/conformance/injections.json");
    let body = fs::read_to_string(&ledger).expect("the fixture injections");
    let doctored = body.replacen("\"consulted\": 0", "\"consulted\": 1", 1);
    assert_ne!(doctored, body, "the injections ledger was doctored");
    fs::write(&ledger, doctored).expect("write the fixture injections");
    let error = failure(&root, false);
    assert!(
        error.contains("contracts/conformance/injections.json"),
        "the refusal names the committed ledger: {error}"
    );
}

/// The receipt binds the toolchain, and a corpus projected by another one is refused.
#[test]
fn a_receipt_naming_another_toolchain_is_refused() {
    let root = fixture("repinned-ess");
    let path = root.join("generated/coverage/receipt.json");
    let body = fs::read_to_string(&path).expect("the fixture receipt");
    let repinned = body.replace("\"ess 0.26.0\"", "\"ess 0.1.0\"");
    assert_ne!(repinned, body, "the recorded toolchain was changed");
    fs::write(&path, repinned).expect("write the fixture receipt");
    let error = failure(&root, false);
    assert!(
        error.contains("ess 0.1.0") && error.contains("ess_version"),
        "the refusal names the recorded toolchain and the field it came from: {error}"
    );
}

/// An implementation digest is a digest of an implementation.
#[test]
fn an_implementation_digest_over_no_sources_is_refused() {
    let root = repo().join("target/xtask-conform-cases/sourceless");
    if root.exists() {
        fs::remove_dir_all(&root).expect("clear the fixture");
    }
    fs::create_dir_all(&root).expect("fixture root");
    let error = conform::implementation_digest(&root)
        .expect_err("a root with no sources has no implementation to digest")
        .to_string();
    assert!(
        error.contains("sourceless"),
        "the refusal names the root that holds no sources: {error}"
    );
}

/// An attribution to a story whose work is over answers nothing.
#[test]
fn a_dead_blocked_on_is_refused_by_name() {
    let root = fixture("dead-attribution");
    let body = outcomes(&root);
    let attributed = row(&body, "mandate.tenancy.CreateTeam/outcome/accepted");
    let dead = attributed.replace("story:ess-synthesizer-prerequisites", "story:coverage-map");
    assert_ne!(dead, attributed, "the attribution was moved");
    write_outcomes(&root, &body.replace(&attributed, &dead));
    let error = failure(&root, false);
    assert!(
        error.contains("mandate.tenancy.CreateTeam/outcome/accepted")
            && error.contains("story:coverage-map"),
        "the refusal names the scenario and the story whose work is over: {error}"
    );
    assert!(
        error.contains("implemented"),
        "the refusal states the rung the store reports: {error}"
    );
}

/// One scenario, two ledgers, two different live stories: whose gap is it?
#[test]
fn a_double_attribution_is_refused_by_name() {
    let root = fixture("double-attribution");
    let body = outcomes(&root);
    // `injections.json` is the authority for this one: the target refused it before dispatch
    // and named the story in its own output. A second, different story here is the ambiguity.
    let unsupported = row(&body, "mandate.tenancy.CreateTeam/outcome/denied");
    let claimed = unsupported.replace(
        "\"outcome\":\"unsupported\"",
        "\"outcome\":\"unsupported\",\"blocked_on\":\"story:declared-writers\"",
    );
    assert_ne!(claimed, unsupported, "a second attribution was added");
    write_outcomes(&root, &body.replace(&unsupported, &claimed));
    let error = failure(&root, false);
    assert!(
        error.contains("mandate.tenancy.CreateTeam/outcome/denied"),
        "the refusal names the doubly attributed scenario: {error}"
    );
    assert!(
        error.contains("story:declared-writers") && error.contains("story:testkit-doubles"),
        "the refusal states both stories: {error}"
    );
}

/// The target's "not attributed here" marker is not an attribution.
#[test]
fn an_attribution_to_the_marker_is_refused_by_name() {
    let root = fixture("marker-attribution");
    let body = outcomes(&root);
    let attributed = row(&body, "mandate.tenancy.CreateTeam/outcome/accepted");
    let marked = attributed.replace("story:ess-synthesizer-prerequisites", "story:conform-gate");
    assert_ne!(
        marked, attributed,
        "the attribution was moved to the marker"
    );
    write_outcomes(&root, &body.replace(&attributed, &marked));
    let error = failure(&root, false);
    assert!(
        error.contains("mandate.tenancy.CreateTeam/outcome/accepted")
            && error.contains("story:conform-gate"),
        "the refusal names the scenario and the marker: {error}"
    );
}

/// A non-passed scenario with no story in either ledger.
#[test]
fn an_unattributed_scenario_is_refused_by_name() {
    let root = fixture("unattributed");
    let body = outcomes(&root);
    let attributed = row(&body, "mandate.tenancy.CreateTeam/outcome/accepted");
    let bare = attributed.replace(
        ",\"blocked_on\":\"story:ess-synthesizer-prerequisites\"",
        "",
    );
    assert_ne!(bare, attributed, "the attribution was removed");
    write_outcomes(&root, &body.replace(&attributed, &bare));
    let error = failure(&root, false);
    assert!(
        error.contains("mandate.tenancy.CreateTeam/outcome/accepted"),
        "the refusal names the unattributed scenario: {error}"
    );
}

/// An `error` row is an inconclusive scenario written down as an expectation.
#[test]
fn an_error_row_is_refused_by_name() {
    let root = fixture("error-row");
    let body = outcomes(&root);
    let unsupported = row(&body, "mandate.audit.RecordAuditEvent/outcome/denied");
    let inconclusive = unsupported.replace("\"outcome\":\"unsupported\"", "\"outcome\":\"error\"");
    assert_ne!(inconclusive, unsupported, "the outcome was changed");
    write_outcomes(&root, &body.replace(&unsupported, &inconclusive));
    let error = failure(&root, false);
    assert!(
        error.contains("mandate.audit.RecordAuditEvent/outcome/denied"),
        "the refusal names the scenario: {error}"
    );
    assert!(
        error.contains("inconclusive"),
        "the refusal states that an inconclusive scenario is not an expectation: {error}"
    );
}

/// Move one scenario into the report's `skipped` list: a scenario nothing decided.
fn skip_one(report: &mut Value) {
    move_one(report, "skipped");
}

/// Move one scenario into the report's `error` list: a check the runner could not execute.
fn error_one(report: &mut Value) {
    move_one(report, "error");
}

fn move_one(report: &mut Value, into: &str) {
    let moved = report["outcomes"]["unsupported"]
        .as_array_mut()
        .expect("the report lists its unsupported scenarios")
        .remove(0);
    report["outcomes"][into]
        .as_array_mut()
        .expect("the report lists the outcome moved into")
        .push(moved);
    for (column, by) in [("unsupported", -1_i64), (into, 1)] {
        let count = report["counts"][column].as_i64().unwrap_or_default() + by;
        report["counts"][column] = Value::from(count);
    }
}

/// A run that skipped a scenario is a run that decided one fewer than it reports.
#[test]
fn a_report_that_skips_a_scenario_is_refused_by_name() {
    let root = fixture("skipped-scenario");
    let error = failure_with(
        &root,
        false,
        conform::Seams {
            doctor: Some(skip_one),
            ..seams()
        },
    );
    assert!(
        error.contains("mandate.audit.AuditEvent/state/Redacted"),
        "the refusal names the skipped scenario: {error}"
    );
    assert!(
        error.contains("skipped"),
        "the refusal states that it was skipped: {error}"
    );
}

/// A run that could not execute a check answered nothing about that scenario.
#[test]
fn a_report_that_errors_a_scenario_is_refused_by_name() {
    let root = fixture("errored-scenario");
    let error = failure_with(
        &root,
        false,
        conform::Seams {
            doctor: Some(error_one),
            ..seams()
        },
    );
    assert!(
        error.contains("mandate.audit.AuditEvent/state/Redacted"),
        "the refusal names the scenario the runner could not decide: {error}"
    );
    assert!(
        error.contains("inconclusive") || error.contains("error"),
        "the refusal states that it is inconclusive: {error}"
    );
}

/// The frontmatter reader reads a value, not the characters around it.
///
/// A quoted `status: "implemented"` and a `status: implemented  # closed at wave D` are both a
/// terminal rung, and a reader that compares the raw text reads either as live
/// (`review-result:wave-d-conform-gate-adversary-1` F9). Both readers are driven over the same
/// file, so the two cannot drift apart while this case runs.
#[test]
fn a_quoted_or_commented_status_is_read_as_terminal() {
    let directory = repo().join("target/xtask-conform-cases/rungs");
    fs::create_dir_all(&directory).expect("the fixture story directory");
    for (name, status) in [
        ("plain", "implemented"),
        ("quoted", "\"implemented\""),
        ("single", "'implemented'"),
        ("commented", "implemented  # closed at wave D"),
        ("spaced", "  implemented  "),
    ] {
        let path = directory.join(format!("{name}.md"));
        fs::write(
            &path,
            format!(
                "---\nformat: aep.planning-md/1\nid: story:{name}\nkind: story\n\
                 status: {status}\n---\n\n## Body\n\nstatus: draft\n"
            ),
        )
        .expect("write a fixture story");
        assert_eq!(
            conform::terminal_rung(&path).as_deref(),
            Some("implemented"),
            "{name}: `status: {status}` is a terminal rung"
        );
        assert_eq!(
            coverage::terminal_rung(&path),
            conform::terminal_rung(&path),
            "{name}: the two readers disagree about `status: {status}`"
        );
    }
    let live = directory.join("live.md");
    fs::write(
        &live,
        "---\nformat: aep.planning-md/1\nid: story:live\nkind: story\nstatus: draft\n---\n",
    )
    .expect("write a fixture story");
    assert_eq!(
        conform::terminal_rung(&live),
        None,
        "a draft is not terminal"
    );
    assert_eq!(
        coverage::terminal_rung(&live),
        None,
        "a draft is not terminal"
    );
}

/// The head this checkout is at, which is what a current evidence record names.
fn head() -> String {
    let out = Command::new("git")
        .current_dir(repo())
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("git rev-parse HEAD");
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// The artifact and the journal as an AEP store holds them: `model_digest` in the document's
/// frontmatter, and the evidence itself as an `aep.evidence.record/v1` line in `journal.jsonl`.
fn write_evidence(root: &Path, model_digest: &str, reference: &str) {
    let planning = root.join(".engineering/planning");
    let directory = planning.join("executable-system-specification");
    fs::create_dir_all(&directory).expect("the fixture artifact directory");
    fs::write(
        directory.join("mandate.md"),
        format!(
            "---\nformat: aep.planning-md/1\nid: executable-system-specification:mandate\n\
             kind: executable-system-specification\nstatus: validated\n\
             title: The Mandate executable system specification\n\
             model_digest: {model_digest}\nrevision: 2\n---\n\n## Authority\n\n\
             The canonical source is `systems/mandate`.\n"
        ),
    )
    .expect("write the fixture artifact");
    let records: Vec<(&str, String, i64)> = if reference.is_empty() {
        Vec::new()
    } else {
        vec![("ess_conformance", reference.to_owned(), 1_789_000_000_000)]
    };
    journal(root, &records);
}

/// The artifact, and a journal holding one `aep.evidence.record/v1` line per record.
///
/// The shape is the store's own, measured by recording evidence into a scratch copy of this
/// store with `aep plan artifact evidence --kind … --source … --ref git:<sha> --at <instant>`:
/// `args.{kind,reference,source}` and `payload.at`.
fn write_records(root: &Path, model_digest: &str, records: &[(&str, String, i64)]) {
    write_evidence(root, model_digest, "");
    journal(root, records);
}

fn journal(root: &Path, records: &[(&str, String, i64)]) {
    let mut lines = String::new();
    for (revision, (kind, reference, at)) in records.iter().enumerate() {
        lines.push_str(&format!(
            "{{\"entity\":\"executable-system-specification\",\"id\":\"mandate\",\
             \"revision\":{},\"type\":\"aep.evidence.record/v1\",\
             \"args\":{{\"command\":\"record-evidence\",\"kind\":\"{kind}\",\
             \"reference\":\"{reference}\",\"source\":\"cargo xtask conform\"}},\
             \"payload\":{{\"at\":{at},\"recorded_at\":\"2026-09-21T00:00:00Z\"}}}}\n",
            revision + 2
        ));
    }
    fs::write(root.join(".engineering/planning/journal.jsonl"), lines)
        .expect("write the fixture journal");
}

fn spec_digest(root: &Path) -> String {
    let suite: Value = serde_json::from_slice(
        &fs::read(root.join("generated/conformance/suite.json")).expect("the fixture suite"),
    )
    .expect("the suite parses");
    suite["provenance"]["spec_digest"]
        .as_str()
        .expect("the suite states its specification digest")
        .to_owned()
}

/// `--release` on a tree whose evidence artifact does not exist.
#[test]
fn release_refuses_when_the_artifact_is_absent() {
    let root = fixture("no-evidence");
    let error = failure(&root, true);
    assert!(
        error.contains("executable-system-specification/mandate.md"),
        "the refusal names the artifact the release evidence lives on: {error}"
    );
}

/// `--release` on a tree whose artifact was validated against another specification.
#[test]
fn release_refuses_a_model_digest_that_is_not_the_suites() {
    let root = fixture("stale-model-digest");
    let stale = "0000000000000000000000000000000000000000000000000000000000000000";
    write_evidence(&root, stale, &format!("git:{}", head()));
    let error = failure(&root, true);
    assert!(
        error.contains("model_digest") && error.contains(stale),
        "the refusal names the recorded model digest: {error}"
    );
}

/// `--release` on a tree whose artifact carries no evidence record at all.
#[test]
fn release_refuses_when_the_journal_records_no_evidence() {
    let root = fixture("no-evidence-record");
    write_evidence(&root, &spec_digest(&root), "");
    let error = failure(&root, true);
    assert!(
        error.contains("journal.jsonl"),
        "the refusal names the journal the evidence is recorded in: {error}"
    );
}

/// `--release` on evidence naming a commit this checkout does not hold.
#[test]
fn release_refuses_a_ref_this_checkout_does_not_hold() {
    let root = fixture("unresolvable-ref");
    write_evidence(&root, &spec_digest(&root), "git:abc1234");
    let error = failure(&root, true);
    assert!(
        error.contains("git:abc1234") || error.contains("abc1234"),
        "the refusal names the reference it could not resolve: {error}"
    );
}

/// `--release` on evidence taken before the implementation moved.
#[test]
fn release_refuses_evidence_taken_before_the_sources_moved() {
    let root = fixture("moved-since-evidence");
    let before = Command::new("git")
        .current_dir(repo())
        .args([
            "rev-list",
            "-1",
            "HEAD",
            "--",
            "crates/*/src/*",
            "services/*/src/*",
            "systems",
        ])
        .output()
        .expect("git rev-list -1 over the sources");
    let before = String::from_utf8_lossy(&before.stdout).trim().to_owned();
    // The evidence is taken at the parent of that commit, so the sources have moved since.
    let before = Command::new("git")
        .current_dir(repo())
        .args(["rev-parse", &format!("{before}~1")])
        .output()
        .expect("git rev-parse <last source commit>~1");
    let before = String::from_utf8_lossy(&before.stdout).trim().to_owned();
    write_evidence(&root, &spec_digest(&root), &format!("git:{before}"));
    let error = failure(&root, true);
    assert!(
        error.contains(&before[..12]),
        "the refusal names the commit the evidence was taken at: {error}"
    );
    assert!(
        error.contains("crates") || error.contains("moved"),
        "the refusal states what moved since: {error}"
    );
}

/// `--release` passes on the evidence the planning store writes for this tree.
#[test]
fn release_accepts_the_evidence_the_store_writes() {
    let root = fixture("current-evidence");
    write_evidence(&root, &spec_digest(&root), &format!("git:{}", head()));
    let report = conform::decide(&root, true, &seams()).expect("current evidence is accepted");
    assert!(
        report.contains("146"),
        "the release run states the counts:\n{report}"
    );
}

/// Re-derive the coverage receipt for a fixture whose ESS sources were edited.
///
/// `cargo xtask generate` is what does this in a real tree; a case that edits
/// `systems/mandate` without it would be refused for the receipt rather than for the thing it
/// is about. The framing is the step's own.
fn reseal_receipt(root: &Path) {
    let sources = root.join("systems/mandate");
    let mut files: Vec<PathBuf> = Vec::new();
    walk(&sources, &mut files);
    let mut framed: Vec<(String, Vec<u8>)> = files
        .into_iter()
        .map(|path| {
            let relative = path
                .strip_prefix(&sources)
                .expect("a source under systems/mandate")
                .to_string_lossy()
                .into_owned();
            (relative, fs::read(&path).expect("read a source"))
        })
        .collect();
    framed.sort_by(|left, right| left.0.cmp(&right.0));
    let mut canonical: Vec<u8> = Vec::new();
    for (path, bytes) in &framed {
        canonical.extend_from_slice(path.as_bytes());
        canonical.push(0);
        canonical.extend_from_slice(bytes.len().to_string().as_bytes());
        canonical.push(0);
        canonical.extend_from_slice(bytes);
    }
    let path = root.join("generated/coverage/receipt.json");
    let mut receipt: Value = serde_json::from_slice(&fs::read(&path).expect("the fixture receipt"))
        .expect("the receipt parses");
    receipt["source_digest"] = Value::from(emit::digest(&canonical));
    fs::write(
        &path,
        serde_json::to_vec_pretty(&receipt).expect("render the receipt"),
    )
    .expect("write the fixture receipt");
}

fn walk(directory: &Path, into: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).expect("read a source directory") {
        let path = entry.expect("a source entry").path();
        if path.is_dir() {
            walk(&path, into);
        } else {
            into.push(path);
        }
    }
}

/// A comment is not a scenario, and the synthesizer is the one that reads the list.
///
/// The step passes `--scenarios` and falls back when ESS answers that the list selected no
/// authored files, so no reader here has to decide what `scenarios: []  # …` means — which is
/// what the two readings this replaces both got wrong
/// (`review-result:wave-d-conform-gate-adversary-2` F1/F2).
#[test]
fn a_comment_beside_the_empty_scenarios_list_is_not_a_scenario() {
    let root = fixture("commented-empty-list");
    let path = root.join("systems/mandate/ess-inputs.yaml");
    let commented = fs::read_to_string(&path)
        .expect("the fixture inputs")
        .replace(
            "scenarios: []",
            "scenarios: []  # story:authored-denial-scenarios fills this",
        );
    fs::write(&path, commented).expect("write the fixture inputs");
    reseal_receipt(&root);
    let report = conform::decide(&root, false, &seams())
        .expect("a comment beside the empty list is the same empty list");
    assert!(
        report.contains("146"),
        "the suite is the same one:\n{report}"
    );
}

/// A checkout of its own, holding the three directories the release rule names.
fn probe_checkout(name: &str) -> PathBuf {
    let root = repo().join("target/xtask-conform-cases").join(name);
    if root.exists() {
        fs::remove_dir_all(&root).expect("clear the probe checkout");
    }
    for directory in [
        "crates/mandate-probe/src",
        "crates/mandate-probe/tests",
        "services/probe-service/src",
        "systems/probe",
    ] {
        fs::create_dir_all(root.join(directory)).expect("the probe checkout");
    }
    fs::write(
        root.join("crates/mandate-probe/src/lib.rs"),
        "pub fn admits(token: &str) -> bool {\n    token == \"granted\"\n}\n",
    )
    .expect("write the probe implementation");
    fs::write(
        root.join("crates/mandate-probe/tests/admission.rs"),
        "#[test]\nfn granted() {}\n",
    )
    .expect("write the probe test");
    fs::write(
        root.join("services/probe-service/src/main.rs"),
        "fn main() {}\n",
    )
    .expect("write the probe service");
    fs::write(
        root.join("systems/probe/system.yaml"),
        "format: ess-system/1\nname: probe\n",
    )
    .expect("write the probe specification");
    probe_git(&root, &["init", "-q", "-b", "main"]);
    probe_git(&root, &["add", "-A"]);
    probe_git(&root, &["commit", "-q", "-m", "the implementation"]);
    root
}

fn probe_git(root: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(root)
        .args([
            "-c",
            "user.name=case",
            "-c",
            "user.email=case@example.invalid",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .output()
        .expect("git");
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// `--release` on a checkout whose implementation is not in any commit.
///
/// Everything else in the step reads the working tree — the digest, the build, the run — so a
/// rule that compares two commits blesses sources nothing ran
/// (`review-result:wave-d-conform-gate-adversary-2` F3).
#[test]
fn release_refuses_an_uncommitted_source() {
    let root = fixture("uncommitted-source");
    let sources = probe_checkout("uncommitted-source-checkout");
    let recorded = probe_git(&sources, &["rev-parse", "HEAD"]);
    fs::write(
        sources.join("crates/mandate-probe/src/lib.rs"),
        "pub fn admits(_token: &str) -> bool {\n    true\n}\n",
    )
    .expect("move the working tree");
    write_evidence(&root, &spec_digest(&root), &format!("git:{recorded}"));
    let error = failure_with(&root, true, conform::Seams { sources, ..seams() });
    assert!(
        error.contains("crates/mandate-probe/src/lib.rs"),
        "the refusal names the source no commit holds: {error}"
    );
}

/// A commit that moves no source the implementation digest covers does not refuse a release.
///
/// The release rule holds exactly the set `implementation_digest` digests, so a second test
/// case landing between the evidence run and the release is not drift
/// (`review-result:wave-d-conform-gate-adversary-2` F4).
#[test]
fn release_accepts_a_test_only_commit() {
    let root = fixture("test-only-commit");
    let sources = probe_checkout("test-only-commit-checkout");
    let recorded = probe_git(&sources, &["rev-parse", "HEAD"]);
    fs::write(
        sources.join("crates/mandate-probe/tests/admission.rs"),
        "#[test]\nfn granted() {}\n\n#[test]\nfn revoked() {}\n",
    )
    .expect("write a second probe test");
    probe_git(&sources, &["add", "-A"]);
    probe_git(&sources, &["commit", "-q", "-m", "a second case"]);
    write_evidence(&root, &spec_digest(&root), &format!("git:{recorded}"));
    let report = conform::decide(&root, true, &conform::Seams { sources, ..seams() })
        .expect("a test-only commit is not a moved implementation");
    assert!(report.contains("146"), "the release run states the counts");
}

/// An approval recorded after the conformance run does not answer for it.
///
/// `aep plan artifact evidence` takes `--kind` free and `--ref` on every kind, so a rule that
/// reads the latest record of any kind lets an approval supply the commit a release is decided
/// on (`review-result:wave-d-conform-gate-adversary-2` F5).
#[test]
fn an_approval_recorded_later_does_not_answer_for_the_conformance_evidence() {
    let root = fixture("masked-evidence");
    let sources = probe_checkout("masked-evidence-checkout");
    let stale = probe_git(&sources, &["rev-parse", "HEAD"]);
    fs::write(
        sources.join("crates/mandate-probe/src/lib.rs"),
        "pub fn admits(_token: &str) -> bool {\n    true\n}\n",
    )
    .expect("move the implementation");
    probe_git(&sources, &["add", "-A"]);
    probe_git(&sources, &["commit", "-q", "-m", "another implementation"]);
    let current = probe_git(&sources, &["rev-parse", "HEAD"]);
    write_records(
        &root,
        &spec_digest(&root),
        &[
            ("ess_conformance", format!("git:{stale}"), 1_789_000_000_000),
            ("approval", format!("git:{current}"), 1_789_000_000_001),
        ],
    );
    let error = failure_with(&root, true, conform::Seams { sources, ..seams() });
    assert!(
        error.contains(&stale[..12]),
        "the refusal names the commit the conformance evidence was taken at: {error}"
    );
}

/// Evidence about this artifact that is not a conformance run is not conformance evidence.
#[test]
fn an_artifact_carrying_only_another_kind_of_evidence_is_refused() {
    let root = fixture("no-conformance-evidence");
    write_records(
        &root,
        &spec_digest(&root),
        &[("approval", format!("git:{}", head()), 1_789_000_000_000)],
    );
    let error = failure(&root, true);
    assert!(
        error.contains("ess_conformance"),
        "the refusal names the kind a release is decided on: {error}"
    );
}
