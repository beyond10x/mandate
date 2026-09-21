//! Adversary pass 1 against `story:conformance-target`.
//!
//! Three properties the unit asserts about itself in prose, driven against the code that
//! wrote the prose. None of them is checked by `crates/mandate-conformance/tests/target.rs`:
//! that file asserts that a `blocked_on` *is spelled* `story:…`, that the injection list is
//! *non-empty*, and that the two registries partition the contract. The gap between "names a
//! story" and "names a live story", and between "recorded an injection" and "injected
//! something", is what these cases close.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use mandate_conformance::Executed;
use mandate_conformance::external::{NO_PORT, PORTS};

/// The repository root, from this crate's manifest directory.
fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate sits two levels below the repository root")
        .to_path_buf()
}

/// The digest a probe run is recorded against.
const DIGEST: &str = "0123456789ab";

/// The suite `systems/mandate` obliges, at the frozen format.
///
/// `ess` exits 1 on the 52 pre-existing synthesis refusals and still writes a complete
/// document for the 146 it selected, so the check is on the artefact and not the status —
/// the same reading `tests/target.rs` gives. Each caller names its own file so two
/// concurrently running cases never read each other's half-written bytes.
fn suite_json(named: &str) -> String {
    let root = repository();
    let out = root.join(format!("target/conformance/adversary1-{named}.json"));
    std::fs::create_dir_all(out.parent().expect("the output has a parent"))
        .expect("the output directory is writable");
    let output = Command::new("ess")
        .current_dir(&root)
        .args([
            "verify",
            "conform",
            "synthesize",
            "--path",
            "systems/mandate",
            "--target",
            "ir",
            "--compact",
            "--suite-format",
            "5",
            "--out",
        ])
        .arg(&out)
        .output()
        .expect("`ess` is on PATH");
    let suite = std::fs::read_to_string(&out).unwrap_or_else(|error| {
        panic!(
            "ess wrote no suite to {}: {error}\n{}",
            out.display(),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    assert!(
        serde_json::from_str::<serde_json::Value>(&suite)
            .ok()
            .and_then(|document| document["scenarios"].as_object().map(serde_json::Map::len))
            .is_some_and(|count| count > 0),
        "ess wrote a document that is not a suite"
    );
    suite
}

/// Which terminal category the report put each scenario in.
fn terminal(report: &str) -> BTreeMap<String, String> {
    let report: serde_json::Value = serde_json::from_str(report).expect("report/2 is JSON");
    let mut placed = BTreeMap::new();
    for (category, listed) in report["outcomes"]
        .as_object()
        .expect("report/2 lists its outcomes by category")
    {
        for id in listed.as_array().expect("a category lists scenarios") {
            placed.insert(
                id.as_str().expect("a scenario identity").to_owned(),
                category.clone(),
            );
        }
    }
    placed
}

/// The rungs a `story` cannot leave except by being archived.
///
/// `artifacts/lifecycles/story.yaml` of the protocol source: `implemented: [archived]`,
/// `rejected: [archived]`, `archived: []`. A story on one of these owns nothing further —
/// it is finished work, and the only move left to it is out of the board.
const CLOSED_RUNGS: &[&str] = &["implemented", "rejected", "archived"];

/// What the target writes on a scenario it executed and whose expectation was unmet.
///
/// Not an attribution. `crates/mandate-conformance/src/lib.rs:758-776` writes it because which
/// story closes a disagreement between the contract and an implementation is a judgement the
/// target cannot make, and `xtask/src/conform.rs:105` refuses an authored ledger that repeats it.
/// The attribution for these rows lives in `contracts/expected-outcomes.json`.
const TARGET_MARKER: &str = "story:conform-gate";

/// The `status:` a planning artifact's front matter declares.
fn status_of(document: &str) -> Option<&str> {
    document
        .lines()
        .find_map(|line| line.strip_prefix("status:"))
        .map(str::trim)
}

/// Every `blocked_on` a run records names a story that is still open.
///
/// `initiative:drift-enforcement`'s release stance — restated on this story's own rulings —
/// is that "a library tag may ship with `conformance_status: failed` while **every failed
/// scenario names a live `blocked_on` story** and the CHANGELOG carries the counts". A
/// scenario attributed to a story that is already `implemented` is attributed to nobody: the
/// lifecycle admits no move from `implemented` back to `active`, so that story will never
/// close the gap, and the reader of `injections.json` is told a gap is owned when it is not.
///
/// `tests/target.rs::every_scenario_that_did_not_pass_names_a_live_story` is named for this
/// property and asserts `story.starts_with("story:")`, which is the spelling and not the
/// liveness.
///
/// **Amended by the coordinator, 2026-09-21.** As first written this case read every `blocked_on`
/// in `injections.json` as an attribution, and `story:conform-gate` is not one. `xtask/src/conform.rs`
/// says so in terms: `injections.json` is the target's own output and is authoritative for a
/// scenario it refused before dispatch or does not support, while a scenario that *executed* and
/// whose expectation was unmet is marked `story:conform-gate` — "not an attribution but a statement
/// that the attribution is not made there" — and is attributed in `contracts/expected-outcomes.json`,
/// which is authored. `crates/mandate-conformance/src/lib.rs:758-776` writes the marker for exactly
/// that reason: which story closes a disagreement between the contract and an implementation is a
/// judgement, and the target is not the thing that can make it.
///
/// So the case failed the moment `story:conform-gate` reached `implemented` — on 54 rows whose real
/// owners (`story:ess-synthesizer-prerequisites` 53, `story:refusal-discriminators` 1) were and are
/// `draft`. It was reading the wrong ledger, not finding a stale attribution.
///
/// It now follows the two-ledger rule, which makes it a stronger check than before: a marker row
/// must be attributed in the authored ledger, and *that* story must be live. A marker with no entry
/// there is a gap owned by nobody, and so is an entry naming a closed story.
#[test]
fn every_blocked_on_story_is_live() {
    let suite = suite_json("live");
    let executed = Executed::of(&suite, DIGEST).expect("the suite executes");
    let injections: serde_json::Value =
        serde_json::from_str(&executed.injections).expect("the injection record is JSON");

    // The authored ledger, which answers for every scenario the target marked as executed-and-unmet.
    let authored: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repository().join("contracts/expected-outcomes.json"))
            .expect("the authored ledger is readable"),
    )
    .expect("the authored ledger is JSON");
    let attributed = |scenario: &str| -> Option<String> {
        authored["scenarios"]
            .as_array()?
            .iter()
            .find(|entry| entry["id"].as_str() == Some(scenario))?["blocked_on"]
            .as_str()
            .map(str::to_owned)
    };

    let store = repository().join(".engineering/planning/story");
    let mut closed: Vec<String> = Vec::new();
    let mut absent: Vec<String> = Vec::new();
    let mut unattributed: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    for entry in injections["blocked"]
        .as_array()
        .expect("the injection record lists what it could not satisfy")
    {
        let mut story = entry["blocked_on"].as_str().expect("a story").to_owned();
        let scenario = entry["scenario"].as_str().expect("a scenario");
        if story == TARGET_MARKER {
            // Not an attribution: the run executed this scenario and its expectation was unmet,
            // so the authored ledger is what owns it.
            match attributed(scenario) {
                Some(owner) => story = owner,
                None => {
                    unattributed.push(scenario.to_owned());
                    continue;
                }
            }
        }
        let slug = story
            .strip_prefix("story:")
            .unwrap_or_else(|| panic!("`{scenario}` names `{story}`, which is not a story"));
        if !seen.insert(story.clone()) {
            continue;
        }
        let path = store.join(format!("{slug}.md"));
        let Ok(document) = std::fs::read_to_string(&path) else {
            absent.push(format!("{story} (first named by `{scenario}`)"));
            continue;
        };
        let status = status_of(&document)
            .unwrap_or_else(|| panic!("`{story}` declares no status"))
            .to_owned();
        if CLOSED_RUNGS.contains(&status.as_str()) {
            closed.push(format!(
                "{story} is `{status}` (first named by `{scenario}`)"
            ));
        }
    }

    assert!(
        unattributed.is_empty(),
        "the target marked these scenarios `{TARGET_MARKER}` — executed, expectation unmet, \
         attribution made elsewhere — and `contracts/expected-outcomes.json` carries no \
         `blocked_on` for them, so each names a gap owned by nobody: {unattributed:?}"
    );
    assert!(
        absent.is_empty(),
        "the run attributes scenarios to stories the planning store does not hold: {absent:?}"
    );
    assert!(
        closed.is_empty(),
        "the run attributes scenarios to stories that are closed, so the gap each names is \
         owned by nobody and `initiative:drift-enforcement`'s release stance is not met: \
         {closed:?}"
    );
}

/// An injection recorded `armed` changed the answer of the scenario that armed it.
///
/// `injections.json` is the document a reader attributes the run by, and
/// `src/external.rs`'s own module doc states what an entry in it means: "This module
/// decides, per command, **where** that fault goes: at the port the handler consults,
/// named". `Injection::kind` is documented as "What was done: armed at a port, or refused
/// before dispatch."
///
/// This drives that document against the code. For each scenario carrying a `kind: "armed"`
/// row, the same suite is run once more with every `configure_external_outcome` step
/// removed. A row that records a fault placed at a port must move something: if the
/// scenario reaches the same terminal category with no arming at all, then the denial it
/// asserts came from the empty fold and not from the forced external outcome, and the row
/// attributes a pass to an injection that did not occur.
///
/// `src/commands/authz.rs` is the unambiguous half: it takes the arming and discards it
/// (`let _ = live.armed.take(COMMAND);`), never substitutes a reader, and `PORTS` records
/// the scenario as `armed` at `mandate_graph::port::GraphRead` regardless.
#[test]
fn every_armed_injection_changes_the_scenario_it_was_armed_for() {
    let suite = suite_json("armed");
    let executed = Executed::of(&suite, DIGEST).expect("the suite executes");
    let injections: serde_json::Value =
        serde_json::from_str(&executed.injections).expect("the injection record is JSON");
    let armed: BTreeMap<String, String> = injections["injections"]
        .as_array()
        .expect("the record lists every armed external outcome")
        .iter()
        .filter(|entry| entry["kind"] == "armed")
        .map(|entry| {
            (
                entry["scenario"].as_str().expect("a scenario").to_owned(),
                entry["command"].as_str().expect("a command").to_owned(),
            )
        })
        .collect();
    assert!(
        !armed.is_empty(),
        "no external outcome was recorded as armed at a port"
    );

    let mut document: serde_json::Value = serde_json::from_str(&suite).expect("the suite is JSON");
    for scenario in document["scenarios"]
        .as_object_mut()
        .expect("a suite carries an object of scenarios")
        .values_mut()
    {
        let steps = scenario["steps"]
            .as_array_mut()
            .expect("a scenario carries steps");
        steps.retain(|step| step["step"] != "configure_external_outcome");
    }
    let unarmed = Executed::of(&document.to_string(), DIGEST).expect("the suite executes");

    let with = terminal(&executed.report);
    let without = terminal(&unarmed.report);
    let inert: Vec<String> = armed
        .iter()
        .filter(|(scenario, _)| with.get(*scenario) == without.get(*scenario))
        .map(|(scenario, command)| {
            format!(
                "{command} ({scenario} is `{}` armed and unarmed)",
                with.get(scenario).map_or("absent", String::as_str)
            )
        })
        .collect();

    assert!(
        inert.is_empty(),
        "{} of {} injections recorded `armed` at a port change nothing: the scenario reaches \
         the same terminal category with no external outcome forced at all, so the row \
         attributes the result to a fault that was not placed: {inert:#?}",
        inert.len(),
        armed.len()
    );
}

/// The bounds `Check` states rather than evaluates are in the record that promises them.
///
/// `src/commands/authz.rs`'s module doc is the contract this drives: "`authorization.yaml`
/// declares `Check(context, action, resource)`, and `mandate_authz::CheckRequest` needs five
/// more that no port in the authorization ceiling can answer: the audience the credential is
/// required to carry, the relation the graph is asked about, the revision floor, the
/// attribute input and the authority scope. … This target states them, and `injections.json`
/// records that it did: **a reader who sees `Check` pass must be able to see which bounds
/// were stated rather than evaluated.**"
///
/// `mandate.authorization.Check/outcome/denied` passes. The record carries two
/// `mandate_authz` rows — `DecisionIdAllocator` and `ChallengeIssuer` — and neither is one of
/// the five: an identity allocator and a challenge issuer are ports that were doubled, not
/// bounds that were stated. Nothing in the document names `expected_audience`, `relation`,
/// the revision floor, the attribute set or the scope, so the reader the doc describes
/// cannot do what it says they can.
#[test]
fn the_bounds_check_states_are_recorded_where_the_module_says_they_are() {
    let suite = suite_json("bounds");
    let executed = Executed::of(&suite, DIGEST).expect("the suite executes");
    let report = terminal(&executed.report);
    assert_eq!(
        report
            .get("mandate.authorization.Check/outcome/denied")
            .map(String::as_str),
        Some("passed"),
        "`Check` did not pass, so the reader this case is about does not exist"
    );

    // The five `CheckRequest` fields the module doc enumerates, by the name `src/commands/
    // authz.rs` binds each to.
    let stated = [
        "expected_audience",
        "relation",
        "minimum",
        "attributes",
        "scope",
    ];
    let unrecorded: Vec<&str> = stated
        .into_iter()
        .filter(|bound| !executed.injections.contains(bound))
        .collect();
    assert!(
        unrecorded.is_empty(),
        "`src/commands/authz.rs` says `injections.json` records the bounds this target \
         states for `mandate.authorization.Check`, and the document names none of these: \
         {unrecorded:?}"
    );
}

/// `none` is recorded only for the commands the module that records it says have no port.
///
/// `src/external.rs`'s module doc states the class exactly: "Ten `mandate.tenancy` commands
/// and the two `mandate.graph` registration commands are decided entirely inside a fold:
/// `Tenancy` and `Topology` read no port". `src/commands/tenancy.rs` repeats it: "None of
/// the ten reads a port." Twelve commands.
///
/// The table carries thirteen, and the thirteenth is `mandate.identity.RevokeSession`, whose
/// refusal text asserts of it what the doc asserts of `Tenancy` and `Topology`: "the handler
/// is decided entirely inside its fold and consults no port". It does consult one.
/// `mandate_identity::revoke_session` calls `log.resolve(&id)` — `IdentityRead::resolve`
/// (`crates/mandate-identity/src/port.rs:177`, implemented for `IdentityLog` at `:775`),
/// the same port method `mandate_identity::refresh_session` reads and that this target
/// *does* arm, at `mandate_identity::IdentityRead`, by substituting `EmptyReads`.
///
/// The consequence is in the deliverable: the scenario is recorded
/// `refused-before-dispatch` against `story:testkit-doubles` on a stated reason that is not
/// the real one.
#[test]
fn only_the_documented_domains_claim_to_have_no_port() {
    let undocumented: Vec<&str> = PORTS
        .iter()
        .filter(|(_, port)| *port == NO_PORT)
        .map(|(command, _)| *command)
        .filter(|command| {
            !command.starts_with("mandate.tenancy.") && !command.starts_with("mandate.graph.")
        })
        .collect();
    assert!(
        undocumented.is_empty(),
        "`src/external.rs` documents the portless class as ten `mandate.tenancy` commands \
         and two `mandate.graph` registrations, and refuses each arming with \"the handler \
         is decided entirely inside its fold and consults no port\"; the table claims it \
         for commands of neither domain: {undocumented:?}"
    );
}
