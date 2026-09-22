//! The target's own contract: the synthesized suite executed end to end, and the four
//! properties a conformance run is worth nothing without.
//!
//! The suite is synthesized here rather than committed, for the reason
//! `story:conformance-target`'s corrections give: nothing of this wave lands under
//! `generated/conformance/`, and a suite fixture frozen beside the test would stop
//! tracking `systems/mandate` on the first model change — which is the drift the whole
//! initiative exists to catch. `ess 0.26.0` compiles it from the contract on every run,
//! into this crate's own build directory.
//!
//! What each case decides:
//!
//! * The partition. Every scenario of the suite reaches a terminal category, the four
//!   categories sum to the suite, and the `unsupported` half is **computed** from the
//!   target's own unrealized registry rather than written down — a command that stops
//!   being realized, or one the contract adds, moves the expected set with it.
//! * Accountability. Every scenario that did not pass carries a live `blocked_on` story
//!   in `injections.json`, which is what the release stance on
//!   `initiative:drift-enforcement` requires of a tag shipped `failed`.
//! * Determinism. Two runs of one suite against one target are byte-identical, or the
//!   report is not evidence about anything.
//! * Falsifiability. A suite with one scenario's expected event mutated fails that
//!   scenario and nothing else — without it, the run shows only that the target answers,
//!   never that the suite would notice a wrong answer.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use mandate_conformance::{Executed, commands};

/// The repository root, from this crate's manifest directory.
fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate sits two levels below the repository root")
        .to_path_buf()
}

/// The suite `systems/mandate` obliges, compiled by `ess` at the frozen format.
///
/// Format 5 is the one `story:conform-gate` names: format 4 emits no `coverage` key and
/// `qualification` requires one.
///
/// # `ess` exits non-zero and the suite is still the suite
///
/// `ess 0.26.0` exits 1 whenever synthesis refuses a scenario, and this contract refuses 52
/// of them — every one an `ESS-SYNTH-004`: a transition whose entity no outcome `creates`.
/// The document it writes is complete and admissible for the 146 it did select, so the
/// check here is on the artefact rather than on the status: the file exists and parses as a
/// suite. A status check would make every run of this lane red for a property of the
/// contract that `story:contract-creates` already took from 106 refusals to 52.
///
/// Each caller names its own output file. Cargo runs the cases in this file concurrently,
/// and two of them writing one path would let one read the other's half-written bytes.
fn suite_json(named: &str) -> String {
    let root = repository();
    let out = root.join(format!("target/conformance/tests-{named}.json"));
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
        .expect("`ess` is on PATH; the repository needs it for `cargo xtask generate` too");
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

/// The scenario identities of a suite, and the commands each one executes.
fn scenarios(suite: &str) -> BTreeMap<String, BTreeSet<String>> {
    let document: serde_json::Value = serde_json::from_str(suite).expect("the suite is JSON");
    document["scenarios"]
        .as_object()
        .expect("a suite carries an object of scenarios")
        .iter()
        .map(|(id, scenario)| {
            let commands = scenario["steps"]
                .as_array()
                .expect("a scenario carries steps")
                .iter()
                .filter(|step| step["step"] == "execute_command")
                .map(|step| {
                    step["command"]
                        .as_str()
                        .expect("an execute_command step names a command")
                        .to_owned()
                })
                .collect();
            (id.clone(), commands)
        })
        .collect()
}

/// The digest a run is recorded against. Any twelve hex characters; the gate supplies the
/// real one.
const DIGEST: &str = "0123456789ab";

#[test]
fn every_command_the_contract_declares_is_dispatched_or_named_with_its_story() {
    // The class-closing case. `injections.json` names a `blocked_on` per unrealized
    // command, and a hand-kept list of those is exactly the defect an adversary finds one
    // entry at a time: this asserts the list and the dispatch table *partition* the
    // commands the suite names, so a command that appears in the contract and in neither
    // half fails here rather than reaching a reader as a silent gap.
    let suite = suite_json("every0");
    let declared: BTreeSet<String> = scenarios(&suite)
        .values()
        .flat_map(|commands| commands.iter().cloned())
        .collect();
    let realized: BTreeSet<String> = commands::REALIZED.iter().map(|&c| c.to_owned()).collect();
    let unrealized: BTreeSet<String> = commands::UNREALIZED
        .iter()
        .map(|(command, _, _)| (*command).to_owned())
        .collect();

    let unaccounted: Vec<&String> = declared
        .iter()
        .filter(|command| !realized.contains(*command) && !unrealized.contains(*command))
        .collect();
    assert!(
        unaccounted.is_empty(),
        "the contract declares commands this target neither dispatches nor names a story \
         for: {unaccounted:?}"
    );
    let invented: Vec<&String> = realized
        .union(&unrealized)
        .filter(|command| !declared.contains(*command))
        .collect();
    assert!(
        invented.is_empty(),
        "this target names commands the contract does not declare: {invented:?}"
    );
    let both: Vec<&String> = realized.intersection(&unrealized).collect();
    assert!(
        both.is_empty(),
        "a command is both dispatched and named unrealized: {both:?}"
    );
    for (command, story, _) in commands::UNREALIZED {
        assert!(
            story.starts_with("story:"),
            "`{command}` is blocked on `{story}`, which is not a story identity"
        );
    }
}

#[test]
fn the_suite_partitions_and_the_unsupported_half_is_the_one_the_target_cannot_drive() {
    let suite = suite_json("the1");
    let executed = Executed::of(&suite, DIGEST).expect("the suite executes");
    let report: serde_json::Value =
        serde_json::from_str(&executed.report).expect("report/2 is JSON");
    let counts = &report["counts"];

    let scenarios = scenarios(&suite);
    let total = u64::try_from(scenarios.len()).expect("the suite fits");
    assert_eq!(counts["total"].as_u64(), Some(total), "report: {report}");
    assert_eq!(
        counts["skipped"].as_u64(),
        Some(0),
        "the Rust producer profile has no skipped category"
    );
    let sum: u64 = ["passed", "failed", "error", "unsupported", "skipped"]
        .iter()
        .map(|key| counts[key].as_u64().expect("a count is a number"))
        .sum();
    assert_eq!(sum, total, "the four categories do not partition the suite");

    let observed: BTreeSet<String> = report["outcomes"]["unsupported"]
        .as_array()
        .expect("report/2 lists its unsupported outcomes")
        .iter()
        .map(|id| id.as_str().expect("a scenario identity").to_owned())
        .collect();

    // Half one, computed from the suite and the target's registry and nothing else: every
    // scenario that executes a command the target names unrealized must be unsupported. A
    // command that quietly acquired a dispatch arm, or a contract that added one nobody
    // accounted for, moves this set and fails here.
    let unrealized: BTreeSet<&str> = commands::UNREALIZED
        .iter()
        .map(|(command, _, _)| *command)
        .collect();
    let obliged: BTreeSet<String> = scenarios
        .iter()
        .filter(|(_, commands)| commands.iter().any(|c| unrealized.contains(c.as_str())))
        .map(|(id, _)| id.clone())
        .collect();
    let missing: Vec<&String> = obliged.difference(&observed).collect();
    assert!(
        missing.is_empty(),
        "scenarios executing a command the registry names unrealized were not reported \
         unsupported: {missing:?}"
    );

    // Half two: the report and the injection ledger partition the same set. A scenario the
    // target refused and did not record, or recorded and did not refuse, is the one way the
    // two documents can disagree — and `injections.json` is what a reader attributes the
    // run by.
    let injections: serde_json::Value =
        serde_json::from_str(&executed.injections).expect("the injection record is JSON");
    let refused: BTreeSet<String> = injections["blocked"]
        .as_array()
        .expect("the injection record lists what it could not satisfy")
        .iter()
        .filter(|entry| entry["reason"] != "expectation-unmet")
        .map(|entry| entry["scenario"].as_str().expect("a scenario").to_owned())
        .collect();
    assert_eq!(
        observed, refused,
        "the scenarios reported unsupported and the scenarios the ledger says the target \
         refused are different sets"
    );

    assert_eq!(
        report["spec_digest"].as_str(),
        serde_json::from_str::<serde_json::Value>(&suite).expect("the suite is JSON")["provenance"]
            ["spec_digest"]
            .as_str(),
        "the report attests a different model from the suite it ran"
    );
}

#[test]
fn every_scenario_that_did_not_pass_names_a_live_story() {
    let suite = suite_json("every2");
    let executed = Executed::of(&suite, DIGEST).expect("the suite executes");
    let report: serde_json::Value =
        serde_json::from_str(&executed.report).expect("report/2 is JSON");
    let injections: serde_json::Value =
        serde_json::from_str(&executed.injections).expect("the injection record is JSON");

    let accounted: BTreeMap<String, String> = injections["blocked"]
        .as_array()
        .expect("the injection record lists what it could not satisfy")
        .iter()
        .map(|entry| {
            (
                entry["scenario"].as_str().expect("a scenario").to_owned(),
                entry["blocked_on"].as_str().expect("a story").to_owned(),
            )
        })
        .collect();

    for category in ["failed", "error", "unsupported"] {
        for id in report["outcomes"][category]
            .as_array()
            .expect("report/2 lists every category")
        {
            let id = id.as_str().expect("a scenario identity");
            let story = accounted
                .get(id)
                .unwrap_or_else(|| panic!("`{id}` is {category} and names no `blocked_on`"));
            assert!(
                story.starts_with("story:"),
                "`{id}` is blocked on `{story}`, which is not a story identity"
            );
        }
    }
    assert!(
        !accounted.is_empty(),
        "nothing was recorded as blocked, which cannot be true while the contract \
         declares commands no crate realizes"
    );
}

#[test]
fn every_standing_double_and_every_injection_is_recorded() {
    let suite = suite_json("every3");
    let executed = Executed::of(&suite, DIGEST).expect("the suite executes");
    let injections: serde_json::Value =
        serde_json::from_str(&executed.injections).expect("the injection record is JSON");

    let doubles = injections["standing_doubles"]
        .as_array()
        .expect("the record names the doubles that stood in for real adapters");
    assert!(
        !doubles.is_empty(),
        "a target driven entirely through doubles that recorded none of them reports a \
         run nobody can attribute"
    );
    for double in doubles {
        assert!(double["port"].is_string(), "a double names its port");
        assert!(double["double"].is_string(), "a double names itself");
    }

    let armed = injections["injections"]
        .as_array()
        .expect("the record lists every armed external outcome");
    assert!(
        !armed.is_empty(),
        "the suite arms an external outcome for every command and none was recorded"
    );
    for entry in armed {
        assert!(
            entry["scenario"].is_string(),
            "an injection names its scenario"
        );
        assert!(
            entry["command"].is_string(),
            "an injection names its command"
        );
        assert!(
            entry["kind"].is_string(),
            "an injection says what was done at the port"
        );
    }
}

#[test]
fn two_runs_of_one_suite_are_byte_identical() {
    let suite = suite_json("two4");
    let first = Executed::of(&suite, DIGEST).expect("the suite executes");
    let second = Executed::of(&suite, DIGEST).expect("the suite executes");
    assert_eq!(
        first.report, second.report,
        "two runs produced different reports, so something varies outside the runner's \
         owned sources"
    );
    assert_eq!(first.run, second.run, "two runs produced different runs");
    assert_eq!(
        first.injections, second.injections,
        "two runs recorded different injections"
    );
}

#[test]
fn one_mutated_expectation_fails_that_scenario_and_nothing_else() {
    // Falsifiability. Without it a partition of 146 scenarios shows only that the target
    // answers every one of them, and nothing about whether the suite would notice a wrong
    // answer.
    //
    // The scenario is chosen from the honest run rather than written down: it must be one
    // that passed and one that asserts a text field of an event payload, and which
    // scenarios those are is a property of the contract and the implementation together.
    let suite = suite_json("one5");
    let honest = Executed::of(&suite, DIGEST).expect("the suite executes");
    let honest: serde_json::Value = serde_json::from_str(&honest.report).expect("report/2");
    let before: BTreeSet<String> = honest["outcomes"]["passed"]
        .as_array()
        .expect("passed outcomes")
        .iter()
        .map(|id| id.as_str().expect("an identity").to_owned())
        .collect();
    assert!(
        !before.is_empty(),
        "no scenario passed, so nothing can show that a wrong answer would be noticed"
    );

    let mut document: serde_json::Value = serde_json::from_str(&suite).expect("the suite is JSON");
    let mut chosen = None;
    let scenarios = document["scenarios"]
        .as_object_mut()
        .expect("a suite carries an object of scenarios");
    for (id, scenario) in scenarios.iter_mut() {
        if chosen.is_some() || !before.contains(id) {
            continue;
        }
        for step in scenario["steps"]
            .as_array_mut()
            .expect("a scenario carries steps")
        {
            if step["step"] != "expect_event" {
                continue;
            }
            let Some(payload) = step["payload"].as_object_mut() else {
                continue;
            };
            let Some(field) = payload
                .iter()
                .find(|(_, value)| value.is_string())
                .map(|(name, _)| name.clone())
            else {
                continue;
            };
            payload.insert(
                field,
                serde_json::Value::String("a value no command was given".to_owned()),
            );
            chosen = Some(id.clone());
            break;
        }
    }
    let chosen = chosen.expect("a passing scenario asserts a text field of an event payload");

    let corrupted = Executed::of(&document.to_string(), DIGEST).expect("the suite executes");
    let corrupted: serde_json::Value = serde_json::from_str(&corrupted.report).expect("report/2");
    let after: BTreeSet<String> = corrupted["outcomes"]["passed"]
        .as_array()
        .expect("passed outcomes")
        .iter()
        .map(|id| id.as_str().expect("an identity").to_owned())
        .collect();
    let lost: Vec<&String> = before.difference(&after).collect();
    assert_eq!(
        lost,
        vec![&chosen],
        "the blast radius of one mutated expectation is the one scenario that carries it"
    );
}

#[test]
fn the_realized_credential_commands_are_driven_rather_than_refused() {
    // The eleven `mandate.credential` commands `services/sts` realizes are reachable now
    // that `mandate-token` is on this crate's dependency line, and a scenario that executes
    // one of them and nothing else unrealized must reach a *verdict* — passed or failed —
    // rather than being answered `Unsupported`. `Unsupported` is ESS's word for a permanent
    // property of the target (`ess-conformance/src/target.rs:854`), and it stopped being
    // true of this domain the moment the admission landed.
    //
    // The set is computed from the suite and the registry, not written down: a command that
    // loses its dispatch arm moves back onto `UNREALIZED` and this fails, and a scenario the
    // contract adds is carried along without an edit here.
    //
    // `ExchangeCredential` is the twelfth and stays refused — `story:constrained-exchange`
    // owns token exchange and no crate realizes it — so scenarios naming it are excluded on
    // exactly the same rule as every other unrealized command.
    let suite = suite_json("credential6");
    let executed = Executed::of(&suite, DIGEST).expect("the suite executes");
    let report: serde_json::Value =
        serde_json::from_str(&executed.report).expect("report/2 is JSON");

    let unrealized: BTreeSet<&str> = commands::UNREALIZED
        .iter()
        .map(|(command, _, _)| *command)
        .collect();
    let driveable: BTreeSet<String> = scenarios(&suite)
        .into_iter()
        .filter(|(_, commands)| {
            commands
                .iter()
                .any(|command| command.starts_with("mandate.credential."))
                && commands
                    .iter()
                    .all(|command| !unrealized.contains(command.as_str()))
        })
        .map(|(id, _)| id)
        .collect();
    assert!(
        !driveable.is_empty(),
        "no scenario executes a realized credential command, so the admission bought nothing"
    );

    let unsupported: BTreeSet<String> = report["outcomes"]["unsupported"]
        .as_array()
        .expect("report/2 lists its unsupported outcomes")
        .iter()
        .map(|id| id.as_str().expect("a scenario identity").to_owned())
        .collect();
    let still_refused: Vec<&String> = driveable.intersection(&unsupported).collect();
    assert!(
        still_refused.is_empty(),
        "scenarios whose every command this target dispatches were answered Unsupported: \
         {still_refused:?}"
    );

    // And the domain is driven rather than merely not refused: at least one credential
    // scenario reaches a passing verdict against the real STS handlers. Without this the
    // case above is satisfied by a target that answers every credential command with a
    // wrong outcome instead of with a refusal.
    let passed: BTreeSet<String> = report["outcomes"]["passed"]
        .as_array()
        .expect("report/2 lists its passed outcomes")
        .iter()
        .map(|id| id.as_str().expect("a scenario identity").to_owned())
        .collect();
    assert!(
        passed
            .iter()
            .any(|id| id.starts_with("mandate.credential.")),
        "no credential scenario passed, so nothing shows the STS handlers were reached"
    );
}

/// The rungs a planning artifact cannot leave except by being archived.
///
/// `implemented`, `rejected` and `archived` are terminal on the story lifecycle: a story on
/// one of them owns nothing further, because the lifecycle admits no move back to `active`.
const TERMINAL_RUNGS: &[&str] = &["implemented", "rejected", "archived"];

/// What the target writes on a scenario it executed and whose expectation was unmet.
///
/// Not an attribution. `crates/mandate-conformance/src/lib.rs:758-776` writes it because which
/// story closes a disagreement between the contract and an implementation is a judgement the
/// target cannot make, and `xtask/src/conform.rs:105` refuses an authored ledger that repeats it.
/// The attribution for these rows lives in `contracts/expected-outcomes.json`.
const TARGET_MARKER: &str = "story:conform-gate";

#[test]
fn every_blocked_on_names_a_story_the_store_holds_and_has_not_finished() {
    // The class the adversary's first finding is an instance of, checked here rather than
    // reviewed. `every_scenario_that_did_not_pass_names_a_live_story` asserted the
    // *spelling* — `story:…` — which is not the property its name claims: a scenario
    // attributed to an `implemented` story is attributed to nobody, and the release stance
    // on `initiative:drift-enforcement` turns on every failed scenario naming a live owner.
    //
    // The check is machine-derived from the planning store on disk, so a story that reaches
    // `implemented` while a row still names it turns this red on the next run without
    // anyone remembering to look — which a hand-kept list of owners never would.
    //
    // Amended by the coordinator, 2026-09-21, for the same reason as the sibling case in
    // `adversary_conformance_1.rs`: `story:conform-gate` in `injections.json` is a marker and not
    // an attribution. `xtask/src/conform.rs:30-38` states the two-ledger rule — the target answers
    // for what it refused before dispatch or does not support, and a scenario that *executed* with
    // its expectation unmet is marked and attributed in the authored
    // `contracts/expected-outcomes.json`. Following the marker through makes this check stricter
    // than it was: the row must be attributed there, and that story must be live.
    let suite = suite_json("live7");
    let executed = Executed::of(&suite, DIGEST).expect("the suite executes");
    let injections: serde_json::Value =
        serde_json::from_str(&executed.injections).expect("the injection record is JSON");
    let store = repository().join(".engineering/planning/story");
    let authored: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repository().join("contracts/expected-outcomes.json"))
            .expect("the authored ledger is readable"),
    )
    .expect("the authored ledger is JSON");

    let mut checked = BTreeSet::new();
    let mut wrong: Vec<String> = Vec::new();
    for entry in injections["blocked"]
        .as_array()
        .expect("the injection record lists what it could not satisfy")
    {
        let mut story = entry["blocked_on"].as_str().expect("a story").to_owned();
        let scenario = entry["scenario"].as_str().expect("a scenario").to_owned();
        if story == TARGET_MARKER {
            let owner = authored["scenarios"]
                .as_array()
                .expect("the authored ledger lists its scenarios")
                .iter()
                .find(|row| row["id"].as_str() == Some(scenario.as_str()))
                .and_then(|row| row["blocked_on"].as_str())
                .map(str::to_owned);
            match owner {
                Some(owner) => story = owner,
                None => {
                    wrong.push(format!(
                        "`{scenario}` is marked `{TARGET_MARKER}` — executed, expectation unmet — \
                         and `contracts/expected-outcomes.json` attributes it to nobody"
                    ));
                    continue;
                }
            }
        }
        if !checked.insert(story.clone()) {
            continue;
        }
        let Some(slug) = story.strip_prefix("story:") else {
            wrong.push(format!(
                "`{scenario}` names `{story}`, which is not a story"
            ));
            continue;
        };
        let Ok(document) = std::fs::read_to_string(store.join(format!("{slug}.md"))) else {
            wrong.push(format!(
                "`{story}` (first named by `{scenario}`) is in no planning store this tree                  holds"
            ));
            continue;
        };
        let status = document
            .lines()
            .find_map(|line| line.strip_prefix("status:"))
            .map(str::trim)
            .unwrap_or("");
        if TERMINAL_RUNGS.contains(&status) {
            wrong.push(format!(
                "`{story}` (first named by `{scenario}`) is `{status}`, which is terminal"
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "a run may only attribute a gap to a story that exists and can still close it: \
         {wrong:#?}"
    );
    assert!(
        !checked.is_empty(),
        "nothing was attributed to any story, which cannot be true while the contract \
         declares commands no crate realizes"
    );
}

#[test]
fn an_armed_row_says_what_its_substituted_reader_did() {
    // The class behind the adversary's second finding. A row that said `armed` and nothing
    // else attributed a scenario's answer to a fault without showing the fault reached
    // anything — the same defect as reporting a manufactured expectation, one layer out.
    //
    // Two properties, and the second is the one that makes the first mean something: every
    // armed row carries a consultation count, and a row still spelled `armed` is one whose
    // substituted reader answered something the standing reader could not have. A row whose
    // reader was never consulted cannot be `armed`.
    let suite = suite_json("armed7");
    let executed = Executed::of(&suite, DIGEST).expect("the suite executes");
    let injections: serde_json::Value =
        serde_json::from_str(&executed.injections).expect("the injection record is JSON");
    let rows = injections["injections"]
        .as_array()
        .expect("the record lists every armed external outcome");

    let mut armed = 0_usize;
    for row in rows {
        let kind = row["kind"].as_str().expect("a row says what was done");
        let command = row["command"].as_str().expect("a row names its command");
        assert!(
            row["consulted"].is_u64(),
            "`{command}` is `{kind}` and carries no consultation count"
        );
        let consulted = row["consulted"].as_u64().expect("a count");
        if kind == "armed" || kind == "armed-unrefused" {
            if kind == "armed" {
                armed += 1;
            }
            assert!(
                consulted > 0,
                "`{command}` is recorded `{kind}` and its substituted reader was never \
                 consulted, so the row attributes the scenario to a fault that reached \
                 nothing; `armed-unreached` is the word for that"
            );
        }
        if kind == "armed-unreached" {
            assert_eq!(
                consulted, 0,
                "`{command}` is recorded `armed-unreached` and its reader answered \
                 {consulted} reads"
            );
        }
        if kind.starts_with("refused") || kind == "unsupported-command" {
            assert_eq!(
                consulted, 0,
                "`{command}` substituted no reader and reports {consulted} consultations"
            );
        }
    }
    assert!(
        armed > 0,
        "no injection reached a port at all, so the suite exercises no forced outcome"
    );

    // The label is read off the counts and nothing else, which is what `armed-unrefused`
    // now says: consulted this many times, refused nothing. It makes no claim about what
    // the scenario would have done unarmed — that is a second run of the suite, and
    // `tests/adversary_conformance_1.rs` is where it is made.
    //
    // `mandate.authorization.Check` is the one the adversary named outright: it took the
    // arming and discarded it, never substituting a reader, while the record said `armed`
    // at `GraphRead`. It now substitutes one — so it either consults it or reports zero,
    // and the record says which.
    let check = rows
        .iter()
        .find(|row| row["command"] == "mandate.authorization.Check")
        .expect("the suite arms an external outcome for `Check`");
    assert_eq!(
        check["port"].as_str(),
        Some("mandate_graph::port::GraphRead"),
        "`Check`'s fault is placed at the port its authority is read through"
    );
    assert!(
        check["consulted"].is_u64(),
        "`Check` records no consultation count"
    );
}

#[test]
fn an_integral_number_is_read_as_the_integer_the_contract_declares() {
    // `--suite-format 5` compiles `generation: 0` on an ESS `Integer` field to the JSON
    // token `0.0`. The contract declares the field an integer and the suite means the
    // integer, so a decoder that refused it would report a schema refusal for a value the
    // specification admits — and `mandate.identity.SecurityEpochRecorded.generation` is the
    // field the authored epoch scenarios establish through.
    let mut fields = BTreeMap::new();
    fields.insert(
        "generation".to_owned(),
        ess_primitives::node::Node::Number(
            ess_primitives::facts::Number::new(0.0).expect("zero is a number"),
        ),
    );
    let generation: i64 = mandate_conformance::node::field(&fields, "generation")
        .expect("an integral number reads as the integer it names");
    assert_eq!(generation, 0);

    // A value with a fractional part is left exactly as it is: nothing is rounded into a
    // different number on the way to a handler.
    fields.insert(
        "fraction".to_owned(),
        ess_primitives::node::Node::Number(
            ess_primitives::facts::Number::new(1.5).expect("a number"),
        ),
    );
    assert!(
        mandate_conformance::node::field::<i64>(&fields, "fraction").is_err(),
        "a fractional value was read as an integer"
    );
}

#[test]
fn every_port_method_the_substituted_reader_implements_counts_its_read() {
    // The class the adversary's pass-2 blocker is an instance of. It named four methods;
    // this calls **every** method of every trait `Substituted` implements and reports each
    // one that answered without counting, so the next method added to a port — or the next
    // one whose signature `cargo fmt` reflows onto a single line, which is how these four
    // came to be skipped — fails here instead of reaching a reader as `consulted: 0`.
    //
    // A reader that answers a handler and reports that it was never asked makes
    // `injections.json` say the arming reached nothing when it decided the clause, which is
    // the same defect as a manufactured expectation one layer out.
    use mandate_conformance::external::Substituted;
    use mandate_federation::publicclient::OAuthClientStore;
    use mandate_federation::register_client::ClientRegistrationAdmission;
    use mandate_federation::{ConnectionStore, ExternalPrincipalStore, LinkStore, PrincipalStore};
    use mandate_graph::port::{GraphQuery, GraphRead};
    use mandate_graph::topology::ResourceLookup;
    use mandate_identity::IdentityRead;
    use mandate_identity::SecurityEpochWrite;
    use mandate_sts::keys::{KeyMaterialResolver, SigningKeyReads};
    use mandate_sts::registry::ResourceServerReads;
    use mandate_sts::resolve::{CredentialReads, CredentialResolution};
    use mandate_types::{
        Audience, AuthoritySubject, AuthzRevision, CorrelationId, CredentialId, CredentialVerifier,
        EpochSnapshotRef, ExternalSubject, FederationConnectionId, Issuer, KeyReference,
        OAuthClientId, OrganizationId, PrincipalId, RedirectUri, ResourceId, ResourceRef,
        ResourceServerId, ResourceType, SecurityEpochTarget, SessionId, SigningKeyId, Uuid,
        VerifiedContext,
    };

    fn identity(tag: u8) -> Uuid {
        let mut bytes = [tag; 16];
        bytes[6] = 0x40 | (bytes[6] & 0x0f);
        bytes[8] = 0x80 | (bytes[8] & 0x3f);
        Uuid::from_bytes(bytes)
    }
    let context = VerifiedContext {
        subject: PrincipalId::new(identity(0x31)),
        actor: None,
        organization: OrganizationId::new(identity(0x32)),
        audience: Audience::new("audience".to_owned()),
        credential: CredentialId::new(identity(0x33)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("correlation".to_owned()),
    };
    let resource = ResourceRef {
        resource_type: ResourceType::new("resource_type"),
        resource_id: ResourceId::new(identity(0x34)),
    };
    let subject = AuthoritySubject::Principal(context.subject);
    let organization = OrganizationId::new(identity(0x32));
    let issuer = Issuer::new("https://issuer.example".to_owned());
    let reference = KeyReference::new("key_reference");
    let audience = Audience::new("audience".to_owned());
    let verifier = CredentialVerifier::new("verifier".to_owned());
    let revision = AuthzRevision::new("0".to_owned());

    // One closure per port method, named as `injections.json` names its port.
    /// One port method, named as `injections.json` names its port, and the call that
    /// exercises it.
    type Read = (&'static str, Box<dyn Fn(&Substituted)>);

    let methods: Vec<Read> = vec![
        (
            "ConnectionStore::connection",
            Box::new(|r: &Substituted| {
                let _ =
                    ConnectionStore::connection(r, &FederationConnectionId::new(identity(0x35)));
            }),
        ),
        (
            "ConnectionStore::enabled_for_issuer",
            Box::new(move |r: &Substituted| {
                let _ = ConnectionStore::enabled_for_issuer(r, &issuer);
            }),
        ),
        (
            "LinkStore::records_on_key",
            Box::new(|r: &Substituted| {
                let _ = LinkStore::records_on_key(
                    r,
                    &mandate_federation::record::ExternalKey {
                        organization_id: OrganizationId::new(identity(0x32)),
                        issuer: Issuer::new("https://issuer.example".to_owned()),
                        subject: ExternalSubject::new("subject".to_owned()),
                    },
                );
            }),
        ),
        (
            "ExternalPrincipalStore::external_principal",
            Box::new(|r: &Substituted| {
                let _ = ExternalPrincipalStore::external_principal(
                    r,
                    &mandate_types::ExternalPrincipalId::new(identity(0x36)),
                );
            }),
        ),
        (
            "PrincipalStore::organization_of",
            Box::new(|r: &Substituted| {
                let _ = PrincipalStore::organization_of(r, &PrincipalId::new(identity(0x31)));
            }),
        ),
        (
            "PrincipalStore::state_of",
            Box::new(|r: &Substituted| {
                let _ = PrincipalStore::state_of(r, &PrincipalId::new(identity(0x31)));
            }),
        ),
        (
            "OAuthClientStore::client",
            Box::new(|r: &Substituted| {
                let _ = OAuthClientStore::client(r, &OAuthClientId::new(identity(0x37)));
            }),
        ),
        (
            "IdentityRead::resolve",
            Box::new(|r: &Substituted| {
                let _ = IdentityRead::resolve(r, &SessionId::new(identity(0x38)));
            }),
        ),
        (
            "IdentityRead::principal",
            Box::new(|r: &Substituted| {
                let _ = IdentityRead::principal(r, &PrincipalId::new(identity(0x31)));
            }),
        ),
        (
            "IdentityRead::current",
            Box::new(|r: &Substituted| {
                let _ = IdentityRead::current(
                    r,
                    &SecurityEpochTarget::Principal(PrincipalId::new(identity(0x31))),
                );
            }),
        ),
        (
            "IdentityRead::snapshot",
            Box::new(|r: &Substituted| {
                let _ = IdentityRead::snapshot(r, &EpochSnapshotRef::new(identity(0x39)));
            }),
        ),
        (
            "IdentityRead::as_of",
            Box::new(|r: &Substituted| {
                let _ = IdentityRead::as_of(r);
            }),
        ),
        (
            "SecurityEpochWrite::increment",
            Box::new(|_r: &Substituted| {}),
        ),
        (
            "ResourceServerReads::resource_server",
            Box::new(|r: &Substituted| {
                let _ =
                    ResourceServerReads::resource_server(r, &ResourceServerId::new(identity(0x3a)));
            }),
        ),
        (
            "ResourceServerReads::registered",
            Box::new(move |r: &Substituted| {
                let _ = ResourceServerReads::registered(r, &organization, &audience);
            }),
        ),
        (
            "ResourceServerReads::admits_audience",
            Box::new(|r: &Substituted| {
                let _ = ResourceServerReads::admits_audience(
                    r,
                    &OrganizationId::new(identity(0x32)),
                    &Audience::new("audience".to_owned()),
                );
            }),
        ),
        (
            "CredentialReads::access_credential",
            Box::new(|r: &Substituted| {
                let _ = CredentialReads::access_credential(r, &CredentialId::new(identity(0x33)));
            }),
        ),
        (
            "CredentialResolution::resolve",
            Box::new(move |r: &Substituted| {
                let _ = CredentialResolution::resolve(r, &verifier);
            }),
        ),
        (
            "SigningKeyReads::signing_key",
            Box::new(|r: &Substituted| {
                let _ = SigningKeyReads::signing_key(r, &SigningKeyId::new(identity(0x3b)));
            }),
        ),
        (
            "SigningKeyReads::signing_keys",
            Box::new(|r: &Substituted| {
                let _ = SigningKeyReads::signing_keys(r);
            }),
        ),
        (
            "SigningKeyReads::holds_its_key_material",
            Box::new(|r: &Substituted| {
                let _ =
                    SigningKeyReads::holds_its_key_material(r, &SigningKeyId::new(identity(0x3b)));
            }),
        ),
        (
            "KeyMaterialResolver::thumbprint",
            Box::new(move |r: &Substituted| {
                let _ = KeyMaterialResolver::thumbprint(r, &reference);
            }),
        ),
        (
            "ClientRegistrationAdmission::admits_client_administration",
            Box::new(move |r: &Substituted| {
                let _ = ClientRegistrationAdmission::admits_client_administration(r, &context);
            }),
        ),
        (
            "ClientRegistrationAdmission::admits_organization",
            Box::new(|r: &Substituted| {
                let _ = ClientRegistrationAdmission::admits_organization(
                    r,
                    &OrganizationId::new(identity(0x32)),
                );
            }),
        ),
        (
            "ClientRegistrationAdmission::admits_redirect_uri",
            Box::new(|r: &Substituted| {
                let _ = ClientRegistrationAdmission::admits_redirect_uri(
                    r,
                    &OrganizationId::new(identity(0x32)),
                    &RedirectUri::new("https://client.example/callback".to_owned()),
                );
            }),
        ),
        (
            "GraphRead::check",
            Box::new(move |r: &Substituted| {
                let context = VerifiedContext {
                    subject: PrincipalId::new(identity(0x31)),
                    actor: None,
                    organization: OrganizationId::new(identity(0x32)),
                    audience: Audience::new("audience".to_owned()),
                    credential: CredentialId::new(identity(0x33)),
                    delegation: None,
                    execution: None,
                    correlation: CorrelationId::new("correlation".to_owned()),
                };
                let _ = GraphRead::check(
                    r,
                    &GraphQuery {
                        context: &context,
                        subject: &subject,
                        resource: &resource,
                        relation: "action",
                    },
                    &revision,
                );
            }),
        ),
        (
            "ResourceLookup::placement",
            Box::new(|r: &Substituted| {
                let _ = ResourceLookup::placement(
                    r,
                    &OrganizationId::new(identity(0x32)),
                    &ResourceRef {
                        resource_type: ResourceType::new("resource_type"),
                        resource_id: ResourceId::new(identity(0x34)),
                    },
                );
            }),
        ),
    ];

    let mut uncounted: Vec<&str> = Vec::new();
    for (name, call) in &methods {
        if *name == "SecurityEpochWrite::increment" {
            // The one write port, which needs `&mut` and so cannot share the closure shape.
            let mut reader = Substituted::new();
            let _ = SecurityEpochWrite::increment(
                &mut reader,
                &VerifiedContext {
                    subject: PrincipalId::new(identity(0x31)),
                    actor: None,
                    organization: OrganizationId::new(identity(0x32)),
                    audience: Audience::new("audience".to_owned()),
                    credential: CredentialId::new(identity(0x33)),
                    delegation: None,
                    execution: None,
                    correlation: CorrelationId::new("correlation".to_owned()),
                },
                &SecurityEpochTarget::Principal(PrincipalId::new(identity(0x31))),
                mandate_identity::StreamVersion::INITIAL,
            );
            if reader.consulted() == 0 {
                uncounted.push(name);
            }
            continue;
        }
        let reader = Substituted::new();
        call(&reader);
        if reader.consulted() == 0 {
            uncounted.push(name);
        }
    }
    assert!(
        uncounted.is_empty(),
        "these port methods of `Substituted` answer a handler and report that nothing was \
         asked, so an `injections.json` row for a command that consults only them reads \
         `armed-unreached`, `consulted: 0`: {uncounted:#?}"
    );
    // The list above is hand-written, and a hand-written list of what to check is the
    // defect an adversary extends one entry at a time. So it is checked against the source
    // it is a list of: every `fn` inside an `impl … for Substituted` block must appear here
    // by name. A method added to a port and not to this list fails on the next run rather
    // than reaching a reader as an uncounted read.
    let source =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/external.rs"))
            .expect("this crate's own source is readable");
    let mut implemented: BTreeSet<String> = BTreeSet::new();
    let mut inside = false;
    for line in source.lines() {
        if line.starts_with("impl ") {
            inside = line.ends_with("for Substituted {") && !line.contains("Default for");
            continue;
        }
        if inside && let Some(rest) = line.strip_prefix("    fn ") {
            implemented.insert(rest.split(['(', '<']).next().unwrap_or_default().to_owned());
        }
    }
    assert!(
        implemented.len() >= 20,
        "the source scan found {} port methods, which cannot be right",
        implemented.len()
    );
    let listed: BTreeSet<String> = methods
        .iter()
        .filter_map(|(name, _)| name.split("::").nth(1).map(ToOwned::to_owned))
        .collect();
    let unexercised: Vec<&String> = implemented.difference(&listed).collect();
    assert!(
        unexercised.is_empty(),
        "`Substituted` implements port methods this case never calls, so nothing shows \
         they count their reads: {unexercised:?}"
    );
}
