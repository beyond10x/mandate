//! Adversary pass 1 on `story:ess-repin-0-59`.
//!
//! The unit moved the `mandate.federation` commands onto `standing_first`
//! (`src/commands/federation.rs`) and documented a new ledger kind, `input-decided`, in
//! `src/external.rs`: "no fault was placed: the command, decided over the standing readers,
//! already answered the forced branch". It also re-attributed the new ESS 0.59 `wrong-state`
//! scenarios in `contracts/expected-outcomes.json`. These cases drive those documents against
//! the code, over suites derived from the committed `generated/conformance/suite.json`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use mandate_conformance::Executed;
use serde_json::{Value, json};

const DIGEST: &str = "0123456789ab";
const REGISTER: &str = "mandate.federation.RegisterFederationConnection";
const DISABLE: &str = "mandate.federation.DisableFederationConnection";

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate sits two levels below the repository root")
        .to_path_buf()
}

fn read(path: &str) -> Value {
    let path = repository().join(path);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    serde_json::from_str(&text).expect("the document is JSON")
}

fn suite() -> Value {
    read("generated/conformance/suite.json")
}

fn steps_of<'a>(suite: &'a mut Value, scenario: &str) -> &'a mut Vec<Value> {
    suite["scenarios"][scenario]["steps"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("{scenario} is in the committed suite"))
}

fn run(suite: &Value) -> Executed {
    Executed::of(&suite.to_string(), DIGEST).expect("the suite executes")
}

/// Terminal category per scenario.
fn terminal(report: &str) -> BTreeMap<String, String> {
    let report: Value = serde_json::from_str(report).expect("report/2 is JSON");
    let mut placed = BTreeMap::new();
    for (category, listed) in report["outcomes"].as_object().expect("outcomes") {
        for id in listed.as_array().expect("a list") {
            placed.insert(id.as_str().expect("an id").to_owned(), category.clone());
        }
    }
    placed
}

/// The ledger row for `(scenario, command)`.
fn row(executed: &Executed, scenario: &str, command: &str) -> Option<Value> {
    let injections: Value = serde_json::from_str(&executed.injections).expect("JSON");
    injections["injections"]
        .as_array()
        .expect("rows")
        .iter()
        .find(|row| row["scenario"] == scenario && row["command"] == command)
        .cloned()
}

/// `input-decided` claims the standing decision "already answered the forced branch". The
/// arming forces `denied`; a standing refusal on another branch (`wrong-state`, a disabled
/// connection disabled again) is not that branch, so the row must not say it is.
///
/// `standing_first` tests `standing.is_err()` and never compares the refusal's outcome with
/// the forced one: `Armed` keeps the command and drops `request.force.outcome`
/// (`src/lib.rs` `configure_external_outcome`, `src/external.rs` `Armed`).
#[test]
fn a_standing_refusal_on_another_branch_is_not_recorded_as_the_forced_one() {
    const SCENARIO: &str = "mandate.federation/authored/federation-disabled-connection";
    let mut suite = suite();
    let steps = steps_of(&mut suite, SCENARIO);
    // 0..=6: register `conn`, disable it, accepted. Then arm `denied` for a second disable.
    let disable = steps[4].clone();
    steps.truncate(7);
    steps.push(json!({"step": "configure_external_outcome",
        "force": {"command": DISABLE, "outcome": "denied"}}));
    steps.push(disable);
    steps.push(json!({"step": "expect_outcome",
        "outcome": {"command": DISABLE, "outcome": "denied"}}));
    let executed = run(&suite);
    let disabled = row(&executed, SCENARIO, DISABLE).expect("the arming is recorded");
    assert_ne!(
        disabled["kind"],
        "input-decided",
        "the standing decision refused the second disable as `wrong-state` \
         (`ConnectionDisabled`), the arming forced `denied`, and the row says the input \
         already answered the forced branch; scenario is `{}`",
        terminal(&executed.report)
            .get(SCENARIO)
            .map_or("absent", String::as_str)
    );
}

/// An unarmed invocation after an `input-decided` one rewrites that row.
///
/// `standing_first`'s unarmed branch calls `live.record_reads`, and `Ledger::consulted`
/// rewrites the **last** row for `(scenario, command)` whether or not this invocation was
/// the armed one, so a later unarmed registration in the same scenario turns
/// `input-decided` into `armed-unreached`.
#[test]
fn an_unarmed_call_after_the_armed_one_leaves_the_armed_row_as_it_was() {
    const SCENARIO: &str = "mandate.federation/authored/federation-ambiguous-tenant";
    let mut suite = suite();
    let steps = steps_of(&mut suite, SCENARIO);
    let mut later = steps[0].clone();
    later["input"]["issuer"]["value"] = json!("https://second.example.test");
    later["input"]["context"]["value"]["correlation"] = json!("adversary-later");
    // After step 8 (the input-decided registration and its checks).
    steps.insert(9, later);
    steps.insert(
        10,
        json!({"step": "expect_outcome", "outcome": {"command": REGISTER, "outcome": "accepted"}}),
    );
    let executed = run(&suite);
    let placed = terminal(&executed.report);
    assert_eq!(
        placed.get(SCENARIO).map(String::as_str),
        Some("passed"),
        "the derived scenario must still pass for this case to be about the ledger"
    );
    let registered = row(&executed, SCENARIO, REGISTER).expect("the arming is recorded");
    assert_eq!(
        registered["kind"], "input-decided",
        "the armed registration was decided by its input; an unarmed registration later in the \
         scenario relabelled its row: {registered}"
    );
}

/// `src/external.rs`: "No authored scenario outside `mandate.federation` answers differently
/// armed and unarmed except one written to reach a write port the input cannot refuse."
/// Driven, not read.
///
/// One authored scenario is set aside by name, and it is checked the other way round: it
/// exists to reach the clause of `IncrementSecurityEpoch`'s declared cause no input decides,
/// "atomic increment cannot commit", so armed it must answer differently from unarmed.
#[test]
fn no_authored_scenario_outside_federation_answers_differently_unarmed() {
    const WRITTEN_FOR_THE_FAULT: &str = "mandate.identity/authored/epoch-increment-commit-fails";
    let armed = suite();
    let mut unarmed = armed.clone();
    let mut checked = Vec::new();
    for (id, scenario) in unarmed["scenarios"]
        .as_object_mut()
        .expect("scenarios")
        .iter_mut()
    {
        if !id.contains("/authored/")
            || id.starts_with("mandate.federation/")
            || id == WRITTEN_FOR_THE_FAULT
        {
            continue;
        }
        let steps = scenario["steps"].as_array_mut().expect("steps");
        let before = steps.len();
        steps.retain(|step| step["step"] != "configure_external_outcome");
        if steps.len() != before {
            checked.push(id.clone());
        }
    }
    assert!(
        !checked.is_empty(),
        "no authored scenario outside federation is armed"
    );
    let with = terminal(&run(&armed).report);
    let mut unarmed_fault = armed.clone();
    steps_of(&mut unarmed_fault, WRITTEN_FOR_THE_FAULT)
        .retain(|step| step["step"] != "configure_external_outcome");
    let without_fault = terminal(&run(&unarmed_fault).report);
    assert_eq!(
        with.get(WRITTEN_FOR_THE_FAULT).map(String::as_str),
        Some("passed"),
        "{WRITTEN_FOR_THE_FAULT} passes armed"
    );
    assert_ne!(
        with.get(WRITTEN_FOR_THE_FAULT),
        without_fault.get(WRITTEN_FOR_THE_FAULT),
        "{WRITTEN_FOR_THE_FAULT} answers the same unarmed, so its arming reaches no write port"
    );
    let without = terminal(&run(&unarmed).report);
    let differ: Vec<String> = checked
        .iter()
        .filter(|id| with.get(*id) != without.get(*id))
        .map(|id| {
            format!(
                "{id}: armed {:?}, unarmed {:?}",
                with.get(id),
                without.get(id)
            )
        })
        .collect();
    assert!(
        differ.is_empty(),
        "of {} armed authored scenarios outside federation, these answer differently \
         unarmed: {differ:#?}",
        checked.len()
    );
}

/// An `armed` row says, per the table in `src/external.rs`, that the substituted reader
/// "answered something the standing reader could not have". Under the 0.59 suite
/// `mandate.credential.RegisterResourceServer/outcome/denied` is recorded `armed` and reaches
/// the same category with every arming removed. `tests/adversary_conformance_1.rs` now sets
/// that row aside by a computed rule rather than letting it fail; the row's label is still
/// the claim a reader of `injections.json` is given.
#[test]
fn every_row_recorded_armed_is_a_fault_the_scenario_needed() {
    let armed = suite();
    let executed = run(&armed);
    let injections: Value = serde_json::from_str(&executed.injections).expect("JSON");
    let mut unarmed = armed.clone();
    for scenario in unarmed["scenarios"]
        .as_object_mut()
        .expect("scenarios")
        .values_mut()
    {
        scenario["steps"]
            .as_array_mut()
            .expect("steps")
            .retain(|step| step["step"] != "configure_external_outcome");
    }
    let with = terminal(&executed.report);
    let without = terminal(&run(&unarmed).report);
    let inert: Vec<String> = injections["injections"]
        .as_array()
        .expect("rows")
        .iter()
        .filter(|row| row["kind"] == "armed")
        .filter_map(|row| row["scenario"].as_str())
        .filter(|id| with.get(*id) == without.get(*id))
        .map(|id| format!("{id} is {:?} armed and unarmed", with.get(id)))
        .collect();
    assert!(
        inert.is_empty(),
        "rows recorded `armed` whose fault changed nothing: {inert:#?}"
    );
}

/// The new `*/outcome/wrong-state` scenarios attributed to
/// `story:ess-synthesizer-prerequisites` — a story whose whole gap is "the synthesizer
/// arranges no prerequisite for an accepted outcome" and whose acceptance is that the ESS fix
/// makes them pass. A `wrong-state` scenario starts from an empty state on purpose ("for an
/// identity no record carries"): there is nothing for a synthesizer to arrange. If the very
/// same scenario passes once its expected branch reads `denied`, the target executed it to
/// the end on the synthesized input and answered `denied` where the contract says
/// `wrong-state`: a refusal-branch disagreement between handler and contract, which no
/// synthesizer release closes.
///
/// Every failed `wrong-state` row is relabelled, whoever owns it, so the case is not vacuous
/// once no row is attributed there: at least one relabelled row must pass, which shows the
/// relabelling reaches a handler's answer and the attribution check below can fire.
#[test]
fn a_wrong_state_scenario_the_handler_answers_denied_is_not_a_synthesizer_gap() {
    let ledger = read("contracts/expected-outcomes.json");
    let failed: Vec<(String, String)> = ledger["scenarios"]
        .as_array()
        .expect("rows")
        .iter()
        .filter(|row| row["outcome"] == "failed")
        .filter_map(|row| Some((row["id"].as_str()?, row["blocked_on"].as_str()?)))
        .filter(|(id, _)| id.ends_with("/outcome/wrong-state"))
        .map(|(id, owner)| (id.to_owned(), owner.to_owned()))
        .collect();
    assert!(
        !failed.is_empty(),
        "no failed wrong-state row is in the ledger"
    );
    let mut relabelled = suite();
    for (id, _) in &failed {
        for step in steps_of(&mut relabelled, id).iter_mut() {
            if step["step"] == "expect_outcome" && step["outcome"]["outcome"] == "wrong-state" {
                step["outcome"]["outcome"] = json!("denied");
            }
        }
    }
    let placed = terminal(&run(&relabelled).report);
    let passes = |id: &String| placed.get(id).map(String::as_str) == Some("passed");
    assert!(
        failed.iter().any(|(id, _)| passes(id)),
        "no failed wrong-state row passes once it expects `denied`, so this case decides nothing"
    );
    let attributed: Vec<&String> = failed
        .iter()
        .filter(|(_, owner)| owner == "story:ess-synthesizer-prerequisites")
        .map(|(id, _)| id)
        .collect();
    let misowned: Vec<&String> = attributed.iter().copied().filter(|id| passes(id)).collect();
    assert!(
        misowned.is_empty(),
        "{} of {} `wrong-state` rows attributed to story:ess-synthesizer-prerequisites pass \
         unchanged once they expect `denied`: the handler decided them on the synthesized input \
         and chose another refusal branch, which is not that story's gap: {misowned:#?}",
        misowned.len(),
        attributed.len()
    );
}
