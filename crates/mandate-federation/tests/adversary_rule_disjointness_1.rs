//! Adversary pass 1 on `story:federation-rule-disjointness`.
//!
//! The authored conformance scenarios are a contract document: `generated/conformance/suite.json`
//! states, per `RegisterFederationConnection` step, whether the command is `accepted` or
//! `denied`, and `contracts/expected-outcomes.json` says every federation scenario `passed`.
//! These cases replay the registration steps of that document through the shipped writer,
//! against a fold of the registrations the document says were accepted before them, and
//! compare the writer's answer with the document's.

use std::path::PathBuf;

use serde_json::Value;

use mandate_federation::SequentialAllocator;
use mandate_federation::record::{
    Projection, RegisterFederationConnection, register_federation_connection,
};
use mandate_model::TenantResolutionRule;
use mandate_types::{ClientId, Issuer, VerifiedContext};

const REGISTER: &str = "mandate.federation.RegisterFederationConnection";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> Value {
    let text = std::fs::read_to_string(root().join(path)).expect("the document is readable");
    serde_json::from_str(&text).expect("the document is JSON")
}

fn literal(input: &Value, field: &str) -> Option<Value> {
    let node = input.get(field)?;
    (node.get("kind")? == "literal").then(|| node.get("value").cloned())?
}

fn registration(input: &Value) -> Option<RegisterFederationConnection> {
    Some(RegisterFederationConnection {
        context: serde_json::from_value::<VerifiedContext>(literal(input, "context")?).ok()?,
        issuer: Issuer::new(literal(input, "issuer")?.as_str()?),
        client_id: ClientId::new(literal(input, "client_id")?.as_str()?),
        tenant_resolution: serde_json::from_value::<TenantResolutionRule>(literal(
            input,
            "tenant_resolution",
        )?)
        .ok()?,
        jit_provisioning: literal(input, "jit_provisioning")?.as_bool()?,
    })
}

/// Replay one scenario's registrations; answer `(step index, document says, writer says)` for
/// every registration where the two disagree. `None` when the scenario is outside what this
/// replay can decide (a non-literal input, an arranged entity, a configured external outcome,
/// or a connection disabled mid-scenario).
fn disagreements(steps: &[Value]) -> Option<Vec<(usize, String, String)>> {
    let skipped = steps.iter().any(|step| {
        matches!(
            step.get("step").and_then(Value::as_str),
            Some("configure_external_outcome" | "establish_entity")
        ) || step.get("command").and_then(Value::as_str)
            == Some("mandate.federation.DisableFederationConnection")
    });
    if skipped {
        return None;
    }
    let mut log = Vec::new();
    let mut allocator = SequentialAllocator::new();
    let mut found = Vec::new();
    for (index, step) in steps.iter().enumerate() {
        if step.get("command").and_then(Value::as_str) != Some(REGISTER)
            || step.get("step").and_then(Value::as_str) != Some("execute_command")
        {
            continue;
        }
        let input = registration(step.get("input")?)?;
        let stated = steps[index + 1..]
            .iter()
            .find(|next| next.get("step").and_then(Value::as_str) == Some("expect_outcome"))?
            .pointer("/outcome/outcome")?
            .as_str()?
            .to_owned();
        let held = Projection::fold(&log).ok()?;
        let answered = match register_federation_connection(&input, &held, &mut allocator) {
            Ok(registered) => {
                if stated == "accepted" {
                    log.push(registered.event);
                }
                String::from("accepted")
            }
            Err(denied) => format!("denied {:?}", denied.clause),
        };
        if !answered.starts_with(&stated) {
            found.push((index, stated, answered));
        }
    }
    Some(found)
}

/// `federation-ambiguous-tenant` is the authored scenario for the multiple-match clause. It
/// registers `{tid: acme}` for organization `a1` and then `{dept: acme}` for organization
/// `a2` on one issuer, and states both registrations `accepted`. The story's `collides`
/// refuses the second, so the scenario the conformance run replays no longer reaches its
/// `AuthenticateFederation` step as authored.
#[test]
fn the_authored_ambiguous_tenant_scenario_registers_both_connections() {
    let suite = read("generated/conformance/suite.json");
    let scenario = suite
        .pointer("/scenarios/mandate.federation~1authored~1federation-ambiguous-tenant/steps")
        .and_then(Value::as_array)
        .expect("the authored scenario is in the generated suite");

    let found = disagreements(scenario).expect("the scenario is replayable here");

    assert!(
        found.is_empty(),
        "the contract document states each registration's outcome and the writer answers \
         differently: {found:?}"
    );
}

/// The same comparison over every authored scenario this replay can decide, so a second
/// scenario arranging two different-claim rules on one issuer is found too.
#[test]
fn every_replayable_scenarios_registrations_answer_as_the_suite_states() {
    let suite = read("generated/conformance/suite.json");
    let scenarios = suite
        .get("scenarios")
        .and_then(Value::as_object)
        .expect("the suite has scenarios");
    let mut decided = 0;
    let mut wrong = Vec::new();
    for (id, scenario) in scenarios {
        // Only the authored scenarios: the per-outcome ones are driven through the
        // conformance target's injections (`contracts/conformance/injections.json`).
        if !id.contains("/authored/") {
            continue;
        }
        let Some(steps) = scenario.get("steps").and_then(Value::as_array) else {
            continue;
        };
        if !steps
            .iter()
            .any(|step| step.get("command").and_then(Value::as_str) == Some(REGISTER))
        {
            continue;
        }
        if let Some(found) = disagreements(steps) {
            decided += 1;
            if !found.is_empty() {
                wrong.push((id.clone(), found));
            }
        }
    }

    assert!(decided > 0, "the replay decided no scenario at all");
    assert!(
        wrong.is_empty(),
        "{} of {decided} replayable scenarios disagree with the writer: {wrong:?}",
        wrong.len()
    );
}
