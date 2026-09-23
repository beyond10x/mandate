//! Adversary pass 2 on `story:federation-rule-disjointness`.
//!
//! `generated/conformance/suite.json` carries `federation-ambiguous-tenant`, whose purpose
//! opens "`tenant resolution has zero or multiple matches`, multiple", and
//! `contracts/use-cases/federated-login.json` step 6 lists it as evidence that "a tenant that
//! resolves to zero or to more than one organization is denied". These cases drive the
//! shipped writer and authenticator from that document and ask whether the scenario still
//! reaches the multiple-match refusal it is named for.

use std::path::PathBuf;

use serde_json::Value;

use mandate_federation::authenticate::{AuthenticateFederation, authenticate_federation};
use mandate_federation::record::{
    FederationEvent, Projection, RegisterFederationConnection, register_federation_connection,
};
use mandate_federation::verifier::{ConstructedVerifier, VerifiedProof};
use mandate_federation::{
    DenialClause, RecordingSessionIssuer, RequestContext, SequentialAllocator,
};
use mandate_model::TenantResolutionRule;
use mandate_types::{
    Audience, ClientId, CorrelationId, CredentialId, CredentialProof, ExternalSubject,
    FederationConnectionId, Issuer, SigningAlgorithm, Timestamp, VerifiedContext,
};

const REGISTER: &str = "mandate.federation.RegisterFederationConnection";
const AUTHENTICATE: &str = "mandate.federation.AuthenticateFederation";
const SCENARIO: &str = "mandate.federation/authored/federation-ambiguous-tenant";

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

fn registration(input: &Value) -> RegisterFederationConnection {
    RegisterFederationConnection {
        context: serde_json::from_value::<VerifiedContext>(literal(input, "context").unwrap())
            .unwrap(),
        issuer: Issuer::new(literal(input, "issuer").unwrap().as_str().unwrap()),
        client_id: ClientId::new(literal(input, "client_id").unwrap().as_str().unwrap()),
        tenant_resolution: serde_json::from_value::<TenantResolutionRule>(
            literal(input, "tenant_resolution").unwrap(),
        )
        .unwrap(),
        jit_provisioning: literal(input, "jit_provisioning")
            .unwrap()
            .as_bool()
            .unwrap(),
    }
}

/// Standard or URL-safe base64, padding optional. A probe decoder, not a codec.
fn unbase64(text: &str) -> Vec<u8> {
    let value = |c: u8| -> u32 {
        match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            other => panic!("not base64: {other}"),
        }
    };
    let digits: Vec<u32> = text.bytes().filter(|c| *c != b'=').map(value).collect();
    let mut out = Vec::new();
    for chunk in digits.chunks(4) {
        let mut acc = 0u32;
        for (i, d) in chunk.iter().enumerate() {
            acc |= d << (18 - 6 * i);
        }
        let bytes = acc.to_be_bytes();
        out.extend_from_slice(&bytes[1..chunk.len()]);
    }
    out
}

/// The claims the scenario's proof literal carries, admitted as validated: the most a
/// verifier could give the authenticator, so a refusal here is tenant resolution's or the
/// link's, never the signature's.
fn verified_from(proof_literal: &str) -> Option<VerifiedProof> {
    let token = String::from_utf8(unbase64(proof_literal)).ok()?;
    let payload = token.split('.').nth(1)?;
    let claims: Value = serde_json::from_slice(&unbase64(payload)).ok()?;
    let mut proof = VerifiedProof::new(
        Issuer::new(claims["iss"].as_str().unwrap()),
        ExternalSubject::new(claims["sub"].as_str().unwrap()),
        ClientId::new(claims["aud"].as_str().unwrap()),
    );
    for (name, value) in claims.as_object().unwrap() {
        if let (false, Some(value)) = (
            ["iss", "sub", "aud"].contains(&name.as_str()),
            value.as_str(),
        ) {
            proof = proof.with_verified_claim(name, value);
        }
    }
    Some(proof)
}

/// Replay the scenario: registrations the writer accepts are folded, the first accepted
/// registration is the captured `conn`, and the login step is answered by the shipped
/// authenticator. Returns the login's clause and the number of connections standing.
fn replay(steps: &[Value]) -> (Option<Result<(), DenialClause>>, usize) {
    let mut log = Vec::new();
    let mut allocator = SequentialAllocator::new();
    let mut captured: Option<FederationConnectionId> = None;
    let mut login = None;
    for step in steps {
        if step.get("step").and_then(Value::as_str) != Some("execute_command") {
            continue;
        }
        let input = step.get("input").unwrap();
        match step.get("command").and_then(Value::as_str) {
            Some(REGISTER) => {
                let held = Projection::fold(&log).unwrap();
                if let Ok(registered) =
                    register_federation_connection(&registration(input), &held, &mut allocator)
                {
                    if let FederationEvent::FederationConnectionCreated { connection_id, .. } =
                        &registered.event
                    {
                        captured.get_or_insert(*connection_id);
                    }
                    log.push(registered.event);
                }
            }
            Some(AUTHENTICATE) => {
                let proof_literal = literal(input, "proof").unwrap();
                let proof_literal = proof_literal.as_str().unwrap();
                let Some(verified) = verified_from(proof_literal) else {
                    continue;
                };
                let verifier =
                    ConstructedVerifier::admitting(&[SigningAlgorithm::new("RS256")], verified)
                        .unwrap();
                let projection = Projection::fold(&log).unwrap();
                let answered = authenticate_federation(
                    &AuthenticateFederation {
                        connection_id: captured.expect("conn was captured"),
                        proof: CredentialProof::from_bytes(unbase64(proof_literal)),
                    },
                    &RequestContext {
                        audience: Audience::new("mandate"),
                        correlation: CorrelationId::new("adversary-disjointness-2"),
                        credential: CredentialId::new(mandate_types::value::Uuid::from_bytes(
                            [0xc1; 16],
                        )),
                        at: Timestamp::new("2026-01-05T09:00:02Z"),
                    },
                    &verifier,
                    &projection,
                    &projection,
                    &mut RecordingSessionIssuer::new(),
                );
                login = Some(answered.map(|_| ()).map_err(|denied| denied.clause));
            }
            _ => {}
        }
    }
    (login, log.len())
}

fn scenario_steps(suite: &Value, id: &str) -> Vec<Value> {
    suite
        .get("scenarios")
        .and_then(|all| all.get(id))
        .and_then(|scenario| scenario.get("steps"))
        .and_then(Value::as_array)
        .expect("the scenario is in the generated suite")
        .clone()
}

/// The acceptance-level question: does the scenario named for the multiple-match clause
/// reach it? Driven from the committed suite with every claim of its proof admitted as
/// validated, the login must be refused `TenantAmbiguous`.
#[test]
fn the_ambiguous_tenant_scenario_is_refused_as_ambiguous() {
    let suite = read("generated/conformance/suite.json");
    let (login, standing) = replay(&scenario_steps(&suite, SCENARIO));
    let login = login.expect("the scenario logs in with a JWT proof");

    assert_eq!(
        login,
        Err(DenialClause::TenantAmbiguous),
        "{SCENARIO} is named for the multiple-match refusal; with {standing} connection(s) \
         standing its login is refused for another reason"
    );
}

/// The contract drift: `federated-login.json` step 6 says a tenant resolving to more than
/// one organization is denied, and cites authored scenarios as `passed` evidence. At least
/// one of those scenarios must be one in which more than one organization could resolve —
/// two connections of different organizations standing on the issuer the login presents.
#[test]
fn some_scenario_cited_for_more_than_one_organization_stands_two_organizations() {
    let use_case = read("contracts/use-cases/federated-login.json");
    let suite = read("generated/conformance/suite.json");
    let mut cited = Vec::new();
    let mut steps_found = Vec::new();
    let mut stack = vec![&use_case];
    while let Some(node) = stack.pop() {
        match node {
            Value::Object(map) => {
                if map.get("command").and_then(Value::as_str) == Some(AUTHENTICATE)
                    && map
                        .get("statement")
                        .and_then(Value::as_str)
                        .is_some_and(|s| s.contains("more than one organization"))
                {
                    steps_found.push(map.get("step").cloned());
                    for evidence in map.get("evidence").and_then(Value::as_array).unwrap() {
                        let id = evidence["id"].as_str().unwrap();
                        if evidence["kind"] == "scenario" && id.contains("/authored/") {
                            cited.push(id.to_owned());
                        }
                    }
                }
                stack.extend(map.values());
            }
            Value::Array(items) => stack.extend(items.iter()),
            _ => {}
        }
    }
    assert!(!steps_found.is_empty(), "the use case makes the claim");

    let standing: Vec<(String, usize, Option<Result<(), DenialClause>>)> = cited
        .iter()
        .filter(|id| {
            scenario_steps(&suite, id)
                .iter()
                .any(|step| step.get("command").and_then(Value::as_str) == Some(REGISTER))
                && !scenario_steps(&suite, id).iter().any(|step| {
                    matches!(
                        step.get("step").and_then(Value::as_str),
                        Some("configure_external_outcome" | "establish_entity")
                    )
                })
        })
        .map(|id| {
            let (login, standing) = replay(&scenario_steps(&suite, id));
            (id.clone(), standing, login)
        })
        .collect();

    assert!(
        standing.iter().any(|(_, n, _)| *n >= 2),
        "step {steps_found:?} cites {} authored scenarios for 'more than one organization is \
         denied'; replayed, none stands two connections: {standing:?}",
        cited.len()
    );
}
