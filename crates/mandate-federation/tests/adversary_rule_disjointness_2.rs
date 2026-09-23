//! Adversary pass 2 on `story:federation-rule-disjointness`.
//!
//! The pass found `federation-ambiguous-tenant` named and cited (`federated-login.json`
//! step 6) for the multiple-match refusal it can no longer reach: the story refuses the
//! overlapping registration that would arrange it. Rewritten on the coordinator's ruling
//! (correction round 2) to assert what the scenario now proves, and to pin the guard over
//! every authored scenario. Both drive the shipped writer and authenticator from
//! `generated/conformance/suite.json`.

use std::collections::{BTreeMap, BTreeSet};
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

/// What replaying one scenario through the shipped writer and authenticator answered.
struct Replayed {
    /// Each registration step in order: admitted, or refused on this clause.
    registrations: Vec<Result<(), DenialClause>>,
    /// The login step's answer, when the scenario logs in with a JWT proof.
    login: Option<Result<(), DenialClause>>,
    /// The connections the writer admitted.
    standing: Vec<FederationEvent>,
}

/// Replay the scenario: registrations the writer accepts are folded, the first accepted
/// registration is the captured `conn`, and the login step is answered by the shipped
/// authenticator.
fn replay(steps: &[Value]) -> Replayed {
    let mut log = Vec::new();
    let mut allocator = SequentialAllocator::new();
    let mut captured: Option<FederationConnectionId> = None;
    let mut registrations = Vec::new();
    let mut login = None;
    for step in steps {
        if step.get("step").and_then(Value::as_str) != Some("execute_command") {
            continue;
        }
        let input = step.get("input").unwrap();
        match step.get("command").and_then(Value::as_str) {
            Some(REGISTER) => {
                let held = Projection::fold(&log).unwrap();
                match register_federation_connection(&registration(input), &held, &mut allocator) {
                    Ok(registered) => {
                        if let FederationEvent::FederationConnectionCreated {
                            connection_id, ..
                        } = &registered.event
                        {
                            captured.get_or_insert(*connection_id);
                        }
                        log.push(registered.event);
                        registrations.push(Ok(()));
                    }
                    Err(denied) => registrations.push(Err(denied.clause)),
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
    Replayed {
        registrations,
        login,
        standing: log,
    }
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

/// What `federation-ambiguous-tenant` proves now that the overlapping rule is refused:
/// organization `a2`'s `{dept: acme}` beside organization `a1`'s `{tid: acme}` is refused at
/// registration on the unadmitted-configuration clause, one connection stands, and the
/// incumbent's login — its proof carries both claims — passes tenant resolution and is
/// refused only for want of a link. Driven from the committed suite with every claim of the
/// proof admitted as validated, so the refusal is the link's and never the signature's.
#[test]
fn the_ambiguous_tenant_scenario_refuses_the_overlapping_registration_and_the_login_for_want_of_a_link()
 {
    let suite = read("generated/conformance/suite.json");
    let replayed = replay(&scenario_steps(&suite, SCENARIO));

    assert_eq!(
        replayed.registrations,
        vec![Ok(()), Err(DenialClause::TenantResolutionUnadmitted)],
        "{SCENARIO}: the incumbent registers and the overlapping second organization is refused"
    );
    assert_eq!(
        replayed.standing.len(),
        1,
        "{SCENARIO}: exactly one connection stands"
    );
    assert_eq!(
        replayed
            .login
            .expect("the scenario logs in with a JWT proof"),
        Err(DenialClause::LinkAbsent),
        "{SCENARIO}: the login resolves one tenant and is refused for want of a link"
    );
}

/// The guard, pinned over every authored scenario: none can stand two connections of
/// different organizations on one issuer, because the writer refuses the second. Every
/// authored scenario that registers a connection is replayed, and every one of them must be
/// replayable, so a scenario the replay cannot read fails here rather than being skipped.
#[test]
fn no_authored_scenario_stands_two_organizations_connections_on_one_issuer() {
    let suite = read("generated/conformance/suite.json");
    let scenarios = suite
        .get("scenarios")
        .and_then(Value::as_object)
        .expect("the suite has scenarios");
    let mut decided = 0;
    let mut shared = Vec::new();
    for (id, scenario) in scenarios {
        if !id.contains("/authored/") {
            continue;
        }
        let steps = scenario.get("steps").and_then(Value::as_array).unwrap();
        if !steps
            .iter()
            .any(|step| step.get("command").and_then(Value::as_str) == Some(REGISTER))
        {
            continue;
        }
        decided += 1;
        let mut organizations: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for event in replay(steps).standing {
            if let FederationEvent::FederationConnectionCreated {
                issuer, context, ..
            } = event
            {
                organizations
                    .entry(issuer.as_str().to_owned())
                    .or_default()
                    .insert(format!("{:?}", context.organization));
            }
        }
        for (issuer, held) in organizations {
            if held.len() > 1 {
                shared.push((id.clone(), issuer, held));
            }
        }
    }

    assert!(decided > 0, "the replay decided no scenario at all");
    assert!(
        shared.is_empty(),
        "{} of {decided} authored scenarios stand two organizations' connections on one \
         issuer: {shared:?}",
        shared.len()
    );
}
