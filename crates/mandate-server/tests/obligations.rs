//! The obligations registry, and one case per declared deny clause of the road commands.
//!
//! `docs/architecture/runtime-decisions.md:118-119`, the evidence `decision-blocker:guards`
//! names: "A written adapter contract naming, for every one of the 59 commands ... which party
//! establishes each declared precondition. A sample is not evidence; the table is the
//! enumeration." and "A negative conformance case per command deny clause". (59 has since
//! become 61; the count is read here rather than restated.)
//!
//! Two enumerations, both machine-checked against a source outside this crate:
//!
//! 1. the registry's command set equals the `operationId` set of `generated/openapi/*.yaml`;
//! 2. each road command's clause list equals the clauses of its row in
//!    `docs/architecture/command-obligations.md`, which `xtask/src/main.rs:255-315` already
//!    pins to the contract's own declared denial text.
//!
//! So a command added to the contract, or a denial phrase that drifts, fails here. Neither is
//! a list this crate can keep green by editing itself.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use mandate_server::decode::{self, Refusal, Request};
use mandate_server::obligations::{
    self, BodyForm, Establishes, OBLIGATIONS, Obligation, ROAD_COMMANDS, Wire,
};
use mandate_server::routes::{self, Binding};

const OPENAPI: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../generated/openapi");
const OBLIGATIONS_TABLE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/architecture/command-obligations.md"
);

const UUID: &str = "1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b";
const OTHER_UUID: &str = "2c5f39cb-3fb2-4e9f-c2c1-9d2e5f607b8c";
const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const ENCODED_REDIRECT: &str = "https%3A%2F%2Fapp.example%2Fcb";

// ------------------------------------------------------------------ the registry itself

#[test]
fn the_registry_names_every_operation_id_the_projection_publishes_and_nothing_else() {
    let published = published_operation_ids();
    let registered: BTreeSet<&str> = OBLIGATIONS
        .iter()
        .map(|obligation| obligation.command)
        .collect();
    assert_eq!(registered, published, "the registry is not the command set");
    assert_eq!(OBLIGATIONS.len(), published.len());
    assert_eq!(OBLIGATIONS.len(), 61);
}

#[test]
fn no_command_is_registered_twice() {
    let mut seen = BTreeSet::new();
    for obligation in OBLIGATIONS {
        assert!(seen.insert(obligation.command), "{}", obligation.command);
    }
}

#[test]
fn every_command_is_reachable_by_name() {
    for obligation in OBLIGATIONS {
        assert_eq!(
            obligations::obligation(obligation.command),
            Some(obligation)
        );
    }
    assert_eq!(obligations::obligation("mandate.core.NotACommand"), None);
}

#[test]
fn the_four_road_commands_are_exactly_the_registry_entries_with_a_product_route() {
    let product: Vec<&str> = OBLIGATIONS
        .iter()
        .filter(|obligation| matches!(obligation.wire, Wire::Product { .. }))
        .map(|obligation| obligation.command)
        .collect();
    assert_eq!(product, ROAD_COMMANDS.to_vec());
    assert_eq!(ROAD_COMMANDS.len(), 4);
}

#[test]
fn every_product_obligation_states_the_route_the_table_declares() {
    for obligation in OBLIGATIONS {
        let Wire::Product { method, path, .. } = obligation.wire else {
            continue;
        };
        let route = routes::route_for_command(obligation.command)
            .unwrap_or_else(|| panic!("{} has no route", obligation.command));
        assert_eq!(route.method, method, "{}", obligation.command);
        assert_eq!(route.path, path, "{}", obligation.command);
    }
    // And the other direction: no route of the table binds a command the registry does not
    // record as reached through it.
    for route in routes::ROUTES {
        if let Binding::Command(command) = route.binds {
            let obligation = obligations::obligation(command)
                .unwrap_or_else(|| panic!("{command} is not registered"));
            assert!(
                matches!(obligation.wire, Wire::Product { .. }),
                "{command} is served but registered as generated-only"
            );
        }
    }
}

#[test]
fn every_command_off_the_road_is_reached_only_through_its_generated_route() {
    for obligation in OBLIGATIONS {
        if ROAD_COMMANDS.contains(&obligation.command) {
            continue;
        }
        assert_eq!(obligation.wire, Wire::Generated, "{}", obligation.command);
        assert!(obligation.decoder.is_none(), "{}", obligation.command);
        // Named residue: the per-clause enumeration exists for the road commands only. The
        // other 57 state, in whole, that this adapter establishes none of their preconditions.
        assert!(obligation.clauses.is_empty(), "{}", obligation.command);
        assert_eq!(
            routes::route_for_command(obligation.command),
            None,
            "{}",
            obligation.command
        );
    }
}

#[test]
fn every_road_obligation_names_the_decoder_that_builds_its_input() {
    let expected = [
        (
            "mandate.federation.AuthenticateFederation",
            "decode::authenticate_federation",
            BodyForm::Json,
        ),
        (
            "mandate.federation.AuthorizePublicClient",
            "decode::authorize_public_client",
            BodyForm::Query,
        ),
        (
            "mandate.credential.RedeemAuthorizationCode",
            "decode::redeem_authorization_code",
            BodyForm::Form,
        ),
        (
            "mandate.credential.IntrospectCredential",
            "decode::introspect_credential",
            BodyForm::Form,
        ),
    ];
    for (command, decoder, form) in expected {
        let obligation = obligations::obligation(command).unwrap();
        assert_eq!(obligation.decoder, Some(decoder));
        let Wire::Product { body, .. } = obligation.wire else {
            panic!("{command} is not a product route");
        };
        assert_eq!(body, form, "{command}");
    }
}

// --------------------------------------------------- the clauses, against the contract

#[test]
fn the_clause_splitter_reads_a_declared_cause_the_way_the_obligations_table_writes_one() {
    assert_eq!(
        obligations::clauses_of("A fails, b fails, or c fails."),
        vec!["A fails", "b fails", "c fails"]
    );
    // A cause that separates its clauses with semicolons is split on those, because one of its
    // clauses carries a comma of its own.
    assert_eq!(
        obligations::clauses_of("A fails; client, redirect or verifier mismatches; or c fails."),
        vec![
            "A fails",
            "client, redirect or verifier mismatches",
            "c fails"
        ]
    );
}

#[test]
fn every_road_command_records_exactly_the_clauses_its_declared_denial_carries() {
    let declared = declared_causes();
    for command in ROAD_COMMANDS {
        let cause = declared
            .get(*command)
            .unwrap_or_else(|| panic!("{command} has no obligations row"));
        let expected = obligations::clauses_of(cause);
        let recorded: Vec<&str> = obligations::obligation(command)
            .unwrap()
            .clauses
            .iter()
            .map(|clause| clause.phrase)
            .collect();
        assert_eq!(recorded, expected, "{command}");
        for phrase in &recorded {
            assert!(cause.contains(phrase), "{command}: {phrase}");
        }
    }
}

#[test]
fn the_four_road_commands_declare_twenty_five_clauses_between_them() {
    let total: usize = ROAD_COMMANDS
        .iter()
        .map(|command| obligations::obligation(command).unwrap().clauses.len())
        .sum();
    assert_eq!(total, 25);
}

/// One case per declared deny clause of the four road commands — 25 of them.
///
/// The case a clause gets is decided by which party the registry records as establishing it,
/// and the rule is uniform:
///
/// * [`Establishes::Adapter`] — the wire form this clause can be provoked with is presented,
///   and the decoder must refuse it with the recorded refusal.
/// * [`Establishes::Handler`] — the wire form is presented, the decoder must **admit** it, and
///   the input it builds must carry no selector by which the caller could have established the
///   condition itself. An adapter that refused here would be deciding a condition it cannot
///   read; one that passed a selector through would let the caller decide it.
///
/// A `(command, phrase)` pair with no arm below fails this case naming itself, so a clause the
/// contract adds cannot be silently uncovered.
#[test]
fn a_case_for_every_declared_deny_clause_of_the_road_commands() {
    let mut covered = 0;
    for command in ROAD_COMMANDS {
        for clause in obligations::obligation(command).unwrap().clauses {
            drive(command, clause.phrase, clause.establishes);
            covered += 1;
        }
    }
    assert_eq!(covered, 25);
}

fn drive(command: &str, phrase: &str, establishes: Establishes) {
    match (command, phrase) {
        // ---- mandate.federation.AuthenticateFederation
        ("mandate.federation.AuthenticateFederation", "Connection is disabled/untrusted")
        | (
            "mandate.federation.AuthenticateFederation",
            "proof signature/issuer/audience/expiry is invalid",
        )
        | (
            "mandate.federation.AuthenticateFederation",
            "tenant resolution has zero or multiple matches",
        )
        | (
            "mandate.federation.AuthenticateFederation",
            "principal linking is absent/conflicting",
        ) => {
            assert_eq!(establishes, Establishes::Handler, "{phrase}");
            let input = decode::authenticate_federation(&login(&format!(
                r#"{{"connection_id":"{UUID}","proof":"Zm9v"}}"#
            )))
            .unwrap_or_else(|refusal| panic!("{phrase}: {refusal}"));
            // The two declared inputs, and nothing by which a caller could name a connection's
            // trust, an organization, a principal or a link.
            assert_eq!(
                decode::AuthenticateFederation::DECLARED_INPUTS,
                ["connection_id", "proof"]
            );
            assert_eq!(input.connection_id.to_string(), UUID);
        }
        (
            "mandate.federation.AuthenticateFederation",
            "any email-domain/unverified-input fallback would be required",
        ) => {
            assert_eq!(establishes, Establishes::Adapter, "{phrase}");
            // There is no unverified input to fall back to: the body admits two members.
            for member in [r#""email":"a@b.example""#, r#""domain":"b.example""#] {
                let body = format!(r#"{{"connection_id":"{UUID}","proof":"Zm9v",{member}}}"#);
                assert_eq!(
                    decode::authenticate_federation(&login(&body)).unwrap_err(),
                    Refusal::UndeclaredField,
                    "{member}"
                );
            }
        }
        // ---- mandate.federation.AuthorizePublicClient
        ("mandate.federation.AuthorizePublicClient", "Session proof is invalid/stale")
        | (
            "mandate.federation.AuthorizePublicClient",
            "client is not a registered public client",
        )
        | ("mandate.federation.AuthorizePublicClient", "the client is disabled")
        | (
            "mandate.federation.AuthorizePublicClient",
            "exact redirect URI or state/applicable nonce binding fails",
        )
        | ("mandate.federation.AuthorizePublicClient", "target is unregistered/outside tenant")
        | ("mandate.federation.AuthorizePublicClient", "STS code issuance/narrowing is refused") => {
            assert_eq!(establishes, Establishes::Handler, "{phrase}");
            let input = decode::authorize_public_client(&authorize(&authorize_query()))
                .unwrap_or_else(|refusal| panic!("{phrase}: {refusal}"));
            assert_eq!(input.client_id.to_string(), UUID);
            assert!(!decode::AUTHORIZE_PARAMETERS.contains(&"organization_id"));
            assert!(!decode::AUTHORIZE_PARAMETERS.contains(&"audience"));
            assert!(!decode::AUTHORIZE_PARAMETERS.contains(&"session_id"));
        }
        ("mandate.federation.AuthorizePublicClient", "S256 challenge is absent/invalid") => {
            assert_eq!(establishes, Establishes::Adapter, "{phrase}");
            let absent = authorize_query()
                .split('&')
                .filter(|pair| !pair.starts_with("code_challenge="))
                .collect::<Vec<_>>()
                .join("&");
            assert_eq!(
                decode::authorize_public_client(&authorize(&absent)).unwrap_err(),
                Refusal::MissingField
            );
            let invalid = authorize_query().replace(CHALLENGE, "too-short");
            assert_eq!(
                decode::authorize_public_client(&authorize(&invalid)).unwrap_err(),
                Refusal::ChallengeMalformed
            );
            let plain = authorize_query()
                .replace("code_challenge_method=S256", "code_challenge_method=plain");
            assert_eq!(
                decode::authorize_public_client(&authorize(&plain)).unwrap_err(),
                Refusal::PkceMethodUnsupported
            );
        }
        // ---- mandate.credential.RedeemAuthorizationCode
        (
            "mandate.credential.RedeemAuthorizationCode",
            "Code proof does not match the server-resolved code_id",
        ) => {
            assert_eq!(establishes, Establishes::Adapter, "{phrase}");
            // "server-resolved" is the adapter's half: the caller cannot name the code_id the
            // proof is resolved against.
            let form = format!("{}&code_id={UUID}", token_form());
            assert_eq!(
                decode::redeem_authorization_code(&token(&form)).unwrap_err(),
                Refusal::ServerResolvedField
            );
            assert!(
                decode::redeem_authorization_code(&token(&token_form()))
                    .unwrap()
                    .code_id
                    .is_none()
            );
        }
        (
            "mandate.credential.RedeemAuthorizationCode",
            "client, redirect URI or S256 verifier mismatches",
        ) => {
            assert_eq!(establishes, Establishes::Adapter, "{phrase}");
            // The wire half of the verifier clause: a verifier that is absent or outside RFC
            // 7636's form is the verifier of nothing, and never reaches the digest comparison.
            let absent = token_form()
                .split('&')
                .filter(|pair| !pair.starts_with("code_verifier="))
                .collect::<Vec<_>>()
                .join("&");
            assert_eq!(
                decode::redeem_authorization_code(&token(&absent)).unwrap_err(),
                Refusal::PkceMissing
            );
            let malformed = token_form().replace(VERIFIER, "short");
            assert_eq!(
                decode::redeem_authorization_code(&token(&malformed)).unwrap_err(),
                Refusal::VerifierMalformed
            );
        }
        ("mandate.credential.RedeemAuthorizationCode", "code is expired")
        | ("mandate.credential.RedeemAuthorizationCode", "the bound client is disabled")
        | ("mandate.credential.RedeemAuthorizationCode", "source/session epoch is stale")
        | (
            "mandate.credential.RedeemAuthorizationCode",
            "registered target is disabled or outside the verified tenant",
        )
        | (
            "mandate.credential.RedeemAuthorizationCode",
            "narrowing/atomic issuance validation fails",
        ) => {
            assert_eq!(establishes, Establishes::Handler, "{phrase}");
            let input = decode::redeem_authorization_code(&token(&token_form()))
                .unwrap_or_else(|refusal| panic!("{phrase}: {refusal}"));
            assert!(input.code_id.is_none());
            for absent in [
                "organization_id",
                "audience",
                "session_id",
                "target",
                "scope",
            ] {
                assert!(!decode::TOKEN_PARAMETERS.contains(&absent), "{absent}");
            }
        }
        // ---- mandate.credential.IntrospectCredential
        (
            "mandate.credential.IntrospectCredential",
            "Caller proof lacks introspection authority for the registered server/tenant or is itself invalid",
        )
        | ("mandate.credential.IntrospectCredential", "revoked or expired")
        | (
            "mandate.credential.IntrospectCredential",
            "principal/connection/epoch validation fails",
        )
        | ("mandate.credential.IntrospectCredential", "audience mismatches")
        | (
            "mandate.credential.IntrospectCredential",
            "authoritative online resolution is unavailable",
        ) => {
            assert_eq!(establishes, Establishes::Handler, "{phrase}");
            let input = decode::introspect_credential(&introspect("token=Zm9v"))
                .unwrap_or_else(|refusal| panic!("{phrase}: {refusal}"));
            assert_eq!(input.caller_proof.expose_bytes(), b"caller");
            // The caller's own authority is the proof it presented and nothing beside it.
            assert!(!decode::INTROSPECT_PARAMETERS.contains(&"audience"));
            assert!(!decode::INTROSPECT_PARAMETERS.contains(&"organization_id"));
        }
        (
            "mandate.credential.IntrospectCredential",
            "the presented credential proof is malformed",
        ) => {
            assert_eq!(establishes, Establishes::Adapter, "{phrase}");
            assert_eq!(
                decode::introspect_credential(&introspect("")).unwrap_err(),
                Refusal::MissingField
            );
            assert_eq!(
                decode::introspect_credential(&introspect("token=not+base64")).unwrap_err(),
                Refusal::MalformedField
            );
        }
        _ => panic!("no case for {command}: {phrase}"),
    }
}

#[test]
fn the_clauses_the_adapter_establishes_are_the_five_the_wire_form_decides() {
    let adapter: Vec<(&str, &str)> = OBLIGATIONS
        .iter()
        .flat_map(|obligation: &Obligation| {
            obligation
                .clauses
                .iter()
                .filter(|clause| clause.establishes == Establishes::Adapter)
                .map(|clause| (obligation.command, clause.phrase))
        })
        .collect();
    assert_eq!(adapter.len(), 5, "{adapter:?}");
}

// ----------------------------------------------------------------------------- fixtures

fn login(body: &str) -> Request {
    Request::new("POST", "/v1/federation/login")
        .with_header("Content-Type", "application/json")
        .with_body(body.as_bytes().to_vec())
}

fn authorize_query() -> String {
    format!(
        "response_type=code&client_id={UUID}&redirect_uri={ENCODED_REDIRECT}\
         &code_challenge={CHALLENGE}&code_challenge_method=S256&state=xyz&nonce=abc\
         &target={OTHER_UUID}&scope=read+write"
    )
}

fn authorize(query: &str) -> Request {
    Request::new("GET", &format!("/oauth/authorize?{query}"))
        .with_header("Authorization", "Bearer Zm9v")
}

fn token_form() -> String {
    format!(
        "grant_type=authorization_code&client_id={UUID}&code=Zm9v\
         &code_verifier={VERIFIER}&redirect_uri={ENCODED_REDIRECT}"
    )
}

fn token(form: &str) -> Request {
    Request::new("POST", "/oauth/token")
        .with_header("Content-Type", "application/x-www-form-urlencoded")
        .with_body(form.as_bytes().to_vec())
}

fn introspect(form: &str) -> Request {
    Request::new("POST", "/oauth/introspect")
        .with_header("Content-Type", "application/x-www-form-urlencoded")
        .with_header("Authorization", "Bearer Y2FsbGVy")
        .with_body(form.as_bytes().to_vec())
}

/// Every `operationId` the four generated OpenAPI documents publish.
fn published_operation_ids() -> BTreeSet<&'static str> {
    let mut ids = BTreeSet::new();
    let mut documents = 0;
    for entry in fs::read_dir(OPENAPI).expect("the generated openapi directory") {
        let path = entry.expect("a generated document").path();
        if path.extension().is_none_or(|extension| extension != "yaml") {
            continue;
        }
        documents += 1;
        let text: &'static str = Box::leak(
            fs::read_to_string(&path)
                .expect("a document")
                .into_boxed_str(),
        );
        for line in text.lines() {
            if let Some(id) = line.trim().strip_prefix("operationId: ") {
                assert!(ids.insert(id), "{id} twice");
            }
        }
    }
    assert_eq!(documents, 4);
    ids
}

/// Each command's declared external denial text, from the table the gate already pins to the
/// contract (`xtask/src/main.rs:255-315`).
fn declared_causes() -> BTreeMap<String, String> {
    let table = fs::read_to_string(OBLIGATIONS_TABLE).expect("the obligations table");
    let mut causes = BTreeMap::new();
    for line in table.lines() {
        let Some(rest) = line.strip_prefix("| `") else {
            continue;
        };
        let Some((name, rest)) = rest.split_once("` | ") else {
            continue;
        };
        let text = rest.strip_suffix(" |").expect("an obligations row");
        causes.insert(name.to_owned(), text.to_owned());
    }
    assert!(causes.len() >= 61, "read {} rows", causes.len());
    causes
}
