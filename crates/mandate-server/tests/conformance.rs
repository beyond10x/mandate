//! The library against the contract it is an adapter for.
//!
//! Three things end to end: the route table, the metadata document built from it, and every
//! road decoder round-tripping a fixture request into the input shape the generated contract
//! declares.
//!
//! # Why the generated input shape is read as text and not linked
//!
//! `generated/rust/mandate-contract` carries the command input structs, and it is **not** in
//! this crate's dependency ceiling: `dependency-boundaries.json` gives `mandate-server`
//! `mandate-types` and `mandate-proto`, and a unit of `story:login-adapters` may not add to it.
//! Neither are the deciding handlers' own input types — `mandate_federation::authenticate`,
//! `mandate_sts::redemption`, `mandate_sts::resolve` — which are in `mandate-federation` and
//! `mandate-sts`, also outside the ceiling. Both were considered; both are unreachable here.
//!
//! What is reachable is the projection itself. Each `.Input` schema in
//! `generated/openapi/*.yaml` lists its `required` members in declaration order, and that list
//! is compared with the decoded value's own `DECLARED_INPUTS`. It decides the same thing a
//! compile against `mandate_contract` would — that the decoder builds exactly the declared
//! input, member for member, in order — against the projection the contract publishes rather
//! than against a Rust type this crate cannot name. When `story:product-listener` composes
//! these decoders with the real handlers in `services/control-plane`, whose ceiling does carry
//! both crates, the compiler decides the rest.

use std::fs;

use mandate_server::decode::{self, Request};
use mandate_server::metadata;
use mandate_server::obligations::{self, ROAD_COMMANDS, Wire};
use mandate_server::routes::{self, Binding, Document, ROUTES};

const OPENAPI: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../generated/openapi");

const UUID: &str = "1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b";
const OTHER_UUID: &str = "2c5f39cb-3fb2-4e9f-c2c1-9d2e5f607b8c";
const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const REDIRECT: &str = "https://app.example/cb";
const ENCODED_REDIRECT: &str = "https%3A%2F%2Fapp.example%2Fcb";
const ISSUER: &str = "https://mandate.example";

#[test]
fn every_road_decoder_builds_exactly_the_members_the_generated_input_declares() {
    for (command, declared) in [
        (
            "mandate.federation.AuthenticateFederation",
            decode::AuthenticateFederation::DECLARED_INPUTS,
        ),
        (
            "mandate.federation.AuthorizePublicClient",
            decode::AuthorizePublicClient::DECLARED_INPUTS,
        ),
        (
            "mandate.credential.RedeemAuthorizationCode",
            decode::RedeemAuthorizationCode::DECLARED_INPUTS,
        ),
        (
            "mandate.credential.IntrospectCredential",
            decode::IntrospectCredential::DECLARED_INPUTS,
        ),
    ] {
        assert_eq!(required_members(command), declared.to_vec(), "{command}");
    }
}

#[test]
fn a_federation_login_round_trips_into_the_declared_input() {
    let request = Request::new("POST", "/v1/federation/login")
        .with_header("Content-Type", "application/json")
        .with_body(format!(r#"{{"connection_id":"{UUID}","proof":"Zm9v"}}"#).into_bytes());
    let route = routes::route_for_command("mandate.federation.AuthenticateFederation").unwrap();
    assert_eq!(request.method, route.method.as_str());
    assert_eq!(request.route_path(), route.path);

    let input = decode::authenticate_federation(&request).unwrap();
    assert_eq!(input.connection_id.to_string(), UUID);
    assert_eq!(input.proof.expose_bytes(), b"foo");
}

#[test]
fn an_authorization_request_round_trips_into_the_declared_input() {
    let query = format!(
        "response_type=code&client_id={UUID}&redirect_uri={ENCODED_REDIRECT}\
         &code_challenge={CHALLENGE}&code_challenge_method=S256&state=xyz&nonce=abc\
         &target={OTHER_UUID}&scope=read+write"
    );
    let request = Request::new("GET", &format!("/oauth/authorize?{query}"))
        .with_header("Authorization", "Bearer Zm9v");
    let route = routes::route_for_command("mandate.federation.AuthorizePublicClient").unwrap();
    assert_eq!(request.method, route.method.as_str());
    assert_eq!(request.route_path(), route.path);

    let input = decode::authorize_public_client(&request).unwrap();
    assert_eq!(input.client_id.to_string(), UUID);
    assert_eq!(input.redirect_uri.as_str(), REDIRECT);
    assert_eq!(input.challenge.as_str(), CHALLENGE);
    assert_eq!(input.method, mandate_types::PkceMethod::S256);
    assert_eq!(input.state, "xyz");
    assert_eq!(input.nonce, "abc");
    assert_eq!(input.session_proof.expose_bytes(), b"foo");
    assert_eq!(input.target.to_string(), OTHER_UUID);
    assert_eq!(input.requested_scope.actions.len(), 2);
}

#[test]
fn a_token_request_round_trips_into_the_declared_input() {
    let form = format!(
        "grant_type=authorization_code&client_id={UUID}&code=Zm9v\
         &code_verifier={VERIFIER}&redirect_uri={ENCODED_REDIRECT}"
    );
    let request = Request::new("POST", "/oauth/token")
        .with_header("Content-Type", "application/x-www-form-urlencoded")
        .with_body(form.into_bytes());
    let route = routes::route_for_command("mandate.credential.RedeemAuthorizationCode").unwrap();
    assert_eq!(request.method, route.method.as_str());
    assert_eq!(request.route_path(), route.path);

    let input = decode::redeem_authorization_code(&request).unwrap();
    assert!(input.code_id.is_none());
    assert_eq!(input.client_id.to_string(), UUID);
    assert_eq!(input.code.expose_bytes(), b"foo");
    assert_eq!(input.pkce_verifier.expose_bytes(), VERIFIER.as_bytes());
    assert_eq!(input.redirect_uri.as_str(), REDIRECT);
}

#[test]
fn an_introspection_round_trips_into_the_declared_input() {
    let request = Request::new("POST", "/oauth/introspect")
        .with_header("Content-Type", "application/x-www-form-urlencoded")
        .with_header("Authorization", "Bearer Y2FsbGVy")
        .with_body(b"token=Zm9v".to_vec());
    let route = routes::route_for_command("mandate.credential.IntrospectCredential").unwrap();
    assert_eq!(request.method, route.method.as_str());
    assert_eq!(request.route_path(), route.path);

    let input = decode::introspect_credential(&request).unwrap();
    assert_eq!(input.caller_proof.expose_bytes(), b"caller");
    assert_eq!(input.credential_proof.expose_bytes(), b"foo");
}

#[test]
fn every_route_of_the_table_is_a_command_the_registry_serves_or_a_document_this_crate_builds() {
    for route in ROUTES {
        match route.binds {
            Binding::Command(command) => {
                let obligation = obligations::obligation(command).unwrap();
                assert!(matches!(obligation.wire, Wire::Product { .. }), "{command}");
                assert!(obligation.decoder.is_some(), "{command}");
                assert!(ROAD_COMMANDS.contains(&command), "{command}");
            }
            Binding::Document(Document::AuthorizationServerMetadata) => {
                assert!(
                    metadata::authorization_server_metadata(ISSUER)
                        .to_json()
                        .starts_with('{')
                );
            }
            Binding::Document(Document::Jwks) => {
                assert_eq!(metadata::Jwks::empty().to_json(), r#"{"keys":[]}"#);
            }
            Binding::RelyingParty(routes::RelyingPartyStep::Authorize) => {
                let request = Request::new("GET", &format!("{}?connection_id={UUID}", route.path));
                assert_eq!(request.route_path(), route.path);
                let input = decode::begin_federation(&request).unwrap();
                assert_eq!(input.connection_id.to_string(), UUID);
            }
            Binding::RelyingParty(routes::RelyingPartyStep::Callback) => {
                let request = Request::new("GET", &format!("{}?code=Zm9v&state=xyz", route.path));
                assert_eq!(request.route_path(), route.path);
                let input = decode::complete_federation(&request).unwrap();
                assert_eq!(input.code.expose_bytes(), b"Zm9v");
                assert_eq!(input.state, "xyz");
            }
        }
    }
}

#[test]
fn the_metadata_advertises_the_paths_a_client_would_then_reach() {
    let document = metadata::authorization_server_metadata(ISSUER);
    for advertised in [
        &document.authorization_endpoint,
        &document.token_endpoint,
        &document.introspection_endpoint,
        &document.jwks_uri,
    ] {
        let path = advertised
            .strip_prefix(ISSUER)
            .expect("an issuer-relative URL");
        assert!(
            ROUTES.iter().any(|route| route.path == path),
            "{advertised} is advertised and routed nowhere"
        );
        assert!(!routes::is_generated_command_path(path), "{advertised}");
    }
}

/// The `required` members of a command's generated input schema, in declaration order.
fn required_members(command: &str) -> Vec<&'static str> {
    let heading = format!("    {command}.Input:");
    let mut found: Option<Vec<&'static str>> = None;
    for entry in fs::read_dir(OPENAPI).expect("the generated openapi directory") {
        let path = entry.expect("a generated document").path();
        if path.extension().is_none_or(|extension| extension != "yaml") {
            continue;
        }
        let text: &'static str = Box::leak(
            fs::read_to_string(&path)
                .expect("a document")
                .into_boxed_str(),
        );
        let Some(block) = text.split_once(&format!("{heading}\n")) else {
            continue;
        };
        let mut members = Vec::new();
        let mut reading = false;
        for line in block.1.lines() {
            if line == "      required:" {
                reading = true;
                continue;
            }
            if reading {
                match line.strip_prefix("      - ") {
                    Some(member) => members.push(member),
                    None => break,
                }
            }
        }
        assert!(!members.is_empty(), "{command} declares no required member");
        assert!(found.is_none(), "{command} is declared in two documents");
        found = Some(members);
    }
    found.unwrap_or_else(|| panic!("{command} has no generated input schema"))
}
