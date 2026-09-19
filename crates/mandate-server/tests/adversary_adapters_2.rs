//! Adversary pass 2 against `story:login-adapters`.
//!
//! Same method as pass 1: every case drives a claim the unit wrote about itself —
//! `docs/architecture/adapter-contract.md` — against the code the same unit wrote, and reads
//! the document as the specification it says it is. Pass 1 reached the *body* of each
//! request; these two reach the components pass 1 did not open — the query string of the
//! three decoders that read a body, and the exact class of character rule 8 names.
//!
//! Nothing here changes an implementation file.

use mandate_server::decode::{self, MAX_BODY_BYTES, Refusal, Request};

const UUID: &str = "1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b";
const OTHER_UUID: &str = "2c5f39cb-3fb2-4e9f-c2c1-9d2e5f607b8c";
const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const ENCODED_REDIRECT: &str = "https%3A%2F%2Fapp.example%2Fcb";

/// The four names `adapter-contract.md` rule 1 names by hand as the ones a caller must not be
/// able to add "and have it ignored".
const SMUGGLED: &str = "organization_id=evil&audience=evil&subject=evil&actor=evil";

fn token_form() -> String {
    format!(
        "grant_type=authorization_code&client_id={UUID}&code=Zm9v\
         &code_verifier={VERIFIER}&redirect_uri={ENCODED_REDIRECT}"
    )
}

fn token_at(target: &str) -> Request {
    Request::new("POST", target)
        .with_header("Content-Type", "application/x-www-form-urlencoded")
        .with_body(token_form().into_bytes())
}

fn introspect_at(target: &str) -> Request {
    Request::new("POST", target)
        .with_header("Content-Type", "application/x-www-form-urlencoded")
        .with_header("Authorization", "Bearer Y2FsbGVy")
        .with_body(b"token=Zm9v".to_vec())
}

fn login_at(target: &str) -> Request {
    Request::new("POST", target)
        .with_header("Content-Type", "application/json")
        .with_body(format!(r#"{{"connection_id":"{UUID}","proof":"Zm9v"}}"#).into_bytes())
}

fn authorize_with_state(state: &str) -> Request {
    let query = format!(
        "response_type=code&client_id={UUID}&redirect_uri={ENCODED_REDIRECT}\
         &code_challenge={CHALLENGE}&code_challenge_method=S256&state={state}&nonce=abc\
         &target={OTHER_UUID}&scope=read+write"
    );
    Request::new("GET", &format!("/oauth/authorize?{query}"))
        .with_header("Authorization", "Bearer Zm9v")
}

// ------------------------------------------------- adapter-contract.md, rule 1 (`:57-62`)

/// `adapter-contract.md` rule 1: "**The admitted parameter set is closed.** Each endpoint
/// declares its keys ... and anything else is refused. A caller cannot add an
/// `organization_id`, an `audience`, a `subject` or an `actor` to a request **and have it
/// ignored; the request is refused**."
///
/// Pass 2 found the three body decoders measuring the query string and never reading or
/// refusing it, so a POST carrying the four names in its target decoded `Ok`. Coordinator
/// ruling (pass 2, F3): a route that reads only the body admits no query at all, the mirror of
/// the query route's `BodyNotAdmitted`; the ceiling is measured first, then the component.
/// The refusal is `Refusal::QueryNotAdmitted`.
///
/// What reaches it: `Request::route_path()` exists to split a target at `?` so a listener can
/// dispatch on the path alone, and the shipped suite already builds POST requests carrying a
/// query (`tests/decode.rs`, `the_byte_ceiling_bounds_the_body_and_the_query_of_all_four_
/// decoders`). Nothing on the road strips a query before a decoder sees it.
#[test]
fn a_query_string_on_a_body_route_is_refused_whole() {
    // The ceiling is measured before the component is refused, on every one of the three.
    let oversized = "a".repeat(MAX_BODY_BYTES + 1);
    assert_eq!(
        decode::redeem_authorization_code(&token_at(&format!("/oauth/token?{oversized}"))),
        Err(Refusal::BodyTooLarge),
        "the token decoder measures the query before refusing it"
    );

    assert_eq!(
        decode::redeem_authorization_code(&token_at(&format!("/oauth/token?{SMUGGLED}")))
            .map(|_| ()),
        Err(Refusal::QueryNotAdmitted),
        "`POST /oauth/token?{SMUGGLED}` was admitted: rule 1 says the request is refused, \
         not that the four names are ignored"
    );
    assert_eq!(
        decode::introspect_credential(&introspect_at(&format!("/oauth/introspect?{SMUGGLED}")))
            .map(|_| ()),
        Err(Refusal::QueryNotAdmitted),
        "`POST /oauth/introspect?{SMUGGLED}` was admitted"
    );
    assert_eq!(
        decode::authenticate_federation(&login_at(&format!("/v1/federation/login?{SMUGGLED}")))
            .map(|_| ()),
        Err(Refusal::QueryNotAdmitted),
        "`POST /v1/federation/login?{SMUGGLED}` was admitted"
    );
}

/// The same hole reached with a declared name rather than an undeclared one.
///
/// `adapter-contract.md` rule 4: "**A repeat is refused, not resolved.**" A token request
/// whose body carries `code=Zm9v` and whose query carries `code=<other>` has presented `code`
/// twice across the two components a form is carried in. Under the F3 ruling the query is
/// refused before its names are read, so the repeat is refused a fortiori and the refusal is
/// the component's, not the field's.
#[test]
fn a_declared_parameter_presented_in_the_query_and_the_body_is_refused_with_the_query() {
    let doubled = token_at("/oauth/token?code=Zm9vYmFy&grant_type=client_credentials");
    assert_eq!(
        decode::redeem_authorization_code(&doubled).map(|_| ()),
        Err(Refusal::QueryNotAdmitted),
        "`code` and `grant_type` presented in both components decoded Ok from the body alone"
    );
}

// ------------------------------------------------- adapter-contract.md, rule 8 (`:81-88`)

/// `adapter-contract.md` rule 8 named the refused class as "C0 control or DEL" while the code
/// refuses Unicode general category `Cc` (`char::is_control`): C0, DEL **and the C1 block
/// U+0080–U+009F**. Pass 2 (F5) put the two in front of the coordinator, whose ruling is the
/// document: the predicate stays `Cc`, and rule 8, `Refusal::ControlCharacter`'s rustdoc and
/// `free_text`'s `# Errors` name the class as Unicode category `Cc`. U+0085 NEXT LINE is a
/// line terminator to some readers, so refusing the C1 block fails closed on the same hazard
/// the rule exists for.
///
/// U+2028 LINE SEPARATOR is outside `Cc` and admitted; asserted so the class is stated whole.
#[test]
fn the_refused_control_class_is_unicode_category_cc_as_the_contract_names_it() {
    assert!(
        decode::authorize_public_client(&authorize_with_state("%E2%80%A8")).is_ok(),
        "U+2028 is outside `Cc` and admitted"
    );

    for (encoded, name) in [("%C2%85", "U+0085"), ("%C2%9B", "U+009B")] {
        assert_eq!(
            decode::authorize_public_client(&authorize_with_state(encoded))
                .map(|_| ())
                .expect_err("a C1 control in `state` is refused"),
            Refusal::ControlCharacter,
            "{name} is a C1 control, inside `Cc`, and rule 8 now names that class"
        );
    }
}
