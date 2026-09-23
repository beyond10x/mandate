//! The decoding boundary: one decoder per road command, building exactly the declared input.
//!
//! `story:login-adapters`, ruling 1 (wave D opening): no road command declares a `context`
//! input, so the road unit is the decoding boundary. What these cases decide is the
//! acceptance statement's first half — "exactly the command's declared inputs reach the
//! handler and every undeclared field is refused (no caller-supplied selector passes
//! through)" — and its second — "the token request is decoded from
//! `application/x-www-form-urlencoded` and refused with the standard OAuth error body when
//! malformed".
//!
//! Nothing here decides a connection, a client, a session, a code or a credential. A request
//! these cases admit is one a deciding handler has not yet seen.

use mandate_proto::oauth::ErrorCode;
use mandate_server::decode::{self, MAX_BODY_BYTES, MAX_TEXT_BYTES, Refusal, Request};
use mandate_types::PkceMethod;

const UUID: &str = "1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b";
const OTHER_UUID: &str = "2c5f39cb-3fb2-4e9f-c2c1-9d2e5f607b8c";
/// 43 unreserved characters: the shortest RFC 7636 section 4.1 code verifier.
const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
/// 43 base64url characters: the rendered length of an S256 challenge.
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const REDIRECT: &str = "https://app.example/cb";
const ENCODED_REDIRECT: &str = "https%3A%2F%2Fapp.example%2Fcb";

// ---------------------------------------------------------------- the request value

#[test]
fn a_request_is_a_crate_local_value_over_plain_text_and_bytes() {
    let request = Request::new("POST", "/oauth/token")
        .with_header("Content-Type", "application/x-www-form-urlencoded")
        .with_body(b"grant_type=authorization_code".to_vec());
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/oauth/token");
    assert_eq!(
        request.headers,
        vec![(
            "Content-Type".to_owned(),
            "application/x-www-form-urlencoded".to_owned()
        )]
    );
    assert_eq!(request.body, b"grant_type=authorization_code".to_vec());
}

#[test]
fn a_target_is_split_into_its_path_and_its_query() {
    let request = Request::new("GET", "/oauth/authorize?client_id=abc&state=x");
    assert_eq!(request.route_path(), "/oauth/authorize");
    assert_eq!(request.query(), "client_id=abc&state=x");
    assert_eq!(Request::new("GET", "/oauth/jwks").query(), "");
}

#[test]
fn a_header_is_found_without_regard_to_case_and_a_repeat_is_refused() {
    let request = Request::new("POST", "/oauth/introspect")
        .with_header("authorization", "Bearer Zm9v")
        .with_header("Authorization", "Bearer YmFy");
    assert_eq!(
        decode::introspect_credential(
            &request
                .clone()
                .with_header("Content-Type", "application/x-www-form-urlencoded")
        )
        .unwrap_err(),
        Refusal::DuplicateHeader
    );
}

// ------------------------------------------------------- AuthenticateFederation, JSON

fn login(body: &str) -> Request {
    Request::new("POST", "/v1/federation/login")
        .with_header("Content-Type", "application/json")
        .with_body(body.as_bytes().to_vec())
}

#[test]
fn a_federation_login_decodes_the_two_inputs_the_contract_declares() {
    let input = decode::authenticate_federation(&login(&format!(
        r#"{{"connection_id":"{UUID}","proof":"Zm9v"}}"#
    )))
    .unwrap();
    assert_eq!(input.connection_id.to_string(), UUID);
    assert_eq!(input.proof.expose_bytes(), b"foo");
}

#[test]
fn a_federation_login_refuses_an_undeclared_member() {
    let body = format!(r#"{{"connection_id":"{UUID}","proof":"Zm9v","organization_id":"{UUID}"}}"#);
    assert_eq!(
        decode::authenticate_federation(&login(&body)).unwrap_err(),
        Refusal::UndeclaredField
    );
}

#[test]
fn a_federation_login_refuses_a_missing_member() {
    assert_eq!(
        decode::authenticate_federation(&login(&format!(r#"{{"connection_id":"{UUID}"}}"#)))
            .unwrap_err(),
        Refusal::MissingField
    );
}

#[test]
fn a_federation_login_refuses_a_member_whose_lexical_form_is_not_the_declared_one() {
    assert_eq!(
        decode::authenticate_federation(&login(r#"{"connection_id":"not-a-uuid","proof":"Zm9v"}"#))
            .unwrap_err(),
        Refusal::MalformedField
    );
    assert_eq!(
        decode::authenticate_federation(&login(&format!(
            r#"{{"connection_id":"{UUID}","proof":"not base64"}}"#
        )))
        .unwrap_err(),
        Refusal::MalformedField
    );
}

#[test]
fn a_federation_login_refuses_a_body_that_is_not_a_flat_json_object() {
    for body in [
        "[]",
        "not json",
        r#"{"connection_id":{"a":"b"},"proof":"Zm9v"}"#,
    ] {
        assert_eq!(
            decode::authenticate_federation(&login(body)).unwrap_err(),
            Refusal::MalformedBody,
            "{body}"
        );
    }
}

#[test]
fn a_federation_login_refuses_another_method_or_another_content_type() {
    let body = format!(r#"{{"connection_id":"{UUID}","proof":"Zm9v"}}"#);
    let wrong_method = Request::new("GET", "/v1/federation/login")
        .with_header("Content-Type", "application/json")
        .with_body(body.as_bytes().to_vec());
    assert_eq!(
        decode::authenticate_federation(&wrong_method).unwrap_err(),
        Refusal::MethodNotAllowed
    );
    let wrong_type = Request::new("POST", "/v1/federation/login")
        .with_header("Content-Type", "text/plain")
        .with_body(body.as_bytes().to_vec());
    assert_eq!(
        decode::authenticate_federation(&wrong_type).unwrap_err(),
        Refusal::ContentTypeUnsupported
    );
}

#[test]
fn a_content_type_is_read_without_its_parameters() {
    let body = format!(r#"{{"connection_id":"{UUID}","proof":"Zm9v"}}"#);
    let request = Request::new("POST", "/v1/federation/login")
        .with_header("Content-Type", "application/json; charset=utf-8")
        .with_body(body.as_bytes().to_vec());
    assert!(decode::authenticate_federation(&request).is_ok());
}

// ------------------------------------------------- AuthorizePublicClient, query string

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

#[test]
fn an_authorization_request_decodes_the_nine_inputs_the_contract_declares() {
    let input = decode::authorize_public_client(&authorize(&authorize_query())).unwrap();
    assert_eq!(input.client_id.to_string(), UUID);
    assert_eq!(input.redirect_uri.as_str(), REDIRECT);
    assert_eq!(input.challenge.as_str(), CHALLENGE);
    assert_eq!(input.method, PkceMethod::S256);
    assert_eq!(input.state, "xyz");
    assert_eq!(input.nonce, "abc");
    assert_eq!(input.session_proof.expose_bytes(), b"foo");
    assert_eq!(input.target.to_string(), OTHER_UUID);
    assert_eq!(
        input
            .requested_scope
            .actions
            .iter()
            .map(|action| action.as_str().to_owned())
            .collect::<Vec<_>>(),
        vec!["read".to_owned(), "write".to_owned()]
    );
    // `mandate.core.AuthorityScope` declares resources and an optional space that RFC 6749's
    // `scope` parameter has no wire form for; the adapter invents neither.
    assert!(input.requested_scope.resources.is_empty());
    assert!(input.requested_scope.space.is_none());
}

#[test]
fn an_authorization_request_refuses_an_undeclared_parameter() {
    let query = format!("{}&organization_id={UUID}", authorize_query());
    assert_eq!(
        decode::authorize_public_client(&authorize(&query)).unwrap_err(),
        Refusal::UndeclaredField
    );
}

#[test]
fn an_authorization_request_refuses_a_repeated_parameter() {
    let query = format!("{}&state=other", authorize_query());
    assert_eq!(
        decode::authorize_public_client(&authorize(&query)).unwrap_err(),
        Refusal::DuplicateField
    );
}

#[test]
fn an_authorization_request_refuses_every_missing_declared_parameter() {
    for key in [
        "response_type",
        "client_id",
        "redirect_uri",
        "code_challenge",
        "code_challenge_method",
        "state",
        "nonce",
        "target",
        "scope",
    ] {
        let query = authorize_query()
            .split('&')
            .filter(|pair| !pair.starts_with(&format!("{key}=")))
            .collect::<Vec<_>>()
            .join("&");
        assert!(
            decode::authorize_public_client(&authorize(&query)).is_err(),
            "{key} was not required"
        );
    }
}

/// `tests/security/cases.json`, case `pkce-plain`.
#[test]
fn pkce_plain_is_refused_at_the_authorization_endpoint() {
    let query =
        authorize_query().replace("code_challenge_method=S256", "code_challenge_method=plain");
    let refused = decode::authorize_public_client(&authorize(&query)).unwrap_err();
    assert_eq!(refused, Refusal::PkceMethodUnsupported);
    assert_eq!(refused.error_code(), ErrorCode::InvalidRequest);
    assert_eq!(refused.body().error, ErrorCode::InvalidRequest);
}

#[test]
fn an_authorization_request_refuses_a_challenge_that_is_not_in_the_s256_shape() {
    for challenge in ["short", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c/"] {
        let query = authorize_query().replace(CHALLENGE, challenge);
        assert_eq!(
            decode::authorize_public_client(&authorize(&query)).unwrap_err(),
            Refusal::ChallengeMalformed,
            "{challenge}"
        );
    }
}

#[test]
fn an_authorization_request_refuses_a_response_type_this_endpoint_does_not_serve() {
    let query = authorize_query().replace("response_type=code", "response_type=token");
    let refused = decode::authorize_public_client(&authorize(&query)).unwrap_err();
    assert_eq!(refused, Refusal::UnsupportedResponseType);
    assert_eq!(refused.error_code(), ErrorCode::UnsupportedResponseType);
}

#[test]
fn an_authorization_request_refuses_an_absent_or_malformed_session_proof() {
    let bare = Request::new("GET", &format!("/oauth/authorize?{}", authorize_query()));
    assert_eq!(
        decode::authorize_public_client(&bare).unwrap_err(),
        Refusal::MissingSessionProof
    );
    let wrong_scheme = bare.clone().with_header("Authorization", "Basic Zm9v");
    assert_eq!(
        decode::authorize_public_client(&wrong_scheme).unwrap_err(),
        Refusal::MalformedSessionProof
    );
    let not_base64 = bare.with_header("Authorization", "Bearer not base64");
    assert_eq!(
        decode::authorize_public_client(&not_base64).unwrap_err(),
        Refusal::MalformedSessionProof
    );
}

#[test]
fn a_bearer_scheme_is_matched_without_regard_to_case() {
    let request = Request::new("GET", &format!("/oauth/authorize?{}", authorize_query()))
        .with_header("Authorization", "bEaReR Zm9v");
    assert!(decode::authorize_public_client(&request).is_ok());
}

// -------------------------------------------- RedeemAuthorizationCode, the token endpoint

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

#[test]
fn a_token_request_decodes_the_declared_input_and_resolves_no_code_id_from_the_caller() {
    let input = decode::redeem_authorization_code(&token(&token_form())).unwrap();
    assert_eq!(input.client_id.to_string(), UUID);
    assert_eq!(input.code.expose_bytes(), b"foo");
    assert_eq!(input.pkce_verifier.expose_bytes(), VERIFIER.as_bytes());
    assert_eq!(input.redirect_uri.as_str(), REDIRECT);
    // `credential.yaml`'s header: "RedeemAuthorizationCode.code_id is resolved by the trusted
    // adapter from proof; it is not a public OAuth parameter or authority selector."
    assert!(input.code_id.is_none());
}

#[test]
fn a_token_request_refuses_a_caller_supplied_code_id() {
    let form = format!("{}&code_id={UUID}", token_form());
    let refused = decode::redeem_authorization_code(&token(&form)).unwrap_err();
    assert_eq!(refused, Refusal::ServerResolvedField);
    assert_eq!(refused.error_code(), ErrorCode::InvalidRequest);
}

#[test]
fn a_token_request_refuses_an_undeclared_parameter() {
    for extra in ["client_secret=s", "organization_id=x", "audience=y"] {
        let form = format!("{}&{extra}", token_form());
        assert_eq!(
            decode::redeem_authorization_code(&token(&form)).unwrap_err(),
            Refusal::UndeclaredField,
            "{extra}"
        );
    }
}

#[test]
fn a_token_request_refuses_a_grant_type_this_endpoint_does_not_serve() {
    let form = token_form().replace("grant_type=authorization_code", "grant_type=password");
    let refused = decode::redeem_authorization_code(&token(&form)).unwrap_err();
    assert_eq!(refused, Refusal::UnsupportedGrantType);
    assert_eq!(refused.error_code(), ErrorCode::UnsupportedGrantType);
    assert_eq!(
        refused.body().to_json(),
        r#"{"error":"unsupported_grant_type","error_description":"the token endpoint serves the authorization_code and token-exchange grants and no other"}"#
    );
}

/// `tests/security/cases.json`, case `pkce-missing`.
#[test]
fn pkce_missing_is_refused_at_the_token_endpoint() {
    let form = token_form()
        .split('&')
        .filter(|pair| !pair.starts_with("code_verifier="))
        .collect::<Vec<_>>()
        .join("&");
    let refused = decode::redeem_authorization_code(&token(&form)).unwrap_err();
    assert_eq!(refused, Refusal::PkceMissing);
    assert_eq!(refused.error_code(), ErrorCode::InvalidRequest);
}

#[test]
fn a_token_request_refuses_a_verifier_outside_the_rfc_7636_form() {
    for verifier in ["short", &"a".repeat(129), "abc def"] {
        let form = token_form().replace(VERIFIER, verifier);
        assert_eq!(
            decode::redeem_authorization_code(&token(&form)).unwrap_err(),
            Refusal::VerifierMalformed,
            "{verifier}"
        );
    }
}

#[test]
fn a_token_request_refuses_a_repeated_parameter() {
    let form = format!("{}&code=YmFy", token_form());
    assert_eq!(
        decode::redeem_authorization_code(&token(&form)).unwrap_err(),
        Refusal::DuplicateField
    );
}

#[test]
fn a_token_request_refuses_another_content_type() {
    let request = Request::new("POST", "/oauth/token")
        .with_header("Content-Type", "application/json")
        .with_body(token_form().into_bytes());
    assert_eq!(
        decode::redeem_authorization_code(&request).unwrap_err(),
        Refusal::ContentTypeUnsupported
    );
}

#[test]
fn a_percent_encoded_credential_survives_the_form_decoding_byte_for_byte() {
    // Base64 carries `+`, `/` and `=`, all of which a form encodes.
    let form = token_form().replace("code=Zm9v", "code=%2B%2F8%3D");
    let input = decode::redeem_authorization_code(&token(&form)).unwrap();
    assert_eq!(input.code.expose_bytes(), &[0xfb, 0xff]);
}

#[test]
fn a_body_over_the_ceiling_is_refused_before_it_is_parsed() {
    let padding = "a".repeat(MAX_BODY_BYTES);
    let form = format!("{}&state={padding}", token_form());
    assert!(form.len() > MAX_BODY_BYTES);
    assert_eq!(
        decode::redeem_authorization_code(&token(&form)).unwrap_err(),
        Refusal::BodyTooLarge
    );
}

#[test]
fn a_body_that_is_not_utf8_is_refused() {
    let request = Request::new("POST", "/oauth/token")
        .with_header("Content-Type", "application/x-www-form-urlencoded")
        .with_body(vec![0xff, 0xfe]);
    assert_eq!(
        decode::redeem_authorization_code(&request).unwrap_err(),
        Refusal::BodyNotUtf8
    );
}

// ------------------------------------------------------ IntrospectCredential, RFC 7662

fn introspect(form: &str) -> Request {
    Request::new("POST", "/oauth/introspect")
        .with_header("Content-Type", "application/x-www-form-urlencoded")
        .with_header("Authorization", "Bearer Y2FsbGVy")
        .with_body(form.as_bytes().to_vec())
}

#[test]
fn an_introspection_takes_the_caller_proof_from_the_header_and_the_credential_from_the_form() {
    let input = decode::introspect_credential(&introspect("token=Zm9v")).unwrap();
    assert_eq!(input.caller_proof.expose_bytes(), b"caller");
    assert_eq!(input.credential_proof.expose_bytes(), b"foo");
}

#[test]
fn an_introspection_reads_the_optional_token_type_hint_and_binds_it_to_nothing() {
    // RFC 7662 section 2.1 declares `token_type_hint` as an optional parameter a server may
    // ignore. `mandate.credential.IntrospectCredential` declares no input it could bind to,
    // so it is read and discarded rather than refused or passed through.
    let input =
        decode::introspect_credential(&introspect("token=Zm9v&token_type_hint=access_token"))
            .unwrap();
    assert_eq!(input.credential_proof.expose_bytes(), b"foo");
    assert_eq!(input.caller_proof.expose_bytes(), b"caller");
}

#[test]
fn an_introspection_refuses_an_undeclared_parameter() {
    let refused = decode::introspect_credential(&introspect("token=Zm9v&audience=x")).unwrap_err();
    assert_eq!(refused, Refusal::UndeclaredField);
}

#[test]
fn an_introspection_refuses_an_absent_caller_proof() {
    let request = Request::new("POST", "/oauth/introspect")
        .with_header("Content-Type", "application/x-www-form-urlencoded")
        .with_body(b"token=Zm9v".to_vec());
    let refused = decode::introspect_credential(&request).unwrap_err();
    assert_eq!(refused, Refusal::MissingCallerProof);
    assert_eq!(refused.error_code(), ErrorCode::InvalidClient);
}

#[test]
fn an_introspection_refuses_an_absent_or_malformed_presented_credential() {
    assert_eq!(
        decode::introspect_credential(&introspect("")).unwrap_err(),
        Refusal::MissingField
    );
    assert_eq!(
        decode::introspect_credential(&introspect("token=not+base64")).unwrap_err(),
        Refusal::MalformedField
    );
}

// ------------------------------------------------------------------ the shape predicates

#[test]
fn the_shape_predicates_decide_form_and_not_correctness() {
    assert!(decode::challenge_has_s256_shape(CHALLENGE));
    assert!(!decode::challenge_has_s256_shape(&CHALLENGE[..42]));
    assert!(!decode::challenge_has_s256_shape(&format!(
        "{}+",
        &CHALLENGE[..42]
    )));
    assert!(decode::verifier_has_rfc7636_shape(VERIFIER));
    assert!(decode::verifier_has_rfc7636_shape(
        &"-._~aB9".repeat(20)[..128]
    ));
    assert!(!decode::verifier_has_rfc7636_shape(&"a".repeat(42)));
    assert!(!decode::verifier_has_rfc7636_shape(&"a".repeat(129)));
    assert!(!decode::verifier_has_rfc7636_shape(&format!(
        "{}!",
        &VERIFIER[..42]
    )));
}

#[test]
fn every_refusal_answers_with_a_standard_oauth_error_code_and_no_caller_text() {
    for refusal in Refusal::ALL {
        let body = refusal.body();
        assert_eq!(body.error, refusal.error_code(), "{refusal:?}");
        assert!(ErrorCode::ALL.contains(&body.error), "{refusal:?}");
        assert!(!body.description.is_empty(), "{refusal:?}");
    }
}

// ============================================================================================
// Adversary pass 1 corrections: each finding's class, enumerated.
//
// The red case for every one of these is in `tests/adversary_adapters_1.rs`, which names one
// instance each. What is below is the rest of the class in each case, because a finding
// answered only at the instance it was reported at is a finding that comes back.
// ============================================================================================

/// One decoder, with a name and a request that is otherwise well formed.
struct Decoder {
    name: &'static str,
    request: Request,
    decode: fn(&Request) -> Result<(), Refusal>,
}

/// The four decoders and a sound fixture for each.
fn every_decoder() -> Vec<Decoder> {
    fn login_of(request: &Request) -> Result<(), Refusal> {
        decode::authenticate_federation(request).map(|_| ())
    }
    fn authorize_of(request: &Request) -> Result<(), Refusal> {
        decode::authorize_public_client(request).map(|_| ())
    }
    fn token_of(request: &Request) -> Result<(), Refusal> {
        decode::redeem_authorization_code(request).map(|_| ())
    }
    fn introspect_of(request: &Request) -> Result<(), Refusal> {
        decode::introspect_credential(request).map(|_| ())
    }
    vec![
        Decoder {
            name: "authenticate_federation",
            request: login(&format!(r#"{{"connection_id":"{UUID}","proof":"Zm9v"}}"#)),
            decode: login_of,
        },
        Decoder {
            name: "authorize_public_client",
            request: authorize(&authorize_query()),
            decode: authorize_of,
        },
        Decoder {
            name: "redeem_authorization_code",
            request: token(&token_form()),
            decode: token_of,
        },
        Decoder {
            name: "introspect_credential",
            request: introspect("token=Zm9v"),
            decode: introspect_of,
        },
    ]
}

/// F7's class: the ceiling is on **both** components of **every** request, not on the one
/// component each decoder happens to read.
#[test]
fn the_byte_ceiling_bounds_the_body_and_the_query_of_all_four_decoders() {
    let oversized = "a".repeat(MAX_BODY_BYTES + 1);
    for entry in every_decoder() {
        let name = entry.name;
        let decode = entry.decode;
        assert!(decode(&entry.request).is_ok(), "{name}: unsound fixture");
        let big_body = entry
            .request
            .clone()
            .with_body(oversized.clone().into_bytes());
        assert_eq!(
            decode(&big_body),
            Err(Refusal::BodyTooLarge),
            "{name}: an oversized body"
        );
        let separator = if entry.request.path.contains('?') {
            "&"
        } else {
            "?"
        };
        let mut big_query = entry.request.clone();
        big_query.path = format!("{}{separator}{oversized}", entry.request.path);
        assert_eq!(
            decode(&big_query),
            Err(Refusal::BodyTooLarge),
            "{name}: an oversized query"
        );
    }
}

/// F5's class: a header presented twice is refused by every decoder, including the two that
/// read no `Authorization` at all. A decoder that ignores a header does not refuse it, and a
/// proxy or an audit reader ahead of it does read it.
#[test]
fn a_repeated_authorization_header_is_refused_by_all_four_decoders() {
    for Decoder {
        name,
        request,
        decode,
    } in every_decoder()
    {
        let doubled = request
            .with_header("Authorization", "Bearer Zm9v")
            .with_header("Authorization", "Bearer YmFy");
        assert_eq!(
            decode(&doubled),
            Err(Refusal::DuplicateHeader),
            "{name}: two Authorization headers"
        );
    }
}

/// F6's class: a caller credential presented to a route whose command declares no input for one
/// is refused, in whichever of RFC 6749 section 2.3.1's two presentations it arrives.
#[test]
fn a_presented_client_credential_is_refused_wherever_no_input_declares_one() {
    let presentations = [
        "Basic Y2xpZW50OnNlY3JldA==",
        "Bearer Zm9v",
        "bearer Zm9v",
        "Digest username=\"client\"",
    ];
    for presented in presentations {
        let at_token = token(&token_form()).with_header("Authorization", presented);
        assert_eq!(
            decode::redeem_authorization_code(&at_token).unwrap_err(),
            Refusal::UndeclaredField,
            "token endpoint: {presented}"
        );
        assert_eq!(
            Refusal::UndeclaredField.error_code(),
            ErrorCode::InvalidRequest,
            "a road that authenticates no client cannot answer invalid_client"
        );
        let at_login = login(&format!(r#"{{"connection_id":"{UUID}","proof":"Zm9v"}}"#))
            .with_header("Authorization", presented);
        assert_eq!(
            decode::authenticate_federation(&at_login).unwrap_err(),
            Refusal::UndeclaredField,
            "federation login: {presented}"
        );
    }
    // The two routes that *do* declare one still read it.
    assert!(decode::authorize_public_client(&authorize(&authorize_query())).is_ok());
    assert!(decode::introspect_credential(&introspect("token=Zm9v")).is_ok());
}

/// F3/F4's class: **every** credential field the wire carries, not the three the finding named.
/// `""` is inside the declared base64 form and decodes to zero bytes, so without this the
/// credential nobody holds reaches a handler as a presented credential.
#[test]
fn no_credential_field_admits_the_empty_or_zero_byte_credential() {
    // 1. the federation login body's `proof`
    for empty in ["", "===="] {
        let body = format!(r#"{{"connection_id":"{UUID}","proof":"{empty}"}}"#);
        assert_eq!(
            decode::authenticate_federation(&login(&body)).unwrap_err(),
            Refusal::MalformedField,
            "login proof {empty:?}"
        );
    }
    // 2. the token endpoint's `code`
    for empty in ["code=", "code=%3D%3D%3D%3D"] {
        let form = token_form().replace("code=Zm9v", empty);
        assert_eq!(
            decode::redeem_authorization_code(&token(&form)).unwrap_err(),
            Refusal::MalformedField,
            "token code {empty:?}"
        );
    }
    // 3. the introspection form's `token`
    assert_eq!(
        decode::introspect_credential(&introspect("token=")).unwrap_err(),
        Refusal::MalformedField
    );
    // 4. the introspection endpoint's bearer caller proof
    let empty_caller = Request::new("POST", "/oauth/introspect")
        .with_header("Content-Type", "application/x-www-form-urlencoded")
        .with_header("Authorization", "Bearer ")
        .with_body(b"token=Zm9v".to_vec());
    assert_eq!(
        decode::introspect_credential(&empty_caller).unwrap_err(),
        Refusal::MalformedCallerProof
    );
    // 5. the authorization endpoint's bearer session proof
    let empty_session = Request::new("GET", &format!("/oauth/authorize?{}", authorize_query()))
        .with_header("Authorization", "Bearer ");
    assert_eq!(
        decode::authorize_public_client(&empty_session).unwrap_err(),
        Refusal::MalformedSessionProof
    );
}

/// F8's class: **every** unconstrained text value the adapter passes through, not `state` alone.
///
/// RFC 6749 section 4.1.2.1 has the authorization endpoint redirect to the presented
/// `redirect_uri` carrying the presented `state` back, and requires the state be "the exact
/// value received from the client". Exact and sanitized cannot both hold, so a value carrying a
/// control character is refused rather than mangled.
#[test]
fn every_free_text_parameter_is_bounded_and_carries_no_control_character() {
    let clean = [
        ("state", "xyz"),
        ("nonce", "abc"),
        ("redirect_uri", ENCODED_REDIRECT),
        ("scope", "read+write"),
    ];
    for (key, present) in clean {
        // Carriage return and line feed: the header-splitting pair.
        for injected in [
            "%0D%0AX-Injected%3A%20yes",
            "%0Amore",
            "%00",
            "%7F",
            "%1B%5B0m",
        ] {
            let query = authorize_query()
                .replace(&format!("{key}={present}"), &format!("{key}={injected}"));
            assert_eq!(
                decode::authorize_public_client(&authorize(&query)).unwrap_err(),
                Refusal::ControlCharacter,
                "{key} carrying {injected}"
            );
        }
        let long = "a".repeat(MAX_TEXT_BYTES + 1);
        let query =
            authorize_query().replace(&format!("{key}={present}"), &format!("{key}={long}"));
        assert_eq!(
            decode::authorize_public_client(&authorize(&query)).unwrap_err(),
            Refusal::TextTooLong,
            "{key} over the bound"
        );
        // Exactly at the bound is admitted: the refusal is a ceiling, not an off-by-one.
        let at_bound = "a".repeat(MAX_TEXT_BYTES);
        let query =
            authorize_query().replace(&format!("{key}={present}"), &format!("{key}={at_bound}"));
        assert!(
            decode::authorize_public_client(&authorize(&query)).is_ok(),
            "{key} at the bound"
        );
    }
}

/// A body presented to a route that reads none is refused, for the same reason a header that
/// reads none is: everything the wire carries is either read or refused.
#[test]
fn the_authorization_endpoint_refuses_a_body_it_would_never_read() {
    let with_body =
        authorize(&authorize_query()).with_body(b"grant_type=authorization_code".to_vec());
    assert_eq!(
        decode::authorize_public_client(&with_body).unwrap_err(),
        Refusal::BodyNotAdmitted
    );
}

// ============================================================================================
// Adversary pass 2 corrections: each finding's class, enumerated.
//
// The red case for F3 is in `tests/adversary_adapters_2.rs`, which names the four smuggled
// parameter names on one decoder. What is below is the class: a route that reads only the body
// admits no query string at all, on each of the three, and the refusal is enumerated where
// every refusal is.
// ============================================================================================

/// The same request, reached with a query string appended to its target.
fn with_query(request: &Request, query: &str) -> Request {
    let mut reached = request.clone();
    reached.path = format!("{}?{query}", request.path);
    reached
}

/// F3's class, first instance: the token endpoint reads its parameters from the body, so a
/// query string is a component nothing on this route reads — and rule 1 refuses the request
/// rather than ignoring what it carries.
#[test]
fn a_token_request_refuses_a_query_string_this_route_reads_nothing_from() {
    let request = token(&token_form());
    assert!(decode::redeem_authorization_code(&request).is_ok());
    for query in [
        "organization_id=evil",
        "code=Zm9vYmFy",
        "grant_type=authorization_code",
        "",
    ] {
        assert_eq!(
            decode::redeem_authorization_code(&with_query(&request, query)).unwrap_err(),
            Refusal::QueryNotAdmitted,
            "POST /oauth/token?{query}"
        );
    }
}

/// F3's class, second instance: RFC 7662 section 2.1 puts the introspection parameters in the
/// body, so the same holds at `/oauth/introspect`.
#[test]
fn an_introspection_refuses_a_query_string_this_route_reads_nothing_from() {
    let request = introspect("token=Zm9v");
    assert!(decode::introspect_credential(&request).is_ok());
    for query in ["token=Zm9vYmFy", "audience=evil", ""] {
        assert_eq!(
            decode::introspect_credential(&with_query(&request, query)).unwrap_err(),
            Refusal::QueryNotAdmitted,
            "POST /oauth/introspect?{query}"
        );
    }
}

/// F3's class, third instance: the federation login reads a JSON body and no parameter at all
/// from its target.
#[test]
fn a_federation_login_refuses_a_query_string_this_route_reads_nothing_from() {
    let request = login(&format!(r#"{{"connection_id":"{UUID}","proof":"Zm9v"}}"#));
    assert!(decode::authenticate_federation(&request).is_ok());
    for query in ["subject=evil", "connection_id=evil", ""] {
        assert_eq!(
            decode::authenticate_federation(&with_query(&request, query)).unwrap_err(),
            Refusal::QueryNotAdmitted,
            "POST /v1/federation/login?{query}"
        );
    }
}

/// The ceiling is measured before the component is refused, on all three.
///
/// `the_byte_ceiling_bounds_the_body_and_the_query_of_all_four_decoders` decides the ceiling
/// itself; what this decides is the *order*, which the new refusal could have taken away: an
/// oversized query on a body route is still `BodyTooLarge`, because a request nobody will read
/// is refused by its size before any component of it is looked at.
#[test]
fn an_oversized_query_on_a_body_route_is_still_refused_by_the_ceiling() {
    let oversized = "a".repeat(MAX_BODY_BYTES + 1);
    assert_eq!(
        decode::redeem_authorization_code(&with_query(&token(&token_form()), &oversized))
            .unwrap_err(),
        Refusal::BodyTooLarge
    );
    assert_eq!(
        decode::introspect_credential(&with_query(&introspect("token=Zm9v"), &oversized))
            .unwrap_err(),
        Refusal::BodyTooLarge
    );
    let body = format!(r#"{{"connection_id":"{UUID}","proof":"Zm9v"}}"#);
    assert_eq!(
        decode::authenticate_federation(&with_query(&login(&body), &oversized)).unwrap_err(),
        Refusal::BodyTooLarge
    );
}

/// Every refusal the enum declares is named in [`Refusal::ALL`].
///
/// `Refusal::ALL` is what `every_refusal_answers_with_a_standard_oauth_error_code_and_no_caller
/// _text` iterates, so a variant absent from it is a refusal no case has ever rendered — and
/// the list is hand-maintained, which is the defect `QueryNotAdmitted` would otherwise have
/// been the next instance of. The variant names are read from the source that declares them,
/// so the list cannot fall behind the enum without failing here, naming what is missing.
#[test]
fn every_declared_refusal_is_named_in_the_list_the_cases_read() {
    const SOURCE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/decode.rs");
    let source = std::fs::read_to_string(SOURCE).expect("the decode source");
    let body = source
        .split_once("pub enum Refusal {")
        .expect("the Refusal declaration")
        .1;
    let body = body.split_once("\n}").expect("the declaration's end").0;
    let declared: std::collections::BTreeSet<String> = body
        .lines()
        .map(str::trim)
        .filter(|line| line.ends_with(',') && !line.starts_with("///"))
        .map(|line| line.trim_end_matches(',').to_owned())
        .collect();
    let enumerated: std::collections::BTreeSet<String> = Refusal::ALL
        .iter()
        .map(|refusal| format!("{refusal:?}"))
        .collect();
    assert!(declared.len() > 20, "read {} variants", declared.len());
    assert_eq!(
        declared, enumerated,
        "a declared refusal that `Refusal::ALL` does not name"
    );
}

// --------------------------------- ExchangeCredential, RFC 8693 at the token endpoint

fn registration(id: &str) -> decode::ExchangeTarget {
    decode::ExchangeTarget::Registration(mandate_types::ResourceServerId::parse(id).unwrap())
}

const EXCHANGE_GRANT: &str = "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange";
const ACCESS_TOKEN: &str = "urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token";

fn exchange_form() -> String {
    format!(
        "grant_type={EXCHANGE_GRANT}&subject_token=Zm9v&subject_token_type={ACCESS_TOKEN}\
         &audience={UUID}&scope=read"
    )
}

#[test]
fn a_token_exchange_decodes_the_declared_input_subject_only() {
    let input = decode::exchange_credential(&token(&exchange_form())).unwrap();
    assert_eq!(input.subject_proof.expose_bytes(), b"foo");
    assert_eq!(input.target, registration(UUID));
    assert_eq!(
        input
            .requested_scope
            .actions
            .iter()
            .map(|action| action.as_str().to_owned())
            .collect::<Vec<_>>(),
        vec!["read".to_owned()]
    );
    // Subject-only (`story:federated-token-exchange`): the wire carries no actor and no
    // delegation, and the two declared inputs that would bind them are absent.
    assert!(input.actor_proof.is_none());
    assert!(input.delegation_id.is_none());
    assert_eq!(
        decode::ExchangeCredential::DECLARED_INPUTS,
        &[
            "subject_proof",
            "actor_proof",
            "target",
            "requested_scope",
            "delegation_id"
        ]
    );
}

#[test]
fn a_token_exchange_names_its_target_by_audience_or_by_a_uuid_resource() {
    let by_resource = exchange_form().replace(
        &format!("audience={UUID}"),
        &format!("resource=urn%3Auuid%3A{UUID}"),
    );
    let input = decode::exchange_credential(&token(&by_resource)).unwrap();
    assert_eq!(input.target, registration(UUID));

    // Correction round 1, F4: an audience that is not a registration identity is the name of
    // one, RFC 8693 section 2.1's "logical name of the target service", and is carried to the
    // handler as a name; the handler resolves it within the subject's organization.
    let by_name = exchange_form().replace(&format!("audience={UUID}"), "audience=platform-api");
    assert_eq!(
        decode::exchange_credential(&token(&by_name))
            .unwrap()
            .target,
        decode::ExchangeTarget::Audience(mandate_types::Audience::new("platform-api"))
    );
    // A name is free text on the wire, and bounded like every other.
    let long = exchange_form().replace(
        &format!("audience={UUID}"),
        &format!("audience={}", "a".repeat(MAX_TEXT_BYTES + 1)),
    );
    assert_eq!(
        decode::exchange_credential(&token(&long)).unwrap_err(),
        Refusal::TextTooLong
    );

    // Both, or neither, is not one target.
    let both = format!("{}&resource=urn%3Auuid%3A{UUID}", exchange_form());
    assert_eq!(
        decode::exchange_credential(&token(&both)).unwrap_err(),
        Refusal::TargetAmbiguous
    );
    let neither = exchange_form().replace(&format!("&audience={UUID}"), "");
    assert_eq!(
        decode::exchange_credential(&token(&neither)).unwrap_err(),
        Refusal::MissingField
    );
    // A resource that is not the URN of a registration identity is a malformed target, and is
    // still the decoder's refusal.
    for malformed in [
        exchange_form().replace(
            &format!("audience={UUID}"),
            "resource=https%3A%2F%2Fapi.example",
        ),
        exchange_form().replace(
            &format!("audience={UUID}"),
            "resource=urn%3Auuid%3Anot-a-uuid",
        ),
    ] {
        assert_eq!(
            decode::exchange_credential(&token(&malformed)).unwrap_err(),
            Refusal::MalformedField,
            "{malformed}"
        );
    }
}

#[test]
fn a_token_exchange_admits_only_the_access_token_type() {
    let refresh = exchange_form().replace(
        ACCESS_TOKEN,
        "urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Arefresh_token",
    );
    let refused = decode::exchange_credential(&token(&refresh)).unwrap_err();
    assert_eq!(refused, Refusal::UnsupportedTokenType);
    assert_eq!(refused.error_code(), ErrorCode::InvalidRequest);

    let missing = exchange_form().replace(&format!("&subject_token_type={ACCESS_TOKEN}"), "");
    assert_eq!(
        decode::exchange_credential(&token(&missing)).unwrap_err(),
        Refusal::MissingField
    );

    let requested = format!("{}&requested_token_type={ACCESS_TOKEN}", exchange_form());
    assert!(decode::exchange_credential(&token(&requested)).is_ok());
    let requested_other = format!(
        "{}&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aid_token",
        exchange_form()
    );
    assert_eq!(
        decode::exchange_credential(&token(&requested_other)).unwrap_err(),
        Refusal::UnsupportedTokenType
    );
}

#[test]
fn a_token_exchange_carries_an_actor_to_the_handler_and_refuses_every_undeclared_parameter() {
    // Correction round 1, F3: an actor is not refused here. It reaches the handler, which
    // refuses it as `ExchangeNotSubjectOnly` and records the refusal; a decoder refusal
    // would record nothing.
    for extra in [
        "actor_token=YmFy".to_owned(),
        format!("actor_token_type={ACCESS_TOKEN}"),
        format!("actor_token=YmFy&actor_token_type={ACCESS_TOKEN}"),
        "actor_token=not%20base64".to_owned(),
    ] {
        let form = format!("{}&{extra}", exchange_form());
        let input = decode::exchange_credential(&token(&form)).unwrap();
        assert!(
            input.actor_proof.is_some(),
            "{extra}: the actor reaches the handler"
        );
    }
    for extra in ["client_secret=s", "organization_id=x", "code=Zm9v"] {
        let form = format!("{}&{extra}", exchange_form());
        assert_eq!(
            decode::exchange_credential(&token(&form)).unwrap_err(),
            Refusal::UndeclaredField,
            "{extra}"
        );
    }
    // A presented client credential is authority the command has no input for.
    let authenticated = token(&exchange_form()).with_header("Authorization", "Basic Zm9vOmJhcg==");
    assert_eq!(
        decode::exchange_credential(&authenticated).unwrap_err(),
        Refusal::UndeclaredField
    );
}

#[test]
fn a_token_exchange_refuses_a_missing_or_empty_subject_token_and_a_missing_scope() {
    let missing = exchange_form().replace("&subject_token=Zm9v", "");
    assert_eq!(
        decode::exchange_credential(&token(&missing)).unwrap_err(),
        Refusal::MissingField
    );
    let empty = exchange_form().replace("subject_token=Zm9v", "subject_token=");
    assert_eq!(
        decode::exchange_credential(&token(&empty)).unwrap_err(),
        Refusal::MalformedField
    );
    let unscoped = exchange_form().replace("&scope=read", "");
    assert_eq!(
        decode::exchange_credential(&token(&unscoped)).unwrap_err(),
        Refusal::MissingField
    );
}

#[test]
fn the_token_endpoint_dispatches_on_the_grant_type() {
    assert!(matches!(
        decode::token_request(&token(&token_form())).unwrap(),
        decode::TokenRequest::AuthorizationCode(_)
    ));
    assert!(matches!(
        decode::token_request(&token(&exchange_form())).unwrap(),
        decode::TokenRequest::TokenExchange(_)
    ));
    // Each grant's own parameter set is closed: a code-grant parameter on an exchange, and an
    // exchange parameter on a code grant, are both undeclared.
    let crossed = format!("{}&subject_token=Zm9v", token_form());
    assert_eq!(
        decode::token_request(&token(&crossed)).unwrap_err(),
        Refusal::UndeclaredField
    );
    let refused = decode::token_request(&token(
        &token_form().replace("authorization_code", "password"),
    ))
    .unwrap_err();
    assert_eq!(refused, Refusal::UnsupportedGrantType);
    assert_eq!(
        refused.body().to_json(),
        r#"{"error":"unsupported_grant_type","error_description":"the token endpoint serves the authorization_code and token-exchange grants and no other"}"#
    );
    let ungranted = token_form().replace("grant_type=authorization_code&", "");
    assert_eq!(
        decode::token_request(&token(&ungranted)).unwrap_err(),
        Refusal::MissingField
    );
    // The entry gate runs before the grant is read.
    assert_eq!(
        decode::token_request(&Request::new("POST", "/oauth/token?grant_type=x")).unwrap_err(),
        Refusal::QueryNotAdmitted
    );
}
