//! Adversary pass 1 against `story:login-adapters`.
//!
//! Every case here drives a claim the unit wrote about itself —
//! `docs/architecture/adapter-contract.md` — against the code the same unit wrote. The
//! document is read as the specification it says it is ("The rules below hold for all four
//! decoders", `:55`), not as commentary.
//!
//! Nothing here changes an implementation file.

use mandate_proto::oauth::ErrorCode;
use mandate_server::decode::{self, MAX_BODY_BYTES, Refusal, Request};
use mandate_server::metadata::{Jwk, JwkRefusal, Jwks};

const UUID: &str = "1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b";
const OTHER_UUID: &str = "2c5f39cb-3fb2-4e9f-c2c1-9d2e5f607b8c";
const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const ENCODED_REDIRECT: &str = "https%3A%2F%2Fapp.example%2Fcb";

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

fn login(body: &str) -> Request {
    Request::new("POST", "/v1/federation/login")
        .with_header("Content-Type", "application/json")
        .with_body(body.as_bytes().to_vec())
}

// ------------------------------------------------- adapter-contract.md, rule 5 (`:73-74`)

/// `adapter-contract.md:53-55,73-74`: "The rules below hold for **all four decoders**. ...
/// **There is a byte ceiling**, `decode::MAX_BODY_BYTES`, checked before anything is parsed,
/// **on the body and on the query string alike**."
///
/// `decode::authorize_public_client` checks `request.query().len()` and never
/// `request.body.len()`, so the ceiling the document states for all four decoders holds for
/// three.
#[test]
fn the_authorization_decoder_does_not_bound_the_body_the_contract_says_it_bounds() {
    let oversized = authorize(&authorize_query()).with_body(vec![b'a'; MAX_BODY_BYTES + 1]);
    assert_eq!(
        decode::authorize_public_client(&oversized).map(|_| ()),
        Err(Refusal::BodyTooLarge),
        "adapter-contract.md:73 states the ceiling on the body for all four decoders"
    );
}

// ------------------------------------------------- adapter-contract.md, rule 4 (`:70-72`)

/// `adapter-contract.md:70-72`: "**A repeat is refused, not resolved.** A parameter presented
/// twice **and a header presented twice** are both refusals. Every rule for picking one of two
/// values is a rule an attacker can aim at a reader that picked the other."
///
/// `decode::redeem_authorization_code` never reads `Authorization`, so the token endpoint
/// admits it twice — the exact "reader that picked the other" shape the rule is written
/// against, since a proxy or an audit reader ahead of this decoder does read it.
#[test]
fn a_repeated_authorization_header_is_admitted_at_the_token_endpoint() {
    let doubled = token(&token_form())
        .with_header("Authorization", "Bearer Zm9v")
        .with_header("Authorization", "Bearer YmFy");
    assert_eq!(
        decode::redeem_authorization_code(&doubled).map(|_| ()),
        Err(Refusal::DuplicateHeader),
        "adapter-contract.md:70 states a header presented twice is a refusal for all four decoders"
    );
}

/// `adapter-contract.md:119-121`: "`client_secret` is not an admitted parameter: this is the
/// public-client road, and the metadata document advertises
/// `token_endpoint_auth_methods_supported: [\"none\"]` **because the decoder refuses it**."
///
/// RFC 6749 section 2.3.1 makes the `Authorization: Basic` form the *preferred* presentation of
/// a client secret and the body parameter the fallback. The decoder refuses the fallback and
/// admits the preferred form, so `["none"]` is enforced against one of the two presentations
/// the RFC declares.
#[test]
fn the_token_endpoint_admits_the_rfc_6749_basic_client_credential() {
    // base64("client:secret")
    let authenticated =
        token(&token_form()).with_header("Authorization", "Basic Y2xpZW50OnNlY3JldA==");
    assert_eq!(
        decode::redeem_authorization_code(&authenticated).map(|_| ()),
        Err(Refusal::UndeclaredField),
        "metadata.rs:19-22 rests `token_endpoint_auth_methods_supported: [\"none\"]` on the \
         decoder refusing a presented client credential"
    );
}

// ------------------------------------------------------------- the empty-string boundary

/// `adapter-contract.md:130`: the introspection endpoint refuses "an absent or **malformed**
/// presented credential".
///
/// `token=` is present and well formed: `CredentialProof::parse_base64("")` is `Ok(vec![])`,
/// so a zero-byte credential — the credential nobody holds — reaches the handler as the
/// presented credential. `oauth::require_code_verifier` checks `!verifier.is_empty()` for the
/// one field the same commit thought of, so the omission is not a house style.
#[test]
fn an_empty_token_is_admitted_as_the_presented_credential() {
    let decoded = decode::introspect_credential(&introspect("token="));
    assert!(
        decoded.is_err(),
        "an empty token decoded to a {}-byte credential_proof",
        decoded
            .map(|input| input.credential_proof.expose_bytes().len())
            .unwrap_or_default()
    );
}

/// The same boundary on the other two credential fields the wire carries: `code` at the token
/// endpoint (`adapter-contract.md:116`, "a value outside the lexical form its declared type
/// admits") and `proof` in the federation login body (`:91`).
///
/// The empty string is inside the declared base64 form, so both decode to a zero-byte
/// `mandate.core.CredentialProof` rather than being refused.
#[test]
fn an_empty_code_and_an_empty_federation_proof_are_admitted_as_credentials() {
    let empty_code = token_form().replace("code=Zm9v", "code=");
    assert!(
        decode::redeem_authorization_code(&token(&empty_code)).is_err(),
        "an empty `code` decoded into the declared input"
    );
    assert!(
        decode::authenticate_federation(&login(&format!(
            r#"{{"connection_id":"{UUID}","proof":""}}"#
        )))
        .is_err(),
        "an empty `proof` decoded into the declared input"
    );
}

// -------------------------------------------------------------- what reaches the listener

/// `adapter-contract.md:211-213`: at the authorization endpoint the error "is returned by
/// redirecting to a validated redirect URI rather than as a body. This library produces the
/// error value; **the rendering is the listener's**."
///
/// RFC 6749 section 4.1.2.1 requires `state` to be returned on that redirect, so the listener
/// this library hands a decoded `state` to must put it in a `Location` header. The decoder
/// percent-decodes it and names no bound, so CR/LF reaches the listener inside the one value
/// the protocol obliges it to echo into a header.
///
/// Ruling 4 of correction round 1 answers this by **refusing** such a request, not by
/// admitting it with a sanitized state: RFC 6749 section 4.1.2.1 requires the state be "the
/// exact value received from the client", and exact and sanitized cannot both hold. Restated
/// by the coordinator against that behaviour.
#[test]
fn the_authorization_decoder_passes_crlf_through_the_state_the_listener_must_echo() {
    let injected = authorize_query().replace("state=xyz", "state=xyz%0D%0AX-Injected%3A%20yes");
    let refused = decode::authorize_public_client(&authorize(&injected))
        .expect_err("a state carrying CR/LF must not reach the listener that echoes it");
    assert_eq!(
        refused,
        Refusal::ControlCharacter,
        "the refusal names the control character, not a generic malformed body"
    );
}

// --------------------------------------------------------- adapter-contract.md, `:226-227`

/// `adapter-contract.md:226`: "**The JWK Set carries no key material**: this crate holds no
/// signer and no key store, and the composition in `services/control-plane` fills the list."
///
/// `metadata::Jwk::parameters` is an open `Vec<(String, String)>` with no admitted-name set,
/// so RFC 7517 section 9.2's private members — `d`, `p`, `q`, `dp`, `dq`, `qi`, `k` — render
/// into the published document exactly as `crv`/`x`/`y` do. The existing case
/// (`tests/metadata.rs:130`) decides the claim for `Jwks::empty()` alone.
#[test]
fn a_jwk_renders_the_private_member_the_contract_says_the_document_never_carries() {
    // Pass 2, F7: `Jwk::parameters` is private, so the struct literal this case was written
    // with no longer compiles and `Jwk::new` is the only way a key is built. The claim is
    // unchanged — no private member reaches the published document — and it is now decided at
    // the one construction site rather than at the rendering.
    assert_eq!(
        Jwk::new(
            "RSA",
            "signing-1",
            "sig",
            "RS256",
            &[("n", "AAAA"), ("e", "AQAB"), ("d", "cHJpdmF0ZQ")],
        )
        .unwrap_err(),
        JwkRefusal::UndeclaredParameter,
        "a private JWK member was carried into a key"
    );
    let admitted = Jwk::new("RSA", "signing-1", "sig", "RS256", &[("n", "AAAA")]).unwrap();
    let rendered = Jwks::new(vec![admitted]).unwrap().to_json();
    for private in [
        "\"d\":", "\"p\":", "\"q\":", "\"dp\":", "\"dq\":", "\"qi\":", "\"k\":",
    ] {
        assert!(
            !rendered.contains(private),
            "a private JWK member reached the published document: {rendered}"
        );
    }
}

/// The same open member set, used the other way: a `parameters` entry whose name collides with
/// a declared member silently replaces it.
///
/// `Jwk::members` appends `parameters` after `kty`/`kid`/`use`/`alg`, and `oauth::object`
/// builds a `serde_json::Map`, so the later insert wins. Everywhere else in this unit a
/// repeat is refused rather than resolved (`adapter-contract.md:70-72`); here it is resolved,
/// silently, in the document a client reads a signing key's identity out of.
#[test]
fn a_jwk_parameter_silently_replaces_the_declared_member_it_collides_with() {
    // Pass 2, F7: the same move as the case above — the collision is refused where the key is
    // built, and the document a reader resolves a `kid` out of cannot be handed one.
    assert_eq!(
        Jwk::new("EC", "declared", "sig", "ES256", &[("kid", "replaced")]).unwrap_err(),
        JwkRefusal::DeclaredMemberCollision,
        "a parameter replaced the declared member it collides with"
    );
    let key = Jwk::new("EC", "declared", "sig", "ES256", &[("crv", "P-256")]).unwrap();
    let rendered = Jwks::new(vec![key]).unwrap().to_json();
    assert!(
        rendered.contains(r#""kid":"declared""#),
        "the declared kid was replaced by a parameter of the same name: {rendered}"
    );
}

// ------------------------------------------------------------------ a control, kept green

/// Not an attack: the closed parameter sets are what the rest of the file is measured
/// against, so a change that widened one would show up here rather than silently making a
/// case above vacuous.
#[test]
fn the_closed_parameter_sets_are_the_ones_the_cases_above_assume() {
    assert!(!decode::TOKEN_PARAMETERS.contains(&"client_secret"));
    assert!(!decode::TOKEN_PARAMETERS.contains(&"scope"));
    assert!(decode::INTROSPECT_PARAMETERS.contains(&"token"));
    assert!(decode::AUTHORIZE_PARAMETERS.contains(&"state"));
    assert_eq!(
        Refusal::MethodNotAllowed.error_code(),
        ErrorCode::InvalidRequest
    );
}
