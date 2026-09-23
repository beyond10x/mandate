//! The two documents a client discovers this deployment through.
//!
//! RFC 8414 section 2 for the authorization server metadata and RFC 7517 section 5 for the
//! JWK Set. Both are **shapes**: this crate builds them and serves neither, and the JWKS
//! carries no key material at all — `story:product-listener`'s composition fills it from the
//! signing keys `story:signing-and-verification` landed.
//!
//! Every endpoint in the metadata is read from `mandate_server::routes::ROUTES`, so a route
//! the table moves is a metadata document that moves with it. `original-design.md:1866`:
//! "Endpoint layout can differ, but metadata MUST accurately advertise it" — advertising it
//! from the same data the listener dispatches is how that is kept true rather than promised.

use mandate_server::metadata::{self, Jwk, JwkRefusal, Jwks};
use mandate_server::routes::{self, Binding, Document, ROUTES};

const ISSUER: &str = "https://mandate.example";

#[test]
fn the_metadata_advertises_every_endpoint_from_the_route_table() {
    let document = metadata::authorization_server_metadata(ISSUER);
    assert_eq!(document.issuer, ISSUER);
    assert_eq!(
        document.authorization_endpoint,
        format!("{ISSUER}/oauth/authorize")
    );
    assert_eq!(document.token_endpoint, format!("{ISSUER}/oauth/token"));
    assert_eq!(
        document.introspection_endpoint,
        format!("{ISSUER}/oauth/introspect")
    );
    assert_eq!(document.jwks_uri, format!("{ISSUER}/oauth/jwks"));
}

#[test]
fn an_advertised_endpoint_is_the_route_table_s_own_path_and_not_a_second_copy() {
    let document = metadata::authorization_server_metadata(ISSUER);
    for (advertised, command) in [
        (
            &document.authorization_endpoint,
            "mandate.federation.AuthorizePublicClient",
        ),
        (
            &document.token_endpoint,
            "mandate.credential.RedeemAuthorizationCode",
        ),
        (
            &document.introspection_endpoint,
            "mandate.credential.IntrospectCredential",
        ),
    ] {
        let path = routes::route_for_command(command).unwrap().path;
        assert_eq!(advertised, &format!("{ISSUER}{path}"), "{command}");
    }
    let jwks = routes::route_for_document(Document::Jwks).unwrap().path;
    assert_eq!(document.jwks_uri, format!("{ISSUER}{jwks}"));
}

#[test]
fn the_metadata_declares_the_policy_this_deployment_actually_enforces() {
    let document = metadata::authorization_server_metadata(ISSUER);
    assert_eq!(document.response_types_supported, vec!["code".to_owned()]);
    // The two grants `decode::token_request` dispatches: the authorization code, and RFC 8693
    // token exchange (`story:federated-token-exchange`).
    assert_eq!(
        document.grant_types_supported,
        vec![
            "authorization_code".to_owned(),
            "urn:ietf:params:oauth:grant-type:token-exchange".to_owned()
        ]
    );
    // `mandate.core.PkceMethod` declares exactly one variant.
    assert_eq!(
        document.code_challenge_methods_supported,
        vec!["S256".to_owned()]
    );
    // The login road is the public-client road: `AuthorizePublicClient`, and a token endpoint
    // that refuses `client_secret` as an undeclared parameter.
    assert_eq!(
        document.token_endpoint_auth_methods_supported,
        vec!["none".to_owned()]
    );
}

#[test]
fn a_trailing_slash_on_the_issuer_does_not_double_a_separator() {
    let document = metadata::authorization_server_metadata("https://mandate.example/");
    assert_eq!(document.issuer, "https://mandate.example");
    assert_eq!(
        document.token_endpoint,
        "https://mandate.example/oauth/token"
    );
}

#[test]
fn the_metadata_renders_the_nine_declared_members_and_no_more() {
    let rendered = metadata::authorization_server_metadata(ISSUER).to_json();
    assert_eq!(
        rendered,
        concat!(
            r#"{"authorization_endpoint":"https://mandate.example/oauth/authorize","#,
            r#""code_challenge_methods_supported":["S256"],"#,
            r#""grant_types_supported":["authorization_code","urn:ietf:params:oauth:grant-type:token-exchange"],"#,
            r#""introspection_endpoint":"https://mandate.example/oauth/introspect","#,
            r#""issuer":"https://mandate.example","#,
            r#""jwks_uri":"https://mandate.example/oauth/jwks","#,
            r#""response_types_supported":["code"],"#,
            r#""token_endpoint":"https://mandate.example/oauth/token","#,
            r#""token_endpoint_auth_methods_supported":["none"]}"#
        )
    );
}

#[test]
fn the_metadata_advertises_no_endpoint_this_deployment_does_not_serve() {
    let rendered = metadata::authorization_server_metadata(ISSUER).to_json();
    for absent in [
        "revocation_endpoint",
        "registration_endpoint",
        "device_authorization_endpoint",
        "userinfo_endpoint",
        "scopes_supported",
    ] {
        assert!(!rendered.contains(absent), "{absent}");
    }
    // Nor the federation login route, which is a control-plane product route and not part of
    // the OAuth surface RFC 8414 describes.
    assert!(!rendered.contains("/v1/federation/login"));
    assert!(
        routes::route_for_command("mandate.federation.AuthenticateFederation")
            .is_some_and(|route| route.path == "/v1/federation/login")
    );
}

#[test]
fn a_jwks_carries_no_key_material_of_its_own() {
    let empty = Jwks::empty();
    assert!(empty.keys.is_empty());
    assert_eq!(empty.to_json(), r#"{"keys":[]}"#);
}

#[test]
fn a_jwks_renders_the_public_members_the_composition_fills_it_with() {
    let jwks = Jwks::new(vec![
        Jwk::new(
            "EC",
            "one",
            "sig",
            "ES256",
            &[("crv", "P-256"), ("x", "AAAA"), ("y", "BBBB")],
        )
        .unwrap(),
    ])
    .unwrap();
    assert_eq!(
        jwks.to_json(),
        concat!(
            r#"{"keys":[{"alg":"ES256","crv":"P-256","kid":"one","kty":"EC","#,
            r#""use":"sig","x":"AAAA","y":"BBBB"}]}"#
        )
    );
}

#[test]
fn a_jwks_member_is_the_rfc_7517_name_use_and_not_the_rust_field_name() {
    let jwks = Jwks::new(vec![Jwk::new("oct", "k", "sig", "A", &[]).unwrap()]).unwrap();
    let rendered = jwks.to_json();
    assert!(rendered.contains(r#""use":"sig""#), "{rendered}");
    assert!(!rendered.contains("key_use"), "{rendered}");
}

#[test]
fn both_documents_are_published_at_a_route_this_table_declares() {
    let published: Vec<&str> = ROUTES
        .iter()
        .filter(|route| matches!(route.binds, Binding::Document(_)))
        .map(|route| route.path)
        .collect();
    assert_eq!(
        published,
        vec!["/.well-known/oauth-authorization-server", "/oauth/jwks"]
    );
}

// ============================================================================================
// Adversary pass 1, F9 and F10: the published JWK member set is closed.
//
// The two red cases are in `tests/adversary_adapters_1.rs` — one private member rendered, one
// declared member silently replaced. Both are instances of one defect: a published document
// assembled from member names nobody checked. What follows is the class.
// ============================================================================================

/// RFC 7517 section 9.2 and RFC 7518 sections 6.2.2, 6.3.2 and 6.4.1: every private member.
const PRIVATE_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "k"];

#[test]
fn the_admitted_member_set_is_the_nine_public_names_and_no_others() {
    assert_eq!(Jwk::DECLARED_MEMBERS, ["kty", "kid", "use", "alg"]);
    assert_eq!(Jwk::ADMITTED_PARAMETERS, ["n", "e", "crv", "x", "y"]);
    for private in PRIVATE_MEMBERS {
        assert!(!Jwk::ADMITTED_PARAMETERS.contains(private), "{private}");
        assert!(!Jwk::DECLARED_MEMBERS.contains(private), "{private}");
    }
}

#[test]
fn the_constructor_refuses_every_private_member() {
    for private in PRIVATE_MEMBERS {
        assert_eq!(
            Jwk::new("RSA", "one", "sig", "A", &[(private, "cHJpdmF0ZQ")]).unwrap_err(),
            JwkRefusal::UndeclaredParameter,
            "{private}"
        );
    }
    // And anything else nobody admitted, including a member RFC 7517 may add later.
    for unknown in ["x5c", "x5t", "oth", "key_ops", "ext", ""] {
        assert_eq!(
            Jwk::new("RSA", "one", "sig", "A", &[(unknown, "v")]).unwrap_err(),
            JwkRefusal::UndeclaredParameter,
            "{unknown}"
        );
    }
}

#[test]
fn the_constructor_refuses_a_parameter_that_collides_with_a_declared_member() {
    for declared in Jwk::DECLARED_MEMBERS {
        assert_eq!(
            Jwk::new("EC", "declared", "sig", "A", &[(declared, "replaced")]).unwrap_err(),
            JwkRefusal::DeclaredMemberCollision,
            "{declared}"
        );
    }
}

#[test]
fn the_constructor_refuses_a_repeated_parameter() {
    assert_eq!(
        Jwk::new("EC", "one", "sig", "A", &[("x", "a"), ("x", "b")]).unwrap_err(),
        JwkRefusal::DuplicateParameter
    );
}

#[test]
fn the_constructor_carries_the_admitted_public_members() {
    let key = Jwk::new(
        "EC",
        "one",
        "sig",
        "ES256",
        &[("crv", "P-256"), ("x", "A"), ("y", "B")],
    )
    .unwrap();
    assert_eq!(
        Jwks::new(vec![key]).unwrap().to_json(),
        concat!(
            r#"{"keys":[{"alg":"ES256","crv":"P-256","kid":"one","kty":"EC","#,
            r#""use":"sig","x":"A","y":"B"}]}"#
        )
    );
}

/// The constructor is the only way in, so what it refused is what the document never carries.
///
/// `Jwk::parameters` is private (pass 2, F7): a struct literal naming it does not compile
/// outside the crate, which is what makes [`Jwk::new`]'s refusal the whole enforcement rather
/// than the first of two. The refusal is decided above; what this decides is the other half —
/// that a key the constructor *admitted* renders every member it was given, so the rendering
/// drops nothing and a document is the key it was handed.
#[test]
fn what_the_constructor_admits_is_what_the_document_carries() {
    let key = Jwk::new(
        "RSA",
        "signing-1",
        "sig",
        "RS256",
        &[("n", "AAAA"), ("e", "AQAB")],
    )
    .unwrap();
    assert_eq!(
        key.parameters(),
        [
            ("n".to_owned(), "AAAA".to_owned()),
            ("e".to_owned(), "AQAB".to_owned()),
        ]
    );
    let rendered = Jwks::new(vec![key]).unwrap().to_json();
    for member in [r#""n":"AAAA""#, r#""e":"AQAB""#, r#""kid":"signing-1""#] {
        assert!(rendered.contains(member), "{member} is not in {rendered}");
    }
    for private in PRIVATE_MEMBERS {
        assert!(
            !rendered.contains(&format!("\"{private}\":")),
            "{private} reached the document: {rendered}"
        );
    }
}

// ============================================================================================
// Adversary pass 2, F8: a key set that names one `kid` twice.
// ============================================================================================

/// RFC 7517 section 4.5: `kid` is how a reader picks the key a signature names, so two keys
/// carrying one `kid` is a set in which that reader's choice is undefined — the same defect as
/// a repeated form parameter (`adapter-contract.md` rule 4), in the document a client resolves
/// a signing key out of. The set is refused at its constructor rather than resolved.
#[test]
fn a_key_set_refuses_two_keys_that_carry_the_same_kid() {
    let one = Jwk::new("EC", "signing-1", "sig", "ES256", &[("crv", "P-256")]).unwrap();
    let two = Jwk::new("RSA", "signing-2", "sig", "RS256", &[("n", "AAAA")]).unwrap();
    let repeat = Jwk::new("RSA", "signing-1", "sig", "RS256", &[("n", "BBBB")]).unwrap();

    let set = Jwks::new(vec![one.clone(), two.clone()]).expect("two distinct kids");
    assert_eq!(set.keys, vec![one.clone(), two]);
    assert!(Jwks::new(Vec::new()).is_ok());

    assert_eq!(
        Jwks::new(vec![one, repeat]).unwrap_err(),
        JwkRefusal::RepeatedKeyId
    );
}

/// **Every grant the document advertises is one the token endpoint dispatches**, and a grant
/// it does not advertise is refused there.
///
/// The class, not the two instances: an advertised grant the decoder refused would be a
/// document lying to every client that read it, which is the failure RFC 8414 exists to
/// prevent. Each advertised value is put through `decode::token_request` and must be refused,
/// if at all, for something other than its grant type.
#[test]
fn every_advertised_grant_is_one_the_token_endpoint_dispatches() {
    use mandate_server::decode::{self, Refusal, Request};

    let document = metadata::authorization_server_metadata(ISSUER);
    let token = |grant: &str| {
        Request::new("POST", "/oauth/token")
            .with_header("Content-Type", "application/x-www-form-urlencoded")
            .with_body(format!("grant_type={}", grant.replace(':', "%3A")).into_bytes())
    };
    for grant in &document.grant_types_supported {
        let decoded = decode::token_request(&token(grant));
        assert_ne!(
            decoded.err(),
            Some(Refusal::UnsupportedGrantType),
            "{grant} is advertised and refused as unsupported"
        );
    }
    assert_eq!(
        decode::token_request(&token("password")).err(),
        Some(Refusal::UnsupportedGrantType)
    );
}
