//! The OAuth road's wire encodings: form decoding, the standard error bodies, and the
//! mapping from the STS's declared denial clauses onto them.
//!
//! Two of these cases are named for the contract corpus entries they are the wire half of:
//! `pkce-missing` (`tests/security/cases.json`, "Public client omits verifier") and
//! `pkce-plain` ("Challenge method plain"). Both are refusals the wire form decides, before
//! any handler is reached, so they belong here and not to a deciding handler.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;

use mandate_proto::oauth::{self, ErrorBody, ErrorCode, FormError, JsonError, Member, S256_METHOD};
use mandate_token::projection::DenialClause;
use mandate_types::DenialReason;

/// The STS crate's source directory: the module set the redemption traversal below walks.
const STS_SRC: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../services/sts/src");
const PROJECTION: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../crates/mandate-token/src/projection.rs"
);
/// Where `mandate-federation` refuses a client at the authorization endpoint.
const PUBLIC_CLIENT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../crates/mandate-federation/src/publicclient.rs"
);

#[test]
fn a_form_is_split_on_ampersand_and_equals() {
    let form = oauth::decode_form("grant_type=authorization_code&client_id=abc").unwrap();
    assert_eq!(form.get("grant_type"), Some("authorization_code"));
    assert_eq!(form.get("client_id"), Some("abc"));
    assert_eq!(form.len(), 2);
    assert!(form.get("code").is_none());
}

#[test]
fn an_empty_body_is_an_empty_form() {
    let form = oauth::decode_form("").unwrap();
    assert!(form.is_empty());
    assert_eq!(form.len(), 0);
}

#[test]
fn a_value_is_percent_decoded_with_plus_as_space() {
    let form = oauth::decode_form("redirect_uri=https%3A%2F%2Fapp.example%2Fcb&state=a+b").unwrap();
    assert_eq!(form.get("redirect_uri"), Some("https://app.example/cb"));
    assert_eq!(form.get("state"), Some("a b"));
}

#[test]
fn a_key_is_percent_decoded_too() {
    let form = oauth::decode_form("code%5Fverifier=x").unwrap();
    assert_eq!(form.get("code_verifier"), Some("x"));
}

#[test]
fn a_duplicate_key_is_refused() {
    assert_eq!(
        oauth::decode_form("code=one&code=two").unwrap_err(),
        FormError::DuplicateKey
    );
}

#[test]
fn a_segment_without_a_separator_is_refused() {
    assert_eq!(
        oauth::decode_form("grant_type").unwrap_err(),
        FormError::MalformedPair
    );
    assert_eq!(
        oauth::decode_form("a=1&&b=2").unwrap_err(),
        FormError::MalformedPair
    );
}

#[test]
fn an_empty_key_is_refused() {
    assert_eq!(oauth::decode_form("=1").unwrap_err(), FormError::EmptyKey);
}

#[test]
fn a_truncated_or_non_hexadecimal_escape_is_refused() {
    for text in ["state=%", "state=%2", "state=%zz", "state=%2z"] {
        assert_eq!(
            oauth::decode_form(text).unwrap_err(),
            FormError::MalformedEscape,
            "{text}"
        );
    }
}

#[test]
fn an_escape_that_is_not_utf8_is_refused() {
    assert_eq!(
        oauth::decode_form("state=%ff%fe").unwrap_err(),
        FormError::NotUtf8
    );
}

#[test]
fn a_refusal_carries_no_caller_supplied_text() {
    // Every refusal this module produces is a unit value or a `&'static str`, so no caller
    // byte can reach a body that is rendered back to that caller.
    const INJECTED: &str = "<script>alert(1)</script>";
    let refused =
        oauth::decode_form("<script>alert(1)</script>=x&<script>alert(1)</script>=y").unwrap_err();
    let rendered = format!("{refused}");
    assert!(!rendered.contains(INJECTED), "{rendered}");
    let body = ErrorBody::new(ErrorCode::InvalidRequest, "the request form is malformed");
    assert!(!body.to_json().contains(INJECTED));
    let json = oauth::flat_object(r#"{"<script>alert(1)</script>":1}"#).unwrap_err();
    assert!(!format!("{json}").contains(INJECTED));
}

#[test]
fn the_five_standard_token_endpoint_codes_render_their_declared_names() {
    assert_eq!(ErrorCode::InvalidRequest.as_str(), "invalid_request");
    assert_eq!(ErrorCode::InvalidClient.as_str(), "invalid_client");
    assert_eq!(ErrorCode::InvalidGrant.as_str(), "invalid_grant");
    assert_eq!(
        ErrorCode::UnsupportedGrantType.as_str(),
        "unsupported_grant_type"
    );
    assert_eq!(ErrorCode::InvalidScope.as_str(), "invalid_scope");
    assert_eq!(
        ErrorCode::UnsupportedResponseType.as_str(),
        "unsupported_response_type"
    );
}

#[test]
fn an_error_body_is_the_json_object_rfc_6749_declares() {
    let body = ErrorBody::new(ErrorCode::InvalidGrant, "the code is not redeemable");
    assert_eq!(
        body.to_json(),
        r#"{"error":"invalid_grant","error_description":"the code is not redeemable"}"#
    );
}

/// `tests/security/cases.json`, case `pkce-missing`: "Public client omits verifier".
///
/// RFC 7636 section 4.5 requires `code_verifier` on the token request of a transaction that
/// recorded a challenge, and this deployment records one for every authorization code, so
/// its absence is decided at the wire and answered `invalid_request`.
#[test]
fn pkce_missing_is_a_wire_refusal_with_invalid_request() {
    let form = oauth::decode_form("grant_type=authorization_code&client_id=abc&code=Zm9v").unwrap();
    let refused = oauth::require_code_verifier(&form).unwrap_err();
    assert_eq!(refused.error, ErrorCode::InvalidRequest);
    assert!(refused.to_json().contains("invalid_request"));

    let present = oauth::decode_form("code_verifier=abc").unwrap();
    assert_eq!(oauth::require_code_verifier(&present).unwrap(), "abc");
}

/// `tests/security/cases.json`, case `pkce-plain`: "Challenge method plain".
///
/// `mandate.core.PkceMethod` declares exactly one variant, `S256`
/// (`crates/mandate-types/src/enumeration.rs:10`), so `plain` is the method of no value this
/// system can construct. It is refused at the wire with `invalid_request`, which is what RFC
/// 7636 section 4.4.1 names for a `code_challenge_method` the server does not support.
#[test]
fn pkce_plain_is_a_wire_refusal_with_invalid_request() {
    let plain = oauth::decode_form("code_challenge_method=plain").unwrap();
    let refused = oauth::require_s256_challenge_method(&plain).unwrap_err();
    assert_eq!(refused.error, ErrorCode::InvalidRequest);
    assert!(refused.to_json().contains("invalid_request"));

    // Absent is the same refusal: RFC 7636 defaults an absent method to `plain`.
    let absent = oauth::decode_form("client_id=abc").unwrap();
    assert_eq!(
        oauth::require_s256_challenge_method(&absent)
            .unwrap_err()
            .error,
        ErrorCode::InvalidRequest
    );

    let s256 = oauth::decode_form("code_challenge_method=S256").unwrap();
    assert!(oauth::require_s256_challenge_method(&s256).is_ok());
    assert_eq!(S256_METHOD, "S256");
}

/// The mapping is a table, and the table is decided against the enum it maps from.
///
/// `DenialClause` is `#[non_exhaustive]`, so a `match` here cannot be made exhaustive by the
/// compiler and a variant added upstream would fall silently into a wildcard. The variant
/// names are therefore read from `crates/mandate-token/src/projection.rs` and compared with
/// the table's own: a clause this crate has not mapped fails here, naming it.
#[test]
fn every_declared_denial_clause_is_mapped_to_a_standard_error_code() {
    let declared = declared_clause_names();
    let mapped: BTreeSet<String> = oauth::CLAUSE_CODES
        .iter()
        .map(|(clause, _)| format!("{clause:?}"))
        .collect();
    assert_eq!(
        declared, mapped,
        "a declared denial clause with no standard error code"
    );
    assert_eq!(oauth::CLAUSE_CODES.len(), declared.len());
}

#[test]
fn the_clauses_a_redemption_refuses_with_map_onto_the_grant_and_the_client() {
    for clause in [
        DenialClause::CodeUnknown,
        DenialClause::CodeProofMismatch,
        DenialClause::CodeExpired,
        DenialClause::CodeConsumed,
        DenialClause::RedirectMismatch,
        DenialClause::VerifierMalformed,
        DenialClause::VerifierMismatch,
        DenialClause::ChallengeMalformed,
        DenialClause::SessionEpochStale,
        DenialClause::SessionUnusable,
        // RFC 6749 section 5.2's own last phrase under `invalid_grant`: "or was issued to
        // another client". Adversary pass 1, F1.
        DenialClause::ClientMismatch,
        // Reachable from a redemption, which declares no `scope` parameter. Adversary pass 1,
        // F2.
        DenialClause::TargetUnregistered,
        DenialClause::TargetDisabled,
        DenialClause::OrganizationMismatch,
        // Adversary pass 2, F1: `binding::bound_client` calls `code::admitted_client` on every
        // redemption, so all four of that function's client clauses are reachable from one —
        // and a road whose metadata advertises `token_endpoint_auth_methods_supported:
        // ["none"]` has no client authentication to have failed.
        DenialClause::ClientUnregistered,
        DenialClause::ClientOutsideOrganization,
        DenialClause::ClientDisabled,
        DenialClause::ClientNotPublic,
        // An exchange's unknown, revoked or expired subject token: the grant presented is
        // invalid, and no client authenticated on this road for `invalid_client` to be about.
        DenialClause::SubjectTokenInvalid,
    ] {
        assert_eq!(
            oauth::code_for_clause(clause),
            ErrorCode::InvalidGrant,
            "{clause:?}"
        );
    }
    // `invalid_client` is "client authentication failed", so it survives only where a caller
    // on this road actually authenticates: RFC 7662 section 2.1's introspection endpoint, whose
    // caller presents a bearer credential. Neither clause is reachable from a redemption.
    for clause in [
        DenialClause::CallerProofInvalid,
        DenialClause::IntrospectionAuthority,
    ] {
        assert_eq!(
            oauth::code_for_clause(clause),
            ErrorCode::InvalidClient,
            "{clause:?}"
        );
    }
    // `invalid_scope` survives only for clauses of commands whose request does carry a
    // requested authority: registration and issuance, never a redemption.
    for clause in [
        DenialClause::ProfileUnadmitted,
        DenialClause::AudienceAmbiguous,
        DenialClause::ServerDisabled,
    ] {
        assert_eq!(
            oauth::code_for_clause(clause),
            ErrorCode::InvalidScope,
            "{clause:?}"
        );
    }
    // A deployment bound the caller cannot correct in any parameter it sent.
    assert_eq!(
        oauth::code_for_clause(DenialClause::ExpiryUnbounded),
        ErrorCode::InvalidRequest
    );
}

#[test]
fn a_json_object_renders_text_lists_and_nested_objects() {
    let rendered = oauth::object(&[
        ("issuer", Member::Text("https://mandate.example".to_owned())),
        (
            "code_challenge_methods_supported",
            Member::List(vec!["S256".to_owned()]),
        ),
        (
            "keys",
            Member::Objects(vec![vec![
                ("kid".to_owned(), "one".to_owned()),
                ("kty".to_owned(), "OKP".to_owned()),
            ]]),
        ),
    ]);
    assert_eq!(
        rendered,
        concat!(
            r#"{"code_challenge_methods_supported":["S256"],"#,
            r#""issuer":"https://mandate.example","#,
            r#""keys":[{"kid":"one","kty":"OKP"}]}"#
        )
    );
}

#[test]
fn a_rendered_member_is_escaped_by_the_json_codec() {
    let rendered = oauth::object(&[("issuer", Member::Text("a\"b\\c".to_owned()))]);
    assert_eq!(rendered, r#"{"issuer":"a\"b\\c"}"#);
}

#[test]
fn a_flat_json_object_of_text_members_is_read_in_order() {
    let members = oauth::flat_object(r#"{"connection_id":"one","proof":"Zm9v"}"#).unwrap();
    assert_eq!(
        members,
        vec![
            ("connection_id".to_owned(), "one".to_owned()),
            ("proof".to_owned(), "Zm9v".to_owned()),
        ]
    );
}

#[test]
fn a_json_body_that_is_not_a_flat_object_of_text_is_refused() {
    assert_eq!(
        oauth::flat_object("not json").unwrap_err(),
        JsonError::NotJson
    );
    assert_eq!(
        oauth::flat_object("[]").unwrap_err(),
        JsonError::NotAnObject
    );
    assert_eq!(
        oauth::flat_object(r#"{"proof":{"nested":"x"}}"#).unwrap_err(),
        JsonError::ValueNotText
    );
    assert_eq!(
        oauth::flat_object(r#"{"proof":1}"#).unwrap_err(),
        JsonError::ValueNotText
    );
    assert_eq!(
        oauth::flat_object(r#"{"proof":"a","proof":"b"}"#).unwrap_err(),
        JsonError::DuplicateKey
    );
}

/// The `DenialClause` variant names, read from the source that declares them.
fn declared_clause_names() -> BTreeSet<String> {
    let source = fs::read_to_string(PROJECTION).expect("the projection source");
    let body = source
        .split_once("pub enum DenialClause {")
        .expect("the DenialClause declaration")
        .1;
    let body = body.split_once("\n}").expect("the declaration's end").0;
    let names: BTreeSet<String> = body
        .lines()
        .map(str::trim)
        .filter(|line| line.ends_with(',') && !line.starts_with("///"))
        .map(|line| line.trim_end_matches(',').to_owned())
        .collect();
    assert!(names.len() > 30, "read {} clause names", names.len());
    names
}

// ------------------------------------- adversary pass 1, F1/F2: the class behind the five

/// **No clause reachable from a redemption may answer `invalid_scope` or `invalid_client`.**
///
/// This is the rule adversary pass 1 found five clauses on the wrong side of, written as a
/// check rather than as five corrections. Both halves come from RFC 6749 section 5.2 and from
/// facts about this road, not from taste:
///
/// * `invalid_scope` is "**the requested scope** is invalid ...", and the token request on this
///   road declares no `scope` parameter at all (`decode::TOKEN_PARAMETERS`), so there is no
///   requested scope for a refusal to be about.
/// * `invalid_client` is "**client authentication failed** ...", and the metadata advertises
///   `token_endpoint_auth_methods_supported: ["none"]`, so no client on this road ever
///   authenticates.
///
/// The reachable set is followed **by call** from `redemption::redeem_authorization_code`
/// through the STS crate's modules — see [`token_endpoint_clauses`] — rather than read from a
/// fixed pair of files. Adversary pass 2 (F2) found the file-named reader short by one hop:
/// `binding::bound_client` calls `code::admitted_client`, whose three client clauses were
/// never in the set the rule was applied over. Following the call is what makes this a bound
/// on the class and not a list that is right until a function moves.
///
/// The premise is guarded below: a traversal that silently stopped reaching
/// `code::admitted_client` would make this case pass by reaching nothing, so the three clauses
/// that hop raises are asserted to be in the set before the rule is applied over it.
#[test]
fn no_clause_a_redemption_can_raise_answers_with_a_scope_or_an_authentication_code() {
    let reachable = token_endpoint_clauses();
    for named in [
        "ClientUnregistered",
        "ClientOutsideOrganization",
        "ClientDisabled",
    ] {
        assert!(
            reachable.contains(named),
            "{named} is raised by code::admitted_client, which binding::bound_client calls on \
             every redemption; the traversal no longer reaches it and this rule would pass by \
             reaching nothing"
        );
    }
    assert!(reachable.len() >= 15, "read {} clauses", reachable.len());
    for (clause, code) in oauth::CLAUSE_CODES {
        if !reachable.contains(&format!("{clause:?}")) {
            continue;
        }
        assert!(
            *code != ErrorCode::InvalidScope && *code != ErrorCode::InvalidClient,
            "{clause:?} is reachable from a redemption and answers {code}"
        );
        assert!(
            ErrorCode::TOKEN_ENDPOINT.contains(code),
            "{clause:?} answers {code}, which RFC 6749 section 5.2 does not declare"
        );
    }
}

/// The five corrections themselves, named, so a regression on any one of them is reported by
/// name rather than only through the rule above.
#[test]
fn the_five_clauses_adversary_pass_one_named_answer_the_codes_the_rfc_assigns() {
    for (clause, code) in [
        (DenialClause::ClientMismatch, ErrorCode::InvalidGrant),
        (DenialClause::TargetUnregistered, ErrorCode::InvalidGrant),
        (DenialClause::TargetDisabled, ErrorCode::InvalidGrant),
        (DenialClause::OrganizationMismatch, ErrorCode::InvalidGrant),
        (DenialClause::ExpiryUnbounded, ErrorCode::InvalidRequest),
    ] {
        assert_eq!(oauth::code_for_clause(clause), code, "{clause:?}");
    }
}

/// Every code the table names is one RFC 6749 section 5.2 declares for the token endpoint.
///
/// The table maps `mandate.credential`'s clauses, and that domain's commands are reached
/// through the token endpoint and the introspection endpoint — never through the authorization
/// endpoint, whose refusals are `mandate-federation`'s and are mapped by reason.
#[test]
fn the_clause_table_names_no_authorization_endpoint_code() {
    for (clause, code) in oauth::CLAUSE_CODES {
        assert!(
            ErrorCode::TOKEN_ENDPOINT.contains(code),
            "{clause:?} answers {code}, an authorization-endpoint code"
        );
    }
}

// ------------------------- adversary pass 1, F11: the authorization endpoint maps by reason

/// Every declared `mandate.core.DenialReason` answers an RFC 6749 section 4.1.2.1 code.
///
/// `code_for_reason`'s match is exhaustive and compiler-checked, so this case cannot fail by a
/// reason going unmapped. What it decides is the other half: that no reason is answered with a
/// *token endpoint* code at the authorization endpoint.
#[test]
fn every_denial_reason_answers_an_authorization_endpoint_code() {
    for reason in DenialReason::VARIANTS {
        let code = oauth::code_for_reason(*reason);
        assert!(
            ErrorCode::AUTHORIZATION_ENDPOINT.contains(&code),
            "{reason:?} answers {code}, which RFC 6749 section 4.1.2.1 does not declare"
        );
    }
    assert_eq!(DenialReason::VARIANTS.len(), 7);
}

#[test]
fn a_refused_authorization_names_the_reason_and_not_a_grant() {
    assert_eq!(
        oauth::code_for_reason(DenialReason::Denied),
        ErrorCode::AccessDenied
    );
    assert_eq!(
        oauth::code_for_reason(DenialReason::InvalidCredential),
        ErrorCode::AccessDenied
    );
    assert_eq!(
        oauth::code_for_reason(DenialReason::TenantMismatch),
        ErrorCode::AccessDenied
    );
    assert_eq!(
        oauth::code_for_reason(DenialReason::StaleEpoch),
        ErrorCode::AccessDenied
    );
    assert_eq!(
        oauth::code_for_reason(DenialReason::Unavailable),
        ErrorCode::TemporarilyUnavailable
    );
    assert_eq!(
        oauth::code_for_reason(DenialReason::AudienceMismatch),
        ErrorCode::InvalidScope
    );
    // `invalid_grant` names a grant the authorization request has not presented; no reason
    // answers it here, and `invalid_client` is a token-endpoint authentication failure.
    for reason in DenialReason::VARIANTS {
        let code = oauth::code_for_reason(*reason);
        assert_ne!(code, ErrorCode::InvalidGrant, "{reason:?}");
        assert_ne!(code, ErrorCode::InvalidClient, "{reason:?}");
    }
}

#[test]
fn the_three_authorization_endpoint_codes_render_their_declared_names() {
    assert_eq!(ErrorCode::AccessDenied.as_str(), "access_denied");
    assert_eq!(ErrorCode::ServerError.as_str(), "server_error");
    assert_eq!(
        ErrorCode::TemporarilyUnavailable.as_str(),
        "temporarily_unavailable"
    );
    assert_eq!(
        ErrorCode::UnauthorizedClient.as_str(),
        "unauthorized_client"
    );
    assert_eq!(ErrorCode::InvalidTarget.as_str(), "invalid_target");
    assert_eq!(ErrorCode::ALL.len(), 11);
}

// ------------------- adversary pass 2, F4: the authorization endpoint's seventh code

/// `ErrorCode::AUTHORIZATION_ENDPOINT` carries every code RFC 6749 section 4.1.2.1 declares.
///
/// The set is the RFC's, and a set documented as the RFC's that is missing one of its members
/// is a set a refusal falls out of: before this, a client refused at `/oauth/authorize`
/// because it is unregistered, not public or disabled was answered `access_denied` — "the
/// resource owner or authorization server denied the request" — which tells a client developer
/// the end user refused.
#[test]
fn the_authorization_endpoint_carries_the_seven_codes_the_rfc_declares() {
    let carried: BTreeSet<&str> = ErrorCode::AUTHORIZATION_ENDPOINT
        .iter()
        .map(|code| code.as_str())
        .collect();
    assert_eq!(
        carried,
        BTreeSet::from([
            "invalid_request",
            "unauthorized_client",
            "access_denied",
            "unsupported_response_type",
            "invalid_scope",
            "server_error",
            "temporarily_unavailable",
        ])
    );
}

/// A client the authorization endpoint does not admit answers `unauthorized_client`.
///
/// `crates/mandate-federation/src/publicclient.rs::registered_public_client` refuses
/// `ClientUnknown`, `ClientNotPublic` and `ClientDisabled` — section 4.1.2.1's "the client is
/// not authorized to request an authorization code using this method" — each carrying
/// `DenialReason::Denied`, which the by-reason mapping alone answers `access_denied`. The
/// clause is therefore read first and the reason is the fallback.
///
/// The three names are read from the source that raises them, so a variant renamed in
/// `mandate-federation` fails here rather than falling quietly back to the reason. They are
/// carried as names because that crate's `DenialClause` is a different type from
/// `mandate_token`'s and is outside this crate's dependency ceiling.
#[test]
fn a_client_the_authorization_endpoint_does_not_admit_answers_unauthorized_client() {
    let raised = fs::read_to_string(PUBLIC_CLIENT).expect("the public-client source");
    for clause in oauth::UNAUTHORIZED_CLIENT_CLAUSES {
        assert!(
            raised.contains(&format!("DenialClause::{clause}")),
            "{clause} is no longer raised by registered_public_client"
        );
        for reason in DenialReason::VARIANTS {
            assert_eq!(
                oauth::code_for_denial(clause, *reason),
                ErrorCode::UnauthorizedClient,
                "{clause} with {reason:?}"
            );
        }
    }
    assert_eq!(
        oauth::UNAUTHORIZED_CLIENT_CLAUSES,
        ["ClientUnknown", "ClientDisabled", "ClientNotPublic"]
    );
}

/// Every other clause of that crate falls back to the reason, and the fallback is the mapping
/// that was already there.
#[test]
fn a_refusal_that_is_not_about_the_client_is_still_answered_by_its_reason() {
    for clause in [
        "SessionUnknown",
        "SessionRevoked",
        "RedirectMismatch",
        "OrganizationMismatch",
        "ChallengeMalformed",
        "",
    ] {
        for reason in DenialReason::VARIANTS {
            let answered = oauth::code_for_denial(clause, *reason);
            assert_eq!(answered, oauth::code_for_reason(*reason), "{clause}");
            assert!(
                ErrorCode::AUTHORIZATION_ENDPOINT.contains(&answered),
                "{clause} with {reason:?} answers {answered}"
            );
        }
    }
}

// ------------------------------- the reachable set, followed by call rather than by file name

/// The clause names a redemption can raise, followed **by call** from the token endpoint's
/// handler through the STS crate.
///
/// Adversary pass 2 (F2) found the earlier reader short: it read `redemption.rs` and the
/// `binding.rs` it calls by name, and the path spans a third file — `binding::bound_client`
/// calls `code::admitted_client` — so the three clauses raised there were never in the set the
/// rule was applied over. A set named by file is a set that is right until a call moves.
///
/// The traversal starts at `redemption::redeem_authorization_code` and, transitively: takes
/// the function's body by brace matching, collects every `DenialClause::<Name>` in it, and
/// follows every call that lands in a sibling module of `services/sts/src` — written either as
/// a bare `name(` that a `use crate::<module>::{...}` names, or as a `<module>::name(` path.
/// A clause moved onto the path into a fourth file is therefore in the set the day it lands.
///
/// This reads source text rather than a call graph a compiler built, and it is an
/// over-approximation on purpose: a name that is not reached at run time (`admitted_client`'s
/// `ClientNotPublic`, behind a `public_client_required` a redemption passes `false` for) is
/// still in the set, because a mapping that is right only for the branch taken today is a
/// mapping the next caller invalidates.
fn token_endpoint_clauses() -> BTreeSet<String> {
    clauses_reachable_from("redemption", "redeem_authorization_code")
}

/// Every clause named in a function body reachable by call from `<module>::<function>`.
fn clauses_reachable_from(module: &str, function: &str) -> BTreeSet<String> {
    let modules = sts_modules();
    let mut clauses = BTreeSet::new();
    let mut walked: BTreeSet<(String, String)> = BTreeSet::new();
    let mut pending: VecDeque<(String, String)> =
        VecDeque::from(vec![(module.to_owned(), function.to_owned())]);
    while let Some((module, function)) = pending.pop_front() {
        if !walked.insert((module.clone(), function.clone())) {
            continue;
        }
        let source = code_only(&sts_source(&module));
        // A name reached by call that is not a free function of the module — a type, a trait
        // method, a macro — has no body here and ends the path.
        let Some(body) = function_body(&source, &function) else {
            continue;
        };
        for name in clauses_named_in(&body) {
            clauses.insert(name);
        }
        let imports = imported_names(&source, &modules);
        pending.extend(called_functions(
            &body, &imports, &modules, &module, &source,
        ));
    }
    clauses
}

/// The sibling modules of `services/sts/src`, by file stem.
///
/// `lib` and `main` are dropped: the crate root and the binary entry are not modules a
/// `use crate::<name>::` path or a `<name>::` call can name.
fn sts_modules() -> BTreeSet<String> {
    let modules: BTreeSet<String> = fs::read_dir(STS_SRC)
        .expect("the STS source directory")
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter_map(|name| name.strip_suffix(".rs").map(str::to_owned))
        .filter(|name| name != "lib" && name != "main")
        .collect();
    for named in ["redemption", "binding", "code"] {
        assert!(
            modules.contains(named),
            "the STS crate no longer carries a {named} module; the traversal below has moved"
        );
    }
    modules
}

/// One module's source text.
fn sts_source(module: &str) -> String {
    fs::read_to_string(format!("{STS_SRC}/{module}.rs")).expect("an STS source file")
}

/// `text` with every `//` line dropped, so a clause *named in prose* is not a clause raised
/// and a call written in a doc comment is not a call.
fn code_only(text: &str) -> String {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The body of `fn <name>`, brace-matched from its opening brace.
fn function_body(source: &str, name: &str) -> Option<String> {
    let declared = source
        .find(&format!("fn {name}("))
        .or_else(|| source.find(&format!("fn {name}<")))?;
    let open = declared + source[declared..].find('{')?;
    let mut depth = 0usize;
    for (offset, character) in source[open..].char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(source[open..=open + offset].to_owned());
                }
            }
            _ => {}
        }
    }
    None
}

/// Every `DenialClause::<Name>` in a body.
fn clauses_named_in(body: &str) -> Vec<String> {
    let mut named = Vec::new();
    let mut rest = body;
    while let Some((_, tail)) = rest.split_once("DenialClause::") {
        let end = tail
            .find(|c: char| !c.is_ascii_alphanumeric())
            .unwrap_or(tail.len());
        named.push(tail[..end].to_owned());
        rest = &tail[end..];
    }
    named
}

/// `use crate::<module>::{a, b};` and `use crate::<module>::a;`: the bare name a call site
/// writes, and the module that name is in.
fn imported_names(source: &str, modules: &BTreeSet<String>) -> BTreeMap<String, String> {
    let mut imported = BTreeMap::new();
    let mut rest = source;
    while let Some((_, tail)) = rest.split_once("use crate::") {
        let end = tail.find(';').unwrap_or(tail.len());
        let (clause, remainder) = tail.split_at(end);
        rest = remainder;
        let Some((module, names)) = clause.split_once("::") else {
            continue;
        };
        if !modules.contains(module) {
            continue;
        }
        for name in names.trim_matches(|c| c == '{' || c == '}').split(',') {
            let name = name.trim();
            if !name.is_empty() {
                imported.insert(name.to_owned(), module.to_owned());
            }
        }
    }
    imported
}

/// Every call in a body that lands in a function this reader can read: `<module>::name(` by
/// path, `name(` through an import of a sibling module, and `name(` declared **in the module
/// the body is in**.
///
/// The third was missing while the rule was only applied to the redemption, whose path happens
/// to cross a module at every hop (`redemption` → `binding` → `code`). The authorization
/// road does not: `code::issue_authorization_code` calls `admitted_client` and
/// `admitted_redirect`, two free functions beside it, and four clause names lived behind that
/// one unfollowed hop. A call is a call whether or not it crosses a file.
///
/// A same-module name is followed only when the module declares a function by that name, and
/// never when it is written as a method call (`value.name(`), so a method that shares a free
/// function's name does not pull that function's clauses in.
fn called_functions(
    body: &str,
    imports: &BTreeMap<String, String>,
    modules: &BTreeSet<String>,
    module: &str,
    source: &str,
) -> Vec<(String, String)> {
    let mut called = Vec::new();
    for (start, end) in identifier_spans(body) {
        let name = &body[start..end];
        let rest = &body[end..];
        if let Some(path) = rest.strip_prefix("::") {
            if !modules.contains(name) {
                continue;
            }
            let length = path.find(|c: char| !is_identifier(c)).unwrap_or(path.len());
            if length > 0 && path[length..].starts_with('(') {
                called.push((name.to_owned(), path[..length].to_owned()));
            }
        } else if rest.starts_with('(') {
            if let Some(imported) = imports.get(name) {
                called.push((imported.clone(), name.to_owned()));
            } else if !body[..start].ends_with('.') && function_body(source, name).is_some() {
                called.push((module.to_owned(), name.to_owned()));
            }
        }
    }
    called
}

/// The byte spans of every identifier in `text`.
fn identifier_spans(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut open: Option<usize> = None;
    for (offset, character) in text.char_indices() {
        if is_identifier(character) {
            open.get_or_insert(offset);
        } else if let Some(start) = open.take() {
            spans.push((start, offset));
        }
    }
    if let Some(start) = open {
        spans.push((start, text.len()));
    }
    spans
}

/// Whether a character can appear in a Rust identifier this reader follows.
fn is_identifier(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_'
}

// --------------------------- adversary pass 1, F8: the deployment's own failures

/// **A refusal the deployment caused is `server_error`, not `access_denied`.**
///
/// RFC 6749 section 4.1.2.1 declares both: `access_denied` is "the resource owner or
/// authorization server denied the request", which a client developer reads as the end user
/// refusing, and `server_error` is "the authorization server encountered an unexpected
/// condition that prevented it from fulfilling the request". `ExpiryUnbounded` is the second:
/// "the profile's TTL or the request instant does not name a span this deployment can add"
/// (`crates/mandate-token/src/projection.rs`) — the deployment's own configuration, carrying
/// `DenialReason::Denied`, which by reason alone is `access_denied`.
///
/// So the clause is read first, as it is for [`oauth::UNAUTHORIZED_CLIENT_CLAUSES`], and for
/// the same reason: the reason is the contract's only wire field and two refusals that share
/// one reason are two different answers.
#[test]
fn a_refusal_the_deployment_caused_answers_server_error() {
    for clause in oauth::SERVER_ERROR_CLAUSES {
        for reason in DenialReason::VARIANTS {
            assert_eq!(
                oauth::code_for_denial(clause, *reason),
                ErrorCode::ServerError,
                "{clause} with {reason:?}"
            );
        }
        assert!(
            !oauth::UNAUTHORIZED_CLIENT_CLAUSES.contains(clause),
            "{clause} is in both clause lists, and the two answer different codes"
        );
    }
    assert_eq!(oauth::SERVER_ERROR_CLAUSES, ["ExpiryUnbounded"]);
    assert!(
        ErrorCode::AUTHORIZATION_ENDPOINT.contains(&ErrorCode::ServerError),
        "RFC 6749 section 4.1.2.1 declares `server_error` at the authorization endpoint"
    );
    assert!(
        !ErrorCode::TOKEN_ENDPOINT.contains(&ErrorCode::ServerError),
        "RFC 6749 section 5.2 declares no `server_error`, so the token endpoint's mapping by \
         clause is unchanged"
    );
    assert_eq!(
        oauth::code_for_clause(DenialClause::ExpiryUnbounded),
        ErrorCode::InvalidRequest,
        "the token endpoint's answer for the same clause is section 5.2's and did not move"
    );
}

/// **Every clause the authorization road can raise is classified, and the check is the
/// classification.**
///
/// The finding behind [`SERVER_ERROR_CLAUSES`] was one clause answering the wrong code; the
/// class is every clause that road raises whose answer is decided by the reason it happens to
/// carry. So the set is followed **by call** from `code::issue_authorization_code` — the STS
/// half of `mandate.federation.AuthorizePublicClient`, which is what
/// `services/control-plane/src/adapters.rs::authorize` calls through `CodeIssuance::issue` —
/// with the same traversal the redemption's set is read by, and each name in it is stated here
/// as one of two things:
///
/// * **the deployment's own failure**, [`oauth::SERVER_ERROR_CLAUSES`], which answers
///   `server_error`;
/// * **the client's own standing**, [`oauth::UNAUTHORIZED_CLIENT_CLAUSES`], which answers
///   `unauthorized_client`; or
/// * **everything else**, which carries no clause override and answers by reason.
///
/// A clause that appears on that road and is in none of the three fails this case by name,
/// rather than falling into the reason mapping and answering `access_denied` for a condition
/// the end user had nothing to do with.
///
/// **Recorded, not changed:** the third list carries `ClientUnregistered`, which is the STS's
/// name for the condition `mandate-federation` raises as `ClientUnknown` — "client is not a
/// registered public client". The federation-raised name answers `unauthorized_client` and
/// this one answers by reason, so the same condition has two answers depending on which of
/// the two read models refused it. It is reachable only when they disagree, the
/// correction round 1 rulings did not name it, and it is written down here rather than
/// resolved by an implementor.
#[test]
fn every_clause_the_authorization_road_raises_is_classified() {
    let reachable = clauses_reachable_from("code", "issue_authorization_code");
    for named in ["ExpiryUnbounded", "ClientNotPublic", "TargetUnregistered"] {
        assert!(
            reachable.contains(named),
            "{named} is raised on the authorization road; the traversal no longer reaches it \
             and this rule would pass by reaching nothing"
        );
    }
    assert!(reachable.len() >= 10, "read {} clauses", reachable.len());

    // Everything else: each one names what the *request* got wrong — the client, the
    // redirect, the target or the challenge it carried — and none of them overrides the
    // reason the handler refused with.
    let by_reason = [
        "ChallengeMalformed",
        "ClientOutsideOrganization",
        "ClientUnregistered",
        "OrganizationMismatch",
        "ProfileUnadmitted",
        "RedirectUnregistered",
        "TargetDisabled",
        "TargetUnregistered",
    ];
    for clause in &reachable {
        let classified = usize::from(oauth::SERVER_ERROR_CLAUSES.contains(&clause.as_str()))
            + usize::from(oauth::UNAUTHORIZED_CLIENT_CLAUSES.contains(&clause.as_str()))
            + usize::from(by_reason.contains(&clause.as_str()));
        assert_eq!(
            classified, 1,
            "{clause} is raised on the authorization road and is classified {classified} \
             times: it is the deployment's own failure, the client's own standing, or \
             neither, and exactly one of those"
        );
    }
    for clause in oauth::SERVER_ERROR_CLAUSES {
        assert!(
            reachable.contains(*clause),
            "{clause} is no longer raised on the authorization road"
        );
    }
    for clause in by_reason {
        for reason in DenialReason::VARIANTS {
            let answered = oauth::code_for_denial(clause, *reason);
            assert_eq!(
                answered,
                oauth::code_for_reason(*reason),
                "{clause} with {reason:?} carries no clause override and answers by reason"
            );
            assert!(
                ErrorCode::AUTHORIZATION_ENDPOINT.contains(&answered),
                "{clause} with {reason:?} answers {answered}"
            );
        }
    }
}
