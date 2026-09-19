//! Adversary pass 1 against `story:login-adapters`, the `oauth` unit.
//!
//! `crates/mandate-proto/src/oauth.rs:352-355` states the rule its own table is built to:
//! "The grouping is the one **RFC 6749 section 5.2 declares**: a refusal about the grant
//! presented is `invalid_grant`, one about the client the grant is bound to is
//! `invalid_client`, one about the authority asked for is `invalid_scope` ...". These cases
//! drive that claim against `CLAUSE_CODES` for the clauses the token endpoint can actually
//! refuse with, using the RFC's own words for each case.
//!
//! The existing case (`crates/mandate-proto/tests/oauth.rs:316`) decides that the table names
//! every `DenialClause` variant. It decides nothing about *which* code each is named with.
//!
//! Nothing here changes an implementation file.

use mandate_proto::oauth::{self, ErrorCode};
use mandate_token::projection::DenialClause;

/// RFC 6749 section 5.2, `invalid_grant`, verbatim: "The provided authorization grant ... is
/// invalid, expired, revoked, does not match the redirection URI used in the authorization
/// request, or **was issued to another client**."
///
/// `DenialClause::ClientMismatch` is "the presented client is not the one the code is bound
/// to" (`crates/mandate-token/src/projection.rs:629`), raised on the redemption path by
/// `services/sts/src/binding.rs:195`. That is the RFC's "was issued to another client",
/// which the RFC assigns to `invalid_grant`; `CLAUSE_CODES` assigns it `invalid_client`.
///
/// `invalid_client` is the RFC's "**Client authentication failed**", and section 5.2 obliges
/// an HTTP 401 for it. The login road's metadata advertises
/// `token_endpoint_auth_methods_supported: ["none"]`, so no client on it ever authenticates
/// and no refusal on it can be an authentication failure.
#[test]
fn a_code_issued_to_another_client_is_answered_with_the_wrong_rfc_6749_code() {
    assert_eq!(
        oauth::code_for_clause(DenialClause::ClientMismatch),
        ErrorCode::InvalidGrant,
        "RFC 6749 section 5.2 names `was issued to another client` under invalid_grant"
    );
    // The neighbouring clause of the same sentence, which the table does get right — so the
    // case above is discriminating and not a blanket disagreement with the mapping.
    assert_eq!(
        oauth::code_for_clause(DenialClause::RedirectMismatch),
        ErrorCode::InvalidGrant,
    );
}

/// RFC 6749 section 5.2, `invalid_scope`, verbatim: "**The requested scope** is invalid,
/// unknown, malformed, or exceeds the scope granted by the resource owner."
///
/// `crates/mandate-server/src/decode.rs`'s `TOKEN_PARAMETERS` admits `grant_type`,
/// `client_id`, `code`, `code_verifier` and `redirect_uri` — no `scope`. A redemption
/// therefore requests no scope, and four clauses reachable on that path answer
/// `invalid_scope` anyway:
///
/// * `TargetUnregistered`, `OrganizationMismatch`, `TargetDisabled` —
///   `services/sts/src/binding.rs:316-326` (`target_in_tenant`, imported by
///   `services/sts/src/redemption.rs:79-81`);
/// * `ExpiryUnbounded` — `services/sts/src/redemption.rs:343`, a deployment whose profile TTL
///   or request instant names no span it can add. That is a server-side condition the client
///   cannot correct in any parameter, least of all one it did not send.
#[test]
fn the_token_endpoint_answers_invalid_scope_for_a_request_that_carries_no_scope() {
    for clause in [
        DenialClause::TargetUnregistered,
        DenialClause::OrganizationMismatch,
        DenialClause::TargetDisabled,
        DenialClause::ExpiryUnbounded,
    ] {
        assert_ne!(
            oauth::code_for_clause(clause),
            ErrorCode::InvalidScope,
            "{clause:?} is reachable from a redemption, which declares no scope parameter"
        );
    }
}

/// A control, kept green: the clauses the redemption path refuses possession with all answer
/// one code, so a caller learns nothing about which of them fired.
///
/// `crates/mandate-token/src/projection.rs:607-614` is explicit that telling `CodeUnknown`
/// from `CodeProofMismatch` "would hold an oracle over the code space". This is the property
/// the two cases above say the rest of the table gives up.
#[test]
fn the_possession_clauses_answer_one_code_and_leak_nothing() {
    let codes: Vec<ErrorCode> = [
        DenialClause::CodeUnknown,
        DenialClause::CodeProofMismatch,
        DenialClause::CodeExpired,
        DenialClause::CodeConsumed,
        DenialClause::VerifierMismatch,
        DenialClause::VerifierMalformed,
        DenialClause::ChallengeMalformed,
    ]
    .into_iter()
    .map(oauth::code_for_clause)
    .collect();
    assert!(
        codes.iter().all(|code| *code == ErrorCode::InvalidGrant),
        "{codes:?}"
    );
}
