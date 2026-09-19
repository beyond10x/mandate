//! Adversary pass 2 against `story:login-adapters`, the `oauth` unit.
//!
//! Correction round 1 replaced pass 1's five named clause corrections with a rule and a check
//! over the class — "**no clause reachable from a redemption may answer** `invalid_scope` **or**
//! `invalid_client`" (`docs/architecture/adapter-contract.md`), decided by
//! `tests/oauth.rs::no_clause_a_redemption_can_raise_answers_with_a_scope_or_an_authentication_code`.
//!
//! These cases drive that rule, and the document's claim about the authorization endpoint's
//! code set, against the sources they name. They read source text with `fs`, exactly as the
//! shipped case does, and add no dependency to this crate's ceiling.
//!
//! Nothing here changes an implementation file.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use mandate_proto::oauth::{self, ErrorCode};
use mandate_token::projection::DenialClause;

const REDEMPTION: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../services/sts/src/redemption.rs"
);
const BINDING: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../services/sts/src/binding.rs"
);
const CODE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../services/sts/src/code.rs"
);
const AUTHORIZE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../crates/mandate-federation/src/authorize.rs"
);
const PUBLIC_CLIENT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../crates/mandate-federation/src/publicclient.rs"
);

fn source(path: &str) -> String {
    fs::read_to_string(path).expect("a source file this workspace declares")
}

// ------------------- adapter-contract.md: "no clause reachable from a redemption may answer
// ------------------- invalid_scope or invalid_client. That is a check, not a convention."

/// A redemption raises three `invalid_client` clauses, one call hop past the two files the
/// check reads.
///
/// `services/sts/src/redemption.rs` calls `binding::bound_client`; `binding.rs` calls
/// `code::admitted_client(&code.client_id, organization, clients, false)`; and
/// `services/sts/src/code.rs::admitted_client` raises `ClientUnregistered`,
/// `ClientOutsideOrganization` and `ClientDisabled`. `oauth::CLAUSE_CODES` maps all three to
/// `invalid_client`, which the document forbids for any clause a redemption can raise — and
/// which RFC 6749 section 5.2 obliges an HTTP 401 for, on a road whose metadata advertises
/// `token_endpoint_auth_methods_supported: ["none"]`.
///
/// This is pass 1's F1 and F2 uncorrected: the same defect, on three more clauses, with the
/// same consequence the F1 ruling gave for `ClientMismatch`.
///
/// What reaches it: `redemption.rs::redeem_authorization_code`, the token endpoint's whole
/// handler, on a redemption whose bound client was disabled, deregistered, or moved to
/// another organization after the code was issued.
#[test]
fn a_redemption_reaches_three_clauses_that_answer_the_authentication_code_the_rule_forbids() {
    // The call chain, read from the sources that declare it.
    let redemption = source(REDEMPTION);
    let binding = source(BINDING);
    let code = source(CODE);
    assert!(
        redemption.contains("bound_client("),
        "redemption.rs no longer calls bound_client; the chain below has moved"
    );
    assert!(
        binding.contains("pub fn bound_client") && binding.contains("admitted_client("),
        "binding.rs no longer routes bound_client into admitted_client"
    );
    assert!(
        code.contains("pub fn admitted_client"),
        "code.rs no longer declares admitted_client"
    );

    let raised = [
        ("ClientUnregistered", DenialClause::ClientUnregistered),
        (
            "ClientOutsideOrganization",
            DenialClause::ClientOutsideOrganization,
        ),
        ("ClientDisabled", DenialClause::ClientDisabled),
    ];
    for (name, clause) in raised {
        assert!(
            code.contains(&format!("DenialClause::{name}")),
            "admitted_client no longer raises {name}"
        );
        let answered = oauth::code_for_clause(clause);
        assert_ne!(
            answered,
            ErrorCode::InvalidClient,
            "{name} is reachable from a redemption through \
             redemption.rs -> binding::bound_client -> code::admitted_client, and answers \
             {answered}, which adapter-contract.md forbids for any redemption-reachable clause"
        );
    }
}

const STS_SRC: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../services/sts/src");

/// The sibling modules of `services/sts/src`, by file name.
fn sts_modules() -> BTreeSet<String> {
    fs::read_dir(STS_SRC)
        .expect("the STS source directory")
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter_map(|name| name.strip_suffix(".rs").map(str::to_owned))
        .filter(|name| name != "lib" && name != "main")
        .collect()
}

/// `text` with every `//` line removed, so a name in prose is not a call.
fn without_comments(text: &str) -> String {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The body of the first `fn <name>` in `text`, brace-matched from its first `{`.
fn body_of(text: &str, name: &str) -> Option<String> {
    let start = text
        .find(&format!("fn {name}("))
        .or_else(|| text.find(&format!("fn {name}<")))?;
    let open = start + text[start..].find('{')?;
    let mut depth = 0usize;
    for (offset, c) in text[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(text[open..=open + offset].to_owned());
                }
            }
            _ => {}
        }
    }
    None
}

/// `use crate::<module>::{a, b}` and `use crate::<module>::a;` in `text`: bare name → module.
fn imports_of(text: &str, modules: &BTreeSet<String>) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let mut rest = text;
    while let Some((_, tail)) = rest.split_once("use crate::") {
        let end = tail.find(';').unwrap_or(tail.len());
        let clause = &tail[..end];
        rest = &tail[end..];
        let Some((module, names)) = clause.split_once("::") else {
            continue;
        };
        if !modules.contains(module) {
            continue;
        }
        for name in names.trim_matches(|c| c == '{' || c == '}').split(',') {
            let name = name.trim();
            if !name.is_empty() {
                map.insert(name.to_owned(), module.to_owned());
            }
        }
    }
    map
}

fn is_ident(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Every call `name(` through an import, or `<module>::name(` by path, that lands in a
/// sibling module of the STS crate.
fn calls_in(
    body: &str,
    imports: &BTreeMap<String, String>,
    modules: &BTreeSet<String>,
) -> Vec<(String, String)> {
    let bytes = body.as_bytes();
    let mut calls = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !is_ident(bytes[i]) || (i > 0 && is_ident(bytes[i - 1])) {
            i += 1;
            continue;
        }
        let mut j = i;
        while j < bytes.len() && is_ident(bytes[j]) {
            j += 1;
        }
        let ident = &body[i..j];
        if body[j..].starts_with("::") {
            let mut k = j + 2;
            while k < bytes.len() && is_ident(bytes[k]) {
                k += 1;
            }
            if k > j + 2 && body[k..].starts_with('(') && modules.contains(ident) {
                calls.push((ident.to_owned(), body[j + 2..k].to_owned()));
            }
            i = k;
            continue;
        }
        if body[j..].starts_with('(')
            && let Some(module) = imports.get(ident)
        {
            calls.push((module.clone(), ident.to_owned()));
        }
        i = j;
    }
    calls
}

/// Every `DenialClause::<Name>` mentioned in a function body reachable by call from
/// `<module>::<function>`, following imports and paths transitively through the STS crate.
fn clauses_reachable_from(module: &str, function: &str) -> BTreeSet<String> {
    let modules = sts_modules();
    let mut seen = BTreeSet::new();
    let mut queue = vec![(module.to_owned(), function.to_owned())];
    let mut clauses = BTreeSet::new();
    while let Some((module, function)) = queue.pop() {
        if !seen.insert((module.clone(), function.clone())) {
            continue;
        }
        let text = without_comments(&source(&format!("{STS_SRC}/{module}.rs")));
        // A type, trait method or macro reached by name is not a free function on the path.
        let Some(body) = body_of(&text, &function) else {
            continue;
        };
        let mut rest = body.as_str();
        while let Some((_, tail)) = rest.split_once("DenialClause::") {
            let end = tail
                .find(|c: char| !c.is_ascii_alphanumeric())
                .unwrap_or(tail.len());
            clauses.insert(tail[..end].to_owned());
            rest = &tail[end..];
        }
        queue.extend(calls_in(&body, &imports_of(&text, &modules), &modules));
    }
    clauses
}

/// The rule's reachable set, computed from calls rather than from a fixed pair of files.
///
/// Correction 1's check read `redemption.rs` and `binding.rs` by name and the path spans
/// three files, so the three clauses `code::admitted_client` raises were never in the set the
/// rule was applied over (pass 2, F2). This case computes reachability the way the corrected
/// check must: from `redeem_authorization_code`, follow every call into a sibling module —
/// through a `use crate::<mod>::{name}` import or a `<mod>::name(` path — into that
/// function's body, transitively, and collect every `DenialClause::` the bodies mention. A
/// clause moved onto the path into a fourth file is caught because the traversal follows the
/// call, not the file name.
///
/// Coordinator amendment (pass 2 ruling on F2): this replaces the case that reproduced the
/// two-file scan and asserted it was short; the shipped check in `tests/oauth.rs` follows the
/// same method, and this case is its independent control.
#[test]
fn every_clause_reachable_from_a_redemption_by_call_answers_neither_scope_nor_client() {
    let reached = clauses_reachable_from("redemption", "redeem_authorization_code");
    for name in [
        "ClientUnregistered",
        "ClientOutsideOrganization",
        "ClientDisabled",
    ] {
        assert!(
            reached.contains(name),
            "{name} is raised by code::admitted_client, which bound_client calls on every \
             redemption; the traversal did not reach it, so this case's premise has moved"
        );
    }
    assert!(
        reached.len() >= 10,
        "a redemption reaches {} clause names; the traversal has lost the path",
        reached.len()
    );
    for (clause, answered) in oauth::CLAUSE_CODES {
        let name = format!("{clause:?}");
        let name = name.split(['(', ' ']).next().unwrap_or(&name);
        if !reached.contains(name) {
            continue;
        }
        assert!(
            *answered != ErrorCode::InvalidClient && *answered != ErrorCode::InvalidScope,
            "{name} is reachable from a redemption by call and answers {answered}, which \
             adapter-contract.md forbids for any redemption-reachable clause"
        );
    }
}

// --------------------------------- adapter-contract.md: the authorization endpoint's codes

/// `unauthorized_client` is the one RFC 6749 section 4.1.2.1 code this library cannot answer,
/// and three refusals on this road are exactly what it names.
///
/// `oauth.rs`'s own module documentation enumerates section 4.1.2.1 as seven codes —
/// "`invalid_request`, `unauthorized_client`, `access_denied`, `unsupported_response_type`,
/// `invalid_scope`, `server_error`, `temporarily_unavailable`" — and then declares
/// `ErrorCode::AUTHORIZATION_ENDPOINT`, documented as "The codes RFC 6749 section 4.1.2.1
/// declares for the authorization endpoint", holding six of them. `ErrorCode` declares no
/// variant for the seventh, so `code_for_reason` cannot return it from any input.
///
/// The stated reason is that "no refusal on this road produces it: it is section 4.1.2.1's
/// 'the client is not authorized to request an authorization code using this method'". Three
/// do. `crates/mandate-federation/src/authorize.rs` calls
/// `publicclient::registered_public_client`, which refuses `ClientUnknown`, `ClientDisabled`
/// and `ClientNotPublic` — "client is not a registered public client" and "the client is
/// disabled", the authorization endpoint's own two declared clauses — each with
/// `DenialReason::Denied`. The composition maps by reason, and `code_for_reason(Denied)` is
/// `access_denied`: "The resource owner or authorization server denied the request", which
/// tells a client developer the end user refused.
///
/// What reaches it: `AuthorizePublicClient` at `GET /oauth/authorize` with a client that is
/// unregistered, not public, or disabled — the first and third rows of the document's own
/// `AuthorizePublicClient` obligations table.
#[test]
fn the_authorization_endpoint_code_set_omits_the_unauthorized_client_the_rfc_declares() {
    // The condition is reachable, and it carries the reason the composition maps.
    let authorize = source(AUTHORIZE);
    let public_client = source(PUBLIC_CLIENT);
    assert!(
        authorize.contains("registered_public_client"),
        "authorize.rs no longer admits the client through publicclient.rs"
    );
    for name in ["ClientUnknown", "ClientNotPublic", "ClientDisabled"] {
        assert!(
            public_client.contains(&format!("DenialClause::{name}")),
            "registered_public_client no longer raises {name}"
        );
    }
    assert!(
        public_client.contains("DenialReason::Denied"),
        "the client refusals no longer carry DenialReason::Denied"
    );

    // RFC 6749 section 4.1.2.1's set, as `oauth.rs`'s own module documentation lists it.
    let declared_by_the_rfc = [
        "invalid_request",
        "unauthorized_client",
        "access_denied",
        "unsupported_response_type",
        "invalid_scope",
        "server_error",
        "temporarily_unavailable",
    ];
    let carried: BTreeSet<&str> = ErrorCode::AUTHORIZATION_ENDPOINT
        .iter()
        .map(|code| code.as_str())
        .collect();
    for name in declared_by_the_rfc {
        assert!(
            carried.contains(name),
            "ErrorCode::AUTHORIZATION_ENDPOINT is documented as the codes RFC 6749 section \
             4.1.2.1 declares and does not carry {name}; a client refused at /oauth/authorize \
             because it is unregistered, not public or disabled is answered access_denied"
        );
    }
}
