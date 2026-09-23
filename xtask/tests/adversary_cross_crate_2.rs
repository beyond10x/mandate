//! Adversary pass 2 against `story:cross-crate-clauses`, over the correction `2aa9f5c`.
//!
//! `mandate.federation.DisableOAuthClient` declares a `denied` outcome whose cause ends "or
//! disablement cannot stop the issuance of new authorization codes to it"
//! (`systems/mandate/domains/federation.yaml:425`). That is a condition under which
//! **DisableOAuthClient itself is refused**. A `denial` row counted `real` for it therefore
//! names a test that drives `disable_oauth_client` and sees it refuse. The correction points
//! the row at a test that drives `disable_oauth_client` to its *accepted* outcome and then
//! observes a different command's resolver (`registered_public_client`, the
//! `AuthorizePublicClient` clause "the client is disabled") refuse.
//!
//! The case reads the committed registry and the named test's source; it builds nothing.

use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_owned()
}

const COMMAND: &str = "mandate.federation.DisableOAuthClient";
const CLAUSE: &str = "disablement cannot stop the issuance of new authorization codes to it";
const HANDLER: &str = "disable_oauth_client(";

/// The source of `fn <name>` in the test binary a `crate::binary::name` id names.
fn test_body(id: &str) -> String {
    let parts: Vec<&str> = id.split("::").collect();
    assert_eq!(parts.len(), 3, "a test id is crate::binary::name: {id}");
    let (krate, binary, name) = (parts[0], parts[1], parts[2]);
    let candidates = [
        repo().join(format!("crates/{krate}/tests/{binary}.rs")),
        repo().join(format!(
            "services/{}/tests/{binary}.rs",
            krate.trim_start_matches("mandate-")
        )),
    ];
    let file = candidates
        .iter()
        .find(|path| path.is_file())
        .unwrap_or_else(|| panic!("no test binary source for {id}: {candidates:?}"));
    let text = fs::read_to_string(file).expect("the test source");
    let head = format!("fn {name}()");
    let at = text
        .find(&head)
        .unwrap_or_else(|| panic!("{} declares no {head}", file.display()));
    let rest = &text[at..];
    let end = rest.find("\n}\n").map_or(rest.len(), |end| end + 3);
    rest[..end].to_owned()
}

/// Whether some call of the handler in `body` is followed, before its statement ends, by a
/// reading of the refusal rather than of the accepted event.
fn sees_the_handler_refuse(body: &str) -> bool {
    body.match_indices(HANDLER).any(|(at, _)| {
        let statement = &body[at..];
        let statement = &statement[..statement.find(";\n").unwrap_or(statement.len())];
        ["expect_err", "unwrap_err", "is_err", "Err("]
            .iter()
            .any(|refusal| statement.contains(refusal))
    })
}

#[test]
fn the_disable_o_auth_client_denial_clause_is_decided_by_a_test_that_sees_disable_o_auth_client_refuse()
 {
    let text = fs::read_to_string(repo().join("contracts/obligations/federation.json"))
        .expect("the federation registry");
    let document: Value = serde_json::from_str(&text).expect("the registry parses");
    let entry = document["commands"]
        .as_array()
        .expect("commands")
        .iter()
        .find(|entry| entry["command"] == COMMAND)
        .expect("the DisableOAuthClient entry");
    let clause = entry["clauses"]
        .as_array()
        .expect("clauses")
        .iter()
        .find(|clause| clause["clause"] == CLAUSE)
        .expect("the issuance-stop clause, read verbatim from the entry");

    let deciding: Vec<&str> = clause["tests"]
        .as_array()
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .filter(|row| row["kind"] == "denial" && row["path"] == "real")
        .filter_map(|row| row["id"].as_str())
        .collect();
    if deciding.is_empty() {
        // Deferred with a blocker is an honest row; nothing to hold.
        return;
    }
    for id in deciding {
        let body = test_body(id);
        assert!(
            body.contains(HANDLER),
            "{COMMAND}'s clause {CLAUSE:?} is counted real on {id}, which never calls \
             {HANDLER}..): a denial of DisableOAuthClient is decided by a test that runs it"
        );
        assert!(
            sees_the_handler_refuse(&body),
            "{COMMAND}'s clause {CLAUSE:?} is a condition under which DisableOAuthClient is \
             refused, and it is counted real on {id}, whose every call of {HANDLER}..) reads \
             the accepted event — the refusal it asserts is another command's:\n{body}"
        );
    }
}
