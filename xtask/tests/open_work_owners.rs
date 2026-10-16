//! No record names a finished story as the owner of work that is still open.
//!
//! The coverage manifest, the obligations registry and the conformance ledger already refuse a
//! `blocked_on` or a `declared`/`deferred` row whose story is on a terminal rung. Two records
//! state an owner outside those readers, and both had drifted onto finished stories:
//!
//! * `tests/security/cases.json` gives every case a `story`. A case the obligations registry
//!   still defers (`cases[].blocked_on`) is open work, so its `story` must be live too;
//!   `graph-revocation` named `story:graph-policy` after that story was implemented, while the
//!   registry deferred the case to `story:graph-policy-adapter`.
//! * A scenario's `summary` names the story that owns its residue (`residue story:<id>`). Five
//!   federation scenarios named `story:signing-and-verification`, implemented, for a residue —
//!   the standing decode-only verifier double — that `story:testkit-doubles` owns.
//!
//! Both are read here against this workspace's own planning store, with the same rung reader
//! the coverage step uses.
#![allow(dead_code)] // the binary target uses the whole of each module; a case here uses part.
#[path = "../src/documents.rs"]
mod documents;
#[path = "../src/emit.rs"]
mod emit;

#[path = "../src/coverage.rs"]
mod coverage;

use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap_or_else(|error| {
        panic!("{}: {error}", path.display());
    }))
    .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// Why `story` answers nothing as an owner of open work, or `None` when it is live.
fn not_live(story: &str) -> Option<String> {
    let slug = story.strip_prefix("story:")?;
    let path = workspace().join(format!(".engineering/planning/story/{slug}.md"));
    if !path.is_file() {
        return Some(format!("{story}, which the planning store does not hold"));
    }
    coverage::terminal_rung(&path).map(|rung| format!("{story}, which is `{rung}`"))
}

#[test]
fn a_security_case_the_registry_still_defers_names_a_live_story() {
    let root = workspace();
    let cases = json(&root.join("tests/security/cases.json"));
    let owner: BTreeMap<&str, &str> = cases["cases"]
        .as_array()
        .expect("tests/security/cases.json: cases")
        .iter()
        .filter_map(|case| Some((case["id"].as_str()?, case["story"].as_str()?)))
        .collect();
    assert!(!owner.is_empty(), "the corpus names no case with a story");

    let mut deferred = 0_usize;
    let mut problems = Vec::new();
    let directory = root.join("contracts/obligations");
    for entry in fs::read_dir(&directory).expect("contracts/obligations") {
        let path = entry.expect("directory entry").path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        let document = json(&path);
        for row in document["cases"].as_array().map_or(&[][..], Vec::as_slice) {
            if row["blocked_on"].is_null() {
                continue;
            }
            deferred += 1;
            let case = row["case"].as_str().expect("a cases row names its case");
            match owner.get(case) {
                None => problems.push(format!(
                    "{}: defers the case {case}, which tests/security/cases.json does not carry",
                    path.display()
                )),
                Some(story) => {
                    if let Some(why) = not_live(story) {
                        problems.push(format!(
                            "{case}: deferred by {} and owned in tests/security/cases.json by \
                             {why}",
                            path.display()
                        ));
                    }
                }
            }
        }
    }
    assert!(
        deferred > 0,
        "no obligations document defers a case, so this check selected nothing"
    );
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn every_scenario_residue_names_a_live_story() {
    let directory = workspace().join("systems/mandate/scenarios");
    let mut named = 0_usize;
    let mut problems = Vec::new();
    for entry in fs::read_dir(&directory).expect("systems/mandate/scenarios") {
        let path = entry.expect("directory entry").path();
        let text = fs::read_to_string(&path).expect("scenario text");
        for (at, _) in text.match_indices("residue story:") {
            let rest = &text[at + "residue ".len()..];
            let story: String = rest
                .chars()
                .take_while(|character| {
                    character.is_ascii_alphanumeric() || *character == '-' || *character == ':'
                })
                .collect();
            named += 1;
            if let Some(why) = not_live(&story) {
                problems.push(format!(
                    "{}: names the residue's owner as {why}",
                    path.display()
                ));
            }
        }
    }
    assert!(
        named > 0,
        "no scenario names a residue owner, so this check selected nothing"
    );
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}
