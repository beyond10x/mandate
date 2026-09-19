//! Adversary pass 2 against `story:model-agreement`, the `mandate-types` half.
//!
//! The state account added by this unit is two documents — the module prose of
//! `tests/conformance.rs` and the item prose of `src/inventory.rs` — and both make claims
//! about the workspace that nothing in the suite reads back. These two cases read them
//! back: the count of `.State` declarations that share a variant list, against
//! `generated/schema/types`, and the list of domain state enums outside this crate,
//! against every `pub enum` in the workspace's own sources.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const WORKSPACE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
const SCHEMA_TYPES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../generated/schema/types");
const INVENTORY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/inventory.rs");
const CONFORMANCE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/conformance.rs");

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|error| panic!("{path}: {error}"))
}

/// The doc prose of one source file, as one line of single-spaced words.
fn prose(source: &str) -> String {
    let lines: Vec<&str> = source
        .lines()
        .map(str::trim_start)
        .map(|line| {
            line.strip_prefix("//!")
                .or_else(|| line.strip_prefix("///"))
                .unwrap_or("")
        })
        .collect();
    lines
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// How many `.State` declarations share their whole variant list with another of the 36.
fn declarations_sharing_a_variant_list() -> usize {
    let mut lists: BTreeMap<Vec<String>, usize> = BTreeMap::new();
    let entries =
        std::fs::read_dir(SCHEMA_TYPES).unwrap_or_else(|error| panic!("{SCHEMA_TYPES}: {error}"));
    for entry in entries {
        let file = entry.expect("directory entry").file_name();
        let file = file.to_string_lossy().into_owned();
        let Some(ess_name) = file.strip_suffix(".schema.json") else {
            continue;
        };
        if !ess_name.ends_with(".State") {
            continue;
        }
        let path = format!("{SCHEMA_TYPES}/{file}");
        let document: serde_json::Value =
            serde_json::from_str(&read(&path)).expect("the compiled declaration is JSON");
        let variants: Vec<String> = document["$defs"][ess_name]["enum"]
            .as_array()
            .unwrap_or_else(|| panic!("{ess_name}: no declared variants"))
            .iter()
            .map(|variant| {
                variant
                    .as_str()
                    .unwrap_or_else(|| panic!("{ess_name}: a declared variant is not a string"))
                    .to_owned()
            })
            .collect();
        *lists.entry(variants).or_default() += 1;
    }
    lists.values().filter(|count| **count > 1).sum()
}

/// Every count a `share a variant list` sentence in `source` states.
///
/// The claim is written `N of the 36 … share a variant list` or `the N … that share a
/// variant list`, so 36 is the denominator and the other number in the window is the
/// count. A sentence that no longer parses is reported as a missing claim rather than as
/// agreement.
fn stated_shared_counts(source: &str) -> Vec<usize> {
    let joined = prose(source);
    let tokens: Vec<&str> = joined.split_whitespace().collect();
    let mut stated = Vec::new();
    for (index, window) in tokens.windows(4).enumerate() {
        if window != ["share", "a", "variant", "list"] {
            continue;
        }
        let mut back = index;
        while back > 0 && index - back < 8 {
            back -= 1;
            let digits = tokens[back].trim_matches(|character: char| !character.is_ascii_digit());
            if let Ok(number) = digits.parse::<usize>()
                && number != 36
            {
                stated.push(number);
                break;
            }
        }
    }
    stated
}

/// Every `.rs` file under a workspace member's `src`, generated emissions excluded.
fn member_sources() -> Vec<PathBuf> {
    fn walk(directory: &Path, found: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(directory) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, found);
            } else if path.extension().and_then(std::ffi::OsStr::to_str) == Some("rs") {
                found.push(path);
            }
        }
    }

    let mut sources = Vec::new();
    for group in ["crates", "services", "bins"] {
        let path = PathBuf::from(WORKSPACE).join(group);
        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            let source = entry.path().join("src");
            if source.is_dir() {
                walk(&source, &mut sources);
            }
        }
    }
    sources.sort();
    sources
}

/// Every `pub enum <…>State` one source declares, with the line it is declared on.
fn public_state_enums(text: &str) -> Vec<(usize, String)> {
    const NEEDLE: &str = "pub enum ";
    let mut found = Vec::new();
    let mut offset = 0;
    while let Some(at) = text[offset..].find(NEEDLE) {
        let start = offset + at + NEEDLE.len();
        let name: String = text[start..]
            .chars()
            .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
            .collect();
        if name.ends_with("State") {
            found.push((text[..start].matches('\n').count() + 1, name));
        }
        offset = start;
    }
    found
}

/// The count of shared variant lists the account states is the count the model declares.
#[test]
fn the_shared_variant_list_count_the_account_states_is_the_count_the_compiled_model_has() {
    let declared = declarations_sharing_a_variant_list();
    for (shown, path) in [
        ("crates/mandate-types/src/inventory.rs", INVENTORY),
        ("crates/mandate-types/tests/conformance.rs", CONFORMANCE),
    ] {
        let stated = stated_shared_counts(&read(path));
        assert!(
            !stated.is_empty(),
            "{shown} no longer states how many of the 36 share a variant list; the claim \
             this case pins is gone rather than agreed with",
        );
        for number in stated {
            assert_eq!(
                number, declared,
                "{shown} states that {number} of the 36 derived state declarations share a \
                 variant list with another; generated/schema/types declares {declared} \
                 that do, so the account understates the pairings its derivation check is \
                 the only discriminator for",
            );
        }
    }
}

/// Every public domain state enum in the workspace is one the account names.
#[test]
fn every_public_domain_state_enum_in_the_workspace_is_named_by_the_account() {
    let account = format!("{} {}", prose(&read(INVENTORY)), prose(&read(CONFORMANCE)));
    let mut seen = 0_usize;
    for path in member_sources() {
        let text = read(&path.to_string_lossy());
        for (line, name) in public_state_enums(&text) {
            seen += 1;
            let shown = path
                .strip_prefix(WORKSPACE)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            assert!(
                account.contains(&format!("`{name}`")),
                "{shown}:{line} declares the domain state enum {name}, and the account of \
                 the 36 derived state enums in crates/mandate-types/{{src/inventory.rs,\
                 tests/conformance.rs}} does not name it, so nothing says which element it \
                 realizes or which story decides it against the contract",
            );
        }
    }
    assert!(
        seen >= 16,
        "the workspace walk found {seen} public state enums, fewer than the sixteen the \
         account already accounts for, so this case is not reading the sources it claims to",
    );
}
