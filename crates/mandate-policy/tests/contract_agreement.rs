//! The realization registry of this crate, decided against the compiled contract.
//!
//! `mandate_types::realizes!` expands each entry into a `use` of the symbol on the right, so
//! a symbol that moved does not build. What no compiler can check is the string on the left,
//! which is the half a coverage report is read through — an element this crate named and the
//! contract does not declare is a realization of nothing. That is what the first case below
//! decides, and the second decides the reverse: that every element the contract declares in
//! this crate's domain is named by [`mandate_policy::ESS_REALIZATIONS`] or by
//! [`mandate_policy::ESS_UNREALIZED`], never by both and never by neither. This is the pair
//! `crates/mandate-federation/tests/contract_agreement.rs` established for its domain.
//!
//! # Why the compiled model is read as file names here
//!
//! `mandate-federation` reads `generated/ir/system.json` with `serde_json`. This crate
//! cannot: `dependency-boundaries.json` gives `mandate-policy` exactly `mandate-types` and
//! `mandate-model`, and `cargo xtask boundaries` refuses any other dependency, so
//! `serde_json` is not a name this test can write. The element set is therefore read as the
//! file names of `generated/schema/<kind>/`, which is how
//! `crates/mandate-types/tests/inventory.rs` reads the same index. Both projections are
//! emitted from one compiled model and `cargo xtask contracts` byte-compares each against a
//! fresh compilation, so the two indexes cannot disagree without the gate failing first.

use std::collections::BTreeSet;
use std::fs;

/// The domain this crate realizes elements of, and of no other
/// (`docs/architecture/ownership.md:13`).
const DOMAIN: &str = "mandate.policy.";

const SCHEMA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../generated/schema");

/// Every element the compiled model declares, across the five element indexes.
///
/// The `responses` directory is deliberately not read: a response is part of a command's
/// declaration and is not an element a crate realizes on its own.
fn declared_elements() -> BTreeSet<String> {
    let mut declared = BTreeSet::new();
    for kind in ["commands", "events", "entities", "errors", "types"] {
        let directory = format!("{SCHEMA}/{kind}");
        let entries =
            fs::read_dir(&directory).unwrap_or_else(|error| panic!("{directory}: {error}"));
        for entry in entries {
            let name = entry.expect("directory entry").file_name();
            let name = name.to_string_lossy();
            let element = name
                .strip_suffix(".schema.json")
                .unwrap_or_else(|| panic!("{directory}: unexpected entry {name}"));
            declared.insert(element.to_owned());
        }
    }
    assert_eq!(declared.len(), 292, "the compiled model's element count");
    declared
}

/// Every element the crate registers as realized is one the contract declares, and one of
/// this crate's own domain.
#[test]
fn every_realized_element_is_one_the_contract_declares() {
    let declared = declared_elements();

    assert!(
        !mandate_policy::ESS_REALIZATIONS.is_empty(),
        "the crate registers what it realizes"
    );
    for (element, symbol) in mandate_policy::ESS_REALIZATIONS {
        assert!(
            declared.contains(*element),
            "{element} (realized by {symbol}) is declared by no commands, events, entities, \
             errors or types index of the compiled model"
        );
        // One declared element has one realizer, and this crate realizes elements of its
        // own domain and of no other. Deny precedence and role expansion live here and are
        // consumed by `mandate-authz`; consuming a rule is not realizing another domain.
        assert!(
            element.starts_with(DOMAIN),
            "{element} (realized by {symbol}) is not an element of this crate's domain"
        );
    }
}

/// The registry and the list of what it does not cover account for every declared element of
/// this domain, once each.
#[test]
fn every_declared_element_of_this_domain_is_realized_or_named_as_unrealized() {
    let realized: BTreeSet<&str> = mandate_policy::ESS_REALIZATIONS
        .iter()
        .map(|(element, _)| *element)
        .filter(|element| element.starts_with(DOMAIN))
        .collect();
    let unrealized: BTreeSet<&str> = mandate_policy::ESS_UNREALIZED
        .iter()
        .map(|(element, _)| *element)
        .collect();

    let declared: BTreeSet<String> = declared_elements()
        .into_iter()
        .filter(|element| element.starts_with(DOMAIN))
        .collect();
    let accounted: BTreeSet<String> = realized
        .iter()
        .chain(unrealized.iter())
        .map(|element| (*element).to_owned())
        .collect();

    assert_eq!(
        declared, accounted,
        "every declared element of this domain is named by ESS_REALIZATIONS or by \
         ESS_UNREALIZED"
    );
    assert!(
        realized.is_disjoint(&unrealized),
        "an element is realized or it is not: {:?}",
        realized.intersection(&unrealized).collect::<Vec<_>>()
    );
    assert_eq!(
        realized.len(),
        mandate_policy::ESS_REALIZATIONS.len(),
        "the registry holds no duplicate"
    );
    assert_eq!(
        unrealized.len(),
        mandate_policy::ESS_UNREALIZED.len(),
        "the unrealized list holds no duplicate"
    );
    for (element, reason) in mandate_policy::ESS_UNREALIZED {
        assert!(
            !reason.trim().is_empty(),
            "{element} is named as unrealized with no reason"
        );
        assert!(
            element.starts_with(DOMAIN),
            "{element} is not an element of this crate's domain"
        );
    }
}

/// The coverage manifest's account of this crate is exactly this crate's registry, element
/// and symbol both.
///
/// `contracts/coverage.json` maps every element of the contract to what implements it, and
/// nothing in the manifest is compiled: a symbol there is a string. This is the case that
/// makes the string answerable — the registry's right-hand sides are expanded into `use`
/// declarations by `mandate_types::realizes!`, so they exist or the crate does not build, and
/// the manifest is asserted equal to them here. An entry claiming this crate realizes an
/// element it does not, or realizes it with a symbol it does not name, fails in this crate's
/// own suite rather than in a reader of the manifest.
///
/// `cargo xtask coverage` decides the complementary half: that every `implemented` entry
/// names a crate which runs a case like this one. An entry naming a crate that runs none
/// would be a claim nothing reconciles.
///
/// # Why the manifest is read as lines
///
/// The same reason the element index is: no `serde_json` is reachable from this crate. The
/// manifest is written one entry to a line for exactly this, and a reflowed manifest would
/// leave this case selecting nothing and passing — so the line count is asserted against the
/// number of entries the file holds, and a reflow is red here as well as in the step.
#[test]
fn the_coverage_manifest_names_exactly_what_this_crate_realizes() {
    let registered: BTreeSet<(String, String)> = mandate_policy::ESS_REALIZATIONS
        .iter()
        .map(|(element, symbol)| ((*element).to_owned(), (*symbol).to_owned()))
        .collect();
    assert_eq!(
        registered.len(),
        mandate_policy::ESS_REALIZATIONS.len(),
        "the registry holds no duplicate pair"
    );
    assert_eq!(
        manifest_entries(env!("CARGO_PKG_NAME")),
        registered,
        "the coverage manifest's implemented entries for this crate are not its registry"
    );
    no_unrealized_element_contradicts_the_coverage_manifest(mandate_policy::ESS_UNREALIZED);
}

const MANIFEST: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contracts/coverage.json");

/// Every `implemented` entry of the coverage manifest that names `crate_name`, as the
/// element and the single symbol it pairs with.
fn manifest_entries(crate_name: &str) -> BTreeSet<(String, String)> {
    let text = fs::read_to_string(MANIFEST).unwrap_or_else(|error| panic!("{MANIFEST}: {error}"));
    let opener = "{\"element\":\"";
    let mine = format!("\"crate\":\"{crate_name}\"");
    let mut entries = BTreeSet::new();
    let mut lines = 0_usize;
    for line in text.lines() {
        if !line.starts_with(opener) {
            continue;
        }
        lines += 1;
        if !line.contains(&mine) {
            continue;
        }
        let element = field(line, "\"element\":\"");
        assert_eq!(
            field(line, "\"status\":\""),
            "implemented",
            "{element}: an entry names a crate and is not implemented"
        );
        let symbols = symbol_list(line, &element);
        assert_eq!(
            symbols.len(),
            1,
            "{element}: one element has one realizer, and one realizer names one symbol"
        );
        entries.insert((element, symbols[0].clone()));
    }
    assert_eq!(
        lines,
        text.matches(opener).count(),
        "the coverage manifest is not written one entry to a line, so this case reads only \
         part of it"
    );
    assert!(
        !entries.is_empty(),
        "the coverage manifest names no entry for {crate_name}, so this case decides nothing"
    );
    entries
}

/// The value of a string field, from the key through to the closing quote.
fn field(line: &str, key: &str) -> String {
    let rest = line
        .split_once(key)
        .unwrap_or_else(|| panic!("a manifest entry states no {key}: {line}"))
        .1;
    rest.split_once('"')
        .unwrap_or_else(|| panic!("a manifest entry's {key} does not close: {line}"))
        .0
        .to_owned()
}

/// The `impl` list of an entry, as the symbol paths it names.
fn symbol_list(line: &str, element: &str) -> Vec<String> {
    let rest = line
        .split_once("\"impl\":[")
        .unwrap_or_else(|| panic!("{element}: the entry states no impl list"))
        .1;
    let list = rest
        .split_once(']')
        .unwrap_or_else(|| panic!("{element}: the entry's impl list does not close"))
        .0;
    if list.is_empty() {
        return Vec::new();
    }
    list.split(',')
        .map(|symbol| {
            symbol
                .strip_prefix('"')
                .and_then(|symbol| symbol.strip_suffix('"'))
                .unwrap_or_else(|| panic!("{element}: {symbol} is no quoted symbol path"))
                .to_owned()
        })
        .collect()
}

/// Every entry of the coverage manifest, as `(status, crate, the first impl symbol)`.
///
/// Read as lines, for the reason `manifest_entries` is: no `serde_json` is reachable from
/// this crate. A reflowed manifest yields fewer than 292 entries here and the count below
/// refuses it, so this reader cannot select nothing and pass.
fn coverage_manifest_claims() -> std::collections::BTreeMap<String, (String, String, String)> {
    let text = fs::read_to_string(MANIFEST).unwrap_or_else(|error| panic!("{MANIFEST}: {error}"));
    let mut claims = std::collections::BTreeMap::new();
    for line in text.lines() {
        if !line.starts_with("{\"element\":\"") {
            continue;
        }
        let element = field(line, "\"element\":\"");
        let holder = if line.contains("\"crate\":\"") {
            field(line, "\"crate\":\"")
        } else {
            String::new()
        };
        let symbols = symbol_list(line, &element);
        claims.insert(
            element,
            (
                field(line, "\"status\":\""),
                holder,
                symbols.first().cloned().unwrap_or_default(),
            ),
        );
    }
    assert_eq!(claims.len(), 292, "the coverage manifest's element count");
    claims
}

/// The symbol an `ESS_UNREALIZED` reason names as the realizer, when it names one.
fn named_realizer(reason: &str) -> Option<String> {
    let (_, named) = reason.split_once("realized by ")?;
    let named = named.trim_start_matches('`');
    let claimed: String = named
        .chars()
        .take_while(|character| {
            character.is_ascii_alphanumeric() || *character == '_' || *character == ':'
        })
        .collect();
    (!claimed.is_empty()).then_some(claimed)
}

/// A manifest symbol as an absolute path: `crate::` is the crate the entry names.
fn absolute(holder: &str, symbol: &str) -> String {
    match symbol.strip_prefix("crate::") {
        Some(tail) => format!("{}::{tail}", holder.replace('-', "_")),
        None => symbol.to_owned(),
    }
}

/// Nothing this crate registers as **unrealized** is reported implemented by the coverage
/// manifest — unless this crate's own reason names the realizer, and then the manifest names
/// that same symbol.
///
/// `ESS_UNREALIZED` is this crate's statement, in the crate's own source, that it realizes an
/// element it declares nothing for. The manifest is a second account of the same question,
/// and until this check nothing in the tree compared them: `cargo xtask coverage` reads only
/// the manifest, and the equality above reads only `ESS_REALIZATIONS`. That gap let 23
/// derived `.State` entries be reported implemented by the generated contract shape, six of
/// them while the crate that owns the domain said in its own registry that nothing realizes
/// them.
///
/// The exemption is not a hole: a reason of the form "realized by `<symbol>`" is this crate
/// naming **another crate's** realization, and the assertion on that branch is stronger than
/// the refusal — the manifest has to report the element implemented by exactly that symbol.
/// One declared element still has one realizer; this says the two documents agree on which.
fn no_unrealized_element_contradicts_the_coverage_manifest(unrealized: &[(&str, &str)]) {
    assert!(
        !unrealized.is_empty(),
        "this crate registers no unrealized element, so this check reads nothing"
    );
    let claims = coverage_manifest_claims();
    let mut contradictions = Vec::new();
    for (element, reason) in unrealized {
        let (status, holder, symbol) = claims
            .get(*element)
            .unwrap_or_else(|| panic!("{element}: the coverage manifest has no entry"));
        match named_realizer(reason) {
            None => {
                if status == "implemented" {
                    contradictions.push(format!(
                        "  {element}: this crate registers it as an element it does not \
                         realize and names no realizer, and the coverage manifest reports it \
                         implemented by {holder} as {symbol}"
                    ));
                }
            }
            Some(named) if status != "implemented" => contradictions.push(format!(
                "  {element}: this crate's reason names {named} as its realizer and the \
                 coverage manifest reports it {status}"
            )),
            Some(named) => {
                let resolved = absolute(holder, symbol);
                if resolved != named {
                    contradictions.push(format!(
                        "  {element}: this crate's reason names {named} as its realizer and \
                         the coverage manifest names {resolved}"
                    ));
                }
            }
        }
    }
    assert!(
        contradictions.is_empty(),
        "this crate's ESS_UNREALIZED registry and the coverage manifest disagree about {} \
         element(s):\n{}",
        contradictions.len(),
        contradictions.join("\n")
    );
}
