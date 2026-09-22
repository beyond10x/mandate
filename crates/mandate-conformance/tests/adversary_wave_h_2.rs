//! Adversary pass 2 against `story:link-absent-discriminates` (`8b7a6e0`), conformance half.
//!
//! `tests/target.rs`'s `every_port_method_the_substituted_reader_implements_counts_its_read`
//! is a guard over a hand-written list, and it says so, and it says what stops the list
//! rotting:
//!
//! > The list above is hand-written, and a hand-written list of what to check is the defect
//! > an adversary extends one entry at a time. So it is checked against the source it is a
//! > list of: every `fn` inside an `impl … for Substituted` block must appear here by name.
//! > A method added to a port and not to this list fails on the next run rather than
//! > reaching a reader as an uncounted read.
//!
//! The check it describes scans `src/external.rs` for the methods `Substituted`
//! **overrides**. A port method with a default body is never in an `impl … for Substituted`
//! block, so it is not in that scan, and the sentence above does not hold for one. The
//! correction under attack added exactly such a method — `LinkStore::link`, defaulted on the
//! trait and derived from `LinkStore::records_on_key` — and the guard did not fire.
//!
//! The case below is the check the comment describes, made over the port definitions rather
//! than over one implementation of them.

use std::collections::BTreeSet;
use std::path::Path;

/// The federation ports `mandate_conformance::external::Substituted` implements, as they
/// are declared in `mandate-federation`'s own source.
const PORTS: [&str; 4] = [
    "ConnectionStore",
    "LinkStore",
    "ExternalPrincipalStore",
    "PrincipalStore",
];

/// Every method a port declares is exercised by the guard, defaulted methods included.
///
/// `target.rs`'s guard is a set difference against the methods `Substituted` *overrides*, so
/// it is blind to a port method that carries a default body — which is the one kind of
/// method that can answer a handler without `Substituted`'s own `read()` ever running,
/// because its body is written somewhere `external.rs` never sees. That is exactly the
/// `consulted: 0` an `injections.json` row reads as `armed-unreached`, which is the defect
/// the guard was written for.
///
/// `LinkStore::link` does not have that consequence today: its default delegates to
/// `records_on_key`, which counts. The guard's claim is what fails — the next defaulted port
/// method does not have to delegate to anything.
#[test]
fn every_method_a_federation_port_declares_is_exercised_by_the_substituted_guard() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let ports = std::fs::read_to_string(manifest.join("../mandate-federation/src/lib.rs"))
        .expect("the federation crate's own source is readable");
    let guard = std::fs::read_to_string(manifest.join("tests/target.rs"))
        .expect("this crate's own test source is readable");

    // Every method each port declares, defaulted or required, as `Port::method`.
    let mut declared: BTreeSet<String> = BTreeSet::new();
    let mut open: Option<&str> = None;
    for line in ports.lines() {
        if let Some(port) = PORTS
            .iter()
            .find(|port| line == format!("pub trait {port} {{"))
        {
            open = Some(port);
            continue;
        }
        let Some(port) = open else { continue };
        if line == "}" {
            open = None;
            continue;
        }
        if let Some(rest) = line.strip_prefix("    fn ") {
            let name = rest.split(['(', '<']).next().unwrap_or_default();
            declared.insert(format!("{port}::{name}"));
        }
    }
    assert!(
        declared.len() >= 6,
        "the scan of the port declarations found {declared:?}, which cannot be right"
    );

    // And every one of them named in the guard's own list of what it calls.
    let unexercised: Vec<&String> = declared
        .iter()
        .filter(|method| !guard.contains(&format!("\"{method}\"")))
        .collect();
    assert!(
        unexercised.is_empty(),
        "`every_port_method_the_substituted_reader_implements_counts_its_read` says \"a method \
         added to a port and not to this list fails on the next run rather than reaching a \
         reader as an uncounted read\". Its own check is a set difference against the methods \
         `src/external.rs` overrides, so a port method with a default body is invisible to it \
         and the sentence does not hold. These are declared on a port `Substituted` implements \
         and are not in the list the guard calls: {unexercised:?}"
    );
}
