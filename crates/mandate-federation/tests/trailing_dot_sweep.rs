//! The 12 168-decision sweep of the JWKS destination guard, kept so its measurements can be
//! taken again.
//!
//! `tests/verifier_real.rs` records four base → head measurements of [`UreqJwks::admits`]
//! taken with this sweep — `story:host-spelling-folded` (`06c6747` →), the address fold
//! (`86a32ae` →) and the two trailing-dot rounds (`bde627b` → `4f268d7` and `4f268d7` →
//! `edfc215`) — and the sweep itself was never committed, so none of them could be
//! reproduced. It is here now, `#[ignore]`d because it measures rather than gates: it
//! runs with `cargo test -p mandate-federation --test trailing_dot_sweep -- --ignored`.
//!
//! # What it asks
//!
//! Every ordered (issuer, destination) pair of the 39 [`SPELLINGS`] — the 25 rows of
//! `tests/verifier_real.rs`'s first spelling table, the 10 of its residue table, and
//! `idp.example`/`keys.idp.example` with and without a trailing dot — under both
//! [`SCHEMES`] and four host lists each: empty, the destination's bare spelling, the
//! destination's spelling with its scheme's default port, and every spelling at once.
//! 39 × 39 × 2 × 4 = 12 168 decisions. Each is also asked against a third-party issuer,
//! which leaves only through the containment guard, so a moved decision can be attributed
//! to the issuer's own-origin comparison or to the containment guard.
//!
//! # Reproducing a base → head measurement
//!
//! A test binary sees one tree, so the movement between two commits is two runs:
//!
//! 1. At the base commit, in a scratch checkout, copy this file into
//!    `crates/mandate-federation/tests/` and run
//!    `MANDATE_SWEEP_WRITE=<table> cargo test -p mandate-federation --test trailing_dot_sweep -- --ignored the_sweep`.
//!    `UreqJwks::admits` has had this signature since `06c6747`.
//! 2. At the head, run the same command with `MANDATE_SWEEP_BASE=<table>` instead. The
//!    sweep prints the head's table summary and the movement against the base: how many
//!    decisions moved each way, and how many of them moved against the third-party issuer
//!    too.
//!
//! The table is one tab-separated line per decision — scheme, issuer spelling,
//! destination spelling, host list, the answer, the third-party answer — so two tables
//! are also comparable with `diff`.
//!
//! # What the trailing-dot rounds left true
//!
//! [`no_spelling_the_trailing_dot_rounds_refused_is_admitted_anywhere_in_the_sweep`] pins
//! the head's side of those two measurements: every decision that names one of the nine
//! spellings the rounds refused, as issuer or destination, is refused (the third-party
//! column speaks for the destination only).

use std::collections::BTreeMap;
use std::fmt::Write as _;

use mandate_federation::verifier_real::UreqJwks;
use mandate_types::Issuer;

/// The 39 host spellings, as written into an issuer or a `jwks_uri`.
const SPELLINGS: [&str; 39] = [
    // The first table of `tests/verifier_real.rs`: 25 spellings of the loopback.
    "127.0.0.1",
    "127.0.0.1.",
    "127.0.0.1..",
    "127.0.0.2",
    "127.0.0.2.",
    "127.255.255.254.",
    "localhost",
    "localhost.",
    "localhost..",
    "LOCALHOST",
    "LOCALHOST.",
    "localhost.localdomain",
    "localhost.localdomain.",
    "keys.localdomain",
    "keys.localdomain.",
    "[::1]",
    "[::1.]",
    "[0:0:0:0:0:0:0:1]",
    "[0:0:0:0:0:0:0:1.]",
    "[0:0::0:1]",
    "[::ffff:127.0.0.1]",
    "[::ffff:127.0.0.1.]",
    "[::ffff:7f00:1]",
    "[::FFFF:7F00:1]",
    "[::127.0.0.1]",
    // Its residue table: 10 spellings a C resolver folds and `IpAddr` does not.
    "127.1",
    "2130706433",
    "0177.0.0.1",
    "0",
    "127.0.0.001",
    "127.0.0.1%2e",
    "localhost%2e",
    "%6cocalhost",
    "%31%32%37.0.0.1",
    ".",
    // Two plain names, with and without their absolute form.
    "idp.example",
    "idp.example.",
    "keys.idp.example",
    "keys.idp.example.",
];

/// The two schemes, each with the port an elided one means.
const SCHEMES: [(&str, u16); 2] = [("http", 80), ("https", 443)];

/// The issuer every decision is also asked against: a host no spelling names, so its
/// answer leaves only through the containment guard.
const THIRD_PARTY: &str = "third-party.example";

/// The nine spellings the two trailing-dot rounds refused: the five marked ² in
/// `tests/verifier_real.rs` (`bde627b` → `4f268d7`), then the three dotted IPv4 literals
/// and `.` (`4f268d7` → `edfc215`).
const REFUSED_BY_THE_TRAILING_DOT_ROUNDS: [&str; 9] = [
    "127.0.0.1..",
    "localhost..",
    "[::1.]",
    "[0:0:0:0:0:0:0:1.]",
    "[::ffff:127.0.0.1.]",
    "127.0.0.1.",
    "127.0.0.2.",
    "127.255.255.254.",
    ".",
];

/// The four host lists asked for one destination, each with the name the table gives it.
fn host_lists(destination: &str, port: u16) -> [(&'static str, Vec<String>); 4] {
    [
        ("empty", Vec::new()),
        ("bare", vec![destination.to_owned()]),
        ("port", vec![format!("{destination}:{port}")]),
        (
            "every",
            SPELLINGS
                .iter()
                .map(|&spelling| spelling.to_owned())
                .collect(),
        ),
    ]
}

/// One decision of the sweep.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Decision {
    scheme: &'static str,
    issuer: &'static str,
    destination: &'static str,
    list: &'static str,
    admitted: bool,
    third_party_admitted: bool,
}

impl Decision {
    /// The row this decision is in both tables, without its answers.
    fn key(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}",
            self.scheme, self.issuer, self.destination, self.list
        )
    }

    fn line(&self) -> String {
        format!(
            "{}\t{}\t{}",
            self.key(),
            self.admitted,
            self.third_party_admitted
        )
    }
}

/// Every decision of the sweep, in a fixed order.
fn sweep() -> Vec<Decision> {
    let mut decisions = Vec::with_capacity(12_168);
    for (scheme, port) in SCHEMES {
        let third_party = Issuer::new(format!("{scheme}://{THIRD_PARTY}"));
        for issuer in SPELLINGS {
            let source = Issuer::new(format!("{scheme}://{issuer}"));
            for destination in SPELLINGS {
                let uri = format!("{scheme}://{destination}/keys");
                for (list, hosts) in host_lists(destination, port) {
                    decisions.push(Decision {
                        scheme,
                        issuer,
                        destination,
                        list,
                        admitted: UreqJwks::admits(&source, &uri, &hosts),
                        third_party_admitted: UreqJwks::admits(&third_party, &uri, &hosts),
                    });
                }
            }
        }
    }
    decisions
}

/// A table written by an earlier run, keyed by row: the answer and the third-party answer.
fn read_table(text: &str) -> BTreeMap<String, (bool, bool)> {
    text.lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(fields.len(), 6, "a table line has six fields: {line:?}");
            let answer = |field: &str| match field {
                "true" => true,
                "false" => false,
                other => panic!("an answer is true or false, not {other:?}"),
            };
            (
                fields[..4].join("\t"),
                (answer(fields[4]), answer(fields[5])),
            )
        })
        .collect()
}

/// The movement from `base` to `head`, as the measurements in `tests/verifier_real.rs`
/// state it.
fn movement(base: &BTreeMap<String, (bool, bool)>, head: &[Decision]) -> String {
    let mut widened = 0_usize;
    let mut narrowed = 0_usize;
    let mut widened_at_third_party = 0_usize;
    let mut narrowed_at_third_party = 0_usize;
    for decision in head {
        let Some(&(was, third_party_was)) = base.get(&decision.key()) else {
            panic!("the base table has no row {:?}", decision.key());
        };
        match (was, decision.admitted) {
            (false, true) => widened += 1,
            (true, false) => narrowed += 1,
            _ => {}
        }
        match (third_party_was, decision.third_party_admitted) {
            (false, true) => widened_at_third_party += 1,
            (true, false) => narrowed_at_third_party += 1,
            _ => {}
        }
    }
    assert_eq!(
        base.len(),
        head.len(),
        "the base table and the head's sweep are not one corpus"
    );
    format!(
        "refused -> admitted: {widened} ({widened_at_third_party} against the third-party issuer)\n\
         admitted -> refused: {narrowed} ({narrowed_at_third_party} against the third-party issuer)\n"
    )
}

/// The sweep: its size, its table, and — when a base table is named — the movement.
///
/// `MANDATE_SWEEP_WRITE` names a file the table is written to; `MANDATE_SWEEP_BASE` names
/// a table an earlier run wrote, and the movement against it is printed. Neither is read
/// by any other case, and with neither set this prints the summary alone.
#[test]
#[ignore = "a measurement, not a gate: run with --ignored, see the module documentation"]
fn the_sweep_decides_twelve_thousand_one_hundred_and_sixty_eight_pairs() {
    let decisions = sweep();
    assert_eq!(
        decisions.len(),
        12_168,
        "39 x 39 spellings x 2 schemes x 4 lists"
    );

    let admitted = decisions
        .iter()
        .filter(|decision| decision.admitted)
        .count();
    let third_party = decisions
        .iter()
        .filter(|decision| decision.third_party_admitted)
        .count();
    let mut report = format!(
        "decisions: {}\nadmitted: {admitted}\nadmitted against the third-party issuer: {third_party}\n",
        decisions.len()
    );

    if let Some(path) = std::env::var_os("MANDATE_SWEEP_WRITE") {
        let mut table = String::new();
        for decision in &decisions {
            let _ = writeln!(table, "{}", decision.line());
        }
        std::fs::write(&path, table).expect("the table is written where MANDATE_SWEEP_WRITE says");
    }
    if let Some(path) = std::env::var_os("MANDATE_SWEEP_BASE") {
        let text = std::fs::read_to_string(&path)
            .expect("MANDATE_SWEEP_BASE names a table an earlier run wrote");
        report.push_str(&movement(&read_table(&text), &decisions));
    }
    println!("{report}");
}

/// The head's side of the two trailing-dot measurements: none of the nine spellings those
/// rounds refused is admitted anywhere in the sweep, as issuer or as destination, under
/// either scheme or any list.
#[test]
#[ignore = "a measurement, not a gate: run with --ignored, see the module documentation"]
fn no_spelling_the_trailing_dot_rounds_refused_is_admitted_anywhere_in_the_sweep() {
    let admitted: Vec<String> = sweep()
        .into_iter()
        .filter(|decision| {
            // The third-party column never names the issuer's spelling, so it speaks only
            // for the destination.
            (REFUSED_BY_THE_TRAILING_DOT_ROUNDS.contains(&decision.issuer) && decision.admitted)
                || (REFUSED_BY_THE_TRAILING_DOT_ROUNDS.contains(&decision.destination)
                    && (decision.admitted || decision.third_party_admitted))
        })
        .map(|decision| decision.line())
        .collect();
    assert!(
        admitted.is_empty(),
        "{} decisions naming a refused trailing-dot spelling are admitted:\n{}",
        admitted.len(),
        admitted.join("\n")
    );
}
