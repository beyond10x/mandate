//! Adversary pass 2 over the `host-spelling-folded` unit of `story:host-spelling-folded`
//! (commit `af2982c`, the correction that answered five of pass 1's seven findings).
//!
//! Nothing here changes an implementation file. No key is generated and no case reaches
//! the network: every case calls [`UreqJwks::admits`], which decides a destination without
//! contacting it.
//!
//! # What was attacked and held
//!
//! The correction's headline claim is monotonicity: that folding the host at the issuer's
//! own-origin comparison widens nothing through the containment branch. Measured here
//! `06c6747` → `af2982c` over 39 × 39 ordered (issuer, destination) spellings, two
//! schemes and four host lists each (empty, the bare host, `host:port`, and a list
//! carrying every spelling at once) — 12 168 decisions: **269 pairs move refused →
//! admitted and every one leaves through the issuer's own-origin comparison; zero leave
//! through the containment branch.** 777 move admitted → refused and every one of those
//! is an address literal spelled with a trailing dot, which is the bypass the unit closed.
//! That claim holds and is not a finding.
//!
//! # What these cases drive
//!
//! | case | what it asks |
//! |---|---|
//! | [`the_corpus_the_reworked_property_iterates_asserts_something_at_both_sites`] | every row of that corpus answers what it declares, and at each of the two sites the corpus holds at least one row the guard admits and at least one it refuses. Opened as two findings — a containment comparison that was two refusals for 14 of 16 rows, and an `("http", "idp.example")` row that was two refusals at all four of its comparisons — and folded into one, because the second is the site-1 refusal witness the first needs |
//! | [`the_fold_does_not_make_the_issuers_own_a_host_origin_refuses`] | `folded` was `trim_end_matches('.')`, so it mapped `.`, `..` and `...` onto the empty host `origin` refuses outright (`src/verifier_real.rs:471`), and three distinct authorities became one origin |
//!
//! # Dispositions
//!
//! Two of this pass's four cases asserted properties of `admits` that hold only when the
//! SSRF containment is deleted: with the containment branch removed entirely, both went
//! green. A case that passes against a broken guard is not a check, and a suite read by
//! its exit status cannot carry one. Their findings were real and are answered — see the
//! case below, which keeps both verbatim and states how — and the assertions were rewritten
//! to ask a question about the corpus, which is what the findings were actually about.
//!
//! A third case, `one_host_gets_one_answer_at_the_issuers_own_origin_however_the_literal_is_spelled`,
//! left this file. `folded` is not total — `::1`, `0:0:0:0:0:0:0:1` and `0:0::0:1` are one
//! host to `literal_address`/`loopback` and three strangers to the issuer's own-origin
//! equality — and that is pre-existing, reproduces at the wave base, fails closed, and is
//! closed only by the guard resolving rather than parsing. It is filed as its own story.

use mandate_federation::verifier_real::UreqJwks;
use mandate_types::Issuer;

/// The rows `a_trailing_dot_does_not_change_what_the_jwks_destination_guard_answers`
/// iterates, with the answer each one declares, copied from `tests/verifier_real.rs`.
///
/// Copied rather than shared because that case owns them; if it gains a row, this list is
/// stale and says so by measuring one fewer row than the case it is about.
///
/// The two `bool`s are the answer the guard owes the row at each of the two sites: whether
/// it is admitted as the issuer's own origin under the empty host list, and whether it is
/// admitted when a third party's document names it and the deployment listed it.
const ROWS: [(&str, &str, bool, bool); 16] = [
    ("https", "localhost", true, false),
    ("https", "localhost.localdomain", true, false),
    ("https", "keys.localdomain", true, false),
    ("https", "127.0.0.1", true, false),
    ("https", "127.0.0.2", true, false),
    ("https", "127.255.255.254", true, false),
    ("https", "keys.idp.example", true, true),
    ("https", "idp.example", true, true),
    ("https", "[::1]", true, false),
    ("https", "[0:0:0:0:0:0:0:1]", true, false),
    ("https", "[::ffff:127.0.0.1]", true, false),
    ("http", "localhost", true, false),
    ("http", "localhost.localdomain", true, false),
    ("http", "127.0.0.1", true, false),
    ("http", "[::1]", true, false),
    ("http", "idp.example", false, false),
];

/// The absolute spelling the case under attack builds, verbatim.
fn dotted(host: &str) -> String {
    match host.strip_suffix(']') {
        Some(inside) => format!("{inside}.]"),
        None => format!("{host}."),
    }
}

/// The `allowed_hosts` the case under attack builds, verbatim.
fn entries(scheme: &str, host: &str) -> [String; 2] {
    let port = if scheme == "https" { 443 } else { 80 };
    let unbracket = |spelling: &str| spelling.trim_matches(|c| c == '[' || c == ']').to_owned();
    [
        format!("{}:{port}", unbracket(host)),
        format!("{}:{port}", unbracket(&dotted(host))),
    ]
}

/// Every row of the reworked property test's corpus answers what it declares, and neither
/// site is all-admissions or all-refusals.
///
/// # The two findings this case was opened with, verbatim
///
/// > The reworked property test's containment half is two refusals for 14 of its 16 rows.
/// >
/// > Pass 1 found that the shipped property was "an enumeration in disguise": it fixed the
/// > issuer at a third host and listed both spellings, so every row left through the
/// > containment branch and none reached the issuer's own origin. The correction rewrote it
/// > to ask each host at both, and its own documentation states the hazard it was avoiding —
/// > *"Two refusals satisfy an equality"*. It then crossed a positive block over the
/// > own-origin half only.
/// >
/// > The containment half kept the equality form. For every row whose host is a spelling of
/// > the loopback the guard refuses both sides *before* `allowed_hosts` is read, and for
/// > every `http` row the branch is dead at `target.scheme == "https"`, so 14 of the 16
/// > comparisons are `false == false`. Deleting `!literal_address(host) && !loopback(host)`
/// > from `admits` turns all 14 into `true == true` and the assertion still passes.
/// >
/// > The guard itself is covered — `a_listed_host_that_spells_the_loopback_interface_is_refused`
/// > kills that mutant on all 23 of its rows — so this is the case's claim about itself
/// > being wrong, not the guard being untested.
///
/// > The one row the correction added to reach the plaintext arm asserts nothing at all.
/// >
/// > `("http", "idp.example")` is the only row that is neither a spelling of the loopback
/// > nor `https`. Its own-origin comparison is `false == false` — `admits` returns
/// > `target.scheme == "https" || loopback(host)` there and neither holds — and its
/// > containment comparison is `false == false` because the branch begins
/// > `target.scheme == "https"`. All four of the row's comparisons are two refusals.
///
/// # How they were answered
///
/// Not by comparing the two spellings. Every row of that corpus now carries the answer the
/// guard owes it and is asserted against that constant, so equality of the two spellings
/// follows and vacuity does not. Measured by mutation, against
/// `a_trailing_dot_does_not_change_what_the_jwks_destination_guard_answers`:
///
/// | mutation of `admits` | that case |
/// |---|---|
/// | `!literal_address(host) && !loopback(host)` deleted | **FAILED** |
/// | `target.scheme == "https"` deleted from the containment branch | **FAILED** |
/// | the own-origin `loopback(host)` condition replaced by `true` | **FAILED** |
/// | none | ok |
///
/// The third row is the `("http", "idp.example")` row earning its place: it is the only row
/// whose own-origin answer is a refusal, so it is the only one that dies when the rule that
/// plaintext survives on the loopback and nowhere else is removed. Deleting it — the
/// obvious reading of the second finding — would have lost that coverage.
///
/// # Why this case no longer asks what it asked
///
/// Both original assertions were about `admits`'s answers, and both are satisfied by
/// deleting the containment branch: with it gone every row is admitted, no comparison is
/// two refusals, and both cases go green. A case that passes against a broken guard is not
/// a check.
///
/// What the findings were actually about is the corpus, and that is checkable: each row
/// answers what it declares, and at each site the corpus holds at least one row the guard
/// admits and at least one it refuses. Make the rows vacuous again and the witness lists go
/// empty; delete any part of the guard and the declared answers stop matching. Neither
/// escape is available.
#[test]
fn the_corpus_the_reworked_property_iterates_asserts_something_at_both_sites() {
    let no_hosts_listed: [String; 0] = [];
    let mut own_origin = (Vec::new(), Vec::new());
    let mut containment = (Vec::new(), Vec::new());

    for (scheme, host, is_own_origin, is_admitted_when_listed) in ROWS {
        let row = format!("{scheme}://{host}");
        let listed = entries(scheme, host);
        let elsewhere = Issuer::new(format!("{scheme}://third-party.example"));

        for destination in [host.to_owned(), dotted(host)] {
            let own = UreqJwks::admits(
                &Issuer::new(format!("{scheme}://{host}")),
                &format!("{scheme}://{destination}/jwks"),
                &no_hosts_listed,
            );
            assert_eq!(
                own, is_own_origin,
                "{row}: destination {scheme}://{destination} is not the answer the row \
                 declares at the issuer's own origin"
            );

            let contained = UreqJwks::admits(
                &elsewhere,
                &format!("{scheme}://{destination}/jwks"),
                &listed,
            );
            assert_eq!(
                contained, is_admitted_when_listed,
                "{row}: destination {scheme}://{destination} is not the answer the row \
                 declares at the containment guard"
            );
        }

        if is_own_origin {
            &mut own_origin.0
        } else {
            &mut own_origin.1
        }
        .push(row.clone());
        if is_admitted_when_listed {
            &mut containment.0
        } else {
            &mut containment.1
        }
        .push(row);
    }

    for (site, (admitted, refused)) in [
        ("the issuer's own origin", &own_origin),
        ("the containment guard", &containment),
    ] {
        assert!(
            !admitted.is_empty(),
            "no row of the corpus is admitted at {site}, so every comparison there is a \
             refusal against a refusal and the corpus asserts nothing about it"
        );
        assert!(
            !refused.is_empty(),
            "no row of the corpus is refused at {site}, so every comparison there is an \
             admission against an admission and the corpus asserts nothing about it"
        );
    }
}

/// The fold maps three distinct authorities onto the empty host `origin` refuses.
///
/// `folded` is `host.trim_end_matches('.')` (`src/verifier_real.rs:521`), which strips
/// every trailing dot rather than the one that makes a name absolute. `origin` refuses an
/// empty host outright — `if host.is_empty() { return None; }` (`src/verifier_real.rs:471`)
/// — and the fold puts it back: `.`, `..` and `...` all fold to `""`, so they are one
/// origin to the issuer's own-origin comparison and the guard returns without reading
/// `allowed_hosts` at all.
///
/// `.` is a row of the module's own residue table, recorded there as a host that *reaches
/// the list*; `..` does not reach the list, it is admitted before the list is consulted.
/// Nothing was found that configures an issuer of `https://.`, so this is a property of
/// the fold rather than a reachable defect — but it is the same over-fold that makes the
/// correction's *"every one is a pair whose two spellings are the same host"*
/// (`tests/verifier_real.rs:2372`) count `127.0.0.1..` as a spelling of `127.0.0.1`, and
/// a name with an empty label is not a spelling of anything.
#[test]
fn the_fold_does_not_make_the_issuers_own_a_host_origin_refuses() {
    let no_hosts_listed: [String; 0] = [];
    let issuer = Issuer::new("https://.");

    for other in ["https://../jwks", "https://.../jwks"] {
        assert!(
            !UreqJwks::admits(&issuer, other, &no_hosts_listed),
            "{other} folds to the empty host `origin` refuses, and was admitted as the \
             issuer's own origin"
        );
    }
}
