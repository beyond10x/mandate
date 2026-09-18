//! Adversary pass 2 on `story:gate-reads-document-deliverables`, against correction round 1.
//!
//! Round 1 answered pass 1 by narrowing what counts as a claim and by adding `Reading.silent_tables`
//! — a report for a `Blocker`-column table that states no blocker, so a row set cannot stop being
//! compared without the gate saying so. These cases drive that guard, and the new claim grammar,
//! against the module's own doc comment:
//!
//! * `documents.rs:17-25`: "A **claim** is one of exactly three things … a row of a table whose
//!   header carries a `Blocker` column … a bolded field whose label ends `(store).`, under a
//!   heading naming a blocker … a row of either shape under a heading whose text begins `exclu`".
//! * `documents.rs:53-54`: "any table that names a `Blocker` column and then states no blocker at
//!   all, which is a row set that stopped being compared without saying so".
//! * `documents.rs:280-281`: "A markdown line wrap inside one is invisible to a reader and must be
//!   invisible here too, or half a row set is compared against all of it."
//!
//! The store is stubbed in every case, as in `xtask/tests/documents.rs`, so nothing here needs a
//! live planning store.
#[allow(dead_code)] // the binary target uses the whole module; a case here uses part of it.
#[path = "../src/documents.rs"]
mod documents;
use documents::Blocker;
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
fn fixture(name: &str) -> PathBuf {
    let root = repo().join("target/xtask-adversary-2-cases").join(name);
    if root.exists() {
        fs::remove_dir_all(&root).expect("clear the fixture");
    }
    fs::create_dir_all(root.join("docs/architecture")).expect("fixture tree");
    fs::write(root.join("README.md"), "# readme\n").expect("fixture README");
    fs::write(root.join("AGENTS.md"), "# agents\n").expect("fixture AGENTS");
    root
}
fn document(root: &Path, name: &str, body: &str) {
    fs::write(root.join("docs/architecture").join(name), body).expect("write document");
}
fn blocker(id: &str, status: &str, blocks: &[&str]) -> Blocker {
    Blocker {
        id: id.to_owned(),
        status: status.to_owned(),
        blocks: blocks.iter().map(|b| (*b).to_owned()).collect(),
    }
}
/// The store's answer for most cases: two open blockers, the shape the live store has.
fn store() -> Vec<Blocker> {
    vec![
        blocker("decision-blocker:epoch", "open", &["story:session-epochs"]),
        blocker(
            "decision-blocker:drive-verifier",
            "open",
            &["task:canonical-types-drive"],
        ),
    ]
}
fn outcome(result: &Result<String, Box<dyn std::error::Error>>) -> String {
    match result {
        Ok(report) => format!("success, reporting {report:?}"),
        Err(e) => format!("failure, reporting:\n{e}"),
    }
}

// ---------------------------------------------------------------------------
// B1. `silent_tables` fires only when a `Blocker` table yields *no* claim at all.
//     One unparseable row among many is still silent, which is the shape every
//     live table has.
// ---------------------------------------------------------------------------

/// `read` (`documents.rs:342-352`) counts a row only when `blocker_id` parses its `Blocker` cell,
/// and `silent_tables` is recorded only when that count reaches zero (`:318-323`, `:373-375`). A
/// table where one row's blocker cell loses its backticks therefore drops that row set with no
/// report at all, because the other rows keep the count above zero.
///
/// `docs/architecture/runtime-decisions.md:35-47` is an eleven-row `Blocker` table, so every live
/// instance of this guard is a table that cannot reach zero by losing one row.
///
/// Row 2 below states `story:domain-runtime`; the store answers `task:canonical-types-drive`.
#[test]
fn one_row_that_stops_being_read_is_reported_like_a_whole_table_that_does() {
    let root = fixture("one-unread-row");
    document(
        &root,
        "runtime-decisions.md",
        "# Runtime decisions\n\
         \n\
         ## Index\n\
         \n\
         | # | Blocker | Marker | Affected stories (store) |\n\
         |---|---|---|---|\n\
         | 1 | `decision-blocker:epoch` | UNMAPPED-EPOCH | `story:session-epochs` |\n\
         | 2 | decision-blocker:drive-verifier | DRIVE | `story:domain-runtime` |\n",
    );
    let result = documents::documents(&root, &store());
    assert!(
        result.is_err(),
        "row 2 of an eleven-row-shaped index stopped being compared and the drifted set it states \
         was never checked; `silent_tables` cannot see it because row 1 still parses. The gate \
         reported {}",
        outcome(&result)
    );
}

// ---------------------------------------------------------------------------
// B2. The guard was added for tables and not for the other claim shape.
// ---------------------------------------------------------------------------

/// `section_blocker` (`documents.rs:218-222`) admits a heading's blocker only through
/// `quoted`, so a heading that names the blocker by its full id **without backticks** yields no
/// section, and the `**… (store).**` field under it is neither a claim nor a report — the exact
/// "stopped being compared without saying so" that `silent_tables` was added to close for the
/// table shape, left open for the field shape.
///
/// The module's own grammar at `documents.rs:22-23` is "a bolded field whose label ends
/// `(store).`, under a heading naming a blocker". The heading below names the blocker.
#[test]
fn a_store_field_whose_heading_is_unreadable_is_reported_not_dropped() {
    let root = fixture("orphan-store-field");
    document(
        &root,
        "runtime-decisions.md",
        "# Runtime decisions\n\
         \n\
         ## 1. decision-blocker:epoch — epoch representation and arithmetic\n\
         \n\
         **Affected stories (store).** `story:domain-runtime`.\n",
    );
    let result = documents::documents(&root, &store());
    assert!(
        result.is_err(),
        "a `(store).` field states a row set whatever its heading looks like; this one claims \
         `story:domain-runtime` where the store answers `story:session-epochs`, and the gate \
         reported {}",
        outcome(&result)
    );
}

// ---------------------------------------------------------------------------
// B3. `blocker_id` reads one token per cell, and invents an id from any slug.
// ---------------------------------------------------------------------------

/// `blocker_id` (`documents.rs:225-236`) is `find_map` over the cell's quoted tokens and returns
/// the **first** match, so a `Blocker` cell naming two blockers claims one and drops the other
/// silently. The row still counts, so `silent_tables` does not fire either.
///
/// The store below does not report `decision-blocker:worker-orchestration` at all.
#[test]
fn a_blocker_cell_naming_two_blockers_claims_both_of_them() {
    let root = fixture("two-blockers-one-cell");
    document(
        &root,
        "federated-login.md",
        "# Federated login\n\
         \n\
         ## Decisions taken by the operator on 2026-09-18\n\
         \n\
         | Blocker | Decision | What it forecloses |\n\
         |---|---|---|\n\
         | `lifecycle` and `worker-orchestration` | Immutable-with-status. | Destructive delete. |\n",
    );
    let blocked = vec![blocker("decision-blocker:lifecycle", "open", &[])];
    let result = documents::documents(&root, &blocked);
    assert!(
        result.is_err(),
        "the row names two blockers and the store reports only one, but the second was never \
         looked up: {}",
        outcome(&result)
    );
}

/// The same function turns *any* backtick-quoted lowercase slug into
/// `decision-blocker:<slug>`. `documents.rs:215-217` states the reason the bare form is refused in
/// a heading — "it would turn `## The \\`epoch\\` field` into a claim about a blocker" — and the
/// identical hazard is admitted in a cell, where the first quoted token wins.
///
/// `` `none` `` is not a hypothetical token: `docs/architecture/federated-login.md:127` writes it
/// inside the very table whose first column this function reads.
#[test]
fn a_quoted_word_in_a_blocker_cell_is_not_automatically_a_blocker() {
    let root = fixture("slug-invented-blocker");
    document(
        &root,
        "federated-login.md",
        "# Federated login\n\
         \n\
         ## Decisions taken by the operator on 2026-09-18\n\
         \n\
         | Blocker | Decision | What it forecloses |\n\
         |---|---|---|\n\
         | `none` yet — tracked under `decision-blocker:epoch` | Deferred. | Nothing. |\n",
    );
    let result = documents::documents(&root, &store());
    assert!(
        result.is_ok(),
        "the cell's only blocker is `decision-blocker:epoch`, which the store reports as open; \
         `none` is a word: {}",
        outcome(&result)
    );
}

// ---------------------------------------------------------------------------
// B4. The `exclu` prefix, widened in round 1, now matches headings that are not
//     exclusions — and an over-match is a false failure, not a missed one.
// ---------------------------------------------------------------------------

/// Round 1 replaced `starts_with("excluded")` with `starts_with("exclu")`
/// (`documents.rs:326`) so that `Exclusions` would also be recognised. `Exclusive` begins `exclu`
/// too. Every claim under such a heading joins the document's excluded set, and every *other*
/// claim of the same blocker in that document is then reported as "recorded as excluded from this
/// document's rows and is one" — so an ordinary section heading fails a correct document.
#[test]
fn a_heading_about_exclusive_access_does_not_exclude_a_blocker() {
    let root = fixture("exclusive-heading");
    document(
        &root,
        "runtime-decisions.md",
        "# Runtime decisions\n\
         \n\
         ## Index\n\
         \n\
         | # | Blocker | Marker | Affected stories (store) |\n\
         |---|---|---|---|\n\
         | 1 | `decision-blocker:epoch` | UNMAPPED-EPOCH | `story:session-epochs` |\n\
         \n\
         ## Exclusive access and lock ordering\n\
         \n\
         | Blocker | Note |\n\
         |---|---|\n\
         | `decision-blocker:epoch` | the epoch row is the one that takes the write lock |\n",
    );
    let result = documents::documents(&root, &store());
    assert!(
        result.is_ok(),
        "`## Exclusive access and lock ordering` is not an exclusions section and the index row is \
         not an error: {}",
        outcome(&result)
    );
}

// ---------------------------------------------------------------------------
// B5. `field_paragraph` joins a wrapped field. A field written as a list is not
//     joined into anything `leading_ids` can read.
// ---------------------------------------------------------------------------

/// `field_paragraph` (`documents.rs:282-301`) breaks at a blank line and `leading_ids` reads only
/// the run of ids the field opens with, so a row set written as a markdown list — the ordinary way
/// to write four of them — is read as the empty set and reported as drift from the store it in
/// fact agrees with. The diagnosis the operator gets, "blocks nothing here", names a document
/// defect that does not exist.
#[test]
fn a_store_field_written_as_a_list_states_the_row_set_it_lists() {
    let root = fixture("store-field-as-list");
    document(
        &root,
        "runtime-decisions.md",
        "# Runtime decisions\n\
         \n\
         ## 1. `decision-blocker:epoch` — epoch representation\n\
         \n\
         **Affected stories (store).**\n\
         \n\
         - `story:session-epochs`\n",
    );
    let result = documents::documents(&root, &store());
    assert!(
        result.is_ok(),
        "the field lists exactly the one story the store answers with: {}",
        outcome(&result)
    );
}
