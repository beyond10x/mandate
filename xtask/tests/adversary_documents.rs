//! Adversary pass 1 on `story:gate-reads-document-deliverables`.
//!
//! Every case here drives `xtask/src/documents.rs` against a document the story's own
//! *Scope and boundary* section, or the module's own doc comment, says it must accept or reject.
//! Nothing here touches the live planning store: the `blocked` list is stubbed, exactly as
//! `xtask/tests/documents.rs` does, so a red case here is red on any machine on any day.
//!
//! The contract lines under attack, quoted:
//!
//! * `story:gate-reads-document-deliverables`, *Scope and boundary*: "a declared document exists,
//!   is non-empty, and — where a document declares a row set derived from the store — that the row
//!   set still matches `aep plan artifact blocked`. **Do not widen this into a prose linter.**"
//! * `xtask/src/documents.rs:16-18`: "A document states a row set in one of two shapes: a table
//!   row, in a table whose header carries a `Blocker` column and a store column (one ending
//!   `(store)`, or `Blocks`), or a bolded field whose label ends `(store).` under a heading naming
//!   the blocker."
//! * `xtask/src/documents.rs:252-253`: "Reports every failure it finds rather than the first."
//! * `docs/architecture/runtime-decisions.md:363` (SC7): "Two further open `decision-blocker`
//!   artifacts exist in the planning store and are **deliberately not rows above**."
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
/// A tree shaped like the repository, under a directory this file alone writes, so the two test
/// binaries can run at the same time without either clearing the other's fixtures.
fn fixture(name: &str) -> PathBuf {
    let root = repo().join("target/xtask-adversary-cases").join(name);
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
/// The store's answer for every case below. Shaped like the live store: every blocker `open`,
/// every held artifact a `story:` or a `task:`.
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

// ---------------------------------------------------------------------------
// A1. The row-set comparison is defeated by an ordinary markdown line wrap.
// ---------------------------------------------------------------------------

/// `documents.rs:123-126` reads a `(store).` field from **one** line, and `leading_ids` stops at
/// the end of it. A row body whose store-derived set wraps — which is what a markdown paragraph
/// does the moment it grows past a line budget — is read as its first line only. The tail is not
/// a mismatch and is not a warning: it is invisible.
///
/// The document below states `story:session-epochs` **and** `story:domain-runtime`. The store
/// holds only the first. That is precisely the drift SC2 (`runtime-decisions.md:358`) exists to
/// catch, and the gate is expected to name it.
#[test]
fn a_wrapped_store_field_hides_a_row_body_that_drifted_from_the_store() {
    let root = fixture("wrapped-store-field");
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
         ## 1. `decision-blocker:epoch` — epoch representation\n\
         \n\
         **Affected stories (store).** `story:session-epochs`,\n\
         `story:domain-runtime`.\n",
    );
    let result = documents::documents(&root, &store());
    let outcome = match &result {
        Ok(report) => format!("success, reporting {report:?}"),
        Err(e) => format!("failure, reporting {e}"),
    };
    let named = result.is_err_and(|e| e.to_string().contains("story:domain-runtime"));
    assert!(
        named,
        "a row body claiming `story:session-epochs` and `story:domain-runtime` while the store \
         holds only the first is the drift SC2 exists to catch, but the gate reported {outcome}"
    );
}

// ---------------------------------------------------------------------------
// A2. The step asserts something the story's boundary does not ask for, and the
//     assertion turns the store's own documented clearance operation red.
// ---------------------------------------------------------------------------

/// `aep plan artifact blocked --help`, verbatim: "A `blocks` edge counts until the artifact
/// declaring it reaches the end of its own lifecycle, so `protocol artifact move <blocker> --to
/// cleared` is how something is unblocked". A cleared blocker therefore leaves the report
/// entirely.
///
/// `documents.rs:271-282` asserts that **every textual occurrence** of `decision-blocker:` in
/// **every** declared document is still in that report — not every row, every occurrence. So
/// clearing one blocker makes `task check` red in every document whose prose names it, and the
/// only remedy is deleting the mention. `docs/architecture/unmapped.md` names twelve blockers in
/// prose and states no row set at all; `docs/architecture/federated-login.md:84,:103,:118` name
/// four more in running sentences.
///
/// The story's *Scope and boundary* names three assertions and this is not one of them, and ends
/// "Do not widen this into a prose linter."
#[test]
fn a_blocker_named_only_in_prose_does_not_have_to_still_be_in_the_blocked_report() {
    let root = fixture("cleared-blocker-in-prose");
    document(
        &root,
        "unmapped.md",
        "# Unmapped markers\n\
         \n\
         A register of the markers the contract carries and what each one waited on.\n\
         \n\
         AEP: `decision-blocker:epoch` blocks `story:session-epochs`.\n\
         \n\
         AEP: `decision-blocker:lifecycle` blocked `story:domain-runtime`; it was cleared on\n\
         2026-09-18 and the register keeps the record that it was ever stuck.\n",
    );
    // The store after that clearance: `decision-blocker:lifecycle` is simply gone.
    let report = documents::documents(&root, &store());
    assert!(
        report.is_ok(),
        "a register recording that a blocker was cleared states no row set, so the gate has \
         nothing to compare and the story forbids it from linting the prose — yet it failed: {}",
        report.unwrap_err()
    );
}

/// The same over-reach reached from the other side: a fenced code block. `named` at
/// `documents.rs:176-191` scans the raw bytes of the document, so a sample of the very report the
/// step shells out to is read as a claim about the store. `AGENTS.md` — a declared document —
/// already carries a fenced block of commands (`AGENTS.md:40-48`), so a declared document
/// documenting `aep plan artifact blocked` is an ordinary next edit, not a contrivance.
#[test]
fn a_blocker_id_inside_a_fenced_code_block_is_a_sample_not_a_claim() {
    let root = fixture("blocker-in-code-fence");
    document(
        &root,
        "tooling.md",
        "# Tooling\n\
         \n\
         `aep plan artifact blocked --format json` answers with one group per blocker:\n\
         \n\
         ```json\n\
         [\n\
         \x20 {\n\
         \x20   \"blocker\": \"decision-blocker:example\",\n\
         \x20   \"status\": \"open\",\n\
         \x20   \"blocks\": []\n\
         \x20 }\n\
         ]\n\
         ```\n\
         \n\
         The step compares that answer against every row set a document states.\n",
    );
    let report = documents::documents(&root, &store());
    assert!(
        report.is_ok(),
        "a placeholder id inside a fenced sample of the report's own shape is not a row set, but \
         the gate failed the document for it: {}",
        report.unwrap_err()
    );
}

/// The token scanner at `documents.rs:180-186` admits `:` into the middle **and the end** of an
/// id, so an unbackticked mention followed by a colon yields the phantom id
/// `decision-blocker:epoch:`, which no store can report. The document is correct; the gate is not.
#[test]
fn a_blocker_named_before_a_colon_is_not_a_different_blocker() {
    let root = fixture("blocker-before-a-colon");
    document(
        &root,
        "notes.md",
        "# Notes\n\
         \n\
         One item is still open, decision-blocker:epoch: what exact representation carries a\n\
         security generation value.\n",
    );
    let report = documents::documents(&root, &store());
    assert!(
        report.is_ok(),
        "`decision-blocker:epoch` is open in the store and the trailing colon is punctuation, \
         not part of the id: {}",
        report.unwrap_err()
    );
}

// ---------------------------------------------------------------------------
// A3. Row sets the reader silently declines to read. No error, no count, no signal.
// ---------------------------------------------------------------------------

/// `store_columns` (`documents.rs:112-121`) matches a header cell only as the bare word `Blocker`
/// and a store cell only as `Blocks` or a cell ending `(store)`. A bolded header — which renders
/// identically and is ordinary markdown — matches neither, so the whole table stops being
/// compared. Nothing reports that it stopped: there is no floor on the row count and no test
/// pins it, so the guard can be switched off by a formatting edit.
///
/// The row below disagrees with the store. The gate is expected to name it.
#[test]
fn a_table_whose_header_cells_are_bolded_is_still_a_row_set() {
    let root = fixture("bolded-table-header");
    document(
        &root,
        "runtime-decisions.md",
        "# Runtime decisions\n\
         \n\
         ## Index\n\
         \n\
         | # | **Blocker** | **Affected stories (store)** |\n\
         |---|---|---|\n\
         | 1 | `decision-blocker:epoch` | `story:domain-runtime` |\n",
    );
    let result = documents::documents(&root, &store());
    assert!(
        result.is_err(),
        "the row states `story:domain-runtime` and the store answers `story:session-epochs`, but \
         bolding the header cells made the table invisible and the gate reported success: {}",
        result.unwrap_or_default()
    );
}

/// GFM requires a literal pipe inside a cell to be written `\|`. `cells` (`documents.rs:108-110`)
/// splits on every `|` without honouring the escape, so one escaped pipe shifts every column to
/// its right by one. The store column then reads the wrong cell, finds no ids, and the gate fails
/// a document that is correct.
#[test]
fn an_escaped_pipe_inside_a_cell_does_not_move_the_store_column() {
    let root = fixture("escaped-pipe");
    document(
        &root,
        "runtime-decisions.md",
        "# Runtime decisions\n\
         \n\
         ## Index\n\
         \n\
         | # | Blocker | Marker | Affected stories (store) |\n\
         |---|---|---|---|\n\
         | 1 | `decision-blocker:epoch` | UNMAPPED-EPOCH \\| UNMAPPED-RESET | `story:session-epochs` |\n",
    );
    let report = documents::documents(&root, &store());
    assert!(
        report.is_ok(),
        "the row's store cell is `story:session-epochs`, which is exactly what the store answers; \
         the escaped pipe in the marker cell is not a column boundary: {}",
        report.unwrap_err()
    );
}

/// SC7 (`runtime-decisions.md:363`) is enforced by `claims` (`documents.rs:204`) recognising the
/// heading that opens the excluded table, and it recognises it by
/// `heading.to_ascii_lowercase().starts_with("excluded")`. `Exclusions` does not start with
/// `excluded`, so renaming the heading turns the whole SC7 assertion off silently: the excluded
/// rows become ordinary rows, and a blocker that is both excluded and a row is no longer
/// anything.
///
/// The first half of this case is the control: with the heading the implementation expects, the
/// same document fails, which is what proves the fixture is otherwise well formed.
#[test]
fn an_exclusions_heading_excludes_as_much_as_an_excluded_heading() {
    let body = |heading: &str| {
        format!(
            "# Runtime decisions\n\
             \n\
             ## Index\n\
             \n\
             | # | Blocker | Marker | Affected stories (store) |\n\
             |---|---|---|---|\n\
             | 1 | `decision-blocker:epoch` | UNMAPPED-EPOCH | `story:session-epochs` |\n\
             | 2 | `decision-blocker:drive-verifier` | DRIVE | `task:canonical-types-drive` |\n\
             \n\
             ## {heading}: execution tooling, not runtime decisions\n\
             \n\
             | Blocker | Title | Blocks |\n\
             |---|---|---|\n\
             | `decision-blocker:drive-verifier` | Evidence verifier | `task:canonical-types-drive` |\n"
        )
    };
    let control = fixture("excluded-heading-control");
    document(&control, "runtime-decisions.md", &body("Excluded"));
    let control = documents::documents(&control, &store());
    assert!(
        control.is_err(),
        "control: under the heading the implementation expects, a blocker that is both excluded \
         and a row must fail — the rest of this case means nothing if it does not: {}",
        control.unwrap_or_default()
    );
    let renamed = fixture("exclusions-heading");
    document(&renamed, "runtime-decisions.md", &body("Exclusions"));
    let renamed = documents::documents(&renamed, &store());
    assert!(
        renamed.is_err(),
        "`Exclusions` names the same section as `Excluded`, and `decision-blocker:drive-verifier` \
         is still both excluded from the rows and one of them, but the gate reported success: {}",
        renamed.unwrap_or_default()
    );
}

// ---------------------------------------------------------------------------
// A4. Boundaries of "exists and is not empty".
// ---------------------------------------------------------------------------

/// `text.trim().is_empty()` (`documents.rs:263`) decides emptiness, and `str::trim` removes
/// `White_Space` characters. U+FEFF is not one: a document whose entire content is a byte order
/// mark — what several editors and shells leave behind when a file is truncated and re-saved — is
/// a non-empty document to this gate.
///
/// The acceptance is "a checkout whose `docs/architecture/runtime-decisions.md` has been emptied
/// … exits non-zero naming that file".
#[test]
fn a_document_emptied_to_a_byte_order_mark_is_empty() {
    let root = fixture("byte-order-mark-only");
    document(&root, "runtime-decisions.md", "\u{feff}");
    let result = documents::documents(&root, &store());
    assert!(
        result.is_err(),
        "a file holding nothing but a byte order mark carries no document, but the gate counted \
         it as one: {}",
        result.unwrap_or_default()
    );
}

/// The `--root` the unit added carries the doc comment "The checkout to read. Defaults to this
/// workspace; pointing it at a copy is how this step's own failure is reproduced without editing
/// the tree it guards" (`xtask/src/main.rs:24-25`). `declared` propagates the bare `read_dir`
/// error with `?` (`documents.rs:91`, `:256`), so the one operator-facing mistake that flag
/// invites — a path that is wrong — is answered with `No such file or directory (os error 2)`
/// and no path at all, while every other failure of this step names its file.
#[test]
fn a_root_that_does_not_exist_is_named_in_the_error() {
    let missing = repo().join("target/xtask-adversary-cases/no-such-checkout");
    if missing.exists() {
        fs::remove_dir_all(&missing).expect("clear");
    }
    let message = documents::documents(&missing, &store())
        .expect_err("a root with no docs/architecture cannot be checked")
        .to_string();
    assert!(
        message.contains("no-such-checkout"),
        "the step names the file in every other failure; a bad --root is answered with {message:?}"
    );
}

// ---------------------------------------------------------------------------
// A5. The claim `documents.rs:252-253` makes about itself.
// ---------------------------------------------------------------------------

/// "Reports every failure it finds rather than the first, so one run names the whole correction."
#[test]
fn every_failure_is_reported_not_the_first() {
    let root = fixture("two-broken-documents");
    document(&root, "a-first.md", "");
    document(
        &root,
        "b-second.md",
        "# Second\n\
         \n\
         | Blocker | Blocks |\n\
         |---|---|\n\
         | `decision-blocker:epoch` | `story:domain-runtime` |\n",
    );
    let message = documents::documents(&root, &store())
        .expect_err("two broken documents")
        .to_string();
    assert!(
        message.contains("a-first.md") && message.contains("b-second.md"),
        "one run must name the whole correction: {message}"
    );
}
