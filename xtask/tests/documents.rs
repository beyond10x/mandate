//! The gate's document reader, decided against constructed trees and a stubbed `blocked` list, so
//! no case here needs the live planning store.
#[allow(dead_code)] // the binary target uses the whole module; a case here uses part of it.
#[path = "../src/documents.rs"]
mod documents;
use documents::Blocker;
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};
fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_owned()
}
/// A tree shaped like the repository: `docs/architecture/` plus the two root documents.
fn fixture(name: &str) -> PathBuf {
    let root = repo().join("target/xtask-documents-cases").join(name);
    if root.exists() {
        fs::remove_dir_all(&root).expect("clear the fixture");
    }
    fs::create_dir_all(root.join("docs/architecture")).expect("fixture tree");
    fs::write(root.join("README.md"), "# readme\n").expect("fixture README");
    fs::write(root.join("AGENTS.md"), "# agents\n").expect("fixture AGENTS");
    root
}
fn copy_architecture(root: &Path) {
    let source = repo().join("docs/architecture");
    for entry in fs::read_dir(&source).expect("docs/architecture") {
        let path = entry.expect("entry").path();
        if path.extension().is_some_and(|e| e == "md") {
            let name = path.file_name().expect("file name");
            fs::copy(&path, root.join("docs/architecture").join(name)).expect("copy document");
        }
    }
}
fn blocker(id: &str, status: &str, blocks: &[&str]) -> Blocker {
    Blocker {
        id: id.to_owned(),
        status: status.to_owned(),
        blocks: blocks.iter().map(|b| (*b).to_owned()).collect(),
    }
}
/// A dossier in the shape `runtime-decisions.md` uses: an index table, one row section per
/// blocker stating its own row set, and an excluded table naming blockers that are not rows.
fn dossier(index: &str, bodies: &str, excluded: &str) -> String {
    format!(
        "# Runtime decisions\n\n## Index\n\n\
         | # | Blocker | Marker | Affected stories (store) |\n|---|---|---|---|\n{index}\n\
         {bodies}\n\
         ## Excluded: execution tooling, not runtime decisions\n\n\
         | Blocker | Title | Blocks |\n|---|---|---|\n{excluded}\n"
    )
}
fn consistent() -> String {
    dossier(
        "| 1 | `decision-blocker:epoch` | UNMAPPED-EPOCH | `story:session-epochs` |\n\
         | 2 | `decision-blocker:backend` | UNMAPPED-BACKEND | `story:graph-policy-adapter` |",
        "\n## 1. `decision-blocker:epoch` — epoch representation\n\n\
         **Affected stories (store).** `story:session-epochs`.\n\n\
         ## 2. `decision-blocker:backend` — policy backend\n\n\
         **Affected stories (store).** `story:graph-policy-adapter` (moved from \
         `story:graph-policy` on 2026-09-18).\n",
        "| `decision-blocker:drive-verifier` | Evidence verifier | `task:canonical-types-drive` |",
    )
}
fn store() -> Vec<Blocker> {
    vec![
        blocker("decision-blocker:epoch", "open", &["story:session-epochs"]),
        blocker(
            "decision-blocker:backend",
            "open",
            &["story:graph-policy-adapter"],
        ),
        blocker(
            "decision-blocker:drive-verifier",
            "open",
            &["task:canonical-types-drive"],
        ),
    ]
}
fn write(root: &Path, body: &str) {
    fs::write(root.join("docs/architecture/runtime-decisions.md"), body).expect("write dossier");
}
#[test]
fn an_emptied_declared_document_fails_naming_it() {
    let root = fixture("emptied-dossier");
    copy_architecture(&root);
    write(&root, "");
    let error = documents::documents(&root, &store())
        .expect_err("an emptied document deliverable must fail the gate");
    let message = error.to_string();
    assert!(
        message
            .lines()
            .any(|l| l == "docs/architecture/runtime-decisions.md: declared document is empty"),
        "{message}"
    );
}
#[test]
fn a_whitespace_only_document_is_empty_too() {
    let root = fixture("whitespace-dossier");
    copy_architecture(&root);
    write(&root, "\n\n   \n");
    let message = documents::documents(&root, &store())
        .expect_err("whitespace is not a document")
        .to_string();
    assert!(
        message
            .lines()
            .any(|l| l == "docs/architecture/runtime-decisions.md: declared document is empty"),
        "{message}"
    );
}
#[test]
fn a_missing_root_document_fails_naming_it() {
    let root = fixture("missing-readme");
    write(&root, &consistent());
    fs::remove_file(root.join("README.md")).expect("remove README");
    let message = documents::documents(&root, &store())
        .expect_err("a declared document that is gone must fail the gate")
        .to_string();
    assert!(message.contains("README.md"), "{message}");
}
#[test]
fn a_tree_whose_row_sets_match_the_store_passes() {
    let root = fixture("consistent");
    write(&root, &consistent());
    let report = documents::documents(&root, &store()).expect("a consistent tree passes");
    assert!(report.contains("3 declared documents"), "{report}");
    assert!(report.contains("5 store-derived row sets"), "{report}");
}
#[test]
fn an_index_row_that_disagrees_with_the_store_fails() {
    let root = fixture("stale-index-row");
    let body = consistent().replace(
        "| 2 | `decision-blocker:backend` | UNMAPPED-BACKEND | `story:graph-policy-adapter` |",
        "| 2 | `decision-blocker:backend` | UNMAPPED-BACKEND | `story:graph-policy` |",
    );
    let row = body
        .lines()
        .position(|l| l.starts_with("| 2 |"))
        .expect("the row under test")
        + 1;
    write(&root, &body);
    let message = documents::documents(&root, &store())
        .expect_err("a row set the store no longer agrees with must fail the gate")
        .to_string();
    assert!(
        message.contains(&format!("docs/architecture/runtime-decisions.md:{row}:")),
        "{message}"
    );
    assert!(message.contains("decision-blocker:backend"), "{message}");
    assert!(message.contains("story:graph-policy-adapter"), "{message}");
}
#[test]
fn a_row_body_that_disagrees_with_the_store_fails() {
    let root = fixture("stale-row-body");
    write(
        &root,
        &consistent().replace(
            "**Affected stories (store).** `story:session-epochs`.",
            "**Affected stories (store).** `story:session-epochs`, `story:domain-runtime`.",
        ),
    );
    let message = documents::documents(&root, &store())
        .expect_err("a row body states a row set too, and it is checked")
        .to_string();
    assert!(message.contains("decision-blocker:epoch"), "{message}");
    assert!(message.contains("story:domain-runtime"), "{message}");
}
#[test]
fn a_blocker_the_store_does_not_report_as_open_fails() {
    let root = fixture("cleared-blocker");
    write(&root, &consistent());
    let mut blocked = store();
    blocked[0].status = "cleared".to_owned();
    let message = documents::documents(&root, &blocked)
        .expect_err("a document may not name a blocker the store has cleared")
        .to_string();
    assert!(message.contains("decision-blocker:epoch"), "{message}");
    assert!(message.contains("cleared"), "{message}");
}
#[test]
fn a_blocker_the_store_does_not_report_at_all_fails() {
    let root = fixture("absent-blocker");
    write(&root, &consistent());
    let blocked: Vec<Blocker> = store()
        .into_iter()
        .filter(|b| b.id != "decision-blocker:drive-verifier")
        .collect();
    let message = documents::documents(&root, &blocked)
        .expect_err("a document may not name a blocker the store does not report")
        .to_string();
    assert!(
        message.contains("decision-blocker:drive-verifier"),
        "{message}"
    );
}
#[test]
fn a_blocker_excluded_from_the_rows_may_not_also_be_a_row() {
    let root = fixture("excluded-and-row");
    write(
        &root,
        &consistent().replace(
            "| 2 | `decision-blocker:backend` | UNMAPPED-BACKEND | `story:graph-policy-adapter` |",
            "| 2 | `decision-blocker:backend` | UNMAPPED-BACKEND | `story:graph-policy-adapter` |\n\
             | 3 | `decision-blocker:drive-verifier` | DRIVE | `task:canonical-types-drive` |",
        ),
    );
    let message = documents::documents(&root, &store())
        .expect_err("a blocker the document excludes from its rows may not be one")
        .to_string();
    assert!(
        message.contains("decision-blocker:drive-verifier"),
        "{message}"
    );
}
#[test]
fn the_declared_list_walks_architecture_and_names_the_two_root_documents() {
    let declared = documents::declared(&repo()).expect("declare the repository's documents");
    for expected in [
        "docs/architecture/runtime-decisions.md",
        "docs/architecture/federated-login.md",
        "docs/architecture/command-obligations.md",
        "README.md",
        "AGENTS.md",
    ] {
        assert!(
            declared.iter().any(|d| d == Path::new(expected)),
            "{expected} is not declared: {declared:?}"
        );
    }
}
/// The report for a `Blocker` table that opens and then states no blocker, pinned by its message
/// and its line — with the report for the row that stated none. A row set that stops being
/// compared is the failure this step exists to prevent, so neither report may be deleted without
/// a red case here.
#[test]
fn a_blocker_table_that_states_no_blocker_is_reported_by_its_own_lines() {
    let root = fixture("table-states-no-blocker");
    let body = "# Runtime decisions\n\
                \n\
                ## Index\n\
                \n\
                | # | Blocker | Marker | Affected stories (store) |\n\
                |---|---|---|---|\n\
                | 1 | to be decided | UNMAPPED-EPOCH | `story:session-epochs` |\n";
    let header = body
        .lines()
        .position(|l| l.starts_with("| # |"))
        .expect("the header row")
        + 1;
    write(&root, body);
    let message = documents::documents(&root, &store())
        .expect_err("a table that states no blocker states no row set either")
        .to_string();
    assert!(
        message.lines().any(|l| l
            == format!(
                "docs/architecture/runtime-decisions.md:{header}: this table names a `Blocker` \
                 column and states no blocker"
            )),
        "{message}"
    );
    assert!(
        message.lines().any(|l| l
            == format!(
                "docs/architecture/runtime-decisions.md:{}: this row of a `Blocker` table states \
                 no blocker",
                header + 2
            )),
        "{message}"
    );
}
/// A `Blocker` column of bare names with no store column at all — the shape
/// `federated-login.md:124-133` has. There is no row set to compare and the blockers are claimed
/// anyway, so one the store stops reporting is still caught.
#[test]
fn bare_names_in_a_blocker_column_without_a_store_column_are_still_claimed() {
    let root = fixture("bare-names-no-store-column");
    write(
        &root,
        "# Federated login\n\
         \n\
         ## Decisions taken by the operator\n\
         \n\
         | Blocker | Decision | What it forecloses |\n\
         |---|---|---|\n\
         | `epoch` | An ESS Integer, monotonic. | Wrapping on overflow. |\n\
         | `lifecycle` | Immutable-with-status. | Destructive delete of any record. |\n",
    );
    let message = documents::documents(&root, &store())
        .expect_err("`decision-blocker:lifecycle` is not in this store")
        .to_string();
    assert!(
        message.contains("claims `decision-blocker:lifecycle`"),
        "{message}"
    );
    assert!(
        !message.contains("decision-blocker:epoch"),
        "`epoch` is open and states no row set here: {message}"
    );
}
/// The store column is found by its header, not by its position: put the row set in the middle and
/// the comparison still reads it.
#[test]
fn a_store_column_that_is_not_the_last_column_is_the_one_compared() {
    let root = fixture("store-column-in-the-middle");
    write(
        &root,
        "# Runtime decisions\n\
         \n\
         ## Index\n\
         \n\
         | Blocker | Affected stories (store) | Marker |\n\
         |---|---|---|\n\
         | `decision-blocker:epoch` | `story:domain-runtime` | UNMAPPED-EPOCH |\n",
    );
    let message = documents::documents(&root, &store())
        .expect_err("the middle column states the row set and it disagrees")
        .to_string();
    assert!(
        message.contains(
            "`decision-blocker:epoch` blocks `story:domain-runtime` here, \
             `story:session-epochs` in the store"
        ),
        "{message}"
    );
}
/// A `Blocker` table with no store column states no row set, so nothing is compared — a cell that
/// looks like one is not one.
#[test]
fn a_blocker_table_without_a_store_column_compares_nothing() {
    let root = fixture("no-store-column");
    write(
        &root,
        "# Runtime decisions\n\
         \n\
         ## Notes\n\
         \n\
         | Blocker | Note |\n\
         |---|---|\n\
         | `decision-blocker:epoch` | the row `story:domain-runtime` waits on |\n",
    );
    let report = documents::documents(&root, &store())
        .expect("a table with no store column has nothing to compare");
    assert!(report.contains("0 store-derived row sets"), "{report}");
}
/// The store the step compares against is this workspace's own, named explicitly on the command
/// line. `--root` relocates the documents and nothing else: a copy of the documents must not be
/// able to answer for itself. The runner is injected, so this pins the command line without a
/// live store.
#[test]
fn the_store_is_read_from_the_workspace_and_never_from_the_document_root() {
    let workspace = Path::new("/checkout/mandate");
    let mut ran: Vec<String> = Vec::new();
    let parsed = documents::blocked_with(workspace, |program, args| {
        ran.push(program.to_owned());
        ran.extend(args.iter().cloned());
        Ok(br#"[{"blocker":"decision-blocker:epoch","status":"open","blocks":[{"id":"story:session-epochs"}]}]"#.to_vec())
    })
    .expect("read the stubbed store");
    assert_eq!(
        ran.iter().map(String::as_str).collect::<Vec<_>>(),
        vec![
            "aep",
            "plan",
            "artifact",
            "blocked",
            "--format",
            "json",
            "--store",
            "/checkout/mandate/.engineering/planning",
        ]
    );
    assert_eq!(
        parsed,
        vec![blocker(
            "decision-blocker:epoch",
            "open",
            &["story:session-epochs"]
        )]
    );
    let (_, elsewhere) = documents::blocked_command(Path::new("/scratch/copy-of-the-documents"));
    assert_eq!(
        elsewhere.last().map(String::as_str),
        Some("/scratch/copy-of-the-documents/.engineering/planning"),
        "the store path is the workspace it is given, not a default and not a document root"
    );
}
#[test]
fn blocked_json_parses_the_shape_aep_prints() {
    let sample = br#"[
      {
        "blocker": "decision-blocker:backend",
        "type": "decision",
        "kind": "decision-blocker",
        "status": "open",
        "title": "UNMAPPED-BACKEND",
        "blocks": [
          {
            "id": "story:graph-policy-adapter",
            "kind": "story",
            "status": "draft",
            "title": "Attach the chosen graph and policy engines behind the ports"
          }
        ]
      }
    ]"#;
    let parsed = documents::parse_blocked(sample).expect("parse `aep plan artifact blocked`");
    assert_eq!(
        parsed,
        vec![blocker(
            "decision-blocker:backend",
            "open",
            &["story:graph-policy-adapter"]
        )]
    );
    let only: BTreeSet<String> = parsed[0].blocks.clone();
    assert_eq!(only.len(), 1);
}
