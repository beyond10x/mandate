//! Adversary pass 2 against `story:conform-gate`, after correction round 1.
//!
//! Every case copies what [`conform::decide`] reads into a scratch root of this pass's own
//! under `target/`, or builds a throwaway checkout there, changes exactly one thing, and
//! drives the step's own entry points. Nothing under `xtask/src` is touched.
//!
//! The two subjects are the rules correction round 1 introduced: the `ess-inputs.yaml`
//! `scenarios:` reader that decides whether `--scenarios` is passed, and the `--release`
//! evidence rule that decides a tree on the store's journal and `git diff`.
#![allow(dead_code)] // the binary target uses the whole of each module; a case here uses part.
#[path = "../src/emit.rs"]
mod emit;

#[path = "../src/conform.rs"]
mod conform;

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_owned()
}

/// This pass's own scratch, so a fixture here cannot collide with one of `conform.rs`'s or
/// with pass 1's.
fn scratch() -> PathBuf {
    repo().join("target/xtask-conform-adversary2")
}

/// Everything the step reads from a root, copied into a scratch root of its own.
fn fixture(name: &str) -> PathBuf {
    let root = scratch().join(name);
    if root.exists() {
        fs::remove_dir_all(&root).expect("clear the fixture");
    }
    fs::create_dir_all(&root).expect("fixture root");
    for directory in [
        "systems/mandate",
        "generated/conformance",
        "generated/schema",
        "generated/coverage",
        "contracts",
    ] {
        copy(&repo().join(directory), &root.join(directory));
    }
    root
}

fn copy(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("fixture directory");
    for entry in fs::read_dir(from).expect("read the source directory") {
        let path = entry.expect("a source entry").path();
        let target = to.join(path.file_name().expect("a named entry"));
        if path.is_dir() {
            copy(&path, &target);
        } else {
            fs::copy(&path, &target).expect("copy a source file");
        }
    }
}

/// This workspace's stories, plus the two the ledger names that its store does not hold.
///
/// The same seam the unit's own cases pass, in a directory of this pass's own: a tree whose
/// store predates the stories its ledger names is what the seam is for, and no case here is
/// about that.
fn stories() -> PathBuf {
    let directory = scratch().join("story");
    if !directory.join("conform-gate.md").is_file() {
        copy(&repo().join(".engineering/planning/story"), &directory);
    }
    for name in [
        "ess-synthesizer-prerequisites",
        "conformance-denial-reasons",
    ] {
        fs::write(
            directory.join(format!("{name}.md")),
            format!(
                "---\nformat: aep.planning-md/1\nid: story:{name}\nkind: story\n\
                 status: draft\ntitle: {name}\nrevision: 1\n---\n"
            ),
        )
        .expect("write a fixture story");
    }
    directory
}

fn seams() -> conform::Seams {
    conform::Seams {
        stories: stories(),
        sources: repo(),
        doctor: None,
    }
}

/// The step's own answer for a root: the empty string when it accepted the tree.
fn refusal(root: &Path, release: bool) -> String {
    match conform::decide(root, release, &seams()) {
        Ok(_) => String::new(),
        Err(error) => error.to_string(),
    }
}

fn spec_digest(root: &Path) -> String {
    let suite: serde_json::Value = serde_json::from_slice(
        &fs::read(root.join("generated/conformance/suite.json")).expect("the fixture suite"),
    )
    .expect("the suite parses");
    suite["provenance"]["spec_digest"]
        .as_str()
        .expect("the suite states its specification digest")
        .to_owned()
}

/// Re-derive the coverage receipt's `source_digest` for a fixture whose sources were edited.
///
/// `cargo xtask generate` is what does this in a real tree, and a case that edits
/// `systems/mandate` without it would be refused for the receipt rather than for the thing it
/// is about. The framing is the step's own — each file's path relative to `systems/mandate`, a
/// NUL, its length, a NUL, its bytes, in sorted path order — so what this writes is what
/// `conform::sources` computes.
fn reseal_receipt(root: &Path) {
    let sources = root.join("systems/mandate");
    let mut files: Vec<PathBuf> = Vec::new();
    walk(&sources, &mut files);
    let mut framed: Vec<(String, Vec<u8>)> = files
        .into_iter()
        .map(|path| {
            let relative = path
                .strip_prefix(&sources)
                .expect("a source under systems/mandate")
                .to_string_lossy()
                .into_owned();
            (relative, fs::read(&path).expect("read a source"))
        })
        .collect();
    framed.sort_by(|left, right| left.0.cmp(&right.0));
    let mut canonical: Vec<u8> = Vec::new();
    for (path, bytes) in &framed {
        canonical.extend_from_slice(path.as_bytes());
        canonical.push(0);
        canonical.extend_from_slice(bytes.len().to_string().as_bytes());
        canonical.push(0);
        canonical.extend_from_slice(bytes);
    }
    let path = root.join("generated/coverage/receipt.json");
    let mut receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("the fixture receipt"))
            .expect("the receipt parses");
    receipt["source_digest"] = serde_json::Value::from(emit::digest(&canonical));
    fs::write(
        &path,
        serde_json::to_vec_pretty(&receipt).expect("render the receipt"),
    )
    .expect("write the fixture receipt");
}

fn walk(directory: &Path, into: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).expect("read a source directory") {
        let path = entry.expect("a source entry").path();
        if path.is_dir() {
            walk(&path, into);
        } else {
            into.push(path);
        }
    }
}

fn inputs(root: &Path) -> PathBuf {
    root.join("systems/mandate/ess-inputs.yaml")
}

/// `ess-inputs.yaml` carries `scenarios: []` today, and a comment is not data.
///
/// The step decides whether to pass `--scenarios` by scanning that file with `str` rather than
/// parsing it: the empty list is recognised only as the exact three characters `[]`. A comment
/// beside it — which is where the story that fills the list would say so — makes the scan
/// answer "this specification lists scenarios", the flag goes to a synthesizer that refuses it
/// against an empty list, nothing is written, and the gate refuses a tree whose specification
/// did not change. Measured beside this: `ess verify conform synthesize --suite-format 5`
/// writes a byte-identical suite for both files, so the specification really is the same one.
#[test]
fn a_comment_beside_the_empty_scenarios_list_is_not_a_scenario() {
    let root = fixture("commented-empty-list");
    let path = inputs(&root);
    let commented = fs::read_to_string(&path)
        .expect("the fixture inputs")
        .replace(
            "scenarios: []",
            "scenarios: []  # story:authored-denial-scenarios fills this",
        );
    assert!(
        commented.contains("# story:authored-denial-scenarios"),
        "the comment was written beside the empty list"
    );
    fs::write(&path, commented).expect("write the fixture inputs");
    reseal_receipt(&root);
    let refusal = refusal(&root, false);
    assert!(
        refusal.is_empty(),
        "`scenarios: []` and `scenarios: []  # …` are the same empty list — ESS synthesizes a \
         byte-identical suite from both — and the gate refuses the second one, because the \
         reader that decides `--scenarios` compares the text after the key with `[]` instead \
         of reading a list: {refusal}"
    );
}

/// The other side of the same reader: a comment inside the block hides the list from it.
///
/// This is `xtask/tests/conform.rs::the_specifications_scenario_list_is_read_when_it_is_not_empty`
/// with one comment line added above the item. The scan stops at the first line that is
/// neither indented nor an item, so a `#` at the left margin ends the list before it has read
/// one, `--scenarios` is dropped, and the authored file — unparseable, listed by the
/// specification, and therefore refused by any synthesis that read the list — never reaches
/// the corpus the gate compares. That is `review-result:wave-d-conform-gate-adversary-1` F2
/// again, behind a comment.
#[test]
fn a_comment_inside_the_scenarios_block_does_not_empty_the_list() {
    let root = fixture("commented-scenario-list");
    let scenarios = root.join("systems/mandate/scenarios");
    fs::create_dir_all(&scenarios).expect("the fixture scenarios directory");
    fs::write(
        scenarios.join("adversary.yaml"),
        "this is not a scenario: [\n",
    )
    .expect("write the fixture scenario");
    let path = inputs(&root);
    let listed = fs::read_to_string(&path)
        .expect("the fixture inputs")
        .replace(
            "scenarios: []",
            "scenarios:\n# story:authored-denial-scenarios fills this\n- scenarios/adversary.yaml",
        );
    assert!(
        listed.contains("- scenarios/adversary.yaml"),
        "the scenario file was listed in the specification's inputs"
    );
    fs::write(&path, listed).expect("write the fixture inputs");
    reseal_receipt(&root);
    let refusal = refusal(&root, false);
    assert!(
        refusal.contains("synthesize") || refusal.contains("suite.json"),
        "the specification lists a scenario file that cannot be parsed, and one comment line \
         above the item is enough for the gate to drop `--scenarios` and synthesize the \
         corpus without ever reading the list. What came back was: {refusal:?}"
    );
}

/// A throwaway checkout holding the three directories the `--release` rule names.
///
/// Its own repository, under `target/`, which the workspace ignores: a case about what
/// `git diff` sees must be able to move a working tree, and the tree under attack is not one
/// to move.
fn probe_checkout(name: &str) -> PathBuf {
    let root = scratch().join(name);
    if root.exists() {
        fs::remove_dir_all(&root).expect("clear the probe checkout");
    }
    for directory in [
        "crates/mandate-probe/src",
        "crates/mandate-probe/tests",
        "services/probe-service/src",
        "systems/probe",
    ] {
        fs::create_dir_all(root.join(directory)).expect("the probe checkout");
    }
    fs::write(
        root.join("crates/mandate-probe/src/lib.rs"),
        "#[must_use]\npub fn admits(token: &str) -> bool {\n    token == \"granted\"\n}\n",
    )
    .expect("write the probe implementation");
    fs::write(
        root.join("crates/mandate-probe/tests/admission.rs"),
        "#[test]\nfn a_granted_token_is_admitted() {\n    assert!(mandate_probe::admits(\"granted\"));\n}\n",
    )
    .expect("write the probe test");
    fs::write(
        root.join("services/probe-service/src/main.rs"),
        "fn main() {}\n",
    )
    .expect("write the probe service");
    fs::write(
        root.join("systems/probe/system.yaml"),
        "format: ess-system/1\nname: probe\n",
    )
    .expect("write the probe specification");
    let initialised = git(&root, &["init", "-q", "-b", "main"]);
    assert!(
        initialised.status.success(),
        "git init: {}",
        String::from_utf8_lossy(&initialised.stderr)
    );
    git(&root, &["add", "-A"]);
    let committed = git(
        &root,
        &[
            "commit",
            "-q",
            "-m",
            "the implementation the evidence was taken against",
        ],
    );
    assert!(
        committed.status.success(),
        "git commit: {}",
        String::from_utf8_lossy(&committed.stderr)
    );
    root
}

fn git(root: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .current_dir(root)
        .args([
            "-c",
            "user.name=adversary",
            "-c",
            "user.email=adversary@example.invalid",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .output()
        .expect("git")
}

fn head(root: &Path) -> String {
    String::from_utf8_lossy(&git(root, &["rev-parse", "HEAD"]).stdout)
        .trim()
        .to_owned()
}

/// The rule `--release` decides a tree on, run exactly as `conform::evidence` runs it after
/// correction round 2: the working tree first (F3), then the two commits, over the pathspec
/// that selects what `implementation_digest` digests (F4). `crates/*/src` alone selects
/// nothing in git, which is why each component ends in `/*`.
fn moved_since(root: &Path, commit: &str) -> Option<i32> {
    const IMPLEMENTATION: [&str; 3] = ["crates/*/src/*", "services/*/src/*", "systems"];
    let mut status = vec!["status", "--porcelain", "--"];
    status.extend(IMPLEMENTATION);
    let uncommitted = git(root, &status);
    if !String::from_utf8_lossy(&uncommitted.stdout)
        .trim()
        .is_empty()
    {
        return Some(1);
    }
    let mut diff = vec!["diff", "--quiet", commit, "HEAD", "--"];
    diff.extend(IMPLEMENTATION);
    git(root, &diff).status.code()
}

/// `--release` decides on two commits, and the implementation it blessed is a working tree.
///
/// Everything else in the step reads the working tree: `implementation_digest` digests
/// `crates/*/src`, `services/*/src` and `systems/` as they are on disk, the target is built
/// from the working tree and the report is that run's. The evidence rule alone compares
/// `<sha>` with `HEAD`, which are two commits — so an edit that never reached a commit moves
/// the implementation the gate just ran and does not move the answer, and the release is bound
/// to a commit whose sources are not the ones under test.
#[test]
fn the_release_rule_sees_an_implementation_that_never_reached_a_commit() {
    let root = probe_checkout("uncommitted-implementation");
    let recorded = head(&root);
    let taken_against =
        conform::implementation_digest(&root).expect("the probe checkout has an implementation");
    fs::write(
        root.join("crates/mandate-probe/src/lib.rs"),
        "#[must_use]\npub fn admits(_token: &str) -> bool {\n    true\n}\n",
    )
    .expect("move the working tree");
    let under_test =
        conform::implementation_digest(&root).expect("the probe checkout has an implementation");
    assert_ne!(
        taken_against, under_test,
        "the working tree the step digests and runs has moved"
    );
    assert_eq!(
        moved_since(&root, &recorded),
        Some(1),
        "the evidence was taken at {recorded} against implementation {taken_against}, the \
         implementation under test is {under_test}, and `git diff --quiet <sha> HEAD -- crates \
         services systems` reports no change — so `cargo xtask conform --release` binds this \
         wave's evidence to a commit that does not hold the sources it ran"
    );
}

/// `--release` refuses a commit the step's own digest calls the same implementation.
///
/// The step defines the implementation under test as `crates/*/src`, `services/*/src` and
/// `systems/` (`implementation_digest`), and the amended acceptance speaks of "an
/// implementation digest other than the tree's". The evidence rule holds the tree to
/// `crates services systems` whole — every test, every manifest, every README under them — so
/// a commit that adds a test case between the evidence run and the release check refuses a
/// release whose implementation digest, suite, report and ledgers are all unchanged.
#[test]
fn the_release_rule_holds_the_tree_to_more_than_the_implementation_it_digests() {
    let root = probe_checkout("test-only-commit");
    let recorded = head(&root);
    let taken_against =
        conform::implementation_digest(&root).expect("the probe checkout has an implementation");
    fs::write(
        root.join("crates/mandate-probe/tests/admission.rs"),
        "#[test]\nfn a_granted_token_is_admitted() {\n    assert!(mandate_probe::admits(\"granted\"));\n}\n\
         \n#[test]\nfn any_other_token_is_not() {\n    assert!(!mandate_probe::admits(\"revoked\"));\n}\n",
    )
    .expect("write a second probe test");
    git(&root, &["add", "-A"]);
    let committed = git(
        &root,
        &[
            "commit",
            "-q",
            "-m",
            "a second case for the same implementation",
        ],
    );
    assert!(
        committed.status.success(),
        "git commit: {}",
        String::from_utf8_lossy(&committed.stderr)
    );
    let under_test =
        conform::implementation_digest(&root).expect("the probe checkout has an implementation");
    assert_eq!(
        taken_against, under_test,
        "a test-only commit does not move the implementation digest"
    );
    assert_eq!(
        moved_since(&root, &recorded),
        Some(0),
        "nothing under crates/*/src, services/*/src or systems/ moved — the implementation \
         digest is {under_test} at both commits — and the evidence rule reports the \
         implementation moved, so `cargo xtask conform --release` refuses a release whose \
         report, suite, ledgers and implementation digest are all the ones the evidence was \
         taken against"
    );
}

/// The artifact and the journal as an AEP store holds them, with one line per record.
///
/// The shape is the store's own: `aep plan artifact set --model-digest` writes `model_digest:`
/// into the frontmatter, and `aep plan artifact evidence` appends an `aep.evidence.record/v1`
/// line carrying `{kind, reference, source}` under `args`.
fn write_store(root: &Path, model_digest: &str, records: &[(&str, String)]) {
    let planning = root.join(".engineering/planning");
    let directory = planning.join("executable-system-specification");
    fs::create_dir_all(&directory).expect("the fixture artifact directory");
    fs::write(
        directory.join("mandate.md"),
        format!(
            "---\nformat: aep.planning-md/1\nid: executable-system-specification:mandate\n\
             kind: executable-system-specification\nstatus: validated\n\
             title: The Mandate executable system specification\n\
             model_digest: {model_digest}\nrevision: 3\n---\n\n## Authority\n\n\
             The canonical source is `systems/mandate`.\n"
        ),
    )
    .expect("write the fixture artifact");
    let mut journal = String::new();
    for (revision, (kind, reference)) in records.iter().enumerate() {
        journal.push_str(&format!(
            "{{\"entity\":\"executable-system-specification\",\"id\":\"mandate\",\
             \"revision\":{},\"type\":\"aep.evidence.record/v1\",\
             \"args\":{{\"command\":\"record-evidence\",\"kind\":\"{kind}\",\
             \"reference\":\"{reference}\",\"source\":\"wave D\"}},\
             \"payload\":{{\"at\":178900000000{revision},\
             \"recorded_at\":\"2026-09-21T00:0{revision}:00Z\"}}}}\n",
            revision + 2
        ));
    }
    fs::write(planning.join("journal.jsonl"), journal).expect("write the fixture journal");
}

/// An approval is not a conformance run, and the release rule reads whichever came last.
///
/// `latest_evidence` matches an `aep.evidence.record/v1` line on the entity, the id and the
/// event type, and on nothing else — not on the `kind` the record carries. `aep plan artifact
/// evidence` takes `--kind` free and `--ref` on every kind (this store already holds nine
/// `approval` records carrying one), so a later record of any other kind supplies the commit
/// the release is decided on. Here the conformance evidence is a wave old and an approval
/// names the head: the run the release rests on was taken against sources that have since
/// moved, which is the one thing this check exists to refuse, and it is refused only while
/// nothing else was ever recorded about the artifact.
#[test]
fn an_approval_recorded_later_does_not_answer_for_the_conformance_evidence() {
    let root = fixture("masked-conformance-evidence");
    let stale = String::from_utf8_lossy(
        &Command::new("git")
            .current_dir(repo())
            .args(["rev-parse", "HEAD~1"])
            .output()
            .expect("git rev-parse HEAD~1")
            .stdout,
    )
    .trim()
    .to_owned();
    let current = String::from_utf8_lossy(
        &Command::new("git")
            .current_dir(repo())
            .args(["rev-parse", "HEAD"])
            .output()
            .expect("git rev-parse HEAD")
            .stdout,
    )
    .trim()
    .to_owned();
    write_store(
        &root,
        &spec_digest(&root),
        &[
            ("ess_conformance", format!("git:{stale}")),
            ("approval", format!("git:{current}")),
        ],
    );
    let refusal = refusal(&root, true);
    assert!(
        refusal.contains(&stale[..12]),
        "the only conformance evidence on this artifact was taken at {} and crates, services \
         or systems have moved since — the unit's own case proves the gate refuses exactly \
         that — and recording an approval afterwards is enough to make the release pass, \
         because the rule reads the latest record of any kind. What came back was: {refusal:?}",
        &stale[..12]
    );
}
