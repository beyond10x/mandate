//! A second pass over the mutation controls, written to break them.
//!
//! The step under test is `xtask/src/mutants.rs`. Its own cases decide the catalogue it ships
//! with, and they decide it against the real tree; what they never reach is the mechanism
//! underneath. These cases go there: where a patch actually lands as against where its header
//! says it lands, what the anchor check is really deciding, what the reused scratch tree keeps
//! forever, what the copy does not carry across, and what a `check-fails` kill is allowed to be.
//!
//! Every case that needs a repository of its own builds one under `target/`, so nothing here
//! reads or writes the checkout. The one case that drives the committed scratch root drives it
//! exactly as `tests/mutants.rs` does, through `catalogue`, which reverts what it applies.
#[allow(dead_code)] // the binary target uses the whole module; a case here uses part of it.
#[path = "../src/mutants.rs"]
mod mutants;
// Coordinator amendment after pass 2: the five case names state the property each body asserts
// (correction round 1 made the bodies green); each doc comment below still describes the defect
// the case was written against.

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    sync::{Mutex, MutexGuard},
};

/// One case at a time: one of these drives the same scratch root the committed cases use.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_owned()
}

/// The reused scratch root the committed catalogue is driven against.
fn work() -> PathBuf {
    repo().join("target/mutants")
}

/// A directory of this case's own, under `target/`, emptied first.
fn scratch(name: &str) -> PathBuf {
    let root = repo().join("target/xtask-adversary-mutants-1").join(name);
    if root.exists() {
        fs::remove_dir_all(&root).expect("clear the scratch directory");
    }
    fs::create_dir_all(&root).expect("scratch directory");
    root
}

fn committed(name: &str) -> String {
    fs::read_to_string(repo().join("tests/mutants").join(name)).expect("committed mutant")
}

/// A record naming every field the step reads, so only the field under attack is in question.
fn record(package: &str, target: &str, test: &str, kill: &str, anchor: &str) -> String {
    format!(
        "{{\"crate\": \"{package}\", \"test_target\": \"{target}\", \"test\": \"{test}\", \
         \"kill\": \"{kill}\", \"anchor\": \"{anchor}\"}}\n"
    )
}

/// A catalogue of exactly the named mutants, in a directory of its own.
fn catalogue(name: &str, mutant: &str, patch: &str, json: &str) -> PathBuf {
    let root = scratch(name);
    fs::write(root.join(format!("{mutant}.patch")), patch).expect("fixture patch");
    fs::write(root.join(format!("{mutant}.json")), json).expect("fixture record");
    root
}

/// A package name no workspace here resolves, so the killing run fails before it builds.
///
/// Every case but the last is about what the step decides *before* it runs anything, and a run
/// that cannot start is how those cases stay under a second. The step reaches the run either
/// way, so what it decided first is what its refusal names.
const NO_SUCH_PACKAGE: &str = "a-package-no-workspace-here-resolves";

fn git(directory: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(args)
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?} in {}: {}",
        directory.display(),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The one-based number of the first line of `before` that `after` does not repeat.
fn first_difference(before: &str, after: &str) -> usize {
    before
        .lines()
        .zip(after.lines())
        .position(|(a, b)| a != b)
        .map_or(0, |index| index + 1)
}

/// `anchored` decides the record's anchor against the patch header's own line numbers. `git
/// apply` does not: it searches the file for the hunk's context and applies it wherever it
/// finds it, exiting 0. Nothing afterwards compares the two, so the header is free to name a
/// place the patch never touches, and the anchor check agrees with the header.
///
/// This is the rot the check exists to catch, seen from the side it cannot see. A hunk moves
/// when the code above it moves; the patch keeps applying, at an offset, and the header and the
/// anchor both stay where they were.
#[test]
fn a_patch_that_lands_away_from_its_header_is_refused() {
    let _serial = serial();
    // Exactly the committed mutant, with its hunk header moved 600 lines up the file.
    let moved = committed("deny-unknown-fields-removed.patch")
        .replace("@@ -729,7 +729,6 @@", "@@ -129,7 +129,6 @@");
    assert!(
        moved.contains("@@ -129,7 +129,6 @@"),
        "the committed header is the one this case moves:\n{moved}"
    );

    // What the step's own `apply` does with it: the same git invocation, against a tree holding
    // the one file the patch names.
    let landing = scratch("moved-header-landing");
    fs::create_dir_all(landing.join("xtask/src")).expect("the copied tree");
    let source = repo().join("xtask/src/emit.rs");
    fs::copy(&source, landing.join("xtask/src/emit.rs")).expect("the file the patch names");
    let written = repo()
        .join("target/xtask-adversary-mutants-1")
        .join("moved-header.patch");
    fs::write(&written, &moved).expect("the moved patch");
    let applied = Command::new("git")
        .arg("-C")
        .arg(repo())
        .args(["apply", "--unsafe-paths"])
        .arg(format!("--directory={}/", landing.display()))
        .arg(&written)
        .output()
        .expect("git apply runs");
    assert!(
        applied.status.success(),
        "git apply takes the moved patch: {}",
        String::from_utf8_lossy(&applied.stderr)
    );
    let landed = first_difference(
        &fs::read_to_string(&source).expect("the file the patch names"),
        &fs::read_to_string(landing.join("xtask/src/emit.rs")).expect("the copied file"),
    );

    // The record the step is handed: an anchor inside the moved header's range, 600 lines from
    // the line the patch rewrites.
    let root = catalogue(
        "moved-header",
        "moved-header",
        &moved,
        &record(
            NO_SUCH_PACKAGE,
            "emit",
            "the_emitted_text_of_each_kind_is_exactly_this",
            "test-fails",
            "xtask/src/emit.rs:132",
        ),
    );
    let refused = mutants::catalogue(&repo(), &root, &scratch("moved-header-work"))
        .expect_err("no workspace here resolves the package the record names");

    assert_eq!(
        landed, 732,
        "the moved patch still rewrites the line the committed one does"
    );
    assert!(
        refused.to_string().contains("outside every hunk"),
        "the record anchors xtask/src/emit.rs:132 and the patch rewrites line {landed}; the \
         step took the record and failed later, on the killing run, instead: {refused}"
    );
}

/// The anchor need only fall inside a hunk's pre-image *range*, and a hunk carries three lines
/// of context on each side. So a record may name a line the patch does not rewrite — here the
/// doc comment of the next function along — and the check agrees.
///
/// The committed catalogue already relies on the latitude: `ess-field-added` anchors
/// `systems/mandate/domains/credential.yaml:593`, a context line the patch only inserts after.
/// The step's own words for what it decides are "the record's anchor names a line this patch
/// actually rewrites".
#[test]
fn an_anchor_the_patch_does_not_rewrite_is_refused() {
    let _serial = serial();
    let port = fs::read_to_string(repo().join("crates/mandate-identity/src/port.rs"))
        .expect("the file the committed patch names");
    let line = port.lines().nth(634).expect("line 635").trim().to_owned();
    assert_eq!(
        line, "/// Why an event cannot be appended, if it cannot.",
        "line 635 is the doc comment of the function after the mutated one"
    );

    let root = catalogue(
        "comment-line",
        "comment-line",
        &committed("event-dropped.patch"),
        &record(
            NO_SUCH_PACKAGE,
            "emitted_events",
            "increment_security_epoch_emits_exactly_the_declared_event",
            "test-fails",
            "crates/mandate-identity/src/port.rs:635",
        ),
    );
    let refused = mutants::catalogue(&repo(), &root, &scratch("comment-line-work"))
        .expect_err("no workspace here resolves the package the record names");

    assert!(
        refused.to_string().contains("outside every hunk"),
        "the record anchors the fault on `{line}`, which the patch carries as context and does \
         not rewrite; the step took the record and failed later, on the killing run, instead: \
         {refused}"
    );
}

/// The copy is one reused directory, and `copy` only ever writes into it. Nothing removes a
/// file the repository has stopped tracking, so the reused tree is the union of every state the
/// repository has been in since the directory was made.
///
/// The committed scratch tree already shows it: it holds files under its own `target/` that no
/// run put there through `copy`, and they will not leave.
#[test]
fn the_reused_copy_drops_a_file_the_repository_no_longer_tracks() {
    let _serial = serial();
    let source = scratch("prune-source");
    fs::write(source.join("kept.txt"), "one\ntwo\nthree\nfour\n").expect("a tracked file");
    fs::write(source.join("retired.txt"), "deleted by a later story\n").expect("a tracked file");
    git(&source, &["init", "-q"]);
    git(&source, &["add", "-A"]);

    let root = catalogue(
        "prune",
        "kept",
        "diff --git a/kept.txt b/kept.txt\n--- a/kept.txt\n+++ b/kept.txt\n\
         @@ -1,3 +1,3 @@\n one\n-two\n+TWO\n three\n",
        &record(NO_SUCH_PACKAGE, "kept", "kept", "test-fails", "kept.txt:2"),
    );
    let work = scratch("prune-work");

    let first = mutants::catalogue(&source, &root, &work);
    assert!(
        first.is_err(),
        "no workspace here resolves the package the record names"
    );
    assert!(
        work.join("tree/retired.txt").is_file(),
        "the first copy carried both tracked files"
    );

    fs::remove_file(source.join("retired.txt")).expect("a later story deletes the file");
    git(&source, &["add", "-A"]);
    let second = mutants::catalogue(&source, &root, &work);
    assert!(
        second.is_err(),
        "no workspace here resolves the package the record names"
    );

    assert!(
        !work.join("tree/retired.txt").exists(),
        "the reused copy at {} still holds retired.txt, which the repository no longer tracks; \
         a file the tree has lost is compiled, read and compared in the copy for as long as the \
         directory lives",
        work.join("tree").display()
    );
}

/// `sync` writes bytes through `fs::write`, which creates a file 0644 whatever the source is.
/// So the copy the mutants are applied to is not the tracked tree: a tracked file with the
/// executable bit loses it the first time it is copied, and nothing restores it.
#[test]
fn the_copy_carries_the_mode_of_a_tracked_file() {
    let _serial = serial();
    let source = scratch("mode-source");
    let script = source.join("run.sh");
    fs::write(&script, "#!/bin/sh\necho one\necho two\n").expect("a tracked script");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("the executable bit");
    git(&source, &["init", "-q"]);
    git(&source, &["add", "-A"]);
    let listed = Command::new("git")
        .arg("-C")
        .arg(&source)
        .args(["ls-files", "-s"])
        .output()
        .expect("git ls-files runs");
    let listed = String::from_utf8_lossy(&listed.stdout).into_owned();
    assert!(
        listed.starts_with("100755 "),
        "the repository tracks the script as executable: {listed}"
    );

    let root = catalogue(
        "mode",
        "mode",
        "diff --git a/run.sh b/run.sh\n--- a/run.sh\n+++ b/run.sh\n\
         @@ -1,3 +1,3 @@\n #!/bin/sh\n-echo one\n+echo ONE\n echo two\n",
        &record(NO_SUCH_PACKAGE, "mode", "mode", "test-fails", "run.sh:2"),
    );
    let work = scratch("mode-work");
    let refused = mutants::catalogue(&source, &root, &work);
    assert!(
        refused.is_err(),
        "no workspace here resolves the package the record names"
    );

    let copied = fs::metadata(work.join("tree/run.sh"))
        .expect("the copied script")
        .permissions()
        .mode();
    assert!(
        copied & 0o111 != 0,
        "the repository tracks run.sh as 100755 and the copy is {:o}: the tree the mutants are \
         applied to is not the tree they are cut from",
        copied & 0o777
    );
}

/// `check-fails` is satisfied by the named step exiting non-zero, and by nothing else. The step
/// says of the three kill kinds that "each is asserted in its own terms rather than on the exit
/// status alone", and of this one that the fault "shows as projection drift".
///
/// It does not. `contracts` runs `ess specify validate` first and compares projections after, so
/// a patch that breaks the contract file as YAML refuses before a single projection is read —
/// and the step records that refusal as the kill, for a mutant declaring a drift it never
/// reached. The two committed ESS mutants are killed by drift today; nothing here says the
/// eleventh will be.
#[test]
fn a_check_fails_mutant_is_killed_only_by_the_refusal_it_declares() {
    let _serial = serial();
    let contract = repo().join("systems/mandate/domains/credential.yaml");
    let body = fs::read_to_string(&contract).expect("the contract the ESS mutants are cut from");
    let lines: Vec<&str> = body.lines().collect();
    let mut patch = String::new();
    patch.push_str("diff --git a/systems/mandate/domains/credential.yaml ");
    patch.push_str("b/systems/mandate/domains/credential.yaml\n");
    patch.push_str("--- a/systems/mandate/domains/credential.yaml\n");
    patch.push_str("+++ b/systems/mandate/domains/credential.yaml\n");
    patch.push_str("@@ -591,6 +591,7 @@ events:\n");
    for number in 591..=596 {
        patch.push(' ');
        patch.push_str(lines[number - 1]);
        patch.push('\n');
        if number == 593 {
            // A flow sequence that is never closed: the file stops being YAML.
            patch.push_str("+      - name: [\n");
        }
    }

    let root = catalogue(
        "contract-unparseable",
        "contract-unparseable",
        &patch,
        &record(
            "xtask",
            "contracts",
            "contracts",
            "check-fails",
            "systems/mandate/domains/credential.yaml:593",
        ),
    );
    let reported = mutants::catalogue(&repo(), &root, &work());

    assert!(
        reported.is_err(),
        "the mutant declares the drift kill of `ess-field-added` and `ess-field-removed`, and \
         `contracts` never reached a projection: it refused at `ess specify validate`. The step \
         recorded it as a kill anyway:\n{}",
        reported.unwrap_or_default()
    );
}
