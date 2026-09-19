//! The mutation controls, decided against repositories small enough to be sure of.
//!
//! The step under test copies the tracked tree, applies a named patch, runs the killing target
//! the mutant declares, and asserts the declared failure. The catalogue itself — every mutant
//! under `tests/mutants/` applied to *this* tree and killed by the target it names — is run by
//! `cargo xtask mutants`, the last step of `check`, and it is not run again here: a case that
//! ran it too would state the same thing twice, pay for it twice, and leave two places to read
//! the table from. The step is the reading the gate takes.
//!
//! What this binary decides is the mechanism the step is made of, one piece per case: what the
//! anchor check accepts and refuses, where a patch lands as against where its header says it
//! lands, what the reused copy carries across and what it drops, and what a `check-fails` kill
//! is allowed to be. Each piece is decided on a repository this file builds under `target/`,
//! because a mechanism decided against 844 tracked files is decided against whatever those
//! files happen to be today. The cases that are about the committed catalogue read its files
//! and drive them through a fixture directory, because `tests/mutants/` holds only mutants that
//! must pass and the step reads every file it finds there.
//!
//! Every case takes [`SERIAL`] before it runs. The cases that drive `target/mutants` share one
//! scratch tree and one build directory, and `cargo test` runs the cases of a target on several
//! threads: without the lock a case would revert a file another case had just mutated.
#[allow(dead_code)] // the binary target uses the whole module; a case here uses part of it.
#[path = "../src/mutants.rs"]
mod mutants;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    sync::{Mutex, MutexGuard},
    time::Duration,
};

/// One case at a time: the scratch tree and its build directory are shared state.
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

/// The reused scratch root the cases that drive this checkout share, so one build directory
/// serves all of them.
fn work() -> PathBuf {
    repo().join("target/mutants")
}

/// A directory of this case's own, under `target/`, emptied first.
fn scratch(name: &str) -> PathBuf {
    let root = repo().join("target/xtask-mutants-cases").join(name);
    if root.exists() {
        fs::remove_dir_all(&root).expect("clear the scratch directory");
    }
    fs::create_dir_all(&root).expect("scratch directory");
    root
}

/// A catalogue of exactly the named mutants, written to its own directory under `target/`.
///
/// `tests/mutants/` is the committed catalogue and holds only mutants that must pass; a fixture
/// that must fail cannot live there, because the step reads every file it finds.
fn catalogue(name: &str, entries: &[(&str, &str, &str)]) -> PathBuf {
    let root = scratch(name);
    for (mutant, patch, json) in entries {
        fs::write(root.join(format!("{mutant}.patch")), patch).expect("fixture patch");
        fs::write(root.join(format!("{mutant}.json")), json).expect("fixture record");
    }
    root
}

fn committed(name: &str) -> String {
    fs::read_to_string(repo().join("tests/mutants").join(name)).expect("committed mutant")
}

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

/// A package name no workspace here resolves, so the killing run fails before it builds.
///
/// A case about what the step decides *before* it runs anything is a case that must not pay for
/// a build to say so. The step reaches the run either way; what it decided first is what its
/// refusal names.
const NO_SUCH_PACKAGE: &str = "a-package-no-workspace-here-resolves";

/// A record naming every field the step reads for a test kill.
fn record(package: &str, target: &str, test: &str, anchor: &str) -> String {
    format!(
        "{{\"crate\": \"{package}\", \"test_target\": \"{target}\", \"test\": \"{test}\", \
         \"kill\": \"test-fails\", \"anchor\": \"{anchor}\"}}\n"
    )
}

/// The twelve lines the toy repositories of the anchor cases are cut from.
const LETTERS: &str = "alpha\nbeta\ngamma\ndelta\nepsilon\nzeta\neta\ntheta\niota\nkappa\n\
                       lambda\nmu\n";

/// A repository tracking exactly `letters.txt`.
fn letters(name: &str) -> PathBuf {
    let source = scratch(name);
    fs::write(source.join("letters.txt"), LETTERS).expect("the tracked file");
    git(&source, &["init", "-q"]);
    git(&source, &["add", "-A"]);
    source
}

/// One hunk rewriting `kappa`, line 10, carrying lines 7 to 12 as its context.
const REWRITES_KAPPA: &str = "diff --git a/letters.txt b/letters.txt\n\
                              --- a/letters.txt\n+++ b/letters.txt\n\
                              @@ -7,6 +7,6 @@\n eta\n theta\n iota\n-kappa\n+KAPPA\n \
                              lambda\n mu\n";

/// One hunk inserting after `kappa`, line 10, and removing nothing at all.
const INSERTS_AFTER_KAPPA: &str = "diff --git a/letters.txt b/letters.txt\n\
                                   --- a/letters.txt\n+++ b/letters.txt\n\
                                   @@ -9,3 +9,4 @@\n iota\n kappa\n+KAPPA AND A HALF\n \
                                   lambda\n";

#[test]
fn a_patch_that_no_longer_applies_fails_the_step_by_name() {
    let _serial = serial();
    let drifted = committed("event-dropped.patch").replace(
        "-        self.events.push(event);",
        "-        self.events.push(event.clone());",
    );
    let root = catalogue(
        "anchor-moved",
        &[(
            "anchor-moved",
            &drifted,
            &committed("event-dropped.json").replace("event-dropped", "anchor-moved"),
        )],
    );

    let refused = mutants::catalogue(&repo(), &root, &work())
        .expect_err("a patch whose anchor has moved fails the step");

    let reported = refused.to_string();
    assert!(
        reported.contains("anchor-moved") && reported.contains("does not apply"),
        "the step names the mutant and why: {reported}"
    );
}

#[test]
fn a_mutant_naming_a_test_that_does_not_exist_fails_the_step_by_name() {
    let _serial = serial();
    let record = committed("event-dropped.json").replace(
        "increment_security_epoch_emits_exactly_the_declared_event",
        "a_test_this_target_has_never_had",
    );
    let root = catalogue(
        "renamed-killer",
        &[("renamed-killer", &committed("event-dropped.patch"), &record)],
    );

    let refused = mutants::catalogue(&repo(), &root, &work())
        .expect_err("a mutant naming a test the tree does not have fails the step");

    let reported = refused.to_string();
    assert!(
        reported.contains("renamed-killer")
            && reported.contains("a_test_this_target_has_never_had"),
        "the step names the mutant and the test it cannot find: {reported}"
    );
}

#[test]
fn a_patch_with_no_record_beside_it_fails_the_step() {
    let _serial = serial();
    let root = catalogue(
        "orphan",
        &[("orphan", &committed("event-dropped.patch"), "{}")],
    );
    fs::remove_file(root.join("orphan.json")).expect("drop the record");

    let refused = mutants::catalogue(&repo(), &root, &work())
        .expect_err("a patch no record names is a mutant that never runs");

    assert!(
        refused.to_string().contains("orphan"),
        "the step names the unread patch: {refused}"
    );
}

/// The anchor is the only part of a record no run reads, so it is the part that rots silently:
/// it is what the story, the table and a reader are given as the site of the fault.
#[test]
fn an_anchor_the_patch_does_not_touch_fails_the_step() {
    let _serial = serial();
    let patch = committed("event-dropped.patch");
    let record = committed("event-dropped.json");
    let elsewhere = catalogue(
        "anchor-elsewhere",
        &[(
            "anchor-elsewhere",
            &patch,
            &record.replace("port.rs:632", "port.rs:1"),
        )],
    );
    let other_file = catalogue(
        "anchor-other-file",
        &[(
            "anchor-other-file",
            &patch,
            &record.replace(
                "crates/mandate-identity/src/port.rs:632",
                "xtask/src/emit.rs:732",
            ),
        )],
    );

    let outside = mutants::catalogue(&repo(), &elsewhere, &work())
        .expect_err("an anchor outside every hunk fails the step");
    let unwritten = mutants::catalogue(&repo(), &other_file, &work())
        .expect_err("an anchor on a file the patch does not write fails the step");

    assert!(
        outside.to_string().contains("outside every hunk"),
        "the step says the anchor is not in the patch: {outside}"
    );
    assert!(
        unwritten
            .to_string()
            .contains("which the patch does not write"),
        "the step says the anchor names another file: {unwritten}"
    );
}

/// Falling somewhere inside a hunk is not enough to be the site of a fault. A hunk carries
/// three lines of context on each side, so a range check accepts a line the patch only reads —
/// the doc comment of the next function along, the field after the one that was deleted — and
/// the catalogue then points a reader at code the mutation never touched.
#[test]
fn an_anchor_a_hunk_only_carries_as_context_fails_the_step() {
    let _serial = serial();
    let source = letters("context-anchor-source");
    let context = catalogue(
        "context-anchor",
        &[(
            "context-anchor",
            REWRITES_KAPPA,
            &record(NO_SUCH_PACKAGE, "letters", "letters", "letters.txt:12"),
        )],
    );
    let rewritten = catalogue(
        "rewritten-anchor",
        &[(
            "rewritten-anchor",
            REWRITES_KAPPA,
            &record(NO_SUCH_PACKAGE, "letters", "letters", "letters.txt:10"),
        )],
    );

    let refused = mutants::catalogue(&source, &context, &scratch("context-anchor-work"))
        .expect_err("an anchor the hunk only carries as context fails the step");
    let taken = mutants::catalogue(&source, &rewritten, &scratch("rewritten-anchor-work"))
        .expect_err("no workspace here resolves the package the record names");

    assert!(
        refused.to_string().contains("outside every hunk"),
        "the hunk carries `mu` at line 12 as context and rewrites `kappa` at line 10; the step \
         took the record anyway: {refused}"
    );
    assert!(
        taken
            .to_string()
            .contains("does not build on the unmutated tree"),
        "the record anchoring the rewritten line reaches the killing run: {taken}"
    );
}

/// A hunk that only inserts removes no line at all, so the one line it can honestly be anchored
/// on is the line the insertion follows. The committed `ess-field-added` is exactly that shape.
#[test]
fn an_insertion_is_anchored_on_the_line_it_follows_and_on_no_other() {
    let _serial = serial();
    let source = letters("insertion-anchor-source");
    let follows = catalogue(
        "insertion-follows",
        &[(
            "insertion-follows",
            INSERTS_AFTER_KAPPA,
            &record(NO_SUCH_PACKAGE, "letters", "letters", "letters.txt:10"),
        )],
    );
    let after = catalogue(
        "insertion-after",
        &[(
            "insertion-after",
            INSERTS_AFTER_KAPPA,
            &record(NO_SUCH_PACKAGE, "letters", "letters", "letters.txt:11"),
        )],
    );

    let taken = mutants::catalogue(&source, &follows, &scratch("insertion-follows-work"))
        .expect_err("no workspace here resolves the package the record names");
    let refused = mutants::catalogue(&source, &after, &scratch("insertion-after-work"))
        .expect_err("an anchor the insertion does not follow fails the step");

    assert!(
        taken
            .to_string()
            .contains("does not build on the unmutated tree"),
        "the record anchoring `kappa`, the line the block is inserted after, reaches the \
         killing run: {taken}"
    );
    assert!(
        refused.to_string().contains("outside every hunk"),
        "the block is inserted after line 10 and the record anchors line 11, which the hunk \
         only carries as context; the step took the record anyway: {refused}"
    );
}

/// `git apply` does not apply a hunk where its header says. It searches the file for the hunk's
/// context and applies it wherever it finds it, at an offset, exiting 0 — so a header that has
/// drifted keeps applying, and the anchor decided against that header keeps agreeing with it.
/// The only thing that knows where the patch landed is the file afterwards.
#[test]
fn a_patch_that_lands_where_its_header_does_not_say_fails_the_step() {
    let _serial = serial();
    let source = letters("moved-header-source");
    // Exactly the hunk that rewrites `kappa` at line 10, with its header moved to line 2.
    let moved = REWRITES_KAPPA.replace("@@ -7,6 +7,6 @@", "@@ -2,6 +2,6 @@");
    let root = catalogue(
        "moved-header",
        &[(
            "moved-header",
            &moved,
            // Line 5 of the moved header's range is the line the header says is removed.
            &record(NO_SUCH_PACKAGE, "letters", "letters", "letters.txt:5"),
        )],
    );

    let refused = mutants::catalogue(&source, &root, &scratch("moved-header-work"))
        .expect_err("a patch that lands somewhere its header does not name fails the step");

    let reported = refused.to_string();
    assert!(
        reported.contains("outside every hunk"),
        "the header names line 5 and the patch rewrites line 10; the step took the record and \
         failed later, on the killing run, instead: {reported}"
    );
    assert!(
        reported.contains("letters.txt:5") && reported.contains("10"),
        "the refusal names the line the record anchors and the line the patch landed on: \
         {reported}"
    );
}

/// The copy is one reused directory. Nothing but `copy` writes the tracked tree into it, so
/// unless `copy` also takes files out, the directory is the union of every state the repository
/// has been in since it was made: a file a story deleted is still compiled, read and compared
/// there, for as long as the directory lives.
#[test]
fn a_file_the_repository_stops_tracking_leaves_the_reused_copy() {
    let _serial = serial();
    let source = scratch("retired-source");
    fs::write(source.join("letters.txt"), LETTERS).expect("a tracked file");
    fs::write(source.join("retired.txt"), "deleted by a later story\n").expect("a tracked file");
    git(&source, &["init", "-q"]);
    git(&source, &["add", "-A"]);
    let root = catalogue(
        "retired",
        &[(
            "retired",
            REWRITES_KAPPA,
            &record(NO_SUCH_PACKAGE, "letters", "letters", "letters.txt:10"),
        )],
    );
    let work = scratch("retired-work");

    let first = mutants::catalogue(&source, &root, &work);
    assert!(
        first.is_err(),
        "no workspace here resolves the package the record names"
    );
    assert!(
        work.join("tree/retired.txt").is_file(),
        "the first copy carries every tracked file"
    );
    // The copy's own `target/` is the build and scratch directory of the runs made inside it,
    // and nothing in it comes from the repository: it is the one thing a prune leaves alone.
    fs::create_dir_all(work.join("tree/target/debug")).expect("the copy's build directory");
    fs::write(work.join("tree/target/debug/built"), "an object").expect("a built object");

    fs::remove_file(source.join("retired.txt")).expect("a later story deletes the file");
    git(&source, &["add", "-A"]);
    let second = mutants::catalogue(&source, &root, &work);
    assert!(
        second.is_err(),
        "no workspace here resolves the package the record names"
    );

    assert!(
        !work.join("tree/retired.txt").exists(),
        "the reused copy still holds retired.txt, which the repository no longer tracks"
    );
    assert!(
        work.join("tree/target/debug/built").is_file(),
        "the copy's own target/ is not the repository's and survives the prune"
    );
    assert!(
        work.join("tree/letters.txt").is_file(),
        "the tracked file is still copied"
    );
}

/// `fs::write` creates a file 0644 whatever the source is, so a tracked file with the executable
/// bit loses it the first time it is copied and nothing restores it. The tree the mutants are
/// applied to would then not be the tree they are cut from — and this repository tracks a
/// script.
#[test]
fn the_copy_carries_the_mode_of_a_tracked_file() {
    let _serial = serial();
    let source = scratch("mode-source");
    let script = source.join("run.sh");
    fs::write(&script, "#!/bin/sh\necho one\necho two\n").expect("a tracked script");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("the executable bit");
    git(&source, &["init", "-q"]);
    git(&source, &["add", "-A"]);
    let root = catalogue(
        "mode",
        &[(
            "mode",
            "diff --git a/run.sh b/run.sh\n--- a/run.sh\n+++ b/run.sh\n\
             @@ -1,3 +1,3 @@\n #!/bin/sh\n-echo one\n+echo ONE\n echo two\n",
            &record(NO_SUCH_PACKAGE, "mode", "mode", "run.sh:2"),
        )],
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
    assert_eq!(
        copied & 0o777,
        0o755,
        "the repository tracks run.sh as 100755 and the copy is {:o}",
        copied & 0o777
    );
}

/// The toy step of the `check-fails` cases: one binary crate, tracked, whose `main` is the
/// `main` this case needs. A `check-fails` kill is the only one whose run is not a test, so the
/// only way to decide what it accepts is to give it a step that can fail in the way under test.
fn toy_step(name: &str, main: &str) -> PathBuf {
    let source = scratch(name);
    fs::create_dir_all(source.join("src")).expect("the crate source directory");
    fs::write(
        source.join("Cargo.toml"),
        "[workspace]\n[package]\nname = \"toy-step\"\nversion = \"0.0.0\"\n\
         edition = \"2021\"\npublish = false\n",
    )
    .expect("the toy manifest");
    fs::write(source.join("src/main.rs"), main).expect("the toy step");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let locked = Command::new(cargo)
        .args(["generate-lockfile", "--offline", "--manifest-path"])
        .arg(source.join("Cargo.toml"))
        .output()
        .expect("cargo runs");
    assert!(
        locked.status.success(),
        "the toy crate locks: {}",
        String::from_utf8_lossy(&locked.stderr)
    );
    git(&source, &["init", "-q"]);
    git(&source, &["add", "-A"]);
    source
}

/// A step that exits 0 as it stands and, once its constant is rewritten, exits non-zero saying
/// two different things — one of which is the fault a mutant would declare.
const TOY_STEP: &str = "fn main() {
    let contract = \"as declared\";
    if contract != \"as declared\" {
        eprintln!(\"the toy step read {contract}\");
        eprintln!(\"projection drift: run cargo xtask generate and review\");
        std::process::exit(1);
    }
    println!(\"the toy step is content\");
}
";

/// The patch that rewrites line 2 of a toy step, cut from the source it patches so it cannot
/// drift from it.
fn toy_patch(main: &str) -> String {
    let lines: Vec<&str> = main.lines().collect();
    format!(
        "diff --git a/src/main.rs b/src/main.rs\n--- a/src/main.rs\n+++ b/src/main.rs\n\
         @@ -1,4 +1,4 @@\n {}\n-{}\n+    let contract = \"renamed\";\n {}\n {}\n",
        lines[0], lines[1], lines[2], lines[3]
    )
}

/// A `check-fails` record, which states the refusal its step must print.
fn check(refusal: &str) -> String {
    check_at(refusal, "src/main.rs:2")
}

/// The same, anchored where the case needs it.
fn check_at(refusal: &str, anchor: &str) -> String {
    format!(
        "{{\"crate\": \"toy-step\", \"test_target\": \"check\", \"test\": \"check\", \
         \"kill\": \"check-fails\", \"refusal\": \"{refusal}\", \"anchor\": \"{anchor}\"}}\n"
    )
}

/// `check-fails` is the kill for a fault that changes nothing about what compiles, and a step
/// exits non-zero for every fault it has — a contract that stopped being YAML refuses at
/// validation, long before a single projection is read. An exit status alone therefore cannot
/// say the declared fault was the one found, so the record states the refusal and the step
/// requires it.
#[test]
fn a_check_fails_mutant_is_killed_by_the_refusal_it_declares_and_by_no_other() {
    let _serial = serial();
    let source = toy_step("check-source", TOY_STEP);
    let patch = toy_patch(TOY_STEP);
    let declared = catalogue(
        "check-declared",
        &[("check-declared", &patch, &check("projection drift"))],
    );
    let elsewhere = catalogue(
        "check-elsewhere",
        &[(
            "check-elsewhere",
            &patch,
            &check("a refusal it never prints"),
        )],
    );
    let silent = catalogue(
        "check-silent",
        &[(
            "check-silent",
            &patch,
            "{\"crate\": \"toy-step\", \"test_target\": \"check\", \"test\": \"check\", \
             \"kill\": \"check-fails\", \"anchor\": \"src/main.rs:2\"}\n",
        )],
    );
    let work = scratch("check-work");

    let killed = mutants::catalogue(&source, &declared, &work)
        .expect("the step refuses with the declared refusal, which is the kill");
    let other = mutants::catalogue(&source, &elsewhere, &work)
        .expect_err("a step that refused for another reason is not this mutant's kill");
    let unstated = mutants::catalogue(&source, &silent, &scratch("check-silent-work"))
        .expect_err("a check-fails record that states no refusal states no kill");

    assert!(
        killed.contains("projection drift: run cargo xtask generate and review"),
        "the table records the refusal the step printed, not the exit status:\n{killed}"
    );
    let other = other.to_string();
    assert!(
        other.contains("a refusal it never prints") && other.contains("the toy step read"),
        "the refusal names what was declared and what was observed: {other}"
    );
    assert!(
        unstated.to_string().contains("refusal"),
        "the step says a check-fails record has to state one: {unstated}"
    );
}

/// A hunk whose inserted line repeats the line beside it can be written down two ways that
/// produce the same file, and the two readings the step takes pick different ones: the patch
/// header describes the block as following one line, and the file it wrote is equally well
/// described as the block following the next. A duplicated statement is the standard mutation
/// operator for "this is done twice" — in this repository, redelivery — so a mutation of that
/// shape has to be enterable, and it is not enterable unless either reading is enough.
#[test]
fn a_hunk_that_duplicates_the_line_beside_it_is_anchored_by_either_reading() {
    let _serial = serial();
    let source = toy_step("slide-source", SLIDING_STEP);
    let work = scratch("slide-work");
    let header = catalogue(
        "slide-header",
        &[(
            "slide-header",
            SLIDES,
            &check_at("projection drift", "src/main.rs:2"),
        )],
    );
    let file = catalogue(
        "slide-file",
        &[(
            "slide-file",
            SLIDES,
            &check_at("projection drift", "src/main.rs:4"),
        )],
    );
    let between = catalogue(
        "slide-between",
        &[(
            "slide-between",
            SLIDES,
            &check_at("projection drift", "src/main.rs:3"),
        )],
    );

    let stated = mutants::catalogue(&source, &header, &work)
        .expect("the line the patch header says the block follows is an anchor");
    let written = mutants::catalogue(&source, &file, &work)
        .expect("the line the written file says the block follows is an anchor too");
    let neither = mutants::catalogue(&source, &between, &scratch("slide-between-work"))
        .expect_err("a line neither reading names is not an anchor");

    assert!(
        stated.contains("the toy step logged 4 entries"),
        "the mutant is killed by the refusal it declares:\n{stated}"
    );
    assert!(
        stated.contains("slides") && stated.contains("line 2") && stated.contains("line 4"),
        "the table says the two readings differ and by which lines, rather than one of them \
         being reported as the site of the fault:\n{stated}"
    );
    assert!(
        !stated.contains("drifted"),
        "the patch applied where its header says, so nothing claims it drifted:\n{stated}"
    );
    assert!(
        written.contains("the toy step logged 4 entries"),
        "the same mutant, anchored the other way, is killed the same way:\n{written}"
    );
    assert!(
        neither.to_string().contains("outside every hunk"),
        "line 3 is named by neither reading and is refused: {neither}"
    );
}

/// A line inserted at the top of a file follows no line. The line it *precedes* is line 1, and
/// that is the only line such a mutation can be anchored on: without it, a fault at the first
/// line of a file cannot be entered in the catalogue at all.
#[test]
fn an_insertion_before_the_first_line_is_anchored_on_the_line_it_precedes() {
    let _serial = serial();
    let source = letters("first-line-source");
    let first = catalogue(
        "first-line",
        &[(
            "first-line",
            INSERTS_BEFORE_ALPHA,
            &record(NO_SUCH_PACKAGE, "letters", "letters", "letters.txt:1"),
        )],
    );
    let second = catalogue(
        "second-line",
        &[(
            "second-line",
            INSERTS_BEFORE_ALPHA,
            &record(NO_SUCH_PACKAGE, "letters", "letters", "letters.txt:2"),
        )],
    );

    let taken = mutants::catalogue(&source, &first, &scratch("first-line-work"))
        .expect_err("no workspace here resolves the package the record names");
    let refused = mutants::catalogue(&source, &second, &scratch("second-line-work"))
        .expect_err("the line after the one the block precedes is not the site of anything");

    assert!(
        taken
            .to_string()
            .contains("does not build on the unmutated tree"),
        "the block is inserted before line 1 and the record anchors line 1, the line it \
         precedes; the step took the record: {taken}"
    );
    assert!(
        refused.to_string().contains("outside every hunk"),
        "line 2 is not the line the block precedes: {refused}"
    );
}

/// The declared refusal has to be found in what the *step* wrote. `cargo run -p <crate> --
/// <step>` echoes the command line it is about to exec before the step has said anything, and
/// that line carries the step's own name — so `contracts` as a declared refusal is satisfied by
/// cargo's progress output for a step that printed nothing at all.
#[test]
fn a_check_fails_kill_is_read_only_from_what_the_step_itself_wrote() {
    let _serial = serial();
    let source = toy_step("silent-source", SILENT_STEP);
    let root = catalogue(
        "silent",
        // `check` is the argument cargo is asked to pass the step, so it is also the last word
        // of the command line cargo echoes before the step runs.
        &[("silent", &toy_patch(SILENT_STEP), &check("check"))],
    );

    let refused = mutants::catalogue(&source, &root, &scratch("silent-work"))
        .expect_err("a step that exits non-zero printing nothing has refused nothing");

    let refused = refused.to_string();
    assert!(
        refused.contains("printed nothing"),
        "the step says the run said nothing, rather than reading cargo's own line as the \
         refusal: {refused}"
    );
}

/// The step refuses a `refusal` that no run would read, because a field no run reads is a claim
/// nothing decides. That is a rule about every key of a record, not about one of them: a record
/// is read field by field, and a key the step does not know — `refusals`, one letter from the
/// field it does read, or `expect`, which reads like a constraint and is not one — is the way
/// such a claim gets written down in the first place.
#[test]
fn a_record_that_states_a_field_no_run_reads_is_refused_by_name() {
    let _serial = serial();
    let root = catalogue(
        "unread-field",
        &[(
            "unread-field",
            REWRITES_KAPPA,
            "{\"crate\": \"a-package-no-workspace-here-resolves\", \
             \"test_target\": \"letters\", \"test\": \"letters\", \"kill\": \"test-fails\", \
             \"anchor\": \"letters.txt:10\", \"refusals\": \"projection drift\", \
             \"expect\": \"0 passed; 1 failed\"}\n",
        )],
    );

    let source = letters("unread-field-source");
    let refused = mutants::catalogue(&source, &root, &scratch("unread-field-work"))
        .expect_err("a record states the fields this step reads and no others");

    let refused = refused.to_string();
    assert!(
        refused.contains("refusals") && refused.contains("expect"),
        "the step names every key no run reads, not the first: {refused}"
    );
}

/// A killing run is a `cargo` invocation on a mutated tree, and a mutation can stop a run
/// ending: a loop whose exit condition the patch removed, a fold that no longer advances. With
/// no bound the gate stops, having said nothing, and the mutant that did it is not named.
#[test]
fn a_killing_run_that_does_not_end_is_refused_within_its_bound() {
    let _serial = serial();
    let source = toy_step("sleeping-source", SLEEPING_STEP);
    let root = catalogue(
        "sleeping",
        &[(
            "sleeping",
            &toy_patch(SLEEPING_STEP),
            &check("projection drift"),
        )],
    );

    let refused = mutants::bounded(
        &source,
        &root,
        &scratch("sleeping-work"),
        Duration::from_secs(3),
    )
    .expect_err("a run that outlives its bound is not a run that refused anything");

    let refused = refused.to_string();
    assert!(
        refused.contains("the killing run did not terminate"),
        "the step names what did not end: {refused}"
    );
    assert!(
        refused.contains("with the mutant applied") && refused.contains("sleeping"),
        "the step names the mutant and says the unmutated run had already ended: {refused}"
    );
}

/// A step whose `main` counts what it was given: it is content with three entries and refuses
/// with the declared refusal when it has more.
const SLIDING_STEP: &str = "fn main() {
    let mut log = Vec::new();
    log.push(1);
    log.push(1);
    log.push(2);
    if log.len() != 3 {
        eprintln!(\"projection drift: the toy step logged {} entries\", log.len());
        std::process::exit(1);
    }
    println!(\"the toy step is content\");
}
";

/// One statement duplicated, written as a hunk that inserts before the pair rather than after
/// it — which is what `git diff` writes, and which is what makes the block slidable.
const SLIDES: &str = "diff --git a/src/main.rs b/src/main.rs\n\
                      --- a/src/main.rs\n+++ b/src/main.rs\n\
                      @@ -2,4 +2,5 @@\n     let mut log = Vec::new();\n\
                      +    log.push(1);\n     log.push(1);\n     log.push(1);\n\
                      \x20    log.push(2);\n";

/// One hunk inserting before `alpha`, line 1, and removing nothing at all.
const INSERTS_BEFORE_ALPHA: &str = "diff --git a/letters.txt b/letters.txt\n\
                                    --- a/letters.txt\n+++ b/letters.txt\n\
                                    @@ -1,3 +1,4 @@\n+aleph\n alpha\n beta\n gamma\n";

/// A step that exits 0 as it stands and, once its constant is rewritten, exits non-zero having
/// written nothing at all.
const SILENT_STEP: &str = "fn main() {
    let contract = \"as declared\";
    if contract != \"as declared\" {
        std::process::exit(1);
    }
    println!(\"the toy step is content\");
}
";

/// A step that exits 0 as it stands and, once its constant is rewritten, does not end.
const SLEEPING_STEP: &str = "fn main() {
    let contract = \"as declared\";
    if contract != \"as declared\" {
        std::thread::sleep(std::time::Duration::from_secs(8));
    }
    println!(\"the toy step is content\");
}
";

#[test]
fn an_empty_catalogue_fails_the_step() {
    let _serial = serial();
    let root = catalogue("empty", &[]);

    let refused = mutants::catalogue(&repo(), &root, &work())
        .expect_err("a catalogue naming no mutant proves nothing");

    assert!(
        refused.to_string().contains("no mutant"),
        "the step says the catalogue is empty: {refused}"
    );
}
