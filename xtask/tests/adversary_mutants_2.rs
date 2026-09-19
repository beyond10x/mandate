//! Second adversarial pass on the mutation controls, against the corrected mechanism.
//!
//! Correction round 1 added two readings of "the line this patch rewrites". [`anchored`] takes
//! one from the patch's own hunk headers before anything runs; `apply` takes another from the
//! file `git apply` wrote, by trimming the common prefix and suffix and running an LCS over what
//! is left. A record is admitted only if its anchor is in *both* sets. Nothing compares the two
//! sets with each other, and for a patch whose change is slidable — an inserted line that
//! repeats the line beside it — they are not the same set. These cases drive that, the reused
//! copy's behaviour when a tracked path changes kind, and what a `check-fails` kill is allowed
//! to be read from.
//!
//! Every case builds its own repository under `target/` and drives `mutants::catalogue` against
//! it, so nothing here depends on what this tree's 844 tracked files happen to be today.
#[allow(dead_code)] // the binary target uses the whole module; a case here uses part of it.
#[path = "../src/mutants.rs"]
mod mutants;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_owned()
}

/// A directory of this case's own, under `target/`, emptied first.
fn scratch(name: &str) -> PathBuf {
    let root = repo().join("target/xtask-adversary-mutants-2").join(name);
    if root.exists() {
        fs::remove_dir_all(&root).expect("clear the scratch directory");
    }
    fs::create_dir_all(&root).expect("scratch directory");
    root
}

/// A catalogue of exactly one mutant, in a directory of its own.
fn catalogue(name: &str, patch: &str, json: &str) -> PathBuf {
    let root = scratch(name);
    fs::write(root.join(format!("{name}.patch")), patch).expect("fixture patch");
    fs::write(root.join(format!("{name}.json")), json).expect("fixture record");
    root
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
/// Every case about what the step decides *before* it runs anything uses it: the step reaches
/// the killing run either way, and this is what its refusal says once it has.
const NO_SUCH_PACKAGE: &str = "a-package-no-workspace-here-resolves";

/// What the step says when a record was admitted and the killing run is the thing that failed.
const REACHED_THE_RUN: &str = "does not build on the unmutated tree";

/// A record naming every field the step reads for a test kill.
fn record(target: &str, anchor: &str) -> String {
    format!(
        "{{\"crate\": \"{NO_SUCH_PACKAGE}\", \"test_target\": \"{target}\", \
         \"test\": \"{target}\", \"kill\": \"test-fails\", \"anchor\": \"{anchor}\"}}\n"
    )
}

/// What the step made of a catalogue, either way, as one line of a report.
fn said(result: Result<String, Box<dyn std::error::Error>>) -> String {
    match result {
        Ok(table) => format!("ACCEPTED: {}", table.replace('\n', " / ")),
        Err(refused) => refused.to_string(),
    }
}

/// The patch `git diff` itself writes for an edit, with the tracked state left as it was.
///
/// Nothing here is hand-written: the patch is the one the tool that generates every committed
/// mutant produces, applied by the tool that applies every committed mutant.
fn generated_patch(source: &Path, file: &str, before: &str, after: &str) -> String {
    fs::write(source.join(file), before).expect("the tracked file");
    git(source, &["add", "-A"]);
    fs::write(source.join(file), after).expect("the edited file");
    let out = Command::new("git")
        .arg("-C")
        .arg(source)
        .args(["diff", "-U3", "--", file])
        .output()
        .expect("git diff runs");
    assert!(out.status.success(), "git diff answers");
    fs::write(source.join(file), before).expect("the tracked state is what the mutant is cut of");
    let patch = String::from_utf8(out.stdout).expect("a patch is text");
    assert!(patch.contains("@@ "), "git diff wrote a hunk:\n{patch}");
    patch
}

/// A repository of one file, tracking exactly it.
fn repository(name: &str, file: &str, body: &str) -> PathBuf {
    let source = scratch(name);
    fs::write(source.join(file), body).expect("the tracked file");
    git(&source, &["init", "-q"]);
    git(&source, &["add", "-A"]);
    source
}

/// Every line of the patched file, tried in turn as the record's anchor, and what the step made
/// of each.
///
/// A mutant has to declare one anchor. If no line of the file is a line the step will accept,
/// the mutation cannot be entered in the catalogue at all — whatever the fault it names.
fn every_anchor(case: &str, source: &Path, patch: &str, file: &str, lines: usize) -> Vec<String> {
    (1..=lines)
        .map(|line| {
            let name = format!("{case}-{line}");
            let root = catalogue(&name, patch, &record("killer", &format!("{file}:{line}")));
            let reported = said(mutants::catalogue(
                source,
                &root,
                &scratch(&format!("{name}-work")),
            ));
            format!("  anchor {file}:{line} — {reported}")
        })
        .collect()
}

/// The six lines a duplicated-statement mutation is cut from: the shape of "the event is
/// delivered twice", which is the fault `redelivery-refused` exists for.
const APPEND: &str = "// the store append path\n//\nfn append(event: Event) {\n    \
                      emit(event);\n    commit();\n}\n";

/// The same, with the emit duplicated: one line inserted, repeating the line it lands beside.
const APPEND_TWICE: &str = "// the store append path\n//\nfn append(event: Event) {\n    \
                            emit(event);\n    emit(event);\n    commit();\n}\n";

/// A mutation `git diff` writes, `git apply` applies where its header says, and the step refuses
/// under every anchor it could be given.
///
/// The inserted line repeats the line beside it, so the block slides: the hunk header describes
/// the insertion as following one line, and the file afterwards is equally well described as the
/// insertion following the next. `anchored` reads the header and demands the first. `apply`
/// trims the common prefix off the written file and demands the second. Nothing reconciles them,
/// so the record that satisfies the first is refused by the second — and the refusal says the
/// patch drifted, which it did not.
///
/// A statement duplicated is the standard mutation operator for "this is done twice"; in this
/// repository that is redelivery, which `services/sts/tests/store.rs` exists to refuse.
#[test]
fn a_mutation_that_duplicates_the_line_beside_it_can_be_anchored_on_no_line_at_all() {
    let source = repository("duplicate-source", "append.rs", APPEND);
    let patch = generated_patch(&source, "append.rs", APPEND, APPEND_TWICE);

    let reported = every_anchor("duplicate", &source, &patch, "append.rs", 6);

    assert!(
        reported.iter().any(|line| line.contains(REACHED_THE_RUN)),
        "`git diff` wrote this patch and `git apply` applies it where its header says, and no \
         line of the file is an anchor the step will take: the header's reading and the written \
         file's reading of the same insertion are different lines, so the record that passes \
         `anchored` is refused by `apply` as having drifted. The patch:\n{patch}\nWhat the step \
         said of each anchor:\n{}",
        reported.join("\n")
    );
}

/// A line inserted at the top of a file follows no line, so the step's reading of "the line the
/// insertion follows" has nothing to name — and both readings agree there is nothing, which
/// leaves the mutation inexpressible rather than mis-anchored.
///
/// The first line of a file is a line like any other, and a mutation that puts something before
/// it is one a catalogue should be able to state.
#[test]
fn a_mutation_that_inserts_before_the_first_line_can_be_anchored_on_no_line_at_all() {
    let before = "alpha\nbeta\ngamma\ndelta\n";
    let after = "#![allow(clippy::all)]\nalpha\nbeta\ngamma\ndelta\n";
    let source = repository("first-line-source", "top.rs", before);
    let patch = generated_patch(&source, "top.rs", before, after);

    let reported = every_anchor("first-line", &source, &patch, "top.rs", 4);

    assert!(
        reported.iter().any(|line| line.contains(REACHED_THE_RUN)),
        "the patch inserts a line before line 1 and the step takes no anchor for it, so this \
         mutation cannot be entered in the catalogue. The patch:\n{patch}\nWhat the step said \
         of each anchor:\n{}",
        reported.join("\n")
    );
}

/// A step that exits 0 as it stands and, once its constant is rewritten, exits non-zero saying
/// nothing whatever.
///
/// The failure is real and it is not the declared one; the point is that the declared one is
/// found anyway, in text this program never wrote.
const SILENT_STEP: &str = "fn main() {
    let contract = \"as declared\";
    if contract != \"as declared\" {
        std::process::exit(1);
    }
    println!(\"the toy step is content\");
}
";

/// The patch that rewrites the toy step's constant, cut from the source it patches.
fn silent_patch() -> String {
    let lines: Vec<&str> = SILENT_STEP.lines().collect();
    format!(
        "diff --git a/src/main.rs b/src/main.rs\n--- a/src/main.rs\n+++ b/src/main.rs\n\
         @@ -1,4 +1,4 @@\n {}\n-{}\n+    let contract = \"renamed\";\n {}\n {}\n",
        lines[0], lines[1], lines[2], lines[3]
    )
}

/// A crate of one binary, tracked and locked, whose `main` is [`SILENT_STEP`].
fn toy_step(name: &str) -> PathBuf {
    let source = scratch(name);
    fs::create_dir_all(source.join("src")).expect("the crate source directory");
    fs::write(
        source.join("Cargo.toml"),
        "[workspace]\n[package]\nname = \"toy-step\"\nversion = \"0.0.0\"\n\
         edition = \"2021\"\npublish = false\n",
    )
    .expect("the toy manifest");
    fs::write(source.join("src/main.rs"), SILENT_STEP).expect("the toy step");
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

/// The declared refusal is looked for in every line of the run's standard error, and cargo
/// writes lines there too.
///
/// `cargo run -p <crate> -- <step>` echoes `Running \`…/<crate> <step>\`` before the step has
/// said anything at all, so a refusal naming the step — `contracts` for the two committed ESS
/// mutants — is carried by a line cargo wrote. The step then reports a kill for a fault nothing
/// found, and the table's "observed failure" cell quotes cargo's own progress line as the
/// refusal. The correction of round 1 was that "an exit status alone does not say the declared
/// fault was the one found"; this is the exit status with one more step.
#[test]
fn a_check_fails_kill_is_taken_from_a_line_cargo_wrote_and_not_from_the_step() {
    let source = toy_step("cargo-said-it-source");
    let root = catalogue(
        "cargo-said-it",
        &silent_patch(),
        // `test_target` is the argument cargo is asked to pass the step, so it is also the last
        // word of the command line cargo echoes.
        "{\"crate\": \"toy-step\", \"test_target\": \"contracts\", \"test\": \"contracts\", \
         \"kill\": \"check-fails\", \"refusal\": \"contracts\", \"anchor\": \"src/main.rs:2\"}\n",
    );

    let reported = mutants::catalogue(&source, &root, &scratch("cargo-said-it-work"));

    assert!(
        reported.is_err(),
        "the mutated step exited non-zero and printed nothing; the declared refusal was found \
         in a line cargo wrote before the step ran, and the step recorded it as the kill:\n{}",
        said(reported)
    );
}

/// The reused copy is written into and never cleared, and a tracked path that changes kind —
/// `store.rs` becoming `store/mod.rs`, the most ordinary refactor there is — leaves a file
/// where the next copy needs a directory.
///
/// `copy` syncs every tracked path first and prunes what is left over afterwards, so the prune
/// that would have removed the stale file never runs: `create_dir_all` refuses, the step fails
/// with a bare `File exists (os error 17)` naming neither the path nor the mutant, and it goes
/// on failing on every later run until someone deletes `target/mutants/tree` by hand.
#[test]
fn a_tracked_file_that_becomes_a_directory_wedges_the_reused_copy() {
    let source = scratch("kind-change-source");
    fs::write(source.join("letters.txt"), "alpha\nbeta\ngamma\ndelta\n").expect("a tracked file");
    fs::write(source.join("store.rs"), "one\ntwo\nthree\n").expect("a tracked file");
    git(&source, &["init", "-q"]);
    git(&source, &["add", "-A"]);
    let root = catalogue(
        "kind-change",
        "diff --git a/letters.txt b/letters.txt\n--- a/letters.txt\n+++ b/letters.txt\n\
         @@ -1,4 +1,4 @@\n alpha\n-beta\n+BETA\n gamma\n delta\n",
        &record("letters", "letters.txt:2"),
    );
    let work = scratch("kind-change-work");

    let first = said(mutants::catalogue(&source, &root, &work));
    assert!(
        first.contains(REACHED_THE_RUN),
        "the first run reaches the killing run, which no workspace here resolves: {first}"
    );
    assert!(
        work.join("tree/store.rs").is_file(),
        "the first copy carries the tracked file"
    );

    // A later story turns the module into a directory. Nothing else about the tree changes.
    fs::remove_file(source.join("store.rs")).expect("the module moves");
    fs::create_dir(source.join("store")).expect("the module directory");
    fs::write(source.join("store/mod.rs"), "one\ntwo\nthree\n").expect("the moved module");
    git(&source, &["add", "-A"]);

    let second = said(mutants::catalogue(&source, &root, &work));

    assert!(
        work.join("tree/store/mod.rs").is_file(),
        "the reused copy does not hold the tracked module after the rename, and the step said: \
         {second}"
    );
}

/// The step refuses a `refusal` on a record no run reads it for, saying that "a field no run
/// reads is a claim nothing decides". It applies that to exactly one field name.
///
/// Every other key is dropped in silence — including a key one letter from one the step does
/// read, which is how the claim gets into a record in the first place. The catalogue's own
/// `deny-unknown-fields-removed` mutant exists to prove this repository's emitter refuses an
/// unknown field; the records that drive it are parsed with unknown fields allowed.
#[test]
fn a_record_may_carry_a_field_no_run_reads_as_long_as_it_is_not_that_one_field() {
    let source = repository(
        "unread-field-source",
        "letters.txt",
        "alpha\nbeta\ngamma\ndelta\n",
    );
    let root = catalogue(
        "unread-field",
        "diff --git a/letters.txt b/letters.txt\n--- a/letters.txt\n+++ b/letters.txt\n\
         @@ -1,4 +1,4 @@\n alpha\n-beta\n+BETA\n gamma\n delta\n",
        // `refusals`, one letter from the field the step reads, plus a claim about the run that
        // reads like a constraint and is not one.
        "{\"crate\": \"a-package-no-workspace-here-resolves\", \"test_target\": \"letters\", \
         \"test\": \"letters\", \"kill\": \"test-fails\", \"anchor\": \"letters.txt:2\", \
         \"refusals\": \"projection drift\", \"expect\": \"0 passed; 1 failed\"}\n",
    );

    let reported = said(mutants::catalogue(
        &source,
        &root,
        &scratch("unread-field-work"),
    ));

    assert!(
        reported.contains("refusals") || reported.contains("expect"),
        "the record states two things no run reads — `refusals`, which is `refusal` \
         misspelled, and `expect` — and the step took it without a word: {reported}"
    );
}
