//! Named mutation controls: each protection is shown to detect the fault it exists for.
//!
//! Every other step of the gate answers "is the tree as it should be". None of them answers
//! "would the suite notice if it were not", and a suite that cannot fail is indistinguishable
//! from one that passes. This step closes that: a catalogue of named faults, each with the test
//! that must refuse it, applied to a copy of this tree and run.
//!
//! A mutant is two files under `tests/mutants/`. `<name>.patch` is a unified diff against the
//! tracked tree; `<name>.json` states the run that must refuse it:
//!
//! ```json
//! { "crate": "mandate-identity", "test_target": "emitted_events",
//!   "test": "increment_security_epoch_emits_exactly_the_declared_event",
//!   "kill": "test-fails", "anchor": "crates/mandate-identity/src/port.rs:632" }
//! ```
//!
//! Those are the fields the step reads, and a record states them and nothing else: a key this
//! step does not read is refused by name, because a claim written into a record that no run
//! looks at is a claim nothing decides — and the way one gets written is a near miss, `refusals`
//! for `refusal`, or a constraint that reads like one and is not taken.
//!
//! `anchor` is the site of the fault, as the catalogue, the table and the story give it. It is
//! required to be a line the patch *rewrites*: one a hunk removes, or, where a hunk only
//! inserts, the line the insertion follows — or, for a block inserted before the first line of
//! the file, line 1, the line it precedes. A line the hunk merely carries as context is not the
//! site of anything.
//!
//! There are two readings of that, and the step takes both. The patch's own hunk headers say
//! which line a hunk rewrites; the file the patch wrote says which line changed. For most
//! patches these are the same line. For a *slidable* change they are not: a line inserted
//! beside its own twin — which is what a duplicated statement is, and a duplicated statement is
//! the standard mutation for "this is done twice" — can be written down as following either
//! twin, and both descriptions produce the same file. So either reading is enough to anchor a
//! mutant, and where the two differ the table's row says so rather than picking one.
//!
//! `kill` is one of three, and each is asserted in its own terms rather than on the exit status
//! alone — an exit status cannot tell a killed mutant from a mutant that did not compile:
//!
//! * `test-fails` — `cargo test -p <crate> --test <test_target> -- --exact <test>` runs the named
//!   test and it fails. The summary must read `0 passed; 1 failed`: a build that broke is not a
//!   kill, and it is reported as its own failure.
//! * `compile-fails` — the same command fails to compile, and prints no test summary at all.
//! * `check-fails` — `cargo run -p <crate> -- <test_target>` (the xtask step of that name) fails,
//!   *and says the thing the record declares*. This is the kill for a mutation of the ESS
//!   contract, where nothing compiles differently and the fault shows as projection drift, so
//!   the record carries a fourth field:
//!
//!   ```json
//!   { "crate": "xtask", "test_target": "contracts", "test": "contracts",
//!     "kill": "check-fails", "refusal": "projection drift",
//!     "anchor": "systems/mandate/domains/credential.yaml:593" }
//!   ```
//!
//!   `refusal` is a substring the step's output must carry, and it is required, because a step
//!   exits non-zero for every fault it has and not only for the declared one. `contracts` runs
//!   `ess specify validate` before it compares a single projection: a patch that breaks the
//!   contract file as YAML refuses there, having never reached a projection, and an exit status
//!   alone would record that as the drift kill. Any other non-zero exit is refused, with what
//!   the step actually said.
//!
//!   It is looked for in what the *step* wrote and nowhere else. `cargo run -p <crate> --
//!   <step>` echoes ``Running `<binary> <step>` `` to the same stream before the step has said
//!   anything, and that line carries the step's own name — so `contracts` as a declared refusal
//!   is otherwise satisfied by cargo's progress output for a step that printed nothing at all.
//!   Only what follows the last such line is read, and a step that printed nothing has not
//!   refused anything.
//!
//! # What this step does not trust
//!
//! **A `git apply` that exits 0 need not have applied anything.** Run with the copy as the
//! working directory, `git` finds the enclosing repository, decides the patch's paths are not
//! the ones it was asked about, prints `Skipped patch '<file>'` and exits **0** — measured here,
//! 2026-09-19. So the patch is applied from the repository root with `--unsafe-paths
//! --directory=<copy>/`, and every file the patch names is then compared against the source: a
//! patch that changed nothing is a mutant that proved nothing, and it fails the step.
//!
//! **A `git apply` that exits 0 need not have applied the patch where its header says.** It
//! searches the file for the hunk's context and applies it wherever it finds it, at an offset,
//! exiting 0. So a header that drifted when the code above it moved keeps applying, and the
//! anchor — decided against that header — keeps agreeing with it, while the table reports a
//! site the patch no longer touches. What tells a patch that drifted from one that did not is
//! the source itself: every hunk's pre-image has to be at the line its header names. Where it
//! is, the patch applied there, and the two readings of what it rewrote are the same edit
//! written down two ways. Where it is not, the header describes a file this is no longer, and
//! only the file the patch actually wrote is read. Every patch in the catalogue is applied,
//! read and reverted once before anything is built: a tenth patch that lands in the wrong place
//! says so in a second, not after nine builds.
//!
//! **A run that has not finished need not be a run that is going to.** A mutation can stop a
//! run ending — a loop whose exit condition the patch removed, a fold that no longer advances —
//! and `Command::output` waits for ever. The gate then stops, having said nothing and named
//! nobody, and the one fact worth having (which mutant did it) is the one that is lost. So each
//! run is spawned, polled, and killed once its bound has passed: ten minutes by default, and
//! whatever [`bounded`] is given otherwise.
//!
//! **A file restored with its original timestamp is not restored as far as cargo is concerned.**
//! Reverting with `cp -p` left the mutant's object in the build directory and the next run of
//! that target re-ran the *mutated* binary and reported it green — measured here, same day. So
//! every write in this step goes through [`sync`], which writes the bytes fresh and therefore
//! stamps the file with the current time; and the file is only written when the bytes differ, so
//! the 844 tracked files that did not change keep their timestamps and their build.
//!
//! **A green run of the killing test is not evidence unless it was green before.** Each mutant is
//! run twice: once on the clean copy, which must pass and must report exactly one test selected,
//! and once mutated. The clean run is what makes the second one mean the mutation; it is also
//! how a mutant naming a test the tree no longer has is caught, because `--exact` on a name that
//! does not exist selects nothing and `cargo test` exits 0.
//!
//! # Retirement
//!
//! A mutant outlives the code it is anchored on only as a gate failure. `deny-unknown-fields-
//! removed` is anchored on this repository's own ESS emitter, which `initiative:drift-
//! enforcement` retires at the E4 close once the ESS release's outputs match: the mutant is
//! removed with it, and the two files are deleted together rather than re-anchored.
//!
//! # The copy
//!
//! `git ls-files` decides what is copied — not the tree walk `main.rs` uses for generated
//! output, which skips only `.ess-output` and would copy `target/`. The copy is reused across
//! runs at `target/mutants/tree`, and the builds it runs go to `target/mutants/target`: a path
//! package's id carries its manifest directory, so the copy's crates get their own fingerprints
//! there while every external dependency is compiled once and reused by all ten mutants.
//!
//! Because the directory is reused, `copy` also takes files *out* of it: a path the repository
//! no longer tracks is removed, or the copy would be the union of every state this repository
//! has been in since the directory was made, and a file a story deleted would go on being
//! compiled, read and compared there. The copy's own `target/` is the exception — it is the
//! build and scratch directory of the runs made inside the copy, and nothing in it came from
//! the repository.
use serde_json::Value;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs,
    path::{Component, Path, PathBuf},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

/// What a killing run is given before it is treated as a run that will not end.
const BOUND: Duration = Duration::from_secs(600);
/// How often a running one is asked whether it has finished.
const POLL: Duration = Duration::from_millis(50);
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// How a mutant is shown to be refused.
enum Kill {
    /// The named test runs and fails.
    Test,
    /// The named target no longer compiles.
    Compile,
    /// The named xtask step refuses the tree, saying this.
    Check(String),
}

impl Kill {
    fn parse(declared: &str, refusal: Option<&str>, name: &str) -> Result<Self> {
        let unread = |kind: &str| -> Result<()> {
            match refusal {
                None => Ok(()),
                Some(_) => Err(format!(
                    "{name}: declares {kind} and states a refusal, which only a check-fails \
                     mutant is read for; a field no run reads is a claim nothing decides"
                )
                .into()),
            }
        };
        match declared {
            "test-fails" => unread("test-fails").map(|()| Self::Test),
            "compile-fails" => unread("compile-fails").map(|()| Self::Compile),
            "check-fails" => Ok(Self::Check(
                refusal
                    .ok_or_else(|| {
                        format!(
                            "{name}: declares check-fails and states no refusal; a step exits \
                             non-zero for every fault it has, so an exit status alone does not \
                             say the declared fault was the one found"
                        )
                    })?
                    .to_owned(),
            )),
            other => Err(format!(
                "{name}: unknown kill {other}; \
                 declare test-fails, compile-fails or check-fails"
            )
            .into()),
        }
    }
}

/// One named fault and the run that must refuse it.
struct Mutant {
    name: String,
    /// The package the killing run names. `crate` is a keyword.
    package: String,
    test_target: String,
    test: String,
    kill: Kill,
    /// The site of the fault, as the catalogue gives it: `<file>:<line>`.
    anchor: String,
    /// The same, split: the file the patch must rewrite, and the line of it that is the site.
    site: (PathBuf, usize),
    patch: PathBuf,
    /// Every file the patch writes, repository-relative, in the order the patch names them.
    files: Vec<PathBuf>,
}

impl Mutant {
    /// The cell naming what was run, and the key the clean run is remembered under.
    fn target(&self) -> String {
        if self.test == self.test_target {
            format!("`{}` `{}`", self.package, self.test_target)
        } else {
            format!("`{}` `{}::{}`", self.package, self.test_target, self.test)
        }
    }

    /// The killing run, as arguments to cargo.
    fn command(&self) -> Vec<String> {
        match &self.kill {
            Kill::Check(_) => vec![
                "run".into(),
                "-p".into(),
                self.package.clone(),
                "--locked".into(),
                "--".into(),
                self.test_target.clone(),
            ],
            Kill::Test | Kill::Compile => vec![
                "test".into(),
                "-p".into(),
                self.package.clone(),
                "--locked".into(),
                "--test".into(),
                self.test_target.clone(),
                "--".into(),
                "--exact".into(),
                self.test.clone(),
            ],
        }
    }
}

/// Every named mutant of this repository, applied and killed.
///
/// # Errors
///
/// Any mutant that does not apply, does not apply where it says it does, does not name a run
/// this tree can make, or is not refused by the run it names.
pub fn mutants(root: &Path) -> Result<String> {
    catalogue(
        root,
        &root.join("tests/mutants"),
        &root.join("target/mutants"),
    )
}

/// The same, over a stated catalogue and scratch root, so a case can decide a mutant that must
/// fail without committing one to `tests/mutants/`.
///
/// # Errors
///
/// As [`mutants`].
pub fn catalogue(root: &Path, directory: &Path, work: &Path) -> Result<String> {
    bounded(root, directory, work, BOUND)
}

/// The same, under a stated wall-clock bound on each run, so a case can decide a run that does
/// not terminate without waiting ten minutes for it.
///
/// # Errors
///
/// As [`mutants`], and a killing run that outlives `bound`.
pub fn bounded(root: &Path, directory: &Path, work: &Path, bound: Duration) -> Result<String> {
    // Absolute from here on. `git apply --directory` prepends its value to every path in the
    // patch and then resolves the result against git's own working directory, not this
    // process's, so a caller that passed `.` would write the mutant into the checkout.
    let root = fs::canonicalize(root).map_err(|e| format!("{}: {e}", root.display()))?;
    fs::create_dir_all(work)?;
    let work = fs::canonicalize(work)?;
    let named = read(directory)?;
    let tree = work.join("tree");
    let target = work.join("target");
    let copied = copy(&root, &tree)?;
    // Where every patch lands is decided before anything is built. A patch is applied, read
    // back and reverted; the reading is what says whether its hunks landed where its header
    // claims, and a catalogue whose last patch has drifted must not cost nine builds to say so.
    let mut slides: BTreeMap<&str, String> = BTreeMap::new();
    for mutant in &named {
        let applied = apply(&root, &tree, mutant);
        revert(&root, &tree, mutant, applied.is_ok())?;
        if let Some(slide) = applied? {
            slides.insert(mutant.name.as_str(), slide);
        }
    }
    let mut clean: BTreeSet<String> = BTreeSet::new();
    let mut rows = String::new();
    for mutant in &named {
        // One clean run per distinct target: the two contract mutants share `xtask contracts`,
        // and the run that proves it green on an unmutated copy is the same run for both.
        if clean.insert(mutant.target()) {
            alive(&mutant.command(), &tree, &target, bound, mutant)?;
        }
        // The copy is reused, so whatever the patch wrote has to come back out before the next
        // mutant is applied — including when the killing run is the thing that refused. Both
        // results are held until the revert has run, and only then read.
        let observed = apply(&root, &tree, mutant)
            .map(|_| killed(&mutant.command(), &tree, &target, bound, mutant));
        revert(&root, &tree, mutant, observed.is_ok())?;
        let observed = observed??;
        // Where the two readings of the hunk's position differ, the row says both rather than
        // picking one: the patch applied where its header says, and a reader given one line as
        // the site of the fault would have no way to tell it from the other.
        let observed = match slides.get(mutant.name.as_str()) {
            Some(slide) => format!("{observed} — {slide}"),
            None => observed,
        };
        println!("mutant {} — {observed}", mutant.name);
        writeln!(
            rows,
            "| `{}` | {} | {} |",
            mutant.name,
            mutant.target(),
            observed
        )?;
    }
    Ok(format!(
        "{} named mutant(s) applied to {} tracked file(s) copied to {}, each refused by the \
         target it names\n\n| Mutant | Target test | Observed failure |\n|---|---|---|\n{rows}",
        named.len(),
        copied,
        tree.display()
    ))
}

/// Every mutant the catalogue names, in name order.
///
/// A patch with no record beside it is refused rather than skipped: it is a mutation nothing
/// runs, and it would sit in the catalogue looking like a control.
fn read(directory: &Path) -> Result<Vec<Mutant>> {
    let mut records = Vec::new();
    let mut patches = Vec::new();
    for entry in fs::read_dir(directory)
        .map_err(|e| format!("mutant catalogue {}: {e}", directory.display()))?
    {
        let path = entry?.path();
        match path.extension().and_then(|e| e.to_str()) {
            Some("json") => records.push(path),
            Some("patch") => patches.push(path),
            _ => {
                return Err(format!(
                    "{}: a catalogue holds <name>.patch and <name>.json and nothing else, \
                     because anything else here is a file no run reads",
                    path.display()
                )
                .into());
            }
        }
    }
    records.sort();
    let mut named = Vec::new();
    for record in records {
        named.push(parse(&record)?);
    }
    for patch in patches {
        if !named.iter().any(|m| m.patch == patch) {
            return Err(format!(
                "{}: a patch no record names, so no run would ever apply it",
                patch.display()
            )
            .into());
        }
    }
    if named.is_empty() {
        return Err(format!(
            "{} names no mutant; a catalogue that runs nothing states nothing",
            directory.display()
        )
        .into());
    }
    Ok(named)
}

/// One record and the patch beside it.
fn parse(record: &Path) -> Result<Mutant> {
    let name = record
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or("mutant name")?
        .to_owned();
    let declared: Value = serde_json::from_slice(&fs::read(record)?)
        .map_err(|e| format!("{}: {e}", record.display()))?;
    let object = declared.as_object().ok_or_else(|| {
        format!("{name}: a record is a JSON object of the fields this step reads")
    })?;
    // The keys the step reads, collected as it reads them rather than listed beside the
    // lookups. A list kept in two places drifts, and what drifts out of it is a field the step
    // stopped reading while the records go on stating it — which is the thing being refused.
    let read: RefCell<BTreeSet<&'static str>> = RefCell::new(BTreeSet::new());
    let given = |key: &'static str| -> Option<&str> {
        read.borrow_mut().insert(key);
        object.get(key).and_then(Value::as_str)
    };
    let field = |key: &'static str| -> Result<String> {
        Ok(given(key)
            .ok_or_else(|| format!("{name}: no {key}"))?
            .to_owned())
    };
    let patch = record.with_extension("patch");
    if !patch.is_file() {
        return Err(format!("{name}: no patch beside the record").into());
    }
    let anchor = field("anchor")?;
    let mutant = Mutant {
        kill: Kill::parse(&field("kill")?, given("refusal"), &name)?,
        package: field("crate")?,
        test_target: field("test_target")?,
        test: field("test")?,
        files: writes(&patch, &name)?,
        site: site(&anchor, &name)?,
        anchor,
        patch,
        name: name.clone(),
    };
    let unread: Vec<String> = object
        .keys()
        .filter(|key| !read.borrow().contains(key.as_str()))
        .map(|key| format!("`{key}`"))
        .collect();
    if !unread.is_empty() {
        return Err(format!(
            "{name}: the record states {}, which nothing in this step reads; a record is read \
             field by field and a key this step does not know is a claim nothing decides — \
             `refusals` is one letter away from the field that would have been read, and a \
             constraint this step does not take is not a constraint",
            unread.join(" and ")
        )
        .into());
    }
    anchored(&mutant)?;
    Ok(mutant)
}

/// `<file>:<line>`, split.
fn site(anchor: &str, name: &str) -> Result<(PathBuf, usize)> {
    let (file, line) = anchor
        .rsplit_once(':')
        .ok_or_else(|| format!("{name}: anchor is not <file>:<line>"))?;
    let line = line
        .parse()
        .map_err(|e| format!("{name}: anchor line: {e}"))?;
    Ok((PathBuf::from(file), line))
}

/// Every path the patch writes, refusing one that leaves the tree.
///
/// `--unsafe-paths` turns off git's own refusal of a path outside the working tree, which is
/// what lets the patch be applied into the copy at all. This is the refusal that replaces it:
/// nothing but a plain relative path is admitted, so no catalogue entry can reach the checkout
/// the copy was taken from.
fn writes(patch: &Path, name: &str) -> Result<Vec<PathBuf>> {
    let body = fs::read_to_string(patch)?;
    let mut files = Vec::new();
    for line in body.lines() {
        let Some(rest) = line.strip_prefix("+++ ") else {
            continue;
        };
        let path = rest
            .split_once('\t')
            .map_or(rest, |(path, _)| path)
            .strip_prefix("b/")
            .ok_or_else(|| format!("{name}: {rest} is not a path this step can write"))?;
        let path = PathBuf::from(path);
        if !path.components().all(|c| matches!(c, Component::Normal(_))) {
            return Err(format!("{name}: {} leaves the copied tree", path.display()).into());
        }
        files.push(path);
    }
    if files.is_empty() {
        return Err(format!("{name}: the patch writes no file").into());
    }
    Ok(files)
}

/// The record's anchor names a file this patch writes.
///
/// Which *line* it names is decided in [`apply`], because it cannot be decided here: a hunk has
/// two readings of the line it rewrites — the one its header states and the one the file it
/// wrote states — and the second does not exist until the patch has been applied.
fn anchored(mutant: &Mutant) -> Result<()> {
    let (file, _) = &mutant.site;
    if !mutant.files.iter().any(|f| f == file) {
        return Err(format!(
            "{}: anchor names {}, which the patch does not write",
            mutant.name,
            file.display()
        )
        .into());
    }
    Ok(())
}

/// One hunk of a patch: the file it writes, where its header says it belongs, what it expects
/// to find there, and which of those lines it rewrites.
struct Hunk {
    file: PathBuf,
    /// The line of the file the header says the hunk's pre-image starts at.
    start: usize,
    /// The pre-image: the hunk's context and the lines it removes, in the order it states them.
    before: Vec<String>,
    /// The pre-image lines this hunk rewrites, by their number in the file.
    rewrites: BTreeSet<usize>,
}

/// Every hunk of the patch, in the order it states them.
///
/// A hunk removes lines and inserts lines; the lines it rewrites are the ones it removes. A
/// hunk that only inserts removes nothing, and the one line it can honestly be said to have
/// rewritten is the line the insertion follows — or, for a block inserted before the first line
/// of the file, the line it precedes, which is line 1. A block at the top of a file is a
/// mutation like any other and has to be enterable under some anchor. Everything else a hunk
/// carries is context, which it reads and writes back unaltered.
fn hunks(patch: &Path, name: &str) -> Result<Vec<Hunk>> {
    let body = fs::read_to_string(patch)?;
    let mut all: Vec<Hunk> = Vec::new();
    let mut file = PathBuf::new();
    // How many lines of the open hunk's two sides are still to come. Both zero means no hunk is
    // open, which is how `--- a/<path>` is told from a line a hunk removes.
    let (mut old, mut new) = (0usize, 0usize);
    let mut line = 0usize;
    let mut removing = false;
    for text in body.lines() {
        if old == 0 && new == 0 {
            if let Some(rest) = text.strip_prefix("+++ ") {
                let path = rest.split_once('\t').map_or(rest, |(path, _)| path);
                file = PathBuf::from(path.strip_prefix("b/").unwrap_or(path));
            } else if let Some(rest) = text.strip_prefix("@@ -") {
                let mut ranges = rest.split_whitespace();
                let (start, count) = range(ranges.next().unwrap_or_default(), text, name)?;
                let added = ranges.next().unwrap_or_default().trim_start_matches('+');
                new = range(added, text, name)?.1;
                old = count;
                line = start;
                removing = false;
                all.push(Hunk {
                    file: file.clone(),
                    start,
                    before: Vec::new(),
                    rewrites: BTreeSet::new(),
                });
            }
            continue;
        }
        let hunk = all
            .last_mut()
            .ok_or_else(|| format!("{name}: a hunk body before any hunk header"))?;
        match text.as_bytes().first() {
            Some(b'-') => {
                hunk.before.push(text[1..].to_owned());
                hunk.rewrites.insert(line);
                line += 1;
                old = old.saturating_sub(1);
                removing = true;
            }
            Some(b'+') => {
                if !removing {
                    hunk.rewrites.insert(if line > 1 { line - 1 } else { 1 });
                }
                new = new.saturating_sub(1);
            }
            // `\ No newline at end of file` describes the line before it and is not one.
            Some(b'\\') => {}
            _ => {
                hunk.before
                    .push(text.get(1..).unwrap_or_default().to_owned());
                line += 1;
                old = old.saturating_sub(1);
                new = new.saturating_sub(1);
                removing = false;
            }
        }
    }
    Ok(all)
}

/// The lines of `file` the patch's own headers say it rewrites.
fn stated(hunks: &[Hunk], file: &Path) -> BTreeSet<usize> {
    hunks
        .iter()
        .filter(|hunk| hunk.file == file)
        .flat_map(|hunk| hunk.rewrites.iter().copied())
        .collect()
}

/// Every hunk's pre-image is where its header says it is.
///
/// `git apply` searches the file for a hunk's context and applies it wherever it finds it, at an
/// offset, exiting 0. So this is what tells a patch that drifted from one that did not: if the
/// lines the header claims are at that line really are, the patch applied there, and any
/// difference between the two readings of what it rewrote is the same edit written down two
/// ways. If they are not, the header describes a file this is no longer, and only the file it
/// actually wrote says anything about where the mutation went.
fn placed(root: &Path, hunks: &[Hunk]) -> Result<bool> {
    for hunk in hunks {
        let path = root.join(&hunk.file);
        let body = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let lines: Vec<&str> = body.lines().collect();
        let at = hunk.start.saturating_sub(1);
        let found = lines.get(at..at + hunk.before.len());
        if found.is_none_or(|found| {
            found
                .iter()
                .zip(&hunk.before)
                .any(|(there, stated)| *there != stated.as_str())
        }) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// `<start>,<count>` from one side of a hunk header, where `,<count>` is omitted for one line.
fn range(text: &str, header: &str, name: &str) -> Result<(usize, usize)> {
    let (start, count) = text.split_once(',').unwrap_or((text, "1"));
    let number = |n: &str| -> Result<usize> {
        n.parse()
            .map_err(|e| format!("{name}: hunk header {header}: {e}").into())
    };
    Ok((number(start)?, number(count)?))
}

/// The lines of `before` that `after` does not keep: every line removed, and, for a block that
/// is only inserted, the line it was inserted after.
///
/// The same reading [`stated`] takes of a hunk header, taken of the file the patch wrote. The
/// two are compared rather than one being trusted, because `git apply` will land a hunk at an
/// offset from where its header says and exit 0.
fn rewritten(before: &str, after: &str) -> BTreeSet<usize> {
    let (source, mutated): (Vec<&str>, Vec<&str>) =
        (before.lines().collect(), after.lines().collect());
    let prefix = source
        .iter()
        .zip(mutated.iter())
        .take_while(|(a, b)| a == b)
        .count();
    let suffix = source[prefix..]
        .iter()
        .rev()
        .zip(mutated[prefix..].iter().rev())
        .take_while(|(a, b)| a == b)
        .count();
    let a = &source[prefix..source.len() - suffix];
    let b = &mutated[prefix..mutated.len() - suffix];
    // The longest common subsequence of what is left, which is a hunk's worth of lines: the
    // prefix and the suffix are the whole of both files either side of what the patch changed.
    let (n, m) = (a.len(), b.len());
    let mut common = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            let longest = if a[i] == b[j] {
                common[i + 1][j + 1] + 1
            } else {
                common[i + 1][j].max(common[i][j + 1])
            };
            common[i][j] = longest;
        }
    }
    let mut lines = BTreeSet::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < n || j < m {
        if i < n && j < m && a[i] == b[j] {
            i += 1;
            j += 1;
            continue;
        }
        // A block: every removal and insertion up to the next line both files keep.
        let start = i;
        let mut removed = BTreeSet::new();
        let mut inserted = false;
        while i < n || j < m {
            if i < n && j < m && a[i] == b[j] {
                break;
            }
            if j < m && (i == n || common[i][j + 1] >= common[i + 1][j]) {
                inserted = true;
                j += 1;
            } else {
                removed.insert(prefix + i + 1);
                i += 1;
            }
        }
        if removed.is_empty() {
            if inserted {
                // The line the block follows, or — for a block before the first line of the
                // file, which follows nothing — the line it precedes.
                lines.insert((prefix + start).max(1));
            }
        } else {
            lines.append(&mut removed);
        }
    }
    lines
}

/// A set of line numbers, as a sentence says them.
fn numbers(lines: &BTreeSet<usize>) -> String {
    let listed: Vec<String> = lines.iter().map(usize::to_string).collect();
    match listed.len() {
        0 => "no line at all".to_owned(),
        1 => format!("line {}", listed[0]),
        _ => format!("lines {}", listed.join(", ")),
    }
}

/// Every tracked file of `root`, into `tree`, answering how many were copied.
///
/// Only a file whose bytes differ is written, so a reused tree keeps the timestamps of every
/// file that did not move, and cargo rebuilds nothing for them. Every path the repository does
/// *not* track is removed, because the directory is reused and would otherwise be the union of
/// every state the repository has been in since it was made. The copy's own `target/` is left
/// alone: it holds the builds and the scratch directories of the runs made inside the copy, and
/// nothing in it came from the repository.
fn copy(root: &Path, tree: &Path) -> Result<usize> {
    let listed = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z"])
        .output()?;
    if !listed.status.success() {
        return Err(format!(
            "git ls-files in {}: {}",
            root.display(),
            String::from_utf8_lossy(&listed.stderr).trim()
        )
        .into());
    }
    let mut tracked: BTreeSet<PathBuf> = BTreeSet::new();
    for raw in listed.stdout.split(|b| *b == 0) {
        if raw.is_empty() {
            continue;
        }
        let relative = Path::new(std::str::from_utf8(raw)?);
        sync(&root.join(relative), &tree.join(relative))?;
        tracked.insert(relative.to_owned());
    }
    if tracked.is_empty() {
        return Err(format!("{} tracks no file to copy", root.display()).into());
    }
    prune(tree, tree, &tracked)?;
    Ok(tracked.len())
}

/// Every path under `directory` that `tracked` does not name, removed.
fn prune(tree: &Path, directory: &Path, tracked: &BTreeSet<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        let relative = path.strip_prefix(tree)?.to_owned();
        if path.is_dir() && !path.is_symlink() {
            if relative == Path::new("target") {
                continue;
            }
            prune(tree, &path, tracked)?;
            if fs::read_dir(&path)?.next().is_none() {
                fs::remove_dir(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            }
        } else if !tracked.contains(&relative) {
            fs::remove_file(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        }
    }
    Ok(())
}

/// `from`'s bytes at `to`, written only when they differ, always with a fresh timestamp, and
/// always with the mode the source carries.
///
/// `fs::write` creates a file 0644 whatever the source is, so without the mode the copy is not
/// the tree the mutants are cut from: a tracked script loses its executable bit the first time
/// it is copied, and nothing ever gives it back.
fn sync(from: &Path, to: &Path) -> Result<bool> {
    let bytes = fs::read(from).map_err(|e| format!("{}: {e}", from.display()))?;
    let mode = fs::metadata(from)
        .map_err(|e| format!("{}: {e}", from.display()))?
        .permissions();
    let same = to.is_file() && fs::read(to)? == bytes;
    if !same {
        if let Some(parent) = to.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(to, &bytes).map_err(|e| format!("{}: {e}", to.display()))?;
    }
    if fs::metadata(to)?.permissions() != mode {
        fs::set_permissions(to, mode).map_err(|e| format!("{}: {e}", to.display()))?;
    }
    Ok(!same)
}

/// The patch, into the copy, from the repository the patch was written against — and then the
/// copy read back, because where a patch lands is not what its header says.
///
/// Answers the note the table carries when the hunk's two readings of the line it rewrites
/// differ, which happens whenever the change is slidable: a line inserted beside its own twin
/// can be written down as following either of them and produces the same file. Both readings
/// are then the site of the fault, and the anchor is accepted by either. Where the hunk did
/// *not* land where its header says, the header describes a file this is no longer and only the
/// file it wrote is read.
fn apply(root: &Path, tree: &Path, mutant: &Mutant) -> Result<Option<String>> {
    let applied = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["apply", "--unsafe-paths"])
        .arg(format!("--directory={}/", tree.display()))
        .arg(&mutant.patch)
        .output()?;
    if !applied.status.success() {
        return Err(format!(
            "{}: patch does not apply to the copied tree — re-anchor it against {}: {}",
            mutant.name,
            mutant.anchor,
            String::from_utf8_lossy(&applied.stderr).trim()
        )
        .into());
    }
    let hunks = hunks(&mutant.patch, &mutant.name)?;
    let placed = placed(root, &hunks)?;
    let (anchor, line) = &mutant.site;
    let mut slide = None;
    for file in &mutant.files {
        let source = fs::read(root.join(file))?;
        let mutated = fs::read(tree.join(file))?;
        if source == mutated {
            return Err(format!(
                "{}: git apply exited 0 and {} is unchanged; the mutant was never applied",
                mutant.name,
                file.display()
            )
            .into());
        }
        if file != anchor {
            continue;
        }
        let landed = rewritten(
            &String::from_utf8_lossy(&source),
            &String::from_utf8_lossy(&mutated),
        );
        if !placed {
            if !landed.contains(line) {
                return Err(format!(
                    "{}: the patch rewrites {} {}, and the record anchors {}, which is outside \
                     every hunk that landed; `git apply` searches a file for a hunk's context \
                     and applies it wherever it finds it, so a header that has drifted keeps \
                     applying, at an offset, and an anchor decided against that header keeps \
                     agreeing with it",
                    mutant.name,
                    file.display(),
                    numbers(&landed),
                    mutant.anchor
                )
                .into());
            }
            continue;
        }
        let header = stated(&hunks, file);
        if header != landed {
            slide = Some(format!(
                "the hunk slides: its header rewrites {}, the file it wrote {}",
                numbers(&header),
                numbers(&landed)
            ));
        }
        if !header.contains(line) && !landed.contains(line) {
            let either: BTreeSet<usize> = header.union(&landed).copied().collect();
            return Err(format!(
                "{}: anchor {} is outside every hunk of the patch, which rewrites {} {}",
                mutant.name,
                mutant.anchor,
                file.display(),
                numbers(&either)
            )
            .into());
        }
    }
    Ok(slide)
}

/// Every file the patch wrote, back to the bytes the checkout holds.
///
/// `mutated` says whether [`apply`] reported the patch landed. When it did, a file that needed
/// no reverting is a mutant that never reached the copy and is refused here; when it did not,
/// the copy may hold anything a half-applied patch left behind, and taking it back out is all
/// this does — the refusal `apply` already has is the one worth reading.
fn revert(root: &Path, tree: &Path, mutant: &Mutant, mutated: bool) -> Result<()> {
    let mut untouched = Vec::new();
    for file in &mutant.files {
        if !sync(&root.join(file), &tree.join(file))? {
            untouched.push(file.display().to_string());
        }
    }
    if mutated && !untouched.is_empty() {
        return Err(format!(
            "{}: {} did not need reverting, so the mutant did not reach the copy",
            mutant.name,
            untouched.join(", ")
        )
        .into());
    }
    Ok(())
}

/// The killing run, in the copy, against the shared build directory, under a wall-clock bound.
///
/// A mutation can stop a run ending — a loop whose exit condition the patch removed, a fold
/// that no longer advances — and an unbounded wait is a gate that stops having said nothing and
/// naming nobody. The run is spawned rather than waited on, its status polled, and the child
/// killed once `bound` has passed.
///
/// Both pipes are drained on threads of their own. A run whose output fills the pipe buffer
/// while nothing reads it blocks for ever, and a bound waited for by a process that has already
/// deadlocked is not a bound.
fn cargo(
    args: &[String],
    tree: &Path,
    target: &Path,
    bound: Duration,
    mutant: &Mutant,
    when: &str,
) -> Result<Output> {
    let program = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let mut child = Command::new(program)
        .args(args)
        .current_dir(tree)
        .env("CARGO_TARGET_DIR", target)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let out = drain(child.stdout.take());
    let err = drain(child.stderr.take());
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= bound {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "{}: the killing run did not terminate within {}s {when} and was killed: {}",
                mutant.name,
                bound.as_secs(),
                mutant.target()
            )
            .into());
        }
        thread::sleep(POLL);
    };
    Ok(Output {
        status,
        stdout: out.and_then(|out| out.join().ok()).unwrap_or_default(),
        stderr: err.and_then(|err| err.join().ok()).unwrap_or_default(),
    })
}

/// One of a running command's pipes, read to the end on a thread of its own.
fn drain<R: std::io::Read + Send + 'static>(
    pipe: Option<R>,
) -> Option<thread::JoinHandle<Vec<u8>>> {
    pipe.map(|mut pipe| {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = pipe.read_to_end(&mut bytes);
            bytes
        })
    })
}

/// The run the mutant names, on the unmutated copy: it must pass, and it must have run the one
/// test it names.
fn alive(
    args: &[String],
    tree: &Path,
    target: &Path,
    bound: Duration,
    mutant: &Mutant,
) -> Result<()> {
    let out = cargo(args, tree, target, bound, mutant, "on the unmutated tree")?;
    if matches!(mutant.kill, Kill::Check(_)) {
        if !out.status.success() {
            return Err(format!(
                "{}: {} already fails on the unmutated tree: {}",
                mutant.name,
                mutant.target(),
                last(&out.stderr)
            )
            .into());
        }
        return Ok(());
    }
    let Some(result) = summary(&out) else {
        return Err(format!(
            "{}: {} does not build on the unmutated tree: {}",
            mutant.name,
            mutant.target(),
            last(&out.stderr)
        )
        .into());
    };
    match count(&result, "passed") {
        Some(1) if out.status.success() => Ok(()),
        Some(0) => Err(format!(
            "{}: `{}` names no test of `{}`; it has been renamed or removed, \
             and this mutant has not been shown to be caught since",
            mutant.name, mutant.test, mutant.test_target
        )
        .into()),
        _ => Err(format!(
            "{}: {} on the unmutated tree reported `{result}`, not one passing test",
            mutant.name,
            mutant.target()
        )
        .into()),
    }
}

/// The same run, mutated: the declared refusal, in its own terms, and what was observed.
fn killed(
    args: &[String],
    tree: &Path,
    target: &Path,
    bound: Duration,
    mutant: &Mutant,
) -> Result<String> {
    let out = cargo(args, tree, target, bound, mutant, "with the mutant applied")?;
    let result = summary(&out);
    if out.status.success() {
        return Err(format!(
            "{}: {} passes with the mutant applied — the fault at {} is not caught",
            mutant.name,
            mutant.target(),
            mutant.anchor
        )
        .into());
    }
    match &mutant.kill {
        Kill::Test => {
            let Some(result) = result else {
                return Err(format!(
                    "{}: declares test-fails and the mutated tree does not build: {}",
                    mutant.name,
                    last(&out.stderr)
                )
                .into());
            };
            if count(&result, "passed") != Some(0) || count(&result, "failed") != Some(1) {
                return Err(format!(
                    "{}: declares test-fails and the run reported `{result}`",
                    mutant.name
                )
                .into());
            }
            Ok(match panicked(&out) {
                Some(site) => format!("1 failed at {site}"),
                None => "1 failed".to_owned(),
            })
        }
        Kill::Compile => {
            if let Some(result) = result {
                return Err(format!(
                    "{}: declares compile-fails and the target ran, reporting `{result}`",
                    mutant.name
                )
                .into());
            }
            Ok(format!("does not compile: {}", first_error(&out.stderr)))
        }
        Kill::Check(refusal) => {
            if String::from_utf8_lossy(&out.stderr).contains("could not compile") {
                return Err(format!(
                    "{}: declares check-fails and the step itself does not build: {}",
                    mutant.name,
                    first_error(&out.stderr)
                )
                .into());
            }
            let said = spoke(&out.stderr);
            if said.trim().is_empty() {
                return Err(format!(
                    "{}: declares check-fails on `{refusal}` and {} exited non-zero having \
                     printed nothing; a step that said nothing has not said the declared fault \
                     was the one it found",
                    mutant.name,
                    mutant.target()
                )
                .into());
            }
            let Some(line) = said.lines().find(|line| line.contains(refusal.as_str())) else {
                return Err(format!(
                    "{}: declares check-fails on `{refusal}` and {} refused saying something \
                     else, so the fault this mutant states was never the one found: {}",
                    mutant.name,
                    mutant.target(),
                    tail(&said, 5)
                )
                .into());
            };
            Ok(line.trim().replace('|', "/"))
        }
    }
}

/// The test runner's own summary line, if the target ran at all.
fn summary(out: &Output) -> Option<String> {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find(|line| line.starts_with("test result:"))
        .map(|line| line.trim().to_owned())
}

/// The number the summary states for `what`, read from the runner's own line.
fn count(result: &str, what: &str) -> Option<usize> {
    let mut previous: Option<&str> = None;
    for token in result.split_whitespace() {
        if token.trim_end_matches(';') == what {
            return previous.and_then(|p| p.parse().ok());
        }
        previous = Some(token);
    }
    None
}

/// Where the failing test gave up, as the runner reported it.
fn panicked(out: &Output) -> Option<String> {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|line| line.split_once("panicked at "))
        .map(|(_, site)| site.trim_end_matches(':').replace('|', "/"))
}

/// What the step itself wrote, out of the run's standard error.
///
/// `cargo run -p <crate> -- <step>` echoes ``Running `<binary> <step>` `` before it hands over,
/// so the command line — which carries the step's own name — is on the same stream the step
/// writes its refusal to. A refusal looked for in the whole stream is a refusal that can be
/// satisfied by cargo's echo of the name of the step that was asked to find it, for a step that
/// printed nothing at all. Only what follows the last of those lines is the step's own; and if
/// there is no such line the step never ran, so it wrote nothing.
fn spoke(stderr: &[u8]) -> String {
    let said = String::from_utf8_lossy(stderr);
    let lines: Vec<&str> = said.lines().collect();
    match lines
        .iter()
        .rposition(|line| line.trim_start().starts_with("Running `"))
    {
        Some(index) => lines[index + 1..].join("\n"),
        None => String::new(),
    }
}

/// The last thing the failing command said, which is where these steps put their refusal.
fn last(stderr: &[u8]) -> String {
    tail(&String::from_utf8_lossy(stderr), 1)
}

/// The last `count` things it said, for a refusal that has to show what was observed rather
/// than only what was declared.
fn tail(said: &str, count: usize) -> String {
    let lines: Vec<&str> = said
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    if lines.is_empty() {
        return "no output".to_owned();
    }
    lines[lines.len().saturating_sub(count)..]
        .join(" / ")
        .replace('|', "/")
}

/// The compiler's first complaint, which names the mutation that did not build.
fn first_error(stderr: &[u8]) -> String {
    String::from_utf8_lossy(stderr)
        .lines()
        .find(|line| line.starts_with("error"))
        .unwrap_or("no compiler error")
        .trim()
        .replace('|', "/")
}
