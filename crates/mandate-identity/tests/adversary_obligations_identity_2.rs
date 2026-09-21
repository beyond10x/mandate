//! Adversary pass 2 against `story:obligations-identity`, after correction 1.
//!
//! Four cases, each driving a document this unit wrote or re-pointed against the code and the
//! store the same unit says it describes. Nothing here edits an implementation file, the unit's
//! files, or the pass-1 file.
//!
//! 1. [`the_declared_overflow_denial_is_the_write_ports_own_and_nothing_else_makes_it`] —
//!    correction 1 rowed `IncrementSecurityEpoch`'s "atomic increment cannot commit" clause
//!    `path: double`, on the ground that the only implementor of `SecurityEpochWrite` is
//!    [`mandate_identity::IdentityLog`], the in-memory double of the adapter. The sibling clause
//!    "the exact unsigned generation is at its maximum" is refused three lines away in that same
//!    function (`src/port.rs:919-921` and `:922-924`) and is rowed `path: real`. This case
//!    measures which code makes the overflow refusal, by handing the command a write port that is
//!    not the double.
//! 2. [`the_registry_readme_states_the_double_backed_clauses_the_directory_now_carries`] — the
//!    unit added the registry's ninth double-backed clause and the first that defers to something
//!    other than `story:graph-policy-adapter`. `contracts/obligations/README.md` states the count
//!    and the deferral as facts and was not touched.
//! 3. [`the_refresh_commands_deferral_names_a_story_that_owns_the_event_it_waits_on`] — the unit
//!    moved `mandate.identity.RefreshSession`'s command-level obligation to
//!    `story:declared-writers`, and `tests/obligations.rs:63-64` says that story "folds the
//!    declared event". This case reads the store.
//! 4. [`every_span_the_unit_cites_for_the_double_classification_states_what_it_is_cited_for`] —
//!    the correction re-read its citations after pass-1 F3. The three spans the *bound* clauses
//!    are justified by are read here; the three the *deferred* clauses are justified by are
//!    pass-1's case 3 and are not repeated.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use mandate_identity::{
    Denial, EpochState, Generation, IncrementSecurityEpoch, SecurityEpochWrite, StreamVersion,
};
use mandate_types::{
    Audience, CorrelationId, CredentialId, DenialReason, OrganizationId, PrincipalId,
    SecurityEpochTarget, Uuid, VerifiedContext,
};
use serde_json::Value;

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn principal() -> PrincipalId {
    PrincipalId::new(uuid(1))
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(2))
}

fn context() -> VerifiedContext {
    VerifiedContext {
        subject: principal(),
        actor: None,
        organization: organization(),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("adversary-2"),
    }
}

/// The workspace root, from this crate's manifest directory.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the workspace root is two directories above this crate")
}

/// One JSON document of the repository.
fn json_at(path: &Path) -> Value {
    let text = fs::read_to_string(path).unwrap_or_else(|error| {
        panic!("{}: {error}", path.display());
    });
    serde_json::from_str(&text).unwrap_or_else(|error| {
        panic!("{}: {error}", path.display());
    })
}

/// The rows of a JSON array, or nothing when the key is absent.
fn rows(value: &Value) -> &[Value] {
    value.as_array().map_or(&[][..], Vec::as_slice)
}

// ==================================================================================
// 1. mandate.identity.IncrementSecurityEpoch, "the exact unsigned generation is at its
//    maximum" — which code makes that refusal
// ==================================================================================

/// A write port that is not [`mandate_identity::IdentityLog`]: it performs the compare-and-set
/// the trait's contract names and holds one generation, and the single thing it omits is the
/// overflow guard `<IdentityLog as SecurityEpochWrite>::increment` makes at
/// `crates/mandate-identity/src/port.rs:922-924`.
///
/// The mutation is expressed here, inside a test this pass added, rather than against the file
/// under attack: the question is whether any code outside the write port refuses an increment at
/// [`Generation::MAX`], and the way to ask it is to hand the command a port that does not.
#[derive(Debug)]
struct AdapterWithoutTheOverflowGuard {
    /// The one generation this stand-in holds.
    generation: Generation,
    /// The version its stream is at, which the compare-and-set compares against.
    version: StreamVersion,
}

impl SecurityEpochWrite for AdapterWithoutTheOverflowGuard {
    fn increment(
        &mut self,
        _context: &VerifiedContext,
        _target: &SecurityEpochTarget,
        expected: StreamVersion,
    ) -> Result<EpochState, Denial> {
        if self.version != expected {
            return Err(Denial::new(DenialReason::Unavailable));
        }
        self.version = self.version.advance();
        Ok(EpochState::new(self.generation, self.version))
    }
}

/// `contracts/obligations/identity.json:30-42` rows "the exact unsigned generation is at its
/// maximum" `path: real`, and `contracts/obligations/README.md:100-105` defines `real` as "the
/// crate's own shipped decision path — a handler, a fold, a validator", against `double`, which
/// is "a stand-in **for the deciding code itself**".
///
/// Three lines away in one function, correction 1 rowed "atomic increment cannot commit"
/// `path: double` with `double: mandate_identity::IdentityLog`, justified at
/// `crates/mandate-identity/tests/obligations.rs:18-27` by: the refusal is
/// `SecurityEpochWrite::increment`'s, "whose only implementor is `IdentityLog`", the in-memory
/// double of the adapter. Both refusals are `return Err(...)` inside
/// `impl SecurityEpochWrite for IdentityLog` — the version at `src/port.rs:919-921`, the maximum
/// at `:922-924`.
///
/// The compiled contract assigns all three to the adapter in one sentence
/// (`generated/ir/system.json`, `mandate.identity.IncrementSecurityEpoch`, accepted outcome):
/// "The adapter must atomically increment the one selected generation, deny unsigned overflow
/// and preserve isolation of unrelated organizations/connections." The unit rowed the first
/// `double`, deferred the third to `story:identity-tenant-containment`, and left the second
/// `real`.
///
/// So: is the overflow refusal made by shipped code outside the write port? The command is handed
/// a port that is not the double and does not guard the maximum. When this case was written the
/// clause was `real`, and the answer it got back was that nothing outside the port refuses.
///
/// **Amended by the coordinator to ruling F1** (`review-result:wave-d-obligations-identity-adversary-2`).
/// The finding was upheld and the contract moved, not the code: one function is not two paths, so
/// both rows of the clause became `path: double`, `double: mandate_identity::IdentityLog`,
/// `blocked_on: decision-blocker:epoch-atomicity`. The case as first written demanded that a
/// handler produce the denial, which is the opposite of what was ruled. It now asserts the two
/// halves that must agree, and goes red if either moves without the other:
///
/// 1. the measurement — the command over a write port that is not `IdentityLog` produces **no**
///    denial at `Generation::MAX`, because `IncrementSecurityEpoch::execute` delegates and
///    decides nothing;
/// 2. the contract's answer to it — every row of the clause is a `double` on
///    `mandate_identity::IdentityLog` and the clause defers to the blocker that owns the port's
///    real implementation.
///
/// If a later change moves the refusal into handler code, (1) fails and the clause is due back on
/// the real path. If someone rows the clause `real` while the handler still decides nothing, (2)
/// fails. Neither can be done quietly.
#[test]
fn the_declared_overflow_denial_is_the_write_ports_own_and_nothing_else_makes_it() {
    // The shipped domain type states the *fact* and no refusal: `advance` answers `None`, which
    // is not a `Denial` and carries no `DenialReason` (`src/generation.rs:50-58`).
    assert!(
        Generation::MAX.advance().is_none(),
        "the shipped generation type refuses to advance past its maximum"
    );

    let mut adapter = AdapterWithoutTheOverflowGuard {
        generation: Generation::MAX,
        version: StreamVersion::INITIAL,
    };

    let outcome =
        IncrementSecurityEpoch::new(context(), SecurityEpochTarget::Principal(principal()))
            .execute(&mut adapter, StreamVersion::INITIAL);

    assert_eq!(
        outcome.as_ref().err().map(Denial::reason),
        None,
        "an increment at `Generation::MAX` over a write port that is not \
         `mandate_identity::IdentityLog` produced {outcome:?}, so some code outside the write \
         port now makes the overflow refusal. When ruling F1 was taken, none did: \
         `IncrementSecurityEpoch::execute` (`src/increment.rs:87-100`) delegated to the port and \
         decided nothing, and the declared denial existed only inside \
         `<IdentityLog as SecurityEpochWrite>::increment` (`src/port.rs:922-924`). If a handler, \
         fold or validator of this crate now produces it, the clause belongs back on the real \
         path and `contracts/obligations/identity.json` should say so."
    );

    let identity = json_at(&repo().join("contracts/obligations/identity.json"));
    let commands = rows(&identity["commands"]);
    let command = commands
        .iter()
        .find(|entry| entry["command"] == "mandate.identity.IncrementSecurityEpoch")
        .expect("identity.json carries mandate.identity.IncrementSecurityEpoch");
    let clauses = rows(&command["clauses"]);
    let clause = clauses
        .iter()
        .find(|entry| entry["clause"] == "the exact unsigned generation is at its maximum")
        .expect("the overflow clause is published");

    let tests = rows(&clause["tests"]);
    assert!(
        !tests.is_empty(),
        "the overflow clause names no test at all, so nothing is evidence of it either way"
    );
    let wrong: Vec<String> = tests
        .iter()
        .filter(|row| row["path"] != "double" || row["double"] != "mandate_identity::IdentityLog")
        .map(|row| {
            format!(
                "  {} — path {}, double {}",
                row["id"], row["path"], row["double"]
            )
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "the measurement above says the overflow refusal is made only inside \
         `<IdentityLog as SecurityEpochWrite>::increment`, and \
         contracts/obligations/identity.json rows it otherwise:\n{}",
        wrong.join("\n")
    );
    assert_eq!(
        clause["blocked_on"], "decision-blocker:epoch-atomicity",
        "a double-backed clause defers to the owner of the port's real implementation \
         (contracts/obligations/README.md); the compare-and-set refused three lines away in the \
         same function defers to decision-blocker:epoch-atomicity and this one defers to {}",
        clause["blocked_on"]
    );
}

// ==================================================================================
// 2. contracts/obligations/README.md against the directory it describes
// ==================================================================================

/// The spelled forms the README writes a small count in.
const SPELLED: [&str; 21] = [
    "zero",
    "one",
    "two",
    "three",
    "four",
    "five",
    "six",
    "seven",
    "eight",
    "nine",
    "ten",
    "eleven",
    "twelve",
    "thirteen",
    "fourteen",
    "fifteen",
    "sixteen",
    "seventeen",
    "eighteen",
    "nineteen",
    "twenty",
];

/// Every clause of an `implemented` command whose only evidence is a double, as
/// `<crate>: <clause>` together with what it defers to.
fn double_backed(root: &Path) -> Vec<(String, String)> {
    let directory = root.join("contracts/obligations");
    let mut found = Vec::new();
    let mut stems: Vec<String> = fs::read_dir(&directory)
        .expect("the registry directory")
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            name.strip_suffix(".json").map(str::to_owned)
        })
        .collect();
    stems.sort();
    for stem in stems {
        let document = json_at(&directory.join(format!("{stem}.json")));
        for command in rows(&document["commands"]) {
            if command["status"] != "implemented" {
                continue;
            }
            for clause in rows(&command["clauses"]) {
                let real = rows(&clause["tests"])
                    .iter()
                    .any(|row| row["kind"] == "denial" && row["path"] == "real");
                let double = rows(&clause["tests"])
                    .iter()
                    .any(|row| row["path"] == "double");
                if !real && double {
                    found.push((
                        format!("{stem}: {}", clause["clause"]),
                        clause["blocked_on"]
                            .as_str()
                            .unwrap_or("<no blocked_on>")
                            .to_owned(),
                    ));
                }
            }
        }
    }
    found
}
/// `contracts/obligations/README.md` states the **rule** a double-backed clause's `blocked_on`
/// follows, and states no instance of it.
///
/// This case was written the other way round. At `181e6c0` the README said:
///
/// > The eight double-backed clauses defer to `story:graph-policy-adapter`, which owns
/// > `mandate_policy::port::PolicyAdministration` and `mandate_graph::topology::ResourceRegistry`
/// > — each crate's own `double` is their only implementor today.
///
/// — a count and a closed list, both exactly true when they were written. This unit added the
/// ninth double-backed clause and it defers to `decision-blocker:epoch-atomicity`, which is not
/// a story and owns no port implementation; the `obligations-graph` unit took the count to 13 in
/// the same week. The coordinator's ruling (`review-result:wave-d-obligations-identity-adversary-2`
/// F2, `…-graph-adversary-2` F5) was that a count and a closed list are stale by construction
/// here: every merge that adds a document moves both, and nothing compares either with the
/// directory, because `xtask/src/obligations_registry.rs` never reads the README.
///
/// So the case asserts what this file can hold and a merge cannot falsify:
///
/// 1. the paragraph names **both** kinds of target its rule admits — the story that owns the
///    port's real implementation, and the open `decision-blocker` holding the question;
/// 2. it states no count of double-backed clauses;
/// 3. every distinct deferral the directory's double-backed clauses actually carry resolves to
///    an artifact the planning store holds whose `status:` is not a terminal rung. That is the
///    rule `README.md` states and `xtask/src/obligations_registry.rs` enforces, checked here
///    against the store directly rather than through the step that wrote the report.
#[test]
fn the_registry_readme_states_the_rule_double_backed_clauses_follow_and_no_instance_of_it() {
    let root = repo();
    let backed = double_backed(&root);
    assert!(
        !backed.is_empty(),
        "no clause in contracts/obligations/ is reached only by a double, so this case has no \
         subject"
    );

    let readme = fs::read_to_string(root.join("contracts/obligations/README.md"))
        .expect("the registry README");
    let flat = readme.split_whitespace().collect::<Vec<_>>().join(" ");

    for limb in ["port's real implementation", "decision-blocker"] {
        assert!(
            flat.contains(limb),
            "contracts/obligations/README.md no longer names {limb:?} as something a \
             double-backed clause's blocked_on may be, and the directory carries deferrals of \
             both kinds: {backed:?}"
        );
    }

    let subject = "double-backed clause";
    let mut counted: Vec<String> = Vec::new();
    let mut consumed = 0_usize;
    while let Some(at) = flat[consumed..].find(subject) {
        let absolute = consumed + at;
        if let Some(word) = flat[..absolute].split_whitespace().next_back()
            && (SPELLED.contains(&word) || word.parse::<usize>().is_ok())
        {
            let tail: String = flat[absolute..].chars().take(70).collect();
            counted.push(format!("  \"{word} {tail}…\""));
        }
        consumed = absolute + subject.len();
    }
    assert!(
        counted.is_empty(),
        "contracts/obligations/README.md states a count of double-backed clauses and the \
         directory carries {}. A count written here is stale at the next merge that adds a \
         document — it said \"eight\" at 181e6c0 — and \
         contracts/conformance/obligations-report.json is what counts them. Claims found:\n{}",
        backed.len(),
        counted.join("\n"),
    );

    let store = root.join(".engineering/planning");
    let mut wrong: Vec<String> = Vec::new();
    let deferrals: BTreeSet<&str> = backed.iter().map(|(_, to)| to.as_str()).collect();
    for deferral in &deferrals {
        let Some((kind, name)) = deferral.split_once(':') else {
            wrong.push(format!("{deferral} names no artifact kind"));
            continue;
        };
        let document = store.join(kind).join(format!("{name}.md"));
        let Ok(text) = fs::read_to_string(&document) else {
            wrong.push(format!(
                "{deferral} is deferred to and the store holds no {}",
                document.display()
            ));
            continue;
        };
        let status = text
            .lines()
            .find_map(|line| line.strip_prefix("status:"))
            .map(str::trim)
            .unwrap_or("<none>");
        // The terminal rungs README.md:130-133 names, plus a blocker that has been answered.
        if matches!(
            status,
            "implemented" | "archived" | "rejected" | "resolved" | "closed"
        ) {
            wrong.push(format!(
                "{deferral} is {status}, a terminal rung, and double-backed clauses still defer \
                 to it: {}",
                backed
                    .iter()
                    .filter(|(_, to)| to == deferral)
                    .map(|(clause, _)| clause.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "contracts/obligations/README.md says a double-backed clause defers to the owner of the \
         port's real implementation or to the open decision-blocker holding the question, and \
         the directory does not:\n\n{}",
        wrong.join("\n"),
    );
}

// ==================================================================================
// 3. mandate.identity.RefreshSession, the command-level deferral
// ==================================================================================

/// The unit withdrew `RefreshSession`'s `no_state_change` row after pass-1 F2 and moved the
/// obligation to a command-level `blocked_on: story:declared-writers`
/// (`contracts/obligations/identity.json:147`), justified at
/// `crates/mandate-identity/tests/obligations.rs:63-64`: "The command carries the deferral at
/// command level, to `story:declared-writers`, which folds the declared event."
///
/// `contracts/obligations/README.md:130-143` is what a deferral means: it names the story that
/// owns the path, because "no test the binding story could write would bind the clause until the
/// path answers", and "Once that story reaches `implemented` the step refuses every clause still
/// deferred to it". `xtask/src/obligations_registry.rs:699-711` enforces that only against the
/// crate's own binding story, so a deferral to any other live story passes the step whether or
/// not that story owns the work.
///
/// This case asks the store whether it does. Three answers are accepted, and the base commit
/// gave the first: the deferral names the crate's binding story, which README:132-135 makes the
/// answer for an obligation nothing has bound yet; or `contracts/coverage.json` rows the named
/// story as the owner of `mandate.identity.SessionRefreshed`, the event the obligation waits to
/// be folded; or the story's own document names that event or the command. At `181e6c0` the
/// command-level deferral was `story:obligations-identity` and this case is green; the unit moved
/// it.
#[test]
fn the_refresh_commands_deferral_names_a_story_that_owns_the_event_it_waits_on() {
    let root = repo();
    let identity = json_at(&root.join("contracts/obligations/identity.json"));
    let refresh = rows(&identity["commands"])
        .iter()
        .find(|command| command["command"] == "mandate.identity.RefreshSession")
        .expect("identity.json carries mandate.identity.RefreshSession");
    let deferral = refresh["blocked_on"]
        .as_str()
        .expect("the command carries a command-level blocked_on")
        .to_owned();
    assert!(
        deferral.starts_with("story:"),
        "the command-level deferral is {deferral:?}, which this case reads as a story"
    );
    // README:132-135: "For an unbound clause that story is `story:obligations-<crate>`, the
    // binding story that owns the crate's `tests/obligations.rs`." That is what `181e6c0`
    // carried, and it is not a defect.
    let binding = format!(
        "story:obligations-{}",
        identity["crate"]
            .as_str()
            .unwrap_or_default()
            .trim_start_matches("mandate-")
    );

    let coverage = json_at(&root.join("contracts/coverage.json"));
    let entry = rows(&coverage["entries"])
        .iter()
        .find(|entry| entry["element"] == "mandate.identity.SessionRefreshed")
        .expect("the coverage manifest rows mandate.identity.SessionRefreshed");
    let owner = entry["story"].as_str().unwrap_or_default().to_owned();
    let status = entry["status"].as_str().unwrap_or_default().to_owned();

    let document = root
        .join(".engineering/planning/story")
        .join(format!("{}.md", deferral.trim_start_matches("story:")));
    let text = fs::read_to_string(&document).unwrap_or_else(|error| {
        panic!("{}: {error}", document.display());
    });
    let names_the_work = text.contains("SessionRefreshed") || text.contains("RefreshSession");

    assert!(
        deferral == binding || deferral == owner || names_the_work,
        "contracts/obligations/identity.json:147 defers mandate.identity.RefreshSession's \
         command-level obligation to {deferral} — off {binding}, which README:132-135 makes the \
         answer for an obligation nothing has bound, and which `181e6c0` carried — and \
         crates/mandate-identity/tests/obligations.rs:63-64 states that {deferral} \"folds the \
         declared event\". The store says otherwise: contracts/coverage.json rows \
         mandate.identity.SessionRefreshed `{status}` under {owner}, not {deferral}, and \
         {} names neither `SessionRefreshed` nor `RefreshSession` anywhere in its {} lines — \
         its Acceptance is about which command creates each of the 36 entities. An obligation \
         deferred to a story that does not own it is published as waiting on work that cannot \
         discharge it, which is the shape contracts/obligations/README.md:130-143 exists to \
         refuse.",
        document.strip_prefix(&root).unwrap_or(&document).display(),
        text.lines().count(),
    );
}

// ==================================================================================
// 4. The spans the correction cites for the clauses it bound
// ==================================================================================

/// One `file:line` span `crates/mandate-identity/tests/obligations.rs` offers for a clause the
/// correction *bound*, as opposed to one it deferred.
struct Citation {
    /// The file, relative to this crate's manifest directory.
    file: &'static str,
    /// The first and last line of the cited span, as the module doc states them.
    span: (usize, usize),
    /// A word the claim cannot be made without.
    word: &'static str,
    /// What the span is cited as stating.
    claim: &'static str,
}

/// The three spans `tests/obligations.rs:12-27` ("What is bound here, and on which path") cites.
/// The spans cited in "What is not here" are pass-1's case 3 and are not repeated.
const CITED: &[Citation] = &[
    Citation {
        file: "src/session.rs",
        span: (369, 369),
        word: "organization",
        claim: "handler code over the fold, and the one place in this crate that compares a \
                record's organization against the caller's verified one",
    },
    // Amended by the coordinator to ruling F4: the correction moved this citation from the
    // wrong span `:917-921`, which holds the compare-and-set and neither name, to `:911`, which
    // is `impl SecurityEpochWrite for IdentityLog` and holds both. The case is what found the
    // defect; it now holds the corrected span, so it goes red again if the citation drifts back.
    Citation {
        file: "src/port.rs",
        span: (911, 911),
        word: "IdentityLog",
        claim: "`SecurityEpochWrite::increment`, whose only implementor is `IdentityLog`",
    },
    Citation {
        file: "src/session.rs",
        span: (342, 343),
        word: "in-memory double",
        claim: "`IdentityLog` is the in-memory double of the event-log adapter a later story \
                supplies",
    },
];

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The cited span of a file, or the reason it cannot be read.
fn span_of(root: &Path, citation: &Citation) -> String {
    let path = root.join(citation.file);
    let text = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("{}: {error}", path.display());
    });
    let lines: Vec<&str> = text.lines().collect();
    let (first, last) = citation.span;
    assert!(
        first >= 1 && last >= first && last <= lines.len(),
        "{}:{first}-{last} is not a span {} has, which holds {} lines",
        citation.file,
        path.display(),
        lines.len(),
    );
    lines[first - 1..last].join("\n")
}

/// Where the claim's word does appear, so a refusal names the correction rather than only the
/// error.
fn first_line_holding(root: &Path, file: &str, word: &str) -> Option<usize> {
    let text = fs::read_to_string(root.join(file)).ok()?;
    text.lines()
        .position(|line| line.contains(word))
        .map(|index| index + 1)
}

/// Pass-1 F3 found two citations at the wrong lines and the correction re-read all nine. The
/// three checked there were the ones justifying a *deferral*; these three justify the two clauses
/// the unit *bound*, and they are what a reader checks the `real` and `double` classifications
/// against. A `file:line` span is the one form of citation a reader verifies by opening the file
/// at that line.
#[test]
fn every_span_the_unit_cites_for_the_double_classification_states_what_it_is_cited_for() {
    let root = crate_root();
    let mut wrong: Vec<String> = Vec::new();
    for citation in CITED {
        let (first, last) = citation.span;
        let quoted = span_of(&root, citation);
        if quoted.contains(citation.word) {
            continue;
        }
        let elsewhere = first_line_holding(&root, citation.file, citation.word).map_or_else(
            || "nowhere in the file".to_owned(),
            |line| format!("{line}"),
        );
        wrong.push(format!(
            "{}:{first}-{last} is cited for {:?} and holds no {:?}; the span reads:\n{quoted}\n\
             the word first appears at line {elsewhere}",
            citation.file, citation.claim, citation.word,
        ));
    }
    assert!(
        wrong.is_empty(),
        "crates/mandate-identity/tests/obligations.rs cites {} span(s) for a bound clause that \
         do not state what they are cited for:\n\n{}",
        wrong.len(),
        wrong.join("\n\n"),
    );
}
