//! Adversary pass 1 against `story:conform-gate`: the gate driven against the documents the
//! unit wrote about itself, and against the planning store it claims to read.
//!
//! Every case here copies what [`conform::conform`] reads into a scratch root of its own under
//! `target/`, changes exactly one thing, and drives the same public entry point the unit's own
//! cases drive. Nothing under `xtask/src` is touched.
#![allow(dead_code)] // the binary target uses the whole of each module; a case here uses part.
#[path = "../src/emit.rs"]
mod emit;

#[path = "../src/conform.rs"]
mod conform;

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

/// Everything the step reads from a root, copied into a scratch root of this pass's own.
///
/// A directory of its own, `xtask-conform-adversary1`, so that a case here and a case in
/// `xtask/tests/conform.rs` cannot collide over a fixture name.
fn fixture(name: &str) -> PathBuf {
    let root = repo().join("target/xtask-conform-adversary1").join(name);
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

/// `ess-inputs.yaml` with `block` written into the specification's `scenarios:` list.
///
/// The list read `scenarios: []` when this case was written and
/// `story:authored-denial-scenarios` has since filled it with the twenty files it authored, so
/// a fixture that replaced the empty list replaced nothing: it wrote the specification back
/// unchanged and drove the gate over a corpus it had not doctored. The key line itself is
/// rewritten instead — `block` is listed whatever the list already holds, and the entries the
/// specification carries follow it.
fn listing(inputs: &str, block: &str) -> String {
    let mut listed = String::new();
    let mut keys = 0_usize;
    for line in inputs.lines() {
        if line.starts_with("scenarios:") {
            keys += 1;
            listed.push_str("scenarios:\n");
            listed.push_str(block);
            listed.push('\n');
            continue;
        }
        listed.push_str(line);
        listed.push('\n');
    }
    assert_eq!(keys, 1, "the specification names its scenario list once");
    listed
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

fn refusal(root: &Path, release: bool) -> String {
    match conform::conform(root, release) {
        Ok(_) => String::new(),
        Err(error) => error.to_string(),
    }
}

/// The artifact and the journal as an AEP store really holds them.
///
/// Measured, not invented. In every planning store on this machine that has recorded evidence
/// about an `executable-system-specification`, the record is an `aep.evidence.record/v1` line
/// in `journal.jsonl` carrying `{kind, reference, source}`, and the artifact markdown carries
/// no evidence section at all — only a `model_digest:` key in its frontmatter, which is what
/// `aep plan artifact set --model-digest` writes and the only digest the document holds. The
/// string `spec_digest` appears in no store's journal and in no store's artifact.
fn store_shaped_evidence(root: &Path, model_digest: &str) {
    // Coordinator amendment (ruling F1): the reference the record carries is what `--release`
    // decides the implementation has not moved since, so it names a commit this checkout holds
    // rather than a literal.
    let head = std::process::Command::new("git")
        .current_dir(repo())
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("git rev-parse HEAD");
    let head = String::from_utf8_lossy(&head.stdout).trim().to_owned();
    let planning = root.join(".engineering/planning");
    let directory = planning.join("executable-system-specification");
    fs::create_dir_all(&directory).expect("the fixture artifact directory");
    fs::write(
        directory.join("mandate.md"),
        format!(
            "---\nformat: aep.planning-md/1\nid: executable-system-specification:mandate\n\
             kind: executable-system-specification\nstatus: validated\n\
             title: The Mandate executable system specification\n\
             model_digest: {model_digest}\nrevision: 2\n---\n\
             ## Authority\n\nThe canonical source is `systems/mandate`. Every file under \
             `generated/` is a projection of it and is not authority.\n"
        ),
    )
    .expect("write the fixture artifact");
    fs::write(
        planning.join("journal.jsonl"),
        "{\"entity\":\"executable-system-specification\",\"version\":1,\"id\":\"mandate\",\
         \"revision\":2,\"type\":\"aep.evidence.record/v1\",\"from_state\":\"validated\",\
         \"to_state\":\"validated\",\"changed\":{},\"args\":{\"command\":\"record-evidence\",\
         \"kind\":\"ess_conformance\",\"reference\":\"git:HEAD_SHA\",\
         \"source\":\"cargo xtask conform\",\"target\":\"01MEM0000000000000001\"},\
         \"payload\":{\"actor\":\"agent:wave-d\",\"at\":1789000000000,\
         \"causation\":\"cmd-evidence-executable-system-specification-mandate-ess_conformance\",\
         \"change\":{\"change\":\"evidence\",\"kind\":\"ess_conformance\",\
         \"reference\":\"git:HEAD_SHA\",\"source\":\"cargo xtask conform\"},\
         \"correlation\":\"protocol-artifact-evidence\",\
         \"event_id\":\"executable-system-specification:mandate@2#0~0123456789abcdef\",\
         \"executor\":null,\"recorded_at\":\"2026-09-21T00:00:00Z\"}}\n"
            .replace("HEAD_SHA", &head),
    )
    .expect("write the fixture journal");
}

/// `--release` reads the evidence the planning store writes, not a shape invented beside it.
///
/// The acceptance is that `cargo xtask conform --release` "additionally exits non-zero when
/// the latest evidence on `executable-system-specification:mandate` carries a `spec_digest` or
/// implementation digest other than the tree's" — which requires it to exit *zero* when the
/// evidence is current. Ruling 3 names how that evidence is recorded:
/// `aep plan artifact new executable-system-specification mandate`, `set --model-digest`,
/// `evidence --from report.json --suite suite.json`. That is the state this case builds.
#[test]
fn release_reads_the_evidence_the_planning_store_actually_writes() {
    let root = fixture("store-shaped-evidence");
    store_shaped_evidence(&root, &spec_digest(&root));
    let refusal = refusal(&root, true);
    assert!(
        refusal.is_empty(),
        "the coordinator recorded this wave's conformance evidence exactly as ruling 3 says \
         (`model_digest` on the artifact, an `aep.evidence.record/v1` line in the journal) and \
         `--release` refuses the tree it was taken against: {refusal}"
    );
}

/// The digests `--release` decides on come from the evidence record, not from anywhere in the
/// file that happens to look like a digest.
///
/// `conform::last_hex` scans the whole document for the last run of hex after a key, and reads
/// the specification digest and the implementation digest by two independent scans. A sentence
/// of prose below a stale record therefore decides the release, and the two halves of the
/// answer need not even come from the same record.
#[test]
fn stale_release_evidence_is_not_rescued_by_a_paragraph_below_it() {
    let root = fixture("prose-rescued-evidence");
    let directory = root.join(".engineering/planning/executable-system-specification");
    fs::create_dir_all(&directory).expect("the fixture artifact directory");
    let stale = "0000000000000000000000000000000000000000000000000000000000000000";
    let current = spec_digest(&root);
    let implementation =
        conform::implementation_digest(&root).expect("the tree's implementation digest");
    fs::write(
        directory.join("mandate.md"),
        format!(
            "---\nformat: aep.planning-md/1\nid: executable-system-specification:mandate\n\
             kind: executable-system-specification\nstatus: validated\n---\n\
             ## Evidence\n\n- kind: conformance_result\n  at: 2026-09-19T00:00:00Z\n  \
             source: task check\n  spec_digest: {stale}\n  \
             implementation: mandate-conformance 0.2.0+src.000000000000\n\n\
             ## Notes\n\nThe run above was taken before the wave closed. For the record, the \
             head this story was scoped at compiles to spec_digest: {current} and the \
             implementation it was read against is mandate-conformance 0.2.0+src.{implementation}.\n"
        ),
    )
    .expect("write the fixture artifact");
    let refusal = refusal(&root, true);
    assert!(
        !refusal.is_empty(),
        "the only evidence record in the artifact was taken against {stale} and an \
         implementation of 000000000000, and `--release` accepted the tree because a later \
         paragraph of prose mentions the current digests"
    );
}

/// The suite the gate re-synthesizes is a synthesis of the whole specification, scenarios
/// included.
///
/// `systems/mandate/ess-inputs.yaml` has a `scenarios:` list; `story:authored-denial-scenarios`
/// fills it with ~22 files and this story's own Scope records that the corpus goes 146 → 166
/// when it merges. The invocation `conform::suite` runs omits `--scenarios`, so the list is
/// never read: this case adds an unparseable file to it, which any invocation that read the
/// list would refuse, and asks the gate what it noticed.
#[test]
fn the_resynthesized_suite_reads_the_specifications_scenario_list() {
    let root = fixture("scenario-list-ignored");
    let scenarios = root.join("systems/mandate/scenarios");
    fs::create_dir_all(&scenarios).expect("the fixture scenarios directory");
    fs::write(
        scenarios.join("adversary.yaml"),
        "this is not a scenario: [\n",
    )
    .expect("write the fixture scenario");
    let inputs = root.join("systems/mandate/ess-inputs.yaml");
    let before = fs::read_to_string(&inputs).expect("the fixture inputs");
    let listed = listing(&before, "- scenarios/adversary.yaml");
    assert_ne!(
        listed, before,
        "the fixture listed the scenario in the specification's inputs"
    );
    assert!(
        listed.contains("scenarios/adversary.yaml"),
        "the scenario was listed in the specification's inputs"
    );
    fs::write(&inputs, listed).expect("write the fixture inputs");
    let refusal = refusal(&root, false);
    assert!(
        refusal.contains("suite.json") || refusal.contains("synthesize"),
        "the specification now lists a scenario file that cannot be parsed, and the gate's \
         re-synthesis of the suite did not notice — it is blind to `ess-inputs.yaml`'s \
         `scenarios:` list, so no authored scenario can ever reach the corpus it compares. \
         The refusal that did arrive is about something else: {refusal}"
    );
}

/// The receipt binds the toolchain as well as the sources, and the gate reads both.
///
/// `xtask/src/receipt.rs` records `ess_version` for one stated reason: "a repin that changes
/// the projections without changing a source would otherwise leave every digest equal and the
/// receipt silent about the one thing that moved". `conform::sources` reads `format` and
/// `source_digest` out of that receipt and never the version, and `conform` itself spawns
/// `ess` without the `version("ess", "ess 0.26.0")` check `generate` makes.
#[test]
fn a_receipt_recording_another_ess_than_the_one_that_synthesized_is_refused() {
    let root = fixture("repinned-ess");
    let path = root.join("generated/coverage/receipt.json");
    let body = fs::read_to_string(&path).expect("the fixture receipt");
    let repinned = body.replace("\"ess 0.26.0\"", "\"ess 0.1.0\"");
    assert_ne!(
        repinned, body,
        "the receipt's recorded toolchain was changed"
    );
    fs::write(&path, repinned).expect("write the fixture receipt");
    let refusal = refusal(&root, false);
    assert!(
        refusal.contains("ess 0.1.0") || refusal.contains("ess_version"),
        "the receipt says this corpus was projected by `ess 0.1.0` and `ess 0.26.0` is what \
         just synthesized the suite the gate compared it against; the gate read the receipt \
         and did not read the one field that records the toolchain: {refusal}"
    );
}

/// An implementation digest is a digest of an implementation.
///
/// [`conform::implementation_digest`] skips `crates` and `services` when they are not there and
/// `systems` when it is not there, so a root holding none of them still answers a digest — the
/// same digest for every such root, since the framed input is empty. It is what `--release`
/// binds the recorded evidence to, and `Action::Conform { root, release }` takes the root from
/// the command line.
#[test]
fn an_implementation_digest_over_no_sources_is_refused() {
    let base = repo().join("target/xtask-conform-adversary1");
    let mut digests = Vec::new();
    for name in ["sourceless-one", "sourceless-two"] {
        let root = base.join(name);
        if root.exists() {
            fs::remove_dir_all(&root).expect("clear the fixture");
        }
        fs::create_dir_all(root.join("contracts")).expect("fixture root");
        fs::write(
            root.join("contracts/marker.json"),
            format!("{{\"root\":\"{name}\"}}\n"),
        )
        .expect("write a fixture marker");
        digests.push(conform::implementation_digest(&root));
    }
    assert!(
        digests[0].is_err(),
        "a root holding no `crates/`, no `services/` and no `systems/` has no implementation \
         to digest, and the step answered {:?} for it — the same answer it gives a second, \
         unrelated sourceless root, {:?}",
        digests[0],
        digests[1]
    );
}
