//! Adversary pass 2 on `story:obligations-policy`: correction 1's own claims, driven against
//! the code and the documents they are claims about.
//!
//! Pass 1 attacked the shipped behaviour and four of its cases are now pins. This pass
//! attacks what correction 1 added — two cases in `crates/mandate-policy/tests/obligations.rs`
//! for the organization half of the later-version guards, the paragraph that says what those
//! cases establish, and the two sentences the unit added to
//! `contracts/obligations/README.md` and to its own file about documents elsewhere in the
//! workspace.
//!
//! Every case here is red against the tree as it stands, and each one's doc comment names the
//! fact that makes it red. Nothing here rewrites, weakens or skips an existing case; every
//! fixture is built in this file.

use std::fs;
use std::path::{Path, PathBuf};

use mandate_policy::double::PolicyDouble;
use mandate_policy::port::{PolicyAdministration, PolicyError};
use mandate_policy::record::{AuthorizationModel, Policy};
use mandate_types::{
    Audience, AuthorizationModelId, CorrelationId, CredentialId, DenialReason, OrganizationId,
    PolicyId, PolicyVersion, PrincipalId, Uuid, VerifiedContext,
};

/// The workspace root, reached the way `adversary_obligations_policy_1.rs` reaches the
/// compiled model.
const WORKSPACE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

/// The file correction 1 added its two cases and its claims to.
const OBLIGATIONS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/obligations.rs");

/// The registry document the unit's own deferral is measured against.
const STS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../contracts/obligations/sts.json"
);

/// The registry's normative README, which this unit edited.
const README: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../contracts/obligations/README.md"
);

/// `crates/mandate-policy/tests/obligations.rs:70`, verbatim and on one line of that file.
const ELEVEN_CLAIM: &str = "with the eleven authority clauses of";

/// `contracts/obligations/README.md:119-120`, with the line break collapsed.
const ONLY_IMPLEMENTOR_CLAIM: &str =
    "`mandate_identity::IdentityLog` is the only implementor of `SecurityEpochWrite`";

fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("{path}: {error}"))
}

fn uuid(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(1))
}

/// The organization `tests/obligations.rs:101` folds the later record for in both of the
/// cases this file is about.
fn another_organization() -> OrganizationId {
    OrganizationId::new(uuid(9))
}

fn context() -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::new(uuid(2)),
        actor: None,
        organization: organization(),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(7)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("correlation"),
    }
}

fn policy_of(held_by: OrganizationId, byte: u8, version: &str) -> Policy {
    Policy::recorded(
        PolicyId::new(uuid(byte)),
        held_by,
        PolicyVersion::new(version),
        "permit(principal, action, resource);",
    )
}

fn model_of(held_by: OrganizationId, byte: u8, version: &str) -> AuthorizationModel {
    AuthorizationModel::recorded(
        AuthorizationModelId::new(uuid(byte)),
        held_by,
        PolicyVersion::new(version),
        "type document relations { viewer, editor }",
    )
}

/// `tests/obligations.rs:145-150`: one policy version and one model version, both current and
/// both this organization's.
fn published() -> PolicyDouble {
    let mut double = PolicyDouble::new();
    double.record_policy(policy_of(organization(), 4, "2026-09-18.1"));
    double.record_model(model_of(organization(), 5, "2026-09-18.1"));
    double
}

/// Every `.rs` file under a `src/` directory of `crates/` or `services/` — the library
/// targets, and no test binary.
fn library_sources() -> Vec<PathBuf> {
    fn walk(root: &Path, found: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(root) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, found);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                found.push(path);
            }
        }
    }

    let workspace = Path::new(WORKSPACE);
    let mut found = Vec::new();
    for packages in ["crates", "services"] {
        let Ok(entries) = fs::read_dir(workspace.join(packages)) else {
            continue;
        };
        for entry in entries.flatten() {
            walk(&entry.path().join("src"), &mut found);
        }
    }
    found.sort();
    found
}

/// Every `impl … <trait> for …` a library target of this workspace states, as `path:line`.
fn implementors_of(name: &str) -> Vec<String> {
    let workspace = Path::new(WORKSPACE);
    let needle = format!("{name} for ");
    let mut found = Vec::new();
    for source in library_sources() {
        let Ok(text) = fs::read_to_string(&source) else {
            continue;
        };
        let shown = source
            .strip_prefix(workspace)
            .unwrap_or(&source)
            .display()
            .to_string();
        for (offset, line) in text.lines().enumerate() {
            if line.starts_with("impl ") && line.contains(&needle) {
                found.push(format!("{shown}:{}", offset + 1));
            }
        }
    }
    found
}

/// Both halves of both later-version guards decide a refusal, and this case is the measurement
/// that says so.
///
/// `src/double.rs:262-264` and `:299-301` ask two things of every record folded after the one
/// under test — that it is `current()` and that it is this organization's.
///
/// As written, this case found that only the organization half was load-bearing. Correction 1's
/// paragraph claimed of its two new cases that "dropping either half of the predicate fells the
/// case", and dropping `policy.current()` from `src/double.rs:264` or `model.current()` from
/// `:301` left all 76 cases green — the four folds those cases built held no superseded record,
/// so `current() && organization_id == organization` and `organization_id == organization` alone
/// answered identically on every one of them.
///
/// Ruling F1 (`review-result:wave-d-obligations-policy-adversary-2`) took the fix that closes the
/// gap rather than the one that softens the sentence: correction 2 folded an already-superseded
/// later record into each of the unit's two cases, and all four mutations were then run and each
/// fells a case.
///
/// **Amended by the coordinator.** The half of this case that rebuilt the unit's four folds line
/// by line is gone: it read a copy of a fixture rather than the fixture, so it went stale the
/// moment the fixture was corrected — the same defect, one rung up, as a test that restates a
/// document's wording instead of reading it. What stands in its place is the measurement itself,
/// in this file's own fixtures. Six assertions: four hold the organization constant and vary
/// `current()`, two hold `current()` constant and vary the organization. Each conjunct
/// independently decides a refusal, and if either stops, this case falls — whatever the unit's
/// fixtures look like that week.
///
/// One property worth knowing and not asserted here: no fold the shipped writer produces can
/// reach a refusal that turns on `current()`, because `src/record.rs:23-25` defines `Superseded`
/// as "a later version is current", so a fold whose later same-organization records are all
/// superseded contradicts its own projection. These fixtures build it through the `pub`
/// `record_policy` / `record_model` directly, which is the only way the conjunct decides
/// anything today. Recorded on `story:unpublished-refusals` beside the fold-order entry.
#[test]
fn both_halves_of_the_later_version_guard_decide_a_refusal() {
    let mut stale = published();
    let mut later = policy_of(organization(), 6, "2026-09-18.2");
    later.supersede();
    stale.record_policy(later);
    assert_eq!(
        stale.supersede_policy(&context(), &PolicyId::new(uuid(4))),
        Err(PolicyError::Denied(DenialReason::Denied)),
        "the only later record of this organization is superseded, so `policy.current()` in \
         `src/double.rs:264` is the conjunct that refuses this call"
    );

    let mut current = published();
    current.record_policy(policy_of(organization(), 6, "2026-09-18.2"));
    assert!(
        current
            .supersede_policy(&context(), &PolicyId::new(uuid(4)))
            .is_ok(),
        "the same fold with that later record current is accepted, so a case over this pair \
         would decide the conjunct"
    );

    let mut stale_model = published();
    let mut later_model = model_of(organization(), 6, "2026-09-18.2");
    later_model.supersede();
    stale_model.record_model(later_model);
    assert_eq!(
        stale_model.supersede_authorization_model(&context(), &AuthorizationModelId::new(uuid(5))),
        Err(PolicyError::Denied(DenialReason::Denied)),
        "and `model.current()` in `src/double.rs:301` is the conjunct that refuses the model \
         command's"
    );

    let mut current_model = published();
    current_model.record_model(model_of(organization(), 6, "2026-09-18.2"));
    assert!(
        current_model
            .supersede_authorization_model(&context(), &AuthorizationModelId::new(uuid(5)))
            .is_ok(),
        "the same model fold with that later record current is accepted"
    );

    // Amended by the coordinator to ruling F1 (`review-result:wave-d-obligations-policy-adversary-2`).
    //
    // This case was written to show that `crates/mandate-policy/tests/obligations.rs` claimed
    // "dropping either half of the predicate fells the case" while only the organization half was
    // load-bearing: dropping `current()` from `src/double.rs:264` and `:301` left all 76 cases
    // green. The ruling took the fix that closes the gap rather than the one that softens the
    // sentence, and correction 2 folded an already-superseded later record into each of the unit's
    // two cases. All four mutations were then run and each fells a case — measured, not claimed.
    //
    // The half of this case that reconstructed the unit's four folds line by line is gone. It was
    // reading a copy of a fixture rather than the fixture, so it went stale the moment the fixture
    // was corrected — which is the same defect, one rung up, as a test that restates a document's
    // wording instead of reading it. What replaces it is the measurement itself, in this file's own
    // fixtures: **each conjunct independently decides a refusal.** Four of the six assertions here
    // hold `organization_id` constant and vary `current()`; the two below hold `current()` constant
    // and vary the organization. If either conjunct stops deciding, this case falls, whatever the
    // unit's fixtures happen to look like that week.
    let mut another_orgs_policy = published();
    another_orgs_policy.record_policy(policy_of(another_organization(), 6, "2026-09-18.2"));
    assert_eq!(
        another_orgs_policy.supersede_policy(&context(), &PolicyId::new(uuid(4))),
        Err(PolicyError::Denied(DenialReason::Denied)),
        "a later record that is current but belongs to another organization no longer refuses, \
         so `organization_id == organization` in `src/double.rs:264` has stopped deciding"
    );

    let mut another_orgs_model = published();
    another_orgs_model.record_model(model_of(another_organization(), 6, "2026-09-18.2"));
    assert_eq!(
        another_orgs_model
            .supersede_authorization_model(&context(), &AuthorizationModelId::new(uuid(5))),
        Err(PolicyError::Denied(DenialReason::Denied)),
        "the same for the model command at `src/double.rs:301`"
    );
}

/// `tests/obligations.rs:70-71` defers this crate's two authority clauses to
/// `decision-blocker:guards` "with the eleven authority clauses of
/// `contracts/obligations/sts.json`", and that document holds no eleven of anything a clause
/// could be counted by.
///
/// The counts the document supports, read off the committed file: 13 clauses defer to
/// `decision-blocker:guards`, 10 clauses name authority at all, 9 do both, and there are 52
/// clauses over 12 commands. Eleven is the number of *implemented commands* in that document
/// — the figure `contracts/obligations/README.md:76` and
/// `services/sts/tests/contract_agreement.rs:399` both use, of "the eleven STS commands" — and
/// it has been carried into a sentence that counts clauses.
///
/// This costs a reader who checks the routing the time it takes to fail to find eleven of
/// anything, and it is the class of claim ruling 3 exists for: a statement about another
/// document that the document does not make.
#[test]
fn the_document_claims_eleven_authority_clauses_and_sts_json_holds_no_such_eleven() {
    let claimed = read(OBLIGATIONS).contains(ELEVEN_CLAIM);
    let sts = read(STS);

    let deferred_to_guards = sts
        .matches("\"blocked_on\": \"decision-blocker:guards\"")
        .count();
    let clauses: Vec<&str> = sts
        .lines()
        .filter(|line| line.trim_start().starts_with("\"clause\":"))
        .collect();
    let naming_authority = clauses
        .iter()
        .filter(|line| line.contains("authority"))
        .count();

    let readings = [deferred_to_guards, naming_authority, clauses.len()];
    assert!(
        !claimed || readings.contains(&11),
        "`crates/mandate-policy/tests/obligations.rs:70-71` names \"the eleven authority \
         clauses of `contracts/obligations/sts.json`\". That document defers {deferred_to_guards} \
         clauses to `decision-blocker:guards`, {naming_authority} of its {} clauses name \
         authority at all, and 9 do both. Eleven is its implemented *command* count \
         (`contracts/obligations/README.md:76`, \"the eleven STS commands\"), not a count of \
         clauses.",
        clauses.len()
    );
}

/// `contracts/obligations/README.md:119-120` — a sentence this unit added to the registry's
/// normative document — says `mandate_identity::IdentityLog` is the only implementor of
/// `SecurityEpochWrite`, and two library targets implement it.
///
/// `crates/mandate-identity/src/port.rs:911` is one. `crates/mandate-conformance/src/external.rs:672`
/// is the other: `impl mandate_identity::SecurityEpochWrite for Substituted`, in that crate's
/// `src/`, outside its `#[cfg(test)]` module, which begins at `:1039`. The unit's own file
/// states the same shape about its own port correctly and with the qualifier that makes it
/// true — "the only implementor of that port **in a library target**"
/// (`tests/obligations.rs:15`) — and the README sentence carries no qualifier that saves it,
/// because the second implementor is in a library target too.
///
/// The sentence is the worked example for which deferral a double-backed clause takes, so a
/// reader who checks it finds an implementor the rule does not account for.
#[test]
fn the_readme_claims_one_implementor_of_security_epoch_write_and_two_ship() {
    let flattened = read(README)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let claimed = flattened.contains(ONLY_IMPLEMENTOR_CLAIM);

    let implementors = implementors_of("SecurityEpochWrite");

    assert!(
        !claimed || implementors.len() == 1,
        "`contracts/obligations/README.md:119-120` states that \
         `mandate_identity::IdentityLog` is the only implementor of `SecurityEpochWrite`. \
         {} library targets of this workspace implement it: {implementors:?}. \
         `crates/mandate-conformance/src/external.rs` is a `src/` module, not a test binary, \
         so the qualifier `tests/obligations.rs:15` uses for this crate's own port — \"in a \
         library target\" — does not rescue this sentence either.",
        implementors.len()
    );
}
