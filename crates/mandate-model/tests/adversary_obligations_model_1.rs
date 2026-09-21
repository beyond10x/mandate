//! Adversary pass 1 on `story:obligations-model`.
//!
//! `contracts/obligations/README.md` opens by stating what the registry is: "The clause-level
//! map from **every external denial an implemented command can produce** to the real-path test
//! that decides it." That is a claim in two directions, and only one of them has a reader.
//! `cargo xtask obligations-registry` walks contract → code: every clause the compiled cause
//! publishes is a clause the document carries, tiled, and either bound to a running test or
//! deferred to live work. Nothing walks code → contract, so a refusal the shipped fold produces
//! for a condition no clause publishes is invisible to every step of the gate.
//!
//! These cases walk the other direction, against the document
//! `story:obligations-model` shipped and the fold it is a claim about
//! (`crates/mandate-model/src/tenancy.rs`).
//!
//! Every case here is read-only against the implementation: it drives the shipped `decide_*`
//! and record halves and reads `contracts/obligations/model.json`,
//! `crates/mandate-model/src/tenancy.rs` and `crates/mandate-model/tests/obligations.rs` as
//! text. No implementation file is changed by this file or by the pass that wrote it.

use std::collections::BTreeSet;
use std::fs;

use mandate_model::tenancy::{MembershipAuthority, Tenancy};
use mandate_types::{
    Audience, CorrelationId, CredentialId, MembershipContributionId, OrganizationId,
    OrganizationMembershipId, PrincipalId, SpaceId, TeamId, TeamMembershipId, VerifiedContext,
};
use serde_json::Value;

/// The document `story:obligations-model` re-wrote.
const REGISTRY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../contracts/obligations/model.json"
);

/// The fold the document is a claim about.
const FOLD: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/tenancy.rs");

/// The case file `story:obligations-model` added.
const CASES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/obligations.rs");

/// The binding story every unbound clause of this crate deferred to before the unit's diff.
const BINDING: &str = "story:obligations-model";

// ==================================================================================
// Reading the document
// ==================================================================================

fn registry() -> Value {
    let text = fs::read_to_string(REGISTRY).expect("contracts/obligations/model.json is readable");
    serde_json::from_str(&text).expect("contracts/obligations/model.json is JSON")
}

fn entries(document: &Value) -> &[Value] {
    document["commands"]
        .as_array()
        .map_or(&[][..], Vec::as_slice)
}

fn clauses<'a>(document: &'a Value, command: &str) -> &'a [Value] {
    entries(document)
        .iter()
        .find(|entry| entry["command"].as_str() == Some(command))
        .map_or(&[][..], |entry| {
            entry["clauses"].as_array().map_or(&[][..], Vec::as_slice)
        })
}

/// The clauses of `command` the document states **shipped code decides**: those carrying a
/// `denial` row on the `real` path.
///
/// `contracts/obligations/README.md`: "`real` is the crate's own shipped decision path — a
/// handler, a fold, a validator — reached with a mismatched or malformed input." A clause with
/// no such row carries `blocked_on` instead, and the document's own rule for that is "Where the
/// shipped path *cannot* produce the declared denial at all, the deferral names the story that
/// owns that path instead".
fn decided_by_shipped_code(document: &Value, command: &str) -> Vec<String> {
    clauses(document, command)
        .iter()
        .filter(|clause| {
            clause["tests"]
                .as_array()
                .map_or(&[][..], Vec::as_slice)
                .iter()
                .any(|row| row["path"] == "real" && row["kind"] == "denial")
        })
        .filter_map(|clause| clause["clause"].as_str().map(str::to_owned))
        .collect()
}

/// Every clause of every command the document defers, as `(command, clause, blocked_on)`.
fn deferrals(document: &Value) -> Vec<(String, String, String)> {
    let mut rows = Vec::new();
    for entry in entries(document) {
        let Some(command) = entry["command"].as_str() else {
            continue;
        };
        for clause in entry["clauses"].as_array().map_or(&[][..], Vec::as_slice) {
            if let (Some(text), Some(id)) =
                (clause["clause"].as_str(), clause["blocked_on"].as_str())
            {
                rows.push((command.to_owned(), text.to_owned(), id.to_owned()));
            }
        }
    }
    rows
}

// ==================================================================================
// A world to drive the fold in
// ==================================================================================

fn uuid(tag: u16) -> String {
    format!("1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f{tag:04x}")
}

fn organization(tag: u16) -> OrganizationId {
    OrganizationId::parse(&uuid(tag)).expect("organization identity")
}

fn membership(tag: u16) -> OrganizationMembershipId {
    OrganizationMembershipId::parse(&uuid(tag)).expect("membership identity")
}

fn principal(tag: u16) -> PrincipalId {
    PrincipalId::parse(&uuid(tag)).expect("principal identity")
}

fn team(tag: u16) -> TeamId {
    TeamId::parse(&uuid(tag)).expect("team identity")
}

fn team_membership(tag: u16) -> TeamMembershipId {
    TeamMembershipId::parse(&uuid(tag)).expect("team membership identity")
}

fn space(tag: u16) -> SpaceId {
    SpaceId::parse(&uuid(tag)).expect("space identity")
}

fn contribution(tag: u16) -> MembershipContributionId {
    MembershipContributionId::parse(&uuid(tag)).expect("contribution identity")
}

fn acme() -> OrganizationId {
    organization(1)
}

fn other() -> OrganizationId {
    organization(2)
}

fn context(organization: OrganizationId, subject: PrincipalId) -> VerifiedContext {
    VerifiedContext {
        subject,
        actor: None,
        organization,
        audience: Audience::new("mandate"),
        credential: CredentialId::parse(&uuid(0xffff)).expect("credential identity"),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("adversary-obligations-model-1"),
    }
}

fn platform() -> VerifiedContext {
    context(organization(0xfff0), principal(0xfff1))
}

fn caller() -> VerifiedContext {
    context(acme(), principal(100))
}

/// Two organizations, each populated the way the shipped platform path populates one.
fn world() -> Tenancy {
    let mut tenancy = Tenancy::new();
    tenancy
        .create_organization(&platform(), acme(), "Acme")
        .expect("acme is created");
    tenancy
        .create_organization(&platform(), other(), "Other")
        .expect("other is created");
    for (identity, organization, subject) in [
        (membership(10), acme(), principal(100)),
        (membership(11), other(), principal(101)),
    ] {
        tenancy
            .add_organization_membership(
                &platform(),
                MembershipAuthority::PlatformOrganizationAdministration,
                identity,
                organization,
                subject,
            )
            .expect("the platform path populates each organization");
    }
    tenancy
        .create_team(&caller(), team(20), "Acme platform")
        .expect("acme holds a team");
    tenancy
        .create_space(&caller(), space(30), "Acme production")
        .expect("acme holds a space");
    tenancy
}

// ==================================================================================
// Code → contract: refusals no clause of the declared cause publishes
// ==================================================================================

/// `mandate.tenancy.CloseOrganization` refuses an organization it **holds a record of**, and
/// no clause of its declared cause publishes that condition.
///
/// `crates/mandate-model/src/tenancy.rs:701-707` admits the closure only when the record
/// exists **and** its state is `Recorded`, so a second closure of the same organization is
/// refused. The command's declared cause enumerates four conditions, and after
/// `story:obligations-model` the document itself states that three of them are decided by no
/// code this crate ships (`decision-blocker:guards`, `decision-blocker:epoch-atomicity`,
/// `decision-blocker:lifecycle`). The fourth — "the organization is unresolved" — is the one
/// clause the document marks `path: real`, and this case shows the organization resolves.
///
/// So the shipped path produces an external denial the registry maps to nothing, which is the
/// direction `contracts/obligations/README.md:1` claims to cover and no gate step reads.
///
/// Pinned by the coordinator to the shipped record on 2026-09-21 (`review-result:wave-d-obligations-model-adversary-1` F1): the
/// refusal is the command's declared `wrong-state` outcome, which the registry does not read;
/// no `denied` clause publishes it. `story:unpublished-refusals` gives `wrong-state` outcomes
/// rows and checks every refusal site against a published outcome; the assertion flips there.
#[test]
fn close_organization_refuses_on_a_condition_no_clause_of_its_declared_cause_publishes() {
    let mut tenancy = world();
    tenancy
        .close_organization(&platform(), acme())
        .expect("acme closes once");

    let before = tenancy.clone();
    let refusal = tenancy.close_organization(&platform(), acme());
    assert!(
        refusal.is_err(),
        "the fold refuses a second closure of one organization"
    );
    assert_eq!(
        tenancy, before,
        "the refused second closure moved the projection"
    );

    // The organization the fold refused to close is one it holds a record of, so the only
    // clause of this command the document marks `real` — "the organization is unresolved" —
    // is not the condition that fired.
    assert!(
        tenancy.organization(acme()).is_some(),
        "the fold still holds the record of the organization it refused to close"
    );

    let document = registry();
    let decided = decided_by_shipped_code(&document, "mandate.tenancy.CloseOrganization");
    let applicable: Vec<&String> = decided
        .iter()
        .filter(|clause| !clause.contains("unresolved"))
        .collect();

    assert!(
        applicable.is_empty(),
        "a denied clause of mandate.tenancy.CloseOrganization now accounts for a second closure \
         ({applicable:?}); story:unpublished-refusals landed and this pin is stale. Shipped \
         record: crates/mandate-model/src/tenancy.rs:706 refuses mandate.tenancy.CloseOrganization for \
         an organization the fold resolves — a second closure — and no clause of the command's \
         declared cause accounts for it. contracts/obligations/model.json marks exactly one \
         clause of this command as decided by shipped code, {decided:?}, and the record \
         resolves; every other clause carries blocked_on, which is the document's own statement \
         that no code this crate ships decides it. contracts/obligations/README.md:1 states the \
         registry is the map from *every* external denial an implemented command can produce, \
         and `cargo xtask obligations-registry` only walks contract to code, so this refusal is \
         published by nothing and countable by nothing."
    );
}

/// `mandate.tenancy.RetireTeam` refuses a team **inside** the verified organization, and no
/// clause of its declared cause publishes that condition.
///
/// `crates/mandate-model/src/tenancy.rs:932-935` refuses a team whose state is no longer
/// `Recorded`, and the one clause the document marks `path: real` for this command is "the
/// team is outside the verified organization". This case shows the refused team is inside it.
///
/// Pinned by the coordinator to the shipped record on 2026-09-21 (`review-result:wave-d-obligations-model-adversary-1` F2): the
/// refusal is the command's declared `wrong-state` outcome; no `denied` clause publishes it.
/// `story:unpublished-refusals` owns it; the assertion flips there.
#[test]
fn retire_team_refuses_a_team_inside_the_verified_organization_that_no_clause_publishes() {
    let mut tenancy = world();
    tenancy
        .retire_team(&caller(), team(20))
        .expect("the team retires once");

    let before = tenancy.clone();
    let refusal = tenancy.retire_team(&caller(), team(20));
    assert!(
        refusal.is_err(),
        "the fold refuses a second retirement of one team"
    );
    assert_eq!(
        tenancy, before,
        "the refused second retirement moved the projection"
    );

    let record = tenancy.team(team(20)).expect("the fold holds the team");
    assert_eq!(
        record.organization_id,
        caller().organization,
        "the refused team is inside the verified organization"
    );

    let document = registry();
    let decided = decided_by_shipped_code(&document, "mandate.tenancy.RetireTeam");
    let applicable: Vec<&String> = decided
        .iter()
        .filter(|clause| !clause.contains("outside the verified organization"))
        .collect();

    assert!(
        applicable.is_empty(),
        "a denied clause of mandate.tenancy.RetireTeam now accounts for an already-retired team \
         ({applicable:?}); story:unpublished-refusals landed and this pin is stale. Shipped \
         record: crates/mandate-model/src/tenancy.rs:934 refuses mandate.tenancy.RetireTeam for a team \
         the fold holds inside the verified organization — one already retired — and no clause \
         of the command's declared cause accounts for it. contracts/obligations/model.json \
         marks exactly one clause of this command as decided by shipped code, {decided:?}, and \
         the team is not outside the verified organization; its other three clauses carry \
         blocked_on."
    );
}

/// The three creating commands refuse, and `contracts/obligations/model.json` states that no
/// code this crate ships decides **any** clause they publish.
///
/// After `story:obligations-model`, `CreateOrganization`, `CreateTeam` and `CreateSpace` each
/// carry three clauses and three deferrals — `real_covered: 0` for all three commands — while
/// their shipped `decide_*` halves refuse an identity the fold already holds
/// (`crates/mandate-model/src/tenancy.rs:661`, `:894`, `:1083`) and, for two of them, a
/// verified organization that does not admit authority. A command whose every published clause
/// is deferred and whose shipped path still refuses is a command the registry accounts for in
/// neither direction.
///
/// Pinned by the coordinator to the shipped record on 2026-09-21 (`review-result:wave-d-obligations-model-adversary-1` F3): all
/// three creators refuse an already-recorded identity, and no published outcome names it —
/// the creators declare no `wrong-state` outcome. `story:unpublished-refusals` gives the
/// condition a home in the specification; the assertion flips there.
#[test]
fn the_creating_commands_refuse_although_the_document_defers_every_clause_they_publish() {
    let tenancy = world();
    let document = registry();

    let refused: [(&str, bool); 3] = [
        (
            "mandate.tenancy.CreateOrganization",
            tenancy
                .decide_create_organization(&platform(), acme(), "Acme again")
                .is_err(),
        ),
        (
            "mandate.tenancy.CreateTeam",
            tenancy
                .decide_create_team(&caller(), team(20), "Acme platform again")
                .is_err(),
        ),
        (
            "mandate.tenancy.CreateSpace",
            tenancy
                .decide_create_space(&caller(), space(30), "Acme production again")
                .is_err(),
        ),
    ];

    let unaccounted: Vec<&str> = refused
        .iter()
        .filter(|(_, denied)| *denied)
        .map(|(command, _)| *command)
        .filter(|command| decided_by_shipped_code(&document, command).is_empty())
        .collect();

    assert_eq!(
        unaccounted.len(),
        3,
        "a creator's refusal is now published ({unaccounted:?} still unaccounted); \
         story:unpublished-refusals landed and this pin is stale. Shipped record: each creator \
         is `implemented`, its shipped decide half refuses an identity \
         the fold already holds, and contracts/obligations/model.json states that every clause \
         of its declared cause is decided by no code this crate ships. The refusal these \
         commands do produce — an already-recorded identity — is published by no clause, so it \
         is in neither the numerator nor the denominator of \
         contracts/conformance/obligations-report.json."
    );
}

// ==================================================================================
// The document against the fold's own record of what it does not realize
// ==================================================================================

/// Every `(command, clause, owner)` the fold's own "Every denial clause this fold does not
/// realize" section enumerates.
///
/// The section groups its bullets under ``## Owed to `<owner>` — <count>`` subheadings and
/// writes each bullet as ``* `<command>` — "<clause>"``, wrapped at the file's comment width.
/// A bullet broken across lines is read with its line breaks collapsed to single spaces, which
/// is the rule the section states for itself. The section ends at the next top-level heading.
fn unrealized(fold: &str) -> BTreeSet<(String, String, String)> {
    const HEADING: &str = "# Every denial clause this fold does not realize";

    let mut rows = BTreeSet::new();
    let mut owner = String::new();
    let mut bullet: Option<String> = None;
    let mut inside = false;

    for line in fold.lines() {
        let Some(body) = line.strip_prefix("//!") else {
            if inside {
                break;
            }
            continue;
        };
        let body = body.trim();

        if body == HEADING {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        if body.starts_with("# ") {
            break;
        }

        if let Some(rest) = body.strip_prefix("* ") {
            if let Some(done) = bullet.replace(rest.to_owned()) {
                insert(&mut rows, &owner, &done);
            }
        } else if body.is_empty() || body.starts_with("## ") {
            if let Some(done) = bullet.take() {
                insert(&mut rows, &owner, &done);
            }
            if let Some(heading) = body.strip_prefix("## Owed to ") {
                owner = heading.split('`').nth(1).unwrap_or_default().to_owned();
            }
        } else if let Some(open) = bullet.as_mut() {
            open.push(' ');
            open.push_str(body);
        }
    }
    if let Some(done) = bullet.take() {
        insert(&mut rows, &owner, &done);
    }
    rows
}

/// One bullet, ``* `<command>` — "<clause>"``, under the owner its group names.
fn insert(rows: &mut BTreeSet<(String, String, String)>, owner: &str, bullet: &str) {
    let mut parts = bullet.splitn(3, '`');
    let (Some(""), Some(command), Some(rest)) = (parts.next(), parts.next(), parts.next()) else {
        return;
    };
    let (Some(open), Some(close)) = (rest.find('"'), rest.rfind('"')) else {
        return;
    };
    if close > open {
        rows.insert((
            command.to_owned(),
            rest[open + 1..close].to_owned(),
            owner.to_owned(),
        ));
    }
}

/// Every clause the unit re-pointed off the binding story is a clause the fold's own module
/// documentation says it does not realize, and every clause that documentation lists is one
/// the record defers to the owner it names.
///
/// `crates/mandate-model/src/tenancy.rs` carries a section headed "Every denial clause this
/// fold does not realize", whose second sentence is "These are all of them, and nothing else
/// in `tenancy.yaml` is unrealized here". That sentence is a claim of completeness against
/// `contracts/obligations/model.json`, which carries the same set as `blocked_on` rows.
///
/// Before the unit's diff every unbound clause of this crate deferred to
/// `story:obligations-model` — a statement that a test was owed, not that the code could not
/// produce the denial. The diff converts twenty-nine of them into deferrals to blockers and to
/// other stories, which is the document's positive claim that **this crate ships no code that
/// decides them** (`contracts/obligations/README.md`, "Where the shipped path *cannot* produce
/// the declared denial at all, the deferral names the story that owns that path instead").
///
/// This case reads the fold's section rather than holding its own copy of it. The copy is the
/// defect the first round of this case was an instance of: a hand-held list of five went stale
/// the moment the registry re-pointed a clause, and only an adversary reading both documents
/// could have extended it. Parsed, the two documents are compared in both directions — a
/// deferral the section omits, and a bullet the record does not defer to the owner the group
/// names — so neither can move again without the other.
#[test]
fn every_clause_re_pointed_off_the_binding_story_is_one_the_fold_records_as_unrealized() {
    let fold = fs::read_to_string(FOLD).expect("crates/mandate-model/src/tenancy.rs is readable");
    assert!(
        fold.contains("These are all of them, and nothing else in `tenancy.yaml` is unrealized"),
        "the fold no longer claims its list of unrealized clauses is complete; this case is \
         about that claim and has to be re-read if it goes"
    );

    let recorded = unrealized(&fold);
    assert!(
        !recorded.is_empty(),
        "the fold's section enumerates no clause this case can read. It is parsed as \
         ``* `<command>` — \"<clause>\"`` bullets under ``## Owed to `<owner>``` subheadings, \
         and an empty parse would compare two empty sets and pass while checking nothing"
    );

    let document = registry();
    let deferred: BTreeSet<(String, String, String)> = deferrals(&document)
        .into_iter()
        .filter(|(_, _, blocked_on)| blocked_on != BINDING)
        .collect();

    let missing: Vec<String> = deferred
        .difference(&recorded)
        .map(|(command, clause, owner)| format!("{command} :: {clause:?} -> {owner}"))
        .collect();
    let unclaimed: Vec<String> = recorded
        .difference(&deferred)
        .map(|(command, clause, owner)| format!("{command} :: {clause:?} -> {owner}"))
        .collect();

    assert!(
        missing.is_empty() && unclaimed.is_empty(),
        "contracts/obligations/model.json and the \"Every denial clause this fold does not \
         realize\" section of crates/mandate-model/src/tenancy.rs disagree, while that section \
         says \"These are all of them\".\n  \
         {} deferred by the record and not enumerated by the fold:\n  {}\n  \
         {} enumerated by the fold and not deferred to that owner by the record:\n  {}",
        missing.len(),
        missing.join("\n  "),
        unclaimed.len(),
        unclaimed.join("\n  ")
    );
}

/// The one `AddTeamMembership` clause the document marks `path: real` bundles a condition the
/// case backing it disclaims in writing.
///
/// The clause is "team or principal is unresolved or outside the verified organization" and
/// the row is `path: real` with no `blocked_on`, so the document publishes the whole clause —
/// the principal half included — as decided on the shipped path. The case that row names says
/// the opposite in its own doc comment: "The principal half of the clause is not decided here
/// and is not claimed to be". [`Tenancy`] holds no principal projection, so it answers
/// identically for a principal other records in the world name and for one nothing names.
///
/// `contracts/obligations/README.md` states the rule this breaks: "where two conditions of one
/// clause have different deciders, the clause is split into those conditions", with
/// `mandate.graph.RegisterResource` as the worked example. The clause is one substring short of
/// being splittable — `or` is an admitted joiner, so "team" and "principal is unresolved or
/// outside the verified organization" tile the cause — and splitting it would move
/// `real_covered` for `mandate-model` from 12 to 12 with one more clause deferred, or leave it
/// at 12 over 41 rather than 40.
#[test]
fn the_add_team_membership_clause_marked_real_bundles_a_condition_its_own_case_disclaims() {
    let cases = fs::read_to_string(CASES).expect("crates/mandate-model/tests/obligations.rs");
    assert!(
        cases.contains("The principal half of the clause is not decided here and is not claimed"),
        "the case that backs the clause no longer disclaims its principal half; this case is \
         about that disclaimer and has to be re-read if it goes"
    );

    // The fold holds no principal record, so "the principal is unresolved" has no input that
    // varies: a principal another organization's membership names and a principal nothing in
    // the world names are one answer.
    let mut tenancy = world();
    let known = tenancy.add_team_membership(
        &caller(),
        team_membership(60),
        team(20),
        principal(101),
        contribution(70),
    );
    let unknown = tenancy.add_team_membership(
        &caller(),
        team_membership(60),
        team(20),
        principal(0x7ffd),
        contribution(70),
    );
    assert_eq!(
        known.is_err(),
        unknown.is_err(),
        "the fold distinguishes a principal it has a record of from one it has not"
    );

    let document = registry();
    let clause = "team or principal is unresolved or outside the verified organization";
    let decided = decided_by_shipped_code(&document, "mandate.tenancy.AddTeamMembership");

    assert!(
        !decided.iter().any(|text| text == clause),
        "contracts/obligations/model.json publishes {clause:?} as decided on the real path by \
         mandate-model::obligations::a_team_membership_of_an_unresolved_team_or_of_a_team_in_\
         another_organization_is_refused, and that case's own doc comment says its principal \
         half is not decided and is not claimed to be. crates/mandate-model/src/tenancy.rs holds \
         no principal projection, so nothing in this crate decides whether a principal resolves \
         and the two calls above answer identically. contracts/obligations/README.md requires a \
         clause whose conditions have different deciders to be split into them; unsplit, the row \
         counts a condition with no decider in real_covered."
    );
}
