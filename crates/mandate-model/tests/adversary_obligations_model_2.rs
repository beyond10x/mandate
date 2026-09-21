//! Adversary pass 2 on `story:obligations-model`, after correction 1.
//!
//! Three cases, against the tree as correction 1 left it. Each reads a document the unit
//! wrote about itself and drives it against the code the same unit wrote; none changes an
//! implementation file, and none edits an existing case.
//!
//! # What each case is about
//!
//! * **The guard citations.** `crates/mandate-model/tests/obligations.rs` opens with a table
//!   headed "What is bound here", one row per clause the unit moved to `path: real`, and each
//!   row names the line span of `crates/mandate-model/src/tenancy.rs` that decides it. Those
//!   spans were written against the fold as it stood at the unit's base commit. The unit's own
//!   diff, and correction 1's rewrite of the "Every denial clause this fold does not realize"
//!   section on top of it, added seventy-three net lines **above** every one of them, so every
//!   span now names other code. [`every_guard_citation_in_the_case_file_points_inside_the_deciding_function`]
//!   decides this without a table of its own: it derives the deciding function of each row's
//!   command from the fold's own source and asks whether the cited span lies inside it.
//!
//! * **The quotations.** The same file quotes the fold's module documentation and attributes
//!   each quotation to a line span. Correction 1 reworded the sentence one of them quotes, so
//!   the quotation is now neither inside the span it names nor anywhere in the file.
//!   [`every_fold_quotation_in_the_case_file_is_verbatim_where_it_is_cited`] decides it.
//!
//! * **The authority conjunct.** `contracts/obligations/model.json` marks
//!   `mandate.tenancy.AddOrganizationMembership`'s clause "organization_id differs from the
//!   verified organization **and the caller lacks platform organization-administration
//!   authority**" as decided on the real path, in the same command entry in which it defers
//!   "Caller lacks membership-administration authority" to `decision-blocker:guards` — and the
//!   fold's own reason for that deferral is that authority "is `mandate-authz`'s and is decided
//!   nowhere here". Both statements rest on [`MembershipAuthority`], which is unvalidated
//!   caller input. [`the_add_organization_membership_clause_marked_real_bundles_an_undecided_authority_conjunct`]
//!   drives the fold to show it, then reads the record.
//!
//! No case here is a claim that the unit is correct or incorrect; each is a claim that one
//! stated fact is false, and each fails if it is.

use std::fs;

use mandate_model::tenancy::{MembershipAuthority, Tenancy};
use mandate_types::{
    Audience, CorrelationId, CredentialId, OrganizationId, OrganizationMembershipId, PrincipalId,
    VerifiedContext,
};
use serde_json::Value;

/// The document `story:obligations-model` re-wrote.
const REGISTRY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../contracts/obligations/model.json"
);

/// The fold every citation below points into.
const FOLD: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/tenancy.rs");

/// The case file `story:obligations-model` added, read as text.
const CASES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/obligations.rs");

/// How every citation in the case file names the fold.
const MARKER: &str = "src/tenancy.rs:";

// ==================================================================================
// Reading the two documents
// ==================================================================================

fn registry() -> Value {
    let text = fs::read_to_string(REGISTRY).expect("contracts/obligations/model.json is readable");
    serde_json::from_str(&text).expect("contracts/obligations/model.json is JSON")
}

fn cases() -> String {
    fs::read_to_string(CASES).expect("crates/mandate-model/tests/obligations.rs is readable")
}

fn fold() -> String {
    fs::read_to_string(FOLD).expect("crates/mandate-model/src/tenancy.rs is readable")
}

/// One row of the case file's "What is bound here" table.
struct Citation {
    /// The command the row names, as the table writes it — without the domain prefix.
    command: String,
    /// The clause the row names.
    clause: String,
    /// The first line of the cited span.
    first: usize,
    /// The last line of the cited span.
    last: usize,
    /// The symbol the row names beside the span, where it names one.
    symbol: Option<String>,
}

/// Every `command`/`clause`/`span` row of the case file's guard table.
///
/// A row is a module-documentation line whose cells are `|`-separated and whose guard cell
/// names the fold. The header and its rule carry no citation and are skipped by that test
/// alone, so the parse states no list of its own.
fn guard_table(source: &str) -> Vec<Citation> {
    let mut rows = Vec::new();
    for line in source.lines() {
        let Some(body) = line.trim_start().strip_prefix("//!") else {
            continue;
        };
        let body = body.trim();
        if !body.starts_with('|') || !body.contains(MARKER) {
            continue;
        }
        let cells: Vec<&str> = body.split('|').map(str::trim).collect();
        if cells.len() < 5 {
            continue;
        }
        let Some((first, last)) = span_of(cells[3]) else {
            continue;
        };
        rows.push(Citation {
            command: cells[1].trim_matches('`').to_owned(),
            clause: cells[2].to_owned(),
            first,
            last,
            symbol: symbol_of(cells[3]),
        });
    }
    rows
}

/// The line span a citation names: `src/tenancy.rs:917` is one line, `:911-914` is four.
fn span_of(cell: &str) -> Option<(usize, usize)> {
    let at = cell.find(MARKER)? + MARKER.len();
    let digits: String = cell[at..]
        .chars()
        .take_while(|character| character.is_ascii_digit() || *character == '-')
        .collect();
    let mut parts = digits.splitn(2, '-');
    let first: usize = parts.next()?.parse().ok()?;
    let last: usize = parts.next().map_or(Ok(first), str::parse).ok()?;
    Some((first, last))
}

/// The symbol a row names after its span, as in ``` `src/tenancy.rs:917`, `holds_team_membership` ```.
fn symbol_of(cell: &str) -> Option<String> {
    let after = cell.split_once(MARKER)?.1;
    let rest = after.split_once('`')?.1;
    let open = rest.find('`')? + 1;
    let close = rest[open..].find('`')? + open;
    Some(rest[open..close].to_owned())
}

/// `AddOrganizationMembership` reads as `add_organization_membership`.
fn snake(name: &str) -> String {
    let mut out = String::new();
    for (index, character) in name.chars().enumerate() {
        if character.is_ascii_uppercase() {
            if index > 0 {
                out.push('_');
            }
            out.push(character.to_ascii_lowercase());
        } else {
            out.push(character);
        }
    }
    out
}

/// The line span of one `pub fn` of the fold's `impl Tenancy` block, inclusive and 1-based.
fn function_span(lines: &[&str], name: &str) -> Option<(usize, usize)> {
    let opening = format!("    pub fn {name}(");
    let start = lines.iter().position(|line| line.starts_with(&opening))?;
    let end = lines[start..].iter().position(|line| *line == "    }")? + start;
    Some((start + 1, end + 1))
}

/// The halves of the fold that decide one command: `decide_<command>` and, where the fold
/// splits the authority rule out, `may_<command>`.
fn deciders(lines: &[&str], command: &str) -> Vec<(String, usize, usize)> {
    let stem = snake(command);
    ["decide_", "may_"]
        .iter()
        .filter_map(|prefix| {
            let name = format!("{prefix}{stem}");
            function_span(lines, &name).map(|(first, last)| (name, first, last))
        })
        .collect()
}

/// One span of the fold, with its comment markers stripped and its whitespace collapsed.
fn span_text(lines: &[&str], first: usize, last: usize) -> String {
    let end = last.min(lines.len());
    let joined: Vec<&str> = lines[first - 1..end]
        .iter()
        .map(|line| line.trim().trim_start_matches("//!").trim())
        .collect();
    normalized(&joined.join(" "))
}

fn normalized(text: &str) -> String {
    text.split_whitespace().collect::<Vec<&str>>().join(" ")
}

// ==================================================================================
// The guard table against the fold it cites
// ==================================================================================

/// Every span the case file's guard table cites lies inside a half of the fold that decides
/// the command the row names, and contains the symbol the row names beside it.
///
/// `crates/mandate-model/tests/obligations.rs` states, under "What is bound here", one row per
/// clause the unit moved to `path: real`, each naming the guard that decides it —
/// ``| `AddTeamMembership` | the principal is already a member of that team |
/// `src/tenancy.rs:917`, `holds_team_membership` |``. A row is the unit's evidence that the
/// clause is decided by shipped code and that a reader can find the decision; the registry
/// step reads none of them, so nothing but this compares the citation with the file.
///
/// The spans were written against `crates/mandate-model/src/tenancy.rs` at the unit's base
/// commit, which is 1469 lines. The unit's own diff and correction 1's rewrite of the "Every
/// denial clause this fold does not realize" section together add seventy-three net lines
/// above every guard in the `impl Tenancy` block, leaving the file at 1542. Every span in the
/// table is therefore short by exactly that, and each now names unrelated code: `:676-680`,
/// cited for the authority rule of [`Tenancy::may_add_organization_membership`], is the
/// signature of `create_organization`; `:917`, cited for `holds_team_membership`, is
/// `self.apply(&event);` inside `create_team`.
///
/// This case derives the answer rather than holding a table of its own: for each row it
/// snake-cases the command, finds `decide_<command>` and `may_<command>` in the fold, and asks
/// whether the cited span lies inside one of them. A citation that moves with the code passes;
/// one that has been left behind does not.
#[test]
fn every_guard_citation_in_the_case_file_points_inside_the_deciding_function() {
    let cases = cases();
    let fold = fold();
    let lines: Vec<&str> = fold.lines().collect();
    let rows = guard_table(&cases);

    assert!(
        rows.len() >= 10,
        "the guard table of crates/mandate-model/tests/obligations.rs parsed as {} rows. It is \
         read as module-documentation lines whose cells are `|`-separated and whose third cell \
         names {MARKER}, and a parse that finds nothing would compare nothing and pass",
        rows.len()
    );

    let mut stale = Vec::new();
    for row in &rows {
        let halves = deciders(&lines, &row.command);
        assert!(
            !halves.is_empty(),
            "no decide_ or may_ half of crates/mandate-model/src/tenancy.rs answers to {}; the \
             command column of the guard table no longer names a command the fold decides",
            row.command
        );
        let inside = halves
            .iter()
            .any(|(_, first, last)| row.first >= *first && row.last <= *last);
        let carries = row
            .symbol
            .as_ref()
            .is_none_or(|symbol| span_text(&lines, row.first, row.last).contains(symbol.as_str()));
        if inside && carries {
            continue;
        }
        let where_they_are: Vec<String> = halves
            .iter()
            .map(|(name, first, last)| format!("{name} is :{first}-{last}"))
            .collect();
        stale.push(format!(
            "{} :: {} cites :{}-{}{}, which holds {:?}; {}",
            row.command,
            row.clause,
            row.first,
            row.last,
            row.symbol
                .as_ref()
                .map_or(String::new(), |symbol| format!(" and names `{symbol}`")),
            span_text(&lines, row.first, row.last),
            where_they_are.join(", ")
        ));
    }

    assert!(
        stale.is_empty(),
        "{} of the {} rows of the \"What is bound here\" table in \
         crates/mandate-model/tests/obligations.rs cite a span of \
         crates/mandate-model/src/tenancy.rs that is not inside the half of the fold deciding \
         the command the row names. The unit's diff and correction 1's rewrite of the fold's \
         module documentation added seventy-three net lines above the `impl Tenancy` block \
         without moving the citations, so the file's own record of where each clause is decided \
         points at other code:\n  {}",
        stale.len(),
        rows.len(),
        stale.join("\n  ")
    );
}

// ==================================================================================
// The quotations against the source they are attributed to
// ==================================================================================

/// Every citation of the form ``` `src/tenancy.rs:A-B`: "…" ``` in the case file, as
/// `(first, last, quotation)`.
fn attributed(doc: &str) -> Vec<(usize, usize, String)> {
    let mut rows = Vec::new();
    let mut cursor = 0;
    while let Some(found) = doc[cursor..].find(MARKER) {
        let at = cursor + found + MARKER.len();
        let digits: String = doc[at..]
            .chars()
            .take_while(|character| character.is_ascii_digit() || *character == '-')
            .collect();
        cursor = at + digits.len();
        let Some(rest) = doc[cursor..].strip_prefix("`: \"") else {
            continue;
        };
        let Some(close) = rest.find('"') else {
            continue;
        };
        let mut parts = digits.splitn(2, '-');
        let Some(Ok(first)) = parts.next().map(str::parse::<usize>) else {
            continue;
        };
        let last = parts
            .next()
            .map_or(Ok(first), str::parse::<usize>)
            .unwrap_or(first);
        rows.push((first, last, rest[..close].to_owned()));
    }
    rows
}

/// The module documentation of the case file, with its comment markers stripped and its
/// whitespace collapsed, so a quotation wrapped across lines reads as one run.
fn module_doc(source: &str) -> String {
    let mut text = String::new();
    for line in source.lines() {
        if let Some(body) = line.trim_start().strip_prefix("//!") {
            if !text.is_empty() {
                text.push(' ');
            }
            text.push_str(body.trim());
        }
    }
    normalized(&text)
}

/// Every quotation the case file attributes to a span of the fold is verbatim in that span.
///
/// `crates/mandate-model/tests/obligations.rs` justifies each of its twenty-nine deferrals by
/// quoting the fold and naming the line span the quotation is from, in the form
/// ``` `src/tenancy.rs:79-91`: "this crate does not close the window between a decision and
/// the append that follows it…" ```. That is the citation `story:obligations-model` is
/// measured by — a deferral is admitted when the source says what it is cited for — and no
/// step reads it.
///
/// Correction 1 rewrote the fold's "Every denial clause this fold does not realize" section
/// and, in rewriting it, reworded the sentence the display-name deferral quotes. The fold now
/// says "no admission rule for a display name exists to implement"; the case file still quotes
/// "No admission rule exists to implement", attributed to `src/tenancy.rs:113-118`, which
/// after the rewrite is the section's own "a clause is listed here exactly when it carries
/// `blocked_on` there" paragraph. So the quotation is in neither the span it names nor
/// anywhere else in the file, and the deferral of the three display-name clauses to
/// `decision-blocker:guards` rests on a sentence the fold does not contain.
///
/// This case asserts both halves separately, because they are different defects: a quotation
/// in the wrong span is a stale line number, and a quotation in no span at all is a statement
/// attributed to a source that never made it.
#[test]
fn every_fold_quotation_in_the_case_file_is_verbatim_where_it_is_cited() {
    let cases = cases();
    let fold = fold();
    let lines: Vec<&str> = fold.lines().collect();
    let whole = normalized(
        &lines
            .iter()
            .map(|line| line.trim().trim_start_matches("//!").trim())
            .collect::<Vec<&str>>()
            .join(" "),
    );

    let quotations = attributed(&module_doc(&cases));
    assert!(
        !quotations.is_empty(),
        "no quotation of crates/mandate-model/src/tenancy.rs in \
         crates/mandate-model/tests/obligations.rs parsed. They are read in the form \
         `{MARKER}A-B`: \"…\", and a parse that finds none would check nothing and pass"
    );

    let mut misplaced = Vec::new();
    let mut absent = Vec::new();
    for (first, last, quotation) in &quotations {
        let wanted = normalized(quotation);
        if span_text(&lines, *first, *last).contains(&wanted) {
            continue;
        }
        if whole.contains(&wanted) {
            misplaced.push(format!(
                ":{first}-{last} is quoted as {quotation:?}, which the file holds elsewhere"
            ));
        } else {
            absent.push(format!(
                ":{first}-{last} is quoted as {quotation:?}, which the file does not hold at all"
            ));
        }
    }

    assert!(
        misplaced.is_empty() && absent.is_empty(),
        "crates/mandate-model/tests/obligations.rs attributes {} quotation(s) to \
         crates/mandate-model/src/tenancy.rs and {} of them are not in the span named.\n  \
         {} in the wrong span:\n  {}\n  {} in no span, so the source does not say what it is \
         cited for:\n  {}",
        quotations.len(),
        misplaced.len() + absent.len(),
        misplaced.len(),
        misplaced.join("\n  "),
        absent.len(),
        absent.join("\n  ")
    );
}

// ==================================================================================
// The one `real` row whose clause names a condition the fold does not decide
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

fn context(organization: OrganizationId, subject: PrincipalId) -> VerifiedContext {
    VerifiedContext {
        subject,
        actor: None,
        organization,
        audience: Audience::new("mandate"),
        credential: CredentialId::parse(&uuid(0xfffe)).expect("credential identity"),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("adversary-2"),
    }
}

/// The clauses of `command` the record states shipped code decides: those carrying a `denial`
/// row on the `real` path.
fn decided_by_shipped_code(document: &Value, command: &str) -> Vec<String> {
    document["commands"]
        .as_array()
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .find(|entry| entry["command"].as_str() == Some(command))
        .map_or(&[][..], |entry| {
            entry["clauses"].as_array().map_or(&[][..], Vec::as_slice)
        })
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

/// Where `command` defers the clause `clause`, if it defers it.
fn deferral(document: &Value, command: &str, clause: &str) -> Option<String> {
    document["commands"]
        .as_array()?
        .iter()
        .find(|entry| entry["command"].as_str() == Some(command))?["clauses"]
        .as_array()?
        .iter()
        .find(|row| row["clause"].as_str() == Some(clause))?["blocked_on"]
        .as_str()
        .map(str::to_owned)
}

/// The `AddOrganizationMembership` clause the unit moved to `path: real` bundles a condition
/// the fold decides nowhere, and the same document defers that condition's sibling for exactly
/// that reason.
///
/// The clause is "organization_id differs from the verified organization **and the caller
/// lacks platform organization-administration authority**". The unit gave it a `path: real`
/// `denial` row and removed its `blocked_on`, so
/// `contracts/conformance/obligations-report.json` counts the whole clause — the authority
/// conjunct included — in `real_covered` for `mandate-model`.
///
/// One entry above it in the same command, "Caller lacks membership-administration authority"
/// is deferred to `decision-blocker:guards`, and `crates/mandate-model/src/tenancy.rs` gives
/// the reason: whether a caller holds the authority a command names "is `mandate-authz`'s and
/// is decided nowhere here; [`MembershipAuthority`] is the caller's statement of which of the
/// contract's two paths it was admitted to, not a grant". Both statements rest on the same
/// enum value. The fold reads it once, in
/// [`Tenancy::may_add_organization_membership`], and validates it against nothing: a caller
/// whose own organization the projection does not hold, who holds no membership and whom no
/// record mentions, writes a membership into another organization by naming
/// `PlatformOrganizationAdministration`. That is what the first half of this case drives.
///
/// `contracts/obligations/README.md` states the rule: "where two conditions of one clause have
/// different deciders, the clause is split into those conditions", each still a verbatim
/// substring and the set still tiling the cause. Correction 1 applied that rule to
/// `AddTeamMembership`, splitting "team or principal is unresolved or outside the verified
/// organization" into the half the fold decides and the half it does not. This clause is the
/// same shape and was not split: "organization_id differs from the verified organization" and
/// "the caller lacks platform organization-administration authority" are both verbatim
/// substrings, `and` is an admitted joiner, and the two tile the position the one clause
/// holds now.
///
/// The counter-reading is that the cause joins the two with `and` rather than `or`, so they
/// are one conjunction and not two conditions. It does not rescue the row: the conjunct the
/// fold evaluates is the caller's own claim, so what the case backing the row establishes is
/// that the fold refuses a caller that *says* it lacks platform authority — not that it
/// refuses a caller that lacks it.
#[test]
fn the_add_organization_membership_clause_marked_real_bundles_an_undecided_authority_conjunct() {
    let fold = normalized(&fold().replace("//!", " "));
    assert!(
        fold.contains("is `mandate-authz`'s and is decided nowhere here"),
        "crates/mandate-model/src/tenancy.rs no longer states that a caller's authority is \
         decided nowhere in this crate; this case is about that statement and has to be \
         re-read if it goes"
    );

    // The fold validates `MembershipAuthority` against nothing. This caller's organization is
    // not a record the projection holds, it holds no membership, and nothing in the world
    // names it; naming the platform path is all it does.
    let mut tenancy = Tenancy::new();
    let platform = context(organization(0xfff0), principal(0xfff1));
    let acme = organization(1);
    tenancy
        .create_organization(&platform, acme, "Acme")
        .expect("acme is created");

    let stranger = context(organization(0x7f00), principal(0x7f01));
    assert!(
        tenancy.organization(stranger.organization).is_none(),
        "the caller's own organization is a record the fold does not hold"
    );
    tenancy
        .add_organization_membership(
            &stranger,
            MembershipAuthority::PlatformOrganizationAdministration,
            membership(0x50),
            acme,
            principal(0x7f02),
        )
        .expect(
            "the fold admits the platform path on the caller's word alone, so it decides \
             nothing about whether the caller holds platform organization-administration \
             authority",
        );

    let document = registry();
    let command = "mandate.tenancy.AddOrganizationMembership";
    let sibling = "Caller lacks membership-administration authority";
    assert_eq!(
        deferral(&document, command, sibling).as_deref(),
        Some("decision-blocker:guards"),
        "the document no longer defers {sibling:?} to decision-blocker:guards; this case is \
         about the two clauses disagreeing and has to be re-read if that changes"
    );

    let bundled: Vec<String> = decided_by_shipped_code(&document, command)
        .into_iter()
        .filter(|clause| clause.contains("lacks platform organization-administration authority"))
        .collect();

    assert!(
        bundled.is_empty(),
        "contracts/obligations/model.json marks {bundled:?} as decided on the real path for \
         {command}, and half of that clause — \"the caller lacks platform \
         organization-administration authority\" — is decided by no code this crate ships. The \
         call above proves it: a caller the projection holds no record of wrote a membership \
         into another organization by naming MembershipAuthority::\
         PlatformOrganizationAdministration, which crates/mandate-model/src/tenancy.rs \
         validates against nothing and documents as \"the caller's statement … not a grant\". \
         The same document defers this command's {sibling:?} to decision-blocker:guards for \
         that reason, so one entry counts the authority decision in real_covered and the entry \
         above it counts the same decision as unshipped. contracts/obligations/README.md \
         requires a clause whose conditions have different deciders to be split into them; \
         correction 1 split mandate.tenancy.AddTeamMembership's clause on that rule and left \
         this one."
    );
}
