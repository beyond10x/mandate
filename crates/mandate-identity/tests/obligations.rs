//! The denial clauses of `mandate.identity` that `contracts/obligations/identity.json`
//! carried unbound, each driven to exactly the clause it names.
//!
//! `story:obligation-registry` split every implemented command's declared `condition.cause`
//! into its clauses and bound the four an existing case already decided. Eight were left
//! `blocked_on: story:obligations-identity`, which is this file. A case here asserts both
//! halves of the refusal: the contract's `mandate.core.DenialReason` and [`RefusedOutcome`],
//! the crate's discriminator for *which* declared error outcome fired. Asserting the reason
//! alone would let a clause be satisfied by any refusal of the command, and `denied` and
//! `wrong-state` render as different statuses (`docs/architecture/command-obligations.md`).
//!
//! # What is bound here, and on which path
//!
//! * `RevokeSession`, "session is outside the verified organization" — the **real** path.
//!   `crates/mandate-identity/src/session.rs:369` is handler code over the fold, and the one
//!   place in this crate that compares a record's organization against the caller's verified
//!   one.
//! * `IncrementSecurityEpoch`, "atomic increment cannot commit" **and** "the exact unsigned
//!   generation is at its maximum" — the **double** path, both of them. Both refusals are made
//!   by one function: `IncrementSecurityEpoch::execute` hands the version the caller read to
//!   `SecurityEpochWrite::increment`, whose only implementor is [`IdentityLog`]
//!   (`crates/mandate-identity/src/port.rs:911`), and that implementation makes the
//!   compare-and-set at `crates/mandate-identity/src/port.rs:919-921` and the overflow refusal
//!   three lines later at `crates/mandate-identity/src/port.rs:922-924`.
//!   `crates/mandate-identity/src/session.rs:342-343` states that [`IdentityLog`] "is the
//!   in-memory double of the event-log adapter a later story supplies". Whether a stream
//!   version that moved commits, and whether a generation already at its maximum advances, are
//!   the adapter's decisions and not this fold's, so the rows of both clauses are `path: double`
//!   and both stay deferred to `decision-blocker:epoch-atomicity`, which owns the event-log
//!   transaction the real port will make them in. The case below is still what states the
//!   refusal; what it does not state is that the shipped adapter refuses. The overflow clause
//!   carries one row, `increment::epoch_overflow_an_increment_at_the_maximum_is_denied_and_the_generation_does_not_move`:
//!   `generation::epoch_overflow_the_maximum_generation_does_not_advance` was withdrawn from it
//!   because it constructs no [`IdentityLog`] and survives every mutation of the refusal it was
//!   rowed for — it is evidence of the domain type's invariant, not of the command refusing.
//! * `IncrementSecurityEpoch`, "tenant containment fails" — the **real** path.
//!   `IncrementSecurityEpoch::execute` compares the target's organization with the caller's
//!   verified one before it reaches the write port — the comparison `RevokeSession` makes at
//!   `src/session.rs:369` — and refuses with `TenantMismatch`. The port only supplies which
//!   organizations its records place the target in (`TargetTenancy`), so the row is `real`:
//!   what is classified is the code that decides, not the code that holds the data.
//! * `IncrementSecurityEpoch`'s `no_state_change` obligation follows the two double-backed
//!   clauses. `emitted_events::a_refused_increment_emits_nothing_and_leaves_the_log_unchanged`
//!   drives exactly the write port's two refusals, so what it measures is [`IdentityLog`]'s own
//!   behaviour: the row is `path: double` and the command carries the deferral at command level,
//!   to `decision-blocker:epoch-atomicity`. The one refusal `execute` makes itself, tenancy,
//!   is asserted to leave the log unchanged by the cases bound to that clause.
//!
//! # What is not here, and why no case could bind it
//!
//! Five clauses stay deferred, none for want of a case:
//!
//! * "Caller lacks authority for the explicitly selected principal/organization/federation
//!   target" and "Caller lacks authority over this session" — `src/increment.rs:9-11` and
//!   `src/session.rs:351-352` both state that the caller's authority is the authorization
//!   domain's decision and is not made here; the verified context is carried through to the
//!   event unexamined.
//! * "Refresh verifier is absent/incorrect" — the declared input is a `CredentialProof`, and
//!   `src/session.rs:267` states that credential proof verification is the credential
//!   domain's. The refresh is reached with a session identity that verification already
//!   resolved.
//! * "principal/session is disabled" — [`IdentityEvent`] carries no disablement arm and
//!   `crates/mandate-identity/src/lib.rs` lists `mandate.identity.PrincipalDisabled` in
//!   `ESS_UNREALIZED`, so every principal this fold answers for is in the declared initial
//!   state. The session half of the clause is the `Revoked` state, which is the
//!   "record is expired/revoked" clause's and is bound there.
//! * "revocation cannot be durably observed under the applicable profile" — [`revoke_session`]
//!   decides and appends; whether a revocation is observed under the credential profile that
//!   presented it is the deployment store's, not this fold's.
//!
//! `mandate.identity.RefreshSession`'s `no_state_change` obligation is not bound here either,
//! and no case is attempted for it: the command takes the port by shared reference, so a
//! refused refresh cannot move the fold whatever it decides, and the accepted outcome does not
//! move it either — the declared `mandate.identity.SessionRefreshed` is never folded. The two
//! outcomes leave byte-identical logs, so a case comparing them asserts the signature rather
//! than the obligation. The command carries the deferral at command level, to
//! `story:declared-writers`, which folds the declared event.
//!
//! `contracts/obligations/identity.json` records which story or blocker owns each of those
//! paths.

use mandate_identity::{
    EpochSnapshotRecorded, Generation, IdentityEvent, IdentityLog, IdentityRead,
    IncrementSecurityEpoch, RefusedOutcome, SecurityEpochRecorded, SessionOpened, revoke_session,
};
use mandate_types::{
    Audience, CorrelationId, CredentialId, DenialReason, EpochSnapshotRef, OrganizationId,
    PrincipalId, SecurityEpochTarget, SessionId, Timestamp, Uuid, VerifiedContext,
};

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn principal() -> PrincipalId {
    PrincipalId::new(uuid(1))
}

/// The organization the verified context of every case is issued in.
fn organization() -> OrganizationId {
    OrganizationId::new(uuid(2))
}

/// An organization the world holds nothing in.
fn another_organization() -> OrganizationId {
    OrganizationId::new(uuid(3))
}

fn handle() -> EpochSnapshotRef {
    EpochSnapshotRef::new(uuid(10))
}

fn session_id() -> SessionId {
    SessionId::new(uuid(20))
}

fn generation(value: i64) -> Generation {
    Generation::new(value).expect("a non-negative generation")
}

/// The instant every case is evaluated at; the world's session expires well after it.
fn as_of() -> Timestamp {
    Timestamp::new("2026-09-18T00:00:00Z")
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
        correlation: CorrelationId::new("obligations"),
    }
}

/// One principal, one organization, one snapshot over both, and one active session bound to
/// it — the smallest world every clause below is decided in.
fn world() -> IdentityLog {
    let mut log = IdentityLog::new().with_as_of(as_of());
    for (target, value) in [
        (SecurityEpochTarget::Principal(principal()), 3),
        (SecurityEpochTarget::Organization(organization()), 7),
    ] {
        log.record(IdentityEvent::SecurityEpochRecorded(
            SecurityEpochRecorded {
                target,
                generation: generation(value),
            },
        ));
    }
    log.record(IdentityEvent::EpochSnapshotRecorded(
        EpochSnapshotRecorded {
            id: handle(),
            principal_id: principal(),
            organization_id: organization(),
            connection_id: None,
        },
    ));
    log.record(IdentityEvent::SessionOpened(SessionOpened {
        id: session_id(),
        principal_id: principal(),
        organization_id: organization(),
        connection_id: None,
        epochs: handle(),
        expires_at: Timestamp::new("2026-12-31T00:00:00Z"),
    }));
    log
}

// ==================================================================================
// mandate.identity.IncrementSecurityEpoch
// ==================================================================================

/// "atomic increment cannot commit": the advance is a compare-and-set on the version the
/// caller read, so a writer whose stream moved under it is refused rather than merged
/// (`src/increment.rs:5-7`). The generation is the one the first writer left, not the one the
/// refused writer would have produced: the increment did not commit, and nothing half
/// committed either.
///
/// The decider is `<IdentityLog as SecurityEpochWrite>::increment`, which is the in-memory
/// double of the event-log adapter (`src/session.rs:342-343`), so the row this case backs is
/// `path: double` and the clause stays deferred to `decision-blocker:epoch-atomicity`.
#[test]
fn an_increment_at_a_version_another_writer_moved_past_cannot_commit() {
    let mut log = world();
    let target = SecurityEpochTarget::Principal(principal());
    let read_at = log.current(&target).version();
    IncrementSecurityEpoch::new(context(), target.clone())
        .execute(&mut log, read_at)
        .expect("the first writer commits at the version it read");
    let held = log.clone();

    let denied = IncrementSecurityEpoch::new(context(), target.clone())
        .execute(&mut log, read_at)
        .expect_err("the second writer read the stream before the first committed");

    assert_eq!(denied.reason(), DenialReason::Unavailable);
    assert_eq!(denied.outcome(), RefusedOutcome::Denied);
    assert_eq!(log, held, "the refused increment appends nothing");
    assert_eq!(
        log.current(&target).generation(),
        generation(4),
        "the generation the first writer committed, advanced exactly once"
    );
}

// ==================================================================================
// mandate.identity.RevokeSession
// ==================================================================================

/// "session is outside the verified organization": the containment is the record's own, and a
/// caller verified in another organization does not acquire it by naming the session. The
/// session resolves and is active, so the refusal is this clause and neither the unresolved
/// session nor the declared `wrong-state` outcome.
#[test]
fn a_session_outside_the_verified_organization_is_refused_at_revoke() {
    let mut log = world();
    let held = log.clone();
    let elsewhere = VerifiedContext {
        organization: another_organization(),
        ..context()
    };
    assert!(
        log.resolve(&session_id())
            .expect("the world holds this session")
            .is_active(),
        "the session resolves and is active, so no other guard can answer first"
    );

    let denied = revoke_session(&mut log, &elsewhere, session_id())
        .expect_err("the session is contained in another organization than the caller's");

    assert_eq!(denied.reason(), DenialReason::TenantMismatch);
    assert_eq!(denied.outcome(), RefusedOutcome::Denied);
    assert_eq!(log, held, "the refused revocation appends nothing");
    assert!(
        log.resolve(&session_id())
            .expect("nothing is deleted")
            .is_active(),
        "the declared `revoke` move did not happen"
    );
}

// ==================================================================================
// The spans this file cites for the classifications above
// ==================================================================================

/// One citation this file's documentation makes, and the phrases the cited lines must hold for
/// the claim made of them to be readable there.
///
/// The adversary found a citation off by six lines, twice: once in pass 1, and once again in
/// pass 2 after the correction answered by re-reading every one of them. Re-reading is the
/// check that failed both times, so the check is a case. The table is closed both ways —
/// [`every_span_this_file_cites_holds_what_it_is_cited_for`] refuses a cited span that does not
/// hold its phrase, and it refuses a citation this table does not carry, so a citation added
/// above is unreadable to a reviewer only until the suite runs.
const CITED: &[(&str, &[&str])] = &[
    (
        "crates/mandate-identity/src/session.rs:369",
        &["session.organization() != &context.organization"],
    ),
    (
        "crates/mandate-identity/src/port.rs:911",
        &["impl SecurityEpochWrite for IdentityLog"],
    ),
    (
        "crates/mandate-identity/src/port.rs:919-921",
        &["state.version() != expected", "DenialReason::Unavailable"],
    ),
    (
        "crates/mandate-identity/src/port.rs:922-924",
        &["state.generation().advance()", "DenialReason::Denied"],
    ),
    (
        "crates/mandate-identity/src/session.rs:342-343",
        &["is the in-memory double of the event-log adapter a later"],
    ),
    (
        "src/increment.rs:9-11",
        &["domain's decision and is not made here"],
    ),
    (
        "src/session.rs:351-352",
        &["is not made here; the verified context is carried through to the event."],
    ),
    (
        "src/session.rs:369",
        &["session.organization() != &context.organization"],
    ),
    (
        "src/session.rs:267",
        &["Credential proof verification is the credential domain's"],
    ),
    (
        "src/increment.rs:5-7",
        &["compare-and-set", "refused rather than merged"],
    ),
    (
        "src/session.rs:342-343",
        &["is the in-memory double of the event-log adapter a later"],
    ),
];

/// The citations above that name a file and no line, and the phrases that file must hold. A
/// span citation is checked line by line; these are checked whole, which is all a citation
/// without a line number claims.
const NAMED: &[(&str, &[&str])] = &[
    (
        "crates/mandate-identity/src/lib.rs",
        &["\"mandate.identity.PrincipalDisabled\""],
    ),
    (
        "docs/architecture/command-obligations.md",
        &["renders as HTTP 409 in the OpenAPI projection"],
    ),
];

fn manifest() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The file a cited path names, whether it is written from the workspace root or from this
/// crate.
fn resolve(path: &str) -> std::path::PathBuf {
    match path.strip_prefix("crates/mandate-identity/") {
        Some(inside) => manifest().join(inside),
        None if path.starts_with("src/") || path.starts_with("tests/") => manifest().join(path),
        None => manifest().join("../..").join(path),
    }
}

/// Every `<path>.rs:<first>[-<last>]` citation in the text, in the order it makes them.
///
/// Read off the text rather than listed by hand: a citation nobody transcribed into the table
/// is the failure this case exists for, so the set it checks may not be a transcription either.
fn cited_spans(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    for (at, _) in text.match_indices(".rs:") {
        let mut first = at;
        while first > 0
            && matches!(bytes[first - 1], b'_' | b'-' | b'/' | b'.')
                | bytes[first - 1].is_ascii_alphanumeric()
        {
            first -= 1;
        }
        let mut last = at + ".rs:".len();
        while bytes.get(last).is_some_and(u8::is_ascii_digit) {
            last += 1;
        }
        if last == at + ".rs:".len() {
            continue;
        }
        if bytes.get(last) == Some(&b'-') && bytes.get(last + 1).is_some_and(u8::is_ascii_digit) {
            last += 1;
            while bytes.get(last).is_some_and(u8::is_ascii_digit) {
                last += 1;
            }
        }
        found.push(text[first..last].to_owned());
    }
    found
}

/// The lines a citation names, or why they cannot be read.
fn lines_of(citation: &str) -> Result<String, String> {
    let (path, span) = citation
        .rsplit_once(':')
        .ok_or_else(|| format!("{citation}: names no line"))?;
    let (first, last) = span.split_once('-').unwrap_or((span, span));
    let (first, last) = (
        first
            .parse::<usize>()
            .map_err(|e| format!("{citation}: {e}"))?,
        last.parse::<usize>()
            .map_err(|e| format!("{citation}: {e}"))?,
    );
    let file = resolve(path);
    let text = std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
    let lines: Vec<&str> = text.lines().collect();
    if first < 1 || last < first || last > lines.len() {
        return Err(format!(
            "{citation} is no span {path} has, which holds {} lines",
            lines.len()
        ));
    }
    Ok(lines[first - 1..last].join("\n"))
}

/// Every `file:line` span this file cites states what it is cited for, and every span it cites
/// is one this case checks.
///
/// A `file:line` span is the one form of citation a reader verifies by opening the file at that
/// line, which is exactly why a wrong one survives review: it reads as precise. Two of them
/// shipped in this file before this case existed.
#[test]
fn every_span_this_file_cites_holds_what_it_is_cited_for() {
    let source = std::fs::read_to_string(manifest().join("tests/obligations.rs"))
        .expect("this file reads itself");
    let documentation: String = source
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("//!") || line.starts_with("///"))
        .collect::<Vec<_>>()
        .join("\n");
    let made = cited_spans(&documentation);
    let mut wrong: Vec<String> = Vec::new();

    for citation in &made {
        let Some((_, phrases)) = CITED.iter().find(|(cited, _)| cited == citation) else {
            wrong.push(format!(
                "{citation} is cited above and CITED does not carry it, so nothing checks that \
                 those lines state what they are cited for"
            ));
            continue;
        };
        match lines_of(citation) {
            Err(reason) => wrong.push(reason),
            Ok(quoted) => {
                for phrase in *phrases {
                    if !quoted.contains(phrase) {
                        wrong.push(format!(
                            "{citation} is cited for {phrase:?} and holds no such text; it \
                             reads:\n{quoted}"
                        ));
                    }
                }
            }
        }
    }
    for (cited, _) in CITED {
        if !made.iter().any(|citation| citation == cited) {
            wrong.push(format!(
                "CITED carries {cited} and the documentation above cites no such span"
            ));
        }
    }
    for (path, phrases) in NAMED {
        let file = resolve(path);
        if !documentation.contains(path) {
            wrong.push(format!(
                "NAMED carries {path} and the documentation names no such file"
            ));
            continue;
        }
        let text = std::fs::read_to_string(&file)
            .unwrap_or_else(|error| panic!("{}: {error}", file.display()));
        for phrase in *phrases {
            if !text.contains(phrase) {
                wrong.push(format!(
                    "{path} is cited for {phrase:?} and holds no such text"
                ));
            }
        }
    }

    assert!(
        wrong.is_empty(),
        "this file cites {} span(s) or file(s) that do not state what they are cited for:\n\n{}",
        wrong.len(),
        wrong.join("\n\n"),
    );
}
