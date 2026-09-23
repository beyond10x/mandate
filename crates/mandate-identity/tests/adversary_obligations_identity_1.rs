//! Adversary pass 1 against `story:obligations-identity`.
//!
//! Three cases, each driving the documents that unit wrote — `contracts/obligations/identity.json`
//! and the module doc of `crates/mandate-identity/tests/obligations.rs` — against the code the
//! same unit says they describe. Nothing here edits an implementation file.
//!
//! 1. [`an_increment_naming_another_organizations_target_fails_tenant_containment`] — the unit
//!    re-pointed `IncrementSecurityEpoch`'s "tenant containment fails" clause from its own binding
//!    story to `decision-blocker:guards` on the ground that this crate cannot decide it. The same
//!    crate decides the identical predicate for `RevokeSession` at `src/session.rs:369`, which the
//!    first assertion of that case exercises; the blocker is about external cryptographic, graph
//!    and policy validation, and a `SecurityEpochTarget::Organization` compared against
//!    `VerifiedContext::organization` is none of those.
//! 2. [`an_accepted_refresh_moves_something_a_refused_one_does_not`] — the unit added a
//!    `no_state_change` row for `mandate.identity.RefreshSession`. `refresh_session` takes `&R`,
//!    so "the refused refresh appends nothing" is a statement of its signature; this case measures
//!    whether the *accepted* outcome appends anything either, which is the only thing that could
//!    make that obligation falsifiable.
//! 3. [`every_source_span_the_unit_cites_for_a_re_pointing_states_what_it_is_cited_for`] — the six
//!    re-pointings are justified in `tests/obligations.rs` by `file:line` spans. This case reads
//!    the spans.

use std::fs;
use std::path::{Path, PathBuf};

use mandate_identity::{
    EpochSnapshotRecorded, Generation, IdentityEvent, IdentityLog, IdentityRead,
    IncrementSecurityEpoch, RefusedOutcome, SecurityEpochRecorded, SessionOpened, refresh_session,
    revoke_session,
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

/// The organization every verified context below is issued in.
fn organization() -> OrganizationId {
    OrganizationId::new(uuid(2))
}

/// A second organization the caller is not verified in, whose generation the log states.
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

fn as_of() -> Timestamp {
    Timestamp::new("2026-09-18T00:00:00Z")
}

/// A verified context in `organization`.
fn context() -> VerifiedContext {
    VerifiedContext {
        subject: principal(),
        actor: None,
        organization: organization(),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("adversary"),
    }
}

/// One principal, two organizations with a stated generation each, one snapshot over the
/// principal and the first organization, and one active session on it.
fn world() -> IdentityLog {
    let mut log = IdentityLog::new().with_as_of(as_of());
    for (target, value) in [
        (SecurityEpochTarget::Principal(principal()), 3),
        (SecurityEpochTarget::Organization(organization()), 7),
        (SecurityEpochTarget::Organization(another_organization()), 5),
    ] {
        log.try_record(IdentityEvent::SecurityEpochRecorded(
            SecurityEpochRecorded {
                target,
                generation: generation(value),
            },
        ))
        .expect("a first generation for each dimension the world states");
    }
    log.try_record(IdentityEvent::EpochSnapshotRecorded(
        EpochSnapshotRecorded {
            id: handle(),
            principal_id: principal(),
            organization_id: organization(),
            connection_id: None,
        },
    ))
    .expect("both dimensions the snapshot names have stated a generation");
    log.try_record(IdentityEvent::SessionOpened(SessionOpened {
        id: session_id(),
        principal_id: principal(),
        organization_id: organization(),
        connection_id: None,
        epochs: handle(),
        expires_at: Timestamp::new("2026-12-31T00:00:00Z"),
    }))
    .expect("the snapshot the opening names is already recorded");
    log
}

// ==================================================================================
// mandate.identity.IncrementSecurityEpoch, "tenant containment fails"
// ==================================================================================

/// `contracts/obligations/identity.json` now defers "tenant containment fails" to
/// `decision-blocker:guards`, whose text is about "executable cryptographic, graph or policy
/// predicates" and a "trusted context adapter". This clause is neither: it is a
/// `SecurityEpochTarget::Organization` compared against `VerifiedContext::organization`, which
/// this crate already performs for `RevokeSession` at `src/session.rs:369` and for a session's
/// snapshot at `src/session.rs:222`.
///
/// The first assertion is that capability, exercised. The second is the clause the contract
/// declares: a caller verified in one organization names another organization's security-epoch
/// target, and `mandate.identity.IncrementSecurityEpoch` declares "tenant containment fails" as
/// one of the four conditions of its `denied` outcome.
///
/// Pinned by the coordinator to the shipped behaviour on 2026-09-21 (`review-result:wave-d-obligations-identity-adversary-1` F1)
/// and flipped by `story:identity-tenant-containment`, which added the comparison to
/// `IncrementSecurityEpoch::execute`: the increment is refused with `TenantMismatch` through the
/// `denied` outcome, and neither the other organization's generation nor the log moves.
#[test]
fn an_increment_naming_another_organizations_target_fails_tenant_containment() {
    let log = world();
    let victim = SecurityEpochTarget::Organization(another_organization());
    assert_eq!(
        log.current(&victim).generation(),
        generation(5),
        "the second organization is one the log states a generation for, not an unknown handle"
    );

    // What this crate decides about the same predicate, on the sibling command: the caller's
    // verified organization is compared against the record's, and a caller outside it is
    // refused. `src/session.rs:369`.
    let mut sibling = log.clone();
    let elsewhere = VerifiedContext {
        organization: another_organization(),
        ..context()
    };
    let refused = revoke_session(&mut sibling, &elsewhere, session_id())
        .expect_err("RevokeSession compares the record's organization against the caller's");
    assert_eq!(refused.reason(), DenialReason::TenantMismatch);
    assert_eq!(refused.outcome(), RefusedOutcome::Denied);

    // The same predicate, on the command whose declared cause also publishes it.
    let mut log = log;
    let before = log.clone();
    let read_at = log.current(&victim).version();
    let refused = IncrementSecurityEpoch::new(context(), victim.clone())
        .execute(&mut log, read_at)
        .expect_err("a caller verified in one organization advanced another's generation");
    assert_eq!(refused.reason(), DenialReason::TenantMismatch);
    assert_eq!(refused.outcome(), RefusedOutcome::Denied);
    assert_eq!(
        log.current(&victim).generation(),
        generation(5),
        "the other organization's generation moved under a caller verified elsewhere"
    );
    assert_eq!(log, before, "the refused increment appended an event");
}

// ==================================================================================
// mandate.identity.RefreshSession, the no_state_change obligation
// ==================================================================================

/// The `no_state_change` obligation this unit bound for `mandate.identity.RefreshSession` says
/// the command refuses without moving its projection. `refresh_session(epochs: &R, ...)` cannot
/// move it whatever it decides, so the obligation can only be falsifiable if the *accepted*
/// outcome moves something — and that outcome declares `emits:
/// ["mandate.identity.SessionRefreshed"]` in `generated/ir/system.json`, with the event named in
/// this crate's `ESS_REALIZATIONS` and absent from `ESS_UNREALIZED`.
///
/// This case measures whether the accepted refresh appends the declared event. If it does not,
/// the refused and the accepted outcome leave byte-identical logs, and the row added to
/// `contracts/obligations/identity.json` is satisfied by every possible implementation of the
/// command.
///
/// Pinned by the coordinator to the shipped behaviour on 2026-09-21 (`review-result:wave-d-obligations-identity-adversary-1` F2): the
/// accepted refresh appends nothing, so the log is unchanged either way. The
/// `no_state_change` row was withdrawn and the command defers to `story:declared-writers`, which
/// folds `mandate.identity.SessionRefreshed`; the assertion flips there.
#[test]
fn an_accepted_refresh_moves_something_a_refused_one_does_not() {
    let log = world();
    let before = log.clone();

    let refreshed = refresh_session(&log, &session_id())
        .expect("the world's session is active, bound and current, so the refresh is accepted");
    assert_eq!(refreshed.session_id(), &session_id());

    assert_eq!(
        log, before,
        "the accepted refresh appended an event; story:declared-writers landed and this pin \
         is stale"
    );
}

// ==================================================================================
// The six re-pointings, against the spans cited for them
// ==================================================================================

/// One `file:line` span `crates/mandate-identity/tests/obligations.rs` offers as the source's own
/// statement that this crate does not decide a clause.
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

/// Every span the unit's module doc cites for a re-pointed clause.
const CITED: &[Citation] = &[
    Citation {
        file: "src/increment.rs",
        span: (9, 11),
        word: "authority",
        claim: "the caller's authority is the authorization domain's decision and is not made here",
    },
    Citation {
        file: "src/session.rs",
        span: (351, 352),
        word: "authority",
        claim: "the caller's authority is the authorization domain's decision and is not made here",
    },
    Citation {
        file: "src/session.rs",
        span: (267, 267),
        word: "verification",
        claim: "proof verification is the credential domain's",
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

/// The unit moved six clauses off its own binding story and onto a blocker or another story, each
/// justified by a span of this crate's source said to state that the crate does not decide the
/// clause. A `file:line` span is the one form of citation a reader checks by opening the file at
/// that line, and it is the form the coordinator's routing decision was handed.
#[test]
fn every_source_span_the_unit_cites_for_a_re_pointing_states_what_it_is_cited_for() {
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
        "crates/mandate-identity/tests/obligations.rs cites {} span(s) that do not state what \
         they are cited for:\n\n{}",
        wrong.len(),
        wrong.join("\n\n"),
    );
}
