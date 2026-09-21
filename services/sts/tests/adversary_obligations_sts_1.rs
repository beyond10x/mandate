//! Adversary pass — `story:obligations-sts`.
//!
//! The unit moved one `mandate-sts` clause from `deferred` to `real_covered` and re-pointed
//! the other twenty deferrals. Neither case here asserts a preference; each asserts a
//! sentence the tree already carries.
//!
//! - [`every_real_covered_sts_clause_is_named_by_evidence_inside_its_own_span`] asserts the
//!   rule `contracts/obligations/README.md` states for a covered clause — the evidence names
//!   *that* condition, which is why the clause list must tile the cause and why "where two
//!   conditions of one clause have different deciders, the clause is split into those
//!   conditions". The crate's own precedent table, `services/sts/tests/declared_denials.rs`
//!   `ROWS`, is the document that says which phrase of a cause each refusal this crate
//!   constructs quotes; it is read here as the document it is, exactly as
//!   `services/sts/tests/adversary_transaction_2.rs` reads it.
//! - [`a_profile_bound_past_the_readable_year_is_refused_or_renders_readably`] asserts the
//!   sentence `services/sts/src/lib.rs` writes over `instant::at`: "The one rendering this
//!   crate performs, so an expiry it decides is written the way the contract's schema reads
//!   it back." The registration handler admits a profile whose `max_ttl` puts the expiry
//!   past the last four-digit year, which is the bound
//!   `services/control-plane/src/adapters.rs` refuses a *code* lifetime for
//!   (`instant::renders_readably`) and which `admits_profile` does not apply.

use std::collections::{BTreeMap, BTreeSet};

use mandate_sts::issue::{
    IssueReferenceCredential, ReferenceParts, Sha256Digest, issue_reference_credential,
};
use mandate_sts::registry::{RegisterResourceServer, register_resource_server};
use mandate_sts::{CountingSecrets, RequestContext, SequentialAllocator};
use mandate_token::CredentialProfile;
use mandate_token::projection::Projection;
use mandate_types::{
    Audience, AuthorityScope, CorrelationId, CredentialId, CredentialKind, Duration,
    OrganizationId, PrincipalId, RevocationGuarantee, Timestamp, Uuid, VerifiedContext,
};
use serde_json::Value;

/// The registry document this unit owns.
const REGISTRY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../contracts/obligations/sts.json"
);

/// The compiled contract the clauses are phrases of.
const IR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../generated/ir/system.json"
);

/// The crate's own table of which phrase each refusal it constructs quotes.
const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/declared_denials.rs");

fn json(path: &str) -> Value {
    let text = std::fs::read_to_string(path).expect("the document is readable");
    serde_json::from_str(&text).expect("the document is JSON")
}

/// The declared external cause of `command`, which its clauses tile.
fn declared_cause(ir: &Value, command: &str) -> String {
    ir["commands"][command]["outcomes"]
        .as_array()
        .unwrap_or_else(|| panic!("{command} declares no outcomes"))
        .iter()
        .find(|outcome| outcome["condition"]["kind"] == "external")
        .and_then(|outcome| outcome["condition"]["cause"].as_str())
        .unwrap_or_else(|| panic!("{command} declares no externally caused outcome"))
        .to_owned()
}

/// Every phrase `services/sts/tests/declared_denials.rs` rows for a command, by command.
///
/// Read out of that file's own `ROWS` block, line-oriented, as
/// `services/sts/tests/adversary_transaction_2.rs` already reads it: a row's command is a
/// line that is nothing but a quoted element name, and a row's phrase is a line beginning
/// `Source::DenialPhrase("`. `Source::WrongState` and `Source::EntityInvariant(…)` carry no
/// phrase of a cause and are skipped.
fn rowed_phrases() -> BTreeMap<String, BTreeSet<String>> {
    let text = std::fs::read_to_string(TABLE).expect("the denial table is readable");
    let rows = text
        .split_once("const ROWS:")
        .expect("declared_denials.rs declares ROWS")
        .1;
    let rows = rows
        .split_once("\n];")
        .expect("the ROWS table is terminated")
        .0;

    let mut current: Option<String> = None;
    let mut rowed: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for line in rows.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix('"')
            && let Some(name) = rest.strip_suffix("\",")
        {
            current = Some(name.to_owned());
            continue;
        }
        if let Some(rest) = line.strip_prefix("Source::DenialPhrase(\"")
            && let Some(phrase) = rest.strip_suffix("\"),")
            && let Some(command) = current.as_deref()
        {
            rowed
                .entry(command.to_owned())
                .or_default()
                .insert(phrase.to_owned());
        }
    }
    rowed
}

/// Every `[start, end)` at which `phrase` occurs in `cause`.
fn occurrences(cause: &str, phrase: &str) -> Vec<(usize, usize)> {
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(offset) = cause[from..].find(phrase) {
        let start = from + offset;
        found.push((start, start + phrase.len()));
        from = start + 1;
    }
    found
}

/// Whether a clause has a `path: real` `denial` row, which is what `real_covered` counts.
fn real_covered(clause: &Value) -> bool {
    clause["tests"].as_array().is_some_and(|tests| {
        tests
            .iter()
            .any(|test| test["kind"] == "denial" && test["path"] == "real")
    })
}

/// **Every clause this document publishes as decided on the real path is named by evidence
/// that lies inside that clause and not across its neighbour.**
///
/// `contracts/obligations/README.md`: the clauses of one command tile the declared cause,
/// "read in order, they account for every character of it exactly once"; a clause nested
/// inside another is refused because it "claims one position of the cause twice and can
/// raise `real_covered` with nothing new decided"; and "where two conditions of one clause
/// have different deciders, the clause is split into those conditions". All three say the
/// same thing about a covered clause: the refusal that covers it answers *that* position of
/// the cause.
///
/// The evidence for a `mandate-sts` clause is a `DenialClause` a handler constructs, and the
/// document that says which phrase each of those quotes is the crate's own
/// `services/sts/tests/declared_denials.rs` `ROWS` — machine-checked in both directions
/// against `generated/ir/system.json` by that file. So a covered clause is one some rowed
/// phrase falls inside.
#[test]
fn every_real_covered_sts_clause_is_named_by_evidence_inside_its_own_span() {
    let registry = json(REGISTRY);
    let ir = json(IR);
    let rowed = rowed_phrases();

    // The parse is shown to work before anything is concluded from what it does not
    // contain, as `adversary_transaction_2.rs` does for the same table.
    for (command, phrase) in [
        (
            "mandate.credential.IssueReferenceCredential",
            "expiry cannot be bounded",
        ),
        (
            "mandate.credential.IssueAuthorizationCode",
            "bounded expiry",
        ),
        ("mandate.credential.RedeemAuthorizationCode", "narrowing"),
    ] {
        assert!(
            rowed
                .get(command)
                .is_some_and(|phrases| phrases.contains(phrase)),
            "the ROWS parse is broken: no `{phrase}` row for {command}, read {:?}",
            rowed.get(command)
        );
    }

    let mut unnamed: Vec<String> = Vec::new();
    for entry in registry["commands"]
        .as_array()
        .expect("the registry lists commands")
    {
        if entry["status"] != "implemented" {
            continue;
        }
        let command = entry["command"].as_str().expect("a command name");
        let cause = declared_cause(&ir, command);
        let empty = BTreeSet::new();
        let phrases = rowed.get(command).unwrap_or(&empty);

        // The clauses tile the cause, so their spans are walked positionally and never
        // searched for: two clauses may repeat a phrase, and the position is what a clause
        // is a claim about.
        let mut from = 0;
        for clause in entry["clauses"]
            .as_array()
            .expect("an implemented command lists clauses")
        {
            let text = clause["clause"].as_str().expect("a clause phrase");
            let start = from
                + cause[from..]
                    .find(text)
                    .unwrap_or_else(|| panic!("{command}: `{text}` does not tile the cause"));
            let end = start + text.len();
            from = end;
            if !real_covered(clause) {
                continue;
            }
            let inside: Vec<&String> = phrases
                .iter()
                .filter(|phrase| {
                    occurrences(&cause, phrase)
                        .iter()
                        .any(|(a, b)| *a >= start && *b <= end)
                })
                .collect();
            if inside.is_empty() {
                let across: Vec<&String> = phrases
                    .iter()
                    .filter(|phrase| {
                        occurrences(&cause, phrase)
                            .iter()
                            .any(|(a, b)| *a < end && *b > start)
                    })
                    .collect();
                unnamed.push(format!(
                    "{command} / `{text}` is published as real_covered, and no phrase \
                     services/sts/tests/declared_denials.rs rows for that command lies \
                     inside it; the rows that reach it at all are {across:?}, which run \
                     across the clause boundary into a neighbouring clause of the same cause"
                ));
            }
        }
    }

    assert!(
        unnamed.is_empty(),
        "contracts/obligations/sts.json publishes a clause as decided on the real path on \
         evidence that does not name it:\n  {}",
        unnamed.join("\n  ")
    );
}

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization(tag: u8) -> OrganizationId {
    OrganizationId::new(uuid(tag))
}

fn context(organization_id: OrganizationId) -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::new(uuid(0x51)),
        actor: None,
        organization: organization_id,
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("adversary-obligations-sts-1"),
    }
}

fn request() -> RequestContext {
    RequestContext {
        correlation: CorrelationId::new("adversary-obligations-sts-1"),
        at: Timestamp::new("2026-09-19T00:00:00Z"),
        epochs: None,
    }
}

fn scope() -> AuthorityScope {
    AuthorityScope {
        actions: Vec::new(),
        resources: Vec::new(),
        space: None,
    }
}

/// Whether the instant carries the layout `services/sts/src/lib.rs:312-320` reads back: the
/// four-digit year RFC 3339 declares, and the separators at the offsets that reader checks.
fn renders_readably(at: &Timestamp) -> bool {
    let text = at.as_str().as_bytes();
    text.len() >= 20
        && text[4] == b'-'
        && text[7] == b'-'
        && text[10] == b'T'
        && text[13] == b':'
        && text[16] == b':'
}

/// **A registration this handler admits issues a credential whose expiry this crate cannot
/// read back, and refuses nothing.**
///
/// `PT99999999H` is a well-formed duration `instant::span_of` reads, and
/// `crate::registry::admits_profile` admits it: it asks that `max_ttl` names a positive span
/// and that the cache is inside it, and nothing about the instant the span lands on. The
/// expiry `bounded_expiry` then computes is past the year 9999, and `instant::at` renders
/// the year with `{year:04}` — a minimum width and not a maximum — so the timestamp on the
/// issued credential is one `instant::seconds_of` answers `None` for.
///
/// `services/control-plane/src/adapters.rs` already refuses exactly this span for the code
/// and session lifetimes, at construction, through `instant::renders_readably`, and says
/// why: the handler would otherwise answer `ExpiryUnbounded` per request "with exit status 0
/// and nothing said at startup". The profile's `max_ttl` reaches the same renderer with no
/// such bound at either end of the road, and the issuance does not refuse — it succeeds.
///
/// The contract publishes the clause for it: `IssueReferenceCredential`'s declared denial
/// names "expiry cannot be bounded", and `services/sts/src/issue.rs` enumerates "every way
/// this can fail" as three ways that do not include this one.
///
/// Pinned by the coordinator to the shipped behaviour on 2026-09-21
/// (`review-result:wave-d-obligations-sts-adversary-1` F2): the registration is admitted, the
/// issuance succeeds, and the expiry it issued is one this crate cannot read back.
/// `story:sts-lifetime-bounds` turns this into a refusal; the assertion flips there.
#[test]
fn a_profile_bound_past_the_readable_year_is_admitted_and_issues_an_unreadable_expiry() {
    let mut allocator = SequentialAllocator::new();
    let registered = register_resource_server(
        &RegisterResourceServer {
            context: context(organization(10)),
            audience: Audience::new("api-a"),
            profile: CredentialProfile {
                name: "reference-past-the-readable-year".to_owned(),
                kind: CredentialKind::Reference,
                revocation: RevocationGuarantee::BoundedOffline,
                // The span `services/control-plane/tests/adapters.rs` names as the one a
                // deployment is refused at startup for.
                max_ttl: Duration::new("PT99999999H"),
                positive_cache_ttl: Duration::new("PT0S"),
                requires_online_authorization: false,
            },
            allowed_exchange_sources: Vec::new(),
        },
        &Projection::default(),
        &mut allocator,
    )
    .expect("the registration handler admits this profile");

    let servers = Projection::fold(std::slice::from_ref(&registered.event)).expect("one creation");
    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();

    let issued = issue_reference_credential(
        &IssueReferenceCredential {
            context: context(organization(10)),
            target: registered.resource_server_id,
            requested_scope: scope(),
        },
        &request(),
        &servers,
        ReferenceParts {
            digest: &Sha256Digest,
            secrets: &mut secrets,
            allocator: &mut allocator,
        },
    );

    let outcome =
        issued.expect("the shipped issuance accepts a profile bound past the readable year");
    assert!(
        !renders_readably(&outcome.descriptor.expires_at),
        "`expires_at` = {:?} renders readably, so the premise story:sts-lifetime-bounds rests \
         on no longer holds; {} secret(s) minted",
        outcome.descriptor.expires_at.as_str(),
        secrets.minted()
    );
}
