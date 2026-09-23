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
//!   it back." A profile whose `max_ttl` puts the expiry past the last four-digit year is
//!   refused at registration, which is the bound `services/control-plane/src/adapters.rs`
//!   refuses a *code* lifetime for (`instant::renders_readably`); the cases after it decide
//!   the same sentence at every site that renders an issued expiry — both issuance commands
//!   and the redemption — for a request instant the registration bound cannot see.

use std::collections::{BTreeMap, BTreeSet};

use mandate_sts::binding::{RecordedSessions, SessionBinding};
use mandate_sts::code::{
    AuthorizationCodeParts, CodeIssuance, CodeLifetime, IssueAuthorizationCode, RecordedClients,
};
use mandate_sts::issue::{
    CredentialIssued, IssueReferenceCredential, IssueSelfContainedCredential, ReferenceParts,
    SelfContainedParts, Sha256Digest, StaticSigner, issue_reference_credential,
    issue_self_contained_credential,
};
use mandate_sts::redemption::{
    BoundReads, RedeemAuthorizationCode, RedemptionParts, redeem_authorization_code,
};
use mandate_sts::registry::{RegisterResourceServer, register_resource_server};
use mandate_sts::store::CodeProjection;
use mandate_sts::{CountingSecrets, RequestContext, SequentialAllocator};
use mandate_token::CredentialProfile;
use mandate_token::projection::{CredentialEvent, DenialClause, Denied, Projection};
use mandate_types::{
    Audience, AuthorityScope, CorrelationId, CredentialId, CredentialKind, CredentialProof,
    DenialReason, Duration, EpochSnapshotRef, Issuer, OAuthClientId, OrganizationId, PkceChallenge,
    PkceMethod, PrincipalId, RedirectUri, ResourceServerId, RevocationGuarantee, SessionId,
    Timestamp, Transient, Uuid, VerifiedContext,
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

fn scope() -> AuthorityScope {
    AuthorityScope {
        actions: Vec::new(),
        resources: Vec::new(),
        space: None,
    }
}

fn oauth_client() -> OAuthClientId {
    OAuthClientId::new(uuid(0x0c))
}

fn oauth_session() -> SessionId {
    SessionId::new(uuid(0x5e))
}

fn snapshot() -> EpochSnapshotRef {
    EpochSnapshotRef::new(uuid(0x60))
}

fn issuer() -> Issuer {
    Issuer::new("https://sts.example")
}

/// A profile of the reference family whose `max_ttl` is `max_ttl`.
fn reference_profile(max_ttl: &str) -> CredentialProfile {
    CredentialProfile {
        name: "reference".to_owned(),
        kind: CredentialKind::Reference,
        revocation: RevocationGuarantee::BoundedOffline,
        max_ttl: Duration::new(max_ttl),
        positive_cache_ttl: Duration::new("PT0S"),
        requires_online_authorization: false,
    }
}

/// One target registered through the real handler, folded.
fn registered(profile: CredentialProfile) -> (Projection, ResourceServerId) {
    let mut allocator = SequentialAllocator::new();
    let outcome = register_resource_server(
        &RegisterResourceServer {
            context: context(organization(10)),
            audience: Audience::new("api-a"),
            profile,
            allowed_exchange_sources: Vec::new(),
        },
        &Projection::default(),
        &mut allocator,
    )
    .expect("a free audience and an admitted profile");
    (
        Projection::fold(std::slice::from_ref(&outcome.event)).expect("one creation"),
        outcome.resource_server_id,
    )
}

/// A target whose registration record carries `profile` without the registration handler
/// having admitted it: a record another writer put in the log, or one written before this
/// handler refused the profile. Constructed, as
/// `services/sts/tests/obligations.rs::narrowing_refuses_a_zero_span_profile_bound_and_moves_nothing`
/// constructs its zero-span record, and for the same reason: an issuance re-reads the
/// registration, and that re-read is what decides a record no handler here would write.
fn recorded(profile: CredentialProfile) -> (Projection, ResourceServerId) {
    let id = ResourceServerId::new(uuid(0x40));
    let log = vec![CredentialEvent::ResourceServerRegistered {
        context: context(organization(10)),
        id,
        audience: Audience::new("api-a"),
        credential_profile: profile,
        allowed_exchange_sources: Vec::new(),
    }];
    (Projection::fold(&log).expect("one creation"), id)
}

fn request_at(at: &str) -> RequestContext {
    RequestContext {
        correlation: CorrelationId::new("adversary-obligations-sts-1"),
        at: Timestamp::new(at),
        epochs: Some(snapshot()),
    }
}

fn expiry_unbounded() -> Denied {
    Denied::new(DenialReason::Denied, DenialClause::ExpiryUnbounded)
}

/// A reference issuance against `target`, and how many secrets it minted.
fn issue_reference(
    servers: &Projection,
    target: ResourceServerId,
    request: &RequestContext,
) -> (Result<CredentialIssued, Denied>, u32) {
    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();
    let issued = issue_reference_credential(
        &IssueReferenceCredential {
            context: context(organization(10)),
            target,
            requested_scope: scope(),
        },
        request,
        servers,
        ReferenceParts {
            digest: &Sha256Digest,
            secrets: &mut secrets,
            allocator: &mut allocator,
        },
    );
    (issued, secrets.minted())
}

/// **A profile whose `max_ttl` puts an expiry past the last four-digit year is refused at
/// registration as `ProfileUnadmitted`.**
///
/// `PT99999999H` is a well-formed duration `instant::span_of` reads — about 11 400 years —
/// and the span `services/control-plane/tests/adapters.rs` names as the one a deployment is
/// refused at startup for as a code or session lifetime. `admits_profile` is the one place a
/// deployment can say, before anything is issued under the profile, that the bound it
/// promises lands on an instant `instant::at` cannot render readably
/// (`review-result:wave-d-obligations-sts-adversary-1` F2, flipped by
/// `story:sts-lifetime-bounds`).
///
/// The profiles on either side of the bound are shown admitted, so the refusal is the bound
/// and not a malformed duration.
#[test]
fn a_profile_bound_past_the_readable_year_is_refused_or_renders_readably() {
    let register = |max_ttl: &str| {
        let mut allocator = SequentialAllocator::new();
        register_resource_server(
            &RegisterResourceServer {
                context: context(organization(10)),
                audience: Audience::new("api-a"),
                profile: CredentialProfile {
                    name: "reference-past-the-readable-year".to_owned(),
                    ..reference_profile(max_ttl)
                },
                allowed_exchange_sources: Vec::new(),
            },
            &Projection::default(),
            &mut allocator,
        )
    };

    for admitted in ["PT1H", "P36500D"] {
        assert!(
            register(admitted).is_ok(),
            "a `max_ttl` of {admitted} lands inside the four-digit year and is admitted"
        );
    }
    for refused in ["PT99999999H", "P3650000D", "PT9223372036854775807S"] {
        let denied = register(refused).expect_err(
            "a profile whose bound lands past the last four-digit year promises an expiry \
             this crate cannot render readably",
        );
        assert_eq!(
            denied,
            Denied::new(DenialReason::Denied, DenialClause::ProfileUnadmitted),
            "{refused}: the declared clause is `ProfileUnadmitted`"
        );
    }
}

/// **A record carrying a profile bound past the readable year issues nothing: both issuance
/// commands refuse with `ExpiryUnbounded` and mint no secret.**
///
/// The registration handler refuses the profile, so a record carrying it is one another
/// writer put in the log. The issuance handlers re-read the registration, and they are the
/// last point at which an expiry the crate cannot read back can be refused rather than
/// handed to a holder as a credential `resolve` answers not-live for.
#[test]
fn a_recorded_profile_bound_past_the_readable_year_issues_nothing() {
    let (servers, target) = recorded(reference_profile("PT99999999H"));
    let (issued, minted) = issue_reference(&servers, target, &request_at("2026-09-19T00:00:00Z"));
    assert_eq!(
        issued.map(|outcome| outcome.descriptor.expires_at),
        Err(expiry_unbounded()),
        "an expiry past the four-digit year is one this crate cannot read back"
    );
    assert_eq!(minted, 0, "a refusal mints no secret");
}

/// **An issuance whose expiry would land past `9999-12-31T23:59:59Z` is refused with
/// `ExpiryUnbounded`, on both issuance commands, under a profile the registration handler
/// admits.**
///
/// The registration bound is decided from a stated request instant, because the handler has
/// no clock. A request after that instant, under an admitted `PT24H`, still reaches an
/// expiry past the four-digit year, and `instant::at` renders it with `{year:04}` — a
/// minimum width — into `+10000-…`, which `instant::seconds_of` answers `None` for. The
/// refusal is the issuance's.
#[test]
fn an_issuance_whose_expiry_would_pass_the_readable_year_is_refused() {
    let (servers, target) = registered(reference_profile("PT24H"));
    let late = request_at("9999-12-31T12:00:00Z");

    let (issued, minted) = issue_reference(&servers, target, &late);
    assert_eq!(
        issued.map(|outcome| outcome.descriptor.expires_at),
        Err(expiry_unbounded()),
        "IssueReferenceCredential: the expiry lands in the year 10000"
    );
    assert_eq!(minted, 0, "a refusal mints no secret");

    let (servers, target) = registered(CredentialProfile {
        kind: CredentialKind::SelfContained,
        ..reference_profile("PT24H")
    });
    let signer = StaticSigner::new("kid-one", 86_400);
    let mut allocator = SequentialAllocator::new();
    let issued = issue_self_contained_credential(
        &IssueSelfContainedCredential {
            context: context(organization(10)),
            target,
            requested_scope: scope(),
        },
        &late,
        &servers,
        SelfContainedParts {
            digest: &Sha256Digest,
            allocator: &mut allocator,
            signer: &signer,
            issuer: &issuer(),
        },
    );
    assert_eq!(
        issued.map(|outcome| outcome.descriptor.expires_at),
        Err(expiry_unbounded()),
        "IssueSelfContainedCredential: the expiry lands in the year 10000"
    );
}

/// **An issuance whose expiry would land before `0000-01-01T00:00:00Z` is refused with
/// `ExpiryUnbounded`.**
///
/// The other end of the same rendering. `0000-01-01T00:00:00+01:00` is a request instant
/// `instant::seconds_of` reads — an hour before the year 0 begins in UTC — and one second
/// later is still in the year -1, which `instant::at` renders as `-001-12-31T23:00:01Z`. That
/// text has a `-` at offset 4 and passes the layout check a separator-only reader applies,
/// and `instant::seconds_of` still answers `None` for it: `-001` is not four digits. So the
/// bound is whether the crate's own reader reads the rendering back, not where its
/// separators fall.
#[test]
fn an_issuance_whose_expiry_would_fall_before_the_year_zero_is_refused() {
    let (servers, target) = registered(reference_profile("PT1S"));
    let (issued, minted) =
        issue_reference(&servers, target, &request_at("0000-01-01T00:00:00+01:00"));
    assert_eq!(
        issued.map(|outcome| outcome.descriptor.expires_at),
        Err(expiry_unbounded()),
        "the expiry lands in the year -1"
    );
    assert_eq!(minted, 0, "a refusal mints no secret");
}

/// **A redemption whose narrowed expiry would land before the year 0 is refused with
/// `ExpiryUnbounded` and mints nothing.**
///
/// The third site `instant::at` renders an issued expiry at
/// (`services/sts/src/redemption.rs`): the earlier of `issued_at + max_ttl` and the code's
/// own `expires_at`. The code's expiry is one the reader read, so the narrowed instant can
/// pass neither end of the readable range from above; from below it can, because the
/// request instant is read with its offset and `issued_at + max_ttl` is then earlier than
/// the year 0 in UTC. Every earlier guard is satisfied: the code was minted by the real
/// issuance handler, the session is fresh, the client is bound and the target is the
/// session's own.
#[test]
fn a_redemption_whose_narrowed_expiry_would_fall_before_the_year_zero_is_refused() {
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const REDIRECT: &str = "https://client.example/callback";
    let early = request_at("0000-01-01T00:00:00+01:00");
    let (servers, target) = registered(reference_profile("PT1S"));
    let clients = RecordedClients::new()
        .enabled(oauth_client(), organization(10))
        .redirect(oauth_client(), RedirectUri::new(REDIRECT));
    let sessions = RecordedSessions::new()
        .session(SessionBinding {
            id: oauth_session(),
            subject: PrincipalId::new(uuid(0x51)),
            organization: organization(10),
            epochs: Some(snapshot()),
            expires_at: Timestamp::new("0000-01-01T12:00:00Z"),
            revoked: false,
        })
        .current(snapshot());

    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();
    let code = CodeIssuance::new(CodeLifetime::new(Duration::new("PT5M")))
        .issue(
            &IssueAuthorizationCode {
                context: context(organization(10)),
                client_id: oauth_client(),
                session_id: oauth_session(),
                target,
                requested_scope: scope(),
                challenge: PkceChallenge::new(CHALLENGE),
                method: PkceMethod::S256,
                redirect_uri: RedirectUri::new(REDIRECT),
                expires_at: Timestamp::new("0000-01-01T00:05:00+01:00"),
            },
            &early,
            &servers,
            &clients,
            AuthorizationCodeParts {
                digest: &Sha256Digest,
                secrets: &mut secrets,
                allocator: &mut allocator,
            },
        )
        .expect("a readable code expiry inside the deployment's ceiling");
    let codes = CodeProjection::fold(std::slice::from_ref(&code.event)).expect("one creation");

    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();
    let redeemed = redeem_authorization_code(
        &RedeemAuthorizationCode {
            code_id: code.code_id,
            client_id: oauth_client(),
            code: CredentialProof::from_bytes(code.code.expose_material().to_vec()),
            pkce_verifier: CredentialProof::from_bytes(VERIFIER.as_bytes().to_vec()),
            redirect_uri: RedirectUri::new(REDIRECT),
        },
        &early,
        &codes,
        BoundReads {
            servers: &servers,
            clients: &clients,
            sessions: &sessions,
        },
        RedemptionParts {
            digest: &Sha256Digest,
            secrets: &mut secrets,
            allocator: &mut allocator,
        },
    );
    assert_eq!(
        redeemed.map(|outcome| outcome.descriptor.expires_at),
        Err(expiry_unbounded()),
        "the narrowed expiry lands in the year -1"
    );
    assert_eq!(secrets.minted(), 0, "a refusal mints no secret");
}
