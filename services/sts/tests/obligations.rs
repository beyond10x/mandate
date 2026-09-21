//! The clauses of `contracts/obligations/sts.json` this story binds, each driven through the
//! shipped handler against arranged state.
//!
//! `services/sts/tests/declared_denials.rs` decides the other direction — that every
//! `(command, clause)` pair this crate's handlers **can** construct is one the contract
//! phrases — and it is what bounds this file. Its `ROWS` table is machine-checked complete
//! per command: every clause a driven handler produced has a row, and every row was
//! produced. Laying `ROWS` over the clause list of `contracts/obligations/sts.json` — each
//! row against the clause whose phrase it quotes — leaves exactly one registry clause that
//! carried no test and does have a `DenialClause` a shipped handler constructs, and that
//! clause is what this file decides:
//!
//! - `mandate.credential.RedeemAuthorizationCode`, "narrowing" —
//!   `DenialClause::ExpiryUnbounded`, the expiry narrowing the transaction performs:
//!   `expires_at` is the earlier of the profile's `issued_at + max_ttl` and the code's own
//!   `expires_at` (`services/sts/src/redemption.rs:343-350`), and the clause is that
//!   narrowing failing to name an instant.
//!
//! # Why the other twenty deferred clauses are not here
//!
//! Every one of them names a condition **no code in this crate decides**, and the registry
//! records that by deferring each to the decision that owns it rather than to this story:
//!
//! - an authoritative external validation the trusted context adapter performs — every
//!   "caller lacks … authority" clause, "Validated context is expired/revoked/stale",
//!   "Trusted control-plane caller/session context", "authority narrowing" and
//!   "principal/connection/epoch validation fails". `services/sts/src/lib.rs` states the
//!   boundary: "no crate in this crate's dependency ceiling decides an authorization
//!   question", and `decision-blocker:guards` is the open decision that owns the adapter.
//! - a durable commit the deployment's store performs — "durable disablement cannot prevent
//!   subsequent issuance", "verifier-only persistence and required audit cannot commit",
//!   "the promised revocation/audit guarantee cannot be met", "retirement cannot durably
//!   stop further issuance under the key", "emergency revocation cannot durably stop both
//!   issuance and verification …", "the named profile revocation guarantee cannot be met"
//!   and "atomic issuance validation fails", the condition the declared cause names beside
//!   the narrowing this file decides — the redemption's commit, not its expiry arithmetic.
//!   `services/sts/src/redemption.rs` states that boundary for the one command path that
//!   writes at all: `decision-blocker:epoch-atomicity` "wants each boundary's isolation
//!   level named and a case showing a rolled-back transaction leaves no partially written
//!   audit record, and neither is decidable in this crate".
//!
//! A case here for any of them would have to construct the refusal itself, which is a double
//! standing in for the deciding code and covers nothing
//! (`contracts/obligations/README.md`).
//!
//! # The state each case is arranged from
//!
//! Through the real handlers, never by folding an invented event: the target is registered by
//! `register_resource_server`, the code is minted by `CodeIssuance::issue`, and the profile
//! the refusal turns on is one the **registration handler admits** — `admits_profile` asks
//! that `max_ttl` names a positive span and nothing more, so a span of `i64::MAX` seconds is
//! registered, and `issued_at.checked_add(span)` — the narrowing's own profile bound —
//! overflows `i64` and answers `None`. That overflow is what refuses, and not the end of the
//! timeline this crate can render: `instant::at` writes the year with `{year:04}`, a minimum
//! width and not a maximum, so an expiry past the last four-digit year is rendered and
//! refused by nothing (`story:sts-lifetime-bounds` owns that one). The refusal is therefore
//! reachable from a registration this deployment would accept, which is the whole difference
//! between a decided clause and an arranged one.

use mandate_sts::binding::{RecordedSessions, SessionBinding};
use mandate_sts::code::{
    AuthorizationCodeParts, CodeIssuance, CodeLifetime, IssueAuthorizationCode, RecordedClients,
};
use mandate_sts::issue::Sha256Digest;
use mandate_sts::redemption::{
    BoundReads, RedeemAuthorizationCode, RedemptionParts, RedemptionRefused, redeem_and_consume,
    redeem_authorization_code,
};
use mandate_sts::registry::{RegisterResourceServer, register_resource_server};
use mandate_sts::store::{AuthorizationCodeEvent, CodeProjection, InMemoryCodeLog, StreamVersion};
use mandate_sts::{CountingSecrets, IdentityAllocator, RequestContext, SequentialAllocator};
use mandate_token::CredentialProfile;
use mandate_token::projection::{
    CredentialEvent, DenialClause, Denied, Projection, RefusedOutcome,
};
use mandate_types::{
    Audience, AuthorityScope, AuthorizationCodeId, CorrelationId, CredentialId, CredentialKind,
    CredentialProof, DenialReason, Duration, EpochSnapshotRef, OAuthClientId, OrganizationId,
    PkceChallenge, PkceMethod, PrincipalId, RedirectUri, ResourceServerId, RevocationGuarantee,
    SessionId, Timestamp, Transient, Uuid, VerifiedContext,
};
use serde_json::Value;

/// The command this file decides a clause of.
const REDEEM_CODE: &str = "mandate.credential.RedeemAuthorizationCode";

/// The clause, verbatim, as `contracts/obligations/sts.json` names it.
const NARROWING: &str = "narrowing";

/// RFC 7636 appendix B: the example code verifier and the S256 challenge it redeems.
const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// The redirect the client registers and the code is bound to.
const REDIRECT: &str = "https://client.example/callback";

/// The compiled contract.
fn system_ir() -> Value {
    const IR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../generated/ir/system.json"
    );
    let text = std::fs::read_to_string(IR).expect("the generated IR is readable");
    serde_json::from_str(&text).expect("the generated IR is JSON")
}

/// The clause a case decides is a verbatim substring of its command's declared cause.
///
/// The registry's own rule (`contracts/obligations/README.md`), applied here so a case
/// cannot name a clause the contract has stopped publishing and go on passing.
fn assert_clause_is_declared(command: &str, clause: &str) {
    let ir = system_ir();
    let declared = ir["commands"][command]["outcomes"]
        .as_array()
        .unwrap_or_else(|| panic!("{command} declares no outcomes"))
        .iter()
        .find(|outcome| outcome["condition"]["kind"] == "external")
        .and_then(|outcome| outcome["condition"]["cause"].as_str())
        .unwrap_or_else(|| panic!("{command} declares no externally caused outcome"))
        .to_owned();
    assert!(
        declared.contains(clause),
        "{command}: `{clause}` is not a phrase of the declared denial:\n  {declared}"
    );
}

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization(tag: u8) -> OrganizationId {
    OrganizationId::new(uuid(tag))
}

fn oauth_client() -> OAuthClientId {
    OAuthClientId::new(uuid(0x0c))
}

fn oauth_session() -> SessionId {
    SessionId::new(uuid(0x5e))
}

fn subject() -> PrincipalId {
    PrincipalId::new(uuid(0x51))
}

fn snapshot() -> EpochSnapshotRef {
    EpochSnapshotRef::new(uuid(0x60))
}

fn context(organization_id: OrganizationId) -> VerifiedContext {
    VerifiedContext {
        subject: subject(),
        actor: None,
        organization: organization_id,
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("obligations"),
    }
}

fn request() -> RequestContext {
    RequestContext {
        correlation: CorrelationId::new("obligations"),
        at: Timestamp::new("2026-09-19T00:00:00Z"),
        epochs: Some(snapshot()),
    }
}

fn scope() -> AuthorityScope {
    AuthorityScope {
        actions: Vec::new(),
        resources: Vec::new(),
        space: None,
    }
}

/// A reference profile the registration handler admits and whose narrowing succeeds.
///
/// The profile the code is minted against in the zero-span case: `register_resource_server`
/// refuses a `max_ttl` of zero (`services/sts/src/registry.rs:146`), so the zero-span record
/// the redemption re-reads cannot be one this handler wrote, and the issuance the redemption
/// consumes still has to come from a registration it would have admitted.
fn reference_profile() -> CredentialProfile {
    CredentialProfile {
        name: "reference".to_owned(),
        kind: CredentialKind::Reference,
        revocation: RevocationGuarantee::BoundedOffline,
        max_ttl: Duration::new("PT1H"),
        positive_cache_ttl: Duration::new("PT0S"),
        requires_online_authorization: false,
    }
}

/// A reference profile whose `max_ttl` the registration handler admits and whose implied
/// credential expiry overflows the arithmetic the redemption narrows with.
///
/// `crate::registry::admits_profile` asks three things of a profile: that `max_ttl` names a
/// positive span, that `positive_cache_ttl` names a span between zero and that bound, and
/// that an `ImmediateOnline` guarantee comes with online authorization. A span of `i64::MAX`
/// seconds answers all three — and the narrowing's profile bound is
/// `issued_at.checked_add(span)`, which overflows `i64` for every request after the epoch
/// and answers `None`.
fn boundless_profile() -> CredentialProfile {
    CredentialProfile {
        name: "reference-past-the-i64-bound".to_owned(),
        kind: CredentialKind::Reference,
        revocation: RevocationGuarantee::BoundedOffline,
        max_ttl: Duration::new("PT9223372036854775807S"),
        positive_cache_ttl: Duration::new("PT0S"),
        requires_online_authorization: false,
    }
}

/// One registered target through the real handler, with the credential log it wrote.
fn registered(profile: CredentialProfile) -> (Projection, Vec<CredentialEvent>, ResourceServerId) {
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
    .expect("a free audience in the caller's own organization");
    let log = vec![outcome.event];
    (
        Projection::fold(&log).expect("one creation"),
        log,
        outcome.resource_server_id,
    )
}

fn clients() -> RecordedClients {
    RecordedClients::new()
        .enabled(oauth_client(), organization(10))
        .redirect(oauth_client(), RedirectUri::new(REDIRECT))
}

fn sessions() -> RecordedSessions {
    RecordedSessions::new()
        .session(SessionBinding {
            id: oauth_session(),
            subject: subject(),
            organization: organization(10),
            epochs: Some(snapshot()),
            expires_at: Timestamp::new("2026-09-19T12:00:00Z"),
            revoked: false,
        })
        .current(snapshot())
}

/// One code, minted through the real issuance handler, with the proof of holding it.
fn issued_code(
    servers: &Projection,
    target: ResourceServerId,
) -> (AuthorizationCodeEvent, AuthorizationCodeId, CredentialProof) {
    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();
    let outcome = CodeIssuance::new(CodeLifetime::new(Duration::new("PT5M")))
        .issue(
            &IssueAuthorizationCode {
                context: context(organization(10)),
                client_id: oauth_client(),
                session_id: oauth_session(),
                target,
                requested_scope: scope(),
                challenge: PkceChallenge::new(PKCE_CHALLENGE),
                method: PkceMethod::S256,
                redirect_uri: RedirectUri::new(REDIRECT),
                expires_at: Timestamp::new("2026-09-19T00:05:00Z"),
            },
            &request(),
            servers,
            &clients(),
            AuthorizationCodeParts {
                digest: &Sha256Digest,
                secrets: &mut secrets,
                allocator: &mut allocator,
            },
        )
        .expect("a registered enabled target and a registered public client");
    let proof = CredentialProof::from_bytes(outcome.code.expose_material().to_vec());
    (outcome.event, outcome.code_id, proof)
}

fn redemption(code_id: AuthorizationCodeId, proof: &CredentialProof) -> RedeemAuthorizationCode {
    RedeemAuthorizationCode {
        code_id,
        client_id: oauth_client(),
        code: CredentialProof::from_bytes(proof.expose_material().to_vec()),
        pkce_verifier: CredentialProof::from_bytes(PKCE_VERIFIER.as_bytes().to_vec()),
        redirect_uri: RedirectUri::new(REDIRECT),
    }
}

/// **"Narrowing": the credential the redemption would issue has no expiry the narrowing can
/// bound, and the transaction refuses rather than issuing one.**
///
/// `services/sts/src/redemption.rs:343-350` narrows the expiry to the earlier of the
/// profile's `issued_at + max_ttl` and the code's own `expires_at`, and `ExpiryUnbounded` is
/// that arithmetic answering `None` — so the clause it decides is "narrowing", not the
/// "atomic issuance validation" the declared cause names beside it, which is the commit
/// `decision-blocker:epoch-atomicity` owns.
///
/// Every earlier guard of the redemption is satisfied — the code resolves, the proof is the
/// one its verifier came from, the PKCE verifier redeems the recorded challenge, the code is
/// `Issued` and unexpired, the redirect is the one it authorized, the session is live and
/// current, the client is the bound one, and the target is the session's own registration —
/// so the refusal is the expiry narrowing and nothing before it.
#[test]
fn narrowing_refuses_a_credential_whose_expiry_cannot_be_bounded() {
    assert_clause_is_declared(REDEEM_CODE, NARROWING);
    let (servers, _, target) = registered(boundless_profile());
    let (issued, code_id, proof) = issued_code(&servers, target);
    let codes = CodeProjection::fold(std::slice::from_ref(&issued)).expect("one creation");
    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();

    let denied = redeem_authorization_code(
        &redemption(code_id, &proof),
        &request(),
        &codes,
        BoundReads {
            servers: &servers,
            clients: &clients(),
            sessions: &sessions(),
        },
        RedemptionParts {
            digest: &Sha256Digest,
            secrets: &mut secrets,
            allocator: &mut allocator,
        },
    )
    .expect_err("the admitted profile overflows the narrowing's `issued_at + max_ttl`");

    assert_eq!(
        denied,
        Denied::new(DenialReason::Denied, DenialClause::ExpiryUnbounded),
        "{REDEEM_CODE} / {NARROWING:?} is the declared `denied` outcome, \
         `DenialReason::Denied` and the crate-local clause `ExpiryUnbounded`"
    );
    assert_eq!(denied.outcome, RefusedOutcome::Denied);
    assert_eq!(
        secrets.minted(),
        0,
        "a refusal mints no credential: nothing above the bound touches the secret source"
    );
}

/// **The same refusal moves nothing: not the code stream, not the code fold, not the
/// credential fold, and not the identities the outcome would have minted.**
///
/// Driven through `redeem_and_consume`, which is the one function in this crate that writes,
/// so "no lifecycle mutation on refusal" is decided over the writer and not over the deciding
/// half alone. The log is an in-memory port that supplies the record; the decision is the
/// shipped handler's.
#[test]
fn a_redemption_refused_on_the_narrowing_clause_moves_neither_log_nor_fold() {
    let (servers, credential_log, target) = registered(boundless_profile());
    let (issued, code_id, proof) = issued_code(&servers, target);
    let mut log = InMemoryCodeLog::new();
    log.append(
        &code_id,
        StreamVersion::INITIAL,
        std::slice::from_ref(&issued),
    )
    .expect("an empty stream takes its creation");

    let events = log.events(&code_id);
    let version = log.version(&code_id);
    let codes = log.projection().clone();
    let credentials = Projection::fold(&seeded(&credential_log, &log, &code_id))
        .expect("the registration, and whatever credential events the code log seeds");
    assert_eq!(
        credentials, servers,
        "before the redemption the seeded fold is the registration and nothing else: an \
         issuance seeds no credential"
    );
    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();

    let refused = redeem_and_consume(
        &redemption(code_id, &proof),
        &request(),
        &mut log,
        BoundReads {
            servers: &servers,
            clients: &clients(),
            sessions: &sessions(),
        },
        RedemptionParts {
            digest: &Sha256Digest,
            secrets: &mut secrets,
            allocator: &mut allocator,
        },
    )
    .expect_err("the admitted profile overflows the narrowing's `issued_at + max_ttl`");

    assert_eq!(
        refused,
        RedemptionRefused::Denied(Denied::new(
            DenialReason::Denied,
            DenialClause::ExpiryUnbounded
        )),
        "the transaction refused on the decision, not on its append"
    );
    assert_eq!(
        log.events(&code_id),
        events,
        "the code stream is the one it was"
    );
    assert_eq!(log.version(&code_id), version, "no group was appended");
    assert_eq!(
        *log.projection(),
        codes,
        "the code fold is the one it was: a refused decision commits nothing"
    );
    assert_eq!(
        Projection::fold(&seeded(&credential_log, &log, &code_id)).expect("the log as refused"),
        credentials,
        "the credential fold the writer's own log seeds is the one it was: a refused \
         redemption appends no `AuthorizationCodeRedeemed`, so `credential_event` seeds nothing"
    );
    assert_eq!(
        secrets.minted(),
        0,
        "a refusal mints no credential material"
    );
    assert_eq!(
        allocator.next_credential_id(),
        SequentialAllocator::new().next_credential_id(),
        "a refusal mints no credential identity: the allocator is where it was"
    );
}

/// The credential log a deployment composing the two holds: the registrations it already had,
/// and the credential payload every event of the code log seeds
/// (`mandate_sts::store::AuthorizationCodeEvent::credential_event`).
///
/// An issuance seeds `None`; only `AuthorizationCodeRedeemed` seeds a credential. Folding this
/// is what makes "the credential fold did not move" a statement about the **writer's own log**
/// rather than about a `Vec` the case is holding, which the same assertion compared to itself
/// before.
fn seeded(
    registrations: &[CredentialEvent],
    log: &InMemoryCodeLog,
    code_id: &AuthorizationCodeId,
) -> Vec<CredentialEvent> {
    registrations
        .iter()
        .cloned()
        .chain(
            log.events(code_id)
                .iter()
                .filter_map(AuthorizationCodeEvent::credential_event),
        )
        .collect()
}

/// **"Narrowing", its second condition: a profile bound naming a span of zero refuses the
/// redemption rather than dating the credential at the instant it was issued, and moves
/// nothing.**
///
/// The clause has two ways to fail, and the case above decides one of them —
/// `issued_at.checked_add(span)` overflowing. This decides the other:
/// `services/sts/src/redemption.rs:346` filters the profile span to `> 0`, and
/// `instant::span_of` never answers a negative span, so that filter decides exactly one
/// input. Without it a zero span dates the credential at `issued_at` and the handler issues a
/// credential that expired at the instant it was minted, rather than refusing.
///
/// The registration carrying the zero span is **constructed**, as
/// `declared_denials::unbounded_profile_target` is and for the same stated reason:
/// `admits_profile` refuses a `max_ttl` of zero at registration
/// (`services/sts/src/registry.rs:146`), so a record carrying one is one another writer put in
/// the log — which is exactly what the redemption's re-read of the registration exists for.
/// The code itself is minted against a registration this handler did admit, so nothing before
/// the narrowing refuses.
///
/// Driven through `redeem_and_consume`, so the "moves nothing" half is decided over the
/// writer and not over the deciding half alone.
#[test]
fn narrowing_refuses_a_zero_span_profile_bound_and_moves_nothing() {
    assert_clause_is_declared(REDEEM_CODE, NARROWING);
    let (admitted, _, target) = registered(reference_profile());
    let (issued, code_id, proof) = issued_code(&admitted, target);
    let credential_log = vec![CredentialEvent::ResourceServerRegistered {
        context: context(organization(10)),
        id: target,
        audience: Audience::new("api-a"),
        credential_profile: CredentialProfile {
            max_ttl: Duration::new("PT0S"),
            ..reference_profile()
        },
        allowed_exchange_sources: Vec::new(),
    }];
    let servers = Projection::fold(&credential_log).expect("one creation");

    let mut log = InMemoryCodeLog::new();
    log.append(
        &code_id,
        StreamVersion::INITIAL,
        std::slice::from_ref(&issued),
    )
    .expect("an empty stream takes its creation");

    let events = log.events(&code_id);
    let version = log.version(&code_id);
    let codes = log.projection().clone();
    let credentials = Projection::fold(&seeded(&credential_log, &log, &code_id))
        .expect("the registration, and whatever credential events the code log seeds");
    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();

    let refused = redeem_and_consume(
        &redemption(code_id, &proof),
        &request(),
        &mut log,
        BoundReads {
            servers: &servers,
            clients: &clients(),
            sessions: &sessions(),
        },
        RedemptionParts {
            digest: &Sha256Digest,
            secrets: &mut secrets,
            allocator: &mut allocator,
        },
    )
    .expect_err("a profile bound of zero names no instant the narrowing can date to");

    assert_eq!(
        refused,
        RedemptionRefused::Denied(Denied::new(
            DenialReason::Denied,
            DenialClause::ExpiryUnbounded
        )),
        "{REDEEM_CODE} / {NARROWING:?}: a zero profile span is the narrowing failing, not a \
         credential dated at its own issuance"
    );
    assert_eq!(
        log.events(&code_id),
        events,
        "the code stream is the one it was"
    );
    assert_eq!(log.version(&code_id), version, "no group was appended");
    assert_eq!(
        *log.projection(),
        codes,
        "the code fold is the one it was: a refused decision commits nothing"
    );
    assert_eq!(
        Projection::fold(&seeded(&credential_log, &log, &code_id)).expect("the log as refused"),
        credentials,
        "the credential fold the writer's own log seeds is the one it was"
    );
    assert_eq!(
        secrets.minted(),
        0,
        "a refusal mints no credential material"
    );
    assert_eq!(
        allocator.next_credential_id(),
        SequentialAllocator::new().next_credential_id(),
        "a refusal mints no credential identity: the allocator is where it was"
    );
}
