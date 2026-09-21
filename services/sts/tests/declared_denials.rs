//! **Every refusal this crate's handlers construct is phrased by the contract.**
//!
//! `mandate_token::projection::DenialClause` is a crate-local discriminator and not a
//! contract field, which is exactly why it can drift: nothing in the compiler relates a
//! variant to the document it is supposed to be a phrase of. Adversary pass 1 found four
//! variants naming conditions `RedeemAuthorizationCode`'s declared denial does not carry.
//! This is the check that closes the class rather than those four instances: every
//! `(command, clause)` pair this crate can produce is decided against
//! `generated/ir/system.json`, and a clause whose phrase the contract does not carry fails
//! here naming both.
//!
//! # What the contract offers, and what is matched against it
//!
//! Three kinds of refusal, and the contract declares each differently:
//!
//! - An **external denial** carries prose: the `denied` outcome's `condition.cause`. A
//!   clause of this kind names a substring of it, verbatim.
//! - A **`wrong-state`** refusal carries no prose at all — the contract declares it by the
//!   transition's `from:` set — so what is decided is that the command declares a
//!   `wrong-state` outcome and that the refusal took it.
//! - One refusal is a **declared entity invariant** checked by the handler rather than a
//!   denial phrase: `RegisterSigningKey`'s `not_before < expires_at`
//!   (`credential.yaml`, `mandate.credential.SigningKey.invariants`). It is matched against
//!   the invariant the IR declares for that entity. That the contract gives it no denial
//!   phrase is a contract observation, recorded on its row rather than excused by an
//!   exception list.
//!
//! # What bounds the class
//!
//! [`ROWS`] is read from this crate's handlers, and the two directions that can be machine
//! checked are: every row's phrase is one the contract carries, and every row is reachable —
//! the authorization-code rows are driven through the real handlers below, and no row is
//! unused. What is **not** compiler-checked is that a handler cannot construct a clause with
//! no row: `DenialClause` is `#[non_exhaustive]`, so a downstream `match` needs a wildcard
//! and cannot be made exhaustive. Closing that half needs the refusal constructor itself to
//! demand a phrase, which reaches four handler files this unit does not own; it is reported
//! rather than implied.

use std::collections::BTreeSet;

use mandate_sts::binding::{RecordedSessions, SessionBinding, fresh_session};
use mandate_sts::code::{
    AuthorizationCodeParts, CodeIssuance, CodeLifetime, IssueAuthorizationCode, RecordedClients,
};
use mandate_sts::issue::{
    IssuanceSigner, IssueReferenceCredential, IssueSelfContainedCredential, ReferenceParts,
    SelfContainedParts, Sha256Digest, StaticSigner, issue_reference_credential,
    issue_self_contained_credential,
};
use mandate_sts::keys::{
    KeyMaterialResolver, RegisterSigningKey, RetireSigningKey, RevokeSigningKey,
    SigningKeyAdministration, retire_signing_key, revoke_signing_key,
};
use mandate_sts::redemption::{
    BoundReads, RedeemAuthorizationCode, RedemptionParts, redeem_authorization_code,
};
use mandate_sts::registry::{
    DisableResourceServer, RegisterResourceServer, disable_resource_server,
    register_resource_server,
};
use mandate_sts::resolve::{
    CredentialResolution, IntrospectCredential, IntrospectionParts, ResolutionUnavailable,
    RevokeAccessCredential, introspect_credential, revoke_access_credential,
};
use mandate_sts::store::{CodeProjection, InMemoryCodeLog, StreamVersion};
use mandate_sts::{CountingSecrets, RequestContext, SequentialAllocator};
use mandate_token::projection::AccessCredential;
use mandate_token::projection::{
    CredentialEvent, DenialClause, Denied, Projection, RefusedOutcome, ResourceServerState,
};
use mandate_token::signing_real::{
    AllowedAlgorithms, SignedCredential, SigningError, StandardClaims,
};
use mandate_token::verifier::verifier_for;
use mandate_token::{CredentialDescriptor, CredentialProfile};
use mandate_types::{
    Audience, AuthorityScope, CorrelationId, CredentialId, CredentialKind, CredentialProof,
    CredentialVerifier, Duration, EpochSnapshotRef, Issuer, KeyReference, OAuthClientId,
    OrganizationId, PkceChallenge, PkceMethod, PrincipalId, RedirectUri, ResourceServerId,
    RevocationGuarantee, SessionId, SigningAlgorithm, SigningKeyId, Timestamp, Transient, Uuid,
    VerifiedContext,
};
use serde_json::Value;

/// Where a refusal's authority comes from in the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    /// A substring of the command's `denied` outcome's declared cause.
    DenialPhrase(&'static str),
    /// The command's declared `wrong-state` outcome, which carries no prose.
    WrongState,
    /// A declared invariant of an entity, checked by the deciding handler.
    EntityInvariant(&'static str, &'static str),
}

/// Every `(command, clause)` pair this crate's handlers construct, with what declares it.
///
/// **Every phrase stays on one line.** `services/sts/tests/adversary_transaction_2.rs` reads
/// this table as a document — a row's command is a line that is nothing but a quoted element
/// name — so a phrase `rustfmt` wrapped onto its own line would read as a command name and
/// silently re-attribute the rows after it. The phrases below are therefore chosen short
/// enough to stay unwrapped, and each is still a verbatim substring of the declared denial,
/// which is the only thing the check compares.
///
/// Read from `services/sts/src/{registry,issue,resolve,keys,code,redemption}.rs` and
/// `crates/mandate-token/src/projection.rs`'s `admits_audience`, which
/// `register_resource_server` refuses through.
const ROWS: &[(&str, DenialClause, Source)] = &[
    // --- RegisterResourceServer
    (
        "mandate.credential.RegisterResourceServer",
        DenialClause::AudienceAmbiguous,
        Source::DenialPhrase("audience registration is ambiguous"),
    ),
    (
        "mandate.credential.RegisterResourceServer",
        DenialClause::ProfileUnadmitted,
        Source::DenialPhrase("profile semantics are unadmitted"),
    ),
    (
        "mandate.credential.RegisterResourceServer",
        DenialClause::SourceUnresolved,
        Source::DenialPhrase("an allowed source server is unresolved"),
    ),
    (
        "mandate.credential.RegisterResourceServer",
        DenialClause::SourceDisabled,
        Source::DenialPhrase("unresolved/disabled/outside"),
    ),
    (
        "mandate.credential.RegisterResourceServer",
        DenialClause::SourceOutsideOrganization,
        Source::DenialPhrase("outside the verified organization"),
    ),
    // --- DisableResourceServer
    (
        "mandate.credential.DisableResourceServer",
        DenialClause::TargetUnregistered,
        Source::DenialPhrase("server is outside the verified organization"),
    ),
    (
        "mandate.credential.DisableResourceServer",
        DenialClause::OrganizationMismatch,
        Source::DenialPhrase("server is outside the verified organization"),
    ),
    (
        "mandate.credential.DisableResourceServer",
        DenialClause::ServerDisabled,
        Source::WrongState,
    ),
    // --- IssueReferenceCredential
    (
        "mandate.credential.IssueReferenceCredential",
        DenialClause::TargetUnregistered,
        Source::DenialPhrase("target/profile is unregistered/disabled/outside tenant"),
    ),
    (
        "mandate.credential.IssueReferenceCredential",
        DenialClause::TargetDisabled,
        Source::DenialPhrase("target/profile is unregistered/disabled/outside tenant"),
    ),
    (
        "mandate.credential.IssueReferenceCredential",
        DenialClause::OrganizationMismatch,
        Source::DenialPhrase("target/profile is unregistered/disabled/outside tenant"),
    ),
    (
        "mandate.credential.IssueReferenceCredential",
        DenialClause::ProfileUnadmitted,
        Source::DenialPhrase("target/profile is unregistered/disabled/outside tenant"),
    ),
    (
        "mandate.credential.IssueReferenceCredential",
        DenialClause::ExpiryUnbounded,
        Source::DenialPhrase("expiry cannot be bounded"),
    ),
    // --- IssueSelfContainedCredential
    (
        "mandate.credential.IssueSelfContainedCredential",
        DenialClause::TargetUnregistered,
        Source::DenialPhrase("target/profile/signing algorithm or key is unadmitted"),
    ),
    (
        "mandate.credential.IssueSelfContainedCredential",
        DenialClause::TargetDisabled,
        Source::DenialPhrase("target/profile/signing algorithm or key is unadmitted"),
    ),
    (
        "mandate.credential.IssueSelfContainedCredential",
        DenialClause::OrganizationMismatch,
        Source::DenialPhrase("target/profile/signing algorithm or key is unadmitted"),
    ),
    (
        "mandate.credential.IssueSelfContainedCredential",
        DenialClause::ProfileUnadmitted,
        Source::DenialPhrase("target/profile/signing algorithm or key is unadmitted"),
    ),
    (
        "mandate.credential.IssueSelfContainedCredential",
        DenialClause::SigningRefused,
        Source::DenialPhrase("target/profile/signing algorithm or key is unadmitted"),
    ),
    (
        "mandate.credential.IssueSelfContainedCredential",
        DenialClause::ExpiryUnbounded,
        Source::DenialPhrase("expiry cannot be bounded"),
    ),
    // --- IntrospectCredential
    (
        "mandate.credential.IntrospectCredential",
        DenialClause::ProofMalformed,
        Source::DenialPhrase("the presented credential proof is malformed"),
    ),
    (
        "mandate.credential.IntrospectCredential",
        DenialClause::CallerProofInvalid,
        Source::DenialPhrase("is itself invalid, revoked or expired"),
    ),
    (
        "mandate.credential.IntrospectCredential",
        DenialClause::IntrospectionAuthority,
        Source::DenialPhrase("lacks introspection authority"),
    ),
    (
        "mandate.credential.IntrospectCredential",
        DenialClause::AudienceMismatch,
        Source::DenialPhrase("audience mismatches"),
    ),
    (
        "mandate.credential.IntrospectCredential",
        DenialClause::ResolutionUnavailable,
        Source::DenialPhrase("authoritative online resolution is unavailable"),
    ),
    // Adversary pass 2, F1. `introspect_credential` refuses a presented credential of
    // another organization than the caller's, and `IntrospectCredential`'s declared denial
    // names no phrase for it: its six clauses are the caller's authority, the caller's own
    // proof, a malformed presented proof, principal/connection/epoch validation, an audience
    // mismatch and an unavailable resolution. "for the registered server/tenant" is the
    // nearest the text comes — the authority clause's own tenant half — and it is not an
    // exact fit. The gap is routed to the contract; recorded here rather than left to the
    // next reader to notice that one branch of that handler quotes nothing.
    (
        "mandate.credential.IntrospectCredential",
        DenialClause::OrganizationMismatch,
        Source::DenialPhrase("for the registered server/tenant"),
    ),
    // --- RevokeAccessCredential
    (
        "mandate.credential.RevokeAccessCredential",
        DenialClause::CredentialUnknown,
        Source::DenialPhrase("resolved credential is outside the verified organization"),
    ),
    (
        "mandate.credential.RevokeAccessCredential",
        DenialClause::OrganizationMismatch,
        Source::DenialPhrase("resolved credential is outside the verified organization"),
    ),
    (
        "mandate.credential.RevokeAccessCredential",
        DenialClause::CredentialRevoked,
        Source::WrongState,
    ),
    // --- RegisterSigningKey
    (
        "mandate.credential.RegisterSigningKey",
        DenialClause::AlgorithmUnadmitted,
        Source::DenialPhrase("the algorithm is outside the deployment's admitted set"),
    ),
    (
        "mandate.credential.RegisterSigningKey",
        DenialClause::KeyReferenceUnresolvable,
        Source::DenialPhrase("the key reference is unresolvable"),
    ),
    (
        "mandate.credential.RegisterSigningKey",
        DenialClause::KeyReferenceRecorded,
        Source::DenialPhrase("the key reference or the key material is already recorded"),
    ),
    (
        "mandate.credential.RegisterSigningKey",
        DenialClause::KeyMaterialRecorded,
        Source::DenialPhrase("the key reference or the key material is already recorded"),
    ),
    // The one refusal in this crate that no denial phrase carries: the declared entity
    // invariant, which `credential.yaml` says is "checked by the deciding handler".
    (
        "mandate.credential.RegisterSigningKey",
        DenialClause::KeyWindowNotOrdered,
        Source::EntityInvariant("mandate.credential.SigningKey", "not_before < expires_at"),
    ),
    // --- RetireSigningKey
    (
        "mandate.credential.RetireSigningKey",
        DenialClause::KeyUnknown,
        Source::DenialPhrase("the key is unresolved"),
    ),
    (
        "mandate.credential.RetireSigningKey",
        DenialClause::NoReplacementKey,
        Source::DenialPhrase("no overlapping replacement key is published"),
    ),
    (
        "mandate.credential.RetireSigningKey",
        DenialClause::KeyNotRecorded,
        Source::WrongState,
    ),
    // --- RevokeSigningKey
    (
        "mandate.credential.RevokeSigningKey",
        DenialClause::KeyUnknown,
        Source::DenialPhrase("the key is unresolved"),
    ),
    (
        "mandate.credential.RevokeSigningKey",
        DenialClause::KeyNotRecorded,
        Source::WrongState,
    ),
    // --- IssueAuthorizationCode
    (
        "mandate.credential.IssueAuthorizationCode",
        DenialClause::TargetUnregistered,
        Source::DenialPhrase("tenant/target agreement"),
    ),
    (
        "mandate.credential.IssueAuthorizationCode",
        DenialClause::TargetDisabled,
        Source::DenialPhrase("tenant/target agreement"),
    ),
    (
        "mandate.credential.IssueAuthorizationCode",
        DenialClause::OrganizationMismatch,
        Source::DenialPhrase("tenant/target agreement"),
    ),
    (
        "mandate.credential.IssueAuthorizationCode",
        DenialClause::ProfileUnadmitted,
        Source::DenialPhrase("tenant/target agreement"),
    ),
    (
        "mandate.credential.IssueAuthorizationCode",
        DenialClause::ClientUnregistered,
        Source::DenialPhrase("registered public client"),
    ),
    (
        "mandate.credential.IssueAuthorizationCode",
        DenialClause::ClientNotPublic,
        Source::DenialPhrase("registered public client"),
    ),
    (
        "mandate.credential.IssueAuthorizationCode",
        DenialClause::ClientOutsideOrganization,
        Source::DenialPhrase("tenant/target agreement"),
    ),
    (
        "mandate.credential.IssueAuthorizationCode",
        DenialClause::ClientDisabled,
        Source::DenialPhrase("the client the code would be bound to is disabled"),
    ),
    (
        "mandate.credential.IssueAuthorizationCode",
        DenialClause::RedirectUnregistered,
        Source::DenialPhrase("exact redirect URI"),
    ),
    (
        "mandate.credential.IssueAuthorizationCode",
        DenialClause::ChallengeMalformed,
        Source::DenialPhrase("S256 policy"),
    ),
    (
        "mandate.credential.IssueAuthorizationCode",
        DenialClause::ExpiryUnbounded,
        Source::DenialPhrase("bounded expiry"),
    ),
    // --- RedeemAuthorizationCode
    (
        "mandate.credential.RedeemAuthorizationCode",
        DenialClause::CodeUnknown,
        Source::DenialPhrase("Code proof does not match the server-resolved code_id"),
    ),
    (
        "mandate.credential.RedeemAuthorizationCode",
        DenialClause::CodeProofMismatch,
        Source::DenialPhrase("Code proof does not match the server-resolved code_id"),
    ),
    (
        "mandate.credential.RedeemAuthorizationCode",
        DenialClause::CodeExpired,
        Source::DenialPhrase("code is expired"),
    ),
    (
        "mandate.credential.RedeemAuthorizationCode",
        DenialClause::CodeConsumed,
        Source::WrongState,
    ),
    (
        "mandate.credential.RedeemAuthorizationCode",
        DenialClause::ClientMismatch,
        Source::DenialPhrase("client, redirect URI or S256 verifier mismatches"),
    ),
    (
        "mandate.credential.RedeemAuthorizationCode",
        DenialClause::ClientUnregistered,
        Source::DenialPhrase("client, redirect URI or S256 verifier mismatches"),
    ),
    (
        "mandate.credential.RedeemAuthorizationCode",
        DenialClause::ClientOutsideOrganization,
        Source::DenialPhrase("client, redirect URI or S256 verifier mismatches"),
    ),
    (
        "mandate.credential.RedeemAuthorizationCode",
        DenialClause::ClientDisabled,
        Source::DenialPhrase("the bound client is disabled"),
    ),
    (
        "mandate.credential.RedeemAuthorizationCode",
        DenialClause::RedirectMismatch,
        Source::DenialPhrase("client, redirect URI or S256 verifier mismatches"),
    ),
    (
        "mandate.credential.RedeemAuthorizationCode",
        DenialClause::ChallengeMalformed,
        Source::DenialPhrase("client, redirect URI or S256 verifier mismatches"),
    ),
    (
        "mandate.credential.RedeemAuthorizationCode",
        DenialClause::VerifierMalformed,
        Source::DenialPhrase("client, redirect URI or S256 verifier mismatches"),
    ),
    (
        "mandate.credential.RedeemAuthorizationCode",
        DenialClause::VerifierMismatch,
        Source::DenialPhrase("client, redirect URI or S256 verifier mismatches"),
    ),
    (
        "mandate.credential.RedeemAuthorizationCode",
        DenialClause::TargetUnregistered,
        Source::DenialPhrase("registered target is disabled or outside the verified tenant"),
    ),
    (
        "mandate.credential.RedeemAuthorizationCode",
        DenialClause::TargetDisabled,
        Source::DenialPhrase("registered target is disabled or outside the verified tenant"),
    ),
    (
        "mandate.credential.RedeemAuthorizationCode",
        DenialClause::OrganizationMismatch,
        Source::DenialPhrase("registered target is disabled or outside the verified tenant"),
    ),
    (
        "mandate.credential.RedeemAuthorizationCode",
        DenialClause::SessionEpochStale,
        Source::DenialPhrase("source/session epoch is stale"),
    ),
    // Adversary pass 2, F4. `RedeemAuthorizationCode`'s denial names "source/session epoch
    // is stale" and **no phrase at all** for a session that resolves to nothing, has been
    // revoked or has expired — which its own accepted summary says the outcome reads through
    // the STS's session port (`credential.yaml:245`). This clause rows to the nearest phrase
    // the text carries, the same one `services/sts/src/binding.rs` names; the two are kept
    // apart as clauses, and by `DenialReason`, because what a caller can act on differs. The
    // gap is routed to the contract.
    (
        "mandate.credential.RedeemAuthorizationCode",
        DenialClause::SessionUnusable,
        Source::DenialPhrase("source/session epoch is stale"),
    ),
    // `services/sts/src/redemption.rs:343-350` narrows the expiry to
    // `min(issued_at + max_ttl, code.expires_at)`, and `ExpiryUnbounded` is the failure of
    // that narrowing and not of the append that follows it. The cause's last condition names
    // two: this row quotes the half the handler decides, so the phrase falls inside the
    // registry clause that carries it (`contracts/obligations/sts.json`) instead of across
    // its boundary into `atomic issuance validation fails`, which
    // `decision-blocker:epoch-atomicity` owns.
    (
        "mandate.credential.RedeemAuthorizationCode",
        DenialClause::ExpiryUnbounded,
        Source::DenialPhrase("narrowing"),
    ),
];

/// The compiled contract, read once per case that needs it.
fn system_ir() -> Value {
    const IR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../generated/ir/system.json"
    );
    let text = std::fs::read_to_string(IR).expect("the generated IR is readable");
    serde_json::from_str(&text).expect("the generated IR is JSON")
}

fn outcome<'a>(ir: &'a Value, command: &str, name: &str) -> Option<&'a Value> {
    ir["commands"][command]["outcomes"]
        .as_array()?
        .iter()
        .find(|outcome| outcome["name"] == name)
}

/// **Every row's phrase is one the contract carries, verbatim.**
#[test]
fn every_clause_this_crate_constructs_is_declared_by_its_command() {
    let ir = system_ir();

    for (command, clause, source) in ROWS {
        assert!(
            ir["commands"].get(command).is_some(),
            "{command} is declared by no command index of generated/ir/system.json"
        );
        match source {
            Source::DenialPhrase(phrase) => {
                let declared = outcome(&ir, command, "denied")
                    .and_then(|denied| denied["condition"]["cause"].as_str())
                    .unwrap_or_else(|| panic!("{command} declares no `denied` cause"));
                assert!(
                    declared.contains(phrase),
                    "{command} / {clause:?}: `{phrase}` is not a phrase of the declared \
                     denial:\n  {declared}"
                );
            }
            Source::WrongState => {
                assert!(
                    outcome(&ir, command, "wrong-state").is_some(),
                    "{command} / {clause:?} is a wrong-state refusal, but {command} \
                     declares no `wrong-state` outcome"
                );
            }
            Source::EntityInvariant(entity, invariant) => {
                let declared = ir["entities"][entity]["invariants"]
                    .as_array()
                    .unwrap_or_else(|| panic!("{entity} declares no invariants"));
                assert!(
                    declared.iter().any(|declared| declared == invariant),
                    "{command} / {clause:?}: `{invariant}` is not an invariant {entity} \
                     declares: {declared:?}"
                );
            }
        }
    }
}

/// No row is an ornament: each `(command, clause)` pair appears once, and a command with a
/// row is one this crate realizes.
#[test]
fn the_rows_are_distinct_and_name_commands_this_crate_realizes() {
    let realized: BTreeSet<&str> = mandate_sts::ESS_REALIZATIONS
        .iter()
        .map(|(element, _)| *element)
        .collect();
    let mut seen: BTreeSet<(&str, String)> = BTreeSet::new();

    for (command, clause, _) in ROWS {
        assert!(
            realized.contains(command),
            "{command} carries a denial row and is realized by nothing in this crate"
        );
        assert!(
            seen.insert((command, format!("{clause:?}"))),
            "{command} / {clause:?} has two rows"
        );
    }
    assert_eq!(seen.len(), ROWS.len());
}

/// **Every command this crate realizes has rows, and every one of them is decided in both
/// directions.**
///
/// Adversary pass 2, F1: the both-direction check ran for two commands, so a clause another
/// handler constructed without a row was caught by neither direction. This is the statement
/// that no command is one-direction any more, machine-checked rather than counted by a
/// reader: the commands `ESS_REALIZATIONS` realizes, the commands `ROWS` carries, and the
/// commands `assert_clauses_match_rows` is called for are the same set.
#[test]
fn every_command_this_crate_realizes_is_decided_in_both_directions() {
    let ir = system_ir();
    let realized: BTreeSet<&str> = mandate_sts::ESS_REALIZATIONS
        .iter()
        .map(|(element, _)| *element)
        .filter(|element| ir["commands"].get(*element).is_some())
        .collect();
    let rowed: BTreeSet<&str> = ROWS.iter().map(|(command, _, _)| *command).collect();
    assert_eq!(
        realized, rowed,
        "every command this crate realizes carries denial rows"
    );

    // The other half is read out of this file: a command is decided in both directions when
    // `assert_clauses_match_rows` is called for it, which is what drives its handler and
    // compares what it produced against its rows.
    const SELF: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/declared_denials.rs");
    let text = std::fs::read_to_string(SELF).expect("this file is readable");
    let driven: BTreeSet<&str> = rowed
        .iter()
        .copied()
        .filter(|command| {
            text.split("assert_clauses_match_rows(")
                .skip(1)
                .any(|call| {
                    call.split_once(',')
                        .is_some_and(|(named, _)| named.trim().trim_matches('"') == *command)
                })
        })
        .collect();
    assert_eq!(
        driven, rowed,
        "every command with rows is driven through assert_clauses_match_rows, so a clause          its handler constructs without a row is red"
    );
}

// --- the authorization-code rows, driven through the real handlers -----------------------

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization(tag: u8) -> OrganizationId {
    OrganizationId::new(uuid(tag))
}

fn client() -> OAuthClientId {
    OAuthClientId::new(uuid(0x0c))
}

fn redirect() -> RedirectUri {
    RedirectUri::new("https://client.example/callback")
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
        correlation: CorrelationId::new("declared-denials"),
    }
}

fn request() -> RequestContext {
    RequestContext {
        correlation: CorrelationId::new("declared-denials"),
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

fn reference_profile() -> CredentialProfile {
    CredentialProfile {
        name: "reference".to_owned(),
        kind: CredentialKind::Reference,
        revocation: RevocationGuarantee::ImmediateOnline,
        max_ttl: Duration::new("PT1H"),
        positive_cache_ttl: Duration::new("PT30S"),
        requires_online_authorization: true,
    }
}

fn registered_target() -> (Projection, ResourceServerId) {
    let mut allocator = SequentialAllocator::new();
    let outcome = register_resource_server(
        &RegisterResourceServer {
            context: context(organization(10)),
            audience: Audience::new("api-a"),
            profile: reference_profile(),
            allowed_exchange_sources: Vec::new(),
        },
        &Projection::default(),
        &mut allocator,
    )
    .expect("a free audience");
    let id = outcome.resource_server_id;
    (
        Projection::fold(std::slice::from_ref(&outcome.event)).expect("one creation"),
        id,
    )
}

fn registered_client() -> RecordedClients {
    RecordedClients::new()
        .enabled(client(), organization(10))
        .redirect(client(), redirect())
}

fn issuance() -> CodeIssuance {
    CodeIssuance::new(CodeLifetime::new(Duration::new("PT5M")))
}

fn code_input(target: ResourceServerId) -> IssueAuthorizationCode {
    IssueAuthorizationCode {
        context: context(organization(10)),
        client_id: client(),
        session_id: SessionId::new(uuid(0x5e)),
        target,
        requested_scope: scope(),
        challenge: PkceChallenge::new("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
        method: PkceMethod::S256,
        redirect_uri: redirect(),
        expires_at: Timestamp::new("2026-09-19T00:05:00Z"),
    }
}

/// Every clause `IssueAuthorizationCode` can refuse with is one a row names, and every row
/// for that command is one the handler actually produces.
#[test]
fn every_refusal_issue_authorization_code_produces_has_a_row() {
    let (servers, target) = registered_target();
    let disabled_servers = {
        let mut fold = servers.clone();
        fold.apply(
            &mandate_sts::registry::disable_resource_server(
                &mandate_sts::registry::DisableResourceServer {
                    id: target,
                    context: context(organization(10)),
                },
                &servers,
            )
            .expect("an enabled registration"),
        )
        .expect("the disablement");
        fold
    };
    let other_tenant = {
        let mut allocator = SequentialAllocator::new();
        let outcome = register_resource_server(
            &RegisterResourceServer {
                context: context(organization(11)),
                audience: Audience::new("api-a"),
                profile: reference_profile(),
                allowed_exchange_sources: Vec::new(),
            },
            &Projection::default(),
            &mut allocator,
        )
        .expect("a free audience");
        (
            Projection::fold(std::slice::from_ref(&outcome.event)).expect("one creation"),
            outcome.resource_server_id,
        )
    };
    let self_contained = {
        let mut allocator = SequentialAllocator::new();
        let outcome = register_resource_server(
            &RegisterResourceServer {
                context: context(organization(10)),
                audience: Audience::new("api-b"),
                profile: CredentialProfile {
                    name: "self-contained".to_owned(),
                    kind: CredentialKind::SelfContained,
                    revocation: RevocationGuarantee::BoundedOffline,
                    max_ttl: Duration::new("PT15M"),
                    positive_cache_ttl: Duration::new("PT0S"),
                    requires_online_authorization: false,
                },
                allowed_exchange_sources: Vec::new(),
            },
            &Projection::default(),
            &mut allocator,
        )
        .expect("a free audience");
        (
            Projection::fold(std::slice::from_ref(&outcome.event)).expect("one creation"),
            outcome.resource_server_id,
        )
    };

    let refuse = |fold: &Projection, clients: &RecordedClients, input: &IssueAuthorizationCode| {
        let mut secrets = CountingSecrets::new();
        let mut allocator = SequentialAllocator::new();
        issuance()
            .issue(
                input,
                &request(),
                fold,
                clients,
                AuthorizationCodeParts {
                    digest: &Sha256Digest,
                    secrets: &mut secrets,
                    allocator: &mut allocator,
                },
            )
            .expect_err("a refusal")
    };

    let observed: Vec<Denied> = vec![
        refuse(
            &servers,
            &registered_client(),
            &IssueAuthorizationCode {
                target: ResourceServerId::new(uuid(0x39)),
                ..code_input(target)
            },
        ),
        refuse(&disabled_servers, &registered_client(), &code_input(target)),
        refuse(
            &other_tenant.0,
            &registered_client(),
            &code_input(other_tenant.1),
        ),
        refuse(
            &self_contained.0,
            &registered_client(),
            &code_input(self_contained.1),
        ),
        refuse(&servers, &RecordedClients::new(), &code_input(target)),
        refuse(
            &servers,
            &RecordedClients::new()
                .confidential(client(), organization(10))
                .redirect(client(), redirect()),
            &code_input(target),
        ),
        refuse(
            &servers,
            &RecordedClients::new()
                .enabled(client(), organization(11))
                .redirect(client(), redirect()),
            &code_input(target),
        ),
        refuse(
            &servers,
            &RecordedClients::new()
                .disabled(client(), organization(10))
                .redirect(client(), redirect()),
            &code_input(target),
        ),
        refuse(
            &servers,
            &registered_client(),
            &IssueAuthorizationCode {
                redirect_uri: RedirectUri::new("https://attacker.example/steal"),
                ..code_input(target)
            },
        ),
        refuse(
            &servers,
            &registered_client(),
            &IssueAuthorizationCode {
                challenge: PkceChallenge::new("too-short"),
                ..code_input(target)
            },
        ),
        refuse(
            &servers,
            &registered_client(),
            &IssueAuthorizationCode {
                expires_at: Timestamp::new("2026-09-19T01:00:00Z"),
                ..code_input(target)
            },
        ),
    ];

    assert_clauses_match_rows("mandate.credential.IssueAuthorizationCode", &observed);
}

/// The same for `RedeemAuthorizationCode`, driven through the deciding half.
#[test]
fn every_refusal_redeem_authorization_code_produces_has_a_row() {
    let (servers, target) = registered_target();
    let clients = registered_client();
    let session = SessionBinding {
        id: SessionId::new(uuid(0x5e)),
        subject: PrincipalId::new(uuid(0x51)),
        organization: organization(10),
        epochs: Some(EpochSnapshotRef::new(uuid(0x60))),
        expires_at: Timestamp::new("2026-09-19T12:00:00Z"),
        revoked: false,
    };
    let sessions = RecordedSessions::new()
        .session(session.clone())
        .current(EpochSnapshotRef::new(uuid(0x60)));

    // One code, through the real issuance.
    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();
    let issued = issuance()
        .issue(
            &code_input(target),
            &request(),
            &servers,
            &clients,
            AuthorizationCodeParts {
                digest: &Sha256Digest,
                secrets: &mut secrets,
                allocator: &mut allocator,
            },
        )
        .expect("a registered enabled target and client");
    let mut log = InMemoryCodeLog::new();
    log.append(
        &issued.code_id,
        StreamVersion::INITIAL,
        std::slice::from_ref(&issued.event),
    )
    .expect("an untouched stream");
    let codes = log.projection().clone();
    let proof = CredentialProof::from_bytes(issued.code.expose_material().to_vec());
    let present = |overrides: RedeemAuthorizationCode| overrides;
    let base = RedeemAuthorizationCode {
        code_id: issued.code_id,
        client_id: client(),
        code: CredentialProof::from_bytes(proof.expose_material().to_vec()),
        pkce_verifier: CredentialProof::from_bytes(
            b"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_vec(),
        ),
        redirect_uri: redirect(),
    };

    let refuse_at = |at: &str,
                     codes: &CodeProjection,
                     servers: &Projection,
                     clients: &RecordedClients,
                     sessions: &RecordedSessions,
                     input: &RedeemAuthorizationCode| {
        let mut secrets = CountingSecrets::new();
        let mut allocator = SequentialAllocator::new();
        redeem_authorization_code(
            input,
            &RequestContext {
                at: Timestamp::new(at),
                ..request()
            },
            codes,
            BoundReads {
                servers,
                clients,
                sessions,
            },
            RedemptionParts {
                digest: &Sha256Digest,
                secrets: &mut secrets,
                allocator: &mut allocator,
            },
        )
        .expect_err("a refusal")
    };
    let refuse = |codes: &CodeProjection,
                  servers: &Projection,
                  clients: &RecordedClients,
                  sessions: &RecordedSessions,
                  input: &RedeemAuthorizationCode| {
        let mut secrets = CountingSecrets::new();
        let mut allocator = SequentialAllocator::new();
        redeem_authorization_code(
            input,
            &request(),
            codes,
            BoundReads {
                servers,
                clients,
                sessions,
            },
            RedemptionParts {
                digest: &Sha256Digest,
                secrets: &mut secrets,
                allocator: &mut allocator,
            },
        )
        .expect_err("a refusal")
    };
    let clone = |input: &RedeemAuthorizationCode| RedeemAuthorizationCode {
        code_id: input.code_id,
        client_id: input.client_id,
        code: CredentialProof::from_bytes(input.code.expose_material().to_vec()),
        pkce_verifier: CredentialProof::from_bytes(input.pkce_verifier.expose_material().to_vec()),
        redirect_uri: input.redirect_uri.clone(),
    };

    // The consumed code, folded from the real redemption's own event.
    let consumed = {
        let mut secrets = CountingSecrets::new();
        let mut allocator = SequentialAllocator::new();
        let accepted = redeem_authorization_code(
            &clone(&base),
            &request(),
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
        )
        .expect("the first redemption");
        let mut fold = codes.clone();
        fold.apply(&accepted.event).expect("the consume");
        fold
    };
    let disabled_servers = {
        let mut fold = servers.clone();
        fold.apply(
            &mandate_sts::registry::disable_resource_server(
                &mandate_sts::registry::DisableResourceServer {
                    id: target,
                    context: context(organization(10)),
                },
                &servers,
            )
            .expect("an enabled registration"),
        )
        .expect("the disablement");
        fold
    };

    let observed: Vec<Denied> = vec![
        refuse(
            &codes,
            &servers,
            &clients,
            &sessions,
            &present(RedeemAuthorizationCode {
                code_id: mandate_types::AuthorizationCodeId::new(uuid(0xad)),
                ..clone(&base)
            }),
        ),
        refuse(
            &codes,
            &servers,
            &clients,
            &sessions,
            &present(RedeemAuthorizationCode {
                code: CredentialProof::from_bytes(b"not-the-code".to_vec()),
                ..clone(&base)
            }),
        ),
        refuse(&consumed, &servers, &clients, &sessions, &clone(&base)),
        refuse(
            &codes,
            &servers,
            &clients,
            &sessions,
            &present(RedeemAuthorizationCode {
                redirect_uri: RedirectUri::new("https://client.example/callback/"),
                ..clone(&base)
            }),
        ),
        refuse(
            &codes,
            &servers,
            &clients,
            &sessions,
            &present(RedeemAuthorizationCode {
                client_id: OAuthClientId::new(uuid(0x0d)),
                ..clone(&base)
            }),
        ),
        refuse(
            &codes,
            &servers,
            &RecordedClients::new(),
            &sessions,
            &clone(&base),
        ),
        refuse(
            &codes,
            &servers,
            &RecordedClients::new()
                .enabled(client(), organization(11))
                .redirect(client(), redirect()),
            &sessions,
            &clone(&base),
        ),
        refuse(
            &codes,
            &servers,
            &RecordedClients::new()
                .disabled(client(), organization(10))
                .redirect(client(), redirect()),
            &sessions,
            &clone(&base),
        ),
        refuse(
            &codes,
            &servers,
            &clients,
            &sessions,
            &present(RedeemAuthorizationCode {
                pkce_verifier: CredentialProof::from_bytes(b"short".to_vec()),
                ..clone(&base)
            }),
        ),
        refuse(
            &codes,
            &servers,
            &clients,
            &sessions,
            &present(RedeemAuthorizationCode {
                pkce_verifier: CredentialProof::from_bytes(
                    b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec(),
                ),
                ..clone(&base)
            }),
        ),
        refuse(
            &codes,
            &disabled_servers,
            &clients,
            &sessions,
            &clone(&base),
        ),
        refuse(
            &codes,
            &servers,
            &clients,
            &RecordedSessions::new(),
            &clone(&base),
        ),
        refuse(
            &codes,
            &servers,
            &clients,
            &RecordedSessions::new().session(session).stale(
                EpochSnapshotRef::new(uuid(0x60)),
                mandate_types::SecurityEpochTarget::Organization(organization(10)),
            ),
            &clone(&base),
        ),
        // The code's own expiry, decided at an instant past it.
        refuse_at(
            "2026-09-19T00:05:01Z",
            &codes,
            &servers,
            &clients,
            &sessions,
            &clone(&base),
        ),
        // The three conditions no command of this crate can arrange, because issuance and
        // registration refuse to write the record they need. Each is folded from a
        // *constructed* event — a record some other writer put in the log — which is the
        // only thing that reaches these branches, and the reason they are not dead code.
        refuse(
            &unregistered_target_code(&codes, &issued),
            &servers,
            &clients,
            &sessions,
            &clone(&base),
        ),
        refuse(
            &codes,
            &other_tenant_target(target),
            &clients,
            &sessions,
            &clone(&base),
        ),
        refuse(
            &codes,
            &unbounded_profile_target(target),
            &clients,
            &sessions,
            &clone(&base),
        ),
        refuse(
            &malformed_challenge_code(&issued),
            &servers,
            &clients,
            &sessions,
            &clone(&base),
        ),
    ];

    assert_clauses_match_rows("mandate.credential.RedeemAuthorizationCode", &observed);
}

/// A code record naming a target no event registered.
///
/// `issue_authorization_code` cannot write one — it refuses an unregistered target — so the
/// event is constructed. A log this deployment did not write is exactly what the redemption's
/// target re-read exists for.
fn unregistered_target_code(
    codes: &CodeProjection,
    issued: &mandate_sts::code::AuthorizationCodeIssuance,
) -> CodeProjection {
    let code = codes
        .authorization_code(&issued.code_id)
        .expect("the code record");
    CodeProjection::fold(&[
        mandate_sts::store::AuthorizationCodeEvent::AuthorizationCodeIssued {
            context: context(organization(10)),
            code_id: code.id,
            client_id: code.client_id,
            session_id: code.session_id,
            verifier: code.verifier.clone(),
            challenge: code.challenge.clone(),
            method: code.method,
            redirect_uri: code.redirect_uri.clone(),
            expires_at: code.expires_at.clone(),
            target: ResourceServerId::new(uuid(0x39)),
            scope: code.scope.clone(),
        },
    ])
    .expect("one creation")
}

/// A code record whose recorded challenge is the S256 challenge of no verifier.
///
/// Since this correction `issue_authorization_code` refuses to record one, so the event is
/// constructed. The redemption's own form check is what keeps such a record from reaching a
/// digest comparison it can never win.
fn malformed_challenge_code(
    issued: &mandate_sts::code::AuthorizationCodeIssuance,
) -> CodeProjection {
    let mandate_sts::store::AuthorizationCodeEvent::AuthorizationCodeIssued {
        client_id,
        session_id,
        verifier,
        method,
        redirect_uri,
        expires_at,
        target,
        scope,
        ..
    } = &issued.event
    else {
        panic!("an issuance emits the issued event");
    };
    CodeProjection::fold(&[
        mandate_sts::store::AuthorizationCodeEvent::AuthorizationCodeIssued {
            context: context(organization(10)),
            code_id: issued.code_id,
            client_id: *client_id,
            session_id: *session_id,
            verifier: verifier.clone(),
            challenge: PkceChallenge::new("too-short"),
            method: *method,
            redirect_uri: redirect_uri.clone(),
            expires_at: expires_at.clone(),
            target: *target,
            scope: scope.clone(),
        },
    ])
    .expect("one creation")
}

/// The same registration identity, recorded to another organization than the session's.
fn other_tenant_target(target: ResourceServerId) -> Projection {
    Projection::fold(&[CredentialEvent::ResourceServerRegistered {
        context: context(organization(11)),
        id: target,
        audience: Audience::new("api-a"),
        credential_profile: reference_profile(),
        allowed_exchange_sources: Vec::new(),
    }])
    .expect("one creation")
}

/// The same registration, published under a profile whose `max_ttl` names no span.
///
/// `register_resource_server` refuses such a profile, so the event is constructed: it is the
/// record that makes the redemption's expiry bound unreachable, and the handler fails closed
/// rather than issuing a credential it cannot date.
fn unbounded_profile_target(target: ResourceServerId) -> Projection {
    Projection::fold(&[CredentialEvent::ResourceServerRegistered {
        context: context(organization(10)),
        id: target,
        audience: Audience::new("api-a"),
        credential_profile: CredentialProfile {
            max_ttl: Duration::new("whenever"),
            ..reference_profile()
        },
        allowed_exchange_sources: Vec::new(),
    }])
    .expect("one creation")
}

/// Every clause observed has a row for this command, and the refusal's outcome agrees with
/// what that row says declares it.
fn assert_clauses_match_rows(command: &str, observed: &[Denied]) {
    let ir = system_ir();
    let declared = outcome(&ir, command, "denied")
        .and_then(|denied| denied["condition"]["cause"].as_str())
        .unwrap_or_else(|| panic!("{command} declares no `denied` cause"))
        .to_owned();

    for denied in observed {
        let row = ROWS
            .iter()
            .find(|(row_command, clause, _)| *row_command == command && *clause == denied.clause)
            .unwrap_or_else(|| {
                panic!(
                    "{command} refused with {:?}, which no row of this file phrases; the \
                     declared denial is:\n  {declared}",
                    denied.clause
                )
            });
        match row.2 {
            Source::WrongState => assert_eq!(
                denied.outcome,
                RefusedOutcome::WrongState,
                "{command} / {:?} is rowed as a wrong-state refusal",
                denied.clause
            ),
            Source::DenialPhrase(_) | Source::EntityInvariant(_, _) => assert_eq!(
                denied.outcome,
                RefusedOutcome::Denied,
                "{command} / {:?} is rowed as an external denial",
                denied.clause
            ),
        }
    }

    // And no row for this command is an ornament: every one was produced above.
    let produced: BTreeSet<String> = observed
        .iter()
        .map(|denied| format!("{:?}", denied.clause))
        .collect();
    let rowed: BTreeSet<String> = ROWS
        .iter()
        .filter(|(row_command, _, _)| *row_command == command)
        .map(|(_, clause, _)| format!("{clause:?}"))
        .collect();
    assert_eq!(
        rowed, produced,
        "{command}: every row is a refusal the handler produces, and every refusal it \
         produces has a row"
    );
}

/// The session port's own two clauses, driven through [`fresh_session`] rather than through
/// a whole redemption, so the five conditions behind them are each shown to land on a rowed
/// clause.
#[test]
fn both_session_clauses_are_rowed_and_reachable() {
    let (servers, target) = registered_target();
    let _ = servers;
    let mut secrets = CountingSecrets::new();
    let mut allocator = SequentialAllocator::new();
    let (fold, _) = registered_target();
    let issued = issuance()
        .issue(
            &code_input(target),
            &request(),
            &fold,
            &registered_client(),
            AuthorizationCodeParts {
                digest: &Sha256Digest,
                secrets: &mut secrets,
                allocator: &mut allocator,
            },
        )
        .expect("a registered enabled target and client");
    let codes = CodeProjection::fold(std::slice::from_ref(&issued.event)).expect("one creation");
    let code = codes
        .authorization_code(&issued.code_id)
        .expect("the code record");
    let live = SessionBinding {
        id: SessionId::new(uuid(0x5e)),
        subject: PrincipalId::new(uuid(0x51)),
        organization: organization(10),
        epochs: Some(EpochSnapshotRef::new(uuid(0x60))),
        expires_at: Timestamp::new("2026-09-19T12:00:00Z"),
        revoked: false,
    };

    let clauses: Vec<DenialClause> = vec![
        // No record.
        fresh_session(&code, &RecordedSessions::new(), &request()),
        // Revoked.
        fresh_session(
            &code,
            &RecordedSessions::new()
                .session(SessionBinding {
                    revoked: true,
                    ..live.clone()
                })
                .current(EpochSnapshotRef::new(uuid(0x60))),
            &request(),
        ),
        // Expired.
        fresh_session(
            &code,
            &RecordedSessions::new()
                .session(SessionBinding {
                    expires_at: Timestamp::new("2026-09-18T00:00:00Z"),
                    ..live.clone()
                })
                .current(EpochSnapshotRef::new(uuid(0x60))),
            &request(),
        ),
        // A snapshot the reader cannot resolve.
        fresh_session(
            &code,
            &RecordedSessions::new().session(live.clone()),
            &request(),
        ),
        // A generation that has moved.
        fresh_session(
            &code,
            &RecordedSessions::new().session(live).stale(
                EpochSnapshotRef::new(uuid(0x60)),
                mandate_types::SecurityEpochTarget::Principal(PrincipalId::new(uuid(0x51))),
            ),
            &request(),
        ),
    ]
    .into_iter()
    .map(|outcome| outcome.expect_err("a refusal").clause)
    .collect();

    assert_eq!(
        clauses,
        [
            DenialClause::SessionUnusable,
            DenialClause::SessionUnusable,
            DenialClause::SessionUnusable,
            DenialClause::SessionEpochStale,
            DenialClause::SessionEpochStale,
        ],
        "five conditions, the two clauses the declared denial phrases"
    );
    assert_eq!(
        ResourceServerState::Enabled,
        ResourceServerState::Enabled,
        "the registration this code was issued against is untouched"
    );
}

// --- the other nine commands, driven through their real handlers ------------------------
//
// Adversary pass 2, F1: `assert_clauses_match_rows` ran for the two authorization-code
// commands alone, so a clause a *different* handler constructed without a row was caught by
// neither direction — which is how `(IntrospectCredential, OrganizationMismatch)` sat
// unrowed. Every command this crate realizes is driven below, so the both-direction check
// covers all eleven and no command is one-direction any more.

fn descriptor(organization_id: OrganizationId, audience: &str) -> CredentialDescriptor {
    CredentialDescriptor {
        kind: CredentialKind::Reference,
        subject: PrincipalId::new(uuid(0x51)),
        actor: None,
        organization: organization_id,
        audience: Audience::new(audience),
        scope: scope(),
        delegation: None,
        execution: None,
        expires_at: Timestamp::new("2026-09-19T01:00:00Z"),
    }
}

fn self_contained_profile() -> CredentialProfile {
    CredentialProfile {
        name: "self-contained".to_owned(),
        kind: CredentialKind::SelfContained,
        revocation: RevocationGuarantee::BoundedOffline,
        max_ttl: Duration::new("PT15M"),
        positive_cache_ttl: Duration::new("PT0S"),
        requires_online_authorization: false,
    }
}

fn registration(
    id: ResourceServerId,
    organization_id: OrganizationId,
    audience: &str,
    profile: CredentialProfile,
) -> CredentialEvent {
    CredentialEvent::ResourceServerRegistered {
        context: context(organization_id),
        id,
        audience: Audience::new(audience),
        credential_profile: profile,
        allowed_exchange_sources: Vec::new(),
    }
}

fn issuance_event(
    credential_id: CredentialId,
    target: ResourceServerId,
    organization_id: OrganizationId,
    audience: &str,
    verifier: CredentialVerifier,
) -> CredentialEvent {
    CredentialEvent::CredentialReferenceIssued {
        context: context(organization_id),
        credential_id,
        reference_verifier: Some(verifier),
        epochs: None,
        issued_at: Timestamp::new("2026-09-19T00:00:00Z"),
        descriptor: descriptor(organization_id, audience),
        target,
        requested_scope: scope(),
    }
}

/// A resolution port that cannot reach the authoritative record at all.
struct Unreachable;

impl CredentialResolution for Unreachable {
    fn resolve(
        &self,
        _: &CredentialVerifier,
    ) -> Result<Option<AccessCredential>, ResolutionUnavailable> {
        Err(ResolutionUnavailable)
    }
}

/// An [`IssuanceSigner`] that refuses every credential it is handed.
struct RefusingSigner;

impl IssuanceSigner for RefusingSigner {
    fn sign_credential(
        &self,
        _: &CredentialDescriptor,
        _: &StandardClaims,
    ) -> Result<SignedCredential, SigningError> {
        Err(SigningError::Encode("this deployment refuses".to_owned()))
    }

    fn ttl_seconds(&self) -> u64 {
        900
    }
}

/// The material this deployment resolves, by reference.
struct ResolvableKeys;

impl KeyMaterialResolver for ResolvableKeys {
    fn thumbprint(&self, reference: &KeyReference) -> Option<String> {
        match reference.as_str() {
            "kms://one" => Some("thumb-one".to_owned()),
            "kms://two" => Some("thumb-two".to_owned()),
            // The same material, filed under a second reference.
            "kms://one-again" => Some("thumb-one".to_owned()),
            _ => None,
        }
    }
}

#[test]
fn every_refusal_register_resource_server_produces_has_a_row() {
    let held = Projection::fold(&[
        registration(
            ResourceServerId::new(uuid(0x40)),
            organization(10),
            "taken",
            reference_profile(),
        ),
        registration(
            ResourceServerId::new(uuid(0x41)),
            organization(11),
            "other-tenant",
            reference_profile(),
        ),
        registration(
            ResourceServerId::new(uuid(0x42)),
            organization(10),
            "to-disable",
            reference_profile(),
        ),
        CredentialEvent::ResourceServerDisabled {
            context: context(organization(10)),
            id: ResourceServerId::new(uuid(0x42)),
        },
    ])
    .expect("three registrations and a disablement");

    let refuse = |input: &RegisterResourceServer| {
        let mut allocator = SequentialAllocator::new();
        register_resource_server(input, &held, &mut allocator).expect_err("a refusal")
    };
    let free = |audience: &str, sources: Vec<ResourceServerId>| RegisterResourceServer {
        context: context(organization(10)),
        audience: Audience::new(audience),
        profile: reference_profile(),
        allowed_exchange_sources: sources,
    };

    let observed = vec![
        refuse(&free("taken", Vec::new())),
        refuse(&RegisterResourceServer {
            profile: CredentialProfile {
                max_ttl: Duration::new("whenever"),
                ..reference_profile()
            },
            ..free("free", Vec::new())
        }),
        refuse(&free("free", vec![ResourceServerId::new(uuid(0x49))])),
        refuse(&free("free", vec![ResourceServerId::new(uuid(0x41))])),
        refuse(&free("free", vec![ResourceServerId::new(uuid(0x42))])),
    ];

    assert_clauses_match_rows("mandate.credential.RegisterResourceServer", &observed);
}

#[test]
fn every_refusal_disable_resource_server_produces_has_a_row() {
    let held = Projection::fold(&[
        registration(
            ResourceServerId::new(uuid(0x40)),
            organization(10),
            "api-a",
            reference_profile(),
        ),
        registration(
            ResourceServerId::new(uuid(0x41)),
            organization(11),
            "api-b",
            reference_profile(),
        ),
        CredentialEvent::ResourceServerDisabled {
            context: context(organization(10)),
            id: ResourceServerId::new(uuid(0x40)),
        },
    ])
    .expect("two registrations and a disablement");

    let refuse = |id: ResourceServerId| {
        disable_resource_server(
            &DisableResourceServer {
                id,
                context: context(organization(10)),
            },
            &held,
        )
        .expect_err("a refusal")
    };

    let observed = vec![
        refuse(ResourceServerId::new(uuid(0x49))),
        refuse(ResourceServerId::new(uuid(0x41))),
        refuse(ResourceServerId::new(uuid(0x40))),
    ];

    assert_clauses_match_rows("mandate.credential.DisableResourceServer", &observed);
}

/// Both issuance families, which share every clause but one.
#[test]
fn every_refusal_the_two_issuance_families_produce_has_a_row() {
    let held = Projection::fold(&[
        registration(
            ResourceServerId::new(uuid(0x40)),
            organization(10),
            "api-a",
            reference_profile(),
        ),
        registration(
            ResourceServerId::new(uuid(0x41)),
            organization(10),
            "api-b",
            self_contained_profile(),
        ),
        registration(
            ResourceServerId::new(uuid(0x42)),
            organization(11),
            "api-c",
            reference_profile(),
        ),
        registration(
            ResourceServerId::new(uuid(0x43)),
            organization(10),
            "api-d",
            reference_profile(),
        ),
        CredentialEvent::ResourceServerDisabled {
            context: context(organization(10)),
            id: ResourceServerId::new(uuid(0x43)),
        },
        // A registration whose `max_ttl` names no span. `register_resource_server` refuses
        // such a profile, so the event is constructed: it is the one record that makes an
        // issuance's expiry bound unreachable.
        registration(
            ResourceServerId::new(uuid(0x44)),
            organization(10),
            "api-e",
            CredentialProfile {
                max_ttl: Duration::new("whenever"),
                ..reference_profile()
            },
        ),
        registration(
            ResourceServerId::new(uuid(0x45)),
            organization(10),
            "api-f",
            self_contained_profile(),
        ),
    ])
    .expect("the registrations");

    let reference = |target: ResourceServerId| {
        let mut secrets = CountingSecrets::new();
        let mut allocator = SequentialAllocator::new();
        issue_reference_credential(
            &IssueReferenceCredential {
                context: context(organization(10)),
                target,
                requested_scope: scope(),
            },
            &request(),
            &held,
            ReferenceParts {
                digest: &Sha256Digest,
                secrets: &mut secrets,
                allocator: &mut allocator,
            },
        )
        .expect_err("a refusal")
    };
    assert_clauses_match_rows(
        "mandate.credential.IssueReferenceCredential",
        &[
            reference(ResourceServerId::new(uuid(0x49))),
            reference(ResourceServerId::new(uuid(0x43))),
            reference(ResourceServerId::new(uuid(0x42))),
            reference(ResourceServerId::new(uuid(0x41))),
            reference(ResourceServerId::new(uuid(0x44))),
        ],
    );

    let self_contained = |target: ResourceServerId, ttl: u64| {
        let mut allocator = SequentialAllocator::new();
        let signer = StaticSigner::new("kid-one", ttl);
        issue_self_contained_credential(
            &IssueSelfContainedCredential {
                context: context(organization(10)),
                target,
                requested_scope: scope(),
            },
            &request(),
            &held,
            SelfContainedParts {
                digest: &Sha256Digest,
                allocator: &mut allocator,
                signer: &signer,
                issuer: &Issuer::new("https://sts.example"),
            },
        )
        .expect_err("a refusal")
    };
    let refused_signer = {
        let mut allocator = SequentialAllocator::new();
        issue_self_contained_credential(
            &IssueSelfContainedCredential {
                context: context(organization(10)),
                target: ResourceServerId::new(uuid(0x41)),
                requested_scope: scope(),
            },
            &request(),
            &held,
            SelfContainedParts {
                digest: &Sha256Digest,
                allocator: &mut allocator,
                signer: &RefusingSigner,
                issuer: &Issuer::new("https://sts.example"),
            },
        )
        .expect_err("the signer refused")
    };
    assert_clauses_match_rows(
        "mandate.credential.IssueSelfContainedCredential",
        &[
            self_contained(ResourceServerId::new(uuid(0x49)), 900),
            // The disabled registration is the reference family's, so the family check
            // fires first; a disabled *self-contained* registration is needed for the
            // disabled clause, and `api-f` after its disablement is it.
            self_contained(ResourceServerId::new(uuid(0x42)), 900),
            self_contained(ResourceServerId::new(uuid(0x40)), 900),
            self_contained(ResourceServerId::new(uuid(0x41)), 3_600),
            refused_signer,
            self_contained_disabled(),
        ],
    );
}

/// A disabled self-contained registration, folded on its own so the disablement reaches the
/// family the case needs.
fn self_contained_disabled() -> Denied {
    let held = Projection::fold(&[
        registration(
            ResourceServerId::new(uuid(0x45)),
            organization(10),
            "api-f",
            self_contained_profile(),
        ),
        CredentialEvent::ResourceServerDisabled {
            context: context(organization(10)),
            id: ResourceServerId::new(uuid(0x45)),
        },
    ])
    .expect("a registration and its disablement");
    let mut allocator = SequentialAllocator::new();
    let signer = StaticSigner::new("kid-one", 900);
    issue_self_contained_credential(
        &IssueSelfContainedCredential {
            context: context(organization(10)),
            target: ResourceServerId::new(uuid(0x45)),
            requested_scope: scope(),
        },
        &request(),
        &held,
        SelfContainedParts {
            digest: &Sha256Digest,
            allocator: &mut allocator,
            signer: &signer,
            issuer: &Issuer::new("https://sts.example"),
        },
    )
    .expect_err("a disabled registration")
}

/// Every clause `IntrospectCredential` refuses with, including the one adversary pass 2
/// found unrowed.
#[test]
fn every_refusal_introspect_credential_produces_has_a_row() {
    // Two registrations in one organization on one audience: the smaller identity holds the
    // key, so a credential issued under the other has a caller whose registration does not
    // hold its audience. That is the `may_introspect` refusal, on an ordinary deployment.
    let caller_verifier = verifier_for(
        &Sha256Digest,
        &CredentialProof::from_bytes(b"caller".to_vec()),
    );
    let same_audience = verifier_for(
        &Sha256Digest,
        &CredentialProof::from_bytes(b"same-audience".to_vec()),
    );
    let other_audience = verifier_for(
        &Sha256Digest,
        &CredentialProof::from_bytes(b"other-audience".to_vec()),
    );
    let other_tenant = verifier_for(
        &Sha256Digest,
        &CredentialProof::from_bytes(b"other-tenant".to_vec()),
    );

    let held = Projection::fold(&[
        // The holder of (organization 10, "api-a").
        registration(
            ResourceServerId::new(uuid(0x40)),
            organization(10),
            "api-a",
            reference_profile(),
        ),
        // The second registration on that key, which does not hold it.
        registration(
            ResourceServerId::new(uuid(0x41)),
            organization(10),
            "api-a",
            reference_profile(),
        ),
        registration(
            ResourceServerId::new(uuid(0x42)),
            organization(10),
            "api-b",
            reference_profile(),
        ),
        registration(
            ResourceServerId::new(uuid(0x43)),
            organization(11),
            "api-a",
            reference_profile(),
        ),
        // The caller speaks for the registration that lost the audience.
        issuance_event(
            CredentialId::new(uuid(0xc1)),
            ResourceServerId::new(uuid(0x41)),
            organization(10),
            "api-a",
            caller_verifier,
        ),
        // Same organization, same audience, a different registration.
        issuance_event(
            CredentialId::new(uuid(0xc2)),
            ResourceServerId::new(uuid(0x40)),
            organization(10),
            "api-a",
            same_audience,
        ),
        // Same organization, another audience.
        issuance_event(
            CredentialId::new(uuid(0xc3)),
            ResourceServerId::new(uuid(0x42)),
            organization(10),
            "api-b",
            other_audience,
        ),
        // Another organization, the same audience.
        issuance_event(
            CredentialId::new(uuid(0xc4)),
            ResourceServerId::new(uuid(0x43)),
            organization(11),
            "api-a",
            other_tenant,
        ),
    ])
    .expect("four registrations and four issuances");

    let refuse = |caller: &[u8], presented: Vec<u8>| {
        introspect_credential(
            &IntrospectCredential {
                caller_proof: CredentialProof::from_bytes(caller.to_vec()),
                credential_proof: CredentialProof::from_bytes(presented),
            },
            &request(),
            &held,
            IntrospectionParts {
                digest: &Sha256Digest,
                resolution: &held,
            },
        )
        .expect_err("a refusal")
    };
    let unreachable = introspect_credential(
        &IntrospectCredential {
            caller_proof: CredentialProof::from_bytes(b"caller".to_vec()),
            credential_proof: CredentialProof::from_bytes(b"same-audience".to_vec()),
        },
        &request(),
        &held,
        IntrospectionParts {
            digest: &Sha256Digest,
            resolution: &Unreachable,
        },
    )
    .expect_err("the authoritative record cannot be reached");

    let observed = vec![
        // A presented proof carrying nothing.
        refuse(b"caller", Vec::new()),
        // A caller proof that resolves to no record.
        refuse(b"not-a-credential", b"same-audience".to_vec()),
        // Another audience, and another organization on this one.
        refuse(b"caller", b"other-audience".to_vec()),
        refuse(b"caller", b"other-tenant".to_vec()),
        // A caller whose registration does not hold its audience, presented a credential of
        // a registration that is not its own.
        refuse(b"caller", b"same-audience".to_vec()),
        unreachable,
    ];

    assert_clauses_match_rows("mandate.credential.IntrospectCredential", &observed);
}

#[test]
fn every_refusal_revoke_access_credential_produces_has_a_row() {
    let held = Projection::fold(&[
        registration(
            ResourceServerId::new(uuid(0x40)),
            organization(10),
            "api-a",
            reference_profile(),
        ),
        registration(
            ResourceServerId::new(uuid(0x41)),
            organization(11),
            "api-b",
            reference_profile(),
        ),
        issuance_event(
            CredentialId::new(uuid(0xc1)),
            ResourceServerId::new(uuid(0x40)),
            organization(10),
            "api-a",
            CredentialVerifier::new("one"),
        ),
        issuance_event(
            CredentialId::new(uuid(0xc2)),
            ResourceServerId::new(uuid(0x41)),
            organization(11),
            "api-b",
            CredentialVerifier::new("two"),
        ),
        CredentialEvent::AccessCredentialRevoked {
            context: context(organization(10)),
            id: CredentialId::new(uuid(0xc1)),
        },
    ])
    .expect("two registrations, two issuances and a revocation");

    let refuse = |id: CredentialId| {
        revoke_access_credential(
            &RevokeAccessCredential {
                id,
                context: context(organization(10)),
            },
            &held,
        )
        .expect_err("a refusal")
    };

    let observed = vec![
        refuse(CredentialId::new(uuid(0xc9))),
        refuse(CredentialId::new(uuid(0xc2))),
        refuse(CredentialId::new(uuid(0xc1))),
    ];

    assert_clauses_match_rows("mandate.credential.RevokeAccessCredential", &observed);
}

#[test]
fn every_refusal_the_three_key_commands_produce_has_a_row() {
    let administration = SigningKeyAdministration::new(
        AllowedAlgorithms::new(&[SigningAlgorithm::new("RS256")]).expect("an allowlist"),
    );
    let recorded = |id: SigningKeyId, reference: &str, thumbprint: &str| {
        CredentialEvent::SigningKeyRegistered {
            context: context(organization(10)),
            id,
            key_reference: KeyReference::new(reference),
            thumbprint: thumbprint.to_owned(),
            algorithm: SigningAlgorithm::new("RS256"),
            not_before: Timestamp::new("2026-09-19T00:00:00Z"),
            expires_at: Timestamp::new("2026-12-31T00:00:00Z"),
        }
    };
    let held = Projection::fold(&[
        recorded(SigningKeyId::new(uuid(0x70)), "kms://one", "thumb-one"),
        recorded(SigningKeyId::new(uuid(0x71)), "kms://two", "thumb-two"),
        CredentialEvent::SigningKeyRevoked {
            context: context(organization(10)),
            id: SigningKeyId::new(uuid(0x71)),
        },
    ])
    .expect("two registrations and a revocation");

    let register = |input: &RegisterSigningKey| {
        let mut allocator = SequentialAllocator::new();
        administration
            .register(input, &held, &ResolvableKeys, &mut allocator)
            .expect_err("a refusal")
    };
    let candidate = |reference: &str, algorithm: &str| RegisterSigningKey {
        context: context(organization(10)),
        key_reference: KeyReference::new(reference),
        algorithm: SigningAlgorithm::new(algorithm),
        not_before: Timestamp::new("2026-09-19T00:00:00Z"),
        expires_at: Timestamp::new("2026-12-31T00:00:00Z"),
    };

    assert_clauses_match_rows(
        "mandate.credential.RegisterSigningKey",
        &[
            // The declared entity invariant, checked by the handler.
            register(&RegisterSigningKey {
                not_before: Timestamp::new("2026-12-31T00:00:00Z"),
                expires_at: Timestamp::new("2026-09-19T00:00:00Z"),
                ..candidate("kms://three", "RS256")
            }),
            register(&candidate("kms://three", "ES256")),
            register(&candidate("kms://unresolvable", "RS256")),
            register(&candidate("kms://one", "RS256")),
            // The same material, filed under a second reference.
            register(&candidate("kms://one-again", "RS256")),
        ],
    );

    // Retirement: an unknown key, a key with no admitted replacement, and one that is not
    // `Recorded`. The replacement here is the revoked key, which `signing_admitted` refuses.
    let retire = |id: SigningKeyId, fold: &Projection| {
        retire_signing_key(
            &RetireSigningKey {
                id,
                context: context(organization(10)),
            },
            fold,
            &request(),
        )
        .expect_err("a refusal")
    };
    let retired = Projection::fold(&[
        recorded(SigningKeyId::new(uuid(0x70)), "kms://one", "thumb-one"),
        recorded(SigningKeyId::new(uuid(0x71)), "kms://two", "thumb-two"),
        CredentialEvent::SigningKeyRetired {
            context: context(organization(10)),
            id: SigningKeyId::new(uuid(0x70)),
        },
    ])
    .expect("two registrations and a retirement");
    assert_clauses_match_rows(
        "mandate.credential.RetireSigningKey",
        &[
            retire(SigningKeyId::new(uuid(0x79)), &held),
            retire(SigningKeyId::new(uuid(0x70)), &held),
            retire(SigningKeyId::new(uuid(0x70)), &retired),
        ],
    );

    let revoke = |id: SigningKeyId| {
        revoke_signing_key(
            &RevokeSigningKey {
                id,
                context: context(organization(10)),
            },
            &held,
        )
        .expect_err("a refusal")
    };
    assert_clauses_match_rows(
        "mandate.credential.RevokeSigningKey",
        &[
            revoke(SigningKeyId::new(uuid(0x79))),
            revoke(SigningKeyId::new(uuid(0x71))),
        ],
    );
}
