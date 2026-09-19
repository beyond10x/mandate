//! The `mandate.credential.AuthorizationCode` record, its fold, and the append that closes
//! the window between a decision and the event it decided.
//!
//! Two things are decided here and nowhere else in this crate:
//!
//! - **The fold.** A creation is insert-if-absent and a `consume` starts from the declared
//!   `from:` set alone, so a redelivered or late event under the kit's at-least-once
//!   delivery writes nothing rather than returning a record to a state the contract does
//!   not admit it moving back to. An event naming a code no event created is a log the fold
//!   cannot read.
//! - **The append.** `docs/adr/0009-event-sourced-persistence.md`: the aggregate append is a
//!   compare-and-set on the expected stream version, and the projection commits inside the
//!   group or rolls back with it. The fake here is a test double with that shape and not a
//!   second durable mechanism (`story:oauth-transaction`, wave C ruling 6).

use mandate_contract::entities;
use mandate_sts::store::{
    AppendRefused, AuthorizationCode, AuthorizationCodeEvent, AuthorizationCodeReads,
    AuthorizationCodeState, CodeFoldError, CodeProjection, InMemoryCodeLog, StreamVersion,
};
use mandate_token::CredentialDescriptor;
use mandate_types::{
    Audience, AuthorityScope, AuthorizationCodeId, CorrelationId, CredentialId, CredentialKind,
    CredentialVerifier, EpochSnapshotRef, OAuthClientId, OrganizationId, PkceChallenge, PkceMethod,
    PrincipalId, RedirectUri, ResourceServerId, SessionId, Timestamp, Uuid, VerifiedContext,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn code_id() -> AuthorizationCodeId {
    AuthorizationCodeId::new(uuid(0xac))
}

fn context() -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::new(uuid(0x51)),
        actor: None,
        organization: OrganizationId::new(uuid(10)),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("store"),
    }
}

fn scope() -> AuthorityScope {
    AuthorityScope {
        actions: Vec::new(),
        resources: Vec::new(),
        space: None,
    }
}

fn challenge() -> PkceChallenge {
    PkceChallenge::new("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
}

fn issued() -> AuthorizationCodeEvent {
    AuthorizationCodeEvent::AuthorizationCodeIssued {
        context: context(),
        code_id: code_id(),
        client_id: OAuthClientId::new(uuid(0x0c)),
        session_id: SessionId::new(uuid(0x5e)),
        verifier: CredentialVerifier::new("recorded-verifier"),
        challenge: challenge(),
        method: PkceMethod::S256,
        redirect_uri: RedirectUri::new("https://client.example/callback"),
        expires_at: Timestamp::new("2026-09-19T00:05:00Z"),
        target: ResourceServerId::new(uuid(0x30)),
        scope: scope(),
    }
}

fn descriptor() -> CredentialDescriptor {
    CredentialDescriptor {
        kind: CredentialKind::Reference,
        subject: PrincipalId::new(uuid(0x51)),
        actor: None,
        organization: OrganizationId::new(uuid(10)),
        audience: Audience::new("api-a"),
        scope: scope(),
        delegation: None,
        execution: None,
        expires_at: Timestamp::new("2026-09-19T01:00:00Z"),
    }
}

fn redeemed_for(code_id: AuthorizationCodeId) -> AuthorizationCodeEvent {
    AuthorizationCodeEvent::AuthorizationCodeRedeemed {
        context: context(),
        code_id,
        credential_id: CredentialId::new(uuid(0xce)),
        reference_verifier: Some(CredentialVerifier::new("credential-verifier")),
        epochs: Some(EpochSnapshotRef::new(uuid(0x60))),
        issued_at: Timestamp::new("2026-09-19T00:00:00Z"),
        descriptor: descriptor(),
        target: ResourceServerId::new(uuid(0x30)),
    }
}

fn redeemed() -> AuthorizationCodeEvent {
    redeemed_for(code_id())
}

fn recorded() -> AuthorizationCode {
    AuthorizationCode {
        id: code_id(),
        client_id: OAuthClientId::new(uuid(0x0c)),
        session_id: SessionId::new(uuid(0x5e)),
        verifier: CredentialVerifier::new("recorded-verifier"),
        challenge: challenge(),
        method: PkceMethod::S256,
        redirect_uri: RedirectUri::new("https://client.example/callback"),
        expires_at: Timestamp::new("2026-09-19T00:05:00Z"),
        target: ResourceServerId::new(uuid(0x30)),
        scope: scope(),
        state: AuthorizationCodeState::Issued,
    }
}

/// One round trip: the domain value's own JSON, read as the generated shape it names and
/// written back.
fn agrees<D, C>(domain: &D, element: &str) -> Value
where
    D: Serialize,
    C: Serialize + DeserializeOwned,
{
    let encoded = serde_json::to_value(domain).expect("a domain value encodes as JSON");
    let shape: C = serde_json::from_value(encoded.clone())
        .unwrap_or_else(|error| panic!("{element}: the generated shape refuses it: {error}"));
    let round_tripped = serde_json::to_value(&shape).expect("a generated shape encodes as JSON");
    assert_eq!(
        round_tripped, encoded,
        "{element}: the round trip through the generated shape is not the identity"
    );
    encoded
}

#[test]
fn an_issuance_creates_the_declared_record() {
    let folded = CodeProjection::fold(&[issued()]).expect("one creation");

    assert_eq!(folded.authorization_code(&code_id()), Some(recorded()));
    assert_eq!(folded.authorization_codes().len(), 1);
}

#[test]
fn the_record_agrees_with_the_generated_entity_shape() {
    agrees::<_, entities::MandateCredentialAuthorizationCode>(
        &recorded(),
        "mandate.credential.AuthorizationCode",
    );
    agrees::<_, entities::MandateCredentialAuthorizationCodeState>(
        &AuthorizationCodeState::Consumed,
        "mandate.credential.AuthorizationCode.State",
    );
}

#[test]
fn each_event_names_the_declared_element_it_is() {
    assert_eq!(
        issued().ess_name(),
        "mandate.credential.AuthorizationCodeIssued"
    );
    assert_eq!(
        redeemed().ess_name(),
        "mandate.credential.AuthorizationCodeRedeemed"
    );
    agrees::<_, mandate_contract::events::MandateCredentialAuthorizationCodeIssued>(
        &issued(),
        "mandate.credential.AuthorizationCodeIssued",
    );
    agrees::<_, mandate_contract::events::MandateCredentialAuthorizationCodeRedeemed>(
        &redeemed(),
        "mandate.credential.AuthorizationCodeRedeemed",
    );
}

/// The redeemed payload is one declaration read by two folds: this crate consumes the code
/// with it and `mandate-token` materializes the credential it seeds
/// (`credential.yaml` header). Two payload structs that drifted apart would be two events.
#[test]
fn the_redeemed_payload_is_the_one_the_credential_fold_reads() {
    let event = redeemed();
    let credential = event
        .credential_event()
        .expect("the redemption seeds a credential record");

    assert_eq!(
        serde_json::to_value(&event).expect("the code payload encodes"),
        serde_json::to_value(&credential).expect("the credential payload encodes"),
        "one declared payload, read by two folds"
    );
    assert_eq!(credential.ess_name(), event.ess_name());
    assert!(
        issued().credential_event().is_none(),
        "an issuance seeds no credential"
    );
}

#[test]
fn a_redelivered_issuance_writes_nothing() {
    let once = CodeProjection::fold(&[issued()]).expect("one creation");
    let twice = CodeProjection::fold(&[issued(), issued()]).expect("a redelivered creation");

    assert_eq!(once, twice);
}

#[test]
fn a_redemption_consumes_the_code() {
    let folded = CodeProjection::fold(&[issued(), redeemed()]).expect("a creation and its move");

    assert_eq!(
        folded.authorization_code(&code_id()).map(|code| code.state),
        Some(AuthorizationCodeState::Consumed)
    );
    assert_eq!(
        folded.authorization_code(&code_id()),
        Some(AuthorizationCode {
            state: AuthorizationCodeState::Consumed,
            ..recorded()
        }),
        "`consume` moves the state and rewrites no other declared field"
    );
}

/// `consume` declares `from: [Issued]` and nothing else, and `Consumed` is terminal: a
/// redelivery after the terminal state writes nothing rather than refusing the log.
#[test]
fn a_redemption_after_the_terminal_state_writes_nothing() {
    let once = CodeProjection::fold(&[issued(), redeemed()]).expect("a creation and its move");
    let twice = CodeProjection::fold(&[issued(), redeemed(), redeemed()])
        .expect("a redelivered move is a readable log");

    assert_eq!(once, twice);
}

#[test]
fn a_move_naming_a_code_no_event_created_is_a_log_the_fold_cannot_read() {
    let refused = CodeProjection::fold(&[redeemed()]).expect_err("no event created the code");

    assert_eq!(
        refused,
        CodeFoldError::UnknownAuthorizationCode { id: code_id() }
    );
}

#[test]
fn an_empty_log_rebuilds_to_an_empty_projection() {
    let rebuilt = CodeProjection::fold(&[]).expect("an empty log");

    assert_eq!(rebuilt, CodeProjection::default());
    assert!(rebuilt.authorization_codes().is_empty());
    assert_eq!(rebuilt.authorization_code(&code_id()), None);
}

#[test]
fn an_append_is_a_compare_and_set_on_the_expected_stream_version() {
    let mut log = InMemoryCodeLog::new();

    assert_eq!(log.version(&code_id()), StreamVersion::INITIAL);
    let after = log
        .append(&code_id(), StreamVersion::INITIAL, &[issued()])
        .expect("an untouched stream is at its initial version");
    assert_eq!(after, StreamVersion::INITIAL.advance());
    assert_eq!(log.version(&code_id()), after);
    assert_eq!(
        log.projection().authorization_code(&code_id()),
        Some(recorded()),
        "the projection commits inside the group"
    );

    let refused = log
        .append(&code_id(), StreamVersion::INITIAL, &[redeemed()])
        .expect_err("the stream moved since that version was read");
    assert_eq!(
        refused,
        AppendRefused::Conflict {
            expected: StreamVersion::INITIAL,
            actual: after,
        }
    );
}

#[test]
fn a_refused_append_leaves_the_stream_and_the_projection_where_they_were() {
    let mut log = InMemoryCodeLog::new();
    log.append(&code_id(), StreamVersion::INITIAL, &[issued()])
        .expect("the creation");
    let before = log.projection().clone();
    let version = log.version(&code_id());

    log.append(&code_id(), StreamVersion::INITIAL, &[redeemed()])
        .expect_err("a stale expected version");

    assert_eq!(log.version(&code_id()), version);
    assert_eq!(log.projection(), &before);
    assert_eq!(log.events(&code_id()), vec![issued()]);
}

/// The double can be made to lose a compare-and-set it would otherwise win, which is how a
/// case shows what a losing writer does without having to run two threads.
#[test]
fn the_double_can_be_made_to_lose_a_compare_and_set() {
    let mut log = InMemoryCodeLog::new();
    log.append(&code_id(), StreamVersion::INITIAL, &[issued()])
        .expect("the creation");
    let version = log.version(&code_id());
    log.lose_the_next_append();

    let refused = log
        .append(&code_id(), version, &[redeemed()])
        .expect_err("the injected conflict");

    assert!(matches!(refused, AppendRefused::Conflict { .. }));
    assert_eq!(log.events(&code_id()), vec![issued()]);
    assert_eq!(
        log.projection()
            .authorization_code(&code_id())
            .map(|code| code.state),
        Some(AuthorizationCodeState::Issued),
        "the injected conflict writes nothing"
    );

    log.append(&code_id(), version, &[redeemed()])
        .expect("the injection is spent");
}

/// One append group per boundary: a group whose second event the fold cannot read rolls the
/// first back with it, so the boundary is all of it or none of it.
#[test]
fn a_group_the_fold_cannot_read_rolls_back_whole() {
    let mut log = InMemoryCodeLog::new();
    let other = AuthorizationCodeId::new(uuid(0xad));

    let refused = log
        .append(
            &code_id(),
            StreamVersion::INITIAL,
            &[issued(), redeemed_for(other)],
        )
        .expect_err("the second event names a code no event created");

    assert_eq!(
        refused,
        AppendRefused::Unreadable(CodeFoldError::UnknownAuthorizationCode { id: other })
    );
    assert_eq!(log.version(&code_id()), StreamVersion::INITIAL);
    assert_eq!(log.projection(), &CodeProjection::default());
    assert!(log.events(&code_id()).is_empty());
}

/// The read the deciding handlers are given, answered by the fold.
#[test]
fn the_fold_answers_the_read_port() {
    let folded = CodeProjection::fold(&[issued()]).expect("one creation");

    assert_eq!(
        AuthorizationCodeReads::authorization_code(&folded, &code_id()),
        Some(recorded())
    );
    assert_eq!(
        AuthorizationCodeReads::authorization_code(&folded, &AuthorizationCodeId::new(uuid(0xad))),
        None
    );
}
