//! `mandate.credential.RedeemAuthorizationCode`: the one-winner transaction.
//!
//! # Two functions, and the difference matters
//!
//! [`redeem_authorization_code`] is the **decide** half this crate's other handlers are:
//! it reads, writes nothing, and returns either the event the accepted outcome emits or the
//! declared [`Denied`]. [`redeem_and_consume`] is the **command path** — the first in this
//! crate — which reads the code stream's version, decides against the projection at that
//! version, and appends the decision's event as one group with a compare-and-set on that
//! version.
//!
//! The second is what the acceptance's third clause needs. "STS atomically consumes the code
//! and persists the narrowed credential and audit outbox ... a failed or replayed
//! transaction produces no credential" (`credential.yaml`), and
//! `docs/adr/0009-event-sourced-persistence.md` says how: the aggregate append is a
//! compare-and-set on the expected stream version, one append group per boundary, with
//! projections committing inside the group or rolling back with it. Two redemptions that
//! each read a fresh code therefore each decide `accepted`, and exactly one append lands;
//! the other presents a version the stream has left and writes nothing. No lock is taken and
//! no second mechanism is introduced.
//!
//! # What this crate's log carries, and what it does not
//!
//! One event, on the code's own stream: the consume. The credential the outcome issues is
//! declared by the same payload — `credential.yaml`'s header: the event "also seeds a
//! `mandate.credential.AccessCredential`" and "carries the whole AccessCredential record" —
//! and the fold that materializes it is `mandate_token::projection`'s. The composition
//! routes [`crate::store::AuthorizationCodeEvent::credential_event`] to the credential log;
//! nothing in this crate holds that log, so nothing in this crate can append to it.
//!
//! The **audit outbox** the same sentence names is not here either: `mandate-audit` is
//! outside this crate's dependency ceiling (`dependency-boundaries.json`) and
//! `decision-blocker:audit-routing` holds the vocabulary. `decision-blocker:epoch-atomicity`
//! is advanced by the race case here and is **not** cleared: it also wants each boundary's
//! isolation level named and a case showing a rolled-back transaction leaves no partially
//! written audit record, and neither is decidable in this crate.
//!
//! # The order the decision is taken in
//!
//! **Possession first, and possession is both halves.** The code resolves, the presented
//! proof is the one the record's verifier was derived from, and the presented PKCE verifier
//! redeems the recorded challenge. Only then the record's own lifecycle and expiry, the
//! redirect, the session and its epochs, the client, and the tenant.
//!
//! `crates/mandate-federation/src/authorize.rs` checks PKCE last, and this command does not,
//! because the two are not in the same position: that validation is non-consuming and
//! already holds an authenticated session, while this one is reached by whoever presents a
//! code. Every refusal after possession reports a fact about this deployment — whether a
//! session is live, whether a client is registered and enabled, whether a target is inside a
//! tenant — and `mandate.credential.Denied` carries `DenialReason` on the wire, so those
//! refusals are answers. A caller holding a stolen code and no verifier is not the client
//! the code was issued to and is told one thing: the verifier does not redeem the challenge.
//!
//! # Reading "remains bound to the code target, scope, session and expiry"
//!
//! The target and the scope are the code record's, and the session is where the subject, the
//! organization and the epochs come from. The **expiry** is the earlier of the two bounds
//! that exist: the registration's profile `max_ttl` from the request instant — the bound
//! every other issuance in this crate keeps ([`crate::issue`]) — and the code's own
//! `expires_at`, which that sentence names. Taking the minimum is what makes both readings
//! true at once, and it is the safer of the two in the one direction that matters: a shorter
//! credential never grants more than a longer one would. The sentence admits a reading under
//! which only the profile bounds it; that reading is not taken here, and the choice is
//! recorded rather than left to be inferred from the behaviour.

use core::fmt;

use mandate_token::CredentialDescriptor;
use mandate_token::projection::{DenialClause, Denied};
use mandate_token::verifier::{
    CredentialDigest, CredentialDomain, constant_time_eq, presents_in, verifier_in,
};
use mandate_types::{
    AuthorizationCodeId, CredentialId, CredentialProof, CredentialSecret, DenialReason,
    EpochSnapshotRef, OAuthClientId, RedirectUri, ResourceServerId, VerifiedContext,
};
use serde::Serialize;

use crate::binding::{
    SessionReads, authorized_redirect, bound_client, fresh_session, target_in_tenant,
};
use crate::code::{
    OAuthClientReads, challenge_is_well_formed, s256_challenge, verifier_is_well_formed,
};
use crate::registry::ResourceServerReads;
use crate::store::{
    AppendRefused, AuthorizationCodeEvent, AuthorizationCodeLog, AuthorizationCodeReads,
    AuthorizationCodeState,
};
use crate::{IdentityAllocator, RequestContext, SecretSource, instant};

/// `mandate.credential.RedeemAuthorizationCode`.
///
/// No `context` input and no caller-supplied selector: "`RedeemAuthorizationCode.code_id` is
/// resolved by the trusted adapter from proof; it is not a public OAuth parameter or
/// authority selector" (`credential.yaml`'s header), and the context the emitted event
/// carries is generated from the code record and the session it names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RedeemAuthorizationCode {
    /// The declared `code_id`.
    pub code_id: AuthorizationCodeId,
    /// The declared `client_id`.
    pub client_id: OAuthClientId,
    /// The declared `code`: the proof of holding the code that was returned once.
    pub code: CredentialProof,
    /// The declared `pkce_verifier`.
    pub pkce_verifier: CredentialProof,
    /// The declared `redirect_uri`.
    pub redirect_uri: RedirectUri,
}

/// The accepted outcome of [`RedeemAuthorizationCode`].
///
/// The five declared response fields and the event the outcome emits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCodeRedemption {
    /// The declared `credential` response: the material, returned once.
    pub credential: CredentialSecret,
    /// The declared `credential_id` response.
    pub credential_id: CredentialId,
    /// The declared `epochs` response: the session's own snapshot, when it names one.
    pub epochs: Option<EpochSnapshotRef>,
    /// The declared `target` response: the registration the code was issued for.
    pub target: ResourceServerId,
    /// The declared `descriptor` response.
    pub descriptor: CredentialDescriptor,
    /// The event the accepted outcome emits.
    pub event: AuthorizationCodeEvent,
}

/// The read models a redemption re-reads, beside the code store.
///
/// Bundled because they always travel together and because a signature that spelled them out
/// would be three more arguments on both functions here.
pub struct BoundReads<'a, R: ResourceServerReads, O: OAuthClientReads, S: SessionReads> {
    /// The `mandate.credential.ResourceServer` fold.
    pub servers: &'a R,
    /// The `mandate.federation.OAuthClient` read model, behind its port.
    pub clients: &'a O,
    /// The session and epoch read model, behind its port.
    pub sessions: &'a S,
}

/// The deployment's ports for a redemption.
pub struct RedemptionParts<'a, D: CredentialDigest, S: SecretSource, A: IdentityAllocator> {
    /// The digest the verifiers are derived through.
    pub digest: &'a D,
    /// The source the returned credential is minted from.
    pub secrets: &'a mut S,
    /// The allocator the response identity is minted from.
    pub allocator: &'a mut A,
}

/// Why a redemption did not produce a credential.
///
/// Two facts, and a caller needs to tell them apart: a decision the contract declares a
/// refusal for, and an append that lost its compare-and-set. The second is not a declared
/// outcome of this command at all — it is the transaction failing, which
/// `credential.yaml` covers with "a failed or replayed transaction produces no credential" —
/// and a deployment answers it by retrying against the state that moved it, which will then
/// return the declared `wrong-state`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RedemptionRefused {
    /// The decision refused, through the outcome [`Denied::outcome`] names.
    Denied(Denied),
    /// The append did not commit.
    Append(AppendRefused),
}

impl fmt::Display for RedemptionRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied(denied) => write!(formatter, "{denied}"),
            Self::Append(refused) => write!(formatter, "{refused}"),
        }
    }
}

impl std::error::Error for RedemptionRefused {}

impl From<Denied> for RedemptionRefused {
    fn from(denied: Denied) -> Self {
        Self::Denied(denied)
    }
}

impl From<AppendRefused> for RedemptionRefused {
    fn from(refused: AppendRefused) -> Self {
        Self::Append(refused)
    }
}

/// Whether a presented code verifier redeems a recorded challenge.
///
/// `BASE64URL-ENCODE(SHA256(ASCII(verifier)))` compared against the recorded challenge in a
/// time that does not depend on how much of it is right
/// ([`mandate_token::verifier::constant_time_eq`]). The form is decided before the digest:
/// a value outside RFC 7636 section 4.1's is not a code verifier, and a short one that
/// happened to collide would otherwise be admitted.
///
/// The recorded challenge's own form is checked too. `crate::code` refuses to record one
/// that is the S256 challenge of no verifier, so a record carrying one came from somewhere
/// else, and admitting it here would carry it into a digest comparison it can never win.
///
/// # Errors
///
/// Returns [`Denied`] when the recorded challenge is not in the declared S256 form, when the
/// presented verifier is not in the declared form, and when its digest is not the recorded
/// challenge.
fn redeems_the_challenge(
    code: &crate::store::AuthorizationCode,
    presented: &CredentialProof,
) -> Result<(), Denied> {
    match code.method {
        // Exhaustive and without a wildcard: `mandate.core.PkceMethod` declares exactly one
        // variant, so RFC 7636's `plain` has no Rust value and a second declared method
        // would fail to compile rather than fall through to the S256 branch. That is what
        // makes `pkce-plain` unrepresentable at the STS rather than refused by a check.
        mandate_types::PkceMethod::S256 => {}
    }
    if !challenge_is_well_formed(&code.challenge) {
        return Err(Denied::new(
            DenialReason::InvalidCredential,
            DenialClause::ChallengeMalformed,
        ));
    }
    if !verifier_is_well_formed(presented) {
        return Err(Denied::new(
            DenialReason::InvalidCredential,
            DenialClause::VerifierMalformed,
        ));
    }
    if !constant_time_eq(
        s256_challenge(presented).as_str().as_bytes(),
        code.challenge.as_str().as_bytes(),
    ) {
        return Err(Denied::new(
            DenialReason::InvalidCredential,
            DenialClause::VerifierMismatch,
        ));
    }
    Ok(())
}

/// Realize `mandate.credential.RedeemAuthorizationCode`: the deciding half.
///
/// Reads and returns; it consumes nothing and appends nothing. [`redeem_and_consume`] is the
/// command path that commits what this decides.
///
/// # Errors
///
/// Returns [`Denied`] through the declared `wrong-state` outcome when the code is already in
/// the terminal `Consumed` state, and through the declared `denied` outcome when the code
/// resolves to no record, the presented proof is not the one the record's verifier was
/// derived from, the code has expired, the redirect is not the one the code authorized, the
/// session is unknown, revoked, stale or expired, the presented client is not the code's or
/// that client is unregistered, out of tenant or disabled, the registered target is
/// unregistered, out of tenant or disabled, the presented PKCE verifier does not redeem the
/// recorded challenge, or the credential's expiry cannot be bounded. A refusal mints no
/// credential and no identity.
pub fn redeem_authorization_code<C, R, O, S, D, X, A>(
    input: &RedeemAuthorizationCode,
    request: &RequestContext,
    codes: &C,
    bound: BoundReads<'_, R, O, S>,
    parts: RedemptionParts<'_, D, X, A>,
) -> Result<AuthorizationCodeRedemption, Denied>
where
    C: AuthorizationCodeReads + ?Sized,
    R: ResourceServerReads,
    O: OAuthClientReads,
    S: SessionReads,
    D: CredentialDigest,
    X: SecretSource,
    A: IdentityAllocator,
{
    // A `code_id` that resolves to nothing refuses exactly as a proof that does not match
    // one does, reason and all: the contract's error carries `DenialReason` and nothing
    // else, and a caller that could tell the two apart would hold an oracle over which code
    // identifiers exist.
    let code = codes
        .authorization_code(&input.code_id)
        .ok_or_else(|| Denied::new(DenialReason::InvalidCredential, DenialClause::CodeUnknown))?;
    // **Possession first, both halves of it.** "STS resolves the proof to `code_id`
    // internally and verifies it against that record" (`docs/architecture/ownership.md`);
    // the record keeps the non-reversible verifier and the proof is resolved in the
    // authorization code's own digest domain, so a credential proof presented here resolves
    // to nothing.
    //
    // The PKCE verifier is checked here too, before anything is read about the session, the
    // client or the tenant. A caller that holds the code but not the verifier is not the
    // client the code was issued to, and every later refusal reports a fact about this
    // deployment's state: whether a session is live, whether a client is registered and
    // enabled, whether a target is inside a tenant. `DenialReason` is on the wire, so those
    // are answers, and answering them for a caller who has not shown possession is the
    // difference between a refusal and a read. Both comparisons are constant-time
    // ([`mandate_token::verifier::presents_in`], [`redeems_the_challenge`]).
    if !presents_in(
        parts.digest,
        CredentialDomain::AuthorizationCodeVerifier,
        &code.verifier,
        &input.code,
    ) {
        return Err(Denied::new(
            DenialReason::InvalidCredential,
            DenialClause::CodeProofMismatch,
        ));
    }
    redeems_the_challenge(&code, &input.pkce_verifier)?;
    match code.state {
        AuthorizationCodeState::Issued => {}
        // `consume` starts from `Issued` alone, so a code already in the terminal state is
        // the declared `wrong-state` outcome and not the external denial — a 409 rather than
        // a 502 in the OpenAPI projection
        // (`docs/architecture/command-obligations.md`). This is `pkce-reuse`'s sequential
        // half; its concurrent half is the compare-and-set in [`redeem_and_consume`].
        AuthorizationCodeState::Consumed => {
            return Err(Denied::wrong_state(
                DenialReason::Denied,
                DenialClause::CodeConsumed,
            ));
        }
    }
    // Redeemable strictly before the instant it expires at, and a code whose expiry names no
    // instant is not one this handler can date.
    if instant::is_before(&request.at, &code.expires_at) != Some(true) {
        return Err(Denied::new(
            DenialReason::InvalidCredential,
            DenialClause::CodeExpired,
        ));
    }
    authorized_redirect(&code, &input.redirect_uri)?;
    let session = fresh_session(&code, bound.sessions, request)?;
    bound_client(
        &code,
        &input.client_id,
        &session.organization,
        bound.clients,
    )?;
    let server = target_in_tenant(&code, bound.servers, &session.organization)?;

    let unbounded = || Denied::new(DenialReason::Denied, DenialClause::ExpiryUnbounded);
    let issued_at = instant::seconds_of(&request.at).ok_or_else(unbounded)?;
    let profile_bound = instant::span_of(&server.credential_profile.max_ttl)
        .filter(|span| *span > 0)
        .and_then(|span| issued_at.checked_add(span))
        .ok_or_else(unbounded)?;
    let code_bound = instant::seconds_of(&code.expires_at).ok_or_else(unbounded)?;
    let expires_at = instant::at(profile_bound.min(code_bound));

    // Nothing above this line mints anything: a refusal leaves the deployment exactly as it
    // was.
    let credential = parts.secrets.next_secret();
    let reference_verifier =
        verifier_in(parts.digest, CredentialDomain::ReferenceSecret, &credential);
    let credential_id = parts.allocator.next_credential_id();
    let descriptor = CredentialDescriptor {
        kind: server.credential_profile.kind,
        subject: session.subject,
        // "its actor, delegation and execution as absent unless the code record names them"
        // — the declared record names none of the three.
        actor: None,
        organization: session.organization,
        // "The audience is the one published by the registration the code record's target
        // names", and never a caller-supplied selector (`AGENTS.md`).
        audience: server.audience.clone(),
        // The code's own narrowed scope, which the issuance recorded.
        scope: code.scope.clone(),
        delegation: None,
        execution: None,
        expires_at,
    };
    Ok(AuthorizationCodeRedemption {
        credential,
        credential_id,
        epochs: session.epochs,
        target: code.target,
        descriptor: descriptor.clone(),
        event: AuthorizationCodeEvent::AuthorizationCodeRedeemed {
            context: VerifiedContext {
                subject: session.subject,
                actor: None,
                organization: session.organization,
                audience: server.audience.clone(),
                // "its credential as the credential_id this outcome issues".
                credential: credential_id,
                delegation: None,
                execution: None,
                // "its correlation as the one the outcome mints for this request", which the
                // adapter carries on the request ([`crate::RequestContext`]).
                correlation: request.correlation.clone(),
            },
            code_id: code.id,
            credential_id,
            reference_verifier: Some(reference_verifier),
            epochs: session.epochs,
            issued_at: request.at.clone(),
            descriptor,
            target: code.target,
        },
    })
}

/// The command path: decide against the code stream as it stands, and commit the decision as
/// one append group with a compare-and-set on the version it was read at.
///
/// The one function in this crate that writes. It appends the code's consume and nothing
/// else in this crate's log; the credential the same event seeds is the credential log's,
/// through [`crate::store::AuthorizationCodeEvent::credential_event`].
///
/// # Errors
///
/// Returns [`RedemptionRefused::Denied`] with whatever [`redeem_authorization_code`]
/// refused, and [`RedemptionRefused::Append`] when the append did not commit — a stream
/// another writer moved first, which is the losing half of two concurrent redemptions and
/// writes nothing.
pub fn redeem_and_consume<L, R, O, S, D, X, A>(
    input: &RedeemAuthorizationCode,
    request: &RequestContext,
    log: &mut L,
    bound: BoundReads<'_, R, O, S>,
    parts: RedemptionParts<'_, D, X, A>,
) -> Result<AuthorizationCodeRedemption, RedemptionRefused>
where
    L: AuthorizationCodeLog + ?Sized,
    R: ResourceServerReads,
    O: OAuthClientReads,
    S: SessionReads,
    D: CredentialDigest,
    X: SecretSource,
    A: IdentityAllocator,
{
    // Read the version first, then decide against the projection at that version: a decision
    // read from a state that has since moved must fail the append rather than overwrite it.
    let expected = log.version(&input.code_id);
    let outcome = redeem_authorization_code(input, request, log.projection(), bound, parts)?;
    log.append(
        &input.code_id,
        expected,
        std::slice::from_ref(&outcome.event),
    )?;
    Ok(outcome)
}
