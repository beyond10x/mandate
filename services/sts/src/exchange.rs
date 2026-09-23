//! `ExchangeCredential`, subject-only: RFC 8693 token exchange of a Mandate access
//! credential for one resource server into a credential for another.
//!
//! # What the source of an exchange is
//!
//! The credential the subject presents, and the registration it was issued for.
//! `allowed_exchange_sources` is a list of `ResourceServerId` that registration admits only
//! as enabled registrations of the same organization (`crate::registry`), and
//! `docs/architecture/combined.md:53` says it in as many words: "Existing source credentials
//! must be eligible for the registered exchange target; an empty source list grants none."
//! So the subject proof is resolved to its `mandate.credential.AccessCredential` record, and
//! that record's own [`mandate_token::projection::AccessCredential::target`] is the source the
//! target's registration must list. Audience text is compared nowhere (`credential.yaml`'s
//! header: "audience text equality cannot admit a source").
//!
//! # What the issued credential carries
//!
//! The subject credential's subject and organization, the target registration's audience —
//! read off the registration, never from the caller — the requested scope when it is inside
//! the subject's own, and an expiry no later than the subject credential's: "the output
//! expiry is at most the earliest applicable subject/actor credential" (`combined.md:53`).
//! Its family is the reference family, the one this deployment mints without a signer; a
//! target whose profile issues self-contained credentials is refused as
//! `ProfileUnadmitted`, exactly as [`crate::issue::issue_reference_credential`] refuses it.
//!
//! # Subject-only
//!
//! `ExchangeCredential` declares an optional `actor_proof` and an optional `delegation_id`.
//! This story realizes neither — the actor and delegation exchange is
//! `story:constrained-exchange`'s — and a request that presents one is refused
//! ([`DenialClause::ExchangeNotSubjectOnly`]) rather than served as though it had not. A
//! subject credential that itself names an actor or a delegation is refused the same way:
//! exchanging it subject-only would drop the actor, and "no ... actor removal is allowed"
//! (`combined.md:53`).
//!
//! # A refusal draws nothing, and is recorded
//!
//! Every refusal is decided before the secret source or the allocator is touched
//! (`story:sts-refusal-draws-nothing`). What a refusal returns beside the declared
//! [`Denied`] is the `mandate.credential.TokenExchangeDenied` record of it, carrying the
//! context the subject credential validated to when it resolved to one and none otherwise:
//! a context is never invented for a proof that named nothing. That record folds into
//! nothing ([`mandate_token::projection::Projection::apply`]); where it is delivered is the
//! adapter's, and durable delivery is `decision-blocker:audit-routing`'s.
//!
//! # What is decided elsewhere
//!
//! The epoch the subject's session was opened under is not re-read here: no crate in this
//! crate's ceiling folds a generation, and `mandate.credential.AccessCredential` carries an
//! `EpochSnapshotRef` handle and never a generation. Authority beyond the subject
//! credential's own scope is an authorization decision, which the adapter takes before it
//! dispatches. Both are named here as residue.

use mandate_token::projection::{AccessCredential, AccessCredentialState, CredentialEvent};
use mandate_token::projection::{DenialClause, Denied};
use mandate_token::verifier::{CredentialDigest, CredentialDomain, verifier_in};
use mandate_types::{
    Audience, AuthorityScope, CredentialKind, CredentialProof, DelegationId, DenialReason,
    ResourceServerId, Transient, Uuid, VerifiedContext,
};
use serde::Serialize;

use crate::issue::{CredentialIssued, admitted_target, bounded_expiry, descriptor_for};
use crate::registry::ResourceServerReads;
use crate::resolve::CredentialResolution;
use crate::{IdentityAllocator, RequestContext, SecretSource, instant};

/// `mandate.credential.ExchangeCredential`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExchangeCredential {
    /// The declared `subject_proof`: the access credential the subject presents.
    pub subject_proof: CredentialProof,
    /// The declared `actor_proof`. Refused when present; see the module documentation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_proof: Option<CredentialProof>,
    /// The declared `target`: the registration the issued credential is for.
    pub target: ResourceServerId,
    /// The declared `requested_scope`.
    pub requested_scope: AuthorityScope,
    /// The declared `delegation_id`. Refused when present; see the module documentation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_id: Option<DelegationId>,
}

/// How a request names the registration the issued credential is for.
///
/// RFC 8693 section 2.1 lets `audience` be "the logical name of the target service", and a
/// client of a downstream platform knows the platform by the audience it registered under,
/// not by a registration identity it was never shown. So the name is admitted beside the
/// identity (correction round 1, F4) — and only ever resolved **within the subject
/// credential's own organization**, after the subject has validated, so a name selects among
/// that organization's registrations and cannot select an organization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExchangeTarget {
    /// The registration identity: the declared `target` input, as it is.
    Registration(ResourceServerId),
    /// The audience a registration of the subject's organization holds.
    Audience(Audience),
}

/// An exchange as the adapter presents it: [`ExchangeCredential`], with the target named
/// either way [`ExchangeTarget`] admits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeRequest {
    /// The declared `subject_proof`.
    pub subject_proof: CredentialProof,
    /// The declared `actor_proof`. Refused when present.
    pub actor_proof: Option<CredentialProof>,
    /// The target, by identity or by audience.
    pub target: ExchangeTarget,
    /// The declared `requested_scope`.
    pub requested_scope: AuthorityScope,
    /// The declared `delegation_id`. Refused when present.
    pub delegation_id: Option<DelegationId>,
}

impl From<&ExchangeCredential> for ExchangeRequest {
    fn from(input: &ExchangeCredential) -> Self {
        Self {
            subject_proof: input.subject_proof.clone(),
            actor_proof: input.actor_proof.clone(),
            target: ExchangeTarget::Registration(input.target),
            requested_scope: input.requested_scope.clone(),
            delegation_id: input.delegation_id,
        }
    }
}

/// The `requested_target` a `TokenExchangeDenied` records, in the ordinary case, for a target
/// named by an audience that resolved to no single registration: the nil identity.
///
/// The event declares `requested_target` a required `ResourceServerId`, and a name no
/// registration answers — or one the refusal was decided before it could be resolved, because
/// the subject that scopes it did not validate — has no identity to record. The requested
/// name is not recorded: it is caller text, and the record's fields are the contract's. Named
/// here as residue — a `requested_audience` field is a contract change.
///
/// **What is recorded is the least identity no registration holds, starting here**
/// ([`unresolved_target`]), not this constant unconditionally. The host allocator never mints
/// the nil identity, but an operator's seeding document may *state* any identity, the nil one
/// included (final correction, F4), and a denial recorded against a registration that exists
/// would name a target the request never reached.
pub const UNRESOLVED_TARGET: ResourceServerId = ResourceServerId::new(Uuid::from_bytes([0; 16]));

/// The least identity, counting up from [`UNRESOLVED_TARGET`], that no registration this
/// read model holds, whatever its state.
///
/// A registration read model holds finitely many identities, so the count ends; in every
/// deployment that states no small identity it ends at the first step.
fn unresolved_target(servers: &impl ResourceServerReads) -> ResourceServerId {
    let mut candidate: u128 = 0;
    loop {
        let id = ResourceServerId::new(Uuid::from_bytes(candidate.to_be_bytes()));
        if servers.resource_server(&id).is_none() {
            return id;
        }
        candidate += 1;
    }
}

/// Which of the four causes made a subject token unusable.
///
/// For the operator's line alone (final correction, F7). The refusal a caller is answered
/// with is one — `SubjectTokenInvalid`, 400 `invalid_grant` — because a caller holding a
/// well-formed token is owed only that it is unusable; the operator is owed the reason, so a
/// replayed revoked credential and garbage are different lines on its stream. Each cause is a
/// fixed word ([`SubjectTokenCause::as_str`]) and carries nothing the caller sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SubjectTokenCause {
    /// The token resolves to no credential this deployment holds.
    Unknown,
    /// The credential it resolves to is revoked.
    Revoked,
    /// The credential it resolves to has expired.
    Expired,
    /// The registration the credential was issued for is disabled.
    SourceDisabled,
}

impl SubjectTokenCause {
    /// The fixed word the operator's line carries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::SourceDisabled => "source-disabled",
        }
    }
}

/// The deployment's ports for an exchange.
pub struct ExchangeParts<'a, D, R, X, A>
where
    D: CredentialDigest,
    R: CredentialResolution,
    X: SecretSource,
    A: IdentityAllocator,
{
    /// The digest a presented proof is resolved through, and the issued verifier derived by.
    pub digest: &'a D,
    /// The authoritative resolution the subject proof is resolved against.
    pub resolution: &'a R,
    /// The source the returned secret is minted from.
    pub secrets: &'a mut X,
    /// The allocator the response identity is minted from.
    pub allocator: &'a mut A,
}

/// A refused exchange: the declared refusal, and the record of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeRefused {
    /// The declared `mandate.credential.Denied`.
    pub denied: Denied,
    /// `mandate.credential.TokenExchangeDenied`, for the adapter to record.
    pub event: CredentialEvent,
    /// Why the subject token was unusable, when that is what refused: for the operator's
    /// line, never the wire.
    pub cause: Option<SubjectTokenCause>,
}

/// What an admitted exchange has decided, before anything is drawn.
struct Decided {
    context: VerifiedContext,
    subject: AccessCredential,
    server: mandate_token::projection::ResourceServer,
    expires_at: mandate_types::Timestamp,
}

/// Realize `mandate.credential.ExchangeCredential`, subject-only.
///
/// # Errors
///
/// Returns [`ExchangeRefused`], boxed because the record it carries is a whole event — the
/// declared `denied` outcome and the
/// `TokenExchangeDenied` record of it — when the subject proof is malformed, resolves to no
/// credential, or resolves to one that is revoked, expired or whose issuing registration is
/// disabled; when an actor or a delegation is presented or carried; when the target is
/// unregistered, disabled, outside the subject's organization or issues another family; when
/// the target does not list the subject credential's registration among its
/// `allowed_exchange_sources`; when the requested scope is not inside the subject's; when
/// the expiry cannot be bounded; and when the authoritative resolution cannot be reached. A
/// refusal mints no secret and hands out no identity.
pub fn exchange_credential<D, R, X, A>(
    input: &ExchangeCredential,
    request: &RequestContext,
    servers: &impl ResourceServerReads,
    parts: ExchangeParts<'_, D, R, X, A>,
) -> Result<CredentialIssued, Box<ExchangeRefused>>
where
    D: CredentialDigest,
    R: CredentialResolution,
    X: SecretSource,
    A: IdentityAllocator,
{
    exchange_request(&ExchangeRequest::from(input), request, servers, parts)
}

/// [`exchange_credential`], for a request naming its target either way [`ExchangeTarget`]
/// admits.
///
/// # Errors
///
/// Every refusal [`exchange_credential`] returns, and one more: a target named by an audience
/// that no enabled registration of the subject's organization holds, or that more than one
/// holds, is refused as `TargetUnregistered` — not resolved to either of two, because whichever
/// one a rule picked, the caller may have meant the other. Its record names
/// [`UNRESOLVED_TARGET`].
pub fn exchange_request<D, R, X, A>(
    input: &ExchangeRequest,
    request: &RequestContext,
    servers: &impl ResourceServerReads,
    parts: ExchangeParts<'_, D, R, X, A>,
) -> Result<CredentialIssued, Box<ExchangeRefused>>
where
    D: CredentialDigest,
    R: CredentialResolution,
    X: SecretSource,
    A: IdentityAllocator,
{
    let mut validated: Option<VerifiedContext> = None;
    let mut resolved_target = match &input.target {
        ExchangeTarget::Registration(id) => Some(*id),
        ExchangeTarget::Audience(_) => None,
    };
    let mut cause = None;
    let decided = decide(
        input,
        request,
        servers,
        parts.digest,
        parts.resolution,
        &mut Findings {
            validated: &mut validated,
            resolved_target: &mut resolved_target,
            cause: &mut cause,
        },
    )
    .map_err(|denied| {
        Box::new(ExchangeRefused {
            denied,
            event: CredentialEvent::TokenExchangeDenied {
                context: validated.clone(),
                requested_target: resolved_target.unwrap_or_else(|| unresolved_target(servers)),
                requested_scope: input.requested_scope.clone(),
            },
            cause,
        })
    })?;

    // Nothing above this line draws anything: every refusal leaves the secret source and
    // the allocator exactly as they were.
    let Decided {
        context,
        subject,
        server,
        expires_at,
    } = decided;
    let descriptor = descriptor_for(&context, &server, &input.requested_scope, expires_at);
    let credential = parts.secrets.next_secret();
    let reference_verifier =
        verifier_in(parts.digest, CredentialDomain::ReferenceSecret, &credential);
    let credential_id = parts.allocator.next_credential_id();
    Ok(CredentialIssued {
        credential,
        credential_id,
        epochs: subject.epochs,
        descriptor: descriptor.clone(),
        event: CredentialEvent::TokenExchangeAllowed {
            context,
            credential_id,
            reference_verifier: Some(reference_verifier),
            epochs: subject.epochs,
            issued_at: request.at.clone(),
            descriptor,
            target: server.id,
            requested_scope: input.requested_scope.clone(),
        },
        kid: None,
    })
}

/// What [`decide`] learned on the way to a refusal, for the record of it.
struct Findings<'a> {
    /// The context the subject token validated to, once it has.
    validated: &'a mut Option<VerifiedContext>,
    /// The registration the target resolved to, once it has.
    resolved_target: &'a mut Option<ResourceServerId>,
    /// Why the subject token was unusable, when it was.
    cause: &'a mut Option<SubjectTokenCause>,
}

/// Every refusal, in the order a caller earns the right to learn it: possession of a usable
/// subject credential first, then everything about the target.
fn decide<D, R>(
    input: &ExchangeRequest,
    request: &RequestContext,
    servers: &impl ResourceServerReads,
    digest: &D,
    resolution: &R,
    found: &mut Findings<'_>,
) -> Result<Decided, Denied>
where
    D: CredentialDigest,
    R: CredentialResolution,
{
    let invalid = || {
        Denied::new(
            DenialReason::InvalidCredential,
            DenialClause::SubjectTokenInvalid,
        )
    };
    let unbounded = || Denied::new(DenialReason::Denied, DenialClause::ExpiryUnbounded);
    let now = instant::seconds_of(&request.at).ok_or_else(unbounded)?;

    if input.subject_proof.expose_material().is_empty() {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::ProofMalformed,
        ));
    }
    // Authoritatively, in both families' digest domains: a proof does not say which family
    // it is, and an exchange is not a read a cached answer may stand in for.
    let mut resolved = None;
    for domain in [
        CredentialDomain::ReferenceSecret,
        CredentialDomain::SelfContainedToken,
    ] {
        resolved = resolution
            .resolve(&verifier_in(digest, domain, &input.subject_proof))
            .map_err(|_| {
                Denied::new(
                    DenialReason::Unavailable,
                    DenialClause::ResolutionUnavailable,
                )
            })?;
        if resolved.is_some() {
            break;
        }
    }
    // Unknown, revoked, expired, or issued by a registration that no longer admits anything:
    // one refusal, so a caller holding a well-formed proof learns only that it is unusable.
    let unusable = |cause: SubjectTokenCause, found: &mut Findings<'_>| {
        *found.cause = Some(cause);
        invalid()
    };
    let Some(subject) = resolved else {
        return Err(unusable(SubjectTokenCause::Unknown, found));
    };
    if subject.state != AccessCredentialState::Active {
        return Err(unusable(SubjectTokenCause::Revoked, found));
    }
    if !instant::seconds_of(&subject.descriptor.expires_at).is_some_and(|expiry| now < expiry) {
        return Err(unusable(SubjectTokenCause::Expired, found));
    }
    if servers.is_enabled(&subject.target) != Some(true) {
        return Err(unusable(SubjectTokenCause::SourceDisabled, found));
    }
    let context = VerifiedContext {
        subject: subject.descriptor.subject,
        actor: subject.descriptor.actor,
        organization: subject.descriptor.organization,
        audience: subject.descriptor.audience.clone(),
        credential: subject.id,
        delegation: subject.descriptor.delegation,
        execution: subject.descriptor.execution,
        correlation: request.correlation.clone(),
    };
    *found.validated = Some(context.clone());

    if input.actor_proof.is_some()
        || input.delegation_id.is_some()
        || context.actor.is_some()
        || context.delegation.is_some()
    {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::ExchangeNotSubjectOnly,
        ));
    }

    // The target, by identity or by a name resolved among the subject's organization's
    // enabled registrations: exactly one, or none at all.
    let target = match &input.target {
        ExchangeTarget::Registration(id) => *id,
        // An audience whose text is the identity of a registration names that registration;
        // any other text is a name (final correction, F3). A registration of another
        // organization found this way is refused by `admitted_target` below exactly as one
        // named by `urn:uuid:` is, and with the same code as a name that resolves to nothing.
        ExchangeTarget::Audience(audience) => {
            let registered = ResourceServerId::parse(audience.as_str())
                .ok()
                .filter(|id| servers.resource_server(id).is_some());
            match registered {
                Some(id) => id,
                None => {
                    let holders = servers.registrations_holding(&context.organization, audience);
                    let [holder] = holders.as_slice() else {
                        return Err(Denied::new(
                            DenialReason::Denied,
                            DenialClause::TargetUnregistered,
                        ));
                    };
                    holder.id
                }
            }
        }
    };
    *found.resolved_target = Some(target);
    // Registered, enabled, the subject's own organization's, issuing the family this
    // deployment mints without a signer.
    let server = admitted_target(&context, &target, servers, CredentialKind::Reference)?;
    // The source: listed by the target's registration, by identity.
    if !server.allowed_exchange_sources.contains(&subject.target) {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::SourceUnadmitted,
        ));
    }
    if !narrows(&input.requested_scope, &subject.descriptor.scope) {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::ScopeNotNarrowed,
        ));
    }

    // At most the target's own bound, and never past the subject credential's expiry.
    let profile_bound =
        instant::span_of(&server.credential_profile.max_ttl).ok_or_else(unbounded)?;
    let subject_left = instant::seconds_of(&subject.descriptor.expires_at)
        .and_then(|expiry| expiry.checked_sub(now))
        .ok_or_else(unbounded)?;
    let expires_at = bounded_expiry(
        request,
        &server.credential_profile,
        profile_bound.min(subject_left),
    )?;
    Ok(Decided {
        context,
        subject,
        server,
        expires_at,
    })
}

/// Whether a requested scope is inside the subject's own.
///
/// Every requested action and resource is one the subject holds, and the space is the
/// subject's. An absent space is not read as narrower than a present one, nor a present one
/// as narrower than an absent one: the two are refused unless they are the same, because
/// nothing here decides what an unscoped authority covers.
fn narrows(requested: &AuthorityScope, held: &AuthorityScope) -> bool {
    requested
        .actions
        .iter()
        .all(|action| held.actions.contains(action))
        && requested
            .resources
            .iter()
            .all(|resource| held.resources.contains(resource))
        && requested.space == held.space
}

/// The whole seconds from one declared instant to another, or `None` when either names no
/// instant.
///
/// RFC 8693 section 2.2.1's `expires_in` is this, from the instant the request was served at
/// to the issued descriptor's `expires_at`. It is here rather than in the adapter so the
/// adapter does not hold a fifth copy of the `date-time` reading (`crate::instant`).
#[must_use]
pub fn seconds_between(
    from: &mandate_types::Timestamp,
    to: &mandate_types::Timestamp,
) -> Option<i64> {
    instant::seconds_of(to)?.checked_sub(instant::seconds_of(from)?)
}
