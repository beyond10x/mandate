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
    AuthorityScope, CredentialKind, CredentialProof, DelegationId, DenialReason, ResourceServerId,
    Transient, VerifiedContext,
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
    let mut validated: Option<VerifiedContext> = None;
    let decided = decide(
        input,
        request,
        servers,
        parts.digest,
        parts.resolution,
        &mut validated,
    )
    .map_err(|denied| {
        Box::new(ExchangeRefused {
            denied,
            event: CredentialEvent::TokenExchangeDenied {
                context: validated.clone(),
                requested_target: input.target,
                requested_scope: input.requested_scope.clone(),
            },
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
            target: input.target,
            requested_scope: input.requested_scope.clone(),
        },
        kid: None,
    })
}

/// Every refusal, in the order a caller earns the right to learn it: possession of a usable
/// subject credential first, then everything about the target.
fn decide<D, R>(
    input: &ExchangeCredential,
    request: &RequestContext,
    servers: &impl ResourceServerReads,
    digest: &D,
    resolution: &R,
    validated: &mut Option<VerifiedContext>,
) -> Result<Decided, Denied>
where
    D: CredentialDigest,
    R: CredentialResolution,
{
    let invalid = || {
        Denied::new(
            DenialReason::InvalidCredential,
            DenialClause::CallerProofInvalid,
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
    let subject = resolved.ok_or_else(invalid)?;
    let live = subject.state == AccessCredentialState::Active
        && instant::seconds_of(&subject.descriptor.expires_at).is_some_and(|expiry| now < expiry)
        && servers.is_enabled(&subject.target) == Some(true);
    if !live {
        return Err(invalid());
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
    *validated = Some(context.clone());

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

    // The target: registered, enabled, the subject's own organization's, issuing the family
    // this deployment mints without a signer.
    let server = admitted_target(&context, &input.target, servers, CredentialKind::Reference)?;
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
