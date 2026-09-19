//! Introspection and revocation: `IntrospectCredential` and `RevokeAccessCredential`.
//!
//! # One answer, not three
//!
//! `credential.yaml`'s own summary of the accepted outcome: "An active answer carries the
//! descriptor and the credential_id of the record this log holds. An inactive answer carries
//! neither — that is the answer for a credential this deployment revoked, one whose expiry
//! has passed, and a well-formed proof that resolves to no record at all, which are one
//! answer here and not three. The three are distinguished by nothing this event carries,
//! deliberately, because a caller holding a well-formed proof learns only whether it is
//! usable."
//!
//! So an unusable credential is **accepted**, not denied. What is denied is a caller whose
//! own proof is not usable, a caller with no registered server to speak for, a presented
//! proof that is malformed, an audience that is not the caller's, and an authoritative
//! resolution that cannot be reached.
//!
//! # Whose guarantee decides a cached resolution
//!
//! `mandate.core.RevocationGuarantee::ImmediateOnline` is a promise to the holder of the
//! *resource*: a revocation takes effect at the next resolution. A cached positive answer is
//! exactly a resolution that did not happen.
//!
//! **A credential's guarantee is the one its issuing registration published, and an audience
//! that changes hands does not change it.** `DisableResourceServer` releases an audience and
//! the deployment may register it again under any profile
//! (`crate::registry::disable_resource_server`), so the registration holding an audience
//! today is not necessarily the one a presented credential was issued under. The record
//! carries its own ([`mandate_token::projection::AccessCredential::issuing_profile`]) and
//! that is what admits or refuses a cached answer about it.
//!
//! Two gates, because neither can do the other's work ([`resolved`]):
//!
//! - the registration the **caller** speaks for decides whether the cache is *asked* at all.
//!   It has to: what a cached answer would be about is not known until something answers.
//!   Under `ImmediateOnline`, under `requires_online_authorization`, or with a
//!   `positive_cache_ttl` of no span ([`admits_a_cache`]), the cache is not consulted — not
//!   consulted and then overridden, but not called, which is what
//!   `services/sts/tests/resolve.rs` and `tests/adversary_profiles_1.rs` assert by counting.
//! - the **credential's own** issuing profile decides whether the answer the cache gave may
//!   stand, by the same two questions. A credential issued under `ImmediateOnline` is
//!   resolved authoritatively however the audience is registered now.
//!
//! The bound is an age, so it is a bound on nothing unless the cache says when it took the
//! answer: [`CredentialResolution::cached_at`] is that, and its default is a refusal.
//!
//! # What is decided elsewhere
//!
//! "Principal/connection/epoch validation fails" is `mandate.identity`'s, and no crate in
//! this crate's dependency ceiling folds a session or a generation: an adapter composes that
//! check over this one. Introspection *authority* is the adapter's decision for the same
//! reason every other authority clause is.

use mandate_token::projection::{
    AccessCredential, AccessCredentialState, CredentialEvent, DenialClause, Denied, Projection,
};
use mandate_token::verifier::{CredentialDigest, CredentialDomain, matches, verifier_in};
use mandate_token::{CredentialDescriptor, CredentialProfile};
use mandate_types::{
    CredentialId, CredentialKind, CredentialProof, CredentialVerifier, DenialReason,
    RevocationGuarantee, Timestamp, Transient, VerifiedContext,
};
use serde::Serialize;

use crate::registry::ResourceServerReads;
use crate::{RequestContext, instant};

/// The authoritative resolution could not be reached.
///
/// Not a decision that the credential is unknown: "authoritative online resolution is
/// unavailable" is its own declared denial, and answering `active: false` for it would tell
/// a caller that a credential is unusable when nothing established that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolutionUnavailable;

/// Resolving a presented proof to the credential it names, behind a port.
///
/// The fold is one implementation ([`Projection`]) and the deployment's store is another;
/// what a deployment adds is the cache, which is why the two questions are separate methods
/// rather than one answer with a flag. An implementation must never answer [`Self::cached`]
/// from the authoritative record — that would make a cache indistinguishable from a
/// resolution, and the distinction is the whole of `reference-revoked`.
pub trait CredentialResolution {
    /// The record a verifier resolves to, authoritatively.
    ///
    /// # Errors
    ///
    /// Returns [`ResolutionUnavailable`] when the authoritative record cannot be reached at
    /// all, which is not the same as resolving to nothing.
    fn resolve(
        &self,
        verifier: &CredentialVerifier,
    ) -> Result<Option<AccessCredential>, ResolutionUnavailable>;

    /// A positive resolution this deployment cached earlier, if it holds one.
    ///
    /// Defaulted to `None`: a store with no cache has nothing to answer, and the fold is
    /// such a store.
    fn cached(&self, verifier: &CredentialVerifier) -> Option<AccessCredential> {
        let _ = verifier;
        None
    }

    /// When the cached positive answer for this verifier was taken.
    ///
    /// **Defaulted to `None`, which is a refusal and not an absence of opinion.** A profile
    /// publishes `positive_cache_ttl` to the holder of the resource, and a bound on the age
    /// of a cached answer is a bound on nothing unless the age is known: a cache that
    /// cannot say when it took an answer cannot be shown to be inside the bound, so its
    /// answer is not used. A deployment whose cache records the instant overrides this; the
    /// fold, which caches nothing, does not.
    ///
    /// This is the only reason it is a second method rather than a field on the answer:
    /// [`Self::cached`]'s shape is fixed by the cases already written against it.
    fn cached_at(&self, verifier: &CredentialVerifier) -> Option<Timestamp> {
        let _ = verifier;
        None
    }
}

impl CredentialResolution for Projection {
    /// The fold is the authoritative record (`docs/adr/0009-event-sourced-persistence.md`)
    /// and cannot be unreachable: a rebuild either happened or this code is not running.
    ///
    /// The comparison is [`mandate_token::verifier::matches`], so a scan over the records
    /// takes a time that depends on how many there are and not on how much of a presented
    /// verifier is correct.
    fn resolve(
        &self,
        verifier: &CredentialVerifier,
    ) -> Result<Option<AccessCredential>, ResolutionUnavailable> {
        Ok(self
            .credentials()
            .iter()
            .find(|credential| {
                credential
                    .reference_verifier
                    .as_ref()
                    .is_some_and(|recorded| matches(recorded, verifier))
            })
            .cloned())
    }
}

/// The `mandate.credential.AccessCredential` read model, keyed by the record's own identity.
///
/// Separate from [`CredentialResolution`] because the questions are different: a lifecycle
/// command names a record, a proof-driven command presents material. An implementation of
/// one is not an implementation of the other.
pub trait CredentialReads {
    /// The credential with this identity, whatever its lifecycle state.
    fn access_credential(&self, id: &CredentialId) -> Option<AccessCredential>;
}

impl CredentialReads for Projection {
    fn access_credential(&self, id: &CredentialId) -> Option<AccessCredential> {
        Self::access_credential(self, id)
    }
}

/// `mandate.credential.IntrospectCredential`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IntrospectCredential {
    /// The declared `caller_proof`.
    pub caller_proof: CredentialProof,
    /// The declared `credential_proof`.
    pub credential_proof: CredentialProof,
}

/// `mandate.credential.RevokeAccessCredential`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RevokeAccessCredential {
    /// The declared `id`.
    pub id: CredentialId,
    /// The declared `context`.
    pub context: VerifiedContext,
}

/// The deployment's ports for an introspection.
pub struct IntrospectionParts<'a, D: CredentialDigest, R: CredentialResolution> {
    /// The digest a presented proof is resolved through.
    pub digest: &'a D,
    /// The resolution the deployment answers from.
    pub resolution: &'a R,
}

/// The accepted outcome of [`IntrospectCredential`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialIntrospection {
    /// The declared `active` response.
    pub active: bool,
    /// The declared `descriptor` response, carried by an active answer alone.
    pub descriptor: Option<CredentialDescriptor>,
    /// The declared `credential_id` response, carried by an active answer alone.
    pub credential_id: Option<CredentialId>,
    /// The event the accepted outcome emits.
    pub event: CredentialEvent,
}

/// Whether a presented proof carries material at all.
///
/// The one reading of "malformed" this handler can make: it does not know which family a
/// proof belongs to before it resolves it, and a proof that carries nothing is not a proof
/// of anything under either. The wave B contract adversaries settled the clause at
/// "malformed" alone — a proof that is well formed and resolves to nothing is the accepted
/// inactive answer, not a refusal.
fn malformed(proof: &CredentialProof) -> bool {
    proof.expose_material().is_empty()
}

/// Whether a credential is live: `Active` in the fold and not yet expired.
///
/// A record whose `expires_at` names no instant is not live, because nothing can show it has
/// not expired. Live strictly before the instant it expires at.
fn live(record: &AccessCredential, now: i64) -> bool {
    record.state == AccessCredentialState::Active
        && instant::seconds_of(&record.descriptor.expires_at).is_some_and(|expiry| now < expiry)
}

/// Whether a credential is usable at an instant: live, and its registration still enabled.
///
/// One thing beyond [`live`], read off [`AccessCredential::target`] — the registration the
/// credential was issued under, not whichever registration holds that audience now: a
/// disabled registration issues nothing further and admits nothing further, and the
/// credentials it issued are not revoked (no declared move does that) and are not usable
/// either.
///
/// # Why it is not also "and still holds its audience"
///
/// It was, after correction 1, and `services/sts/tests/adversary_profiles_2.rs` shows what
/// that costs. Two writers that each read a free `(organization_id, audience)` both register
/// — the race `mandate_token::projection` documents as ordinary, where "the log is the
/// record of both registrations" — and the one that loses the key stays `Enabled`,
/// `audience_conflicts` reports it, and `crate::issue::admitted_target` issues against it. A
/// holder test here would then answer `active: false` for a credential this deployment
/// minted a moment earlier, with nothing revoked and nothing expired.
///
/// The invariant that matters is that **issuance and introspection ask the same question at
/// the same instant**, and they do: both ask whether the registration is enabled, and
/// neither asks which registration holds the audience. Resolving the race is the operator's
/// — `audience_conflicts` is the read that reports it, and `DisableResourceServer` is the
/// command that acts on it, at which point the enabled test refuses the loser's credentials
/// on both sides at once.
///
/// **The caller's own proof gets this same test**, not [`live`] alone: a credential this
/// handler answers `active: false` for is not a valid caller proof by any reading of
/// `IntrospectCredential`'s clause "or is itself invalid, revoked or expired".
fn usable(record: &AccessCredential, now: i64, servers: &impl ResourceServerReads) -> bool {
    live(record, now) && servers.is_enabled(&record.target) == Some(true)
}

/// Whether a caller may introspect a credential at all.
///
/// A caller speaks for the registration its own credential was issued under — read off
/// [`AccessCredential::target`], which is the registration that issued it whatever has
/// happened to the audience since. Its authority is over:
///
/// - **its own registration's credentials.** A resource server the operator disabled still
///   needs to reason about the credentials presented to it before the handover, and they are
///   its own. `services/sts/tests/adversary_profiles_1.rs` pins this: a caller and a
///   credential of one registration that was then disabled, answered `active: false` and not
///   refused.
/// - **every credential for the audience it holds**, when it is the registration holding
///   that audience now. That is what makes it *the* resource server that audience names, and
///   it is what lets the successor of a handover introspect the credentials its predecessor
///   issued for the same audience.
///
/// What is refused is the other direction, which is the one that leaks: the holder of a
/// registration the operator shut down asking about the credentials of the registration that
/// took its audience over. `services/sts/tests/adversary_profiles_2.rs` states what that
/// buys the refused caller — the successor's full descriptors and the `credential_id` it
/// would need to name one in `RevokeAccessCredential`.
///
/// A proof that resolves to no record reaches none of this: there is no registration to
/// compare, the answer is the inactive one, and a caller learns only that the proof is not
/// usable.
fn may_introspect(
    caller: &AccessCredential,
    presented: &AccessCredential,
    holds_the_audience: bool,
) -> bool {
    holds_the_audience || presented.target == caller.target
}

/// The domains a presented proof is resolved in, the registered family first.
///
/// A proof does not say which family it belongs to, and the two families digest into
/// disjoint spaces ([`CredentialDomain`]), so resolution tries each. The registration's own
/// `kind` is the family its holders were issued, so it is tried first and answers on the
/// first attempt in every ordinary case; the other covers a credential issued before the
/// audience was registered under this family.
const fn domains(kind: CredentialKind) -> [CredentialDomain; 2] {
    match kind {
        CredentialKind::Reference => [
            CredentialDomain::ReferenceSecret,
            CredentialDomain::SelfContainedToken,
        ],
        CredentialKind::SelfContained => [
            CredentialDomain::SelfContainedToken,
            CredentialDomain::ReferenceSecret,
        ],
    }
}

/// Whether a profile admits a cached positive answer at all.
///
/// Three fields say no, and each is the profile's own statement to the holder of the
/// resource:
///
/// - `revocation: ImmediateOnline` — a revocation takes effect at the next resolution, and a
///   cached answer is a resolution that did not happen;
/// - `requires_online_authorization: true` — "whether authorization must be resolved online"
///   (`mandate_token::CredentialProfile`). A profile that requires it and then answered from
///   a cache would be publishing one rule and keeping another; the two fields are separate
///   because a profile may require online authorization without promising immediate
///   revocation, and that profile still may not answer from a cache.
/// - a `positive_cache_ttl` that names no span, or no time at all. A window of nothing
///   admits nothing, which falls out of [`inside_cache_bound`] too and is stated here so the
///   cache is not even asked.
fn admits_a_cache(profile: &CredentialProfile) -> bool {
    profile.revocation != RevocationGuarantee::ImmediateOnline
        && !profile.requires_online_authorization
        && instant::span_of(&profile.positive_cache_ttl).is_some_and(|bound| bound > 0)
}

/// Whether a cached positive answer taken at some instant is inside a profile's bound.
///
/// Three ways it is not, and each is a refusal rather than a shrug: the profile's
/// `positive_cache_ttl` names no span, the cache does not say when it took the answer, or
/// the answer is older than the span. `PT0S` is the case that matters most — a profile that
/// publishes no positive-cache window at all — and it falls out of the same comparison
/// rather than needing a rule of its own.
fn inside_cache_bound(profile: &CredentialProfile, taken: Option<&Timestamp>, now: i64) -> bool {
    let Some(bound) = instant::span_of(&profile.positive_cache_ttl) else {
        return false;
    };
    if bound <= 0 {
        return false;
    }
    let Some(taken) = taken.and_then(instant::seconds_of) else {
        return false;
    };
    // A cached answer from the future is not an answer whose age is known.
    now >= taken && now - taken <= bound
}

/// Resolve the presented proof the way the guarantees admit.
///
/// **Two gates, and the narrower wins.** The first is the registration the caller speaks
/// for: it publishes what this deployment may answer for that audience *without asking*, so
/// its guarantee and its `positive_cache_ttl` decide whether the cache is consulted at all.
/// The second is the credential's own: the cached record names the registration it was
/// issued under ([`AccessCredential::issuing_profile`]), and an answer that registration's
/// guarantee does not admit is discarded even though the cache held it — an audience that
/// changed hands does not relax the guarantee the credential was issued under.
///
/// Both gates are needed, and neither replaces the other. Only the first can keep the cache
/// from being *asked*, which is what an `ImmediateOnline` registration promises. Only the
/// second can refuse an answer whose credential was issued under a stricter registration
/// than the one holding that audience today.
fn resolved(
    verifier: &CredentialVerifier,
    caller_profile: &CredentialProfile,
    now: i64,
    resolution: &impl CredentialResolution,
) -> Result<Option<AccessCredential>, Denied> {
    let unavailable = || {
        Denied::new(
            DenialReason::Unavailable,
            DenialClause::ResolutionUnavailable,
        )
    };
    if admits_a_cache(caller_profile)
        && let Some(cached) = resolution.cached(verifier)
        && admits_a_cache(&cached.issuing_profile)
        && inside_cache_bound(
            &cached.issuing_profile,
            resolution.cached_at(verifier).as_ref(),
            now,
        )
        && inside_cache_bound(caller_profile, resolution.cached_at(verifier).as_ref(), now)
    {
        return Ok(Some(cached));
    }
    resolution.resolve(verifier).map_err(|_| unavailable())
}

/// Realize `mandate.credential.IntrospectCredential`.
///
/// The `context` the emitted event declares `generated: true` is built here, from the
/// credential the caller's own proof resolved to and the correlation the request carries:
/// every selector on it comes from credential validation and none from a caller-supplied
/// value (`AGENTS.md`).
///
/// # Errors
///
/// Returns [`Denied`] through the declared `denied` outcome when the caller's own proof is
/// malformed, resolves to nothing, is revoked or has expired; when the caller's context
/// resolves to no enabled registration; when the presented proof is malformed; when the
/// presented credential names another audience or another organization; and when the
/// authoritative resolution cannot be reached.
pub fn introspect_credential<D, R>(
    input: &IntrospectCredential,
    request: &RequestContext,
    servers: &impl ResourceServerReads,
    parts: IntrospectionParts<'_, D, R>,
) -> Result<CredentialIntrospection, Denied>
where
    D: CredentialDigest,
    R: CredentialResolution,
{
    let unavailable = || {
        Denied::new(
            DenialReason::Unavailable,
            DenialClause::ResolutionUnavailable,
        )
    };
    let invalid_caller = || {
        Denied::new(
            DenialReason::InvalidCredential,
            DenialClause::CallerProofInvalid,
        )
    };
    // A reader that cannot be dated cannot decide an expiry, which is not a decision that
    // anything has expired.
    let now = instant::seconds_of(&request.at).ok_or_else(unavailable)?;

    // "Caller proof ... is itself invalid, revoked or expired."
    if malformed(&input.caller_proof) {
        return Err(invalid_caller());
    }
    // The caller's own proof is resolved authoritatively and never from a cache: what a
    // cached answer may say is decided by the registration the caller speaks for, and that
    // registration is not known until this resolves. Both families are tried, because
    // nothing here yet says which one the caller holds.
    let mut resolved_caller = None;
    for domain in [
        CredentialDomain::ReferenceSecret,
        CredentialDomain::SelfContainedToken,
    ] {
        resolved_caller = parts
            .resolution
            .resolve(&verifier_in(parts.digest, domain, &input.caller_proof))
            .map_err(|_| unavailable())?;
        if resolved_caller.is_some() {
            break;
        }
    }
    let caller = resolved_caller.ok_or_else(invalid_caller)?;
    if !live(&caller, now) {
        return Err(invalid_caller());
    }

    // The registered server the caller speaks for: the registration its own credential was
    // issued under, read off the record rather than off whichever registration holds that
    // audience now. A disabled registration is still the one that issued it.
    let server = servers
        .resource_server(&caller.target)
        .ok_or_else(|| Denied::new(DenialReason::Denied, DenialClause::IntrospectionAuthority))?;
    // Whether that registration is also the one holding the audience today, which is what
    // widens the caller's authority beyond its own registration; see [`may_introspect`].
    let holds_the_audience = servers
        .registered(&caller.descriptor.organization, &caller.descriptor.audience)
        .is_some_and(|holder| holder.id == caller.target);

    // "The presented credential proof is malformed."
    if malformed(&input.credential_proof) {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::ProofMalformed,
        ));
    }
    let mut presented = None;
    for domain in domains(server.credential_profile.kind) {
        presented = resolved(
            &verifier_in(parts.digest, domain, &input.credential_proof),
            &server.credential_profile,
            now,
            parts.resolution,
        )?;
        if presented.is_some() {
            break;
        }
    }

    if let Some(record) = &presented {
        // "Audience mismatches": a credential for another audience is not this caller's to
        // introspect, and answering `active: false` would report it unusable when it is not.
        if record.descriptor.audience != caller.descriptor.audience {
            return Err(Denied::new(
                DenialReason::AudienceMismatch,
                DenialClause::AudienceMismatch,
            ));
        }
        if record.descriptor.organization != caller.descriptor.organization {
            return Err(Denied::new(
                DenialReason::TenantMismatch,
                DenialClause::OrganizationMismatch,
            ));
        }
        // "Caller proof lacks introspection authority for the registered server/tenant."
        if !may_introspect(&caller, record, holds_the_audience) {
            return Err(Denied::new(
                DenialReason::Denied,
                DenialClause::IntrospectionAuthority,
            ));
        }
    }

    let active = presented
        .as_ref()
        .is_some_and(|record| usable(record, now, servers));
    let descriptor = active.then(|| {
        presented
            .as_ref()
            .expect("an active answer resolved to a record")
            .descriptor
            .clone()
    });
    let credential_id = active.then(|| {
        presented
            .as_ref()
            .expect("an active answer resolved to a record")
            .id
    });
    let context = VerifiedContext {
        subject: caller.descriptor.subject,
        actor: caller.descriptor.actor,
        organization: caller.descriptor.organization,
        audience: caller.descriptor.audience.clone(),
        credential: caller.id,
        delegation: caller.descriptor.delegation,
        execution: caller.descriptor.execution,
        correlation: request.correlation.clone(),
    };
    Ok(CredentialIntrospection {
        active,
        descriptor: descriptor.clone(),
        credential_id,
        event: CredentialEvent::CredentialIntrospected {
            context,
            descriptor,
            active,
            credential_id,
        },
    })
}

/// Realize `mandate.credential.RevokeAccessCredential`.
///
/// The record is kept and moves to its declared terminal state; nothing is destroyed
/// (`decision-blocker:lifecycle`). What the revocation reaches is every later resolution —
/// immediately, for a profile that resolves online, and within the profile's own bound for
/// one that does not, which is the guarantee the registration published.
///
/// # Errors
///
/// Returns [`Denied`] through the declared `denied` outcome when the credential does not
/// resolve or belongs to another organization than the caller's verified one, and through
/// the declared `wrong-state` outcome when it is already in the terminal `Revoked` state.
pub fn revoke_access_credential(
    input: &RevokeAccessCredential,
    credentials: &impl CredentialReads,
) -> Result<CredentialEvent, Denied> {
    let record = credentials
        .access_credential(&input.id)
        .ok_or_else(|| Denied::new(DenialReason::Denied, DenialClause::CredentialUnknown))?;
    // "Resolved credential is outside the verified organization." The binding is the
    // descriptor's own.
    if record.descriptor.organization != input.context.organization {
        return Err(Denied::new(
            DenialReason::TenantMismatch,
            DenialClause::OrganizationMismatch,
        ));
    }
    match record.state {
        AccessCredentialState::Active => {}
        // `revoke` starts from `Active` alone.
        AccessCredentialState::Revoked => {
            return Err(Denied::wrong_state(
                DenialReason::Denied,
                DenialClause::CredentialRevoked,
            ));
        }
    }
    Ok(CredentialEvent::AccessCredentialRevoked {
        context: input.context.clone(),
        id: record.id,
    })
}
