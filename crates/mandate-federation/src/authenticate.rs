//! `mandate.federation.AuthenticateFederation` and
//! `mandate.federation.ProvisionExternalPrincipal`.
//!
//! # What `jit_provisioning` gates
//!
//! Creation, and only creation. `federation.yaml:4`: a connection that does not admit
//! provisioning "denies the first login and creates nothing". An existing link is not a
//! first login, so it is admitted by any enabled connection of that organization on that
//! issuer whose tenant rule the proof satisfies, including a sibling that refuses
//! provisioning. `authenticate_federation` therefore does not read the flag at all.
//!
//! # Subjects
//!
//! The validated subject becomes a key component exactly as the issuer issued it. A
//! subject that is empty, or that is not its own trim, is refused; nothing is
//! canonicalized, because `sub` is opaque and case-sensitive and folding two forms
//! together would merge identities the issuer keeps distinct.

use std::collections::BTreeSet;

use serde::Serialize;

use mandate_model::TenantResolutionRule;
use mandate_types::{
    CredentialProof, DenialReason, EpochSnapshotRef, ExternalLinkMethod, ExternalPrincipalId,
    ExternalSubject, FederationConnectionId, OrganizationId, PrincipalId, PrincipalKind, SessionId,
    Timestamp,
};

use crate::record::{
    ConnectionState, ExternalKey, FederationConnection, FederationEvent, LinkState,
};
use crate::verifier::VerifiedProof;
use crate::{ConnectionStore, DenialClause, Denied, FederationVerifier, IdentityAllocator};
use crate::{LinkResolution, LinkStore, RequestContext, SessionIssuer};
use crate::{PrincipalState, PrincipalStore};

/// `mandate.federation.AuthenticateFederation`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthenticateFederation {
    /// The declared `connection_id`.
    pub connection_id: FederationConnectionId,
    /// The declared `proof`.
    pub proof: CredentialProof,
}

/// The accepted outcome of [`AuthenticateFederation`].
///
/// The five declared response fields (`federation.yaml`, `AuthenticateFederation`), and
/// the event the outcome emits. `mandate.federation.FederationAuthenticated` sources four
/// of its payload fields from this response, so every one of them is named here rather
/// than left inside the event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authenticated {
    /// The declared `session_id` response.
    pub session_id: SessionId,
    /// The declared `organization_id` response: the organization the context is
    /// established in.
    pub organization_id: OrganizationId,
    /// The declared `principal_id` response: the linked principal the context is
    /// established for.
    pub principal_id: PrincipalId,
    /// The declared `epochs` response: the snapshot handle the session is bound to.
    pub epochs: EpochSnapshotRef,
    /// The declared `expires_at` response: when the session stops being refreshable.
    pub expires_at: Timestamp,
    /// The event the accepted outcome emits.
    pub event: FederationEvent,
}

/// `mandate.federation.ProvisionExternalPrincipal`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProvisionExternalPrincipal {
    /// The declared `connection_id`.
    pub connection_id: FederationConnectionId,
    /// The declared `proof`.
    pub proof: CredentialProof,
}

/// The accepted outcome of [`ProvisionExternalPrincipal`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provisioned {
    /// The declared `external_principal_id` response.
    pub external_principal_id: ExternalPrincipalId,
    /// The declared `principal_id` response.
    pub principal_id: PrincipalId,
    /// The declared `subject` response, read from the validated proof.
    pub subject: ExternalSubject,
    /// The declared `display_name` response: the name the created Principal record
    /// carries, decided here from the validated subject, never from unvalidated input.
    pub display_name: String,
    /// The event the accepted outcome emits.
    pub event: FederationEvent,
}

/// Realize `mandate.federation.AuthenticateFederation`.
///
/// # Errors
///
/// Returns [`Denied`] when the connection is unresolved or disabled, the proof is
/// refused, its issuer or audience is not the connection's, tenant resolution has zero or
/// multiple matches, a fallback on unvalidated input would be required, or the link is
/// absent.
pub fn authenticate_federation(
    input: &AuthenticateFederation,
    request: &RequestContext,
    verifier: &impl FederationVerifier,
    connections: &(impl ConnectionStore + PrincipalStore),
    links: &impl LinkStore,
    issuer: &mut impl SessionIssuer,
) -> Result<Authenticated, Denied> {
    let resolved = resolve(&input.connection_id, &input.proof, verifier, connections)?;
    // Step 7: resolve the external principal. "principal linking is absent/conflicting".
    // The key is the only route; no email, domain or display value reaches this read.
    // A row in the terminal `Unlinked` state is not an explicitly linked principal. The
    // command reads the lifecycle state itself: a port cannot make that a property of
    // the command. Which record holds the key is `LinkResolution`'s, blanket-implemented
    // over every `LinkStore` so that no store can answer it and no store is asked to.
    let link = links
        .link(&resolved.key)
        .filter(|link| link.state == LinkState::Linked)
        .ok_or_else(|| Denied::new(DenialReason::Denied, DenialClause::LinkAbsent))?;
    // The link survives the principal's disablement — nothing in this domain unlinks on
    // it — so the session is what must not be issued. An unanswered principal is not
    // refused here, unlike at `link_external_principal`: the link row is itself the
    // record that this principal existed and was explicitly linked, and a store that
    // cannot see `mandate.identity`'s disablement events has said nothing about it.
    if connections.state_of(&link.principal_id) == Some(PrincipalState::Disabled) {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::PrincipalDisabled,
        ));
    }
    // Steps 8 and 9: establish the organization context and issue the session.
    let issued = issuer.issue(
        link.principal_id,
        resolved.organization_id,
        resolved.connection.id,
    )?;
    Ok(Authenticated {
        session_id: issued.session_id,
        organization_id: resolved.organization_id,
        principal_id: link.principal_id,
        epochs: issued.epochs,
        expires_at: issued.expires_at.clone(),
        event: FederationEvent::FederationAuthenticated {
            session_id: issued.session_id,
            principal_id: link.principal_id,
            audience: request.audience.clone(),
            correlation: request.correlation.clone(),
            connection_id: resolved.connection.id,
            organization_id: resolved.organization_id,
            epochs: issued.epochs,
            expires_at: issued.expires_at,
        },
    })
}

/// Realize `mandate.federation.ProvisionExternalPrincipal`.
///
/// # Errors
///
/// Returns [`Denied`] on every condition [`authenticate_federation`] refuses except an
/// absent link, and additionally when the connection does not admit provisioning or the
/// composite key already exists.
pub fn provision_external_principal(
    input: &ProvisionExternalPrincipal,
    request: &RequestContext,
    verifier: &impl FederationVerifier,
    connections: &impl ConnectionStore,
    links: &impl LinkStore,
    allocator: &mut impl IdentityAllocator,
) -> Result<Provisioned, Denied> {
    let resolved = resolve(&input.connection_id, &input.proof, verifier, connections)?;
    // "connection does not admit provisioning": `jit_provisioning` gates this command
    // alone, and a connection that does not admit it creates nothing.
    if !resolved.connection.jit_provisioning {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::ProvisioningNotAdmitted,
        ));
    }
    // "the composite (organization, configured issuer, subject) key already exists". This
    // command asks whether the key is free to create a record on, and a key whose every
    // record reached the terminal `Unlinked` state of
    // `mandate.federation.UnlinkExternalPrincipal` is not free — it is empty, not erased.
    // `authenticate_federation` above and `link_external_principal` ask the other
    // question, whether the key resolves to an *explicitly linked* principal, and so read
    // `LinkResolution::link` and the lifecycle state on what it hands them.
    //
    // Both questions are answered in `LinkResolution`, blanket-implemented over every
    // `LinkStore`, so neither is a property of the implementation this command was handed.
    // `LinkAbsent` names two conditions — never linked, and revoked — and the composition
    // `decision-blocker:jit-provisioning` prescribes provisions on it, so a store free to
    // answer nothing for a key whose every record is revoked would mint a **new**
    // `PrincipalId` for that subject, which is not a revocation and which nothing
    // downstream can correlate to the principal that was revoked. A store is asked one
    // thing, `records_on_key`, and an empty answer is the only way to say the key is free.
    if links.key_is_held(&resolved.key) {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::ExternalKeyExists,
        ));
    }
    let principal_id = allocator.next_principal_id();
    let external_principal_id = allocator.next_external_principal_id();
    // `display_name` is a response field the event sources (`federation.yaml`, wave B):
    // decided from the validated subject, so no unvalidated input contributes to a
    // persisted record, and the response and the event carry the same value.
    let display_name = resolved.key.subject.as_str().to_owned();
    Ok(Provisioned {
        external_principal_id,
        principal_id,
        subject: resolved.key.subject.clone(),
        display_name: display_name.clone(),
        event: FederationEvent::ExternalPrincipalProvisioned {
            organization_id: resolved.organization_id,
            correlation: request.correlation.clone(),
            connection_id: resolved.connection.id,
            principal_id,
            kind: PrincipalKind::User,
            display_name,
            external_principal_id,
            subject: resolved.key.subject,
            link_method: ExternalLinkMethod::ConfiguredFederation,
            linked_at: request.at.clone(),
        },
    })
}

/// What steps 1 to 6 of the resolution order established.
struct Resolved {
    connection: FederationConnection,
    organization_id: OrganizationId,
    key: ExternalKey,
}

/// Steps 1 to 6 of the resolution order `docs/architecture/federated-login.md` mandates,
/// shared by both proof-driven commands: a proof validated twice inside its window
/// cannot be admitted by one and refused by the other.
fn resolve(
    connection_id: &FederationConnectionId,
    proof: &CredentialProof,
    verifier: &impl FederationVerifier,
    connections: &impl ConnectionStore,
) -> Result<Resolved, Denied> {
    // 1: select the configured trust relationship.
    let connection = connections
        .connection(connection_id)
        .ok_or_else(|| Denied::new(DenialReason::Denied, DenialClause::ConnectionUnknown))?;
    if connection.state != ConnectionState::Enabled {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::ConnectionDisabled,
        ));
    }
    // 3: validate the signature. Behind the port; no cryptography here.
    let verified = verifier.verify(&connection, proof)?;
    // 2: validate the issuer, against the connection's own and nothing else.
    if *verified.issuer() != connection.issuer {
        return Err(Denied::new(
            DenialReason::InvalidCredential,
            DenialClause::IssuerMismatch,
        ));
    }
    // 4: validate the audience/client binding.
    if *verified.audience() != connection.client_id {
        return Err(Denied::new(
            DenialReason::AudienceMismatch,
            DenialClause::AudienceBinding,
        ));
    }
    // A validated subject that trims to nothing is not a subject: it would become a whole
    // key component, and every identity from this issuer carrying one would resolve to
    // the first principal recorded under it.
    if verified.subject().as_str().trim().is_empty() {
        return Err(Denied::new(
            DenialReason::InvalidCredential,
            DenialClause::EmptySubject,
        ));
    }
    // Refused, not trimmed: the trimmed form is a different subject.
    if verified.subject().as_str() != verified.subject().as_str().trim() {
        return Err(Denied::new(
            DenialReason::InvalidCredential,
            DenialClause::SubjectNotTrimmed,
        ));
    }
    // 6: resolve the configured organization. Step 5, nonce/state/PKCE, applies to
    // `AuthorizePublicClient`, which `story:pkce-sessions` realizes.
    let organization_id = resolve_tenant(verifier, connections, &connection, &verified)?;
    Ok(Resolved {
        key: ExternalKey {
            organization_id,
            // The issuer is read from the validated connection, never duplicated and
            // never caller-selected (`federation.yaml:1`).
            issuer: connection.issuer.clone(),
            subject: verified.subject().clone(),
        },
        connection,
        organization_id,
    })
}

/// Resolve the configured organization, or refuse.
///
/// Resolution runs over every enabled connection configured for the validated issuer,
/// because a single connection carries one rule and could only ever yield zero or one
/// match, while the declared denial names "zero or multiple matches".
fn resolve_tenant(
    verifier: &impl FederationVerifier,
    connections: &impl ConnectionStore,
    connection: &FederationConnection,
    verified: &VerifiedProof,
) -> Result<OrganizationId, Denied> {
    // The command decides which connections take part, not the store: a `Disabled`
    // connection, or one on another issuer, is dropped whatever a store answered.
    let candidates = crate::enabled_on_issuer(connections, verified.issuer());
    // Step 6 validates the tenant binding *of the trust relationship step 1 selected*.
    // The selected connection's own rule is the binding; another connection's rule
    // cannot stand in for it, or the configured rule would be advisory.
    if !matches_validated(&connection.tenant_resolution, verified) {
        let fallback = candidates
            .iter()
            .chain(std::iter::once(connection))
            .any(|candidate| matches_unvalidated(&candidate.tenant_resolution, verified));
        if fallback {
            return Err(Denied::new(
                DenialReason::TenantMismatch,
                DenialClause::UnverifiedFallback,
            ));
        }
        // Zero matches with no fallback owed. When the rule's claim arrived as a
        // non-string, the verifier is told its type so the refusal says why; the denial
        // is the `TenantZero` a skipped claim always produced, and nothing before this
        // point — the subject checks, the fallback analysis — answers differently. A rule
        // with a claim name and no value matches nothing of any type, so the type is not
        // reported for it.
        let rule = &connection.tenant_resolution;
        if let Some(kind) = rule
            .verified_claim_name
            .as_deref()
            .filter(|_| rule.verified_claim_value.is_some())
            .and_then(|name| verified.claim_type(name))
        {
            verifier.tenant_claim_refused(kind);
        }
        return Err(Denied::new(
            DenialReason::TenantMismatch,
            DenialClause::TenantZero,
        ));
    }
    let matched: BTreeSet<OrganizationId> = candidates
        .iter()
        .filter(|candidate| matches_validated(&candidate.tenant_resolution, verified))
        .map(|candidate| candidate.tenant_resolution.configured_organization)
        .collect();
    let mut found = matched.into_iter();
    let organization_id = match (found.next(), found.next()) {
        (None, _) => {
            // Zero matches. If a rule would have matched on a value that arrived
            // unvalidated, the request is refused for *that* reason: the fallback is
            // named and refused rather than silently unavailable.
            let fallback = candidates
                .iter()
                .any(|candidate| matches_unvalidated(&candidate.tenant_resolution, verified));
            return Err(Denied::new(
                DenialReason::TenantMismatch,
                if fallback {
                    DenialClause::UnverifiedFallback
                } else {
                    DenialClause::TenantZero
                },
            ));
        }
        // Two configured tenants match. Mandate denies rather than guesses.
        (Some(_), Some(_)) => {
            return Err(Denied::new(
                DenialReason::TenantMismatch,
                DenialClause::TenantAmbiguous,
            ));
        }
        (Some(only), None) => only,
    };
    // "consistent organization/connection binding" (`federation.yaml:2`).
    if organization_id != connection.organization_id {
        return Err(Denied::new(
            DenialReason::TenantMismatch,
            DenialClause::OrganizationMismatch,
        ));
    }
    Ok(organization_id)
}

/// Whether a rule matches on what the verifier validated.
///
/// A rule that names a claim without a value, or a value without a claim, matches
/// nothing: half a rule is not a binding, and this path fails closed.
fn matches_validated(rule: &TenantResolutionRule, verified: &VerifiedProof) -> bool {
    match (&rule.verified_claim_name, &rule.verified_claim_value) {
        (None, None) => true,
        (Some(name), Some(value)) => verified.verified_claim(name) == Some(value.as_str()),
        _ => false,
    }
}

/// Whether a rule *would* have matched on a value that arrived unvalidated.
///
/// Nothing acts on this. It exists so that a refusal can say which one it is.
fn matches_unvalidated(rule: &TenantResolutionRule, verified: &VerifiedProof) -> bool {
    match (&rule.verified_claim_name, &rule.verified_claim_value) {
        (Some(name), Some(value)) => verified.unverified_hint(name) == Some(value.as_str()),
        _ => false,
    }
}
