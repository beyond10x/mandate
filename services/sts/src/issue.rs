//! Both credential families: `IssueReferenceCredential` and
//! `IssueSelfContainedCredential`.
//!
//! # What the two share
//!
//! A registered, enabled target in the caller's verified organization, whose registered
//! `CredentialProfile` admits the family being asked for, and an expiry the profile bounds.
//! The descriptor is the caller's own context against that target's audience: the audience
//! is read from the registration and never from the caller, because "authentication context
//! comes from credential validation, never independent organization/audience selectors"
//! (`AGENTS.md`).
//!
//! # What the two do not share
//!
//! A reference credential's material is a secret this deployment mints ([`crate::SecretSource`])
//! and can resolve; a self-contained credential's is a token [`IssuanceSigner`] produced,
//! which a verifier checks without asking anyone. The bound is decided differently for the
//! same reason: a reference credential expires when this deployment says it does, while a
//! self-contained one expires when the `exp` the signer wrote says it does — so the signer's
//! own TTL is checked against the profile's `max_ttl` and the descriptor is written from the
//! signer's TTL, not from the profile's. A deployment whose signer and whose request clock
//! disagree writes a descriptor that differs from the token's `exp` by that skew; one clock
//! is the deployment's obligation, and this is the "documented TTL/skew bound" of
//! `profile-offline-bound`.
//!
//! # Both record a verifier, and the contract is why
//!
//! `credential.yaml:410,428` declares `reference_verifier` on **both** issuance events —
//! `CredentialReferenceIssued` and `CredentialSelfContainedIssued` — sourced `generated:
//! true`, while `mandate.credential.AccessCredential` carries the field as an `Optional`.
//! The two readings do not agree: a `generated` source is a value the outcome produces, and
//! `mandate-testkit`'s `check_payload_sources` refuses an emitted payload that omits one
//! ("generated at runtime, but the event carries no such field"), so a self-contained
//! issuance that recorded nothing would emit a payload the contract's own source check
//! rejects. **That is why this family records the digest of the token it returned**, and it
//! is a contract observation routed to the coordinator, not a decision taken here.
//!
//! It is also what an introspection of this family needs: nothing in this crate's
//! dependency ceiling parses a JWS, so a presented token is resolved the same way a
//! presented secret is — by its digest, in its own domain
//! ([`mandate_token::verifier::CredentialDomain`]). For the reference family the recorded
//! verifier is the whole of `reference-persistence`. Neither family records the material:
//! [`mandate_token::verifier`] derives the verifier, and `mandate.core.CredentialSecret` is
//! not a `PersistedValue`.
//!
//! # What is decided elsewhere
//!
//! "Subject/actor authority or ceilings do not cover requested scope" is an authorization
//! decision — `mandate-authz` is outside this crate's ceiling — so the scope carried is the
//! one the adapter presents, already narrowed. "Validated context is expired/revoked/stale"
//! is the adapter's validation of the caller's own credential, which is what produced the
//! `VerifiedContext` these handlers are given.

use mandate_token::projection::{CredentialEvent, DenialClause, Denied, ResourceServer};
use mandate_token::signing_real::{
    Clock, CredentialSigner, RealSigner, SignedCredential, SigningError, StandardClaims,
};
use mandate_token::verifier::{CredentialDigest, CredentialDomain, verifier_in};
use mandate_token::{CredentialDescriptor, CredentialProfile};
use mandate_types::{
    AuthorityScope, CredentialId, CredentialKind, CredentialSecret, CredentialVerifier,
    DenialReason, EpochSnapshotRef, Issuer, ResourceServerId, Timestamp, VerifiedContext,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::registry::ResourceServerReads;
use crate::{IdentityAllocator, RequestContext, SecretSource, instant};

/// The digest this deployment records a credential under.
///
/// SHA-256 of the material, rendered as lower-case hexadecimal, through the port
/// `mandate-token` declares — that crate has no digest of its own
/// (`dependency-boundaries.json`), and `mandate-sts` has `sha2`.
///
/// It digests exactly what it is handed and separates no families itself: the material
/// already carries its [`CredentialDomain`] tag by the time it arrives, because
/// [`mandate_token::verifier::verifier_in`] prefixes it. An implementation that had to
/// remember would be one that could forget.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Sha256Digest;

impl CredentialDigest for Sha256Digest {
    fn digest(&self, material: &[u8]) -> CredentialVerifier {
        let digested = Sha256::digest(material);
        let mut rendered = String::with_capacity(digested.len() * 2);
        for byte in digested {
            rendered.push_str(&format!("{byte:02x}"));
        }
        CredentialVerifier::new(rendered)
    }
}

/// The signing port, as issuance can name it.
///
/// [`mandate_token::signing_real::CredentialSigner`] is the port
/// `story:signing-and-verification` declared, and this crate consumes it — but its
/// `published_keys` returns a `jsonwebtoken` type, and `jsonwebtoken` is not in this crate's
/// dependency ceiling (`dependency-boundaries.json`), so its name cannot appear here. This
/// is that port narrowed to what issuance uses, plus the one value issuance must know and
/// `CredentialSigner` does not expose: the TTL the signer writes into `exp`.
///
/// Every [`RealSigner`] is one, by the implementation below, so the deployment's real signer
/// is admitted without a wrapper.
pub trait IssuanceSigner {
    /// Sign a descriptor as the credential's claims, under the signer's active key.
    ///
    /// # Errors
    ///
    /// Whatever the signer refuses: no active key, a reserved claim, or an encoding failure.
    fn sign_credential(
        &self,
        claims: &CredentialDescriptor,
        standard: &StandardClaims,
    ) -> Result<SignedCredential, SigningError>;

    /// The lifetime the signer writes into every credential it signs, in seconds.
    fn ttl_seconds(&self) -> u64;
}

impl<C: Clock> IssuanceSigner for RealSigner<C> {
    fn sign_credential(
        &self,
        claims: &CredentialDescriptor,
        standard: &StandardClaims,
    ) -> Result<SignedCredential, SigningError> {
        self.sign(claims, standard)
    }

    fn ttl_seconds(&self) -> u64 {
        Self::ttl_seconds(self)
    }
}

/// An [`IssuanceSigner`] that renders a token from the claims it was given.
///
/// **A fixture, never a shipped implementation: it signs nothing.** What it returns is the
/// `kid`, the credential's own identifier and the claims, which is enough for a case to
/// show that the material a holder receives is the material the record resolves — and not
/// enough for anything else. The real implementation is
/// [`mandate_token::signing_real::RealSigner`], which needs key material no fixture in this
/// repository may carry.
///
/// It is `pub` and lives here because every file under `tests/` compiles as its own crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticSigner {
    kid: String,
    ttl_seconds: u64,
}

impl StaticSigner {
    /// A double that renders under this `kid`, writing this TTL.
    #[must_use]
    pub fn new(kid: impl Into<String>, ttl_seconds: u64) -> Self {
        Self {
            kid: kid.into(),
            ttl_seconds,
        }
    }
}

impl IssuanceSigner for StaticSigner {
    fn sign_credential(
        &self,
        claims: &CredentialDescriptor,
        standard: &StandardClaims,
    ) -> Result<SignedCredential, SigningError> {
        let claims = serde_json::to_string(claims)
            .map_err(|error| SigningError::Encode(error.to_string()))?;
        Ok(SignedCredential {
            // `token_id` is the credential's own identity, so two credentials over one
            // descriptor are two tokens — which is what the record's verifier index needs.
            token: format!("unsigned.{}.{}.{}", self.kid, standard.token_id, claims),
            kid: self.kid.clone(),
        })
    }

    fn ttl_seconds(&self) -> u64 {
        self.ttl_seconds
    }
}

/// `mandate.credential.IssueReferenceCredential`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IssueReferenceCredential {
    /// The declared `context`.
    pub context: VerifiedContext,
    /// The declared `target`.
    pub target: ResourceServerId,
    /// The declared `requested_scope`.
    pub requested_scope: AuthorityScope,
}

/// `mandate.credential.IssueSelfContainedCredential`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IssueSelfContainedCredential {
    /// The declared `context`.
    pub context: VerifiedContext,
    /// The declared `target`.
    pub target: ResourceServerId,
    /// The declared `requested_scope`.
    pub requested_scope: AuthorityScope,
}

/// The deployment's ports for a reference issuance.
///
/// Bundled rather than passed one by one: the handler takes the command, the request, the
/// read model and the deployment, and a signature that spelled the deployment out would be
/// four more arguments that always travel together.
pub struct ReferenceParts<'a, D: CredentialDigest, S: SecretSource, A: IdentityAllocator> {
    /// The digest the verifier is derived through.
    pub digest: &'a D,
    /// The source the returned secret is minted from.
    pub secrets: &'a mut S,
    /// The allocator the response identity is minted from.
    pub allocator: &'a mut A,
}

/// The deployment's ports for a self-contained issuance.
pub struct SelfContainedParts<'a, D: CredentialDigest, A: IdentityAllocator, K: IssuanceSigner> {
    /// The digest the verifier is derived through.
    pub digest: &'a D,
    /// The allocator the response identity is minted from.
    pub allocator: &'a mut A,
    /// The signer the token is produced by.
    pub signer: &'a K,
    /// The issuer the deployment speaks as, written into `iss`.
    pub issuer: &'a Issuer,
}

/// The accepted outcome of either issuance command.
///
/// The four declared response fields, the event the outcome emits, and the `kid` — which is
/// not a declared response field and is carried because the composition binds the credential
/// to the `mandate.credential.SigningKey` record it was signed under, and nothing else in
/// the outcome names that key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialIssued {
    /// The declared `credential` response: the material, returned once.
    pub credential: CredentialSecret,
    /// The declared `credential_id` response.
    pub credential_id: CredentialId,
    /// The declared `epochs` response.
    pub epochs: Option<EpochSnapshotRef>,
    /// The declared `descriptor` response.
    pub descriptor: CredentialDescriptor,
    /// The event the accepted outcome emits.
    pub event: CredentialEvent,
    /// The key the credential was signed under, for the self-contained family alone.
    pub kid: Option<String>,
}

/// The registration an issuance is for, or the declared refusal.
///
/// "Target/profile is unregistered/disabled/outside tenant", one clause at a time, plus the
/// family: a registration names which family its holders get, and a command that asked for
/// the other is refused rather than served the profile's.
fn admitted_target(
    context: &VerifiedContext,
    target: &ResourceServerId,
    servers: &impl ResourceServerReads,
    family: CredentialKind,
) -> Result<ResourceServer, Denied> {
    let record = servers
        .resource_server(target)
        .ok_or_else(|| Denied::new(DenialReason::Denied, DenialClause::TargetUnregistered))?;
    if record.organization_id != context.organization {
        return Err(Denied::new(
            DenialReason::TenantMismatch,
            DenialClause::OrganizationMismatch,
        ));
    }
    if servers.is_enabled(target) != Some(true) {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::TargetDisabled,
        ));
    }
    if record.credential_profile.kind != family {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::ProfileUnadmitted,
        ));
    }
    Ok(record)
}

/// The instant a credential issued now stops being valid, or the declared refusal.
///
/// "Expiry cannot be bounded" is every way this can fail: a request that names no instant,
/// a profile whose `max_ttl` names no span, a lifetime longer than the profile's bound, and
/// an expiry [`instant::at`] cannot render as one this crate reads back.
fn bounded_expiry(
    request: &RequestContext,
    profile: &CredentialProfile,
    lifetime: i64,
) -> Result<Timestamp, Denied> {
    let unbounded = || Denied::new(DenialReason::Denied, DenialClause::ExpiryUnbounded);
    let issued_at = instant::seconds_of(&request.at).ok_or_else(unbounded)?;
    let bound = instant::span_of(&profile.max_ttl).ok_or_else(unbounded)?;
    if lifetime <= 0 || lifetime > bound {
        return Err(unbounded());
    }
    issued_at
        .checked_add(lifetime)
        .and_then(instant::at)
        .ok_or_else(unbounded)
}

/// The descriptor an issuance responds with and records.
fn descriptor_for(
    context: &VerifiedContext,
    server: &ResourceServer,
    requested_scope: &AuthorityScope,
    expires_at: Timestamp,
) -> CredentialDescriptor {
    CredentialDescriptor {
        kind: server.credential_profile.kind,
        subject: context.subject,
        actor: context.actor,
        organization: context.organization,
        // The audience is the registration's. A caller-supplied one would be an independent
        // audience selector, which `AGENTS.md` refuses.
        audience: server.audience.clone(),
        scope: requested_scope.clone(),
        delegation: context.delegation,
        execution: context.execution,
        expires_at,
    }
}

/// Realize `mandate.credential.IssueReferenceCredential`.
///
/// The secret is minted, returned once, and never recorded: what the log carries is the
/// verifier it derives. Nothing here can put the material on a record — the event's payload
/// types are all `PersistedValue` and `CredentialSecret` is not one.
///
/// # Errors
///
/// Returns [`Denied`] through the declared `denied` outcome when the target is unregistered,
/// disabled or outside the caller's verified organization, when its registered profile does
/// not issue this family, or when the expiry cannot be bounded. A refusal mints no secret.
pub fn issue_reference_credential<D, S, A>(
    input: &IssueReferenceCredential,
    request: &RequestContext,
    servers: &impl ResourceServerReads,
    parts: ReferenceParts<'_, D, S, A>,
) -> Result<CredentialIssued, Denied>
where
    D: CredentialDigest,
    S: SecretSource,
    A: IdentityAllocator,
{
    let server = admitted_target(
        &input.context,
        &input.target,
        servers,
        CredentialKind::Reference,
    )?;
    let lifetime = instant::span_of(&server.credential_profile.max_ttl)
        .ok_or_else(|| Denied::new(DenialReason::Denied, DenialClause::ExpiryUnbounded))?;
    let expires_at = bounded_expiry(request, &server.credential_profile, lifetime)?;
    let descriptor = descriptor_for(&input.context, &server, &input.requested_scope, expires_at);

    // Nothing above this line mints anything: a refusal leaves the deployment exactly as it
    // was, which is what "fail closed; no credential ... on refusal" means for a source that
    // counts what it handed out.
    let credential = parts.secrets.next_secret();
    let reference_verifier =
        verifier_in(parts.digest, CredentialDomain::ReferenceSecret, &credential);
    let credential_id = parts.allocator.next_credential_id();
    Ok(CredentialIssued {
        credential,
        credential_id,
        epochs: request.epochs,
        descriptor: descriptor.clone(),
        event: CredentialEvent::CredentialReferenceIssued {
            context: input.context.clone(),
            credential_id,
            reference_verifier: Some(reference_verifier),
            epochs: request.epochs,
            issued_at: request.at.clone(),
            descriptor,
            target: input.target,
            requested_scope: input.requested_scope.clone(),
        },
        kid: None,
    })
}

/// Realize `mandate.credential.IssueSelfContainedCredential`.
///
/// The credential is the token the signer produced. Its lifetime is the signer's, because
/// that is what an offline verifier reads, and a signer configured beyond the profile's
/// `max_ttl` is refused rather than silently shortened — the token would outlive the bound
/// whatever this handler wrote into the descriptor.
///
/// # Errors
///
/// Returns [`Denied`] through the declared `denied` outcome when the target is unregistered,
/// disabled or outside the caller's verified organization, when its registered profile does
/// not issue this family, when the signer's lifetime is not inside the profile's bound, or
/// when the signer refuses.
pub fn issue_self_contained_credential<D, A, K>(
    input: &IssueSelfContainedCredential,
    request: &RequestContext,
    servers: &impl ResourceServerReads,
    parts: SelfContainedParts<'_, D, A, K>,
) -> Result<CredentialIssued, Denied>
where
    D: CredentialDigest,
    A: IdentityAllocator,
    K: IssuanceSigner,
{
    let server = admitted_target(
        &input.context,
        &input.target,
        servers,
        CredentialKind::SelfContained,
    )?;
    let lifetime = i64::try_from(parts.signer.ttl_seconds())
        .map_err(|_| Denied::new(DenialReason::Denied, DenialClause::ExpiryUnbounded))?;
    let expires_at = bounded_expiry(request, &server.credential_profile, lifetime)?;
    let descriptor = descriptor_for(&input.context, &server, &input.requested_scope, expires_at);

    // The identity is signed into the token, so it exists before the signer can refuse —
    // reserved, not drawn. It is handed out only once the signer has signed: nothing below
    // the commit refuses, so a refusal leaves the deployment exactly as it was.
    let credential_id = parts.allocator.reserve_credential_id();
    let Ok(signed) = parts.signer.sign_credential(
        &descriptor,
        &StandardClaims {
            issuer: parts.issuer.clone(),
            subject: input.context.subject,
            audience: server.audience.clone(),
            token_id: credential_id.to_string(),
        },
    ) else {
        parts.allocator.release_credential_id(credential_id);
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::SigningRefused,
        ));
    };
    parts.allocator.commit_credential_id(credential_id);
    let credential = CredentialSecret::from_bytes(signed.token.into_bytes());
    // The token's own domain: a token and a reference secret never share a verifier space.
    let reference_verifier = verifier_in(
        parts.digest,
        CredentialDomain::SelfContainedToken,
        &credential,
    );
    Ok(CredentialIssued {
        credential,
        credential_id,
        epochs: request.epochs,
        descriptor: descriptor.clone(),
        event: CredentialEvent::CredentialSelfContainedIssued {
            context: input.context.clone(),
            credential_id,
            reference_verifier: Some(reference_verifier),
            epochs: request.epochs,
            issued_at: request.at.clone(),
            descriptor,
            target: input.target,
            requested_scope: input.requested_scope.clone(),
        },
        kid: Some(signed.kid),
    })
}
