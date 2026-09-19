//! The signing key's lifecycle: `RegisterSigningKey`, `RetireSigningKey` and
//! `RevokeSigningKey`.
//!
//! `mandate.credential.SigningKey` records the key a self-contained credential is signed
//! under: the identity that is the `kid`, the reference the deployment resolves to the
//! material, the thumbprint of the public key that reference resolved to, the algorithm name
//! and the validity window. No key material enters the contract, and none enters this
//! module: [`KeyMaterialResolver`] answers a thumbprint and nothing else.
//!
//! # Rotation and revocation are different commands
//!
//! "A signing key is retired for rotation and revoked in an emergency; neither destroys the
//! record, and no command deletes a key" (`credential.yaml:7`). A retirement is refused
//! unless a replacement is published and valid *now*, because a retired key signs nothing
//! further and a deployment with no valid key signs nothing at all. A revocation is refused
//! for nothing of the kind: the compromised key must go whether or not anything replaces it.
//!
//! # The algorithm is a name, never a name this crate knows
//!
//! `UNMAPPED-ALGORITHM-POLICY`: "SigningAlgorithm is a name, not an admitted algorithm. A
//! verifier-side allowlist is required before issuance/validation."
//! [`SigningKeyAdministration`] takes that allowlist as a constructor argument and no
//! algorithm is named anywhere in `services/sts/src` — which is the shape
//! `decision-blocker:algorithm-policy` asks for, and the list itself is the deployment's.
//!
//! # What is decided elsewhere
//!
//! Platform signing-key administration authority, on all three commands, is the adapter's —
//! the same boundary every other authority clause keeps. Rehydrating
//! [`mandate_token::signing_real::RealSigner::new_with_revocations`] from this fold — every
//! `Revoked` key's identity and thumbprint, so revoked material can never be installed again
//! after a restart — is the composition's, named as residue in the crate documentation.

use mandate_token::projection::{
    CredentialEvent, DenialClause, Denied, Projection, SigningKey, SigningKeyState,
};
use mandate_token::signing_real::AllowedAlgorithms;
use mandate_types::{
    DenialReason, KeyReference, SigningAlgorithm, SigningKeyId, Timestamp, VerifiedContext,
};
use serde::Serialize;

use crate::{IdentityAllocator, RequestContext, instant};

/// The `mandate.credential.SigningKey` read model. A fold over the event log.
pub trait SigningKeyReads {
    /// The key with this identity, whatever its lifecycle state.
    fn signing_key(&self, id: &SigningKeyId) -> Option<SigningKey>;

    /// Every recorded key, in whatever state.
    ///
    /// Registration reads all of them: a reference or a thumbprint already held is refused
    /// "in every state that key can be in, including Retired and Revoked".
    fn signing_keys(&self) -> Vec<SigningKey>;

    /// Whether this key holds both indexes it records — its `key_reference` and its
    /// `thumbprint`.
    ///
    /// A second record of material another key already has does not take the index from it
    /// ([`mandate_token::projection::Projection::signing_key_conflicts`]), and a key that
    /// holds neither index is admitted for nothing. Required rather than defaulted: a
    /// default of `true` would be a store silently claiming an index it never checked.
    fn holds_its_key_material(&self, id: &SigningKeyId) -> bool;
}

impl SigningKeyReads for Projection {
    fn signing_key(&self, id: &SigningKeyId) -> Option<SigningKey> {
        Self::signing_key(self, id)
    }

    fn signing_keys(&self) -> Vec<SigningKey> {
        Self::signing_keys(self).to_vec()
    }

    fn holds_its_key_material(&self, id: &SigningKeyId) -> bool {
        Self::holds_its_key_material(self, id)
    }
}

/// Resolving a key reference to the public key's thumbprint, behind a port.
///
/// The deployment holds the material; the contract holds a handle to it. What the accepted
/// outcome decides is the RFC 7638 thumbprint of the public half — which
/// [`mandate_token::signing_real::SigningKeyMaterial::thumbprint`] computes for material a
/// deployment has loaded, and which nothing in this crate could compute for material it has
/// not.
pub trait KeyMaterialResolver {
    /// The thumbprint of the public key this reference resolves to, or `None` when the
    /// deployment cannot resolve it.
    fn thumbprint(&self, reference: &KeyReference) -> Option<String>;
}

/// `mandate.credential.RegisterSigningKey`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegisterSigningKey {
    /// The declared `context`.
    pub context: VerifiedContext,
    /// The declared `key_reference`.
    pub key_reference: KeyReference,
    /// The declared `algorithm`.
    pub algorithm: SigningAlgorithm,
    /// The declared `not_before`.
    pub not_before: Timestamp,
    /// The declared `expires_at`.
    pub expires_at: Timestamp,
}

/// `mandate.credential.RetireSigningKey`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RetireSigningKey {
    /// The declared `id`.
    pub id: SigningKeyId,
    /// The declared `context`.
    pub context: VerifiedContext,
}

/// `mandate.credential.RevokeSigningKey`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RevokeSigningKey {
    /// The declared `id`.
    pub id: SigningKeyId,
    /// The declared `context`.
    pub context: VerifiedContext,
}

/// The accepted outcome of [`RegisterSigningKey`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningKeyRecorded {
    /// The declared `id` response, which is the `kid` the signer publishes.
    pub id: SigningKeyId,
    /// The declared `thumbprint` response, resolved from the key reference.
    pub thumbprint: String,
    /// The event the accepted outcome emits.
    pub event: CredentialEvent,
}

/// `RegisterSigningKey`, over the algorithm allowlist one deployment configured.
///
/// A value rather than a free function because the allowlist is deployment configuration
/// validated once at startup — [`AllowedAlgorithms::new`] refuses an empty list, `none` and
/// any unadmitted name — and a handler that took it per call would admit a policy nobody
/// checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningKeyAdministration {
    allowed: AllowedAlgorithms,
}

impl SigningKeyAdministration {
    /// Administration over the algorithms this deployment admits.
    #[must_use]
    pub const fn new(allowed: AllowedAlgorithms) -> Self {
        Self { allowed }
    }

    /// The algorithms this deployment admits.
    #[must_use]
    pub const fn allowed(&self) -> &AllowedAlgorithms {
        &self.allowed
    }

    /// Realize `mandate.credential.RegisterSigningKey`.
    ///
    /// The key enters the contract's `Recorded` state, which is what rotation requires: a
    /// retirement is refused with no overlapping replacement, and no replacement can exist
    /// until a key can be registered.
    ///
    /// # Errors
    ///
    /// Returns [`Denied`] through the declared `denied` outcome when the window is not
    /// ordered, when the algorithm is outside the deployment's admitted set, when the key
    /// reference is unresolvable, and when the key reference or the material it resolves to
    /// is already recorded — in any state, so material this deployment revoked never returns
    /// under a second identity.
    ///
    /// This is a read-then-write guard, like the audience index; storage enforces the same
    /// two indexes atomically (`docs/adr/0009-event-sourced-persistence.md`). What a racing
    /// pair produces is a second record that holds neither index, which every admission
    /// refuses.
    pub fn register(
        &self,
        input: &RegisterSigningKey,
        keys: &impl SigningKeyReads,
        material: &impl KeyMaterialResolver,
        allocator: &mut impl IdentityAllocator,
    ) -> Result<SigningKeyRecorded, Denied> {
        // The entity invariant `not_before < expires_at`, "checked by the deciding handler"
        // (`credential.yaml`, `RegisterSigningKey`). Decided as instants: the declared
        // `date-time` form admits offsets, and its byte order is not its chronological one.
        // A value that names no instant cannot be shown to be before another, so it fails
        // closed here rather than being compared as text.
        if instant::is_before(&input.not_before, &input.expires_at) != Some(true) {
            return Err(Denied::new(
                DenialReason::Denied,
                DenialClause::KeyWindowNotOrdered,
            ));
        }
        // "The algorithm is outside the deployment's admitted set." Both halves — a name
        // the crate's table does not admit at all, and one this deployment did not
        // configure — are this clause.
        self.allowed
            .admit(&input.algorithm)
            .map_err(|_| Denied::new(DenialReason::Denied, DenialClause::AlgorithmUnadmitted))?;
        // "The key reference is unresolvable."
        let thumbprint = material.thumbprint(&input.key_reference).ok_or_else(|| {
            Denied::new(DenialReason::Denied, DenialClause::KeyReferenceUnresolvable)
        })?;
        let recorded = keys.signing_keys();
        // "The key reference or the key material is already recorded." Two clauses, because
        // an operator who re-files revoked material under a new reference produces the
        // second and not the first.
        //
        // **This is where the uniqueness lives.** The fold records every registration and
        // names the loser of each index
        // ([`mandate_token::projection::Projection::signing_key_conflicts`]) rather than
        // refusing the log, so the write path is what keeps a second record of one piece of
        // material out — and a second record that is appended anyway, by two writers racing,
        // holds no index and is therefore admitted for neither issuance
        // ([`signing_admitted`]) nor verification ([`admitted_for_verification`]).
        if recorded
            .iter()
            .any(|key| key.key_reference == input.key_reference)
        {
            return Err(Denied::new(
                DenialReason::Denied,
                DenialClause::KeyReferenceRecorded,
            ));
        }
        if recorded.iter().any(|key| key.thumbprint == thumbprint) {
            return Err(Denied::new(
                DenialReason::Denied,
                DenialClause::KeyMaterialRecorded,
            ));
        }
        let id = allocator.next_signing_key_id();
        Ok(SigningKeyRecorded {
            id,
            thumbprint: thumbprint.clone(),
            event: CredentialEvent::SigningKeyRegistered {
                context: input.context.clone(),
                id,
                key_reference: input.key_reference.clone(),
                thumbprint,
                algorithm: input.algorithm.clone(),
                not_before: input.not_before.clone(),
                expires_at: input.expires_at.clone(),
            },
        })
    }
}

/// Whether a recorded key may still **sign** at an instant.
///
/// `Recorded` alone, inside its own window, holding both its indexes. It is what a rotation
/// needs of the successor — a retirement is refused unless another key can take issuance
/// over — and it is not the same question as
/// [`admitted_for_verification`], which is why the two are separate functions rather than
/// one called "published".
///
/// A key that does not hold its `key_reference` or its `thumbprint` signs nothing: it is a
/// second record of material another key already has, and admitting it would let material
/// this deployment revoked come back under a second identity, which is exactly what the
/// contract's uniqueness clause is for.
#[must_use]
pub fn signing_admitted(key: &SigningKey, now: i64, keys: &impl SigningKeyReads) -> bool {
    key.state == SigningKeyState::Recorded
        && inside_window(key, now)
        && keys.holds_its_key_material(&key.id)
}

/// Whether a recorded key is admitted for **verifying** a credential at an instant.
///
/// `Recorded` **and** `Retired`, which is the whole of what retirement means:
/// "a retired key signs nothing further; it remains admitted for verifying credentials
/// already issued under it until they expire, which is the overlapping rotation period the
/// key requirements demand" (`credential.yaml`, `RetireSigningKey`). `Revoked` is admitted
/// for neither — "a revoked key is admitted for neither issuance nor verification, and the
/// self-contained credentials it signed are refused from that point".
///
/// The window is the key's own. A credential that outlives it is refused at its own expiry,
/// which the issuing profile bounds (`crate::issue`), and keeping the overlap longer than
/// the TTL is the deployment's configuration — `RealSigner::new` refuses a shorter pairing.
#[must_use]
pub fn admitted_for_verification(key: &SigningKey, now: i64, keys: &impl SigningKeyReads) -> bool {
    matches!(
        key.state,
        SigningKeyState::Recorded | SigningKeyState::Retired
    ) && inside_window(key, now)
        && keys.holds_its_key_material(&key.id)
}

/// Whether an instant is inside a key's declared window: `not_before <= now < expires_at`.
///
/// A bound that names no instant fails closed, as every comparison in this crate does.
fn inside_window(key: &SigningKey, now: i64) -> bool {
    instant::seconds_of(&key.not_before).is_some_and(|starts| starts <= now)
        && instant::seconds_of(&key.expires_at).is_some_and(|ends| now < ends)
}

/// Realize `mandate.credential.RetireSigningKey`.
///
/// Rotation, not revocation: "a retired key signs nothing further; it remains admitted for
/// verifying credentials already issued under it until they expire, which is the overlapping
/// rotation period the key requirements demand".
///
/// # Errors
///
/// Returns [`Denied`] through the declared `denied` outcome when the key is unresolved and
/// when no other recorded key is published and valid at the request's instant — including
/// when that instant cannot be read, which cannot show a replacement is published — and
/// through the declared `wrong-state` outcome when the key is in a state `retire` does not
/// start from.
pub fn retire_signing_key(
    input: &RetireSigningKey,
    keys: &impl SigningKeyReads,
    request: &RequestContext,
) -> Result<CredentialEvent, Denied> {
    let key = keys
        .signing_key(&input.id)
        .ok_or_else(|| Denied::new(DenialReason::Denied, DenialClause::KeyUnknown))?;
    match key.state {
        SigningKeyState::Recorded => {}
        // `retire` starts from `Recorded` alone.
        SigningKeyState::Retired | SigningKeyState::Revoked => {
            return Err(Denied::wrong_state(
                DenialReason::Denied,
                DenialClause::KeyNotRecorded,
            ));
        }
    }
    // "No overlapping replacement key is published for continued verification."
    let Some(now) = instant::seconds_of(&request.at) else {
        return Err(Denied::new(
            DenialReason::Unavailable,
            DenialClause::NoReplacementKey,
        ));
    };
    if !keys
        .signing_keys()
        .iter()
        .any(|held| held.id != key.id && signing_admitted(held, now, keys))
    {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::NoReplacementKey,
        ));
    }
    Ok(CredentialEvent::SigningKeyRetired {
        context: input.context.clone(),
        id: key.id,
    })
}

/// Realize `mandate.credential.RevokeSigningKey`.
///
/// The emergency procedure: "a revoked key is admitted for neither issuance nor verification,
/// and the self-contained credentials it signed are refused from that point; the key record
/// itself is kept". No replacement is required — the compromised key goes whether or not
/// anything can take its place, which is the difference between this command and a
/// retirement.
///
/// # Errors
///
/// Returns [`Denied`] through the declared `denied` outcome when the key is unresolved, and
/// through the declared `wrong-state` outcome when it is already `Revoked`.
pub fn revoke_signing_key(
    input: &RevokeSigningKey,
    keys: &impl SigningKeyReads,
) -> Result<CredentialEvent, Denied> {
    let key = keys
        .signing_key(&input.id)
        .ok_or_else(|| Denied::new(DenialReason::Denied, DenialClause::KeyUnknown))?;
    match key.state {
        // `revoke` starts from `Recorded` and from `Retired`.
        SigningKeyState::Recorded | SigningKeyState::Retired => {}
        SigningKeyState::Revoked => {
            return Err(Denied::wrong_state(
                DenialReason::Denied,
                DenialClause::KeyNotRecorded,
            ));
        }
    }
    Ok(CredentialEvent::SigningKeyRevoked {
        context: input.context.clone(),
        id: key.id,
    })
}
