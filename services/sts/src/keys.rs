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
//! the same boundary every other authority clause keeps.
//!
//! # The signer follows the records
//!
//! [`RecordedSigner`] is the one place a [`RealSigner`] is built and changed, and it is
//! changed only from this fold: the key it signs under is [`issuing_key`], the keys it
//! refuses for ever are [`revocations`] — every `Revoked` record's identity and thumbprint,
//! handed to [`RealSigner::new_with_revocations`] when the signer is built, so material this
//! deployment revoked is never installed again after a restart — and the private material
//! comes through [`KeyProvider`], the key-provider seam, by the record's `key_reference`.
//! The `kid` a key signs and is published under is the record's identity.

use mandate_token::projection::{
    CredentialEvent, DenialClause, Denied, Projection, SigningKey, SigningKeyState,
};
use mandate_token::signing_real::{
    AllowedAlgorithms, Clock, CredentialSigner, RealSigner, RevokedKey, SigningError,
    SigningKeyMaterial,
};
use mandate_types::{
    DenialReason, KeyReference, SigningAlgorithm, SigningKeyId, SigningKeyWindow, VerifiedContext,
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
    /// The declared `window`.
    pub window: SigningKeyWindow,
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
        // The entity invariant `window.not_before < window.expires_at`, "checked by the deciding handler"
        // (`credential.yaml`, `RegisterSigningKey`). Decided as instants: the declared
        // `date-time` form admits offsets, and its byte order is not its chronological one.
        // A value that names no instant cannot be shown to be before another, so it fails
        // closed here rather than being compared as text.
        if instant::is_before(&input.window.not_before, &input.window.expires_at) != Some(true) {
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
                window: input.window.clone(),
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
    instant::seconds_of(&key.window.not_before).is_some_and(|starts| starts <= now)
        && instant::seconds_of(&key.window.expires_at).is_some_and(|ends| now < ends)
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

/// The key an issuance signs under at an instant: the newest key [`signing_admitted`] then.
///
/// Newest by the start of its window, and between two that start together by the later
/// registration — the fold's own order — so a key mounted for rotation takes issuance over
/// from the one it replaces as soon as its window opens. `None` is the state in which
/// nothing is issued: "issuance under a retired or revoked key is denied".
#[must_use]
pub fn issuing_key(keys: &impl SigningKeyReads, now: i64) -> Option<SigningKey> {
    let mut newest: Option<(i64, SigningKey)> = None;
    for key in keys.signing_keys() {
        if !signing_admitted(&key, now, keys) {
            continue;
        }
        let Some(starts) = instant::seconds_of(&key.window.not_before) else {
            continue;
        };
        if newest.as_ref().is_none_or(|(held, _)| starts >= *held) {
            newest = Some((starts, key));
        }
    }
    newest.map(|(_, key)| key)
}

/// Whether `kid` names a recorded key that may sign at an instant.
///
/// What an issuance asks of the key a signer actually signed under: the `kid` is the
/// record's identity, and a `kid` naming no record — or one that is retired, revoked,
/// outside its window or a second record of held material — signs nothing.
#[must_use]
pub fn kid_signing_admitted(kid: &str, now: i64, keys: &impl SigningKeyReads) -> bool {
    keys.signing_keys()
        .iter()
        .any(|key| key.id.to_string() == kid && signing_admitted(key, now, keys))
}

/// The `kid` of every key [`admitted_for_verification`] at an instant.
///
/// What a published key set may carry: a key the signer still holds but whose record is
/// revoked, or whose window has closed, is not published, whatever the signer's own
/// rotation window says.
#[must_use]
pub fn verification_kids(keys: &impl SigningKeyReads, now: i64) -> Vec<String> {
    keys.signing_keys()
        .iter()
        .filter(|key| admitted_for_verification(key, now, keys))
        .map(|key| key.id.to_string())
        .collect()
}

/// Every `Revoked` record, as the signer's revocation list: its identity, which is the `kid`
/// it was held under, and its thumbprint.
///
/// What [`RealSigner::new_with_revocations`] is rehydrated from, so that neither the `kid`
/// nor the material of a key this deployment revoked is installed again.
#[must_use]
pub fn revocations(keys: &impl SigningKeyReads) -> Vec<RevokedKey> {
    keys.signing_keys()
        .into_iter()
        .filter(|key| key.state == SigningKeyState::Revoked)
        .map(|key| RevokedKey {
            kid: key.id.to_string(),
            thumbprint: key.thumbprint,
        })
        .collect()
}

/// The key-provider seam: private key material, by the reference a record holds.
///
/// The deployment holds the material — a mounted file, a key-management service — and the
/// contract holds a handle to it. Nothing here keeps the material: it is loaded when the
/// signer needs it, under the `kid` and the algorithm the record states, and the signer is
/// the one holder of what was loaded.
pub trait KeyProvider {
    /// The material `reference` resolves to, loaded to sign as `kid` under `algorithm`, or
    /// `None` when the deployment cannot resolve it.
    fn load(
        &self,
        reference: &KeyReference,
        kid: &str,
        algorithm: &SigningAlgorithm,
    ) -> Option<SigningKeyMaterial>;
}

/// Why [`RecordedSigner::sync`] could not bring the signer in line with the records.
///
/// Each names the key by its identity and nothing else: no reference to a file, no byte of
/// material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerRefused {
    /// The key provider resolves the record's reference to nothing.
    MaterialUnavailable(SigningKeyId),
    /// The material the reference resolves to now is not the material it was registered
    /// with: its thumbprint differs from the record's.
    MaterialChanged(SigningKeyId),
    /// The signer refused the key.
    Signing(SigningError),
}

impl core::fmt::Display for SignerRefused {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MaterialUnavailable(id) => {
                write!(
                    formatter,
                    "the signing key {id} resolves to no key material"
                )
            }
            Self::MaterialChanged(id) => write!(
                formatter,
                "the signing key {id} resolves to key material other than the material it was \
                 registered with"
            ),
            Self::Signing(error) => write!(formatter, "the signer refused a key: {error}"),
        }
    }
}

impl std::error::Error for SignerRefused {}

/// A [`RealSigner`] kept in step with the `mandate.credential.SigningKey` records.
///
/// The records decide; the signer follows. [`RecordedSigner::sync`] is called after every
/// change to the fold and does three things, in this order:
///
/// 1. every `Revoked` record the signer still holds is revoked in the signer, so a revoked
///    key stops signing and leaves [`CredentialSigner::published_keys`] at once;
/// 2. the signer is built, the first time a key is [`issuing_key`], over [`revocations`];
/// 3. when the issuing key is not the signer's active one, the signer rotates onto it, which
///    keeps the previous key published for the overlap.
///
/// What it does not do is decide issuance: [`crate::issue::issue_self_contained_credential`]
/// asks the records itself, so a signer that has not yet been synced signs nothing the
/// records do not admit.
pub struct RecordedSigner<C> {
    allowed: AllowedAlgorithms,
    clock: C,
    ttl_seconds: u64,
    overlap_seconds: u64,
    signer: Option<RealSigner<C>>,
}

impl<C: Clock + Clone> RecordedSigner<C> {
    /// A signer holding no key yet, configured as every key it will hold is.
    ///
    /// # Errors
    ///
    /// [`SigningError::OverlapShorterThanTtl`] when a key rotated out would leave the
    /// published set before a credential it signed expires — refused here rather than at
    /// the first key, so a configuration nothing can honour is refused at startup.
    pub fn new(
        allowed: AllowedAlgorithms,
        clock: C,
        ttl_seconds: u64,
        overlap_seconds: u64,
    ) -> Result<Self, SigningError> {
        if overlap_seconds < ttl_seconds {
            return Err(SigningError::OverlapShorterThanTtl {
                ttl_seconds,
                overlap_seconds,
            });
        }
        Ok(Self {
            allowed,
            clock,
            ttl_seconds,
            overlap_seconds,
            signer: None,
        })
    }

    /// The signer, once a key has been installed.
    #[must_use]
    pub const fn signer(&self) -> Option<&RealSigner<C>> {
        self.signer.as_ref()
    }

    /// Whether this signer can sign at an instant: it holds an active key, and that key's
    /// record is [`signing_admitted`] then.
    #[must_use]
    pub fn ready(&self, keys: &impl SigningKeyReads, now: i64) -> bool {
        self.signer
            .as_ref()
            .and_then(RealSigner::active_kid)
            .is_some_and(|kid| kid_signing_admitted(kid, now, keys))
    }

    /// The key set a verifier is published at an instant, one JSON object per key.
    ///
    /// [`CredentialSigner::published_keys`] — the active key and the previous keys still in
    /// their overlap, public parts only — narrowed to the keys whose records are
    /// [`admitted_for_verification`] now, through [`verification_kids`]. So a key the records
    /// revoked leaves the set on the next read whatever the signer still holds, and a key the
    /// records still admit is published only while the signer holds its material. Rendered as
    /// JSON because the signer's own set type is outside this crate's dependency ceiling.
    #[must_use]
    pub fn published_keys(&self, keys: &impl SigningKeyReads, now: i64) -> Vec<serde_json::Value> {
        let Some(signer) = self.signer.as_ref() else {
            return Vec::new();
        };
        let admitted = verification_kids(keys, now);
        signer
            .published_keys()
            .keys
            .iter()
            .filter(|key| {
                key.common
                    .key_id
                    .as_ref()
                    .is_some_and(|kid| admitted.contains(kid))
            })
            .filter_map(|key| serde_json::to_value(key).ok())
            .collect()
    }

    /// Bring the signer in line with the records at an instant.
    ///
    /// # Errors
    ///
    /// [`SignerRefused`] when the issuing key's material cannot be loaded, is not the
    /// material its record was registered with, or is refused by the signer. A revocation is
    /// applied before any of these can be reached, so a refusal never leaves a revoked key
    /// signing.
    pub fn sync(
        &mut self,
        keys: &impl SigningKeyReads,
        provider: &(impl KeyProvider + ?Sized),
        now: i64,
    ) -> Result<(), SignerRefused> {
        if let Some(signer) = self.signer.as_mut() {
            for revoked in revocations(keys) {
                if signer.revoked().iter().any(|held| held.kid == revoked.kid) {
                    continue;
                }
                // A key the signer never held has nothing to drop; its record is what keeps
                // it out, because [`issuing_key`] never names a revoked key.
                match signer.revoke(&revoked.kid) {
                    Ok(()) | Err(SigningError::UnknownKid(_) | SigningError::RevokedKey(_)) => {}
                    Err(other) => return Err(SignerRefused::Signing(other)),
                }
            }
        }
        let Some(issuing) = issuing_key(keys, now) else {
            return Ok(());
        };
        let kid = issuing.id.to_string();
        if self
            .signer
            .as_ref()
            .and_then(RealSigner::active_kid)
            .is_some_and(|active| active == kid)
        {
            return Ok(());
        }
        let material = provider
            .load(&issuing.key_reference, &kid, &issuing.algorithm)
            .ok_or(SignerRefused::MaterialUnavailable(issuing.id))?;
        if material.thumbprint() != issuing.thumbprint {
            return Err(SignerRefused::MaterialChanged(issuing.id));
        }
        // A rotation keeps the previous key published for the overlap, and is how a newer key
        // takes over. It cannot install a key the signer still holds in its window — which is
        // what the issuing key is after a newer one was revoked — so that case, like the first
        // key, builds the signer afresh over the records. Keys rotated out before then leave
        // the published set early; a revocation is the emergency path, and the records still
        // refuse nothing they admitted.
        let held_in_window = self.signer.as_ref().is_some_and(|signer| {
            signer
                .published_keys()
                .keys
                .iter()
                .any(|key| key.common.key_id.as_deref() == Some(kid.as_str()))
        });
        match self.signer.as_mut() {
            Some(signer) if !held_in_window => {
                signer.rotate(material).map_err(SignerRefused::Signing)
            }
            _ => {
                self.signer = Some(
                    RealSigner::new_with_revocations(
                        self.allowed.clone(),
                        material,
                        self.clock.clone(),
                        self.ttl_seconds,
                        self.overlap_seconds,
                        revocations(keys),
                    )
                    .map_err(SignerRefused::Signing)?,
                );
                Ok(())
            }
        }
    }
}

impl<C> core::fmt::Debug for RecordedSigner<C> {
    /// Delegates to [`RealSigner`]'s own rendering, which names keys and never renders them.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RecordedSigner")
            .field("signer", &self.signer)
            .finish_non_exhaustive()
    }
}

/// The `kid` of [`issuing_key`] at a declared instant, or `None` when no key may sign then
/// or the instant names none.
///
/// For a composition that holds a request's instant as a timestamp and a signer that is not a
/// [`RecordedSigner`] — a double that signs under whichever `kid` it is told.
#[must_use]
pub fn issuing_kid(keys: &impl SigningKeyReads, at: &mandate_types::Timestamp) -> Option<String> {
    issuing_key(keys, instant::seconds_of(at)?).map(|key| key.id.to_string())
}
