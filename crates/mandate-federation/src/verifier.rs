//! Step 3 of the resolution order: the port, and the double that stands in for it.
//!
//! No cryptography. `dependency-boundaries.json` admits no external crate here and
//! `Cargo.lock` holds no JOSE library, so signature verification, OIDC discovery, JWKS
//! caching and key rollover belong to `story:signing-and-verification`, which attaches
//! at [`crate::FederationVerifier`].

use std::collections::BTreeMap;

use mandate_types::{
    ClientId, CredentialProof, DenialReason, ExternalSubject, Issuer, SigningAlgorithm,
};

use crate::record::FederationConnection;
use crate::{DenialClause, Denied, FederationVerifier};

/// What a verifier validated, and what it refused to treat as validated.
///
/// The two claim sets are separate on purpose. Tenant resolution reads
/// [`VerifiedProof::verified_claim`] and nothing else; an organization selector or an
/// email domain that arrived unvalidated is reachable only through
/// [`VerifiedProof::unverified_hint`], which no resolution path calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProof {
    issuer: Issuer,
    subject: ExternalSubject,
    audience: ClientId,
    verified_claims: BTreeMap<String, String>,
    unverified_hints: BTreeMap<String, String>,
    claim_types: BTreeMap<String, ClaimType>,
}

/// The JSON type a claim arrived as, when it is not the string a tenant rule compares
/// against.
///
/// A bare name, so a refusal naming it stays log-safe: the value is never carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClaimType {
    /// A JSON number.
    Number,
    /// A JSON array, whatever its members.
    Array,
    /// A JSON object.
    Object,
    /// `true` or `false`.
    Boolean,
    /// `null`.
    Null,
}

impl VerifiedProof {
    /// A proof validated as carrying this issuer, subject and audience.
    #[must_use]
    pub fn new(issuer: Issuer, subject: ExternalSubject, audience: ClientId) -> Self {
        Self {
            issuer,
            subject,
            audience,
            verified_claims: BTreeMap::new(),
            unverified_hints: BTreeMap::new(),
            claim_types: BTreeMap::new(),
        }
    }

    /// Record that the claim `name` arrived as a non-string JSON value of type `kind`.
    ///
    /// The type alone, never the value. Nothing resolves on it; it lets a tenant refusal
    /// say why the rule's claim could not match.
    #[must_use]
    pub fn with_claim_type(mut self, name: &str, kind: ClaimType) -> Self {
        self.claim_types.insert(name.to_owned(), kind);
        self
    }

    /// The non-string JSON type the claim `name` arrived as, if one was recorded.
    #[must_use]
    pub fn claim_type(&self, name: &str) -> Option<ClaimType> {
        self.claim_types.get(name).copied()
    }

    /// Record a claim the verifier validated.
    #[must_use]
    pub fn with_verified_claim(mut self, name: &str, value: &str) -> Self {
        self.verified_claims
            .insert(name.to_owned(), value.to_owned());
        self
    }

    /// Record a value that arrived with the request and was *not* validated.
    #[must_use]
    pub fn with_unverified_hint(mut self, name: &str, value: &str) -> Self {
        self.unverified_hints
            .insert(name.to_owned(), value.to_owned());
        self
    }

    /// The validated issuer.
    #[must_use]
    pub fn issuer(&self) -> &Issuer {
        &self.issuer
    }

    /// The validated subject.
    #[must_use]
    pub fn subject(&self) -> &ExternalSubject {
        &self.subject
    }

    /// The validated audience.
    #[must_use]
    pub fn audience(&self) -> &ClientId {
        &self.audience
    }

    /// A claim the verifier validated.
    #[must_use]
    pub fn verified_claim(&self, name: &str) -> Option<&str> {
        self.verified_claims.get(name).map(String::as_str)
    }

    /// A value that arrived unvalidated. No resolution path reads this.
    #[must_use]
    pub fn unverified_hint(&self, name: &str) -> Option<&str> {
        self.unverified_hints.get(name).map(String::as_str)
    }
}

/// A [`FederationVerifier`] that admits or refuses by construction.
///
/// A fixture, never a shipped implementation: it performs no cryptography and decides
/// nothing about the proof it is handed. `story:signing-and-verification` supplies the
/// implementation; the move of this double to `crates/mandate-testkit` is a later story
/// the coordinator files.
///
/// The allowlist is a constructor argument, which is the shape
/// `decision-blocker:algorithm-policy` decided: a deployment-configured allowlist
/// validated at startup, with an empty set rejected. The admitted names are withheld
/// pending an approving authority, so this type names none and neither does any test of
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstructedVerifier {
    admitted_algorithms: Vec<SigningAlgorithm>,
    outcome: Result<VerifiedProof, Denied>,
}

impl ConstructedVerifier {
    /// A verifier that admits every proof, returning `proof` as what it validated.
    ///
    /// # Errors
    ///
    /// Returns [`Denied`] when `admitted_algorithms` is empty.
    pub fn admitting(
        admitted_algorithms: &[SigningAlgorithm],
        proof: VerifiedProof,
    ) -> Result<Self, Denied> {
        Ok(Self {
            admitted_algorithms: admitted(admitted_algorithms)?,
            outcome: Ok(proof),
        })
    }

    /// A verifier that refuses every proof.
    ///
    /// # Errors
    ///
    /// Returns [`Denied`] when `admitted_algorithms` is empty.
    pub fn refusing(admitted_algorithms: &[SigningAlgorithm]) -> Result<Self, Denied> {
        Ok(Self {
            admitted_algorithms: admitted(admitted_algorithms)?,
            outcome: Err(Denied::new(
                DenialReason::InvalidCredential,
                DenialClause::ProofInvalid,
            )),
        })
    }

    /// The configured allowlist.
    #[must_use]
    pub fn admitted_algorithms(&self) -> &[SigningAlgorithm] {
        &self.admitted_algorithms
    }
}

impl FederationVerifier for ConstructedVerifier {
    fn verify(
        &self,
        _connection: &FederationConnection,
        _proof: &CredentialProof,
    ) -> Result<VerifiedProof, Denied> {
        // By construction, and by construction only: this double performs no
        // cryptography and reads neither argument. The proof it returns is the one it
        // was built with, so a test states what was validated rather than forging it.
        self.outcome.clone()
    }
}

/// `decision-blocker:algorithm-policy`: an empty allowlist is rejected. Which names are
/// admitted is withheld pending an approving authority, so nothing here inspects a name.
fn admitted(admitted_algorithms: &[SigningAlgorithm]) -> Result<Vec<SigningAlgorithm>, Denied> {
    if admitted_algorithms.is_empty() {
        return Err(Denied::new(
            DenialReason::InvalidCredential,
            DenialClause::AlgorithmPolicy,
        ));
    }
    Ok(admitted_algorithms.to_vec())
}
