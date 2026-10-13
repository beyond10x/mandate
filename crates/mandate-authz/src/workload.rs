//! `mandate.workload.AuthenticateWorkload`: a workload runtime and the application agent it
//! runs, each authenticated on its own.
//!
//! `systems/mandate/domains/workload.yaml` declares the command: a workload proof, the
//! application agent and an optional execution. Accepted, it emits
//! `mandate.workload.WorkloadAuthenticated` — the workload identity, the runtime principal it
//! names, the agent, the organization and the execution — and creates or moves nothing; the
//! event is `mandate_model::workload::WorkloadEvent::Authenticated` and folds into no record.
//! `mandate-model` holds the workload records and the event; the decision is here because it
//! reads the agent and execution records only this crate folds ([`AgentAuthorityRead`]).
//!
//! # The two identities
//!
//! The workload proof is verified by the trust domain that issued it, through
//! [`TrustDomainVerifier`], which answers the verified `(trust domain, external subject)` and
//! the proof's expiry. That pair resolves through
//! [`mandate_model::workload::WorkloadIdentityRead::bindings`] to exactly one `Recorded`
//! workload identity, which names the runtime principal. A pair no record carries, one whose
//! only records are revoked, and one two recorded identities carry are refused; a revoked
//! record beside one recorded identity does not block it.
//!
//! The application agent is the one the caller names, never derived from the proof: an
//! `Agent` record of the workload identity's organization, not retired, whose principal is
//! not disabled. The standing is read through [`AgentAuthorityRead::standing`] and refused
//! only when `Disabled`, exactly as the shared record checks `crate::agent` decides `Check`
//! and the token exchange by read it. An agent recorded in another organization refuses like
//! one nobody recorded. When an execution is named it is recorded, not completed, before its
//! `expires_at`, of that organization and held by that agent.
//!
//! # One refusal
//!
//! Every refusal is one `mandate.workload.Denied` with one reason ([`Denied::contract`]), so a
//! caller learns only that the pair is not admitted. [`Denied::clause`] says internally which
//! declared condition refused it; a read that could not be answered refuses as
//! [`DenialReason::Unavailable`].
//!
//! # Residue
//!
//! No real trust-domain verifier ships in this module. A SPIFFE JWT-SVID or X.509-SVID
//! verifier — trust bundle retrieval, signature and audience checks, expiry from the SVID —
//! is the [`TrustDomainVerifier`] a deployment supplies, and stays on
//! `story:agent-security`. [`ConfiguredTrustDomains`] is the double a caller under test
//! arranges; the declared clauses "The workload proof is malformed" and "unverified by its
//! trust domain" are therefore decided by no shipped path yet.

use mandate_model::workload::{
    Denied as Refusal, WorkloadEvent, WorkloadIdentityRead, WorkloadIdentityState,
};
use mandate_types::{
    CredentialProof, DenialReason, ExecutionId, ExternalSubject, OrganizationId, PrincipalId,
    Timestamp, TrustDomain, WorkloadIdentityId,
};

use crate::agent::{AgentAuthorityRead, PrincipalStanding, Unavailable, instant};
use crate::delegation::{AgentState, ExecutionState};

/// What a trust domain established about one workload proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedWorkload {
    /// The trust domain that issued and verified the proof.
    pub trust_domain: TrustDomain,
    /// The subject the proof names inside that trust domain.
    pub external_subject: ExternalSubject,
    /// When the proof stops being valid.
    pub expires_at: Timestamp,
}

/// Why a trust domain did not verify a proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofRefused {
    /// The proof is not one the verifier can read.
    Malformed,
    /// The proof is readable and no trust domain the verifier holds verifies it.
    Unverified,
    /// The verifier could not answer.
    Unavailable,
}

/// The trust-domain verification port: the proof and the decision instant in, the verified
/// binding and the proof's expiry out, or a refusal.
///
/// The decider compares the expiry against the instant itself; a verifier may refuse an
/// expired proof earlier, as [`ProofRefused::Unverified`].
pub trait TrustDomainVerifier {
    /// Verify `proof` at `at`.
    ///
    /// # Errors
    ///
    /// [`ProofRefused`] when the proof is not verified.
    fn verify(
        &self,
        proof: &CredentialProof,
        at: &Timestamp,
    ) -> Result<VerifiedWorkload, ProofRefused>;
}

/// A [`TrustDomainVerifier`] answered from a list: each configured proof verifies as its
/// configured binding, an empty proof is malformed, and every other proof is unverified.
///
/// The double a caller under test arranges; see the module documentation for the verifier a
/// deployment supplies.
#[derive(Debug, Clone, Default)]
pub struct ConfiguredTrustDomains {
    proofs: Vec<(CredentialProof, VerifiedWorkload)>,
}

impl ConfiguredTrustDomains {
    /// A verifier that verifies nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify `proof` as `verified`.
    #[must_use]
    pub fn with_proof(mut self, proof: CredentialProof, verified: VerifiedWorkload) -> Self {
        self.proofs.push((proof, verified));
        self
    }
}

impl TrustDomainVerifier for ConfiguredTrustDomains {
    fn verify(
        &self,
        proof: &CredentialProof,
        _at: &Timestamp,
    ) -> Result<VerifiedWorkload, ProofRefused> {
        if proof.expose_bytes().is_empty() {
            return Err(ProofRefused::Malformed);
        }
        self.proofs
            .iter()
            .find(|(configured, _)| configured == proof)
            .map(|(_, verified)| verified.clone())
            .ok_or(ProofRefused::Unverified)
    }
}

/// The declared input of `mandate.workload.AuthenticateWorkload`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticateWorkload {
    /// The workload proof, verified by its trust domain.
    pub workload_proof: CredentialProof,
    /// The application agent, authenticated on its own.
    pub agent: PrincipalId,
    /// The execution the pair acts in, when it names one.
    pub execution: Option<ExecutionId>,
}

/// The accepted outcome: the declared event and the declared response.
#[derive(Debug, Clone, PartialEq)]
pub struct Authenticated {
    /// `mandate.workload.WorkloadAuthenticated`.
    pub event: WorkloadEvent,
    /// The response's `workload`.
    pub workload: WorkloadIdentityId,
    /// The response's `runtime`.
    pub runtime: PrincipalId,
    /// The response's `organization`.
    pub organization: OrganizationId,
}

/// Which declared condition a refusal is an instance of.
///
/// A crate-local discriminator, not a contract field: the contract's error payload is
/// [`DenialReason`] alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum AuthenticationClause {
    /// "The workload proof is malformed", or the decision instant names no instant.
    ProofMalformed,
    /// "unverified by its trust domain".
    ProofUnverified,
    /// The proof's expiry is not after the decision instant.
    ProofExpired,
    /// "it resolves to no workload identity".
    WorkloadUnresolved,
    /// "a revoked one": every record carrying the binding is revoked.
    WorkloadRevoked,
    /// Two recorded workload identities carry the binding.
    WorkloadAmbiguous,
    /// "one in another organization than the agent".
    OrganizationMismatch,
    /// "the agent is unrecorded".
    AgentUnrecorded,
    /// The agent is retired.
    AgentRetired,
    /// "its principal disabled".
    AgentPrincipalDisabled,
    /// "a named execution is unrecorded".
    ExecutionUnrecorded,
    /// The named execution is completed.
    ExecutionCompleted,
    /// The named execution's `expires_at` is not after the decision instant.
    ExecutionExpired,
    /// "bound to another agent or organization".
    ExecutionBoundElsewhere,
    /// A read could not be answered.
    Unavailable,
}

/// `mandate.workload.Denied`, with the condition it was refused on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Denied {
    /// The declared reason. This is what crosses the wire.
    pub reason: DenialReason,
    /// The condition refused on.
    pub clause: AuthenticationClause,
}

impl Denied {
    const fn on(clause: AuthenticationClause) -> Self {
        let reason = match clause {
            AuthenticationClause::Unavailable => DenialReason::Unavailable,
            _ => DenialReason::Denied,
        };
        Self { reason, clause }
    }

    /// The contract's error payload: the reason, and nothing about the clause.
    #[must_use]
    pub const fn contract(&self) -> Refusal {
        Refusal {
            reason: self.reason,
        }
    }
}

const fn unavailable(_: Unavailable) -> Denied {
    Denied::on(AuthenticationClause::Unavailable)
}

/// The decide half of `mandate.workload.AuthenticateWorkload`, at the instant `at`.
///
/// Reads the verifier, the workload records and the agent records, and writes nothing: the
/// returned event folds into no record.
///
/// # Errors
///
/// [`Denied`], on the first condition of the declared refusal that holds, in the order the
/// contract states them: the proof, its resolution, the agent, the execution.
pub fn decide_authenticate_workload<V, W, R>(
    verifier: &V,
    workloads: &W,
    records: &R,
    input: &AuthenticateWorkload,
    at: &Timestamp,
) -> Result<Authenticated, Denied>
where
    V: TrustDomainVerifier + ?Sized,
    W: WorkloadIdentityRead + ?Sized,
    R: AgentAuthorityRead + ?Sized,
{
    let now = instant::parse(at).ok_or(Denied::on(AuthenticationClause::ProofMalformed))?;

    // The proof, verified by its trust domain.
    let verified = verifier
        .verify(&input.workload_proof, at)
        .map_err(|refused| {
            Denied::on(match refused {
                ProofRefused::Malformed => AuthenticationClause::ProofMalformed,
                ProofRefused::Unverified => AuthenticationClause::ProofUnverified,
                ProofRefused::Unavailable => AuthenticationClause::Unavailable,
            })
        })?;
    let ends = instant::parse(&verified.expires_at)
        .ok_or(Denied::on(AuthenticationClause::ProofMalformed))?;
    if ends <= now {
        return Err(Denied::on(AuthenticationClause::ProofExpired));
    }

    // One recorded workload identity carries the verified binding.
    let bound = workloads.bindings(&verified.trust_domain, &verified.external_subject);
    let mut recorded = bound
        .iter()
        .filter(|record| record.state == WorkloadIdentityState::Recorded);
    let identity = match (recorded.next(), recorded.next()) {
        (Some(identity), None) => identity.clone(),
        (Some(_), Some(_)) => return Err(Denied::on(AuthenticationClause::WorkloadAmbiguous)),
        (None, _) if bound.is_empty() => {
            return Err(Denied::on(AuthenticationClause::WorkloadUnresolved));
        }
        (None, _) => return Err(Denied::on(AuthenticationClause::WorkloadRevoked)),
    };
    let organization = identity.organization_id;

    // The agent the caller names: never the runtime the proof resolved to.
    let agent = records
        .agent(&input.agent)
        .map_err(unavailable)?
        .ok_or(Denied::on(AuthenticationClause::AgentUnrecorded))?;
    if agent.organization_id != organization {
        return Err(Denied::on(AuthenticationClause::OrganizationMismatch));
    }
    if agent.state == AgentState::Retired {
        return Err(Denied::on(AuthenticationClause::AgentRetired));
    }
    if records.standing(&input.agent).map_err(unavailable)? == Some(PrincipalStanding::Disabled) {
        return Err(Denied::on(AuthenticationClause::AgentPrincipalDisabled));
    }

    // The execution, when one is named.
    if let Some(id) = &input.execution {
        let execution = records
            .execution(id)
            .map_err(unavailable)?
            .ok_or(Denied::on(AuthenticationClause::ExecutionUnrecorded))?;
        if execution.organization_id != organization || execution.agent_id != input.agent {
            return Err(Denied::on(AuthenticationClause::ExecutionBoundElsewhere));
        }
        if execution.state == ExecutionState::Completed {
            return Err(Denied::on(AuthenticationClause::ExecutionCompleted));
        }
        let expires = instant::parse(&execution.expires_at)
            .ok_or(Denied::on(AuthenticationClause::ExecutionExpired))?;
        if expires <= now {
            return Err(Denied::on(AuthenticationClause::ExecutionExpired));
        }
    }

    Ok(Authenticated {
        event: WorkloadEvent::Authenticated {
            workload: identity.id,
            runtime: identity.principal_id,
            agent: input.agent,
            organization,
            execution: input.execution,
            authenticated_at: at.clone(),
        },
        workload: identity.id,
        runtime: identity.principal_id,
        organization,
    })
}
