//! The `mandate.workload.WorkloadIdentity` projection, its revocation and the fold that writes it.
//!
//! `systems/mandate/domains/workload.yaml` declares one entity and two commands.
//! `RevokeWorkloadIdentity` moves a `WorkloadIdentity` from `Recorded` to `Revoked` along
//! `revoke` and emits `mandate.workload.WorkloadIdentityRevoked`, `{context, id}`; every
//! refusal carries `mandate.workload.Denied`. `docs/architecture/ownership.md` gives
//! `mandate.workload` records to this crate.
//!
//! `AuthenticateWorkload` reads agent and execution records this crate does not hold, so
//! `mandate-authz` decides it. Its event, `mandate.workload.WorkloadAuthenticated`, is
//! [`WorkloadEvent::Authenticated`] here beside the revocation and folds into no record; the
//! decider resolves a verified binding through [`WorkloadIdentityRead::bindings`].
//!
//! # The record is read through a port, and no command writes one
//!
//! No command's accepted outcome in `systems/mandate` creates a `WorkloadIdentity`, so the
//! record has no declared writer (`story:declared-writers`). The decider therefore reads it
//! through [`WorkloadIdentityRead`] rather than off a fold of its own creation events, and
//! [`WorkloadIdentities`] — the projection — starts from the records it is handed and folds
//! the revocations over them. When a creating command is declared, its event joins
//! [`WorkloadEvent`] and the starting records become part of the log.
//!
//! # Deciding, applying and folding
//!
//! The same split as `crate::tenancy` and `crate::graph`:
//!
//! * [`decide_revoke_workload_identity`] reads the port and returns the declared event or
//!   [`Denied`]. It writes nothing.
//! * [`WorkloadIdentities::apply`] writes an event. It cannot refuse and re-checks nothing.
//! * [`WorkloadIdentities::fold`] applies a whole log to the starting records.
//!
//! # What the refusal does and does not hide
//!
//! `workload.yaml` gives the command one `denied` clause — "Caller lacks workload-identity
//! administration authority, the identity is outside the verified organization, or
//! revocation cannot durably stop the exchange of workload credentials presented under the
//! binding" — and one error carrying one [`mandate_types::DenialReason`]. An identity no
//! record carries, one recorded in another organization and one already revoked refuse with
//! the same value, so a caller cannot tell "no such identity" from "not yours" by reading a
//! refusal. That is the repository's non-disclosure rule, and it is why an unknown identity
//! does not take the declared `wrong-state` branch: answering `wrong-state` for an unknown
//! identity and `denied` for a foreign one would disclose which identities exist elsewhere
//! (`story:unknown-instance-non-disclosing`).
//!
//! # Every denial clause this fold does not realize
//!
//! Two of the three clauses, each quoted verbatim from the declared cause and grouped by what
//! owes it; `contracts/obligations/model.json` carries the same two as `blocked_on` rows.
//!
//! ## Owed to `decision-blocker:guards` — one
//!
//! Whether the caller holds the authority is `mandate-authz`'s, as for every administration
//! clause of `crate::tenancy`.
//!
//! * `mandate.workload.RevokeWorkloadIdentity` — "Caller lacks workload-identity
//!   administration authority"
//!
//! ## Owed to `story:agent-security` — one
//!
//! Stopping the exchange needs the exchange path that reads this record, which is workload
//! authentication and stays on that story.
//!
//! * `mandate.workload.RevokeWorkloadIdentity` — "revocation cannot durably stop the exchange
//!   of workload credentials presented under the binding"

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use mandate_types::{
    DenialReason, ExecutionId, ExternalSubject, OrganizationId, PrincipalId, Timestamp,
    TrustDomain, VerifiedContext, WorkloadIdentityId,
};

/// `mandate.workload.Denied`: the decision refused, and nothing was written.
///
/// Fail closed: no credential, authority or lifecycle mutation follows a refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Denied {
    /// The declared reason.
    pub reason: DenialReason,
}

impl Denied {
    /// The one refusal this domain produces.
    const fn refusal() -> Self {
        Self {
            reason: DenialReason::Denied,
        }
    }
}

/// `mandate.workload.WorkloadIdentity.State`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkloadIdentityState {
    /// The initial state: the binding is admitted.
    Recorded,
    /// The terminal state: the binding stops being admitted and the record is kept.
    Revoked,
}

/// `mandate.workload.WorkloadIdentity`: a trust domain and external subject bound to one
/// principal of one organization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadIdentity {
    /// The identity of this binding.
    pub id: WorkloadIdentityId,
    /// The organization the binding belongs to.
    pub organization_id: OrganizationId,
    /// The principal the binding resolves to.
    pub principal_id: PrincipalId,
    /// The trust domain the workload credential is issued under.
    pub trust_domain: TrustDomain,
    /// The subject the workload credential names.
    pub external_subject: ExternalSubject,
    /// The recorded state.
    pub state: WorkloadIdentityState,
}

/// The read port the revocation decides against.
pub trait WorkloadIdentityRead {
    /// The kept record, in whatever state and organization it holds, or `None` when no
    /// record carries the identity.
    ///
    /// A record-level read: deciding whether the caller may see the record is the
    /// decider's, never the reader's.
    fn workload_identity(&self, id: &WorkloadIdentityId) -> Option<WorkloadIdentity>;

    /// Every kept record carrying this trust domain and external subject, in every state and
    /// organization, in identity order; empty when none does.
    ///
    /// A record-level read, as [`Self::workload_identity`] is: which of them, if any, a
    /// verified workload proof resolves to is the decider's (`mandate-authz`'s
    /// `AuthenticateWorkload`), never the reader's.
    fn bindings(
        &self,
        trust_domain: &TrustDomain,
        external_subject: &ExternalSubject,
    ) -> Vec<WorkloadIdentity>;
}

/// The declared `mandate.workload` event payloads.
///
/// `#[serde(untagged)]`, so a variant serializes as the bare payload object, as
/// [`crate::tenancy::TenancyEvent`] and [`crate::graph::ResourceEvent`] do; `Serialize`
/// only, for the reason `TenancyEvent` gives.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum WorkloadEvent {
    /// `mandate.workload.WorkloadIdentityRevoked`.
    IdentityRevoked {
        /// The caller's verified context.
        context: VerifiedContext,
        /// The binding that stops being admitted.
        id: WorkloadIdentityId,
    },
    /// `mandate.workload.WorkloadAuthenticated`: a workload runtime and the application
    /// agent it runs, each authenticated on its own.
    ///
    /// Decided by `mandate-authz` (`workload::decide_authenticate_workload`), which reads the
    /// agent records this crate does not hold. It folds into no record:
    /// [`WorkloadIdentities::apply`] leaves the projection as it was.
    Authenticated {
        /// The workload identity the verified proof resolved to.
        workload: WorkloadIdentityId,
        /// The runtime principal that workload identity names.
        runtime: PrincipalId,
        /// The application agent the caller named; never derived from the proof.
        agent: PrincipalId,
        /// The organization of the workload identity and of the agent.
        organization: OrganizationId,
        /// The execution the caller named, when it named one.
        ///
        /// Absent rather than null, for the reason `crate::graph::ResourceEvent`'s `parent`
        /// gives.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        execution: Option<ExecutionId>,
        /// The decision instant.
        authenticated_at: Timestamp,
    },
}

impl WorkloadEvent {
    /// The qualified ESS name of the payload this event is.
    ///
    /// Exhaustive and without a wildcard arm, so a variant added without a name here does not
    /// compile.
    #[must_use]
    pub fn ess_name(&self) -> &'static str {
        match self {
            Self::IdentityRevoked { .. } => "mandate.workload.WorkloadIdentityRevoked",
            Self::Authenticated { .. } => "mandate.workload.WorkloadAuthenticated",
        }
    }
}

/// The decide half of `mandate.workload.RevokeWorkloadIdentity`: the declared event, or the
/// refusal. Nothing is written; a command path appends the returned event and applies it.
///
/// # Errors
///
/// Refuses, with one reason, an identity no record carries, one recorded in an organization
/// other than the verified one, and one already revoked.
pub fn decide_revoke_workload_identity(
    read: &dyn WorkloadIdentityRead,
    context: &VerifiedContext,
    id: WorkloadIdentityId,
) -> Result<WorkloadEvent, Denied> {
    let admitted = read.workload_identity(&id).is_some_and(|record| {
        record.organization_id == context.organization
            && record.state == WorkloadIdentityState::Recorded
    });
    if !admitted {
        return Err(Denied::refusal());
    }
    Ok(WorkloadEvent::IdentityRevoked {
        context: context.clone(),
        id,
    })
}

/// The `mandate.workload.WorkloadIdentity` projection: the starting records with every
/// revocation of the log applied.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkloadIdentities {
    records: BTreeMap<WorkloadIdentityId, WorkloadIdentity>,
}

impl WorkloadIdentities {
    /// A projection holding these records and no event applied.
    ///
    /// The records stand in for the creation no command declares; see the module
    /// documentation. A later record with an identity already held does not replace it.
    #[must_use]
    pub fn holding(records: impl IntoIterator<Item = WorkloadIdentity>) -> Self {
        let mut held = BTreeMap::new();
        for record in records {
            held.entry(record.id).or_insert(record);
        }
        Self { records: held }
    }

    /// The projection every event of a log has been applied to, from these starting records.
    #[must_use]
    pub fn fold(
        records: impl IntoIterator<Item = WorkloadIdentity>,
        events: &[WorkloadEvent],
    ) -> Self {
        let mut fold = Self::holding(records);
        for event in events {
            fold.apply(event);
        }
        fold
    }

    /// Write one declared event into the projection.
    ///
    /// **Total, and re-checks nothing**, exactly as `crate::tenancy::Tenancy::apply` is: a
    /// fold that refuses is not a rebuild. An event naming no held record changes nothing.
    pub fn apply(&mut self, event: &WorkloadEvent) {
        match event {
            WorkloadEvent::IdentityRevoked { id, .. } => {
                if let Some(record) = self.records.get_mut(id) {
                    record.state = WorkloadIdentityState::Revoked;
                }
            }
            // `workload.yaml`: nothing is created or moved, and the event folds into no
            // record.
            WorkloadEvent::Authenticated { .. } => {}
        }
    }

    /// How many records the projection holds, in every state and organization.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the projection holds no record at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl WorkloadIdentityRead for WorkloadIdentities {
    fn workload_identity(&self, id: &WorkloadIdentityId) -> Option<WorkloadIdentity> {
        self.records.get(id).cloned()
    }

    fn bindings(
        &self,
        trust_domain: &TrustDomain,
        external_subject: &ExternalSubject,
    ) -> Vec<WorkloadIdentity> {
        self.records
            .values()
            .filter(|record| {
                record.trust_domain == *trust_domain && record.external_subject == *external_subject
            })
            .cloned()
            .collect()
    }
}

impl mandate_types::PersistedValue for WorkloadIdentityState {}

/// The credential boundary over the projection, asserted rather than described, as
/// `crate::graph` does for `Resource`. Destructured without `..`, so a field added and not
/// named here does not compile.
const _: () = {
    fn persistable<T: mandate_types::PersistedValue + ?Sized>(_: &T) {}

    #[allow(dead_code)]
    fn every_projection_field_is_persistable(identity: &WorkloadIdentity) {
        let WorkloadIdentity {
            id,
            organization_id,
            principal_id,
            trust_domain,
            external_subject,
            state,
        } = identity;
        persistable(id);
        persistable(organization_id);
        persistable(principal_id);
        persistable(trust_domain);
        persistable(external_subject);
        persistable(state);
    }
};
