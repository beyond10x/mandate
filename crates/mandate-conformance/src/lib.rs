//! The in-process ESS conformance target over the real Mandate handlers.
//!
//! [`MandateTarget`] is the `ess_conformance::ConformanceTarget` a suite is executed
//! against. Every scenario runs against the real handlers of `mandate-federation`,
//! `mandate-identity`, `mandate-model` and `mandate-authz`, and what this crate reports is
//! what those handlers did: the event through the emitting crate's own `Serialize`, the
//! response from the values the handler returned, the refusal with the declared reason and
//! the declared branch the crate says it is. Nothing here decides an outcome, and no
//! payload is assembled by hand — a target that manufactured an expectation would be
//! agreeing with the suite about itself, which is the one failure a conformance report
//! cannot show.
//!
//! # One fold per scenario
//!
//! §8 requires that observations from one scenario cannot satisfy another, and the cheapest
//! honest way to get it is a fresh [`Live`] per `begin_scenario`: an empty federation event
//! log and its projection, an empty `IdentityLog`, empty `Tenancy` and `Topology` folds, an
//! empty authorization-code log, and the doubles the ports have no adapter for. An accepted
//! command appends its event to the log and the projection is **refolded from the log**,
//! which is `docs/adr/0009-event-sourced-persistence.md`'s rule executed rather than
//! restated: a projection that drifted from its log would make every later step of the
//! scenario read a state no replay produces.
//!
//! # What varies, and where §37 puts it
//!
//! Nothing here reads a clock and nothing generates a uuid. The instant is
//! [`FIXED_INSTANT`], every identity the folds need is minted from a counter ([`Mint`]), and
//! the consistency token is the invocation number. Two runs of one suite are therefore
//! byte-identical, which `crates/mandate-conformance/tests/target.rs` decides, and a red
//! run is a red run a reader can reproduce.

pub mod commands;
pub mod establish;
pub mod external;
pub mod node;

use std::cell::RefCell;

use ess_conformance::target::{
    ConformanceTarget, EntitySetupRequest, EventObservationRequest, ExternalOutcomeControl,
    ImplementationIdentity, ObservedEvent, RedeliveryRequest, ScenarioContext,
    SemanticCommandRequest, SemanticCommandResult, SemanticViewRequest, SemanticViewResult,
    TargetError,
};
use ess_conformance::{AdmittedSuite, CountReport, CountRun, CountStatus, Runner};
use ess_primitives::consistency::ConsistencyToken;
use ess_primitives::ids::CorrelationId as EssCorrelationId;

use mandate_authz::decision::{FixedChallenge, SequentialDecisionIds};
use mandate_federation::record::{FederationEvent, Projection};
use mandate_federation::register_client::ConfiguredAdmission;
use mandate_federation::{RecordingSessionIssuer, SequentialAllocator};
use mandate_graph::double::GraphDouble;
use mandate_identity::IdentityLog;
use mandate_model::graph::{ResourceEvent, Topology};
use mandate_model::tenancy::{Tenancy, TenancyEvent};
use mandate_policy::double::PolicyDouble;
use mandate_sts::binding::RecordedSessions;
use mandate_sts::code::{CodeIssuance, CodeLifetime, RecordedClients};
use mandate_sts::issue::StaticSigner;
use mandate_sts::keys::SigningKeyAdministration;
use mandate_sts::store::{AuthorizationCodeEvent, InMemoryCodeLog};
use mandate_sts::{CountingSecrets, RequestContext as StsRequest, SequentialAllocator as StsIds};
use mandate_token::projection::CredentialEvent;
use mandate_token::signing_real::AllowedAlgorithms;
use mandate_types::{
    Audience, CredentialId, Duration, Issuer, MembershipContributionId, OrganizationId,
    OrganizationMembershipId, PrincipalId, SpaceId, TeamId, TeamMembershipId, Timestamp, Uuid,
};

use crate::external::{Armed, Ledger, ScenarioVerifier};

/// The instant every handler that needs one is served at.
///
/// A clock is an adapter concern (`mandate_federation::RequestContext`), and §37 puts every
/// source of variation outside the thing under test. One literal, so two runs decide the
/// same expiry.
pub const FIXED_INSTANT: &str = "2026-01-01T00:00:00Z";

/// The audience this target establishes every context for.
pub const AUDIENCE: &str = "mandate-conformance";

/// The correlation a seeded record carries where no request supplies one.
pub const CORRELATION: &str = "mandate-conformance";

/// The name this implementation is reported under.
pub const IMPLEMENTATION: &str = "mandate-conformance";

/// The issuer a self-contained credential names.
pub const ISSUER: &str = "https://mandate-conformance.invalid";

/// The key identifier the standing signer signs under.
pub const SIGNING_KID: &str = "mandate-conformance";

/// The lifetime the standing signer writes into every credential it signs.
pub const SIGNED_LIFETIME_SECONDS: u64 = 3600;

/// The one algorithm this target's allowlist admits.
///
/// `mandate_token::signing_real` admits two names and refuses every other and `none`; the
/// list is a deployment's and this target states one so that `RegisterSigningKey` is decided
/// against a policy rather than against nothing.
pub const ADMITTED_ALGORITHM: &str = "ES256";

/// The longest lifetime this target issues an authorization code for.
pub const CODE_LIFETIME: &str = "PT10M";

/// One scenario's execution context: the folds, the doubles and what was armed.
pub struct Live {
    /// Which scenario, for the injection ledger.
    pub scenario: String,
    /// The activity every observation of this scenario belongs to.
    pub correlation: EssCorrelationId,
    /// The federation event log; the projection is refolded from it.
    pub federation_log: Vec<FederationEvent>,
    /// The federation read model.
    pub federation: Projection,
    /// The identities `federation.yaml` binds from a response.
    pub federation_ids: SequentialAllocator,
    /// Step 9 of the resolution order.
    pub session_issuer: RecordingSessionIssuer,
    /// Client-administration authority, which no crate in the federation ceiling decides.
    pub admission: ConfiguredAdmission,
    /// The identity event log and the fold over it.
    pub identity: IdentityLog,
    /// The tenancy event log; the fold is rebuilt from it.
    pub tenancy_log: Vec<TenancyEvent>,
    /// The tenancy read model.
    pub tenancy: Tenancy,
    /// The resource event log; the topology is rebuilt from it.
    pub topology_log: Vec<ResourceEvent>,
    /// The resource read model.
    pub topology: Topology,
    /// The credential event log; the STS read model is rebuilt from it.
    pub credential_log: Vec<CredentialEvent>,
    /// The `mandate.credential` read model every STS handler decides against.
    pub credentials: mandate_token::projection::Projection,
    /// The identities `credential.yaml` binds from a response.
    pub sts_ids: StsIds,
    /// The transient secret a reference issuance returns once.
    pub secrets: CountingSecrets,
    /// The signer a self-contained issuance is signed under.
    pub signer: StaticSigner,
    /// The issuer a self-contained credential names.
    pub issuer: Issuer,
    /// The public half of a key reference.
    pub key_material: crate::external::ScenarioKeys,
    /// Signing-key administration under this deployment's algorithm allowlist.
    pub key_administration: SigningKeyAdministration,
    /// Authorization-code issuance under this deployment's lifetime ceiling.
    pub code_issuance: CodeIssuance,
    /// The OAuth clients the STS reads, which no command of this contract writes.
    pub oauth_clients: RecordedClients,
    /// The sessions the STS reads, which no command of this contract writes.
    pub sessions: RecordedSessions,
    /// The authorization-code log the STS appends to.
    pub codes: InMemoryCodeLog,
    /// The relationship graph.
    pub graph: GraphDouble,
    /// The policy evaluator and the role catalog.
    pub policy: PolicyDouble,
    /// The decision identities.
    pub decisions: SequentialDecisionIds,
    /// What an approval-required decision needs and no port answers.
    pub challenge: FixedChallenge,
    /// The identities the folds are handed, minted from counters.
    pub mint: Mint,
    /// The audience every established context carries.
    pub audience: Audience,
    /// The external outcome armed for the next invocation.
    pub armed: Armed,
    /// This run's ledger, carried per scenario and merged back at its end.
    pub ledger: Ledger,
    /// The invocations performed, which the consistency token is minted from.
    sequence: u64,
}

impl Live {
    /// A fresh execution context for one scenario.
    fn open(scenario: &ScenarioContext, ledger: Ledger) -> Self {
        Self {
            scenario: scenario.scenario.to_string(),
            correlation: scenario.correlation.clone(),
            federation_log: Vec::new(),
            federation: Projection::default(),
            federation_ids: SequentialAllocator::new(),
            session_issuer: RecordingSessionIssuer::new(),
            admission: ConfiguredAdmission::new(),
            identity: IdentityLog::new().with_as_of(Timestamp::new(FIXED_INSTANT)),
            tenancy_log: Vec::new(),
            tenancy: Tenancy::new(),
            topology_log: Vec::new(),
            topology: Topology::new(),
            credential_log: Vec::new(),
            credentials: mandate_token::projection::Projection::default(),
            sts_ids: StsIds::new(),
            secrets: CountingSecrets::new(),
            signer: StaticSigner::new(SIGNING_KID, SIGNED_LIFETIME_SECONDS),
            issuer: Issuer::new(ISSUER.to_owned()),
            key_material: crate::external::ScenarioKeys,
            key_administration: SigningKeyAdministration::new(
                AllowedAlgorithms::new(&[mandate_types::SigningAlgorithm::new(
                    ADMITTED_ALGORITHM.to_owned(),
                )])
                .expect("`ES256` is one of the two names mandate-token admits"),
            ),
            code_issuance: CodeIssuance::new(CodeLifetime::new(Duration::new(
                CODE_LIFETIME.to_owned(),
            ))),
            oauth_clients: RecordedClients::new(),
            sessions: RecordedSessions::new(),
            codes: InMemoryCodeLog::new(),
            graph: GraphDouble::default(),
            policy: PolicyDouble::new(),
            decisions: SequentialDecisionIds::new(),
            challenge: FixedChallenge {
                expires_at: Timestamp::new(FIXED_INSTANT),
                approver_policy: None,
            },
            mint: Mint::default(),
            audience: Audience::new(AUDIENCE.to_owned()),
            armed: Armed::default(),
            ledger,
            sequence: 0,
        }
    }

    /// The next invocation number, which the consistency token is minted from.
    pub const fn next_sequence(&mut self) -> u64 {
        self.sequence += 1;
        self.sequence
    }

    /// The token this invocation may be read no older than.
    #[must_use]
    pub fn token(&self) -> Option<ConsistencyToken> {
        commands::token(self.sequence)
    }

    /// Record what the reader substituted for one armed command did.
    ///
    /// Called after the handler returns, which is when the count exists. A command that
    /// refused before reading anything leaves its row at `armed-unreached` and
    /// `consulted: 0`, which is the fact the row is for.
    pub fn record_reads(&mut self, command: &str, consulted: u32, refused: u32) {
        let scenario = self.scenario.clone();
        self.ledger
            .consulted(&scenario, command, consulted, refused);
    }

    /// The verifier a federation command is answered through.
    #[must_use]
    pub fn verifier(&mut self, command: &str) -> ScenarioVerifier {
        if self.armed.take(command) {
            ScenarioVerifier::refusing()
        } else {
            ScenarioVerifier::reading()
        }
    }

    /// The credential identity an authentication's context carries, which the declared
    /// input does not.
    #[must_use]
    pub fn minted_credential(&mut self) -> CredentialId {
        self.mint.credential()
    }

    /// Append a federation event and refold the projection from the log.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::Unavailable`] when the fold refuses the log, which is a
    /// disagreement between the handler that emitted the event and the fold that reads it —
    /// a finding about the crate, reported rather than swallowed.
    pub fn append_federation(&mut self, event: FederationEvent) -> Result<(), TargetError> {
        self.federation_log.push(event);
        self.federation = Projection::fold(&self.federation_log).map_err(|error| {
            TargetError::unavailable("refolding the federation projection", format!("{error:?}"))
        })?;
        Ok(())
    }

    /// Append a tenancy event and refold.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::Unavailable`] when the fold refuses the log.
    pub fn append_tenancy(&mut self, event: TenancyEvent) -> Result<(), TargetError> {
        self.tenancy_log.push(event);
        self.tenancy = Tenancy::fold(&self.tenancy_log);
        Ok(())
    }

    /// Append a resource event and refold.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::Unavailable`] when the fold refuses the log.
    pub fn append_topology(&mut self, event: ResourceEvent) -> Result<(), TargetError> {
        self.topology_log.push(event);
        self.topology = Topology::fold(&self.topology_log);
        Ok(())
    }

    /// Append a credential event and refold the STS read model from the log.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::Unavailable`] when the fold refuses the log, which is a
    /// disagreement between the handler that emitted the event and the fold that reads it.
    pub fn append_credential(&mut self, event: CredentialEvent) -> Result<(), TargetError> {
        self.credential_log.push(event);
        self.credentials = mandate_token::projection::Projection::fold(&self.credential_log)
            .map_err(|error| {
                TargetError::unavailable("refolding the credential projection", error.to_string())
            })?;
        Ok(())
    }

    /// Show that a refused credential command wrote nothing.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::Unavailable`] when the projection is not the fold of the log.
    pub fn credentials_unchanged(&self) -> Result<(), TargetError> {
        let folded =
            mandate_token::projection::Projection::fold(&self.credential_log).map_err(|error| {
                TargetError::unavailable("refolding the credential projection", error.to_string())
            })?;
        unchanged(folded == self.credentials, "mandate.credential")
    }

    /// What the adapter carries that neither a credential command's input nor the read
    /// model supplies: the correlation, the instant, and the epoch snapshot a credential is
    /// bound to.
    #[must_use]
    pub fn sts_context(&self, context: &mandate_types::VerifiedContext) -> StsRequest {
        StsRequest {
            correlation: context.correlation.clone(),
            at: Timestamp::new(FIXED_INSTANT),
            epochs: None,
        }
    }

    /// The same, for the three commands whose declared input carries no verified context.
    #[must_use]
    pub fn sts_request_context(&self) -> StsRequest {
        StsRequest {
            correlation: mandate_types::CorrelationId::new(CORRELATION.to_owned()),
            at: Timestamp::new(FIXED_INSTANT),
            epochs: None,
        }
    }

    /// Append an authorization-code event to the STS log.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::Unavailable`] when the log refuses the append.
    pub fn append_code(&mut self, event: AuthorizationCodeEvent) -> Result<(), TargetError> {
        let stream = match &event {
            AuthorizationCodeEvent::AuthorizationCodeIssued { code_id, .. }
            | AuthorizationCodeEvent::AuthorizationCodeRedeemed { code_id, .. } => *code_id,
        };
        let expected = mandate_sts::store::AuthorizationCodeLog::version(&self.codes, &stream);
        mandate_sts::store::AuthorizationCodeLog::append(
            &mut self.codes,
            &stream,
            expected,
            std::slice::from_ref(&event),
        )
        .map(|_| ())
        .map_err(|refused| {
            TargetError::unavailable("establishing an authorization code", refused.to_string())
        })
    }

    /// Show that a refused federation command wrote nothing.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::Unavailable`] when the projection is not the fold of the log,
    /// which would mean a refusal wrote a record.
    pub fn federation_unchanged(&self) -> Result<(), TargetError> {
        let folded = Projection::fold(&self.federation_log).map_err(|error| {
            TargetError::unavailable("refolding the federation projection", format!("{error:?}"))
        })?;
        unchanged(folded == self.federation, "mandate.federation")
    }

    /// Show that a refused tenancy command wrote nothing.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::Unavailable`] when the fold moved.
    pub fn tenancy_unchanged(&self) -> Result<(), TargetError> {
        unchanged(
            Tenancy::fold(&self.tenancy_log) == self.tenancy,
            "mandate.tenancy",
        )
    }

    /// Show that a refused resource command wrote nothing.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::Unavailable`] when the fold moved.
    pub fn topology_unchanged(&self) -> Result<(), TargetError> {
        unchanged(
            Topology::fold(&self.topology_log) == self.topology,
            "mandate.graph",
        )
    }

    /// Show that a refused identity command wrote nothing, against the log as it stood
    /// before the command ran.
    ///
    /// `IdentityLog` exposes no length and no event slice, and the handlers of this domain
    /// take the log itself rather than a port, so the comparison is against a snapshot the
    /// caller took: `IdentityLog` is `Clone` and `PartialEq`, and equality over the whole
    /// log is strictly stronger than the count this previously claimed to compare and did
    /// not compare at all.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::Unavailable`] when the log moved under a refusal.
    pub fn identity_unchanged(&self, before: &IdentityLog) -> Result<(), TargetError> {
        unchanged(*before == self.identity, "mandate.identity")
    }
}

/// The refusal a fold that moved under a refused command produces.
fn unchanged(held: bool, domain: &str) -> Result<(), TargetError> {
    if held {
        return Ok(());
    }
    Err(TargetError::unavailable(
        format!("refusing a `{domain}` command"),
        "the fold moved under a refusal, which the domain's own rule forbids",
    ))
}

/// The identities the folds are handed, minted from counters.
///
/// `tenancy.yaml` and `graph.yaml` bind every created record's identity from the accepted
/// outcome's response, and the folds generate nothing: each takes the identity as an
/// argument. §37 puts that source of variation outside the thing under test, so it is here,
/// and it is a counter rather than a clock or a random source so that two runs mint the same
/// values in the same order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mint {
    minted: u32,
}

impl Mint {
    /// The next identity, tagged by the kind it is for so that two kinds never share a wire
    /// form.
    fn next(&mut self, tag: u8) -> Uuid {
        self.minted += 1;
        let mut bytes = [0_u8; 16];
        bytes[0] = tag;
        bytes[12..].copy_from_slice(&self.minted.to_be_bytes());
        // The declared form is a canonical uuid, so the version and variant nibbles are the
        // ones a `mandate.core.*` identifier admits.
        bytes[6] = 0x40 | (bytes[6] & 0x0f);
        bytes[8] = 0x80 | (bytes[8] & 0x3f);
        Uuid::from_bytes(bytes)
    }

    /// The identity `CreateOrganization` responds with.
    pub fn organization(&mut self) -> OrganizationId {
        OrganizationId::new(self.next(0x01))
    }

    /// The identity `CreateTeam` responds with.
    pub fn team(&mut self) -> TeamId {
        TeamId::new(self.next(0x02))
    }

    /// The identity `CreateSpace` responds with.
    pub fn space(&mut self) -> SpaceId {
        SpaceId::new(self.next(0x03))
    }

    /// The identity `AddOrganizationMembership` responds with.
    pub fn organization_membership(&mut self) -> OrganizationMembershipId {
        OrganizationMembershipId::new(self.next(0x04))
    }

    /// The identity `AddTeamMembership` responds with.
    pub fn team_membership(&mut self) -> TeamMembershipId {
        TeamMembershipId::new(self.next(0x05))
    }

    /// The `mandate.directory.MembershipContribution` the same outcome records.
    pub fn contribution(&mut self) -> MembershipContributionId {
        MembershipContributionId::new(self.next(0x06))
    }

    /// The credential a context names, which no declared input carries.
    pub fn credential(&mut self) -> CredentialId {
        CredentialId::new(self.next(0x07))
    }

    /// The subject a seeded context carries.
    pub fn principal(&mut self) -> PrincipalId {
        PrincipalId::new(self.next(0x08))
    }
}

/// The Mandate implementation, as an ESS conformance suite sees it.
pub struct MandateTarget {
    /// The digest of the implementation under test, as the caller measured it.
    digest: String,
    /// The open scenario, or none between scenarios.
    live: RefCell<Option<Live>>,
    /// Everything this run stood in for, injected or could not satisfy.
    ledger: RefCell<Ledger>,
}

impl MandateTarget {
    /// A target reporting against `digest`.
    #[must_use]
    pub fn over(digest: &str) -> Self {
        Self {
            digest: digest.to_owned(),
            live: RefCell::new(None),
            ledger: RefCell::new(Ledger::opened()),
        }
    }

    /// The ledger this run produced, in canonical order.
    #[must_use]
    pub fn ledger(&self) -> Ledger {
        self.ledger.borrow().clone().sorted()
    }
}

/// A borrow of the open scenario, or the refusal that none is open.
fn open(live: &mut Option<Live>) -> Result<&mut Live, TargetError> {
    live.as_mut()
        .ok_or_else(|| TargetError::unavailable("driving the handlers", "no scenario is open (§8)"))
}

impl ConformanceTarget for MandateTarget {
    fn identity(&self) -> Result<ImplementationIdentity, TargetError> {
        Ok(ImplementationIdentity::new(
            IMPLEMENTATION,
            format!("{}+src.{}", env!("CARGO_PKG_VERSION"), self.digest),
        ))
    }

    fn begin_scenario(&self, scenario: &ScenarioContext) -> Result<(), TargetError> {
        let ledger = std::mem::take(&mut *self.ledger.borrow_mut());
        *self.live.borrow_mut() = Some(Live::open(scenario, ledger));
        Ok(())
    }

    fn execute_command(
        &self,
        request: SemanticCommandRequest,
    ) -> Result<SemanticCommandResult, TargetError> {
        let mut live = self.live.borrow_mut();
        let live = open(&mut live)?;
        commands::execute(live, &request)
    }

    fn query_view(&self, request: SemanticViewRequest) -> Result<SemanticViewResult, TargetError> {
        Err(TargetError::unsupported(
            format!("reading `{}`", request.view),
            "`systems/mandate` declares no view, so this target projects none",
        ))
    }

    fn observe_events(
        &self,
        request: EventObservationRequest,
    ) -> Result<Vec<ObservedEvent>, TargetError> {
        // Every event of this contract is published by the command that decided it, and a
        // command's own occurrences are reported on its result (§13). Nothing here delivers
        // an event to another component, so an activity's published set is empty away from
        // the invocation — which is the honest answer and not a refusal: a target that
        // reported `unsupported` would say it cannot see its own publications.
        let _ = request;
        Ok(Vec::new())
    }

    fn configure_external_outcome(
        &self,
        request: ExternalOutcomeControl,
    ) -> Result<(), TargetError> {
        let mut live = self.live.borrow_mut();
        let live = open(&mut live)?;
        let command = request.force.command.to_string();
        let scenario = live.scenario.clone();
        if let Some((story, why)) = commands::unrealized(&command) {
            live.ledger
                .block(&scenario, &command, "unrealized-command", story);
            live.ledger.inject(
                &scenario,
                &command,
                external::NO_PORT,
                "unsupported-command",
            );
            return Err(TargetError::unsupported(
                format!("forcing `{}`", request.force),
                format!("{why}; owner {story}"),
            ));
        }
        match external::port_of(&command) {
            None => {
                live.ledger
                    .inject(&scenario, &command, external::NO_PORT, "unknown-command");
                Err(TargetError::unavailable(
                    format!("forcing `{}`", request.force),
                    "this target dispatches the command and names no port for it, which is a \
                     defect in its own port table",
                ))
            }
            Some(external::NO_PORT) => {
                // Ruling 5: the handler reads no port, so there is nowhere to put a fault
                // and no honest way to make it refuse for an external cause. Refuse the
                // arming before dispatch rather than pretending.
                live.ledger.inject(
                    &scenario,
                    &command,
                    external::NO_PORT,
                    "refused-before-dispatch",
                );
                live.ledger.block(
                    &scenario,
                    &command,
                    "no-injection-port",
                    "story:testkit-doubles",
                );
                Err(TargetError::unsupported(
                    format!("forcing `{}`", request.force),
                    "the handler is decided entirely inside its fold and consults no port, so \
                     no external answer can make it refuse; owner story:testkit-doubles",
                ))
            }
            Some(external::NOT_SUBSTITUTABLE) => {
                // The handler *does* read a port — `IdentityRead::resolve` — and takes the
                // concrete `IdentityLog` to read it through, so no caller can put a reader
                // in its place. The refusal is the portless class's and the reason is not:
                // "consults no port" is true of the tenancy and graph folds and false here.
                live.ledger.inject(
                    &scenario,
                    &command,
                    external::NOT_SUBSTITUTABLE,
                    "refused-before-dispatch",
                );
                live.ledger.block(
                    &scenario,
                    &command,
                    "port-not-substitutable",
                    "story:testkit-doubles",
                );
                Err(TargetError::unsupported(
                    format!("forcing `{}`", request.force),
                    "the handler takes the concrete log; the port method it reads is not \
                     substitutable here; owner story:testkit-doubles",
                ))
            }
            Some(port) => {
                // `armed-unreached` until the command says otherwise: the row is upgraded by
                // `Live::record_reads` when a reader is substituted and consulted, and a
                // command that refuses before reading anything leaves it exactly as it is.
                live.ledger
                    .inject(&scenario, &command, port, "armed-unreached");
                live.armed.arm(&command);
                Ok(())
            }
        }
    }

    fn redeliver_event(&self, request: RedeliveryRequest) -> Result<(), TargetError> {
        Err(TargetError::unsupported(
            format!("delivering `{}` again", request.event),
            "`systems/mandate` declares no binding, so nothing delivers an event at all",
        ))
    }

    fn establish_entity(&self, request: EntitySetupRequest) -> Result<(), TargetError> {
        let mut live = self.live.borrow_mut();
        let live = open(&mut live)?;
        establish::establish(live, &request)
    }

    fn end_scenario(&self, _scenario: &ScenarioContext) -> Result<(), TargetError> {
        if let Some(live) = self.live.borrow_mut().take() {
            *self.ledger.borrow_mut() = live.ledger;
        }
        Ok(())
    }
}

/// One complete run: the three documents it produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Executed {
    /// `ess-conformance-report/2`, canonical.
    pub report: String,
    /// `ess-conformance-run/2`, canonical.
    pub run: String,
    /// The injection ledger, canonical.
    pub injections: String,
    /// The conformance verdict, for a caller that reports it.
    pub conformance_status: CountStatus,
}

impl Executed {
    /// Execute `suite` against the real handlers and produce the three documents.
    ///
    /// # Errors
    ///
    /// Returns the admission failure when the bytes are not an admissible suite, and the
    /// count-stage failure when the run and the suite disagree.
    pub fn of(suite: &str, digest: &str) -> Result<Self, String> {
        let admitted = AdmittedSuite::from_json(suite).map_err(|error| error.to_string())?;
        let target = MandateTarget::over(digest);
        let executed = Runner::for_suite(admitted.suite()).run_admitted(&admitted, &target);
        let report =
            CountReport::from_run(&executed, &admitted).map_err(|error| error.to_string())?;
        let run = CountRun::from_run(&executed, &admitted).map_err(|error| error.to_string())?;
        let mut ledger = target.ledger();
        account(&mut ledger, &executed);
        let mut injections =
            serde_json::to_string_pretty(&ledger.sorted()).map_err(|error| error.to_string())?;
        injections.push('\n');
        Ok(Self {
            report: report.to_canonical_json().map_err(|e| e.to_string())?,
            run: run.to_canonical_json().map_err(|e| e.to_string())?,
            injections,
            conformance_status: report.conformance_status(),
        })
    }

    /// Write `report.json`, `run.json` and `injections.json` under `directory`.
    ///
    /// # Errors
    ///
    /// Returns the filesystem failure.
    pub fn write(&self, directory: &std::path::Path) -> std::io::Result<()> {
        std::fs::create_dir_all(directory)?;
        std::fs::write(directory.join("report.json"), &self.report)?;
        std::fs::write(directory.join("run.json"), &self.run)?;
        std::fs::write(directory.join("injections.json"), &self.injections)
    }
}

/// Give every scenario that did not pass a story, so the run can be read as evidence.
///
/// The target already names the ones it refused, each against the story that owns the gap
/// it hit. What is left is the other kind: a scenario the target **executed** and whose
/// expectation the real handlers did not meet. That is the finding a conformance run exists
/// to produce, and the target is not the thing that can attribute it — which story closes a
/// particular disagreement between the contract and an implementation is a judgement, and
/// `story:conform-gate` owns the ledger of those judgements (`generated/conformance/
/// expected-outcomes.json`, coordinator ruling D5: "every non-passed entry with a story").
/// So each one is recorded against that story by name, rather than against a guess this
/// file would have to keep in step by hand.
///
/// The loop is over the run's own terminal results, so the ledger and `report.outcomes`
/// partition the same set by construction: a scenario cannot fail without an entry here,
/// and one cannot be recorded for a scenario that passed.
fn account(ledger: &mut Ledger, executed: &ess_conformance::ExecutedRun) {
    use ess_conformance::report::Status;
    for result in &executed.scenarios {
        if result.status == Status::Passed {
            continue;
        }
        ledger.block(
            &result.scenario.to_string(),
            "",
            "expectation-unmet",
            "story:conform-gate",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{IMPLEMENTATION, Live, MandateTarget, Mint};
    use ess_conformance::target::{ConformanceTarget, ScenarioContext};
    use ess_primitives::ids::CorrelationId;

    fn context() -> ScenarioContext {
        ScenarioContext::new(
            ess_conformance::scenario::ScenarioId::parse(
                "mandate.tenancy.CreateOrganization/outcome/accepted",
            )
            .expect("an identity"),
            CorrelationId::new("c").expect("a correlation"),
        )
    }

    /// The three ESS crates resolve, compile and link at the pinned tag.
    #[test]
    fn ess_crates_link_at_the_pinned_tag() {
        assert!(
            !ess_primitives::error::ValidationCode::ALL.is_empty(),
            "ess-primitives declares no validation codes"
        );
        assert!(
            ess_domain::types::Primitive::ALL.contains(&ess_domain::types::Primitive::String),
            "ess-domain declares no string primitive"
        );
        assert!(
            ess_conformance::AdmittedSuite::from_json("").is_err(),
            "ess-conformance admitted an empty document as a suite"
        );
    }

    /// Each scenario opens on a fold that holds nothing an earlier one wrote (§8).
    #[test]
    fn a_scenario_opens_on_a_fold_that_holds_nothing() {
        let target = MandateTarget::over("000000000000");
        target.begin_scenario(&context()).expect("a scenario opens");
        {
            let mut live = target.live.borrow_mut();
            let live = live.as_mut().expect("a scenario is open");
            live.federation_log.push(
                mandate_federation::record::FederationEvent::FederationConnectionDisabled {
                    context: mandate_types::VerifiedContext {
                        subject: live.mint.principal(),
                        actor: None,
                        organization: live.mint.organization(),
                        audience: live.audience.clone(),
                        credential: live.mint.credential(),
                        delegation: None,
                        execution: None,
                        correlation: mandate_types::CorrelationId::new("c".to_owned()),
                    },
                    id: mandate_types::FederationConnectionId::new(
                        mandate_types::Uuid::from_bytes([9; 16]),
                    ),
                },
            );
        }
        target.end_scenario(&context()).expect("a scenario closes");
        target.begin_scenario(&context()).expect("a scenario opens");
        let live = target.live.borrow();
        let live = live.as_ref().expect("a scenario is open");
        assert!(
            live.federation_log.is_empty(),
            "a scenario opened on the previous scenario's log"
        );
    }

    /// The implementation is named with the digest the caller measured.
    #[test]
    fn the_identity_carries_the_measured_digest() {
        let identity = MandateTarget::over("abc123abc123")
            .identity()
            .expect("the target names itself");
        assert_eq!(identity.name, IMPLEMENTATION);
        assert!(
            identity.version.ends_with("+src.abc123abc123"),
            "the identity does not carry the digest: {}",
            identity.version
        );
    }

    /// Two mints of one kind differ, and two kinds never share a wire form.
    #[test]
    fn minted_identities_are_distinct_and_canonical() {
        let mut mint = Mint::default();
        let first = mint.organization();
        let second = mint.organization();
        assert_ne!(first, second, "one counter minted one value twice");
        let team = mint.team();
        assert_ne!(
            first.to_string()[..2],
            team.to_string()[..2],
            "two kinds share a prefix"
        );
        for rendered in [first.to_string(), team.to_string()] {
            assert_eq!(rendered.len(), 36, "{rendered} is not a canonical uuid");
            assert_eq!(&rendered[14..15], "4", "{rendered} is not version 4");
        }
    }

    /// A scenario that was never opened refuses rather than panicking.
    #[test]
    fn a_closed_target_refuses_every_observation() {
        let target = MandateTarget::over("000000000000");
        let request = ess_conformance::target::EntitySetupRequest {
            entity: "mandate.identity.Session".parse().expect("an entity"),
            identity: ess_primitives::node::Node::Null,
            fields: std::collections::BTreeMap::new(),
            state: "Active".parse().expect("a state"),
            correlation: CorrelationId::new("c").expect("a correlation"),
        };
        assert!(target.establish_entity(request).is_err());
        let _ = Live::open(&context(), super::Ledger::opened());
    }
}
