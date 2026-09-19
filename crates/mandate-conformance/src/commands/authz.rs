//! `mandate.authorization.Check`, the one command the domain declares.
//!
//! # Five values the contract's input does not carry
//!
//! `authorization.yaml` declares `Check(context, action, resource)`, and
//! [`mandate_authz::CheckRequest`] needs five more that no port in the authorization
//! ceiling can answer: the audience the credential is required to carry, the relation the
//! graph is asked about, the revision floor, the attribute input and the authority scope.
//! Each is documented at its field in that crate with the reason it cannot be looked up.
//! This target states them, and `injections.json` records that it did: a reader who sees
//! `Check` pass must be able to see which bounds were stated rather than evaluated.
//!
//! # The accepted branch reports no event, and says so
//!
//! `mandate.authorization.DecisionRecorded` has no realizer: no type in any crate on this
//! line carries that payload, so the only way to report the event the accepted outcome
//! declares would be to assemble `{context, decision}` here — which is precisely the
//! manufactured expectation the acceptance forbids. An allow is therefore answered
//! `Unsupported` against `story:coverage-map`, which owns the authorization domain's
//! realization registry; a refusal declares no event and is reported in full.

use ess_conformance::target::{SemanticCommandRequest, SemanticCommandResult, TargetError};
use mandate_authz::evaluate::Ceiling;
use mandate_authz::{CheckRequest, Pdp};
use mandate_policy::port::AttributeSet;
use mandate_types::{Action, AuthzRevision, ResourceRef, VerifiedContext};

use crate::Live;
use crate::commands::refused;
use crate::external::Substituted;
use crate::node;

/// The declared error the refusing outcome of this domain carries.
const DENIED: &str = "mandate.authorization.Denied";

/// The revision floor a read must not answer below. The initial one: this target's graph
/// double has answered nothing yet, so demanding a later revision would refuse every read
/// for the floor rather than for the authority.
const INITIAL_REVISION: &str = "0";

/// `mandate.authorization.Check`.
///
/// # Errors
///
/// Returns [`TargetError::Unsupported`] for an allow, whose declared event has no realizer,
/// and [`TargetError::Unavailable`] when a declared input is not one the contract's schema
/// admits.
pub fn check(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.authorization.Check";
    let context: VerifiedContext = node::field(&request.input, "context")?;
    let action: Action = node::field(&request.input, "action")?;
    let resource: ResourceRef = node::field(&request.input, "resource")?;
    // The arming substitutes a reader at `GraphRead`, which is the port a decision's
    // authority is read through. Discarding the arming here — which an earlier version did —
    // left `injections.json` recording a fault at a port where nothing was put, which is the
    // adversary's second finding.
    let reader = Substituted::new();
    let armed = live.armed.take(COMMAND);
    let attributes = AttributeSet::new();
    let minimum = AuthzRevision::new(INITIAL_REVISION.to_owned());
    let expected_audience = context.audience.clone();
    let relation = action.as_str().to_owned();
    let ceilings: [Ceiling; 0] = [];
    let request = CheckRequest {
        context: &context,
        action: &action,
        resource: &resource,
        expected_audience: &expected_audience,
        relation: &relation,
        minimum: &minimum,
        attributes: &attributes,
        scope: None,
        ceilings: &ceilings,
    };
    let decided = if armed {
        mandate_authz::check(
            &Pdp {
                graph: &reader,
                policy: &live.policy,
                catalog: &live.policy,
                issuer: &live.challenge,
                tenancy: &live.tenancy,
                topology: &live.topology,
            },
            &mut live.decisions,
            &request,
        )
    } else {
        mandate_authz::check(
            &Pdp {
                graph: &live.graph,
                policy: &live.policy,
                catalog: &live.policy,
                issuer: &live.challenge,
                tenancy: &live.tenancy,
                topology: &live.topology,
            },
            &mut live.decisions,
            &request,
        )
    };
    live.record_reads(COMMAND, reader.consulted(), reader.refused());
    match decided {
        Ok(_) => {
            live.ledger.block(
                &live.scenario,
                COMMAND,
                "event-unrealized",
                "story:coverage-map",
            );
            Err(TargetError::unsupported(
                format!("the event `mandate.authorization.DecisionRecorded` of `{COMMAND}`"),
                "no type on this crate's dependency line realizes that payload, and the \
                 only other way to report it would be to assemble it here; owner \
                 story:coverage-map",
            ))
        }
        Err(denied) => refused(COMMAND, "denied", DENIED, denied.reason),
    }
}
