//! The three `mandate.identity` commands this target drives.
//!
//! `DisablePrincipal` and `RevokeRefreshCredential` are the other two the domain declares
//! and are named with `story:declared-writers` in [`crate::commands::UNREALIZED`]: no
//! handler decides either and neither record's disablement is folded.

use ess_conformance::target::{SemanticCommandRequest, SemanticCommandResult, TargetError};
use mandate_identity::{IdentityEvent, IncrementSecurityEpoch};
use mandate_types::{CredentialProof, SecurityEpochTarget, SessionId, VerifiedContext};

use crate::Live;
use crate::commands::{accepted, refused};
use crate::external::Substituted;
use crate::node;

/// The declared error every refusing outcome of this domain carries.
const DENIED: &str = "mandate.identity.Denied";

/// `mandate.identity.RevokeSession`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn revoke_session(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.identity.RevokeSession";
    let context: VerifiedContext = node::field(&request.input, "context")?;
    let id: SessionId = node::field(&request.input, "id")?;
    let before = live.identity.clone();
    match mandate_identity::revoke_session(&mut live.identity, &context, id) {
        Ok(revoked) => accepted(
            live,
            COMMAND,
            "mandate.identity.SessionRevoked",
            &revoked,
            Vec::new(),
        ),
        Err(denial) => {
            live.identity_unchanged(&before)?;
            refused(COMMAND, denial.outcome().ir_name(), DENIED, denial.reason())
        }
    }
}

/// `mandate.identity.RefreshSession`.
///
/// The declared input is a `refresh_proof`, and resolving a proof to a session identity is
/// the credential domain's — "the proof that resolves a session identity is verified by the
/// credential domain before this is reached" (`identity.yaml`).
///
/// **`mandate-token` being on the line did not close this.** The record a refresh proof
/// resolves through is `mandate.identity.RefreshCredential`, and nothing projects it:
/// `mandate_identity::ESS_UNREALIZED` names the record, its `.State` and its revocation
/// event, and the STS's `CredentialResolution` answers a `mandate_token` `AccessCredential`
/// whose fields carry no session identity. There is no port to read, so a proof whose text
/// *is* a session identity is driven through the real handler and any other proof is
/// answered `Unsupported` against `story:session-epochs` rather than denied for a reason
/// this target invented.
///
/// # Errors
///
/// Returns [`TargetError::Unsupported`] when the proof is not a session identity, and
/// [`TargetError::Unavailable`] when a declared input is not one the contract's schema
/// admits.
pub fn refresh_session(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.identity.RefreshSession";
    let before = live.identity.clone();
    let proof: CredentialProof = node::field(&request.input, "refresh_proof")?;
    let text = std::str::from_utf8(proof.expose_bytes()).unwrap_or_default();
    let Ok(id) = SessionId::parse(text) else {
        live.ledger.block(
            &live.scenario,
            COMMAND,
            "refresh-credential-unprojected",
            "story:declared-writers",
        );
        return Err(TargetError::unsupported(
            format!("invoking `{COMMAND}`"),
            "a refresh proof resolves through `mandate.identity.RefreshCredential`, which no \
             crate projects: `mandate_identity::ESS_UNREALIZED` names the record, its state \
             and its revocation, and the STS's own `CredentialResolution` answers an \
             `AccessCredential` that carries no session identity; owner story:declared-writers",
        ));
    };
    let reader = Substituted::new();
    let armed = live.armed.take(COMMAND);
    let decided = if armed {
        mandate_identity::refresh_session(&reader, &id)
    } else {
        mandate_identity::refresh_session(&live.identity, &id)
    };
    live.record_reads(COMMAND, reader.consulted(), reader.refused());
    match decided {
        Ok(refreshed) => accepted(
            live,
            COMMAND,
            "mandate.identity.SessionRefreshed",
            &refreshed,
            vec![("session_id", node::response_field(refreshed.session_id())?)],
        ),
        Err(denial) => {
            live.identity_unchanged(&before)?;
            refused(COMMAND, denial.outcome().ir_name(), DENIED, denial.reason())
        }
    }
}

/// `mandate.identity.IncrementSecurityEpoch`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn increment_security_epoch(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.identity.IncrementSecurityEpoch";
    let context: VerifiedContext = node::field(&request.input, "context")?;
    let target: SecurityEpochTarget = node::field(&request.input, "target")?;
    let before = live.identity.clone();
    let expected = mandate_identity::IdentityRead::current(&live.identity, &target).version();
    let input = IncrementSecurityEpoch::new(context, target);
    if live.armed.take(COMMAND) {
        let mut refusing = Substituted::new();
        let decided = input.execute(&mut refusing, expected);
        live.record_reads(COMMAND, refusing.consulted(), refusing.refused());
        live.identity_unchanged(&before)?;
        return match decided {
            Ok(_) => Err(TargetError::unavailable(
                format!("forcing the external outcome of `{COMMAND}`"),
                "the refusing write port admitted an increment",
            )),
            Err(denial) => refused(COMMAND, denial.outcome().ir_name(), DENIED, denial.reason()),
        };
    }
    match input.execute(&mut live.identity, expected) {
        Ok(incremented) => {
            let event = IdentityEvent::SecurityEpochIncremented(incremented.clone());
            accepted(live, COMMAND, event.ess_name(), &incremented, Vec::new())
        }
        Err(denial) => {
            live.identity_unchanged(&before)?;
            refused(COMMAND, denial.outcome().ir_name(), DENIED, denial.reason())
        }
    }
}
