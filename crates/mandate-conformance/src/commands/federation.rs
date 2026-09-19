//! The nine `mandate.federation` commands, one function each — eight of them driven
//! through a real handler and the ninth refusing by name.
//!
//! `mandate.federation.AuthorizePublicClient` is the ninth. The crate realizes
//! `authorize::validate_authorization_code`, and that function validates a *redemption*:
//! its input is a whole `AuthorizationCode` record, which the declared command input does
//! not carry. There is no decoding from the one to the other, so
//! [`authorize_public_client`] answers `Unsupported` against `story:oauth-integration` —
//! the story that owns the adapter carrying the validation candidate into the STS call —
//! rather than calling the handler with an argument this target would have to invent. It
//! keeps a dispatch arm rather than a registry row because the gap is in the *shape* of one
//! command, not in a domain nothing realizes, and the arm is where a reader looks for it.

use ess_conformance::target::{SemanticCommandRequest, SemanticCommandResult, TargetError};
use mandate_federation::record::FederationEvent;
use mandate_federation::{RequestContext, disable, link, record, register_client};
use mandate_types::{CorrelationId, CredentialId, Timestamp};

use crate::Live;
use crate::commands::{accepted, refused};
use crate::external::Substituted;
use crate::node;

/// The declared error every refusing outcome of this domain carries.
const DENIED: &str = "mandate.federation.Denied";

/// `mandate.federation.RegisterFederationConnection`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn register_federation_connection(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.federation.RegisterFederationConnection";
    let input = record::RegisterFederationConnection {
        context: node::field(&request.input, "context")?,
        issuer: node::field(&request.input, "issuer")?,
        client_id: node::field(&request.input, "client_id")?,
        tenant_resolution: node::field(&request.input, "tenant_resolution")?,
        jit_provisioning: node::field(&request.input, "jit_provisioning")?,
    };
    let reader = Substituted::new();
    let armed = live.armed.take(COMMAND);
    let decided = if armed {
        record::register_federation_connection(&input, &reader, &mut live.federation_ids)
    } else {
        record::register_federation_connection(&input, &live.federation, &mut live.federation_ids)
    };
    live.record_reads(COMMAND, reader.consulted(), reader.refused());
    match decided {
        Ok(registered) => {
            live.append_federation(registered.event.clone())?;
            accepted(
                live,
                COMMAND,
                registered.event.ess_name(),
                &registered.event,
                vec![(
                    "connection_id",
                    node::response_field(&registered.connection_id)?,
                )],
            )
        }
        Err(denied) => {
            live.federation_unchanged()?;
            refused(COMMAND, denied.outcome.ir_name(), DENIED, denied.reason)
        }
    }
}

/// `mandate.federation.LinkExternalPrincipal`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn link_external_principal(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.federation.LinkExternalPrincipal";
    let input = link::LinkExternalPrincipal {
        context: node::field(&request.input, "context")?,
        connection_id: node::field(&request.input, "connection_id")?,
        external_subject: node::field(&request.input, "external_subject")?,
        principal_id: node::field(&request.input, "principal_id")?,
        method: node::field(&request.input, "method")?,
    };
    let context = self::context(live, &input.context.correlation, input.context.credential);
    let reader = Substituted::new();
    let armed = live.armed.take(COMMAND);
    let decided = if armed {
        link::link_external_principal(
            &input,
            &context,
            &live.federation,
            &reader,
            &mut live.federation_ids,
        )
    } else {
        link::link_external_principal(
            &input,
            &context,
            &live.federation,
            &live.federation,
            &mut live.federation_ids,
        )
    };
    live.record_reads(COMMAND, reader.consulted(), reader.refused());
    match decided {
        Ok(linked) => {
            live.append_federation(linked.event.clone())?;
            accepted(
                live,
                COMMAND,
                linked.event.ess_name(),
                &linked.event,
                vec![(
                    "external_principal_id",
                    node::response_field(&linked.external_principal_id)?,
                )],
            )
        }
        Err(denied) => {
            live.federation_unchanged()?;
            refused(COMMAND, denied.outcome.ir_name(), DENIED, denied.reason)
        }
    }
}

/// `mandate.federation.AuthenticateFederation`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn authenticate_federation(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.federation.AuthenticateFederation";
    let input = mandate_federation::authenticate::AuthenticateFederation {
        connection_id: node::field(&request.input, "connection_id")?,
        proof: node::field(&request.input, "proof")?,
    };
    let correlation = CorrelationId::new(request.correlation.to_string());
    let credential = live.minted_credential();
    let context = self::context(live, &correlation, credential);
    let verifier = live.verifier(COMMAND);
    let decided = mandate_federation::authenticate::authenticate_federation(
        &input,
        &context,
        &verifier,
        &live.federation,
        &live.federation,
        &mut live.session_issuer,
    );
    live.record_reads(COMMAND, verifier.consulted(), verifier.refused());
    match decided {
        Ok(authenticated) => {
            live.append_federation(authenticated.event.clone())?;
            accepted(
                live,
                COMMAND,
                authenticated.event.ess_name(),
                &authenticated.event,
                vec![
                    (
                        "session_id",
                        node::response_field(&authenticated.session_id)?,
                    ),
                    (
                        "principal_id",
                        node::response_field(&authenticated.principal_id)?,
                    ),
                    (
                        "organization_id",
                        node::response_field(&authenticated.organization_id)?,
                    ),
                    ("epochs", node::response_field(&authenticated.epochs)?),
                    (
                        "expires_at",
                        node::response_field(&authenticated.expires_at)?,
                    ),
                ],
            )
        }
        Err(denied) => {
            live.federation_unchanged()?;
            refused(COMMAND, denied.outcome.ir_name(), DENIED, denied.reason)
        }
    }
}

/// `mandate.federation.ProvisionExternalPrincipal`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn provision_external_principal(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.federation.ProvisionExternalPrincipal";
    let input = mandate_federation::authenticate::ProvisionExternalPrincipal {
        connection_id: node::field(&request.input, "connection_id")?,
        proof: node::field(&request.input, "proof")?,
    };
    let correlation = CorrelationId::new(request.correlation.to_string());
    let credential = live.minted_credential();
    let context = self::context(live, &correlation, credential);
    let verifier = live.verifier(COMMAND);
    let decided = mandate_federation::authenticate::provision_external_principal(
        &input,
        &context,
        &verifier,
        &live.federation,
        &live.federation,
        &mut live.federation_ids,
    );
    live.record_reads(COMMAND, verifier.consulted(), verifier.refused());
    match decided {
        Ok(provisioned) => {
            live.append_federation(provisioned.event.clone())?;
            let organization_id = match &provisioned.event {
                FederationEvent::ExternalPrincipalProvisioned {
                    organization_id, ..
                } => *organization_id,
                _ => {
                    return Err(TargetError::unavailable(
                        "reading the provisioning's organization",
                        "the accepted outcome emitted an event that is not the declared one",
                    ));
                }
            };
            accepted(
                live,
                COMMAND,
                provisioned.event.ess_name(),
                &provisioned.event,
                vec![
                    (
                        "external_principal_id",
                        node::response_field(&provisioned.external_principal_id)?,
                    ),
                    (
                        "principal_id",
                        node::response_field(&provisioned.principal_id)?,
                    ),
                    ("organization_id", node::response_field(&organization_id)?),
                    ("subject", node::response_field(&provisioned.subject)?),
                    (
                        "display_name",
                        node::response_field(&provisioned.display_name)?,
                    ),
                ],
            )
        }
        Err(denied) => {
            live.federation_unchanged()?;
            refused(COMMAND, denied.outcome.ir_name(), DENIED, denied.reason)
        }
    }
}

/// `mandate.federation.AuthorizePublicClient`, which this target cannot drive.
///
/// # Errors
///
/// Always [`TargetError::Unsupported`]: see the module documentation.
pub fn authorize_public_client(
    live: &mut Live,
    _request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.federation.AuthorizePublicClient";
    live.ledger.block(
        &live.scenario,
        COMMAND,
        "input-shape-unrealized",
        "story:oauth-integration",
    );
    Err(TargetError::unsupported(
        format!("invoking `{COMMAND}`"),
        "the crate realizes `authorize::validate_authorization_code`, which validates a \
         redemption against a whole AuthorizationCode record the declared input does not \
         carry; owner story:oauth-integration",
    ))
}

/// `mandate.federation.DisableFederationConnection`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn disable_federation_connection(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.federation.DisableFederationConnection";
    let input = disable::DisableFederationConnection {
        context: node::field(&request.input, "context")?,
        id: node::field(&request.input, "id")?,
    };
    let reader = Substituted::new();
    let armed = live.armed.take(COMMAND);
    let decided = if armed {
        disable::disable_federation_connection(&input, &reader)
    } else {
        disable::disable_federation_connection(&input, &live.federation)
    };
    live.record_reads(COMMAND, reader.consulted(), reader.refused());
    finish(live, COMMAND, decided)
}

/// `mandate.federation.UnlinkExternalPrincipal`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn unlink_external_principal(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.federation.UnlinkExternalPrincipal";
    let input = disable::UnlinkExternalPrincipal {
        context: node::field(&request.input, "context")?,
        id: node::field(&request.input, "id")?,
    };
    let reader = Substituted::new();
    let armed = live.armed.take(COMMAND);
    let decided = if armed {
        disable::unlink_external_principal(&input, &reader)
    } else {
        disable::unlink_external_principal(&input, &live.federation)
    };
    live.record_reads(COMMAND, reader.consulted(), reader.refused());
    finish(live, COMMAND, decided)
}

/// `mandate.federation.DisableOAuthClient`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn disable_oauth_client(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.federation.DisableOAuthClient";
    let input = disable::DisableOAuthClient {
        context: node::field(&request.input, "context")?,
        id: node::field(&request.input, "id")?,
    };
    let reader = Substituted::new();
    let armed = live.armed.take(COMMAND);
    let decided = if armed {
        disable::disable_oauth_client(&input, &reader)
    } else {
        disable::disable_oauth_client(&input, &live.federation)
    };
    live.record_reads(COMMAND, reader.consulted(), reader.refused());
    finish(live, COMMAND, decided)
}

/// `mandate.federation.RegisterOAuthClient`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn register_oauth_client(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.federation.RegisterOAuthClient";
    let input = register_client::RegisterOAuthClient {
        context: node::field(&request.input, "context")?,
        public: node::field(&request.input, "public")?,
        redirect_uris: node::field(&request.input, "redirect_uris")?,
        pkce_method: node::field(&request.input, "pkce_method")?,
    };
    let reader = Substituted::new();
    let armed = live.armed.take(COMMAND);
    let standing = live.admission.clone();
    let decided = if armed {
        register_client::register_o_auth_client(&input, &reader, &mut live.federation_ids)
    } else {
        register_client::register_o_auth_client(&input, &standing, &mut live.federation_ids)
    };
    live.record_reads(COMMAND, reader.consulted(), reader.refused());
    match decided {
        Ok(registered) => {
            live.append_federation(registered.event.clone())?;
            let organization_id = match &registered.event {
                FederationEvent::OAuthClientRegistered {
                    organization_id, ..
                } => *organization_id,
                _ => {
                    return Err(TargetError::unavailable(
                        "reading the registration's organization",
                        "the accepted outcome emitted an event that is not the declared one",
                    ));
                }
            };
            accepted(
                live,
                COMMAND,
                registered.event.ess_name(),
                &registered.event,
                vec![
                    ("id", node::response_field(&registered.id)?),
                    ("organization_id", node::response_field(&organization_id)?),
                ],
            )
        }
        Err(denied) => {
            live.federation_unchanged()?;
            refused(COMMAND, denied.outcome.ir_name(), DENIED, denied.reason)
        }
    }
}

/// The three lifecycle commands whose accepted outcome returns the event alone.
fn finish(
    live: &mut Live,
    command: &str,
    decided: Result<FederationEvent, mandate_federation::Denied>,
) -> Result<SemanticCommandResult, TargetError> {
    match decided {
        Ok(event) => {
            live.append_federation(event.clone())?;
            accepted(live, command, event.ess_name(), &event, Vec::new())
        }
        Err(denied) => {
            live.federation_unchanged()?;
            refused(command, denied.outcome.ir_name(), DENIED, denied.reason)
        }
    }
}

/// What the adapter carries that neither the input nor the read model supplies.
///
/// A clock is an adapter concern and so is the audience a context is established for; both
/// are fixed values of this target, minted from a counter, so two runs of one suite decide
/// the same instant.
fn context(live: &Live, correlation: &CorrelationId, credential: CredentialId) -> RequestContext {
    RequestContext {
        audience: live.audience.clone(),
        correlation: correlation.clone(),
        credential,
        at: Timestamp::new(crate::FIXED_INSTANT),
    }
}
