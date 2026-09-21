//! The eleven `mandate.credential` commands `services/sts` realizes, one function each.
//!
//! `ExchangeCredential` is the twelfth and is the only one still named in
//! [`crate::commands::UNREALIZED`]: no crate realizes token exchange, and
//! `story:constrained-exchange` owns it.
//!
//! # What each function is handed
//!
//! Every STS handler decides against `mandate_token::projection::Projection` — the read
//! model this crate reached only after `mandate-token` was admitted to its dependency line —
//! and the fold is refolded from the event log after each accepted command, exactly as the
//! federation, tenancy and resource folds are. The values no read model can answer are the
//! deployment's and are handed in as doubles, each written to `injections.json`: the digest,
//! the secret source, the identity allocator, the issuance signer, the key-material
//! resolver, the algorithm allowlist and the code-lifetime ceiling.
//!
//! # Three commands read a port this target cannot fill
//!
//! `IssueAuthorizationCode` reads an `OAuthClientReads`, `RedeemAuthorizationCode` reads
//! that and a `SessionReads`, and both are answered by `RecordedClients` and
//! `RecordedSessions` holding nothing: no command of this contract writes either, so the
//! records a scenario would need are ones only `establish_entity` or an authored arrangement
//! can put there. That is not a refusal — the handlers run and decide — and it is why those
//! scenarios deny rather than pass.

use ess_conformance::target::{SemanticCommandRequest, SemanticCommandResult, TargetError};
use mandate_sts::{code, issue, keys, redemption, registry, resolve};
use mandate_token::projection::{CredentialEvent, Denied};
use mandate_types::{CredentialProof, VerifiedContext};

use crate::Live;
use crate::commands::{accepted, refused};
use crate::external::Substituted;
use crate::node;

/// The declared error every refusing outcome of this domain carries.
const DENIED: &str = "mandate.credential.Denied";

/// `mandate.credential.RegisterResourceServer`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn register_resource_server(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.credential.RegisterResourceServer";
    let input = registry::RegisterResourceServer {
        context: node::field(&request.input, "context")?,
        audience: node::field(&request.input, "audience")?,
        profile: node::field(&request.input, "profile")?,
        allowed_exchange_sources: node::field(&request.input, "allowed_exchange_sources")?,
    };
    let reader = Substituted::new();
    let armed = live.armed.take(COMMAND);
    let decided = if armed {
        registry::register_resource_server(&input, &reader, &mut live.sts_ids)
    } else {
        registry::register_resource_server(&input, &live.credentials, &mut live.sts_ids)
    };
    live.record_reads(COMMAND, reader.consulted(), reader.refused());
    match decided {
        Ok(registered) => {
            live.append_credential(registered.event.clone())?;
            accepted(
                live,
                COMMAND,
                registered.event.ess_name(),
                &registered.event,
                vec![(
                    "resource_server_id",
                    node::response_field(&registered.resource_server_id)?,
                )],
            )
        }
        Err(denied) => refuse(live, COMMAND, denied),
    }
}

/// `mandate.credential.DisableResourceServer`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn disable_resource_server(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.credential.DisableResourceServer";
    let input = registry::DisableResourceServer {
        id: node::field(&request.input, "id")?,
        context: node::field(&request.input, "context")?,
    };
    let reader = Substituted::new();
    let armed = live.armed.take(COMMAND);
    let decided = if armed {
        registry::disable_resource_server(&input, &reader)
    } else {
        registry::disable_resource_server(&input, &live.credentials)
    };
    live.record_reads(COMMAND, reader.consulted(), reader.refused());
    finish(live, COMMAND, decided)
}

/// `mandate.credential.IssueReferenceCredential`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn issue_reference_credential(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.credential.IssueReferenceCredential";
    let input = issue::IssueReferenceCredential {
        context: node::field(&request.input, "context")?,
        target: node::field(&request.input, "target")?,
        requested_scope: node::field(&request.input, "requested_scope")?,
    };
    let context = live.sts_context(&input.context);
    let reader = Substituted::new();
    let armed = live.armed.take(COMMAND);
    let decided = if armed {
        issue::issue_reference_credential(
            &input,
            &context,
            &reader,
            issue::ReferenceParts {
                digest: &issue::Sha256Digest,
                secrets: &mut live.secrets,
                allocator: &mut live.sts_ids,
            },
        )
    } else {
        issue::issue_reference_credential(
            &input,
            &context,
            &live.credentials,
            issue::ReferenceParts {
                digest: &issue::Sha256Digest,
                secrets: &mut live.secrets,
                allocator: &mut live.sts_ids,
            },
        )
    };
    live.record_reads(COMMAND, reader.consulted(), reader.refused());
    issued(live, COMMAND, decided)
}

/// `mandate.credential.IssueSelfContainedCredential`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn issue_self_contained_credential(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.credential.IssueSelfContainedCredential";
    let input = issue::IssueSelfContainedCredential {
        context: node::field(&request.input, "context")?,
        target: node::field(&request.input, "target")?,
        requested_scope: node::field(&request.input, "requested_scope")?,
    };
    let context = live.sts_context(&input.context);
    let issuer = live.issuer.clone();
    let signer = live.signer.clone();
    let reader = Substituted::new();
    let armed = live.armed.take(COMMAND);
    let decided = if armed {
        issue::issue_self_contained_credential(
            &input,
            &context,
            &reader,
            issue::SelfContainedParts {
                digest: &issue::Sha256Digest,
                allocator: &mut live.sts_ids,
                signer: &signer,
                issuer: &issuer,
            },
        )
    } else {
        issue::issue_self_contained_credential(
            &input,
            &context,
            &live.credentials,
            issue::SelfContainedParts {
                digest: &issue::Sha256Digest,
                allocator: &mut live.sts_ids,
                signer: &signer,
                issuer: &issuer,
            },
        )
    };
    live.record_reads(COMMAND, reader.consulted(), reader.refused());
    issued(live, COMMAND, decided)
}

/// `mandate.credential.IntrospectCredential`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn introspect_credential(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.credential.IntrospectCredential";
    let input = resolve::IntrospectCredential {
        caller_proof: node::field(&request.input, "caller_proof")?,
        credential_proof: node::field(&request.input, "credential_proof")?,
    };
    let context = live.sts_request_context();
    let reader = Substituted::new();
    let armed = live.armed.take(COMMAND);
    let decided = if armed {
        resolve::introspect_credential(
            &input,
            &context,
            &reader,
            resolve::IntrospectionParts {
                digest: &issue::Sha256Digest,
                resolution: &reader,
            },
        )
    } else {
        resolve::introspect_credential(
            &input,
            &context,
            &live.credentials,
            resolve::IntrospectionParts {
                digest: &issue::Sha256Digest,
                resolution: &live.credentials,
            },
        )
    };
    live.record_reads(COMMAND, reader.consulted(), reader.refused());
    match decided {
        Ok(introspection) => {
            live.append_credential(introspection.event.clone())?;
            let mut response = vec![("active", node::response_field(&introspection.active)?)];
            if let Some(descriptor) = &introspection.descriptor {
                response.push(("descriptor", node::response_field(descriptor)?));
            }
            if let Some(credential_id) = &introspection.credential_id {
                response.push(("credential_id", node::response_field(credential_id)?));
            }
            accepted(
                live,
                COMMAND,
                introspection.event.ess_name(),
                &introspection.event,
                response,
            )
        }
        Err(denied) => refuse(live, COMMAND, denied),
    }
}

/// `mandate.credential.RevokeAccessCredential`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn revoke_access_credential(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.credential.RevokeAccessCredential";
    let input = resolve::RevokeAccessCredential {
        id: node::field(&request.input, "id")?,
        context: node::field(&request.input, "context")?,
    };
    let reader = Substituted::new();
    let armed = live.armed.take(COMMAND);
    let decided = if armed {
        resolve::revoke_access_credential(&input, &reader)
    } else {
        resolve::revoke_access_credential(&input, &live.credentials)
    };
    live.record_reads(COMMAND, reader.consulted(), reader.refused());
    finish(live, COMMAND, decided)
}

/// `mandate.credential.RegisterSigningKey`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn register_signing_key(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.credential.RegisterSigningKey";
    let input = keys::RegisterSigningKey {
        context: node::field(&request.input, "context")?,
        key_reference: node::field(&request.input, "key_reference")?,
        algorithm: node::field(&request.input, "algorithm")?,
        not_before: node::field(&request.input, "not_before")?,
        expires_at: node::field(&request.input, "expires_at")?,
    };
    let administration = live.key_administration.clone();
    let material = live.key_material;
    let reader = Substituted::new();
    let armed = live.armed.take(COMMAND);
    let decided = if armed {
        administration.register(&input, &reader, &reader, &mut live.sts_ids)
    } else {
        administration.register(&input, &live.credentials, &material, &mut live.sts_ids)
    };
    live.record_reads(COMMAND, reader.consulted(), reader.refused());
    match decided {
        Ok(recorded) => {
            live.append_credential(recorded.event.clone())?;
            accepted(
                live,
                COMMAND,
                recorded.event.ess_name(),
                &recorded.event,
                vec![
                    ("id", node::response_field(&recorded.id)?),
                    ("thumbprint", node::response_field(&recorded.thumbprint)?),
                ],
            )
        }
        Err(denied) => refuse(live, COMMAND, denied),
    }
}

/// `mandate.credential.RetireSigningKey`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn retire_signing_key(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.credential.RetireSigningKey";
    let input = keys::RetireSigningKey {
        id: node::field(&request.input, "id")?,
        context: node::field(&request.input, "context")?,
    };
    let context = live.sts_request_context();
    let reader = Substituted::new();
    let armed = live.armed.take(COMMAND);
    let decided = if armed {
        keys::retire_signing_key(&input, &reader, &context)
    } else {
        keys::retire_signing_key(&input, &live.credentials, &context)
    };
    live.record_reads(COMMAND, reader.consulted(), reader.refused());
    finish(live, COMMAND, decided)
}

/// `mandate.credential.RevokeSigningKey`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn revoke_signing_key(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.credential.RevokeSigningKey";
    let input = keys::RevokeSigningKey {
        id: node::field(&request.input, "id")?,
        context: node::field(&request.input, "context")?,
    };
    let reader = Substituted::new();
    let armed = live.armed.take(COMMAND);
    let decided = if armed {
        keys::revoke_signing_key(&input, &reader)
    } else {
        keys::revoke_signing_key(&input, &live.credentials)
    };
    live.record_reads(COMMAND, reader.consulted(), reader.refused());
    finish(live, COMMAND, decided)
}

/// `mandate.credential.IssueAuthorizationCode`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn issue_authorization_code(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.credential.IssueAuthorizationCode";
    let input = code::IssueAuthorizationCode {
        context: node::field(&request.input, "context")?,
        client_id: node::field(&request.input, "client_id")?,
        session_id: node::field(&request.input, "session_id")?,
        target: node::field(&request.input, "target")?,
        requested_scope: node::field(&request.input, "requested_scope")?,
        challenge: node::field(&request.input, "challenge")?,
        method: node::field(&request.input, "method")?,
        redirect_uri: node::field(&request.input, "redirect_uri")?,
        expires_at: node::field(&request.input, "expires_at")?,
    };
    let context = live.sts_context(&input.context);
    let issuance = live.code_issuance.clone();
    let clients = live.oauth_clients.clone();
    let reader = Substituted::new();
    let armed = live.armed.take(COMMAND);
    let decided = if armed {
        issuance.issue(
            &input,
            &context,
            &reader,
            &clients,
            code::AuthorizationCodeParts {
                digest: &issue::Sha256Digest,
                secrets: &mut live.secrets,
                allocator: &mut live.sts_ids,
            },
        )
    } else {
        issuance.issue(
            &input,
            &context,
            &live.credentials,
            &clients,
            code::AuthorizationCodeParts {
                digest: &issue::Sha256Digest,
                secrets: &mut live.secrets,
                allocator: &mut live.sts_ids,
            },
        )
    };
    live.record_reads(COMMAND, reader.consulted(), reader.refused());
    match decided {
        Ok(issuance) => {
            live.append_code(issuance.event.clone())?;
            accepted(
                live,
                COMMAND,
                issuance.event.ess_name(),
                &issuance.event,
                vec![
                    ("code_id", node::response_field(&issuance.code_id)?),
                    ("code", node::response_field(&issuance.code)?),
                ],
            )
        }
        Err(denied) => refuse(live, COMMAND, denied),
    }
}

/// `mandate.credential.RedeemAuthorizationCode`.
///
/// Driven through [`redemption::redeem_and_consume`] rather than
/// [`redemption::redeem_authorization_code`]: the declared accepted outcome *consumes* the
/// code, and the consuming call is the one that performs the log's compare-and-set. The
/// other is the non-consuming read a caller uses to decide first, and reporting it would
/// leave the code re-redeemable — which is the single thing this command's one-use rule is.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn redeem_authorization_code(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.credential.RedeemAuthorizationCode";
    let input = redemption::RedeemAuthorizationCode {
        code_id: node::field(&request.input, "code_id")?,
        client_id: node::field(&request.input, "client_id")?,
        code: node::field(&request.input, "code")?,
        pkce_verifier: node::field(&request.input, "pkce_verifier")?,
        redirect_uri: node::field(&request.input, "redirect_uri")?,
    };
    let context = live.sts_request_context();
    let clients = live.oauth_clients.clone();
    let sessions = live.sessions.clone();
    let reader = Substituted::new();
    let armed = live.armed.take(COMMAND);
    let credentials = live.credentials.clone();
    let decided = if armed {
        redemption::redeem_and_consume(
            &input,
            &context,
            &mut live.codes,
            redemption::BoundReads {
                servers: &reader,
                clients: &clients,
                sessions: &sessions,
            },
            redemption::RedemptionParts {
                digest: &issue::Sha256Digest,
                secrets: &mut live.secrets,
                allocator: &mut live.sts_ids,
            },
        )
    } else {
        redemption::redeem_and_consume(
            &input,
            &context,
            &mut live.codes,
            redemption::BoundReads {
                servers: &credentials,
                clients: &clients,
                sessions: &sessions,
            },
            redemption::RedemptionParts {
                digest: &issue::Sha256Digest,
                secrets: &mut live.secrets,
                allocator: &mut live.sts_ids,
            },
        )
    };
    live.record_reads(COMMAND, reader.consulted(), reader.refused());
    match decided {
        Ok(redeemed) => {
            let mut response = vec![
                ("credential", node::response_field(&redeemed.credential)?),
                (
                    "credential_id",
                    node::response_field(&redeemed.credential_id)?,
                ),
                ("target", node::response_field(&redeemed.target)?),
                ("descriptor", node::response_field(&redeemed.descriptor)?),
            ];
            if let Some(epochs) = &redeemed.epochs {
                response.push(("epochs", node::response_field(epochs)?));
            }
            accepted(
                live,
                COMMAND,
                redeemed.event.ess_name(),
                &redeemed.event,
                response,
            )
        }
        // `RedemptionRefused` is either the declared refusal or the log refusing the
        // compare-and-set. The first is the command's own answer; the second is the target
        // unable to carry out the request, which is what `Unavailable` says and what a
        // retry might answer differently.
        Err(redemption::RedemptionRefused::Denied(denied)) => refuse(live, COMMAND, denied),
        Err(other) => Err(TargetError::unavailable(
            format!("consuming the code for `{COMMAND}`"),
            other.to_string(),
        )),
    }
}

/// The two issuance commands, whose accepted outcome returns one credential.
fn issued(
    live: &mut Live,
    command: &str,
    decided: Result<issue::CredentialIssued, Denied>,
) -> Result<SemanticCommandResult, TargetError> {
    match decided {
        Ok(credential) => {
            live.append_credential(credential.event.clone())?;
            let mut response = vec![
                ("credential", node::response_field(&credential.credential)?),
                (
                    "credential_id",
                    node::response_field(&credential.credential_id)?,
                ),
                ("descriptor", node::response_field(&credential.descriptor)?),
            ];
            if let Some(epochs) = &credential.epochs {
                response.push(("epochs", node::response_field(epochs)?));
            }
            accepted(
                live,
                command,
                credential.event.ess_name(),
                &credential.event,
                response,
            )
        }
        Err(denied) => refuse(live, command, denied),
    }
}

/// The four lifecycle commands whose accepted outcome returns the event alone.
fn finish(
    live: &mut Live,
    command: &str,
    decided: Result<CredentialEvent, Denied>,
) -> Result<SemanticCommandResult, TargetError> {
    match decided {
        Ok(event) => {
            live.append_credential(event.clone())?;
            accepted(live, command, event.ess_name(), &event, Vec::new())
        }
        Err(denied) => refuse(live, command, denied),
    }
}

/// Report the refusal through the declared branch the crate says it is, having shown the
/// fold is exactly as it was.
fn refuse(
    live: &mut Live,
    command: &str,
    denied: Denied,
) -> Result<SemanticCommandResult, TargetError> {
    live.credentials_unchanged()?;
    refused(command, denied.outcome.ir_name(), DENIED, denied.reason)
}

/// The proof a scenario presented, as the bytes the digest is taken over.
///
/// Kept beside the commands that read one so the two places agree on what a proof is: a
/// `mandate.core.CredentialProof` is a transient *bytes* newtype, never text.
#[must_use]
pub fn proof_bytes(proof: &CredentialProof) -> &[u8] {
    proof.expose_bytes()
}

/// The verified context an STS request is served under, where the command carries one.
#[must_use]
pub fn carried(context: &VerifiedContext) -> &VerifiedContext {
    context
}

#[cfg(test)]
mod tests {
    use crate::commands::{REALIZED, UNREALIZED};

    /// The domain's twelve commands are accounted for, and only token exchange is refused.
    ///
    /// The case is the one that catches a regression in the other direction: an arm removed
    /// without its registry row restored, or a row left behind after an arm landed.
    #[test]
    fn eleven_are_dispatched_and_only_token_exchange_is_named() {
        let dispatched: Vec<&str> = REALIZED
            .iter()
            .filter(|command| command.starts_with("mandate.credential."))
            .copied()
            .collect();
        assert_eq!(
            dispatched.len(),
            11,
            "the STS realizes eleven commands and the dispatch table holds {}",
            dispatched.len()
        );
        let named: Vec<&str> = UNREALIZED
            .iter()
            .filter(|(command, _, _)| command.starts_with("mandate.credential."))
            .map(|(command, _, _)| *command)
            .collect();
        assert_eq!(named, vec!["mandate.credential.ExchangeCredential"]);
        assert_eq!(
            UNREALIZED
                .iter()
                .find(|(command, _, _)| *command == "mandate.credential.ExchangeCredential")
                .map(|(_, story, _)| *story),
            Some("story:constrained-exchange")
        );
        assert!(
            !UNREALIZED
                .iter()
                .any(|(_, story, _)| *story == "story:conformance-target"),
            "a row still names this story, so the admission it waited for has not been \
             carried through"
        );
    }
}
