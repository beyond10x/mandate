//! The `mandate.credential` realization registry, and every command input this crate holds,
//! decided against the compiled contract.
//!
//! Two directions, and the pair is the point. One asks whether every element the registry
//! names is an element the contract declares; the other asks whether every *declared*
//! element of this domain is accounted for — by `ESS_REALIZATIONS` or by `ESS_UNREALIZED`,
//! never by both and never by neither. A registry read as coverage is read as a statement
//! about the whole domain, and an element nobody named is the one shape of drift a list of
//! what *is* covered cannot show.
//!
//! One registry for one domain, ruled at the wave B opening: `crates/mandate-token` projects
//! three of this domain's entities and folds nine of its events, and those realizations are
//! accounted here by path. `crates/mandate-token/tests/contract_agreement.rs` decides the
//! shapes; this decides the coverage.
//!
//! The command inputs are round-tripped the same way the event payloads are there:
//! `to_value`, `from_value` into the generated shape, `to_value` again, compared. The
//! generated shapes carry `#[serde(deny_unknown_fields)]` and declare every non-optional key
//! required, so a field renamed, added or dropped fails at `from_value` naming the key.

use mandate_contract::commands;
use mandate_sts::issue::{IssueReferenceCredential, IssueSelfContainedCredential};
use mandate_sts::keys::{RegisterSigningKey, RetireSigningKey, RevokeSigningKey};
use mandate_sts::registry::{DisableResourceServer, RegisterResourceServer};
use mandate_sts::resolve::{IntrospectCredential, RevokeAccessCredential};
use mandate_sts::{ESS_REALIZATIONS, ESS_UNREALIZED};
use mandate_token::CredentialProfile;
use mandate_types::{
    Audience, AuthorityScope, CorrelationId, CredentialId, CredentialKind, CredentialProof,
    DelegationId, Duration, ExecutionId, KeyReference, OrganizationId, PrincipalId,
    ResourceServerId, RevocationGuarantee, SigningAlgorithm, SigningKeyId, Timestamp, Uuid,
    VerifiedContext,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::collections::BTreeSet;

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

/// A verified context carrying every optional the declaration admits.
fn populated_context() -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::new(uuid(1)),
        actor: Some(PrincipalId::new(uuid(3))),
        organization: OrganizationId::new(uuid(2)),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(5)),
        delegation: Some(DelegationId::new(uuid(6))),
        execution: Some(ExecutionId::new(uuid(7))),
        correlation: CorrelationId::new("correlation"),
    }
}

/// The same context with every optional absent.
fn bare_context() -> VerifiedContext {
    VerifiedContext {
        actor: None,
        delegation: None,
        execution: None,
        ..populated_context()
    }
}

fn scope() -> AuthorityScope {
    AuthorityScope {
        actions: Vec::new(),
        resources: Vec::new(),
        space: None,
    }
}

fn profile() -> CredentialProfile {
    CredentialProfile {
        name: "reference".to_owned(),
        kind: CredentialKind::Reference,
        revocation: RevocationGuarantee::ImmediateOnline,
        max_ttl: Duration::new("PT1H"),
        positive_cache_ttl: Duration::new("PT30S"),
        requires_online_authorization: true,
    }
}

/// One round trip: the domain value's own JSON, read as the generated shape it names and
/// written back.
fn agrees<D, C>(domain: &D, element: &str) -> Value
where
    D: Serialize,
    C: Serialize + DeserializeOwned,
{
    let encoded = serde_json::to_value(domain).expect("a domain value encodes as JSON");
    let shape: C = serde_json::from_value(encoded.clone())
        .unwrap_or_else(|error| panic!("{element}: the generated shape refuses it: {error}"));
    let round_tripped = serde_json::to_value(&shape).expect("a generated shape encodes as JSON");
    assert_eq!(
        round_tripped, encoded,
        "{element}: the round trip through the generated shape is not the identity"
    );
    encoded
}

/// Every key of a document, at every depth, carries a value the contract declares.
fn carries_no_null(document: &Value, path: &str) {
    match document {
        Value::Null => panic!("{path} is null; the contract spells absence by omitting the key"),
        Value::Object(fields) => {
            for (key, value) in fields {
                carries_no_null(value, &format!("{path}.{key}"));
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                carries_no_null(item, &format!("{path}[{index}]"));
            }
        }
        _ => {}
    }
}

/// Every command input this crate holds, over one context.
///
/// The two proof-driven fields render the redaction marker rather than the material
/// (`mandate_types::REDACTED`); the contract declares them as strings, so the round trip
/// decides the key set here and the credential boundary is decided where it is enforced, in
/// `mandate-types`.
fn each_input_agrees(context: &VerifiedContext) -> Vec<Value> {
    vec![
        agrees::<_, commands::MandateCredentialRegisterResourceServerInput>(
            &RegisterResourceServer {
                context: context.clone(),
                audience: Audience::new("api-a"),
                profile: profile(),
                allowed_exchange_sources: Vec::new(),
            },
            "mandate.credential.RegisterResourceServer",
        ),
        agrees::<_, commands::MandateCredentialDisableResourceServerInput>(
            &DisableResourceServer {
                id: ResourceServerId::new(uuid(0x30)),
                context: context.clone(),
            },
            "mandate.credential.DisableResourceServer",
        ),
        agrees::<_, commands::MandateCredentialIssueReferenceCredentialInput>(
            &IssueReferenceCredential {
                context: context.clone(),
                target: ResourceServerId::new(uuid(0x30)),
                requested_scope: scope(),
            },
            "mandate.credential.IssueReferenceCredential",
        ),
        agrees::<_, commands::MandateCredentialIssueSelfContainedCredentialInput>(
            &IssueSelfContainedCredential {
                context: context.clone(),
                target: ResourceServerId::new(uuid(0x30)),
                requested_scope: scope(),
            },
            "mandate.credential.IssueSelfContainedCredential",
        ),
        agrees::<_, commands::MandateCredentialIntrospectCredentialInput>(
            &IntrospectCredential {
                caller_proof: CredentialProof::from_bytes(b"caller".to_vec()),
                credential_proof: CredentialProof::from_bytes(b"presented".to_vec()),
            },
            "mandate.credential.IntrospectCredential",
        ),
        agrees::<_, commands::MandateCredentialRevokeAccessCredentialInput>(
            &RevokeAccessCredential {
                id: CredentialId::new(uuid(0x40)),
                context: context.clone(),
            },
            "mandate.credential.RevokeAccessCredential",
        ),
        agrees::<_, commands::MandateCredentialRegisterSigningKeyInput>(
            &RegisterSigningKey {
                context: context.clone(),
                key_reference: KeyReference::new("kms://one"),
                algorithm: SigningAlgorithm::new("declared-by-deployment"),
                not_before: Timestamp::new("2026-09-19T00:00:00Z"),
                expires_at: Timestamp::new("2026-12-31T00:00:00Z"),
            },
            "mandate.credential.RegisterSigningKey",
        ),
        agrees::<_, commands::MandateCredentialRetireSigningKeyInput>(
            &RetireSigningKey {
                id: SigningKeyId::new(uuid(0x70)),
                context: context.clone(),
            },
            "mandate.credential.RetireSigningKey",
        ),
        agrees::<_, commands::MandateCredentialRevokeSigningKeyInput>(
            &RevokeSigningKey {
                id: SigningKeyId::new(uuid(0x70)),
                context: context.clone(),
            },
            "mandate.credential.RevokeSigningKey",
        ),
    ]
}

#[test]
fn every_command_input_round_trips_with_every_optional_carried() {
    assert_eq!(
        each_input_agrees(&populated_context()).len(),
        9,
        "one input per command this crate realizes"
    );
}

#[test]
fn every_command_input_round_trips_with_every_optional_absent_and_spells_absence_by_omission() {
    for document in each_input_agrees(&bare_context()) {
        carries_no_null(&document, "input");
    }
}

/// The compiled contract, read once per case that needs it.
fn system_ir() -> Value {
    const IR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../generated/ir/system.json"
    );
    let text = std::fs::read_to_string(IR).expect("the generated IR is readable");
    serde_json::from_str(&text).expect("the generated IR is JSON")
}

/// The registry and the list of what it does not cover account for every declared element of
/// this domain, once each.
#[test]
fn every_declared_element_of_this_domain_is_realized_or_named_as_unrealized() {
    let ir = system_ir();
    let realized: BTreeSet<&str> = ESS_REALIZATIONS
        .iter()
        .map(|(element, _)| *element)
        .collect();
    let unrealized: BTreeSet<&str> = ESS_UNREALIZED.iter().map(|(element, _)| *element).collect();

    let mut declared: BTreeSet<String> = BTreeSet::new();
    for kind in ["commands", "events", "entities", "errors", "types"] {
        let Some(index) = ir[kind].as_object() else {
            continue;
        };
        declared.extend(
            index
                .keys()
                .filter(|element| element.starts_with("mandate.credential."))
                .cloned(),
        );
    }

    let accounted: BTreeSet<String> = realized
        .iter()
        .chain(unrealized.iter())
        .map(|element| (*element).to_owned())
        .collect();
    assert_eq!(
        declared, accounted,
        "every declared element of this domain is named by ESS_REALIZATIONS or by \
         ESS_UNREALIZED"
    );
    assert!(
        realized.is_disjoint(&unrealized),
        "an element is realized or it is not: {:?}",
        realized.intersection(&unrealized).collect::<Vec<_>>()
    );
    for (element, reason) in ESS_UNREALIZED {
        assert!(
            !reason.trim().is_empty(),
            "{element} is named as unrealized with no reason"
        );
    }
}

/// Every element the registry names as realized is one the contract declares.
///
/// The registry's other half is the compiler's: `mandate_types::realizes!` expands each entry
/// into a `use` of the symbol on the right, so a symbol that moved does not build. What no
/// compiler can check is the string on the left, which is the half a coverage report is read
/// through.
#[test]
fn every_realized_element_is_one_the_contract_declares() {
    let ir = system_ir();
    let kinds = ["commands", "events", "entities", "errors", "types"];

    assert!(
        !ESS_REALIZATIONS.is_empty(),
        "the crate registers what it realizes"
    );
    for (element, symbol) in ESS_REALIZATIONS {
        assert!(
            kinds
                .iter()
                .any(|kind| ir[kind].get(element).is_some_and(|node| !node.is_null())),
            "{element} (realized by {symbol}) is declared by no commands, events, entities, \
             errors or types index of generated/ir/system.json"
        );
        assert!(
            element.starts_with("mandate.credential."),
            "{element} (realized by {symbol}) is not an element of this domain"
        );
    }
}

/// Every unrealized element names the story that owns it, or says which crate realizes it
/// instead. A reason that named neither would be a list of what is missing with no way to
/// find out when it stops being missing.
#[test]
fn every_unrealized_element_names_an_owner() {
    for (element, reason) in ESS_UNREALIZED {
        assert!(
            reason.contains("story:") || reason.contains("realized by "),
            "{element}: `{reason}` names neither an owning story nor the crate that realizes \
             it"
        );
    }
}

/// Every command of this domain is realized here or named as unrealized, and the ones this
/// crate realizes are the nine its handlers decide.
#[test]
fn the_commands_this_crate_realizes_are_the_nine_its_handlers_decide() {
    let ir = system_ir();
    let realized: BTreeSet<&str> = ESS_REALIZATIONS
        .iter()
        .map(|(element, _)| *element)
        .filter(|element| ir["commands"].get(*element).is_some())
        .collect();

    assert_eq!(
        realized,
        BTreeSet::from([
            "mandate.credential.DisableResourceServer",
            "mandate.credential.IntrospectCredential",
            "mandate.credential.IssueReferenceCredential",
            "mandate.credential.IssueSelfContainedCredential",
            "mandate.credential.RegisterResourceServer",
            "mandate.credential.RegisterSigningKey",
            "mandate.credential.RetireSigningKey",
            "mandate.credential.RevokeAccessCredential",
            "mandate.credential.RevokeSigningKey",
        ])
    );
}
