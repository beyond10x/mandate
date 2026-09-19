//! Round-trip conformance for every type the compiled index declares.
//!
//! Every case is decided against `generated/schema/types`, the ESS projection that
//! `cargo xtask contracts` byte-compares. Nothing here asserts runtime enforcement.
//!
//! The index holds 110 entries: the 74 authored `mandate.core` types, which
//! `mandate_types::conformance::cases()` realizes and the cases below decide, and the 36
//! derived `<Entity>.State` enums, which join the same account at the end of this file.
//!
//! # The rule the state account applies, and exactly what it covers
//!
//! **A `.State` enum has no hand-written representation in `mandate-types`, and none is
//! invented for it.** The macros in `crates/mandate-types/src/macros.rs` hardcode the
//! `mandate.core.` prefix, every derived state enum is `mandate.<domain>.<Entity>.State`,
//! and no crate this one depends on declares one. What every reader of the contract does
//! get is the generated `mandate_contract::entities::<Entity>State` shape, a dev-dependency
//! here, so each of the 36 compiled declarations is paired with the generated enum that
//! realizes it and decided through it: every declared variant is read back, re-serialized
//! and put through the same [`assert_encoding_matches_schema`] every authored type goes
//! through, and an undeclared variant is refused. That is 36 of 36 — and it is worth being
//! plain about what that kind of coverage is and is not:
//!
//! * **Six are decided against the contract through a domain enum as well.**
//!   `OrganizationState`, `OrganizationMembershipState`, `TeamState`,
//!   `TeamMembershipState`, `SpaceState` and `ResourceState` are declared in
//!   `mandate-model` and put through the generated shape, variant for variant, by
//!   `crates/mandate-model/tests/contract_agreement.rs`. For these six a hand-written
//!   representation is measured against the contract.
//! * **The other 30 are accounted through the generated enum only.** The generated crate
//!   and the JSON Schema projection are two emissions of one compiled model, so a case
//!   over both says they agree with each other; it does not say any hand-written Rust
//!   agrees with either, because for these 30 this crate has none. They are named in
//!   `mandate_types::inventory::DERIVED_STATE_ENUMS` — the 36 minus the six above.
//! * **Thirteen of those 30 do have a domain enum, in a crate this one cannot reach**, and
//!   each is decided by the story that owns its crate, not here. In `mandate-federation`:
//!   `ConnectionState` (`mandate.federation.FederationConnection.State`), `LinkState`
//!   (`mandate.federation.ExternalPrincipal.State`), `OAuthClientState`
//!   (`mandate.federation.OAuthClient.State`) and `AuthorizationCodeState`
//!   (`mandate.credential.AuthorizationCode.State`); in `mandate-identity`, `PrincipalState`
//!   (`mandate.identity.Principal.State`, realized there since wave B while
//!   `mandate-federation` keeps a port view of the same name) and `SessionState`
//!   (`mandate.identity.Session.State`) — those six belong to
//!   `story:federation-identity-alignment`. In `mandate-token`: `ResourceServerState`
//!   (`mandate.credential.ResourceServer.State`), `AccessCredentialState`
//!   (`mandate.credential.AccessCredential.State`) and `SigningKeyState`
//!   (`mandate.credential.SigningKey.State`) — those three belong to
//!   `story:credential-profiles`. In `mandate-graph`, `RelationState`
//!   (`mandate.graph.Relation.State`) and `GrantState` (`mandate.graph.Grant.State`); in
//!   `mandate-policy`, `PolicyState` (`mandate.policy.Policy.State`) and
//!   `AuthorizationModelState` (`mandate.policy.AuthorizationModel.State`) — those four
//!   belong to `story:graph-policy-adapter`. `mandate-types` is a leaf and depends on none
//!   of these crates; a case here could not construct their values.
//! * **The remaining seventeen have no domain enum anywhere in this workspace**, so for
//!   them the generated shape is the only realization there is to decide.
//!
//! The pairing is the only hand-written part of the account, and two things hold it to the
//! contract. It is asserted equal to `mandate_types::inventory::DERIVED_STATE_ENUMS`,
//! which `tests/inventory.rs` asserts is exactly the `.State` half of the compiled index;
//! and each pair is asserted to be the type its element name *derives* to under ESS's own
//! `declaration_name` rule, because the procedure alone cannot tell paired enums apart —
//! 23 of the 36 declarations share a variant list with another, and every cross-pairing
//! among them passes every other assertion here unchanged.

use std::collections::BTreeSet;

use mandate_contract::entities;
use mandate_types::conformance::{self, Canonical, Case};
use mandate_types::inventory::{ACCEPTED, DERIVED_STATE_ENUMS, Owner};
use mandate_types::{
    Audience, AuthoritySubject, CorrelationId, CredentialId, CredentialProof, CredentialSecret,
    EpochSnapshotRef, OrganizationId, PrincipalId, SecurityEpochTarget, VerifiedContext,
};

const SCHEMA_TYPES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../generated/schema/types");

const UUID_PATTERN: &str =
    "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";
const BASE64_PATTERN: &str = "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$";

const SAMPLE_UUID: &str = "1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b";

fn schema_node(ess_name: &str) -> serde_json::Value {
    let path = format!("{SCHEMA_TYPES}/{ess_name}.schema.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
    let document: serde_json::Value = serde_json::from_str(&text).expect("schema is JSON");
    document["$defs"][ess_name].clone()
}

fn assert_uuid_lexical_form(text: &str) {
    assert_eq!(text.len(), 36, "uuid lexical form length: {text}");
    for (index, byte) in text.bytes().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            assert_eq!(byte, b'-', "uuid separator at {index}: {text}");
        } else {
            assert!(
                byte.is_ascii_hexdigit(),
                "uuid hex digit at {index}: {text}"
            );
        }
    }
}

fn assert_base64_lexical_form(text: &str) {
    assert_eq!(text.len() % 4, 0, "base64 quantum: {text}");
    let padding = text.bytes().rev().take_while(|byte| *byte == b'=').count();
    assert!(padding <= 2, "base64 padding: {text}");
    for byte in text.bytes().take(text.len() - padding) {
        assert!(
            byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/',
            "base64 alphabet: {text}"
        );
    }
}

/// Every `pattern` the projection declares is enforced here. A pattern this suite
/// does not know about is a failure, not a silent pass.
fn assert_pattern(pattern: &str, text: &str) {
    match pattern {
        UUID_PATTERN => assert_uuid_lexical_form(text),
        BASE64_PATTERN => assert_base64_lexical_form(text),
        other => panic!("no conformance check for declared pattern {other}"),
    }
}

fn assert_encoding_matches_schema(ess_name: &str, encoded: &str) {
    let node = schema_node(ess_name);
    let value: serde_json::Value = serde_json::from_str(encoded).expect("encoded form is JSON");

    if let Some(one_of) = node.get("oneOf") {
        let tag = node["x-ess-union-tag"]
            .as_str()
            .expect("declared union tag");
        let object = value.as_object().expect("union encodes as an object");
        assert_eq!(
            object.keys().collect::<Vec<_>>(),
            vec![tag, "value"],
            "{ess_name}: union wire shape"
        );
        let selected = object[tag].as_str().expect("union tag is a string");
        let titles: Vec<&str> = one_of
            .as_array()
            .expect("oneOf list")
            .iter()
            .map(|variant| variant["title"].as_str().expect("variant title"))
            .collect();
        assert!(
            titles.contains(&selected),
            "{ess_name}: unknown tag {selected}"
        );
        return;
    }

    match node["type"].as_str().expect("declared JSON type") {
        "string" => {
            let text = value.as_str().expect("encodes as a JSON string");
            if let Some(members) = node.get("enum") {
                let members = members.as_array().expect("enum list");
                assert!(
                    members.contains(&value),
                    "{ess_name}: {text} is not a declared variant"
                );
            }
            if let Some(pattern) = node.get("pattern") {
                assert_pattern(pattern.as_str().expect("pattern is a string"), text);
            }
        }
        "object" => {
            assert_eq!(
                node["additionalProperties"],
                serde_json::Value::Bool(false),
                "{ess_name}: closed record"
            );
            let object = value.as_object().expect("encodes as a JSON object");
            let properties = node["properties"].as_object().expect("declared properties");
            for key in object.keys() {
                assert!(
                    properties.contains_key(key),
                    "{ess_name}: undeclared field {key}"
                );
            }
            for required in node["required"].as_array().expect("required list") {
                let required = required.as_str().expect("required name");
                assert!(
                    object.contains_key(required),
                    "{ess_name}: missing {required}"
                );
            }
        }
        other => panic!("{ess_name}: unexpected declared JSON type {other}"),
    }
}

#[test]
fn every_realized_type_round_trips_and_matches_its_projection() {
    let cases: Vec<Case> = conformance::cases();
    assert!(!cases.is_empty(), "the conformance suite executed no case");
    for case in &cases {
        assert!(
            !case.encoded.is_empty(),
            "{}: no sample encoded",
            case.ess_name
        );
        for encoded in &case.encoded {
            assert_encoding_matches_schema(case.ess_name, encoded);
        }
    }
}

#[test]
fn the_realized_set_is_exactly_the_share_this_crate_owns() {
    let mut realized: Vec<&str> = conformance::cases()
        .iter()
        .map(|case| case.ess_name)
        .collect();
    realized.sort_unstable();
    let mut owned: Vec<&str> = ACCEPTED
        .iter()
        .filter(|accepted| accepted.owner == Owner::Types)
        .map(|accepted| accepted.ess_name)
        .collect();
    owned.sort_unstable();
    assert_eq!(realized, owned);
}

#[test]
fn identifiers_share_a_wire_form_without_sharing_a_type() {
    let principal = PrincipalId::parse(SAMPLE_UUID).expect("principal identifier");
    let organization = OrganizationId::parse(SAMPLE_UUID).expect("organization identifier");
    assert_eq!(
        serde_json::to_string(&principal).expect("encode"),
        serde_json::to_string(&organization).expect("encode"),
        "the declared wire form is shared"
    );
    // The type-level half of this observation is the compile_fail doctest pair in lib.rs.
    assert_eq!(principal.to_string(), SAMPLE_UUID);
    assert_eq!(organization.to_string(), SAMPLE_UUID);
}

#[test]
fn identifier_parsing_rejects_a_form_the_contract_does_not_declare() {
    assert!(PrincipalId::parse("not-a-uuid").is_err());
    assert!(PrincipalId::parse("").is_err());
    assert!(serde_json::from_str::<PrincipalId>("\"not-a-uuid\"").is_err());
    assert!(serde_json::from_str::<PrincipalId>("0").is_err());
}

#[test]
fn identifiers_serialize_in_the_canonical_lower_case_form() {
    let upper = "1B4E28BA-2FA1-4D8E-B1B0-8C1D4E5F6A7B";
    let parsed = PrincipalId::parse(upper).expect("uppercase input is accepted");
    assert_eq!(
        serde_json::to_string(&parsed).expect("encode"),
        format!("\"{SAMPLE_UUID}\""),
        "serialization is canonical, not input-shaped"
    );
}

#[test]
fn transient_credential_values_never_render_their_bytes() {
    let secret = CredentialSecret::from_bytes(b"top-secret-material".to_vec());
    let proof = CredentialProof::from_bytes(b"top-secret-material".to_vec());
    for rendered in [format!("{secret:?}"), format!("{proof:?}")] {
        assert!(
            !rendered.contains("top-secret"),
            "debug output leaked: {rendered}"
        );
        assert!(
            !rendered.contains("dG9wLXNlY3JldA"),
            "debug output leaked: {rendered}"
        );
        assert!(
            rendered.contains("redacted"),
            "debug output is not marked: {rendered}"
        );
    }
}

#[test]
fn transient_credential_values_cross_the_boundary_only_through_a_named_call() {
    let secret = CredentialSecret::from_bytes(b"abc".to_vec());

    // Ambient serialization is reachable by every container that derives `Serialize`,
    // including one declared outside this crate, so it never carries the material.
    assert_eq!(
        serde_json::to_string(&secret).expect("encode"),
        format!("\"{}\"", mandate_types::REDACTED)
    );
    assert!(
        serde_json::from_str::<CredentialSecret>(&format!("\"{}\"", mandate_types::REDACTED))
            .is_err(),
        "the redaction marker must not decode back into a credential"
    );

    // The declared base64 form is reached by naming a route; this is one of the three.
    let encoded = Canonical::encode(&secret).expect("encode");
    assert_eq!(encoded, "\"YWJj\"");
    assert_eq!(CredentialSecret::decode(&encoded).expect("decode"), secret);
    assert!(CredentialSecret::decode("\"not base64!\"").is_err());
}

/// The class the wrapper case belongs to: `mandate-model`'s adversary suite shows a
/// downstream crate can launder a transient type past `canonical_record!` inside its own
/// generic wrapper, because the orphan rule permits `impl PersistedValue for
/// Envelope<CredentialSecret>`. Whatever container reaches `Serialize`, the material does
/// not follow.
#[test]
fn no_container_puts_transient_credential_material_on_the_wire() {
    #[derive(serde::Serialize)]
    struct Envelope<T>(T);

    #[derive(serde::Serialize)]
    struct Nested<T> {
        held: Vec<Option<T>>,
    }

    let secret = CredentialSecret::from_bytes(b"abc".to_vec());
    let proof = CredentialProof::from_bytes(b"abc".to_vec());
    let forms = [
        serde_json::to_string(&Envelope(&secret)).expect("encode"),
        serde_json::to_string(&Envelope(&proof)).expect("encode"),
        serde_json::to_string(&Nested {
            held: vec![Some(&secret)],
        })
        .expect("encode"),
        serde_json::to_string(&vec![&secret]).expect("encode"),
        serde_json::to_string(&Some(&proof)).expect("encode"),
    ];
    for form in forms {
        assert!(
            !form.contains("YWJj"),
            "credential material reached a wire form through a container: {form}"
        );
        assert!(
            form.contains(mandate_types::REDACTED),
            "not redacted: {form}"
        );
    }
}

#[test]
fn an_absent_optional_field_stays_absent_across_a_round_trip() {
    let context = VerifiedContext {
        subject: PrincipalId::parse(SAMPLE_UUID).expect("subject"),
        actor: None,
        organization: OrganizationId::parse(SAMPLE_UUID).expect("organization"),
        audience: Audience::new("mandate"),
        credential: CredentialId::parse(SAMPLE_UUID).expect("credential"),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("correlation"),
    };
    let encoded = serde_json::to_string(&context).expect("encode");
    assert!(
        !encoded.contains("actor"),
        "an absent actor must not be written: {encoded}"
    );
    let decoded: VerifiedContext = serde_json::from_str(&encoded).expect("decode");
    assert_eq!(decoded, context);

    let mut present = context.clone();
    present.actor = Some(PrincipalId::parse(SAMPLE_UUID).expect("actor"));
    let encoded = serde_json::to_string(&present).expect("encode");
    assert!(
        encoded.contains("\"actor\""),
        "a present actor must be written: {encoded}"
    );
    let decoded: VerifiedContext = serde_json::from_str(&encoded).expect("decode");
    assert_eq!(decoded.actor, present.actor);
}

#[test]
fn a_closed_record_rejects_a_field_the_contract_does_not_declare() {
    let encoded = "{\"resource_type\":\"document\",\"resource_id\":\"1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b\",\"tenant\":\"x\"}";
    assert!(serde_json::from_str::<mandate_types::ResourceRef>(encoded).is_err());
}

#[test]
fn a_union_uses_the_declared_tag_and_carries_no_numeric_content() {
    let subject = AuthoritySubject::Principal(PrincipalId::parse(SAMPLE_UUID).expect("principal"));
    assert_eq!(
        serde_json::to_string(&subject).expect("encode"),
        format!("{{\"kind\":\"principal\",\"value\":\"{SAMPLE_UUID}\"}}")
    );
    let target =
        SecurityEpochTarget::Organization(OrganizationId::parse(SAMPLE_UUID).expect("target"));
    let encoded = serde_json::to_string(&target).expect("encode");
    assert_eq!(
        encoded,
        format!("{{\"kind\":\"organization\",\"value\":\"{SAMPLE_UUID}\"}}")
    );
    let value: serde_json::Value = serde_json::from_str(&encoded).expect("decode");
    assert!(
        value["value"].is_string(),
        "a security epoch target carries a reference, never a generation number"
    );
    assert!(
        serde_json::from_str::<SecurityEpochTarget>("{\"kind\":\"generation\",\"value\":7}")
            .is_err()
    );
}

#[test]
fn an_epoch_snapshot_reference_stays_an_opaque_record_handle() {
    let handle = EpochSnapshotRef::parse(SAMPLE_UUID).expect("snapshot handle");
    assert_eq!(
        serde_json::to_string(&handle).expect("encode"),
        format!("\"{SAMPLE_UUID}\"")
    );
    assert!(serde_json::from_str::<EpochSnapshotRef>("1").is_err());
    // The absence of arithmetic is proved by the compile_fail doctest in lib.rs.
}

/// The route a container names when the contract requires it to carry credential
/// material: `generated/schema/commands` and `generated/schema/responses` `$ref` the two
/// transient types across twelve files, and
/// `systems/mandate/domains/credential.yaml:298` declares one of them optional.
///
/// Naming the helper is the whole difference. The `unnamed` field below is the same type
/// with no attribute, and it redacts.
#[test]
fn a_container_that_must_carry_credential_material_names_the_helper_at_the_field() {
    #[derive(serde::Serialize)]
    struct IssueResponse {
        #[serde(serialize_with = "mandate_types::value::declared_credential_form")]
        secret: CredentialSecret,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            serialize_with = "mandate_types::value::declared_optional_credential_form"
        )]
        proof: Option<CredentialProof>,
        unnamed: CredentialSecret,
    }

    let carried = IssueResponse {
        secret: CredentialSecret::from_bytes(b"abc".to_vec()),
        proof: Some(CredentialProof::from_bytes(b"abc".to_vec())),
        unnamed: CredentialSecret::from_bytes(b"abc".to_vec()),
    };
    assert_eq!(
        serde_json::to_string(&carried).expect("encode"),
        format!(
            "{{\"secret\":\"YWJj\",\"proof\":\"YWJj\",\"unnamed\":\"{}\"}}",
            mandate_types::REDACTED
        )
    );

    let absent = IssueResponse {
        secret: CredentialSecret::from_bytes(Vec::new()),
        proof: None,
        unnamed: CredentialSecret::from_bytes(Vec::new()),
    };
    let encoded = serde_json::to_string(&absent).expect("encode");
    assert!(
        !encoded.contains("proof"),
        "an absent optional stays absent: {encoded}"
    );
}

/// ESS's `declaration_name`, the rule that decides which Rust name an element takes.
///
/// Reproduced from `xtask/src/emit.rs:266-279`, which reproduces ESS 0.26.0's own rule:
/// split on every character Rust cannot carry, upper-case the first letter of each part,
/// and join. `mandate.tenancy.Organization.State` becomes
/// `MandateTenancyOrganizationState`.
fn declaration_name(ess_name: &str) -> String {
    let mut derived = String::new();
    for part in ess_name
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
    {
        let mut characters = part.chars();
        if let Some(first) = characters.next() {
            derived.push(first.to_ascii_uppercase());
            derived.push_str(characters.as_str());
        }
    }
    derived
}

/// One derived `<Entity>.State` enum, decided through the generated shape that realizes it.
struct StateEnum {
    /// The compiled declaration this case covers.
    ess_name: &'static str,
    /// The generated enum it is paired with, as `std::any::type_name` writes it.
    rust_name: &'static str,
    /// Read one declared variant back through the generated shape and re-serialize it.
    /// `None` when the shape refuses the variant.
    encode: fn(&str) -> Option<String>,
}

fn through_generated_shape<T: serde::Serialize + serde::de::DeserializeOwned>(
    variant: &str,
) -> Option<String> {
    let wire = serde_json::to_string(variant).expect("a variant name encodes as a JSON string");
    let decoded: T = serde_json::from_str(&wire).ok()?;
    Some(serde_json::to_string(&decoded).expect("the generated shape encodes"))
}

/// Pair each compiled `<Entity>.State` declaration with the generated enum that realizes it.
///
/// The table is a literal, and a literal pairing is a claim, not evidence: the procedure
/// reads the variants out of the file named on the left and pushes them through the type
/// named on the right, and where two declarations carry the same variant list — 23 of the
/// 36 do — the right side can name another element's enum with nothing failing. So the
/// Rust name is captured here and
/// `every_derived_state_enum_joins_the_per_type_schema_account` asserts it is the name the
/// left side derives to.
macro_rules! state_enums {
    ($($ess:literal => $shape:ty),+ $(,)?) => {
        fn state_enums() -> Vec<StateEnum> {
            vec![$(StateEnum {
                ess_name: $ess,
                rust_name: std::any::type_name::<$shape>(),
                encode: through_generated_shape::<$shape>,
            }),+]
        }
    };
}

state_enums! {
    "mandate.audit.AuditEvent.State" => entities::MandateAuditAuditEventState,
    "mandate.credential.AccessCredential.State" => entities::MandateCredentialAccessCredentialState,
    "mandate.credential.AuthorizationCode.State" => entities::MandateCredentialAuthorizationCodeState,
    "mandate.credential.ResourceServer.State" => entities::MandateCredentialResourceServerState,
    "mandate.credential.SigningKey.State" => entities::MandateCredentialSigningKeyState,
    "mandate.delegation.Agent.State" => entities::MandateDelegationAgentState,
    "mandate.delegation.AgentCapabilityCeiling.State" => entities::MandateDelegationAgentCapabilityCeilingState,
    "mandate.delegation.Approval.State" => entities::MandateDelegationApprovalState,
    "mandate.delegation.Delegation.State" => entities::MandateDelegationDelegationState,
    "mandate.delegation.Execution.State" => entities::MandateDelegationExecutionState,
    "mandate.directory.DirectoryGroup.State" => entities::MandateDirectoryDirectoryGroupState,
    "mandate.directory.DirectoryGroupMembership.State" => entities::MandateDirectoryDirectoryGroupMembershipState,
    "mandate.directory.DirectoryGroupTeamMapping.State" => entities::MandateDirectoryDirectoryGroupTeamMappingState,
    "mandate.directory.MembershipContribution.State" => entities::MandateDirectoryMembershipContributionState,
    "mandate.directory.SyncJob.State" => entities::MandateDirectorySyncJobState,
    "mandate.federation.ExternalPrincipal.State" => entities::MandateFederationExternalPrincipalState,
    "mandate.federation.FederationConnection.State" => entities::MandateFederationFederationConnectionState,
    "mandate.federation.OAuthClient.State" => entities::MandateFederationOAuthClientState,
    "mandate.graph.Grant.State" => entities::MandateGraphGrantState,
    "mandate.graph.Relation.State" => entities::MandateGraphRelationState,
    "mandate.graph.Resource.State" => entities::MandateGraphResourceState,
    "mandate.identity.FederationSecurityEpoch.State" => entities::MandateIdentityFederationSecurityEpochState,
    "mandate.identity.OrganizationSecurityEpoch.State" => entities::MandateIdentityOrganizationSecurityEpochState,
    "mandate.identity.Principal.State" => entities::MandateIdentityPrincipalState,
    "mandate.identity.PrincipalSecurityEpoch.State" => entities::MandateIdentityPrincipalSecurityEpochState,
    "mandate.identity.RefreshCredential.State" => entities::MandateIdentityRefreshCredentialState,
    "mandate.identity.SecurityEpochSnapshot.State" => entities::MandateIdentitySecurityEpochSnapshotState,
    "mandate.identity.Session.State" => entities::MandateIdentitySessionState,
    "mandate.policy.AuthorizationModel.State" => entities::MandatePolicyAuthorizationModelState,
    "mandate.policy.Policy.State" => entities::MandatePolicyPolicyState,
    "mandate.tenancy.Organization.State" => entities::MandateTenancyOrganizationState,
    "mandate.tenancy.OrganizationMembership.State" => entities::MandateTenancyOrganizationMembershipState,
    "mandate.tenancy.Space.State" => entities::MandateTenancySpaceState,
    "mandate.tenancy.Team.State" => entities::MandateTenancyTeamState,
    "mandate.tenancy.TeamMembership.State" => entities::MandateTenancyTeamMembershipState,
    "mandate.workload.WorkloadIdentity.State" => entities::MandateWorkloadWorkloadIdentityState,
}

#[test]
fn every_derived_state_enum_joins_the_per_type_schema_account() {
    let enums = state_enums();
    let covered: BTreeSet<&str> = enums.iter().map(|state| state.ess_name).collect();
    assert_eq!(covered.len(), enums.len(), "the account holds no duplicate");
    assert_eq!(
        covered,
        DERIVED_STATE_ENUMS
            .iter()
            .copied()
            .collect::<BTreeSet<&str>>(),
        "the state account is not the account tests/inventory.rs decides against the \
         compiled index",
    );

    let mut decided = 0_usize;
    for state in &enums {
        let node = schema_node(state.ess_name);
        assert_eq!(node["x-ess-kind"], "enum", "{}", state.ess_name);
        assert_eq!(
            node["x-ess-name"].as_str(),
            Some(state.ess_name),
            "{}: the compiled declaration this case reads names {}",
            state.ess_name,
            node["x-ess-name"],
        );

        // The pairing itself, by ESS's own derivation rule. Without this the procedure
        // below is blind to a right-hand side naming another element's enum.
        let derived = declaration_name(state.ess_name);
        let paired = state
            .rust_name
            .rsplit("::")
            .next()
            .expect("a Rust type path");
        assert_eq!(
            paired, derived,
            "{}: paired with {}, which is not the {derived} its name derives to",
            state.ess_name, state.rust_name,
        );
        assert!(
            state.rust_name.ends_with(&derived),
            "{}: {} does not end with {derived}",
            state.ess_name,
            state.rust_name,
        );
        let declared = node["enum"]
            .as_array()
            .unwrap_or_else(|| panic!("{}: no declared variants", state.ess_name))
            .clone();
        assert!(
            !declared.is_empty(),
            "{}: no declared variant",
            state.ess_name
        );
        for variant in &declared {
            let variant = variant.as_str().unwrap_or_else(|| {
                panic!("{}: a declared variant is not a string", state.ess_name)
            });
            let encoded = (state.encode)(variant).unwrap_or_else(|| {
                panic!(
                    "{}: the generated shape refuses the declared variant {variant}",
                    state.ess_name
                )
            });
            assert_eq!(
                encoded,
                format!("\"{variant}\""),
                "{}: {variant} does not re-serialize to itself",
                state.ess_name
            );
            assert_encoding_matches_schema(state.ess_name, &encoded);
            decided += 1;
        }
        assert!(
            (state.encode)("MandateUndeclaredVariant").is_none(),
            "{}: the generated shape accepted an undeclared variant",
            state.ess_name
        );
    }
    assert_eq!(enums.len(), 36, "derived state enums decided");
    assert_eq!(decided, 70, "declared variants decided");

    // The rule has to discriminate to be evidence: two declarations deriving to one Rust
    // name would leave a swap between them undetectable. ESS refuses that itself
    // (`name_collision`, reproduced at `xtask/src/emit.rs:505-528`); this is that refusal
    // over the derived half of the index.
    let derived: BTreeSet<String> = enums
        .iter()
        .map(|state| declaration_name(state.ess_name))
        .collect();
    assert_eq!(
        derived.len(),
        enums.len(),
        "two derived declarations reach one Rust name, so the pairing check cannot \
         discriminate between them",
    );
}

#[test]
fn no_derived_state_enum_reaches_the_accepted_account_of_this_crate() {
    for name in DERIVED_STATE_ENUMS {
        assert!(
            !ACCEPTED.iter().any(|accepted| accepted.ess_name == *name),
            "{name} entered the accepted account",
        );
        assert!(
            !conformance::cases()
                .iter()
                .any(|case| case.ess_name == *name),
            "{name} entered this crate's own realization registry",
        );
    }
}
