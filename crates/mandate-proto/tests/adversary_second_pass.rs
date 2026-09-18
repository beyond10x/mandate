//! Second adversarial pass over `story:canonical-types`.
//!
//! Every case here is driven from a document this unit wrote about itself — the ESS
//! projection it claims to realize, and the doc comments it shipped beside the code — and
//! run against the code the same unit wrote. Nothing here is an opinion.
//!
//! This crate is the only one in the workspace that can reach all four: `mandate-types`,
//! `mandate-model`, `mandate-token` and its own wire surface.

use std::collections::BTreeSet;

use mandate_model::{AuditRecord, Decision, DecisionChallenge, TenantResolutionRule};
use mandate_proto::WireContract;
use mandate_token::{CredentialDescriptor, CredentialProfile};
use mandate_types::conformance::Canonical;
use mandate_types::{
    AuthorityScope, CredentialProof, CredentialSecret, EpochSnapshotRef, PrincipalId, ResourceRef,
    VerifiedContext,
};

const SCHEMA_TYPES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../generated/schema/types");

const UUID_PATTERN: &str =
    "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";
const BASE64_PATTERN: &str = "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$";

fn declared_node(ess_name: &str) -> serde_json::Value {
    let path = format!("{SCHEMA_TYPES}/{ess_name}.schema.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
    let document: serde_json::Value = serde_json::from_str(&text).expect("schema is JSON");
    document["$defs"][ess_name].clone()
}

/// The declared base64 lexical form, decided without a regex engine.
///
/// `^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`, read as: a run of
/// whole four-character quanta, optionally followed by a short final quantum padded to
/// four with `=`.
fn matches_base64_pattern(text: &str) -> bool {
    let (body, remainder) = if let Some(stripped) = text.strip_suffix("==") {
        (stripped, 2usize)
    } else if let Some(stripped) = text.strip_suffix('=') {
        (stripped, 3usize)
    } else {
        (text, 0usize)
    };
    if body.len() < remainder {
        return false;
    }
    if (body.len() - remainder) % 4 != 0 {
        return false;
    }
    body.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
}

/// The declared UUID lexical form, decided without a regex engine.
fn matches_uuid_pattern(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

/// Decide one admitted type's `serde` serialization against the form its projection
/// declares, and report each sample that does not satisfy it.
///
/// `serde::Serialize` is the only rendering a container reaches. Every record in this
/// workspace is `#[derive(Serialize)]`, and a container declared over a type parameter —
/// which is what a realized command or response envelope is — has no other route to the
/// value inside it.
fn projection_violations<T: Canonical>(failures: &mut Vec<String>) {
    let name = <T as Canonical>::ESS_NAME;
    let node = declared_node(name);
    let Some(pattern) = node.get("pattern").and_then(serde_json::Value::as_str) else {
        return;
    };
    for sample in T::samples() {
        let serialized = serde_json::to_string(&sample).expect("serde serialization");
        let value: serde_json::Value = serde_json::from_str(&serialized).expect("JSON");
        let Some(text) = value.as_str() else {
            failures.push(format!(
                "{name}: serializes as {serialized}; the projection declares a string"
            ));
            continue;
        };
        let satisfied = match pattern {
            UUID_PATTERN => matches_uuid_pattern(text),
            BASE64_PATTERN => matches_base64_pattern(text),
            other => panic!("{name}: no check for the declared pattern {other}"),
        };
        if !satisfied {
            failures.push(format!(
                "{name}: serde renders {serialized}, which the declared pattern {pattern} refuses"
            ));
        }
    }
}

/// The unit's acceptance statement, asserted directly:
///
/// > Given the accepted ESS type set, when the canonical Rust conformance suite
/// > **serializes** and decodes each admitted type, then the canonical type conformance
/// > suite exits zero.
///
/// `crates/mandate-types/src/conformance.rs:100` is the suite that discharges it, and it
/// does not serialize: it calls `Canonical::encode`, whose default *is* the serialization
/// for 72 of the 74 admitted types and is an override for the other two
/// (`crates/mandate-types/src/macros.rs:239`). `Case::encoded`, which every crate-level
/// projection check reads, therefore holds a form `serde` never produces for exactly the
/// two types where the two disagree.
///
/// `generated/schema/types/mandate.core.CredentialSecret.schema.json` declares
/// `{"type":"string","pattern":"^(?:[A-Za-z0-9+/]{4})*…","contentEncoding":"base64"}`, and
/// `…CredentialProof.schema.json` declares the same node. `crates/mandate-types/src/lib.rs:131`
/// chooses `REDACTED` precisely because it "is not a form the contract declares".
///
/// The first two calls below are controls: they are admitted types with a declared
/// pattern whose serialization satisfies it. Only the type argument differs between a
/// control and a subject.
#[test]
fn every_admitted_type_serializes_into_the_form_its_projection_declares() {
    let mut failures = Vec::new();
    projection_violations::<PrincipalId>(&mut failures);
    projection_violations::<EpochSnapshotRef>(&mut failures);
    projection_violations::<CredentialSecret>(&mut failures);
    projection_violations::<CredentialProof>(&mut failures);
    assert!(
        failures.is_empty(),
        "admitted types whose serde serialization is not the declared form: {failures:#?}"
    );
}

/// `crates/mandate-types/src/macros.rs:164-165`, on the transient credential types:
/// "The declared base64 form is reachable only through
/// [`crate::conformance::Canonical::encode`]." `:205-206` restates it: "The declared
/// base64 form is reachable through [`crate::conformance::Canonical::encode`], which
/// nothing derives."
///
/// `crates/mandate-proto/src/lib.rs:170` passes all 74 admitted types, the two transient
/// ones among them, to `wire_contracts!`. That macro gives each a
/// [`WireContract::to_wire`], a public method on a public trait in the crate
/// `dependency-boundaries.json` has `mandate-client` and `mandate-server` depending on.
/// A caller that never names `Canonical` gets the material from it.
///
/// `b"abc"` renders as `YWJj` in the declared base64 form.
#[test]
fn the_declared_credential_material_is_not_reachable_without_naming_canonical() {
    let secret = CredentialSecret::from_bytes(b"abc".to_vec());
    let proof = CredentialProof::from_bytes(b"abc".to_vec());
    for (name, wire) in [
        (
            "mandate.core.CredentialSecret",
            secret.to_wire().expect("encode"),
        ),
        (
            "mandate.core.CredentialProof",
            proof.to_wire().expect("encode"),
        ),
    ] {
        assert!(
            !wire.contains("YWJj"),
            "{name}: WireContract::to_wire rendered the credential material: {wire}"
        );
    }
}

/// Which declared fields of one record the explicit-null walk actually reaches.
///
/// `crates/mandate-types/src/conformance.rs:152` walks the keys of each *encoded sample*,
/// so a declared field no sample ever sets is never tested. `:150-151` says why that is
/// held to be enough: "A record with optional fields declares samples for both the absent
/// and the present state, so every declared field of that record is reached." Nothing
/// enforces that sentence; this decides it against the projection's declared property set.
fn fields_the_null_walk_never_reaches<T: Canonical>(gaps: &mut Vec<String>) {
    let name = <T as Canonical>::ESS_NAME;
    let node = declared_node(name);
    let declared: BTreeSet<String> = node["properties"]
        .as_object()
        .expect("declared properties")
        .keys()
        .cloned()
        .collect();
    let mut reached: BTreeSet<String> = BTreeSet::new();
    for sample in T::samples() {
        let serialized = sample.encode().expect("encode");
        if let Ok(serde_json::Value::Object(object)) = serde_json::from_str(&serialized) {
            reached.extend(object.keys().cloned());
        }
    }
    for missing in declared.difference(&reached) {
        gaps.push(format!("{name}.{missing}"));
    }
}

/// Every one of the nine admitted records, so that the walk at
/// `crates/mandate-types/src/conformance.rs:152` is shown to be non-vacuous rather than
/// asserted to be.
#[test]
fn the_explicit_null_walk_reaches_every_field_every_record_declares() {
    let mut gaps = Vec::new();
    fields_the_null_walk_never_reaches::<ResourceRef>(&mut gaps);
    fields_the_null_walk_never_reaches::<AuthorityScope>(&mut gaps);
    fields_the_null_walk_never_reaches::<VerifiedContext>(&mut gaps);
    fields_the_null_walk_never_reaches::<CredentialDescriptor>(&mut gaps);
    fields_the_null_walk_never_reaches::<CredentialProfile>(&mut gaps);
    fields_the_null_walk_never_reaches::<TenantResolutionRule>(&mut gaps);
    fields_the_null_walk_never_reaches::<DecisionChallenge>(&mut gaps);
    fields_the_null_walk_never_reaches::<Decision>(&mut gaps);
    fields_the_null_walk_never_reaches::<AuditRecord>(&mut gaps);
    assert!(
        gaps.is_empty(),
        "declared fields no sample ever sets, so no explicit-null case covers them: {gaps:#?}"
    );
}
