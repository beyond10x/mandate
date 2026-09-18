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
use mandate_types::Transient;
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

/// The rendering a container reaches for a type whose `Serialize` is the declared form.
fn serde_rendering<T: Canonical>(sample: &T) -> String {
    serde_json::to_string(sample).expect("serde serialization")
}

/// The rendering a container reaches for a transient credential type.
///
/// A bare `#[derive(Serialize)]` field redacts, by design and on purpose. A container that
/// must carry credential material names
/// [`mandate_types::value::declared_credential_form`] at the field with
/// `#[serde(serialize_with = ...)]`; this is that container, in the shape a realized
/// command or response envelope has. What is returned is the field's own JSON, so the
/// comparison against the declared pattern is the same comparison the other rendering gets.
fn declared_field_rendering<T: Canonical + Transient + Clone>(sample: &T) -> String {
    #[derive(serde::Serialize)]
    struct Envelope<T: Transient> {
        #[serde(serialize_with = "mandate_types::value::declared_credential_form")]
        credential: T,
    }

    let envelope = serde_json::to_string(&Envelope {
        credential: sample.clone(),
    })
    .expect("serde serialization");
    let value: serde_json::Value = serde_json::from_str(&envelope).expect("JSON");
    serde_json::to_string(&value["credential"]).expect("JSON")
}

/// Decide one admitted type's rendering against the form its projection declares, and
/// report each sample that does not satisfy it.
///
/// **Changed in round 3 by the implementor, at the coordinator's instruction.** As first
/// written this took no `render` argument and always used `serde_json::to_string`, which
/// is the rendering every derived container reaches. That found a real defect — the two
/// transient credential types render `mandate_types::REDACTED`, which the declared base64
/// pattern refuses — but the only way to satisfy it as written was to drop the redaction,
/// and the redaction is what keeps credential material out of a record that laundered the
/// type past `canonical_record!` (`crates/mandate-model/tests/adversary.rs:79`). The fix
/// shipped instead was a `serialize_with` helper, so a container that must carry the
/// material names it at the field and a container that says nothing still redacts. This
/// case now decides the helper's output for those two types and the derived serialization
/// for the rest; the comparison against the projection, and the assertion below, are
/// unchanged.
fn projection_violations<T: Canonical>(failures: &mut Vec<String>, render: fn(&T) -> String) {
    let name = <T as Canonical>::ESS_NAME;
    let node = declared_node(name);
    let Some(pattern) = node.get("pattern").and_then(serde_json::Value::as_str) else {
        return;
    };
    for sample in T::samples() {
        let serialized = render(&sample);
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
                "{name}: renders {serialized}, which the declared pattern {pattern} refuses"
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
/// The first two calls below are controls: admitted types with a declared pattern whose
/// derived serialization satisfies it, rendered the same way a container renders them.
/// The last two are the subjects, rendered the way a container that carries credential
/// material has to render them.
#[test]
fn every_admitted_type_serializes_into_the_form_its_projection_declares() {
    let mut failures = Vec::new();
    projection_violations::<PrincipalId>(&mut failures, serde_rendering);
    projection_violations::<EpochSnapshotRef>(&mut failures, serde_rendering);
    projection_violations::<CredentialSecret>(&mut failures, declared_field_rendering);
    projection_violations::<CredentialProof>(&mut failures, declared_field_rendering);
    assert!(
        failures.is_empty(),
        "admitted types whose serde serialization is not the declared form: {failures:#?}"
    );
}

/// **Changed in round 3 by the implementor, at the coordinator's instruction.** As first
/// written this asserted that `WireContract::to_wire` does not render credential material,
/// quoting `crates/mandate-types/src/macros.rs:164-165` — "The declared base64 form is
/// reachable only through [`Canonical::encode`]" — against
/// `crates/mandate-proto/src/lib.rs`, which passes all 74 admitted types, the two
/// transient ones among them, to `wire_contracts!`, and so gives each a public
/// `to_wire` in a crate `mandate-client` and `mandate-server` depend on.
///
/// The doc was the wrong half. `to_wire` on those two is kept: the projection names them
/// from six commands and six responses, this crate is where those cross, and a named call
/// on a named trait is what "explicit conversion" means here. Gating it would have taken
/// `WIRE_CONTRACTS` to 72 and turned `tests/adversary.rs` — which requires a contract for
/// every accepted type the projection puts on the wire — red.
///
/// So the sentences were corrected to name every route, and this case now decides that
/// route set: the two documented renderings carry the material, the ambient one does not,
/// and a route appearing or disappearing fails here.
///
/// `b"abc"` renders as `YWJj` in the declared base64 form.
#[test]
fn the_declared_credential_material_is_reachable_through_exactly_the_documented_routes() {
    let secret = CredentialSecret::from_bytes(b"abc".to_vec());
    let proof = CredentialProof::from_bytes(b"abc".to_vec());

    for (name, sanctioned, ambient) in [
        (
            "mandate.core.CredentialSecret",
            [
                Canonical::encode(&secret).expect("encode"),
                secret.to_wire().expect("encode"),
            ],
            serde_json::to_string(&secret).expect("serde serialization"),
        ),
        (
            "mandate.core.CredentialProof",
            [
                Canonical::encode(&proof).expect("encode"),
                proof.to_wire().expect("encode"),
            ],
            serde_json::to_string(&proof).expect("serde serialization"),
        ),
    ] {
        for rendering in sanctioned {
            assert_eq!(
                rendering, "\"YWJj\"",
                "{name}: a documented route stopped rendering the declared form"
            );
        }
        assert!(
            !ambient.contains("YWJj"),
            "{name}: the rendering every derived container reaches carried the material: {ambient}"
        );
        assert_eq!(
            ambient,
            format!("\"{}\"", mandate_types::REDACTED),
            "{name}: the ambient rendering is no longer the redaction"
        );
    }

    // The third documented route, and the only one a container reaches by declaring a
    // field: it renders the declared form, and omitting it still redacts.
    #[derive(serde::Serialize)]
    struct Envelope {
        #[serde(serialize_with = "mandate_types::value::declared_credential_form")]
        named: CredentialSecret,
        unnamed: CredentialSecret,
    }

    assert_eq!(
        serde_json::to_string(&Envelope {
            named: CredentialSecret::from_bytes(b"abc".to_vec()),
            unnamed: CredentialSecret::from_bytes(b"abc".to_vec()),
        })
        .expect("serde serialization"),
        format!(
            "{{\"named\":\"YWJj\",\"unnamed\":\"{}\"}}",
            mandate_types::REDACTED
        )
    );
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
