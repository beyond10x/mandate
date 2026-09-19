//! Adversary pass 2 against the emitter: the positions the round-1 refusals do not cover, the
//! refusals that do not name what they refuse, and the binding between the committed emission
//! and a fresh render of the committed model.
//!
//! Every doctored model below was first put through the real authoring surface: the same edit
//! written in `systems/mandate/domains/core.yaml` and compiled with `ess specify compile
//! --path mandate --format json` at ESS 0.26.0, which exits 0 for each of them. These are
//! declarations a contract author can write today, not shapes only a fixture can build.

#[allow(dead_code)] // the binary target uses the whole module; a case here uses part of it.
#[path = "../src/emit.rs"]
mod emit;

use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_owned()
}

/// The committed model: the emitter's only input.
fn model() -> Vec<u8> {
    fs::read(repo().join("generated/ir/system.json")).expect("the committed IR")
}

fn parsed() -> Value {
    serde_json::from_slice(&model()).expect("the committed IR parses")
}

fn doctored(model: &Value) -> Vec<u8> {
    serde_json::to_vec(model).expect("serialize")
}

/// The first emitted line carrying a needle, for a refusal that did not happen.
fn line_with(files: &BTreeMap<String, String>, needle: &str) -> String {
    for (name, body) in files {
        for line in body.lines() {
            if line.contains(needle) {
                return format!("{name}: {}", line.trim());
            }
        }
    }
    format!("no emitted line carries {needle:?}")
}

/// An `optional` in a position that is not a record key is refused, as one inside a list is.
///
/// `nested_optional` refuses `optional` under `list` only, and `positions()` walks three more
/// places an `optional` can sit: a union variant, the value a newtype wraps, and another
/// `optional`. ESS 0.26.0 compiles all three (measured), and its own JSON Schema projection
/// spells them as `null` (newtype: `anyOf: [$ref, {"type": "null"}]`) or as a content key
/// dropped from `required` (union) — neither of which `Presence` can read or write. The
/// emitter writes those shapes instead of refusing them.
#[test]
fn an_optional_outside_a_record_key_is_refused() {
    let optional = serde_json::json!({
        "kind": "optional",
        "of": {"kind": "declared", "name": "mandate.core.PrincipalId"},
    });

    let mut union = parsed();
    union["types"]["mandate.core.AuthoritySubject"]["body"]["variants"]["principal"] =
        optional.clone();

    let mut newtype = parsed();
    newtype["types"]["mandate.core.Audience"]["body"]["of"] = optional.clone();

    let mut nested = parsed();
    {
        let fields = nested["types"]["mandate.core.VerifiedContext"]["body"]["fields"]
            .as_array_mut()
            .expect("the struct's fields");
        for field in fields.iter_mut() {
            if field["name"] == "actor" {
                let inner = field["type_ref"].clone();
                field["type_ref"] = serde_json::json!({"kind": "optional", "of": inner});
            }
        }
    }

    let mut emitted = Vec::new();
    for (position, declaration, doctored_model, needle) in [
        (
            "a union variant",
            "mandate.core.AuthoritySubject",
            union,
            "Principal(Presence<",
        ),
        (
            "the value a newtype wraps",
            "mandate.core.Audience",
            newtype,
            "pub struct MandateCoreAudience(pub Presence<",
        ),
        (
            "an optional inside an optional",
            "mandate.core.VerifiedContext",
            nested,
            "Presence<Presence<",
        ),
    ] {
        match emit::render(&doctored(&doctored_model)) {
            Ok(files) => emitted.push(format!(
                "{position}: the emitter emitted `{}` instead of refusing {declaration}",
                line_with(&files, needle)
            )),
            Err(refusal) => assert!(
                refusal.to_string().contains(declaration),
                "{position}: the refusal does not name {declaration}: {refusal}"
            ),
        }
    }
    assert!(
        emitted.is_empty(),
        "an optional was emitted outside a record key:\n{}",
        emitted.join("\n")
    );
}

/// Every refusal names the declaration that caused it, as the keyword refusal does.
///
/// `a_name_rust_cannot_take_is_refused` asserts the refusal carries
/// `mandate.identity.SessionRevoked`, and the emitter's own doc gives the reason: a failure
/// reported against a generated file instead of against the declaration is what the whole
/// module exists to prevent. Two refusals in the same enumeration do not name it.
#[test]
fn a_refusal_names_the_declaration_that_caused_it() {
    let mut anonymous = Vec::new();
    for (reason, type_ref) in [
        (
            "an unmapped primitive",
            serde_json::json!({"kind": "primitive", "name": "decimal"}),
        ),
        (
            "an unmapped type expression",
            serde_json::json!({"kind": "map", "of": {"kind": "primitive", "name": "string"}}),
        ),
    ] {
        let mut model = parsed();
        model["events"]["mandate.identity.SessionRevoked"]["fields"]
            .as_array_mut()
            .expect("event fields")
            .push(serde_json::json!({
                "name": "rate",
                "type_ref": type_ref,
                "naming": {},
            }));
        let refusal = emit::render(&doctored(&model))
            .expect_err("the emitter refuses what it cannot map")
            .to_string();
        if !refusal.contains("mandate.identity.SessionRevoked") {
            anonymous.push(format!("{reason}: {refusal}"));
        }
    }
    assert!(
        anonymous.is_empty(),
        "a refusal does not name the declaration that carries it:\n{}",
        anonymous.join("\n")
    );
}

/// A reference to nothing is refused through a wrapper chain, not only in a bare position.
///
/// Round 1's cases put the undeclared name directly in `type_ref`. `declared_names` recurses
/// through `optional` and `list`, and a chain is the position where a walk that stopped at the
/// outermost expression would read "this declaration names nothing undeclared".
#[test]
fn a_dangling_reference_is_refused_through_an_optional_list_chain() {
    let mut model = parsed();
    model["events"]["mandate.identity.SessionRevoked"]["fields"]
        .as_array_mut()
        .expect("event fields")[0]["type_ref"] = serde_json::json!({
        "kind": "optional",
        "of": {
            "kind": "list",
            "of": {"kind": "declared", "name": "mandate.core.NotDeclared"},
        },
    });
    let refusal = emit::render(&doctored(&model))
        .expect_err("a reference to nothing is refused through a chain")
        .to_string();
    assert!(refusal.contains("mandate.core.NotDeclared"), "{refusal}");
    assert!(refusal.contains("context"), "{refusal}");
    assert!(
        refusal.contains("mandate.identity.SessionRevoked"),
        "{refusal}"
    );
}

/// A declared type whose Rust name is an entity's injected state enum is refused as a collision.
///
/// `mandate.identity.Principal.State` is emitted into `entities.rs` and every other declared
/// type into `types.rs`, so a collision between the two lands in different modules and the
/// compiler reports neither. `mandate.identity.PrincipalState` reaches the same Rust name.
#[test]
fn a_type_named_for_an_injected_state_enum_is_refused_as_a_collision() {
    let mut model = parsed();
    model["types"]["mandate.identity.PrincipalState"] = serde_json::json!({
        "name": "mandate.identity.PrincipalState",
        "body": {"kind": "newtype", "of": {"kind": "primitive", "name": "string"}},
        "naming": {},
    });
    let refusal = emit::render(&doctored(&model))
        .expect_err("two declarations that become one Rust name are refused")
        .to_string();
    assert!(
        refusal.contains("MandateIdentityPrincipalState"),
        "{refusal}"
    );
    assert!(
        refusal.contains("mandate.identity.Principal.State"),
        "{refusal}"
    );
    assert!(
        refusal.contains("mandate.identity.PrincipalState"),
        "{refusal}"
    );
}

/// The committed emission is byte-for-byte a fresh render of the committed model.
///
/// Nothing else in either suite reads `generated/rust/**` and compares it to the emitter.
/// `emit_writes_the_four_files_under_the_generated_root` writes a fixture root and compares it
/// to `render`, and the crate's cases compile the committed files without asserting where they
/// came from — so a hand-edit of a committed file is answered by `cargo xtask contracts`, which
/// needs `ess` and a full regeneration, and by nothing in `cargo test`.
#[test]
fn the_committed_emission_is_exactly_what_the_committed_model_renders() {
    let files = emit::render(&model()).expect("the committed IR emits");
    let directory = repo().join("generated/rust/mandate-contract/src");
    for (name, body) in &files {
        let path = directory.join(name);
        let committed =
            fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        assert_eq!(
            committed, *body,
            "{name} is not what the committed model renders"
        );
    }
}

/// What a declared position holds, on either side of the two projections.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Shape {
    Optional(Box<Shape>),
    List(Box<Shape>),
    Text,
    Integer,
    Boolean,
    Named(String),
}

/// The shape an emitted Rust type states.
fn rust_shape(rust: &str) -> Shape {
    let rust = rust.trim();
    for carrier in ["super::types::Presence<", "Presence<"] {
        if let Some(inner) = rust.strip_prefix(carrier).and_then(|r| r.strip_suffix('>')) {
            return Shape::Optional(Box::new(rust_shape(inner)));
        }
    }
    if let Some(inner) = rust.strip_prefix("Vec<").and_then(|r| r.strip_suffix('>')) {
        return Shape::List(Box::new(rust_shape(inner)));
    }
    match rust {
        "String" => Shape::Text,
        "bool" => Shape::Boolean,
        "::serde_json::Number" => Shape::Integer,
        other => Shape::Named(
            other
                .rsplit("::")
                .next()
                .expect("a Rust type name")
                .to_owned(),
        ),
    }
}

/// The shape a JSON Schema property states.
fn schema_shape(property: &Value) -> Shape {
    if let Some(reference) = property["$ref"].as_str() {
        let declared = reference.rsplit('/').next().expect("a $ref target");
        return Shape::Named(emit::declaration_name(declared));
    }
    match property["type"].as_str() {
        Some("array") => Shape::List(Box::new(schema_shape(&property["items"]))),
        Some("integer") => Shape::Integer,
        Some("boolean") => Shape::Boolean,
        Some("string") => Shape::Text,
        _ => panic!("unmapped schema property: {property}"),
    }
}

/// Every emitted record, by Rust name, with the shape of each of its keys.
fn emitted_records(files: &BTreeMap<String, String>) -> BTreeMap<String, BTreeMap<String, Shape>> {
    let mut records = BTreeMap::new();
    for body in files.values() {
        let mut open: Option<(String, BTreeMap<String, Shape>)> = None;
        for line in body.lines() {
            if let Some(rest) = line.strip_prefix("pub struct ") {
                if let Some(name) = rest.strip_suffix(" {") {
                    open = Some((name.to_owned(), BTreeMap::new()));
                } else if let Some(name) = rest.strip_suffix(" {}") {
                    records.insert(name.to_owned(), BTreeMap::new());
                }
                continue;
            }
            if line == "}" {
                if let Some((name, fields)) = open.take() {
                    records.insert(name, fields);
                }
                continue;
            }
            if let Some((_, fields)) = open.as_mut()
                && let Some(rest) = line.strip_prefix("    pub ")
                && let Some((name, rust)) = rest.trim_end_matches(',').split_once(": ")
            {
                fields.insert(name.to_owned(), rust_shape(rust));
            }
        }
    }
    records
}

/// Every emitted record key carries the type its JSON Schema projection states, not only its
/// name and whether it is optional.
///
/// `every_emitted_record_agrees_with_its_json_schema_projection` compares key sets and
/// required-ness. It does not read either side's type, so an `integer` emitted as a `String`,
/// a `$ref` emitted as the wrong declaration or a `list` emitted flat is a document the two
/// projections disagree about and both suites pass.
#[test]
fn every_emitted_field_carries_the_type_its_schema_projects() {
    let records = emitted_records(&emit::render(&model()).expect("the committed IR emits"));
    let mut checked = 0usize;
    let mut claimed = BTreeSet::new();
    let compare = |rust: &str, root: &Value, checked: &mut usize| {
        let found = records
            .get(rust)
            .unwrap_or_else(|| panic!("{rust} is not an emitted record"));
        let required = root["required"]
            .as_array()
            .map(|values| {
                values
                    .iter()
                    .map(|value| value.as_str().expect("a required key").to_owned())
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        for (key, property) in root["properties"]
            .as_object()
            .expect("a record's properties")
        {
            let mut want = schema_shape(property);
            if !required.contains(key) {
                want = Shape::Optional(Box::new(want));
            }
            let got = found
                .get(key)
                .unwrap_or_else(|| panic!("{rust} carries no key {key}"));
            assert_eq!(*got, want, "{rust}.{key} is not what its schema projects");
            *checked += 1;
        }
    };
    for (kind, suffix) in [
        ("events", ""),
        ("entities", ""),
        ("commands", "Input"),
        ("responses", "Response"),
        ("errors", ""),
    ] {
        let directory = repo().join("generated/schema").join(kind);
        for entry in fs::read_dir(&directory).expect("a schema directory") {
            let path = entry.expect("a schema file").path();
            let declared = path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_suffix(".schema.json"))
                .expect("a schema file name")
                .to_owned();
            let schema: Value =
                serde_json::from_slice(&fs::read(&path).expect("read")).expect("a schema parses");
            let rust = format!("{}{suffix}", emit::declaration_name(&declared));
            compare(&rust, &schema, &mut checked);
            claimed.insert(rust);
        }
    }
    for entry in fs::read_dir(repo().join("generated/schema/types")).expect("a schema directory") {
        let path = entry.expect("a schema file").path();
        let declared = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".schema.json"))
            .expect("a schema file name")
            .to_owned();
        let schema: Value =
            serde_json::from_slice(&fs::read(&path).expect("read")).expect("a schema parses");
        let root = &schema["$defs"][&declared];
        if root["x-ess-kind"] == "struct" {
            let rust = emit::declaration_name(&declared);
            compare(&rust, root, &mut checked);
            claimed.insert(rust);
        }
    }
    assert_eq!(
        records.keys().cloned().collect::<BTreeSet<_>>(),
        claimed,
        "an emitted record was compared against no schema, or the reverse"
    );
    assert!(checked >= 656, "only {checked} keys were compared");
}
