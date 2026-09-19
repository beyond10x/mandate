//! Adversary pass 1 over `story:contract-shapes`: the emission read against ESS's own JSON
//! Schema projection of the same model, and against doctored models the emitter does not refuse.
//!
//! Two projections of one model have to agree, and nothing else in the tree compares them: the
//! byte-compare in `cargo xtask contracts` proves the emission is a fixed point of the emitter,
//! not that it says what `generated/schema/**` says.
#[allow(dead_code)]
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

fn model() -> Vec<u8> {
    fs::read(repo().join("generated/ir/system.json")).expect("the committed IR")
}

fn doctored(model: &Value) -> Vec<u8> {
    serde_json::to_vec(model).expect("serialize")
}

fn parsed_model() -> Value {
    serde_json::from_slice(&model()).expect("the committed IR parses")
}

/// One emitted `deny_unknown_fields` record: its field names, and which carry `Presence`.
#[derive(Debug, Default, PartialEq)]
struct Record {
    closed: bool,
    fields: BTreeMap<String, bool>,
}

/// One emitted adjacently tagged union.
#[derive(Debug, Default, PartialEq)]
struct Union {
    tag: String,
    content: String,
    variants: BTreeSet<String>,
}

#[derive(Debug, Default)]
struct Emitted {
    records: BTreeMap<String, Record>,
    enums: BTreeMap<String, Vec<String>>,
    unions: BTreeMap<String, Union>,
    transparent: BTreeSet<String>,
}

fn head(rest: &str) -> String {
    rest.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .next()
        .unwrap_or_default()
        .to_owned()
}

fn attribute(line: &str, key: &str) -> Option<String> {
    let start = line.find(key)? + key.len();
    let rest = &line[start..];
    let quoted = rest.strip_prefix(" = \"")?;
    Some(quoted[..quoted.find('"')?].to_owned())
}

/// Every declaration the four emitted files make, read back out of the text they emit.
fn read_emission(files: &BTreeMap<String, String>) -> Emitted {
    let mut emitted = Emitted::default();
    for body in files.values() {
        let lines: Vec<&str> = body.lines().collect();
        let mut index = 0;
        let mut attributes: Vec<&str> = Vec::new();
        while index < lines.len() {
            let line = lines[index];
            if line.starts_with("#[") {
                attributes.push(line);
                index += 1;
                continue;
            }
            if let Some(rest) = line.strip_prefix("pub struct ") {
                let name = head(rest);
                if rest.contains("{}") {
                    assert!(
                        emitted
                            .records
                            .insert(name.clone(), Record::default())
                            .is_none(),
                        "{name} is declared twice"
                    );
                } else if rest.contains('(') {
                    assert!(
                        emitted.transparent.insert(name.clone()),
                        "{name} is declared twice"
                    );
                } else {
                    let closed = attributes.iter().any(|a| a.contains("deny_unknown_fields"));
                    let mut fields = BTreeMap::new();
                    let mut optional = false;
                    index += 1;
                    while index < lines.len() && lines[index] != "}" {
                        let field = lines[index];
                        if field.contains("skip_serializing_if") {
                            optional = true;
                        } else if let Some(rest) = field.strip_prefix("    pub ") {
                            fields.insert(head(rest), optional);
                            optional = false;
                        }
                        index += 1;
                    }
                    assert!(
                        emitted
                            .records
                            .insert(name.clone(), Record { closed, fields })
                            .is_none(),
                        "{name} is declared twice"
                    );
                }
            } else if let Some(rest) = line.strip_prefix("pub enum ") {
                let name = head(rest);
                let tag = attributes.iter().find_map(|a| attribute(a, "tag"));
                let mut renames = Vec::new();
                index += 1;
                while index < lines.len() && lines[index] != "}" {
                    if let Some(rename) = attribute(lines[index], "rename") {
                        renames.push(rename);
                    }
                    index += 1;
                }
                match tag {
                    Some(tag) => {
                        let content = attributes
                            .iter()
                            .find_map(|a| attribute(a, "content"))
                            .expect("a union states its content key");
                        assert!(
                            emitted
                                .unions
                                .insert(
                                    name.clone(),
                                    Union {
                                        tag,
                                        content,
                                        variants: renames.into_iter().collect(),
                                    }
                                )
                                .is_none(),
                            "{name} is declared twice"
                        );
                    }
                    None => {
                        assert!(
                            emitted.enums.insert(name.clone(), renames).is_none(),
                            "{name} is declared twice"
                        );
                    }
                }
            }
            attributes.clear();
            index += 1;
        }
    }
    emitted
}

/// Every ESS schema file of one kind, by the declared name its file is called after.
fn schemas(kind: &str) -> BTreeMap<String, Value> {
    let directory = repo().join("generated/schema").join(kind);
    let mut out = BTreeMap::new();
    for entry in fs::read_dir(&directory).expect("a schema directory") {
        let path = entry.expect("a schema file").path();
        let name = path
            .file_name()
            .expect("a file name")
            .to_str()
            .expect("utf-8")
            .strip_suffix(".schema.json")
            .expect("a schema file name")
            .to_owned();
        let schema: Value =
            serde_json::from_slice(&fs::read(&path).expect("read")).expect("a schema parses");
        out.insert(name, schema);
    }
    out
}

/// What a JSON Schema object says a record is: its keys, and which of them are optional.
fn schema_record(schema: &Value) -> Record {
    let required = schema["required"]
        .as_array()
        .map(|values| {
            values
                .iter()
                .map(|v| v.as_str().expect("a required key").to_owned())
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    Record {
        closed: schema["additionalProperties"] == Value::Bool(false),
        fields: schema["properties"]
            .as_object()
            .expect("a record's properties")
            .keys()
            .map(|key| (key.clone(), !required.contains(key)))
            .collect(),
    }
}

/// The emitted record of every event, entity, command input, response and refusal is the record
/// its JSON Schema projection states, key for key, and closed exactly where the schema is closed.
#[test]
fn every_emitted_record_agrees_with_its_json_schema_projection() {
    let emitted = read_emission(&emit::render(&model()).expect("the committed IR emits"));
    let mut claimed = BTreeSet::new();
    for (kind, suffix) in [
        ("events", ""),
        ("entities", ""),
        ("commands", "Input"),
        ("responses", "Response"),
        ("errors", ""),
    ] {
        for (declared, schema) in schemas(kind) {
            let rust = format!("{}{suffix}", emit::declaration_name(&declared));
            let found = emitted
                .records
                .get(&rust)
                .unwrap_or_else(|| panic!("{declared} ({kind}) has no emitted record {rust}"));
            assert_eq!(
                *found,
                schema_record(&schema),
                "{rust} does not state what {declared}'s schema states"
            );
            claimed.insert(rust);
        }
    }
    for (declared, schema) in schemas("types") {
        let root = &schema["$defs"][&declared];
        let rust = emit::declaration_name(&declared);
        match root["x-ess-kind"].as_str().expect("an ESS kind") {
            "struct" => {
                let found = emitted
                    .records
                    .get(&rust)
                    .unwrap_or_else(|| panic!("{declared} has no emitted record"));
                assert_eq!(*found, schema_record(root), "{rust} drifts from its schema");
                claimed.insert(rust);
            }
            "newtype" => {
                assert!(
                    emitted.transparent.contains(&rust),
                    "{rust} is not an emitted transparent newtype"
                );
                claimed.insert(rust);
            }
            "enum" | "union" => {
                claimed.insert(rust);
            }
            other => panic!("unmapped ESS kind {other} in {declared}"),
        }
    }
    let declared = emitted
        .records
        .keys()
        .chain(emitted.transparent.iter())
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        declared.difference(&claimed).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "the emission declares a record no ESS schema projects"
    );
}

/// Every emitted enum carries exactly the values its schema admits, and every emitted union
/// carries the tag, the content key and the labels its schema's `oneOf` branches carry.
#[test]
fn every_emitted_enum_and_union_agrees_with_its_json_schema_projection() {
    let emitted = read_emission(&emit::render(&model()).expect("the committed IR emits"));
    let mut seen = 0;
    for (declared, schema) in schemas("types") {
        let root = &schema["$defs"][&declared];
        let rust = emit::declaration_name(&declared);
        match root["x-ess-kind"].as_str().expect("an ESS kind") {
            "enum" => {
                let values = root["enum"]
                    .as_array()
                    .unwrap_or_else(|| panic!("{declared} projects no enum"))
                    .iter()
                    .map(|v| v.as_str().expect("an enum value").to_owned())
                    .collect::<Vec<_>>();
                let found = emitted
                    .enums
                    .get(&rust)
                    .unwrap_or_else(|| panic!("{declared} has no emitted enum {rust}"));
                assert_eq!(*found, values, "{rust} does not carry its schema's values");
                seen += 1;
            }
            "union" => {
                let branches = root["oneOf"].as_array().expect("a union projects branches");
                let tag = root["x-ess-union-tag"]
                    .as_str()
                    .expect("a union states its tag")
                    .to_owned();
                let mut content = BTreeSet::new();
                let mut variants = BTreeSet::new();
                for branch in branches {
                    let properties = branch["properties"].as_object().expect("branch properties");
                    for key in properties.keys() {
                        if key != &tag {
                            content.insert(key.clone());
                        }
                    }
                    variants.insert(
                        properties[&tag]["const"]
                            .as_str()
                            .expect("a branch label")
                            .to_owned(),
                    );
                }
                assert_eq!(content.len(), 1, "{declared} projects one content key");
                let found = emitted
                    .unions
                    .get(&rust)
                    .unwrap_or_else(|| panic!("{declared} has no emitted union {rust}"));
                assert_eq!(
                    *found,
                    Union {
                        tag,
                        content: content.into_iter().next().expect("a content key"),
                        variants,
                    },
                    "{rust} does not encode its union the way its schema does"
                );
                seen += 1;
            }
            _ => {}
        }
    }
    assert_eq!(seen, 46, "44 enums and 2 unions are projected");
}

/// The emitter's refusal, or a panic naming the text it wrote instead of refusing.
fn refusal(
    emitted: std::result::Result<BTreeMap<String, String>, Box<dyn std::error::Error>>,
    file: &str,
    needle: &str,
) -> String {
    match emitted {
        Err(refusal) => refusal.to_string(),
        Ok(files) => panic!(
            "the emitter did not refuse; {file} carries:\n{}",
            files[file]
                .split("\n\n")
                .filter(|block| block.contains(needle))
                .take(3)
                .collect::<Vec<_>>()
                .join("\n")
        ),
    }
}

/// A declared name the model does not carry is a refusal, not a reference to nothing.
#[test]
fn a_declared_reference_the_model_does_not_carry_is_refused() {
    let mut model = parsed_model();
    model["events"]["mandate.identity.SessionRevoked"]["fields"][1]["type_ref"] =
        serde_json::json!({"kind": "declared", "name": "mandate.core.NotDeclaredAnywhere"});
    let refused = refusal(
        emit::render(&doctored(&model)),
        "events.rs",
        "NotDeclaredAnywhere",
    );
    assert!(
        refused.contains("mandate.core.NotDeclaredAnywhere"),
        "{refused}"
    );
}

/// Two declarations whose Rust names collide are a refusal, not two declarations of one name.
///
/// ESS refuses this itself (`name_collision`, `realize.rs:272` at tag 0.26.0), and the emitter
/// reproduces ESS's `declaration_name` without the guard that stands beside it.
#[test]
fn two_declarations_whose_rust_name_collides_are_refused() {
    let mut model = parsed_model();
    model["types"]["mandate.core.Space_Id"] = serde_json::json!({
        "name": "mandate.core.Space_Id",
        "body": {"kind": "newtype", "of": {"kind": "primitive", "name": "uuid"}, "invariants": []},
        "naming": {}
    });
    let refused = refusal(
        emit::render(&doctored(&model)),
        "types.rs",
        "pub struct MandateCoreSpaceId",
    );
    assert!(refused.contains("MandateCoreSpaceId"), "{refused}");
}

/// An entity that declares a field named `state` is a refusal, not a record with two of them.
#[test]
fn an_entity_field_that_collides_with_the_injected_lifecycle_state_is_refused() {
    let mut model = parsed_model();
    model["entities"]["mandate.identity.Principal"]["fields"]
        .as_array_mut()
        .expect("entity fields")
        .push(serde_json::json!({
            "name": "state",
            "type_ref": {"kind": "primitive", "name": "string"},
            "naming": {}
        }));
    let refused = refusal(
        emit::render(&doctored(&model)),
        "entities.rs",
        "pub state: String",
    );
    assert!(refused.contains("state"), "{refused}");
}

/// A list of an optional is a refusal: `Presence` has no meaning in a list position.
///
/// `Presence::Absent` has no JSON spelling outside a skipping field (it refuses to serialize,
/// per the round-1 ruling) and `Presence` refuses `null` on the way back, so a
/// `Vec<Presence<T>>` the emitter writes is a shape that cannot carry an absent element.
#[test]
fn a_list_of_an_optional_is_refused() {
    let mut model = parsed_model();
    model["events"]["mandate.identity.SessionRevoked"]["fields"]
        .as_array_mut()
        .expect("event fields")
        .push(serde_json::json!({
            "name": "prior_ids",
            "type_ref": {
                "kind": "list",
                "of": {"kind": "optional", "of": {"kind": "declared", "name": "mandate.core.SessionId"}}
            },
            "naming": {}
        }));
    let refused = refusal(
        emit::render(&doctored(&model)),
        "events.rs",
        "Vec<super::types::Presence<",
    );
    assert!(refused.contains("prior_ids"), "{refused}");
}

/// An entity whose lifecycle admits no state is a refusal, not a record nothing can be.
#[test]
fn an_entity_with_no_lifecycle_state_is_refused() {
    let mut model = parsed_model();
    model["entities"]["mandate.identity.Principal"]["lifecycle"]["states"] = serde_json::json!([]);
    model["types"]["mandate.identity.Principal.State"]["body"]["variants"] = serde_json::json!([]);
    let refused = refusal(
        emit::render(&doctored(&model)),
        "entities.rs",
        "MandateIdentityPrincipalState",
    );
    assert!(refused.contains("mandate.identity.Principal"), "{refused}");
}

/// A field named for a *reserved* keyword is a refusal too, not a file that will not parse.
///
/// `identifier` refuses Rust's 39 strict keywords. Edition 2024 also reserves `try`, `gen`,
/// `box`, `final`, `become`, `do`, `abstract`, `macro`, `override`, `priv`, `typeof`,
/// `unsized`, `virtual` and `yield`, and none of them can be a plain field name either:
/// `rustc --edition 2024` answers `expected identifier, found reserved keyword`.
#[test]
fn a_field_named_for_a_reserved_keyword_is_refused() {
    let mut model = parsed_model();
    model["events"]["mandate.identity.SessionRevoked"]["fields"]
        .as_array_mut()
        .expect("event fields")
        .push(serde_json::json!({
            "name": "try",
            "type_ref": {"kind": "declared", "name": "mandate.core.SessionId"},
            "naming": {}
        }));
    let refused = refusal(emit::render(&doctored(&model)), "events.rs", "pub try:");
    assert!(refused.contains("try"), "{refused}");
}
