//! Adversarial cases against the corrections `story:event-payloads-for-folds` made after
//! adversary pass 1 — the four directory seeding events, the two component publish lists,
//! `resource: mandate.core.ResourceRef` on the two graph events, and the residue the wave
//! records for itself.
//!
//! Same discipline as `adversary_fold_inputs.rs`, and the same reasons: the contract is
//! read by running `ess specify compile --path systems/mandate --format json` at test
//! time, never from `generated/`, which the coordinator regenerates after a unit merges
//! and which is therefore stale in a unit worktree. No dependency is added; `serde_json`
//! is already a dependency of this crate and ESS 0.25.0 is a prerequisite of
//! `cargo xtask check` (`AGENTS.md`).
//!
//! Pass 1 asserted that an event names the fields a fold needs **by name**. That reader
//! is too weak in both directions, and this file carries the stronger one: a field is
//! carried when some event field has the entity field's exact name *and* its exact type,
//! or when a struct the event carries has a member of that exact name and type. The one
//! struct it never descends into is `mandate.core.VerifiedContext`: its `subject` and
//! `actor` are the caller, and reading them as `mandate.delegation.Approval`'s `subject`
//! and `actor` — same names, same types, different records — would report a fold that
//! does not exist.

use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;
use std::sync::OnceLock;

const SYSTEM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../systems/mandate");

fn compiled() -> &'static Value {
    static MODEL: OnceLock<Value> = OnceLock::new();
    MODEL.get_or_init(|| {
        let output = Command::new("ess")
            .args(["specify", "compile", "--path", SYSTEM, "--format", "json"])
            .output()
            .unwrap_or_else(|error| {
                panic!(
                    "ess specify compile --path {SYSTEM} --format json: {error}. ESS 0.25.0 \
                     compiles this repository's contract (AGENTS.md) and cargo xtask check \
                     already requires it on PATH"
                )
            });
        assert!(
            output.status.success(),
            "ess specify compile: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("the compiled model is JSON")
    })
}

fn section(key: &str) -> &'static Map<String, Value> {
    compiled()[key]
        .as_object()
        .unwrap_or_else(|| panic!("the compiled model holds a {key} section"))
}

fn canonical(reference: &Value) -> String {
    match reference.get("kind").and_then(Value::as_str) {
        Some("declared" | "primitive") => reference["name"]
            .as_str()
            .expect("a named type reference")
            .to_owned(),
        Some("optional") => format!("Optional<{}>", canonical(&reference["of"])),
        Some("list") => format!("List<{}>", canonical(&reference["of"])),
        other => panic!("unmodelled type reference kind {other:?}"),
    }
}

fn fields_of(holder: &Value) -> Vec<(String, String)> {
    holder["fields"]
        .as_array()
        .expect("a fields array")
        .iter()
        .map(|field| {
            (
                field["name"].as_str().expect("a field name").to_owned(),
                canonical(&field["type_ref"]),
            )
        })
        .collect()
}

/// The members of a struct type, or nothing for a newtype, an enum or a union.
fn members(name: &str) -> Vec<(String, String)> {
    let Some(declared) = section("types").get(name) else {
        return Vec::new();
    };
    if declared["body"]["kind"].as_str() != Some("struct") {
        return Vec::new();
    }
    fields_of(&declared["body"])
}

fn identity_type(entity: &Value) -> String {
    canonical(&entity["identity"]["type_ref"])
}

fn transitions(entity: &Value) -> usize {
    entity
        .get("lifecycle")
        .and_then(|lifecycle| lifecycle.get("transitions"))
        .and_then(Value::as_array)
        .map_or(0, Vec::len)
}

fn pinned(entity: &Value) -> BTreeSet<String> {
    entity
        .get("invariants")
        .and_then(Value::as_array)
        .map(|invariants| {
            invariants
                .iter()
                .filter_map(Value::as_str)
                .filter_map(|text| {
                    let (left, right) = text.split_once("==")?;
                    let name = left.trim();
                    (!right.trim().is_empty() && !name.is_empty()).then(|| name.to_owned())
                })
                .collect()
        })
        .unwrap_or_default()
}

fn publisher_of() -> BTreeMap<String, String> {
    let mut publisher = BTreeMap::new();
    for (component, declared) in section("components") {
        for event in declared["publishes"].as_array().into_iter().flatten() {
            publisher.insert(
                event.as_str().expect("a published event name").to_owned(),
                component.clone(),
            );
        }
    }
    publisher
}

/// Every event that could create a row of `entity`: it carries the identity type, and
/// every declared field of the entity is on it under that field's own name and type —
/// directly, or as a member of a struct the event carries, or (for `organization_id`
/// alone) inside the `VerifiedContext` the event carries, which is the exemption the
/// coordinator tripwire states. A field an entity invariant pins to a literal is produced
/// from the invariant and is not looked for.
fn creating_events(entity: &Value) -> Vec<String> {
    let identity = identity_type(entity);
    let pinned = pinned(entity);
    let required: Vec<(String, String)> = fields_of(entity)
        .into_iter()
        .filter(|(name, _)| !pinned.contains(name))
        .collect();

    let mut creators = Vec::new();
    for (name, event) in section("events") {
        let carried = fields_of(event);
        if !carried.iter().any(|(_, kind)| *kind == identity) {
            continue;
        }
        let context = carried
            .iter()
            .any(|(_, kind)| kind == "mandate.core.VerifiedContext");
        let complete = required.iter().all(|(field, kind)| {
            if carried
                .iter()
                .any(|(carried, carried_kind)| carried == field && carried_kind == kind)
            {
                return true;
            }
            let descended = carried.iter().any(|(_, carried_kind)| {
                if carried_kind == "mandate.core.VerifiedContext" {
                    return false;
                }
                let base = carried_kind
                    .strip_prefix("List<")
                    .and_then(|rest| rest.strip_suffix('>'))
                    .unwrap_or(carried_kind);
                members(base)
                    .iter()
                    .any(|(member, member_kind)| member == field && member_kind == kind)
            });
            descended || (field == "organization_id" && context)
        });
        if complete {
            creators.push(name.clone());
        }
    }
    creators
}

/// Not a finding of its own: the guard. Every number and string is read from
/// `ess specify compile`.
#[test]
fn the_second_pass_reader_sees_the_contract_it_claims_to_see() {
    assert_eq!(section("events").len(), 72, "compiled events");
    assert_eq!(section("commands").len(), 59, "compiled commands");
    assert_eq!(section("types").len(), 110, "compiled type entries");
    assert_eq!(section("entities").len(), 36, "compiled entities");

    assert_eq!(
        members("mandate.core.ResourceRef"),
        vec![
            (
                "resource_type".to_owned(),
                "mandate.core.ResourceType".to_owned()
            ),
            (
                "resource_id".to_owned(),
                "mandate.core.ResourceId".to_owned()
            ),
        ],
        "a struct's members are read with their types, so descent is possible"
    );
    assert_eq!(
        members("mandate.core.CredentialProof"),
        Vec::new(),
        "a newtype has no members to descend into"
    );

    assert_eq!(
        publisher_of().get("mandate.directory.DirectoryGroupRecorded"),
        Some(&"mandate-control-plane".to_owned()),
        "component publish lists are read"
    );
    assert_eq!(
        section("components")["mandate-worker"]["owns"]
            .as_array()
            .expect("an owns array")
            .len(),
        1,
        "mandate-worker owns exactly one domain"
    );
    assert_eq!(
        pinned(&section("entities")["mandate.delegation.Delegation"]),
        BTreeSet::from(["transitive".to_owned()]),
        "an invariant pinning a field to a literal is read"
    );
}

/// A component's `owns:` is the contract's statement of which domain's records and events
/// are that deployment's. `publishes:` is what it writes. A component publishing an event
/// of a domain another component owns puts the writer of a record and the owner of its
/// domain in two deployments, and the contract then names no single place the record is
/// written — which is the property the whole story turns on.
///
/// `ess specify validate` accepts it, so nothing but this case reports it.
#[test]
fn every_component_publishes_only_events_of_a_domain_it_owns() {
    let events = section("events");
    let mut foreign: BTreeMap<String, String> = BTreeMap::new();
    for (component, declared) in section("components") {
        let owns: BTreeSet<&str> = declared["owns"]
            .as_array()
            .expect("an owns array")
            .iter()
            .map(|domain| domain.as_str().expect("a domain name"))
            .collect();
        for published in declared["publishes"].as_array().into_iter().flatten() {
            let event = published.as_str().expect("a published event name");
            let domain = events[event]["domain"].as_str().expect("an event domain");
            if !owns.contains(domain) {
                foreign.insert(
                    event.to_owned(),
                    format!("{component} publishes it and owns only {owns:?}"),
                );
            }
        }
    }
    assert_eq!(
        foreign,
        BTreeMap::new(),
        "at the story's base every one of the 65 declared events was published by the \
         component owning its domain; mandate.directory is owned by mandate-control-plane, \
         which also accepts every mandate.directory command"
    );
}

/// The publish lists and the `emits:` clauses are two accounts of the same thing and
/// nothing in ESS compares them. An emitted event no component publishes is written by a
/// deployment the contract does not name; one published twice has two.
#[test]
fn every_emitted_event_is_published_by_exactly_one_component() {
    let mut emitted: BTreeSet<String> = BTreeSet::new();
    for command in section("commands").values() {
        for outcome in command["outcomes"].as_array().expect("outcomes") {
            for event in outcome["emits"].as_array().into_iter().flatten() {
                emitted.insert(event.as_str().expect("an event name").to_owned());
            }
        }
    }
    let mut published: BTreeMap<String, usize> = BTreeMap::new();
    for declared in section("components").values() {
        for event in declared["publishes"].as_array().into_iter().flatten() {
            *published
                .entry(event.as_str().expect("an event name").to_owned())
                .or_default() += 1;
        }
    }

    assert_eq!(emitted.len(), 59, "events some command outcome emits");
    assert_eq!(published.len(), 72, "events some component publishes");
    let unpublished: Vec<&String> = emitted
        .iter()
        .filter(|event| !published.contains_key(*event))
        .collect();
    assert_eq!(
        unpublished,
        Vec::<&String>::new(),
        "emitted and unpublished"
    );
    let twice: Vec<&String> = published
        .iter()
        .filter(|(_, count)| **count > 1)
        .map(|(event, _)| event)
        .collect();
    assert_eq!(twice, Vec::<&String>::new(), "published by two components");
}

/// The residue this wave records for itself: `adversary_fold_inputs.rs:357` and the
/// story's own prose say sixteen entities cannot be rebuilt from the log. That list was
/// produced by pass 1's name-only reader and then extended during the correction round,
/// and a name-only reader cannot see a field carried inside a struct.
///
/// Measured with the exact-type reader that descends one level into a carried struct, the
/// residue is smaller. An entity recorded as unfoldable that folds is a record of work
/// still to do that is already done: it sends the next wave after a writer that exists.
const RECORDED_RESIDUE: [&str; 14] = [
    "mandate.credential.AccessCredential",
    "mandate.credential.AuthorizationCode",
    "mandate.credential.SigningKey",
    "mandate.delegation.Agent",
    "mandate.delegation.AgentCapabilityCeiling",
    "mandate.delegation.Approval",
    "mandate.delegation.Execution",
    "mandate.federation.OAuthClient",
    "mandate.graph.Grant",
    "mandate.graph.Resource",
    "mandate.identity.RefreshCredential",
    "mandate.policy.AuthorizationModel",
    "mandate.policy.Policy",
    "mandate.workload.WorkloadIdentity",
];

#[test]
fn the_recorded_residue_is_what_an_exact_type_reader_measures() {
    let mut measured: BTreeSet<&str> = BTreeSet::new();
    let mut folds: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (name, entity) in section("entities") {
        if transitions(entity) == 0 {
            continue;
        }
        let creators = creating_events(entity);
        if creators.is_empty() {
            measured.insert(name.as_str());
        } else {
            folds.insert(name.as_str(), creators);
        }
    }

    let recorded: BTreeSet<&str> = RECORDED_RESIDUE.into_iter().collect();
    let over_reported: BTreeMap<&str, &Vec<String>> = recorded
        .iter()
        .filter(|name| !measured.contains(*name))
        .map(|name| (*name, &folds[name]))
        .collect();
    let under_reported: BTreeSet<&&str> = measured.difference(&recorded).collect();

    assert_eq!(
        under_reported,
        BTreeSet::new(),
        "an entity nothing can rebuild that the wave does not record"
    );
    assert_eq!(
        over_reported,
        BTreeMap::new(),
        "the wave records these as unable to fold, and an event carries every field each \
         one declares, with that field's own name and type"
    );
}

/// The seeding events this wave added exist because no command creates the record. Their
/// whole justification is that the adapter writes one event per record and every field of
/// the record is on it — so the event is the record, and a fold that has the event has the
/// row. Anything less and the seeding event is a second incomplete writer rather than the
/// creation record.
const SEEDS: [(&str, &str); 6] = [
    ("mandate.identity.SessionOpened", "mandate.identity.Session"),
    (
        "mandate.identity.EpochSnapshotRecorded",
        "mandate.identity.SecurityEpochSnapshot",
    ),
    (
        "mandate.directory.DirectoryGroupRecorded",
        "mandate.directory.DirectoryGroup",
    ),
    (
        "mandate.directory.SyncJobRecorded",
        "mandate.directory.SyncJob",
    ),
    (
        "mandate.directory.DirectoryGroupMembershipRecorded",
        "mandate.directory.DirectoryGroupMembership",
    ),
    (
        "mandate.directory.MembershipContributionRecorded",
        "mandate.directory.MembershipContribution",
    ),
];

#[test]
fn every_seeding_event_mirrors_its_record_field_for_field() {
    let mut differences: BTreeMap<&str, String> = BTreeMap::new();
    for (event, record) in SEEDS {
        let entity = &section("entities")[record];
        let mut expected = vec![(
            entity["identity"]["name"]
                .as_str()
                .expect("an identity name")
                .to_owned(),
            identity_type(entity),
        )];
        expected.extend(fields_of(entity));
        let carried = fields_of(&section("events")[event]);
        if carried != expected {
            differences.insert(
                event,
                format!("carries {carried:?} where {record} declares {expected:?}"),
            );
        }
    }
    assert_eq!(
        differences,
        BTreeMap::new(),
        "a seeding event that is not its record's exact shape seeds an incomplete row"
    );
}

/// A `List<XId>` on an event names rows of `X` that some other event creates. When the
/// naming event and the creating event are published by two different deployments, the
/// log has two writers for one row and the contract declares nothing that orders them: a
/// reader that sees the list first holds an identity with no fields and cannot tell a
/// write that has not arrived from one that never will.
///
/// `directory.yaml`'s own summary says each row's fields are "on its own
/// DirectoryGroupMembershipRecorded" — written, per `components.yaml`, by a component
/// other than the one that publishes the list naming it.
#[test]
fn no_row_is_created_by_one_component_and_named_by_another() {
    let publisher = publisher_of();
    let mut split: BTreeMap<String, String> = BTreeMap::new();
    for (name, entity) in section("entities") {
        if transitions(entity) == 0 {
            continue;
        }
        let creators = creating_events(entity);
        if creators.is_empty() {
            continue;
        }
        let writing: BTreeSet<&String> = creators.iter().map(|event| &publisher[event]).collect();
        let plural = format!("List<{}>", identity_type(entity));
        for (event, declared) in section("events") {
            if creators.contains(event) {
                continue;
            }
            for (field, kind) in fields_of(declared) {
                if kind == plural && !writing.contains(&publisher[event]) {
                    split.insert(
                        format!("{event}.{field}"),
                        format!(
                            "{} names rows of {name} that only {creators:?} create, published \
                             by {writing:?}",
                            publisher[event]
                        ),
                    );
                }
            }
        }
    }
    assert_eq!(
        split,
        BTreeMap::new(),
        "one record written by two deployments, in an order the contract does not state"
    );
}
