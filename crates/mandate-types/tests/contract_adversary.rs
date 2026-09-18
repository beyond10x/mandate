//! Adversarial contract cases against `story:domain-runtime`.
//!
//! These read `systems/mandate/domains/*.yaml` — the ESS source — rather than
//! `generated/`, on purpose. `generated/` in this tree predates the contract change
//! under attack, so a case that read it would be red because the tree is stale and
//! not because the contract is wrong, which proves nothing. The ESS source is the
//! contract as it stands right now, and a case that reads it is red only while the
//! contract says what it says.
//!
//! The one case that does read `generated/schema` is about the projection itself,
//! and it asserts nothing about a property the projection has not been regenerated
//! to carry yet.

use std::collections::{BTreeMap, BTreeSet};

const DOMAINS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../systems/mandate/domains");
const SCHEMA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../generated/schema");

#[derive(Debug, Default, Clone)]
struct Entity {
    name: String,
    file: String,
    fields: Vec<String>,
    initial: String,
    states: Vec<String>,
    terminal: BTreeSet<String>,
    invariants: Vec<String>,
}

#[derive(Debug, Default, Clone)]
struct Command {
    name: String,
    file: String,
    input: BTreeSet<String>,
}

#[derive(Debug, Default)]
struct Contract {
    entities: Vec<Entity>,
    commands: Vec<Command>,
}

/// A deliberately narrow reader for the exact, machine-regular shape these twelve
/// files are written in: top-level keys in column zero, list items at two spaces,
/// item keys at four, list members at six, lifecycle keys at six and their members
/// at eight. Anything else is ignored rather than guessed at. The companion case
/// `the_reader_sees_the_contract_it_claims_to_see` fails loudly if that stops
/// holding, so a reader bug can never be mistaken for a finding.
fn read_contract() -> Contract {
    let mut contract = Contract::default();
    let mut files: Vec<_> = std::fs::read_dir(DOMAINS)
        .unwrap_or_else(|error| panic!("{DOMAINS}: {error}"))
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "yaml")
        })
        .collect();
    files.sort();

    for path in files {
        let file = path
            .file_name()
            .expect("file name")
            .to_string_lossy()
            .into_owned();
        let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{file}: {error}"));

        let mut section = String::new();
        let mut key = String::new();
        let mut lifecycle_key = String::new();

        for line in text.lines() {
            if !line.starts_with(' ') && !line.starts_with('#') && line.ends_with(':') {
                section = line.trim_end_matches(':').to_owned();
                key.clear();
                lifecycle_key.clear();
                continue;
            }

            if let Some(name) = line.strip_prefix("  - name: ") {
                key.clear();
                lifecycle_key.clear();
                match section.as_str() {
                    "entities" => contract.entities.push(Entity {
                        name: name.trim().to_owned(),
                        file: file.clone(),
                        ..Entity::default()
                    }),
                    "commands" => contract.commands.push(Command {
                        name: name.trim().to_owned(),
                        file: file.clone(),
                        ..Command::default()
                    }),
                    _ => {}
                }
                continue;
            }

            // An item key: exactly four spaces of indent, then `<key>:`.
            if line.starts_with("    ")
                && !line.starts_with("     ")
                && line.ends_with(':')
                && !line.trim_start().starts_with('-')
            {
                key = line.trim().trim_end_matches(':').to_owned();
                lifecycle_key.clear();
                continue;
            }

            if section == "entities" {
                let Some(entity) = contract.entities.last_mut() else {
                    continue;
                };
                match key.as_str() {
                    "fields" => {
                        if let Some(name) = line.strip_prefix("      - name: ") {
                            entity.fields.push(name.trim().to_owned());
                        }
                    }
                    "invariants" => {
                        if let Some(text) = line.strip_prefix("      - ") {
                            entity.invariants.push(text.trim().to_owned());
                        }
                    }
                    "lifecycle" => {
                        if let Some(state) = line.strip_prefix("      initial: ") {
                            entity.initial = state.trim().to_owned();
                        } else if line.starts_with("      ")
                            && !line.starts_with("       ")
                            && line.ends_with(':')
                        {
                            lifecycle_key = line.trim().trim_end_matches(':').to_owned();
                        } else if let Some(state) = line.strip_prefix("        - ") {
                            match lifecycle_key.as_str() {
                                "states" => entity.states.push(state.trim().to_owned()),
                                "terminal" => {
                                    entity.terminal.insert(state.trim().to_owned());
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
                continue;
            }

            if section == "commands"
                && key == "input"
                && let Some(name) = line.strip_prefix("      - name: ")
                && let Some(command) = contract.commands.last_mut()
            {
                command.input.insert(name.trim().to_owned());
            }
        }
    }

    contract
}

/// Not a finding of its own: a guard so that a reader bug shows up as a reader bug.
/// Every number here is read from `ess specify compile --path systems/mandate`.
#[test]
fn the_reader_sees_the_contract_it_claims_to_see() {
    let contract = read_contract();
    assert_eq!(
        contract.entities.len(),
        36,
        "the compiled model holds 36 entities"
    );
    assert_eq!(
        contract.commands.len(),
        59,
        "the compiled model holds 59 commands"
    );

    let key = contract
        .entities
        .iter()
        .find(|entity| entity.name == "mandate.credential.SigningKey")
        .expect("SigningKey is an entity");
    assert_eq!(key.initial, "Recorded");
    assert_eq!(key.states, ["Recorded", "Retired", "Revoked"]);
    assert!(key.terminal.contains("Revoked"));

    let connection = contract
        .entities
        .iter()
        .find(|entity| entity.name == "mandate.federation.FederationConnection")
        .expect("FederationConnection is an entity");
    assert!(
        connection.fields.contains(&"jit_provisioning".to_owned()),
        "the unit declares jit_provisioning on FederationConnection"
    );

    let register = contract
        .commands
        .iter()
        .find(|command| command.name == "mandate.federation.RegisterFederationConnection")
        .expect("RegisterFederationConnection is a command");
    assert!(
        register.input.contains("tenant_resolution"),
        "command inputs are read"
    );

    let epoch = contract
        .entities
        .iter()
        .find(|entity| entity.name == "mandate.identity.PrincipalSecurityEpoch")
        .expect("PrincipalSecurityEpoch is an entity");
    assert_eq!(epoch.invariants, ["generation >= 0"], "invariants are read");
}

/// `decision-blocker:jit-provisioning` admits JIT as a command "gated by a `Boolean`
/// `jit_provisioning` field on `FederationConnection`", and the evidence it asks for
/// begins "a first-time user on a connection with `jit_provisioning: true`".
/// `federation.yaml:4` says the same: a connection that does not admit provisioning
/// denies the first login and creates nothing.
///
/// A gate is only a gate if the state it admits can be reached. Every other field of
/// `FederationConnection` is supplied by `RegisterFederationConnection`, the one
/// command that creates one, and `story:domain-runtime` states there is no
/// `UpdateFederationConnection`. So the field that decides whether JIT provisioning
/// happens at all must be an input of some declared command, or no connection in this
/// contract ever admits it.
#[test]
fn the_field_that_gates_provisioning_is_settable_by_a_declared_command() {
    let contract = read_contract();

    let connection = contract
        .entities
        .iter()
        .find(|entity| entity.name == "mandate.federation.FederationConnection")
        .expect("FederationConnection is an entity");

    let unsettable: Vec<&String> = connection
        .fields
        .iter()
        .filter(|field| field.as_str() != "organization_id")
        .filter(|field| {
            !contract
                .commands
                .iter()
                .any(|command| command.input.contains(field.as_str()))
        })
        .collect();

    let register = contract
        .commands
        .iter()
        .find(|command| command.name == "mandate.federation.RegisterFederationConnection")
        .expect("RegisterFederationConnection is a command");

    assert_eq!(
        unsettable,
        Vec::<&String>::new(),
        "mandate.federation.FederationConnection ({}) declares {unsettable:?}, which \
         no declared command takes as input. RegisterFederationConnection ({}, \
         inputs {:?}) is the only command that creates a connection and there is no \
         UpdateFederationConnection, so no connection this contract can produce ever \
         admits just-in-time provisioning and mandate.federation.\
         ProvisionExternalPrincipal is unreachable on its accepted outcome",
        connection.file,
        register.file,
        register.input
    );
}

/// ESS states what `terminal` means, in the prose it generates for every entity:
/// "`X` is terminal, so an instance may rest there forever. That is declared rather
/// than inferred from having no way out: an entity that cannot leave a state is
/// either finished or stuck, and only its author knows which."
///
/// So a state an instance is expected to rest in is terminal, whether or not a move
/// leaves it. Thirty-five of this system's thirty-six entities declare every state
/// but the initial one terminal.
#[test]
fn every_declared_state_is_the_initial_state_or_a_declared_resting_state() {
    let contract = read_contract();

    let mut restless: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for entity in &contract.entities {
        let states: Vec<String> = entity
            .states
            .iter()
            .filter(|state| *state != &entity.initial && !entity.terminal.contains(*state))
            .cloned()
            .collect();
        if !states.is_empty() {
            restless.insert(format!("{} ({})", entity.name, entity.file), states);
        }
    }

    assert_eq!(
        restless,
        BTreeMap::new(),
        "a state that is neither the initial state nor terminal declares that no \
         instance may rest there. mandate.credential.RetireSigningKey's own accepted \
         summary says a retired key \"remains admitted for verifying credentials \
         already issued under it until they expire\" — it rests in Retired, and \
         expiry is not a recorded move — while the only terminal state is Revoked, \
         which the same file calls the emergency procedure that refuses the \
         credentials the key signed"
    );
}

/// An entity invariant is the only place this contract can bound a field, and
/// `decision-blocker:epoch` turns on the bound: the generation is "an `Integer`,
/// constrained non-negative". `identity.yaml:3` claims it is "constrained
/// non-negative by its entity invariant", and `src/inventory.rs` records that "the
/// contract declares the generation as a non-negative Integer".
///
/// The projected JSON Schema is what a consumer validates against. This asserts that
/// a field an invariant bounds is bounded there too. Properties the projection has
/// not been regenerated to carry yet are reported, not asserted on: staleness is not
/// the finding.
#[test]
fn the_projection_still_drops_entity_invariants_a_known_gap_tracked_by_story_invariant_boundary_validation()
 {
    const CONSTRAINTS: [&str; 8] = [
        "minimum",
        "exclusiveMinimum",
        "maximum",
        "exclusiveMaximum",
        "const",
        "enum",
        "multipleOf",
        "x-ess-invariant",
    ];

    let contract = read_contract();
    let mut unbounded: Vec<String> = Vec::new();
    let mut not_yet_projected: Vec<String> = Vec::new();

    for entity in &contract.entities {
        for invariant in &entity.invariants {
            let Some(field) = invariant.split_whitespace().next() else {
                continue;
            };
            if !entity.fields.iter().any(|name| name == field) {
                continue;
            }
            let path = format!("{SCHEMA}/entities/{}.schema.json", entity.name);
            let text =
                std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
            let document: serde_json::Value = serde_json::from_str(&text).expect("schema is JSON");
            let Some(property) = document["properties"].get(field) else {
                not_yet_projected.push(format!("{}.{field} ({invariant})", entity.name));
                continue;
            };
            let bounded = CONSTRAINTS
                .iter()
                .any(|constraint| property.get(constraint).is_some());
            if !bounded {
                unbounded.push(format!(
                    "{}.{field} declares `{invariant}` and projects as {property}",
                    entity.name
                ));
            }
        }
    }

    assert!(
        !unbounded.is_empty(),
        "ESS now projects entity invariants into the schema: retire this tripwire and revisit story:invariant-boundary-validation. Unbounded pairs: {:?}",
        unbounded
    );
}

// ---------------------------------------------------------------------------
// Second pass. The cases above attack the contract as it was first written.
// The cases below attack the contract as it was corrected, and they need more
// of it than the reader above collects: input and response types, the denial
// text, the accepted summary, and the fields each event carries. So they have
// their own reader over the same twelve files, and their own guard case.
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Named {
    name: String,
    ty: String,
}

#[derive(Debug, Default, Clone)]
struct Outcome {
    name: String,
    emits: Vec<String>,
    moves: String,
    summary: String,
    external: String,
}

#[derive(Debug, Default, Clone)]
struct Record {
    name: String,
    file: String,
    line: usize,
    identity: Named,
    fields: Vec<Named>,
    initial: String,
    states: Vec<String>,
    transitions: Vec<String>,
}

#[derive(Debug, Default, Clone)]
struct Operation {
    name: String,
    file: String,
    line: usize,
    input: Vec<Named>,
    response: Vec<Named>,
    outcomes: Vec<Outcome>,
}

#[derive(Debug, Default, Clone)]
struct Notice {
    name: String,
    file: String,
    line: usize,
    fields: Vec<Named>,
}

#[derive(Debug, Default)]
struct Model {
    records: Vec<Record>,
    operations: Vec<Operation>,
    notices: Vec<Notice>,
}

impl Model {
    fn record(&self, name: &str) -> &Record {
        self.records
            .iter()
            .find(|record| record.name == name)
            .unwrap_or_else(|| panic!("{name} is a declared entity"))
    }

    fn operation(&self, name: &str) -> &Operation {
        self.operations
            .iter()
            .find(|operation| operation.name == name)
            .unwrap_or_else(|| panic!("{name} is a declared command"))
    }

    fn notice(&self, name: &str) -> &Notice {
        self.notices
            .iter()
            .find(|notice| notice.name == name)
            .unwrap_or_else(|| panic!("{name} is a declared event"))
    }
}

impl Operation {
    /// The one outcome that is not the denial. Fifty-eight of the fifty-nine
    /// commands name it `accepted`; `mandate.audit.RecordAuditEvent` names its
    /// `recorded`, which is why this is written as "not denied" rather than as a
    /// name match.
    fn accepted(&self) -> &Outcome {
        self.outcomes
            .iter()
            .find(|outcome| outcome.name != "denied")
            .unwrap_or_else(|| panic!("{} declares an outcome that is not denied", self.name))
    }

    fn denial(&self) -> &str {
        self.outcomes
            .iter()
            .find(|outcome| outcome.name == "denied")
            .map(|outcome| outcome.external.as_str())
            .unwrap_or_else(|| panic!("{} declares a denied outcome", self.name))
    }

    fn moves(&self, entity: &str) -> bool {
        let prefix = format!("{entity}.");
        self.outcomes
            .iter()
            .any(|outcome| outcome.moves.starts_with(&prefix))
    }

    fn reads(&self, ty: &str) -> Vec<String> {
        self.input
            .iter()
            .filter(|field| field.ty == ty)
            .map(|field| field.name.clone())
            .collect()
    }
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

fn unquote(value: &str) -> String {
    let value = value.trim();
    value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(value)
        .to_owned()
}

/// The same narrow reader discipline as `read_contract`: the twelve files are
/// machine-regular, so indentation alone decides what a line is, and anything
/// that does not match a known shape is ignored rather than guessed at.
/// `the_second_reader_sees_the_contract_it_claims_to_see` fails loudly if that
/// stops holding.
fn read_model() -> Model {
    let mut model = Model::default();
    let mut files: Vec<_> = std::fs::read_dir(DOMAINS)
        .unwrap_or_else(|error| panic!("{DOMAINS}: {error}"))
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "yaml")
        })
        .collect();
    files.sort();

    for path in files {
        let file = path
            .file_name()
            .expect("file name")
            .to_string_lossy()
            .into_owned();
        let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{file}: {error}"));

        let mut section = String::new();
        let mut key = String::new();
        let mut inner = String::new();

        for (position, line) in text.lines().enumerate() {
            let number = position + 1;

            if !line.starts_with(' ') && !line.starts_with('#') && line.ends_with(':') {
                section = line.trim_end_matches(':').to_owned();
                key.clear();
                inner.clear();
                continue;
            }

            if let Some(name) = line.strip_prefix("  - name: ") {
                key.clear();
                inner.clear();
                let name = name.trim().to_owned();
                match section.as_str() {
                    "entities" => model.records.push(Record {
                        name,
                        file: file.clone(),
                        line: number,
                        ..Record::default()
                    }),
                    "commands" => model.operations.push(Operation {
                        name,
                        file: file.clone(),
                        line: number,
                        ..Operation::default()
                    }),
                    "events" => model.notices.push(Notice {
                        name,
                        file: file.clone(),
                        line: number,
                        ..Notice::default()
                    }),
                    _ => {}
                }
                continue;
            }

            if indent(line) == 4 && line.ends_with(':') && !line.trim_start().starts_with('-') {
                key = line.trim().trim_end_matches(':').to_owned();
                inner.clear();
                continue;
            }

            match section.as_str() {
                "entities" => {
                    let Some(record) = model.records.last_mut() else {
                        continue;
                    };
                    match key.as_str() {
                        "identity" => {
                            if let Some(value) = line.strip_prefix("      name: ") {
                                record.identity.name = value.trim().to_owned();
                            } else if let Some(value) = line.strip_prefix("      type: ") {
                                record.identity.ty = value.trim().to_owned();
                            }
                        }
                        "fields" => {
                            if let Some(value) = line.strip_prefix("      - name: ") {
                                record.fields.push(Named {
                                    name: value.trim().to_owned(),
                                    ty: String::new(),
                                });
                            } else if let Some(value) = line.strip_prefix("        type: ")
                                && let Some(field) = record.fields.last_mut()
                            {
                                field.ty = value.trim().to_owned();
                            }
                        }
                        "lifecycle" => {
                            if let Some(value) = line.strip_prefix("      initial: ") {
                                record.initial = value.trim().to_owned();
                            } else if indent(line) == 6 && line.ends_with(':') {
                                inner = line.trim().trim_end_matches(':').to_owned();
                            } else if inner == "states"
                                && let Some(value) = line.strip_prefix("        - ")
                            {
                                record.states.push(value.trim().to_owned());
                            } else if inner == "transitions"
                                && let Some(value) = line.strip_prefix("        - name: ")
                            {
                                record.transitions.push(value.trim().to_owned());
                            }
                        }
                        _ => {}
                    }
                }
                "commands" => {
                    let Some(operation) = model.operations.last_mut() else {
                        continue;
                    };
                    match key.as_str() {
                        "input" | "response" => {
                            let list = if key == "input" {
                                &mut operation.input
                            } else {
                                &mut operation.response
                            };
                            if let Some(value) = line.strip_prefix("      - name: ") {
                                list.push(Named {
                                    name: value.trim().to_owned(),
                                    ty: String::new(),
                                });
                            } else if let Some(value) = line.strip_prefix("        type: ")
                                && let Some(field) = list.last_mut()
                            {
                                field.ty = value.trim().to_owned();
                            }
                        }
                        "outcomes" => {
                            if let Some(value) = line.strip_prefix("      - name: ") {
                                inner.clear();
                                operation.outcomes.push(Outcome {
                                    name: value.trim().to_owned(),
                                    ..Outcome::default()
                                });
                            } else if let Some(outcome) = operation.outcomes.last_mut() {
                                if indent(line) == 8 && line.ends_with(':') {
                                    inner = line.trim().trim_end_matches(':').to_owned();
                                } else if let Some(value) = line.strip_prefix("        moves: ") {
                                    outcome.moves = value.trim().to_owned();
                                } else if let Some(value) = line.strip_prefix("        summary: ") {
                                    outcome.summary = unquote(value);
                                } else if let Some(value) = line.strip_prefix("        external: ")
                                {
                                    outcome.external = unquote(value);
                                } else if inner == "emits"
                                    && let Some(value) = line.strip_prefix("          - ")
                                {
                                    outcome.emits.push(value.trim().to_owned());
                                }
                            }
                        }
                        _ => {}
                    }
                }
                "events" => {
                    let Some(notice) = model.notices.last_mut() else {
                        continue;
                    };
                    if key == "fields" {
                        if let Some(value) = line.strip_prefix("      - name: ") {
                            notice.fields.push(Named {
                                name: value.trim().to_owned(),
                                ty: String::new(),
                            });
                        } else if let Some(value) = line.strip_prefix("        type: ")
                            && let Some(field) = notice.fields.last_mut()
                        {
                            field.ty = value.trim().to_owned();
                        }
                    }
                }
                _ => {}
            }
        }
    }

    model
}

/// Not a finding of its own. Every number and string here is read from
/// `ess specify compile --path systems/mandate --format json`, so a reader bug
/// shows up as a reader bug and never as a finding.
#[test]
fn the_second_reader_sees_the_contract_it_claims_to_see() {
    let model = read_model();
    assert_eq!(
        model.records.len(),
        36,
        "the compiled model holds 36 entities"
    );
    assert_eq!(
        model.operations.len(),
        59,
        "the compiled model holds 59 commands"
    );
    assert_eq!(
        model.notices.len(),
        65,
        "the compiled model holds 65 events"
    );

    let client = model.record("mandate.federation.OAuthClient");
    assert_eq!(client.identity.ty, "mandate.core.OAuthClientId");
    assert_eq!(client.initial, "Recorded");
    assert_eq!(client.states, ["Recorded", "Disabled"]);
    assert_eq!(client.transitions, ["disable"]);

    let register = model.operation("mandate.federation.RegisterFederationConnection");
    assert_eq!(
        register.response,
        vec![Named {
            name: "connection_id".to_owned(),
            ty: "mandate.core.FederationConnectionId".to_owned(),
        }],
        "command responses are read with their types"
    );
    assert!(
        register
            .reads("Boolean")
            .contains(&"jit_provisioning".to_owned()),
        "command inputs are read with their types"
    );

    // The convention the class case below tests for, demonstrated working on the
    // one command that follows it: the correction added this clause, and the
    // recogniser sees it.
    let redeem = model.operation("mandate.credential.RedeemAuthorizationCode");
    assert!(
        redeem.denial().contains("the bound client is disabled"),
        "denial text is read"
    );
    assert!(
        redeem.accepted().emits == ["mandate.credential.AuthorizationCodeRedeemed"],
        "emitted events are read"
    );
    assert!(
        model
            .operation("mandate.tenancy.CloseOrganization")
            .moves("mandate.tenancy.Organization"),
        "moves is read"
    );
}

/// The seventeen entities this unit's diff gives a lifecycle transition to.
/// Every one of them was `Recorded`-only at `d47c0b5`, which declares — in ESS's
/// own words for `terminal` — that an instance rests in `Recorded` forever. The
/// fifteen entities that already moved at base are not in this list and are not
/// asserted on here: their denials are `story:event-payloads-for-folds`' and the
/// base's, not this unit's.
const STOPPABLE_BY_THIS_UNIT: [&str; 17] = [
    "mandate.audit.AuditEvent",
    "mandate.credential.SigningKey",
    "mandate.delegation.Agent",
    "mandate.delegation.AgentCapabilityCeiling",
    "mandate.delegation.Approval",
    "mandate.delegation.Execution",
    "mandate.directory.DirectoryGroup",
    "mandate.directory.SyncJob",
    "mandate.federation.OAuthClient",
    "mandate.graph.Resource",
    "mandate.policy.AuthorizationModel",
    "mandate.policy.Policy",
    "mandate.tenancy.Organization",
    "mandate.tenancy.Space",
    "mandate.tenancy.Team",
    "mandate.tenancy.TeamMembership",
    "mandate.workload.WorkloadIdentity",
];

/// `Disabled` -> `disabl`, `Retired` -> `retir`, `Deregistered` -> `deregister`.
/// The stem, not the word, because the contract writes "is disabled" in one
/// denial and "disablement" in another.
fn state_stem(state: &str) -> String {
    let lower = state.to_lowercase();
    lower
        .strip_suffix("ed")
        .or_else(|| lower.strip_suffix('d'))
        .unwrap_or(&lower)
        .to_owned()
}

/// `mandate.federation.OAuthClient` -> `["auth", "client"]`. Derived from the
/// entity's own name, so nothing here is a noun I chose.
fn record_words(name: &str) -> Vec<String> {
    let simple = name.rsplit('.').next().unwrap_or(name);
    let mut words: Vec<String> = Vec::new();
    let mut current = String::new();
    for character in simple.chars() {
        if character.is_uppercase() && !current.is_empty() {
            words.push(std::mem::take(&mut current));
        }
        current.push(character.to_ascii_lowercase());
    }
    words.push(current);
    words.retain(|word| word.len() >= 3);
    words
}

fn mentions_word(haystack: &str, word: &str) -> bool {
    let bytes = haystack.as_bytes();
    haystack.match_indices(word).any(|(start, _)| {
        let before = start
            .checked_sub(1)
            .is_none_or(|index| !bytes[index].is_ascii_alphanumeric());
        let after = bytes
            .get(start + word.len())
            .is_none_or(|byte| !byte.is_ascii_alphanumeric());
        before && after
    })
}

/// A denial clause covers an entity's off state when one clause of it names both
/// the state and the entity. `RedeemAuthorizationCode`'s "the bound client is
/// disabled" is the shape; the guard case above asserts the recogniser sees it.
fn denial_covers(denial: &str, record: &Record) -> bool {
    let words = record_words(&record.name);
    let stems: Vec<String> = record
        .states
        .iter()
        .filter(|state| *state != &record.initial)
        .map(|state| state_stem(state))
        .collect();
    denial.to_lowercase().split([';', ',']).any(|clause| {
        stems.iter().any(|stem| clause.contains(stem.as_str()))
            && words
                .iter()
                .any(|word| mentions_word(clause, word.as_str()))
    })
}

/// A lifecycle state is only a control if the commands that would act on the
/// record refuse it there. `DisableOAuthClient`'s own accepted summary
/// (`federation.yaml:307`) states the control: "No new authorization code is
/// issued to it." `RetireTeam`'s (`tenancy.yaml:273`) states another: the team
/// "stops resolving as an authorization subject". `RetireDirectoryGroup`'s
/// (`directory.yaml:323`) a third: the group "stops contributing authority".
///
/// This unit declares seventeen new off states. For each one whose identity type
/// names exactly one moving entity — so that "this command reads that record" is
/// decidable from the type alone — every command that reads the record and does
/// not itself move it must name the off state in its denial. The contract does
/// this everywhere the state already existed at base: `AuthenticateFederation`
/// refuses a disabled `FederationConnection`, `ExchangeCredential` a disabled
/// `ResourceServer`, and the correction added "the bound client is disabled" to
/// `RedeemAuthorizationCode`. The question is whether the seventeen new states
/// got the same treatment.
#[test]
fn an_off_state_this_unit_declares_is_refused_by_the_commands_that_admit_into_it() {
    let model = read_model();

    let moving: Vec<&Record> = model
        .records
        .iter()
        .filter(|record| !record.transitions.is_empty())
        .collect();

    let mut unguarded: Vec<String> = Vec::new();
    let mut undecidable: Vec<String> = Vec::new();

    for name in STOPPABLE_BY_THIS_UNIT {
        let record = model.record(name);
        assert!(
            !record.transitions.is_empty(),
            "{name} is in this unit's list of newly stoppable records but declares no transition"
        );
        let shared = moving
            .iter()
            .filter(|other| other.identity.ty == record.identity.ty)
            .count();
        if shared != 1 {
            undecidable.push(format!("{name} ({})", record.identity.ty));
            continue;
        }
        for operation in &model.operations {
            let reads = operation.reads(&record.identity.ty);
            if reads.is_empty() || operation.moves(name) {
                continue;
            }
            if denial_covers(operation.denial(), record) {
                continue;
            }
            unguarded.push(format!(
                "{name} rests in {:?} and {} ({}:{}) reads it as {reads:?} without \
                 refusing it there — its whole denial is: {}",
                record
                    .states
                    .iter()
                    .filter(|state| *state != &record.initial)
                    .collect::<Vec<_>>(),
                operation.name,
                operation.file,
                operation.line,
                operation.denial()
            ));
        }
    }

    assert_eq!(
        unguarded,
        Vec::<String>::new(),
        "a state this unit made reachable is admitted into by a command that never \
         refuses it. mandate.federation.DisableOAuthClient's accepted summary says \
         \"No new authorization code is issued to it\", and the two commands that \
         issue an authorization code both take an OAuthClientId and refuse only a \
         client that is \"not a registered public client\" — which a disabled one \
         still is, because the same summary says \"The registration record is \
         kept\". Not asserted on, because the identity type does not name one \
         moving record: {undecidable:?}"
    );
}

/// `decision-blocker:jit-provisioning` gates JIT on a per-connection `Boolean`,
/// and the correction put it where it can be set: `RegisterFederationConnection`
/// takes it (`federation.yaml:190`) and carries it into
/// `FederationConnectionCreated`. ADR-0009 makes the events the record and every
/// read a fold, so the flag has to arrive somewhere a fold can put it.
///
/// Every one of the six creation commands this unit adds carries the created
/// record's identity on its event — `CreateOrganization`, `CreateTeam`,
/// `CreateSpace`, `AddOrganizationMembership`, `AddTeamMembership`, and in this
/// same file `ProvisionExternalPrincipal`, which binds `external_principal_id:
/// {response: external_principal_id}`. This asserts the one creation event the
/// unit changed rather than added does the same.
#[test]
fn the_event_that_records_the_provisioning_gate_names_the_connection_it_gates() {
    let model = read_model();

    let connection = model.record("mandate.federation.FederationConnection");
    let register = model.operation("mandate.federation.RegisterFederationConnection");
    let created = model.notice("mandate.federation.FederationConnectionCreated");

    let carried: Vec<&String> = created
        .fields
        .iter()
        .filter(|field| {
            connection
                .fields
                .iter()
                .any(|declared| declared.name == field.name && declared.ty == field.ty)
        })
        .map(|field| &field.name)
        .collect();
    assert!(
        !carried.is_empty(),
        "guard: the event is expected to carry at least one field of the record it creates"
    );

    let bindable: Vec<&String> = register
        .response
        .iter()
        .filter(|field| field.ty == connection.identity.ty)
        .map(|field| &field.name)
        .collect();

    let names_it: Vec<&String> = created
        .fields
        .iter()
        .filter(|field| field.ty == connection.identity.ty)
        .map(|field| &field.name)
        .collect();

    assert_ne!(
        names_it,
        Vec::<&String>::new(),
        "{} ({}:{}) carries {carried:?}, a per-connection setting of {} ({}:{}), and \
         no field of type {} — so the event that records which connections admit \
         just-in-time provisioning says nothing about which connection it is, and \
         the gate mandate.federation.ProvisionExternalPrincipal's denial turns on \
         (\"connection does not admit provisioning\") cannot be folded from the log \
         ADR-0009 calls the record. {} declares response {bindable:?} of exactly \
         that type, and the same file's ExternalPrincipalProvisioned binds its \
         created identity from the response already. The event carries the issuer, \
         client and tenant-resolution rule no more than it carries the identity: \
         its full field list is {:?}",
        created.name,
        created.file,
        created.line,
        connection.name,
        connection.file,
        connection.line,
        connection.identity.ty,
        register.name,
        created
            .fields
            .iter()
            .map(|field| format!("{}: {}", field.name, field.ty))
            .collect::<Vec<_>>()
    );
}

/// Adversary pass 1 found `AddTeamMembership` describing a `MembershipContribution`
/// recorded alongside the membership, which no command creates. The correction
/// reworded the summary. It now says the contribution is "mandate.directory's own
/// record, written by that domain's commands", and `RemoveTeamMembership` — new in
/// the same diff — still refuses a removal while "a mandate.directory mapping
/// contribution still supports it".
///
/// Both sentences are claims about a record some command creates. This asserts one
/// does.
#[test]
fn the_contribution_two_new_tenancy_commands_rest_on_is_created_by_a_declared_command() {
    let model = read_model();

    let add = model.operation("mandate.tenancy.AddTeamMembership");
    let remove = model.operation("mandate.tenancy.RemoveTeamMembership");
    let contribution = model.record("mandate.directory.MembershipContribution");

    assert!(
        add.accepted()
            .summary
            .contains("written by that domain's commands"),
        "guard: AddTeamMembership's summary still attributes the contribution to mandate.directory"
    );
    assert!(
        remove
            .denial()
            .contains("mapping contribution still supports it"),
        "guard: RemoveTeamMembership's denial still turns on a contribution"
    );

    let creators: Vec<String> = model
        .operations
        .iter()
        .filter(|operation| {
            let accepted = operation.accepted();
            accepted.moves.is_empty()
                && (operation
                    .response
                    .iter()
                    .any(|field| field.ty == contribution.identity.ty)
                    || accepted.emits.iter().any(|event| {
                        model
                            .notice(event)
                            .fields
                            .iter()
                            .any(|field| field.ty == contribution.identity.ty)
                    }))
        })
        .map(|operation| format!("{} ({}:{})", operation.name, operation.file, operation.line))
        .collect();

    assert_ne!(
        creators,
        Vec::<String>::new(),
        "no declared command creates a {} ({}:{}): none names {} in a response and \
         none emits an event carrying it. mandate.directory declares eight \
         commands and the only one that touches a contribution is \
         RemoveMembershipContribution, which moves an existing one to Removed. So \
         {} ({}:{}) attributes the record to commands that do not exist, and {} \
         ({}:{}) refuses a removal on a condition nothing in this contract can ever \
         make true — the protection its summary promises, that \"a retracted \
         mapping never removes a membership a manual decision still holds up\", is \
         a guard over an empty set",
        contribution.name,
        contribution.file,
        contribution.line,
        contribution.identity.ty,
        add.name,
        add.file,
        add.line,
        remove.name,
        remove.file,
        remove.line
    );
}

/// `CreateOrganization` is the command this unit added for the story's own
/// "Creation commands the tenancy story needs", and its accepted summary
/// (`tenancy.yaml:185`) says the organization "is created empty, and no
/// membership, team, space or grant exists inside it until that record's own
/// command writes one".
///
/// Every command that writes such a record binds it to `input.context`, and
/// `mandate.core.VerifiedContext` (`core.yaml:211-219`) carries exactly one
/// `organization`, the caller's. So a record's own command can write into the new
/// organization only if some command can name an organization that is not the
/// caller's. This asserts one can.
#[test]
fn an_organization_this_contract_creates_can_be_named_by_a_command_that_writes_in_it() {
    let model = read_model();

    let organization = model.record("mandate.tenancy.Organization");
    let create = model.operation("mandate.tenancy.CreateOrganization");

    let returned: Vec<&String> = create
        .response
        .iter()
        .filter(|field| field.ty == organization.identity.ty)
        .map(|field| &field.name)
        .collect();
    assert!(
        !returned.is_empty(),
        "guard: CreateOrganization is expected to return the identity it creates"
    );

    let selectors: Vec<String> = model
        .operations
        .iter()
        .filter(|operation| !operation.moves(&organization.name))
        .filter(|operation| !operation.reads(&organization.identity.ty).is_empty())
        .map(|operation| {
            format!(
                "{} ({}:{}) takes {:?}",
                operation.name,
                operation.file,
                operation.line,
                operation.reads(&organization.identity.ty)
            )
        })
        .collect();

    assert_ne!(
        selectors,
        Vec::<String>::new(),
        "{} ({}:{}) returns {returned:?}, and the only command in all 59 that takes \
         a {} as an input is the one that closes the organization again. Every \
         command that would put a membership, team, space, grant, connection or \
         resource inside an organization resolves it from input.context, whose \
         organization field is the caller's own — mandate.tenancy.\
         AddOrganizationMembership even denies when \"the principal is already a \
         member of the verified organization\". So the isolation root this command \
         creates admits nothing and is reachable by nothing, and its own summary — \
         \"{}\" — names four records none of whose commands can say which \
         organization to write into",
        create.name,
        create.file,
        create.line,
        organization.identity.ty,
        create.accepted().summary
    );
}
