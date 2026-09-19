---
format: aep.planning-md/1
id: story:conformance-target
kind: story
status: active
title: An in-process ESS conformance target over the real Mandate handlers
relations:
- decomposes: epic:foundations
- serves: vision:mandate
- depends_on: story:federation-identity-alignment
- depends_on: story:tenancy-graph-events
- depends_on: story:contract-creates
- depends_on: story:authored-denial-scenarios
- informed_by: initiative:drift-enforcement
scope:
- confidence: inferred
  path: Cargo.lock
- confidence: cited
  path: crates/mandate-conformance/Cargo.toml
- confidence: inferred
  path: crates/mandate-conformance/src/commands
- confidence: inferred
  path: crates/mandate-conformance/src/establish.rs
- confidence: inferred
  path: crates/mandate-conformance/src/external.rs
- confidence: cited
  path: crates/mandate-conformance/src/lib.rs
- confidence: cited
  path: crates/mandate-conformance/src/main.rs
- confidence: inferred
  path: crates/mandate-conformance/src/node.rs
- confidence: inferred
  path: crates/mandate-conformance/tests/target.rs
- confidence: cited
  path: dependency-boundaries.json
revision: 15
---
## Acceptance

Given the synthesized and authored suite, when `mandate-conform --suite <suite> --impl-digest <d> --out <dir>` runs, then every scenario executes against the real handlers through `ess_conformance::ConformanceTarget`, the target reports what it observed (emitted events serialized through the crates' own types, resulting state, denials with the declared reason) and never a manufactured expectation, every standing double and injected fault is written to `injections.json`, and the run yields `report.json` (report/2) and `run.json` deterministically.

## Scope

Derived 2026-09-19 by `story-scoper` on `integration/wave-20260919-005` at `75f41b5`. **cited** = read from the tree or ESS at tag 0.26.0; **inferred** = a reading that could be wrong.

- **Primary surface:** `crates/mandate-conformance` — cited; today a stub (`src/lib.rs:25` `pub struct MandateTarget;`, `src/main.rs:50` `fn conform` returns 1).
- **Files (new):** `src/node.rs`, `src/external.rs`, `src/establish.rs`, `src/commands/{federation,identity,authz,tenancy,graph,credential}.rs`, `tests/target.rs`.
- **Coordinator-owned:** `crates/mandate-conformance/Cargo.toml:17-30` and `dependency-boundaries.json:110-124` gain `mandate-sts` (the eleven credential commands are decided only in `services/sts/src/*`; no existing crate admits all seven domains — `services/control-plane` sees `mandate-sts` but not `mandate-authz`, `mandate-graph`, `mandate-policy`); `Cargo.lock`; `generated/conformance/{suite,report,run,injections}.json` (the directory does not exist yet).
- **Symbols:** `ess_conformance::ConformanceTarget` (`ess/crates/verify/ess-conformance/src/target.rs:87`), `Runner::run_admitted` (`runner.rs:353`), `AdmittedSuite::from_json` (`admission.rs:103`), `CountReport::from_run` (`counts.rs:151`).
- **The suite:** 146 scenarios, 61 `configure_external_outcome` steps (one per command, all `denied`), 0 `establish_entity` steps, 0 view steps (the `state/<S>/refuses/<Cmd>` scenarios arrange with real commands and `capture_instance`). 100 executable against realized handlers (35 accepted, 36 denied, 15 state-refuses, 14 transition), 46 blocked on 24 unrealized commands (delegation 10, directory 13, audit 6, graph relationship/revocation 7, `ExchangeCredential` 5, identity 2, policy 2, workload 1).
- **Injection points per realized command:** federation authenticate/authorize → `FederationVerifier` (`ConstructedVerifier::refusing`); link/disable/unlink/register → the store ports (`lib.rs:479,510,499,527`); `RegisterOAuthClient` → `ClientRegistrationAdmission`; `AuthorizePublicClient` → `TargetRegistry` + `OAuthClientStore` + `PkceDigest`; identity → `IdentityRead`/`SecurityEpochWrite`; authz `Check` → `DecisionIdAllocator`/`ChallengeIssuer` + the graph/policy doubles; credential → `ResourceServerReads`, `CredentialReads`/`CredentialResolution`, `SigningKeyReads`/`KeyMaterialResolver`, `OAuthClientReads` (`RecordedClients`), `SessionReads` (`RecordedSessions`), `AuthorizationCodeReads`/`AuthorizationCodeLog` (the CAS fake's `AppendRefused`). Tenancy (10) and graph register/deregister (2) have no port: refused before dispatch and recorded in `injections.json`.
- **Report/2:** `--suite-format 5` (the default 4 emits no `coverage` key; `qualification` requires `coverage().is_complete()`), frozen beside the CLI. `unsupported > 0` yields `failed`; `Unavailable` yields `error` → `inconclusive`.
- **Evidence:** `spec_digest 2f11d2da…`, `contract_digest c10ff600…` at this head; `ess --version` pinned; the implementation digest over `crates/**/src`, `services/**/src`, `systems/**` and the suite.
- **Gate:** `cargo test -p mandate-conformance --locked`; the binary twice for byte-identity; runtime unmeasured (10,739 `expect_no_event` steps over 224 `execute_command`s).
- **Would collide with:** `generated/conformance/**` with `obligation-registry` (different file, same directory); the suite bytes change when `authored-denial-scenarios` lands (merge order: authored first); `product-listener` cites `dependency-boundaries.json`, `Cargo.lock` (coordinator pre-lands the admission before either unit tree is cut).

## Coordinator rulings after critic round 1, 2026-09-19

- `generated/ir/system.json` is pre-landed by the coordinator in the opening commit (a fifth `cargo xtask generate` kind: `ess specify compile --format json`), so every E1 story reads a file that exists at the wave base; the emitter story adds only the Rust kind (parallel-safety PS1, design D1).
- Merge order in E1 is fixed: `contract-shapes` first (wiring the Rust kind), then `contract-creates`, then the coordinator regenerates every kind and commits the regeneration; `cargo xtask contracts` is expected red between those two merges and green after (PS2, D3).
- `tenancy-graph-events` emits one payload for `ResourceRegistered`: `{context, resource_id, resource, parent}` — the shape after `contract-creates` lands (which adds `resource_id` as `instance:` for `creates: Resource`); the coordinator verifies the name at regeneration and aligns if the yaml differs (PS3, D2).
- The `realizes!` macro and `ESS_REALIZATIONS` registry are pre-landed by the coordinator in `crates/mandate-types/src/macros.rs` in the opening commit; `coverage-map` owns the step, the manifest, the receipt and the authz/graph/policy registrations; federation, identity and model register in their own stories using the one macro (D4).
- `conformance-target` produces the first `generated/conformance/{suite,report,run,injections}.json` as part of its deliverable; `conform-gate` owns `expected-outcomes.json` and the byte-compare step (D5).
- The `obligations()` outcome-selection change (external cause, not the first error outcome) is pre-landed by the coordinator in the opening commit with a test, before `wrong-state` outcomes arrive (D6).
- `story:declared-writers` gains `depends_on story:contract-creates`; its later creators change the residue after this story's acceptance was evaluated at close, which is the intended order (D7).

## Rulings — wave D enforcement track, 2026-09-19

Coordinator, wave D enforcement track, 2026-09-19.

1. **Home:** `crates/mandate-conformance`, with `mandate-sts` admitted to its boundary line and manifest by the coordinator before the unit tree is cut (also `mandate-testkit` dev if not present).
2. **Suite format frozen at 5** (`ess verify conform synthesize --path systems/mandate --scenarios systems/mandate --target ir --compact --suite-format 5 --out …`), recorded in the CLI contract and on `story:conform-gate`.
3. **Blocked scenarios answer `Unavailable`** (report `error`, status `inconclusive`), each with `blocked_on` its owning story in `injections.json`/the run; `Unsupported` is reserved for capabilities the target lacks. The release stance of the plan (a library tag may ship `inconclusive` with the counts in the CHANGELOG) stands.
4. **`establish_entity` supports `mandate.identity.Session` (state `Active`)** and the other adapter-seeded records (`EpochSnapshotRecorded`, `SecurityEpochRecorded`, the Principal via `ExternalPrincipalProvisioned`), because the authored PKCE scenarios need a session no scenario file can mint through the real verifier; every other entity answers `Unsupported`.
5. **Tenancy and graph denials** (no port) are refused before dispatch and recorded; that is the honest answer and the class is routed to `story:testkit-doubles`/the deciders growing a port.
6. **Order:** `authored-denial-scenarios` merges first (it changes the suite bytes); `coverage-map` and this story both add under `generated/**` — the coordinator regenerates once after both merge.

- Corrections at the enforcement opening, after `review-result:wave-d-enforcement-parallel-r1`: (a) this wave commits nothing under `generated/conformance/` — `generate()` produces the six ESS kinds and the target's outputs are the binary's; the target writes `suite.json`, `report.json`, `run.json`, `injections.json` under `target/conformance/` and `story:conform-gate` decides the committed-and-byte-compared location with its `conform()` step (the four `generated/conformance/*` scope rows are struck); (b) the coordinator re-runs `mandate-conform` on the merged head after `authored-denial-scenarios` and this story have both merged and records the counts as the wave's evidence; (c) `mandate-testkit` is admitted as a dev dependency by the coordinator in the same pre-land as `mandate-sts` (`crates/mandate-conformance/Cargo.toml`, `dependency-boundaries.json`) before the tree is cut.

- Correction after `review-result:wave-d-enforcement-design-r1` (ruling 3 replaced): the 46 scenarios blocked on unrealized commands answer `Unsupported` — ESS's own definition (`ess-conformance/src/target.rs:854`: a permanent property of the target) — so report/2 reads `failed` with every failed scenario carrying its `blocked_on` story in the run. `Unavailable` is reserved for a check the runner could not execute. The plan's release stance is restated on `initiative:drift-enforcement`: a library tag may ship with `conformance_status: failed` while every failed scenario names a live `blocked_on` story and the CHANGELOG carries the counts (`passed`, `failed`, `unsupported`).
