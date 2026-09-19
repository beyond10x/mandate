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
revision: 20
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

- Coupling from `story:authored-denial-scenarios` (2026-09-19): the four seeded redemption scenarios carry the domain-separated SHA-256 verifier of the presented code (`Sha256Digest`, `crates/mandate-token/src/verifier.rs:108-120`, `services/sts/src/issue.rs:83-92`); the target must install `Sha256Digest` as its `CredentialDigest` or those four answer `CodeProofMismatch`.

- Implementor result, rounds 1–2 (2026-09-19): `crates/mandate-conformance` 13 files, 5358 lines; 28 cases (lib 19, bin 2, `tests/target.rs` 7); `mandate-conform --suite --impl-digest --out` byte-identical on two runs; report/2 over the 146-scenario synthesized suite: 29 passed / 54 failed / 0 error / 63 unsupported / 0 skipped, `conformance_status: failed`; `blocked` by reason: `unrealized-command` 46, `no-injection-port` 13, `expectation-unmet` 54, `input-shape-unrealized` 2, `refresh-credential-unprojected` 2; 23 armed injection ports, 13 refused-before-dispatch, 25 unsupported-command; 17 standing doubles (`ScenarioVerifier` reads JWS claims unsigned, `Sha256Digest`, `CountingSecrets`, `SequentialAllocator`, `StaticSigner`, `ScenarioKeys`, `RecordedClients`, `RecordedSessions`, …). Gaps: `AuthorizePublicClient` unsupported (input carries no `AuthorizationCode` record → `story:oauth-integration`); `DecisionRecorded` has no realizer (not hand-assembled); `RefreshSession` unsupported (`RefreshCredential` is projected nowhere → `story:session-epochs`); `ExchangeCredential` → `story:constrained-exchange`; the 54 expectation-unmet scenarios are the synthesizer arranging no prerequisite (`CreateTeam` with no `Organization`, `RegisterFederationConnection` with a rule resolving to a foreign organization, `RegisterSigningKey` with `algorithm: "algorithm"` and `not_before == expires_at`) and carry `blocked_on: story:conform-gate` pending per-scenario attribution in `expected-outcomes.json`; `RevokeSession` takes `&mut IdentityLog` directly (Scope's `IdentityRead` row corrected). `AuthorizationCode/Consumed` establishes through the log's compare-and-set with a derived `CredentialDescriptor`, recorded as `established-prerequisite`.

- Correction (2026-09-19): the two routings above to `story:tenancy-graph-events` and `story:session-epochs` are withdrawn — both are `implemented`; the live homes are `story:refusal-discriminators` and `story:epoch-snapshot-generations`.

- Coordinator note (2026-09-19): the suite compiles `generation: 0` on an `Integer` field to `"generation": 0.0` (only float-shaped number in the 167-scenario suite; `review-result:wave-d-authored-denials-adversary-2` F5); the `Node ↔ serde_json::Value` decoder must accept an integral float for an integer field. The authored files name `mandate_conformance::external::ScenarioVerifier` as the standing decode-only verifier double.

- Correction 1 result (2026-09-19): 35 cases green, four adversary cases 0 → 4 passed; report/2 unchanged (29 / 54 / 0 / 63 / 0 of 146); `injections.json` rows carry `consulted` from counting doubles — `armed` 2, `armed-standing` 12, `armed-unreached` 9 (consulted 0), `refused-before-dispatch` 13, `unsupported-command` 25; 22 standing doubles (the five `CheckRequest` bounds added); the substituted reader answers absence wherever the signature can express one (`CredentialResolution::resolve` → `Ok(None)`, a manufactured refusal removed); `Check` armed substitutes a `GraphRead + ResourceLookup` double; `RevokeSession` refused as not substitutable (concrete `IdentityLog`), routing `story:testkit-doubles`; `identity_unchanged` compares a cloned log; `node::to_json` renders an integral number as a JSON integer. The two `RefreshSession` rows point at `story:declared-writers` (active, owns the unprojected `RefreshCredential` class) since `story:epoch-snapshot-generations` is absent from the unit tree's store; the liveness case reads the store frontmatter for every `blocked_on`. Adversary 2 dispatched.
