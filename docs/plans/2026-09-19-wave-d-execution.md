# Wave D — the login road's adapters and the served route

**Skill version 0.9.2** — `aep-drive`. **AEP** `protocol 0.55.0`. **ESS** `ess 0.26.0`. Base: `a954be8`, the last bot-only commit whose tree equals `main` at `6f6f639` (wave C merged through PR #13). Integration branch `integration/wave-20260919-005`.

## Why this wave

After wave C every command on the customer login road has a deciding handler behind ports: a login opens a Session, the control plane validates an authorization request and assembles the code issuance by value, the STS issues and redeems the code into a credential, and introspection answers for it. Nothing serves any of it. This wave decodes the road's requests (`story:login-adapters`, split from `story:protocol-adapters`) and binds them to a listener in one composition binary (`story:product-listener`), so the vertical runs end to end over HTTP with in-memory folds.

## Selection

| Story | Status at opening | Agent | Lands in |
|---|---|---|---|
| `story:login-adapters` | draft → active | one Opus implementor, round 1; units `context`, `routes`, `oauth`, `obligations`, `metadata`, the crate roots, `docs/architecture/adapter-contract.md` | `crates/mandate-server/**`, `crates/mandate-proto/src/{lib,oauth}.rs`, `crates/mandate-proto/tests/oauth.rs` |
| `story:product-listener` | draft → active | one Opus implementor, round 2, cut from the merged head; units `composition` (the three port adapters and the wired folds) and `listener` (`std::net` + `httparse`, the four routes, the two documents, every generated command path refused) | `services/control-plane/**` |

Not selected: `story:oauth-integration` (its acceptance over HTTP is what the listener's served-route test proves; the story's own close follows), `story:protocol-adapters` (the off-road residue: the denial-audit path, exchange and SCIM rows), the E2 set (deferred).

Sequential by symbol: the listener dispatches the adapters' route table and decoders, so its tree is cut after round 1 merges.

## Decisions taken at the opening (reported to the operator)

| Fork | Taken | Reversal cost |
|---|---|---|
| D1 composition home | `services/control-plane` gains a `[lib]` and its own boundary key (`LIBRARIES` 17 → 18) | one key and one constant |
| D2 transport | `std::net` + `httparse` (in the lock, MIT OR Apache-2.0); no runtime, no framework | one array entry |
| D3 `serve` refusal | narrowed from six binaries to five; `mandate-control-plane serve` must bind and answer; lands with the listener merge | one `xtask` row |
| D4 persistence | in-memory folds now; `eventlog-sqlite` with its runtime as the next milestone | none |

## The enforcement track, in parallel (operator instruction of 2026-09-19)

The operator's reading of the E1 close was that the enforcement programme was done; it was not — E2–E4 and the ESS wave remained, and the E1 report did not say so. From this wave on the enforcement stories run in parallel with the road, up to five agents at once, tracked in `initiative:drift-enforcement` (the standing table every wave report names). Wave D carries four of them as their own rounds, disjoint by file from the road units: `story:coverage-map` (`xtask/src/coverage.rs`, `contracts/coverage.json`, `generated/coverage/`), `story:authored-denial-scenarios` (`systems/mandate/scenarios/*.yaml`, `ess-inputs.yaml`), `story:conformance-target` (`crates/mandate-conformance`), `story:mutation-controls` (`xtask/src/mutants.rs`, `tests/mutants/`). `xtask/src/main.rs` and `generated/**` stay the coordinator's. Scopers dispatched (Opus, 4); critics follow on the four as a set; then implementors.

## Coordinator pre-lands (opening commit)

1. Store: `story:login-adapters` (Scope, edges, `metadata` addendum); `story:product-listener`'s Scope re-recorded with the four rulings, `depends_on login-adapters`, `protocol-adapters` downgraded to `informed_by`, the `mandate-federation` adapters files struck; `story:protocol-adapters`' scope narrowed to its residue; the critic review-results and rulings; both stories active.
2. `services/control-plane/Cargo.toml`: a `[lib]` target and the composition's dependencies (`mandate-types`, `mandate-model`, `mandate-token`, `mandate-identity`, `mandate-federation`, `mandate-server`, `mandate-proto`, `mandate-sts`, `serde`, `serde_json`, `httparse`); `services/control-plane/src/lib.rs` as an empty root; `dependency-boundaries.json` key `mandate-control-plane`; `xtask/src/main.rs` `LIBRARIES` 18 and its doc comment; `Cargo.lock`. The `serve` rows stay until the listener lands.
3. Wave page.

## Commits this wave makes

Through `atlas/scripts/as-bot.sh`: this opening commit; one commit per unit round and one `--no-ff` merge each; the coordinator's alignment commit with the `serve` rows at the listener merge; alignment commits where a ruling moves a pinned value; the closing store commit; publication through `b10x-gates` from the bot-only lineage; the PR to `main` and its App merge. No tag, no release.

## Preflight

- Coordinator tree `mandate-wc-coordinator` reused on the new branch; lease held; disk 82G free.
- `aep plan artifact validate`: valid.

## Stage log

- Scopers (Opus, read-only, 2): `protocol-adapters` — four road units need no new dependency and only implemented stories; the audit path is blocked twice (the crate ceiling and `decision-blocker:audit-routing`); 61 generated routes, not 34. `product-listener` — the four cross-crate port adapters can land only in a composition crate; four forks named (composition home, transport, the `serve` refusal, persistence).

- Critic panel round 1 (Opus, read-only, 2): parallel-safety `needs-revision`, 5 findings (the listener's stale unit table; the two document paths' home; three stale statements); design `needs-revision`, 8 findings (the residue story still claiming the split units; the `context` unit with no road consumer; the listener's two unit tables and stale acceptance; the mitigation edge; the route-path review; `metadata`'s two owners; the D1 citation). All ruled: `context` is `decode` (the decoding boundary — exactly the declared inputs, undeclared fields refused; `VerifiedContext` stays with the product routes); the document paths are route-table entries; the composition hosts both deployment roles with the authority rows unmoved (`ownership.md` says so); both stories active.
- Opening commit `75f41b5`; `task check` on it: exit 0, 1306 tests across 183 targets.
- `login-adapters` implementor green: 14 files +4543 — `decode` (four road decoders over a crate-local request value, undeclared fields refused, body ceiling), `oauth` (form decoding in `std`, six error codes, `CLAUSE_CODES` decided against `DenialClause`'s source), `routes` (six entries, the disjointness proof over the 61 generated routes at test time, a shape predicate), `metadata` (RFC 8414 and JWKS shapes), `obligations` (61 rows equal to the operationIds; 25 road clauses each with a negative case), `docs/architecture/adapter-contract.md`; two crates 16 → 110 tests; boundaries and documents green. Route paths accepted by the coordinator (recorded on the story). Adversary 1 dispatched.
- Enforcement track: four scopes recorded with rulings; the coordinator admitted `mandate-sts` to `mandate-conformance`'s boundary line and manifest; critics dispatched on the set.
- Enforcement critics (Opus, read-only, 2): parallel-safety `needs-revision`, 7 findings (nothing lands under `generated/conformance/` this wave — the target's outputs go to `target/conformance/` and `conform-gate` decides the committed location; the two xtask units gate through their `#[path]`-included step tests; the testkit admission; the red window; the read anchors); design `needs-revision`, 3 findings (the 110 type entries proven in `mandate-types`; `--suite-format 5` on `conform-gate`; the emitter mutant retires with the emitter) plus three lane notes taken as rulings (`Unsupported` for scenarios blocked on unrealized commands, report `failed` with `blocked_on`, the release stance restated on the tracker; two ESS-side drift mutants). All ruled; four stories active; four trees cut; implementors dispatched (Opus, 4) beside the adapters adversary.
- Adapters adversary 1 (`review-result:wave-d-login-adapters-adversary-1`): 12 cases, 10 red; 1 blocker (no `code_id` on the wire and none resolved — routed to the composition through a by-verifier read on the STS store), 10 warnings (RFC 6749 §5.2 mappings; empty credential fields admitted; a second `Authorization` header and a Basic client credential admitted at the token endpoint; the body ceiling missing on one decoder; unbounded `state`/`nonce`; an open JWK parameter list), 1 note; ruled; correction 1 dispatched.
- Enforcement opening commit `fe03999`; four unit trees cut; four implementors dispatched.
- `authored-denial-scenarios` implementor green: 23 files (+1814 lines) and `ess-inputs.yaml`; `author` 23/23, 0 refusals; synthesize 146 → 169 scenarios, 52 refusals unchanged; three findings routed (the summary cap; the redirect reason; `ExternalPrincipal` and `AuthorizationCode` seeding for the target). Adversary dispatched.
- Adapters correction 1 green (two crates 110 → 140; the CRLF case restated by the coordinator to the ruled refusal); adversary 2 dispatched.
- `mutation-controls` round 1 implementor green: `xtask/src/mutants.rs` (605 lines), `xtask/tests/mutants.rs` (6 cases), ten `tests/mutants/*.{patch,json}`; the ten warm in 25–30 s, cold ~100 s (a second CI job not needed at 20 min; decided at close); `xtask` 78 → 84 tests. Adversary dispatched.
- Authored-denials adversary (`review-result:wave-d-authored-denials-adversary-1`): 9 blockers (clauses unreachable from a file: possession decided first on secrets that live only in responses; tenancy unseeded; unsigned proofs the real verifier refuses; no port from a refresh proof to a session), 5 warnings, 2 notes; ruled — seed through `setup:` with real domain-separated digests computed offline, seed tenancy through real commands, the decode-only verifier as a recorded standing double, one case dropped; correction 1 dispatched.
- `coverage-map` implementor green: `contracts/coverage.json` 292 entries (205 implemented / 26 declared / 61 deferred), `xtask/src/{coverage,receipt}.rs`, 17 step cases, three new registries with exhaustiveness cases, eight per-crate manifest cases; nine packages 1060 → 1091. Two core types stay `declared` (no `mandate-token` registry; routed). Adversary dispatched.
- Login-adapters adversary 2 (`review-result:wave-d-login-adapters-adversary-2`): 2 blockers (three redemption-reachable clauses answer `invalid_client`; the reachability check reads two files and the path spans three), 4 warnings, 2 notes; ruled; adversary cases 2, 4, 5, 6 amended by the coordinator; correction 2 dispatched.
- `conformance-target` implementor green in its tree (27 cases; report/2 over the 146-scenario suite: 14 passed / 39 failed / 93 unsupported / 0 skipped); `mandate-token` was missing from the crate's dependency line, so the whole `mandate.credential` domain was `Unsupported`; the coordinator applied the admission (`Cargo.toml`, boundaries, lock) and resumed the implementor for the eleven credential arms.
- `conformance-target` round 2 green: 28 cases; report/2 29 passed / 54 failed / 63 unsupported over 146 scenarios; 15 credential scenarios pass against the real STS handlers; `RefreshSession` stays unsupported (`RefreshCredential` projected nowhere → `story:session-epochs`); tenancy/graph `Denied` discriminator gap routed to `story:tenancy-graph-events`. Adversary dispatched.
- `coverage-map` adversary (`review-result:wave-d-coverage-map-adversary-1`): 2 blockers (23 derived `.State` entries name generated contract symbols as implementations, 13 of them for records that are not implemented; `CredentialDescriptor`/`CredentialProfile` deferred on an unrelated blocker), 3 warnings, 1 note; ruled — a generated symbol is never an implementation, a `.State` follows its record, `mandate-token` gains a registry (scope extended); correction 1 dispatched.
- `mutation-controls` adversary (`review-result:wave-d-mutation-controls-adversary-1`): 0 blockers, 4 warnings (`check-fails` kills on any non-zero exit; the anchor is never compared with where the patch landed; the reused copy is never pruned; the catalogue would run twice per gate), 3 notes; ruled; correction 1 dispatched.
- Authored-denials adversary 2 (`review-result:wave-d-authored-denials-adversary-2`): 3 blockers (the decode-only verifier double the summaries name lives in the sibling conformance unit as `mandate_conformance::external::ScenarioVerifier`, so the federation claim files resolve at integration), 5 warnings, 2 notes; ruled; one more file dropped (`pkce-stale-session-epoch`, unestablishable snapshot generation); two draft stories created as live homes for post-implementation gaps: `story:epoch-snapshot-generations`, `story:refusal-discriminators`; earlier routings to `implemented` stories withdrawn; correction 2 dispatched.
- Login-adapters correction 2 green (155 tests); unit commit `d3f6445`, merge `6c4c397`; listener tree cut from the merged head and `story:product-listener` implementor dispatched.
- Conformance-target adversary (`review-result:wave-d-conformance-target-adversary-1`): 2 blockers (`blocked_on` naming an implemented story; 21 of 23 armed injections inert and attributed as the cause of a pass), 2 warnings, 3 notes; ruled; correction 1 dispatched.
- Authored-denials correction 2 green (20 files, suite 166); the bot commit was refused by the `b10x-gates` pre-commit hook (13 secret-scanner findings on synthetic JWS fixtures: `jwt`, `jwt-base64`, `generic-api-key`); admission is a trusted-policy exception, the operator's; the unit waits in its tree and merges last.
- `coverage-map` correction 1 green (1350 workspace tests; 190 / 40 / 62 of 292); adversary 2 dispatched.
- `conformance-target` correction 1 green (35 cases; injections carry `consulted`; 2 armed / 12 armed-standing / 9 armed-unreached); adversary 2 dispatched.
- `mutation-controls` correction 1 green (94 xtask cases; catalogue 26 s); adversary 2 dispatched.
- `coverage-map` adversary 2 (`review-result:wave-d-coverage-map-adversary-2`): 3 blockers (the four identity epoch `.State` entries contradict the unit's own rule; 16 `declared` entries route at `implemented` stories; the receipt writer's signature cannot be wired into `generate()`), 1 warning; ruled; correction 2 pending.
- **Outage** (~15:40): Opus weekly limit reached (resets 2026-09-24 04:00 Europe/Berlin). Killed mid-work: `product-listener` implementor (partial: `adapters.rs` 1251 lines, `tests/{adapters,serve}.rs`, the `store.rs` read; no `serve.rs`, no gate run), `conformance-target` adversary 2 and `mutation-controls` adversary 2 (nothing written). Not dispatched: `coverage-map` correction 2. Open operator decision: wait for the reset / authorize another model for sub-agents / coordinator-side work; default on silence recorded in the operator report.
- `coverage-map` correction 2 green (coordinator-implemented, deviation 3); unit `f370aaf`, merge `6ada847`; coverage wiring + receipt alignment commit `1d2c70d`; `cargo xtask coverage` 201 / 29 / 62 of 292 and `contracts` byte-identical on the integration head.
- Full `task check` on the integration head `1d2c70d`: exit 0, 1496 tests across 200 targets, coverage 201 / 29 / 62 of 292, projections and receipt byte-identical, 22 packages, 10 documents. `story:login-adapters` and `story:coverage-map` moved to `implemented` on that record.
- `product-listener` finished by the coordinator in the main session after the Opus outage: 22 cases (the road end to end over raw TCP), 220 across the two packages; unit `82c6419`, merge `c306da3`, serve-row alignment `3cbab1a`. No adversary pass ran (deviation 4). Full `task check` on `3cbab1a` running.
- Full `task check` on `3cbab1a`: exit 0, 1518 tests across 202 targets, coverage 201 / 29 / 62, projections and receipt byte-identical, 22 packages, 10 documents. `story:product-listener` moved to `implemented` on that record.

## Declared deviations

1. The coordinator applied two implementor patches to coordinator-owned adversary files in the adapters unit (`crates/mandate-proto/tests/adversary_adapters_2.rs` clippy findings from the coordinator's own amendment; `crates/mandate-server/tests/adversary_adapters_1.rs` struct literals over `Jwk.parameters`, rewritten through `Jwk::new` for ruling F7) after verifying fmt, clippy and the 155-test suite in the unit tree.

2. The coordinator-owned adversary file `crates/mandate-token/tests/adversary_authored_2.rs` is held out of the authored unit commit and lands in the alignment commit after the conformance-target merge: its case 2 reads `crates/mandate-conformance/src/external.rs` (the decode-only double the scenarios name) and is red on any tree without it.

3. The coordinator implemented `coverage-map`'s correction round 2 itself (the Opus sub-agent weekly quota was exhausted mid-wave, resets 2026-09-24 04:00 Europe/Berlin), against the two adversary files as independent checks and the unit's own cases; the implementor/coordinator separation the protocol assumes did not hold for that round.

4. `product-listener` was finished by the coordinator in the main session (the Opus implementor was terminated mid-unit by the weekly quota) and merged with **no adversary pass**: the wave protocol's two passes are owed and are the next wave's first item; the coordinator's self-review is recorded on the story and is not a substitute.

None yet.

## Close

Wave D closes in two halves. This half — `login-adapters`, `coverage-map`, `product-listener` and the two coordinator alignments (coverage wiring + receipt, serve rows) — is published from `3cbab1a` with the gate above; the goal's road is served end to end. Carried to the next wave, each green in its tree: `conformance-target` (adversary 2 owed), `mutation-controls` (adversary 2 owed, then round 2: `coverage_mutants.rs`, `manifest-relabel`), `authored-denial-scenarios` (commit blocked on a trusted-policy exception for synthetic JWS fixtures; the held adversary file `crates/mandate-token/tests/adversary_authored_2.rs` lands with it), and the two adversary passes `product-listener` is owed. The tracker `initiative:drift-enforcement` carries the rows.
