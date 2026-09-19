# Wave B — credential profiles and the login road's declared writers

**Skill version 0.9.2** — `aep-drive` at `.claude-plugin/plugin.json` of the loaded plugin. **AEP** `protocol 0.55.0`. **ESS** `ess 0.26.0` (unchanged). Base: `main` at `a76267b` (wave A merged through PR #11). Integration branch `integration/wave-20260919-003`.

## Why this wave

The operator's priority of 2026-09-19 is the customer login road: a user signed in at the customer's own identity provider enters a Mandate-protected flow and ends with a Mandate credential (`docs/architecture/federated-login.md`). After wave A the road has real verification and signing behind ports, a login that opens a Session, and projections that agree with the contract. What it lacks next, in dependency order (`aep plan artifact waves`): the credential families, the audience registry and introspection (`story:credential-profiles`, on which `oauth-integration`, `protocol-adapters` and `product-listener` all depend), and the two records the road creates without a declared writer — the `Principal` a first login provisions and the `OAuthClient` an authorization request reads (`story:declared-writers`). Waves E2–E4 of the drift-protection plan stay deferred behind the road.

## Selection

| Story | Status at opening | Agent | Lands in |
|---|---|---|---|
| `story:declared-writers` | active | one Opus implementor, two rounds: the contract round (A1, A2, C0, C1) first, one adversary pass, merge, the coordinator's regeneration; then the realization round (A3, A4) | `systems/mandate/domains/{identity,federation,credential}.yaml`, `components.yaml`, `command-obligations.md`; then `crates/mandate-identity/src/{port,lib}.rs`, `crates/mandate-federation/src/{register_client,record,lib}.rs` and tests |
| `story:credential-profiles` | active | one Opus implementor, cut from the regenerated head; units `projection`, `verifier`, `registry`, `issue`, `resolve`, `keys` in the order the story's Scope and rulings state | `crates/mandate-token/src/{projection,verifier}.rs`, `services/sts/src/{lib,registry,issue,resolve,keys}.rs`, their tests |

Not selected: `story:oauth-integration`, `story:product-listener`, `story:protocol-adapters` (each `depends_on` a story in this wave or a draft outside it); the E2 set (`coverage-map`, `authored-denial-scenarios`, `conformance-target`, …) by the operator's prioritization; `declared-writers` units B and C2 (creators outside the road) to a later wave.

Disjoint by file, sequential by the IR: `credential-profiles` touches nothing under `systems/`, `generated/`, `crates/mandate-identity`, `crates/mandate-federation`; `declared-writers` touches nothing under `crates/mandate-token`, `services/sts`; but the credential realization registry asserts the `mandate.credential` element set exhaustively against `generated/ir/system.json`, which the contract round changes (`review-result:wave-b-parallel-r1`), so `credential-profiles`' tree is cut only after the regeneration commit (`depends_on` recorded). Workspace one-writer files (`Cargo.toml`, `Cargo.lock`, `dependency-boundaries.json`, `xtask/src/main.rs`, `generated/**`, the count pins, `tests/security/cases.json`) are the coordinator's.

## Coordinator pre-lands (opening commit)

1. `services/sts/Cargo.toml`: a `[lib]` target beside the `[[bin]]`; `serde`, `serde_json`, `mandate-types`, `mandate-model`, `mandate-token`; dev `mandate-contract`, `mandate-testkit`. `services/sts/src/lib.rs` as an empty crate root with the crate doc.
2. `crates/mandate-token/Cargo.toml`: dev `mandate-contract`, `mandate-testkit`.
3. `dependency-boundaries.json`: a `mandate-sts` key (`clap`, `serde`, `serde_json`, `sha2`, `mandate-types`, `mandate-model`, `mandate-token`, `mandate-contract`, `mandate-testkit`); `mandate-token` gains `mandate-contract`, `mandate-testkit`. No `mandate-federation` edge: the `TargetRegistry` adapter over the credential fold is the composition's (`story:product-listener`, ruled on `credential-profiles`).
4. `xtask/src/main.rs`: `LIBRARIES` 16 → 17 and the doc comment naming the packages without an entry.
5. `tests/security/cases.json`: `profile-offline-bound` names `IssueSelfContainedCredential` (a "signed credential" case; it named the reference family).
6. Store: the two Scope sections re-derived after wave A; `story:credential-profiles depends_on story:audit-client` downgraded to `informed_by` (no reason recorded, and `services/sts` cannot depend on `mandate-audit` under the boundary policy); `story:signing-and-verification depends_on story:credential-profiles` removed and the true edge recorded the other way; `credential-profiles depends_on declared-writers`; the opening rulings (9 on `credential-profiles`, 7 on `declared-writers`); both stories `active`; `review-result:wave-b-parallel-r1` (3 findings) and `review-result:wave-b-design-r1` (8 findings), outcomes `fixed`.

## Commits this wave makes

Through `atlas/scripts/as-bot.sh`, author and committer `b10x-bot[bot]`: this opening commit; one commit per unit round on its `impl/*` branch (`credential-profiles` one, `declared-writers` two); one `--no-ff` merge per unit round; the coordinator's regeneration commit after the contract round merges (`generated/**`, count pins, `docs/architecture/federated-login.md` lines naming the Principal's writer); alignment commits where a ruling moves a pinned value; the closing store commit; publication through `b10x-gates`; the PR to `main` and its App merge. No tag, no release.

## Preflight

- Tree `mandate-wb-coordinator` cut from `main` `a76267b`; `cargo xtask adopt` run once (4 projection owners); lease held.
- Disk: 70G free on `/` at opening; unit trees build in-tree `target/`, removed at finish.
- `aep plan artifact validate`: valid after the store pre-lands (20 legacy prose-only review warnings unchanged).

## Stage log

- Critic panel round 1 (Opus, read-only, 2): parallel-safety `needs-revision`, 3 findings (the credential registry versus the contract round's two new elements; two owners named for the crate roots); design `needs-revision`, 8 findings (a backwards `depends_on` on `signing-and-verification`; no edge recording the contract-round order; `TargetRegistry` would need a federation edge; no caller for `SigningKey`; `organization_id` beside `context` on `OAuthClientRegistered`; `CredentialIntrospected` naming neither credential nor answer; the Session arm's rule for a principal without a record; Exclusions contradicting A4). Every finding ruled at the opening; none deferred.
- Scopers (Opus, read-only, 2): `credential-profiles` — four superseded unit rows dropped, three contract gaps named (`IntrospectCredential` active/denied, `SigningKey` has no creator, `profile-offline-bound` names the wrong family), the `audit-client` edge unexplained; `declared-writers` — Principal needs a declaration only (P1), OAuthClient needs a creator, the fold homes decided by the crate direction.

## Declared deviations

None yet.

## Close

Pending.
