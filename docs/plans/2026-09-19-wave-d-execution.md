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

## Declared deviations

None yet.

## Close

Pending.
