# Wave C — the authorization-code transaction at the STS

**Skill version 0.9.2** — `aep-drive`. **AEP** `protocol 0.55.0`. **ESS** `ess 0.26.0`. Base: `0589bce`, the last bot-only commit whose tree equals `main` at `7f3bcd7` (wave B merged through PR #12). Integration branch `integration/wave-20260919-004`.

## Why this wave

The login road after wave B: a verified login opens a Session (`AuthenticateFederation`), the control plane turns it into an authorization request (`AuthorizePublicClient`, landed) and assembles the `IssueAuthorizationCode` input by value, and the STS holds the credential families, the audience registry and introspection. What is missing between the two is the STS-side transaction: the `AuthorizationCode` record, its issuance, and its one-winner redemption into a credential. `story:oauth-integration` carried that together with the HTTP endpoint and depended on the endpoint stories; the wave C opening splits it — `story:oauth-transaction` (this wave) carries the library part with no dependency off `main`, `story:oauth-integration` keeps the endpoint.

## Selection

| Story | Status at opening | Agent | Lands in |
|---|---|---|---|
| `story:declared-writers` | active | one Opus implementor, contract round 2 (the three `credential.yaml` gaps the scoper named: `AuthorizationCodeRedeemed` carrying the credential it issues; the redemption's context and epoch source stated; the `pkce-missing` note), then the coordinator's regeneration | `systems/mandate/domains/credential.yaml`, `command-obligations.md` if a denial changes |
| `story:oauth-transaction` | draft → active | one Opus implementor, cut from the regenerated head; units `store`, `code`, `binding`, `redemption` | `services/sts/src/{lib,store,code,binding,redemption}.rs` and tests |

Not selected: `story:oauth-integration` (endpoint; depends on `protocol-adapters`, `product-listener`), `story:constrained-exchange` (collides on `services/sts` until refined), the E2 set (deferred by the operator).

Sequential by the generated shapes: the contract round changes `AuthorizationCodeRedeemed`'s shape, which the transaction's emitted-event tests construct, so the implementor's tree is cut after regeneration (the wave B rule).

## Coordinator pre-lands (opening commit)

1. Store: `story:oauth-transaction` created with its Scope, edges (`depends_on credential-profiles`, `pkce-sessions`; `oauth-integration depends_on` it); `story:oauth-integration`'s Scope re-recorded to the endpoint; the contract gaps routed on `story:declared-writers`; the critic review-results and opening rulings.
2. `tests/security/cases.json`: `pkce-valid`, `pkce-wrong`, `pkce-redirect`, `pkce-reuse` → `story:oauth-transaction`; `pkce-missing`, `pkce-plain` → `story:protocol-adapters` (unrepresentable at the STS: `pkce_verifier` is non-optional, `PkceMethod` has one variant); `pkce-state-nonce` stays `story:oauth-integration`'s (state and nonce are `AuthorizePublicClient`'s inputs, the endpoint's round trip). `cargo xtask corpus`: 50 scenarios traced.
3. No manifest change: `mandate-sts` already carries every dependency the units need; `eventlog-core` is not admitted (the in-memory fake is a test double with the kit's shape, ADR 0009: no second mechanism).

Ruling on ownership: `services/sts/src/lib.rs` is the `oauth-transaction` implementor's this wave (the registry rows, `ESS_UNREALIZED`, the allocator method), as it was `credential-profiles`' in wave B; no other unit touches `services/sts`. The `AccessCredential` fold arm seeded by `AuthorizationCodeRedeemed` (`crates/mandate-token/src/projection.rs`) and the `AuthorizationCode.State` line in `crates/mandate-federation/src/lib.rs` are the same implementor's; its gate adds `cargo test -p mandate-token -p mandate-federation`.

## Commits this wave makes

Through `atlas/scripts/as-bot.sh`, author and committer `b10x-bot[bot]`: this opening commit; one commit per unit round (`declared-writers` contract round, `oauth-transaction`); one `--no-ff` merge each; the coordinator's regeneration commit after the contract round; alignment commits where a ruling moves a pinned value; the closing store commit; publication through `b10x-gates` from the bot-only lineage; the PR to `main` and its App merge. No tag, no release.

## Preflight

- Tree `mandate-wc-coordinator` cut from `0589bce`; `cargo xtask adopt` run once; lease held. Disk 87G free at opening.
- `aep plan artifact validate`: valid.

## Stage log

- Scoper (Opus, read-only): `story:oauth-integration` — the library part is implementable now behind ports; the record's home is `services/sts` (three citations); the control plane's call is a value, not a port; sessions and epochs through a port declared at the STS; three contract gaps; three of the seven `pkce-*` cases weaker than the body claimed (`pkce-missing`, `pkce-plain` unrepresentable at the STS; `pkce-state-nonce` not the STS's).

- Critic panel round 1 (Opus, read-only, 2): parallel-safety `needs-revision`, 3 findings (gap 3 had no landing file; the endpoint story's stale scope rows and Units table; `product-listener` omitted from the collisions); design `needs-revision`, 6 findings (the same stale scope; no owner for the `AccessCredential` fold arm the redeemed event seeds; gap 1's field set short of the record; the federation registry still naming `AuthorizationCode.State`; no `depends_on declared-writers`; `pkce-sessions` cannot own a corpus row). All ruled at the opening: the transaction story owns the token fold arm and the federation registry line; the redeemed event mirrors `CredentialReferenceIssued`'s record fields; the seven `pkce-*` rows reassigned (four to `oauth-transaction`, two to `protocol-adapters`, `pkce-state-nonce` stays on `oauth-integration`); `oauth-transaction` active.

- Opening commit `975788e`; `task check` on it: exit 0, 1205 tests across 173 targets.
- `declared-writers` contract round 2 implementor green: `credential.yaml` +26/−1 — `RedeemAuthorizationCode` responds `credential_id` and `target`; `AuthorizationCodeRedeemed` carries `credential_id`, `target`, `reference_verifier`, `epochs` (generated, the implementor's call, flagged for the adversary), `issued_at`; the header declares it seeds an `AccessCredential`; an accepted summary states the context and epoch source. Validate 14 files; corpus 61; synthesize unchanged 146/52 with identical refusals; no element added, no pin or fixture red (two hits on the generated names, both definitions). Adversary 1 dispatched.

- Contract adversary (`review-result:wave-c-writers-contract-adversary-1`): 19 probe cases, 11 red; 2 blockers (`epochs` sourced `generated` unlike the other three creators; the context account missing `credential` and `correlation`), 3 warnings, 3 notes; ruled. Correction 1 green: the response carries `epochs`, the context account names every field, the header names the issuing registration; 51/51 probe cases; adversary probes 16/20 green, 4 red by ruling (the generated-Optional class ×2, the IR's three creators, the design row until aligned).
- Unit commit `46c9a39`; merge `6fe547b`; coordinator regeneration (`MandateCredentialRedeemAuthorizationCodeResponse` +3 fields, `MandateCredentialAuthorizationCodeRedeemed` +5; no count pin moves) and `docs/architecture/federated-login.md:52` aligned to the five-field response.

- Regeneration commit `f951f9d`; `task check` on it: exit 0, 1205 tests across 173 targets. Transaction tree cut from it.
- `oauth-transaction` implementor green: 18 files +5589/−144 — `store` (the `AuthorizationCode` record, events, fold, the compare-and-set port and its fake), `code`, `binding` (the session/epoch port mirrored over `mandate-types` values), `redemption` (the one-winner race pinned), the `AccessCredential` fold arm from the redeemed event in `mandate-token`, the registries (STS realizes 6 more elements; `AuthorizationCode.State` leaves federation's), `DenialClause` +16 variants (one per declared denial phrase); three crates 500 → 558 tests, workspace 1263; fmt, clippy, boundaries, corpus green. Judgement calls recorded in the module docs: the credential's expiry is the minimum of the profile's `max_ttl` and the code's `expires_at`; the issuance target rule is wave B's `admitted_target` (no holder test); no code-lifetime ceiling exists in the contract (residue). Adversary 1 dispatched.
- Transaction adversary 1 (`review-result:wave-c-oauth-transaction-adversary-1`): 24 cases, all green, retained; no blocker; 3 warnings (`public` and the exact redirect not re-checked at issuance; no code-lifetime ceiling), 2 notes; ruled; correction 1 dispatched.
- Transaction correction 1 green: `is_public` and `redirect_registered` on the client port with refusals at issuance; `CodeIssuance::new(CodeLifetime)` carries the deployment's ceiling; the session clauses merged into the two phrases the denial carries; `tests/declared_denials.rs` (62 rows, both directions for the two code commands). The coordinator amended the pass-1 adversary file: the mechanical adaptation, the two characterizing cases rewritten to the ruled behaviour (refused with `RedirectUnregistered`/`ExpiryUnbounded`, nothing minted), the property case issuing under a wide ceiling. Three crates 558 → 591 tests; fmt, clippy green. Adversary 2 dispatched.
- Transaction adversary 2 (`review-result:wave-c-oauth-transaction-adversary-2`): 2 cases, both red; no blocker; 3 warnings (a missing denial-table row; the verifier decided after the session re-reads; the session clause rowed to the wrong phrase), 3 notes; ruled; correction 2 dispatched. Two contract observations and the scope-narrowing residue routed on `story:declared-writers`.

## Declared deviations

1. Four prose and allowance edits outside the transaction unit's file set (`crates/mandate-token/{src,tests}/verifier.rs` "used by nothing in this wave"; `crates/mandate-federation/src/lib.rs` `ESS_UNREALIZED` reason; `crates/mandate-federation/tests/contract_agreement.rs` — the `cross_domain` allowance for `AuthorizationCode.State` became unreachable once the line moved to the STS registry) were written by the implementor as patches and applied by the coordinator inside the unit tree before the adversary pass, so they land in the unit's commit rather than an alignment commit.

## Close

| Measure | Value |
|---|---|
| Closing gate | `658f396`, `task check` exit 0, 1306 tests across 181 targets (opening: 1205 / 173) |
| Units | contract round 2 `46c9a39` (merge `6fe547b`), transaction `e7ff558` (merge `658f396`) |
| Coordinator commits | opening `975788e`, regeneration `f951f9d`, the closing store commit |
| Adversary passes | 3 (1 contract, 2 transaction), 19 findings, all ruled; 26 adversary cases retained |
| Stories | `oauth-transaction` implemented on the gate's record; `declared-writers` stays active (contract rounds 1–2 landed; units B and C2 remain) |
| Blockers | none cleared; `decision-blocker:epoch-atomicity` advanced by the race case, not cleared (isolation level per boundary undecidable in these crates) |
| Deviations | 1 (four prose and allowance edits applied inside the unit tree) |
| Release | none |

Routed onward: the `RedeemAuthorizationCode` and `IntrospectCredential` denial phrases the STS cannot row exactly (a session unresolved, revoked or expired; a presented credential of another organization) and the `RegisterSigningKey` window phrase (`story:declared-writers`, contract); scope narrowing at issuance (`mandate-authz`, the composition); the refusal constructor demanding a phrase (four handler files, a later STS story); the ESS one-subject-per-outcome limit (ESS wave).

Next on the road: `story:protocol-adapters` and `story:product-listener` (the endpoint and the served route), then `story:oauth-integration`'s acceptance over HTTP.
