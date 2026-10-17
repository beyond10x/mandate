# Wave 11 (OpenID Provider, spec first): proposal and execution

Opened 2026-10-16 on `integration/wave-20261015-003`, cut from `main` at `04e1465` (0.9.0); the
branch carries ADR 0012, ADR 0013 and the epic's stories (`87a2e69`). Epic: `epic:openid-provider`,
plus `story:token-guard` (`informed_by` the epic). This is the epic's spec-first wave, "W1" of its
plan, after the forks were decided (`decision-blocker:oidc-design-forks`, cleared 2026-10-15,
`.engineering/planning/decision-blocker/oidc-design-forks.md:5,16,36-50`).

Purpose: every parity contract change modelled in `systems/mandate` before any of it is built, one
unit per domain file, with each new scenario observed failing and recorded as such
(`docs/adr/0012-openid-provider.md:137-138`; `.engineering/planning/epic/openid-provider.md:38-39`).
Beside the spec units, three units with no contract to wait for: the token guard's spec and
library, the image and health half of packaging, and the federation fold over the `eventlog` kit.

## Before any unit (coordinator)

0. **Merge `origin/main` (`cd691e8`, 0.9.1) into the integration branch.** This branch's base is
   `04e1465`. `main` has since moved the pins to ESS 0.60.0 and AEP 0.73.0 (`1151324`): on `main`,
   `xtask/src/main.rs:112` requires `ess 0.60.0`, and `AGENTS.md:13` names ESS 0.60.0. This tree
   still requires exactly `ess 0.59.0` (`xtask/src/main.rs:85-90,112`, `xtask/src/conform.rs:93`,
   `.github/workflows/ci.yml:24`, `AGENTS.md:13`), while `ess` on PATH is 0.60.0. Without the
   merge, `cargo xtask generate` refuses with "required tool: ess 0.59.0". With it, every unit
   validates and generates with 0.60.0, the newest `ess` installed on this host.
   Done 2026-10-16 as `13c7e6a`, merging `main` at `e9230f2` (0.9.2), which already holds wave 10.
1. **Wave 10 lands on `main` first** (see "Overlap with wave 10"). Done: wave 10 merged as
   `f072085` and shipped in 0.9.2 before step 0, so every unit is cut from `13c7e6a` or later.
1a. **U0, the AEP repin (`story:tooling-repin-aep-0-74`), coordinator.** AEP 0.74.0 is on PATH.
   `aep plan store migrate git --dry-run` under 0.74.0: "already selects `aep.project/5` … nothing
   to migrate or repair". The pins move to 0.74.0 in `xtask/src/main.rs:604`,
   `.github/workflows/ci.yml:24`, `AGENTS.md:13`, `README.md:26` and `docs/public/development.md:7`.
2. Validate the merged head (`ess specify validate --strict-requires --path systems/mandate`), then
   `cargo xtask adopt` once in each fresh unit tree before `cargo xtask generate`
   (`AGENTS.md:13`; `xtask/src/main.rs:183-221`).

## Decisions taken for the units

1. **The F15 rename is not in this wave.** `AuthorizePublicClient` → `AuthorizeClient`
   (`.engineering/planning/story/oidc-discovery-and-code-flow.md:57-59`) reaches
   `crates/mandate-server/src/{routes,metadata,decode}.rs`, `services/control-plane/src/{adapters,serve}.rs`,
   `services/sts/src/{code,store}.rs`, 13 files in `crates/mandate-federation` and 3 in
   `crates/mandate-conformance` (`git grep -l AuthorizePublicClient`). That would share files with U5
   and with wave 10. The rename and the scenarios that need it move to P1's unit (b) in a later wave
   (`oidc-discovery-and-code-flow.md:124-125`): `oidc-authorize-confidential-without-pkce`,
   `oidc-authorize-public-without-pkce-refused` (`:60-62`) and `oidc-authorize-peer-audience-scope`
   (`.engineering/planning/story/oidc-trusted-peers.md:46-48`).
2. **`oidc-refresh-epoch-mismatch-refused` is deferred**
   (`.engineering/planning/story/oidc-refresh-and-logout.md:55`). `SecurityEpochSnapshot` declares
   no generation, so no `setup:` can make a snapshot that is behind
   (`systems/mandate/ess-inputs.yaml:45-48`). That half belongs to
   `story:epoch-snapshot-generations` (`oidc-refresh-and-logout.md:86-87`). U3 records the deferral
   as an `ess-inputs.yaml` comment, in the form of `:39-48`.
3. **The keys and JWKS half of P2 (P2a) moves to wave 12.** It needs `crates/mandate-server/src/metadata.rs`
   and `services/control-plane/src/main.rs`
   (`.engineering/planning/story/oidc-signed-tokens-and-key-rotation.md:87,89`), and so does U5
   (`.engineering/planning/story/oidc-deployment-package.md:57-59`). The story's own text puts it in
   wave 2 of the epic (`oidc-signed-tokens-and-key-rotation.md:103-104`). Until then, readiness reflects
   the keys admitted from `--key` documents; P2a rewires it to the signer.
4. **New scenarios are recorded as failing first.** Each one enters `contracts/expected-outcomes.json`
   as `"outcome":"failed"` with `blocked_on` naming its implementing story (the form of
   `contracts/expected-outcomes.json:14`), and a later implementing unit flips it. A spec unit is
   green when `ess specify validate --strict-requires` is valid, `cargo xtask generate` leaves no
   drift (`xtask/src/main.rs:176-178`) and `cargo xtask conform` matches the ledger.
5. **Generated Rust spills into crates.** `generated/rust/mandate-contract` compiles into
   `crates/mandate-contract` (`crates/mandate-contract/src/lib.rs:31-43`), which mandate-model,
   mandate-types, mandate-identity, mandate-federation, mandate-token, mandate-server, sts and
   control-plane import (`git grep -l mandate_contract`). A spec unit may touch a consumer only
   where the regenerated types stop it compiling, and it lists those lines. Behaviour stays with
   the implementing stories.
6. **The token guard is a new domain**, `mandate.guard` in `systems/mandate/domains/guard.yaml`. ADR
   0013 models the allow rule, the limits and the refusals (`docs/adr/0013-token-guard.md:35-37`),
   and the guard owns them, in a file no other unit edits. The admission is a command whose
   accepted outcome emits an event and creates or moves nothing. Wave 8's `AuthenticateWorkload`
   took the same form (`docs/plans/2026-10-13-wave-8-execution.md:22-26`). Per-identity limits are
   counters. If ESS refuses an outcome decided by one, as `ESS-COMMAND-003` refused an outcome
   chosen by an identity (`docs/plans/2026-10-13-wave-8-execution.md:19-20`), U4 stops and reports.
   It does not keep a parallel model in Rust.
7. **`story:domain-folds-over-the-kit` needs its blocker cleared.** `decision-blocker:async-runtime`
   is open (`.engineering/planning/decision-blocker/async-runtime.md:5`) and blocks the story
   (`.engineering/planning/story/domain-folds-over-the-kit.md:64-66`). The runtime has already been
   decided: fork F9, "tokio + hyper, the organization `eventlog` kit on SQLite on a volume"
   (`docs/adr/0012-openid-provider.md:161`, accepted by the operator, `:3`). Every earlier clearing
   was recorded as a human act in each `decision-blocker/*.md` transition. The clearing is the
   operator's, citing ADR 0012:161, and is on this branch as `2cc62c8`. Without it, U6 is not dispatched
   and the wave is five units wide.

### Decisions taken during the wave

8. **Unrealized commands are recorded as `unsupported`**, not `failed` as decision 4 said: that is
   what `cargo xtask conform` answers for a command with no adapter, and the ledger records the run's
   answer with the owner the run names.
9. **`InvalidClient`** joins `DenialReason` and `DecisionReason` (`systems/mandate/domains/core.yaml`);
   the authorization endpoint maps it to `AccessDenied`.
10. **Test proofs in scenarios use `scenario.<payload>.unsigned`** with a `kid` claim, and client
    secrets in scenarios are low-entropy placeholders, so the secret scan has nothing to match. No
    policy exception was added.
11. **`RedeemAuthorizationCode/outcome/denied` stays `failed` on
    `story:ess-synthesizer-prerequisites`.** The identity-token branch makes the synthesizer arrange
    the code through `IssueAuthorizationCode` with placeholder ids, and the target refuses that
    arrangement, as it should. The `accepted` row is red for the same reason. Loosening the target
    would weaken a refusal; the row flips when the synthesizer can arrange real prerequisites.
12. **`ResourceServer.client_id` stays.** RFC 8693 `audience=<client id>` names a client, and the
    trusted-peer admission needs the client a resource server backs. The alternative, a default
    resource server on `OAuthClient`, is left to `story:oidc-trusted-peers`.
13. **`RotateRefreshCredential` is deferred** in `contracts/obligations/identity.json` on
    `story:oidc-refresh-and-logout`, which realizes it; `mandate.guard.AdmitRequest` is deferred in
    `contracts/obligations/authz.json` on `story:token-guard` (the registry's crate list is fixed).
14. **The security review's two introduced issues are fixed in this wave**: the guard refetches a
    JWK Set older than 15 minutes and refuses a key the fresh set no longer lists (refetches stay
    limited to one per 30 s); `RegisterOAuthClient` decides the denials its input alone decides.
    Two follow-ups are drafted rather than built: a bound on how long the guard may keep a stale set
    when every refetch fails (today it keeps it, as the `JwksSource` contract says), and redaction
    tombstones in the federation fold (no path redacts today).

## Units

| unit | story | owns (files) | spec-first step | acceptance (named) | tier | build | ETA |
|---|---|---|---|---|---|---|---|
| U1 `spec-federation` | `story:oidc-static-client-registry` (contract half), `story:oidc-google-upstream` (contract half of (a)) | `systems/mandate/domains/federation.yaml`, `systems/mandate/domains/core.yaml`; new `systems/mandate/scenarios/{oidc-client-*,federation-hosted-domain-*,federation-profile-*,federation-groups-*}.yaml`; compile-only spill per decision 5 | `OAuthClient` gains `client_type`, `secret_verifiers` (`List<mandate.core.CredentialVerifier>`, `core.yaml:123`), `pkce_required`, `trusted_peers`, `post_logout_redirect_uris`, carried by `RegisterOAuthClient` and `OAuthClientRegistered` (`oidc-static-client-registry.md:43-47`); `TenantResolutionRule.verified_claim_values` (`core.yaml:273`; `oidc-google-upstream.md:52-55`); event `ExternalProfileObserved` (`:56-59`) | `oidc-client-confidential-registered`, `oidc-client-public-with-secret-refused`, `oidc-client-public-pkce-optional-refused`, `oidc-client-peer-unknown-refused` (`oidc-static-client-registry.md:48-54`); `federation-hosted-domain-listed`, `federation-hosted-domain-unlisted-refused`, `federation-profile-observed-on-login`, `federation-profile-groups-filtered`, `federation-groups-over-cap-refused` (`oidc-google-upstream.md:52-61`) | opus | 3G | 1 day |
| U2 `spec-credential` | `story:oidc-signed-tokens-and-key-rotation` (contract half), `story:oidc-discovery-and-code-flow` (redemption half), `story:oidc-trusted-peers` (exchange half) | `systems/mandate/domains/credential.yaml`; new `systems/mandate/scenarios/{oidc-redeem-*,oidc-id-token-*,oidc-no-id-token-*,oidc-sign-*,oidc-retire-*,oidc-peer-*}.yaml` | `RedeemAuthorizationCode` gains client-authentication inputs (`oidc-discovery-and-code-flow.md:96-97`), and its response declares `id_token` and `expires_in`; event `IdentityTokenIssued` with no claim values (`oidc-signed-tokens-and-key-rotation.md:51-54`); `ExchangeCredential` admits an ID-token subject (`oidc-trusted-peers.md:42`) | `oidc-redeem-client-auth-failed`, `oidc-redeem-public-with-secret-refused` (`oidc-discovery-and-code-flow.md:63-65`); `oidc-id-token-issued-on-openid`, `oidc-no-id-token-without-openid`, `oidc-sign-with-retired-key-refused`, `oidc-retire-without-successor-refused` (`oidc-signed-tokens-and-key-rotation.md:55-59`); `oidc-peer-exchange-allowed`, `oidc-peer-exchange-not-trusted-refused`, `oidc-peer-cross-organization-refused` (`oidc-trusted-peers.md:42-45`) | opus | 3G | 1 day, merged after U1 |
| U3 `spec-identity` | `story:oidc-refresh-and-logout` (contract half) | `systems/mandate/domains/identity.yaml`; new `systems/mandate/scenarios/{oidc-refresh-*,oidc-end-session-*}.yaml`; the deferral comment in `ess-inputs.yaml` (decision 2) | `RefreshCredential` gains `family_id`, `client_id`, `predecessor`, `issued_at`, `last_used_at` and the states `Active \| Rotated \| Revoked`; events `RefreshCredentialIssued`, `RefreshCredentialRotated`, `RefreshFamilyRevoked`; command `RotateRefreshCredential` (`oidc-refresh-and-logout.md:45-48`) | `oidc-refresh-rotates`, `oidc-refresh-reuse-revokes-family`, `oidc-refresh-grace-sibling-once`, `oidc-refresh-wrong-client-refused`, `oidc-end-session-revokes` (`oidc-refresh-and-logout.md:49-57`) | opus | 3G | 1 day |
| U4 `token-guard` | `story:token-guard` (spec and library) | new `systems/mandate/domains/guard.yaml`; new `systems/mandate/scenarios/guard-*.yaml`; `crates/mandate-client/src/**`, `crates/mandate-client/Cargo.toml`, `crates/mandate-client/tests/**` | domain `mandate.guard` (decision 6): a guard policy (issuer, audiences, `allow.emails`, `allow.domains`, limits) and an admission command whose denied clauses are issuer, audience, expiry, unknown key, identity not allowed, over limit, queue full (`docs/adr/0013-token-guard.md:24-33`) | scenarios `guard-issuer-mismatch-refused`, `guard-audience-mismatch-refused`, `guard-expired-refused`, `guard-unknown-key-refused`, `guard-identity-not-allowed-refused`, `guard-identity-allowed-admitted` (`.engineering/planning/story/token-guard.md:37-40,44`); Rust tests `verify::jwks_rotation_picked_up_without_restart` (`:43`) and `verify::refusal_is_typed` (`:37-38`) | opus | 3G | 2 days (spec 0.5, library 1.5, `token-guard.md:48`) |
| U5 `deployment-image-health` | `story:oidc-deployment-package` (image and health half) | `deploy/docker/Dockerfile`; `crates/mandate-server/src/{routes,metadata}.rs` (health documents only), `crates/mandate-server/tests/routes.rs`; `services/control-plane/src/{main,serve}.rs` (`--config-dir`, dispatch); the image job in `.github/workflows/ci.yml` | none: health is a wire document (`oidc-deployment-package.md:51`, fork F14). The unit runs `ess specify validate` once to show no contract moved | `routes::health_paths_are_not_command_shaped`, `end_to_end::ready_reflects_signing_key`, `control_plane::config_dir_equivalent_to_flags`, the CI image runs `mandate-control-plane --version` (`oidc-deployment-package.md:39-48`) | sonnet | 3G (no local image build) | 1 day of 2 (`:76`) |
| U6 `domain-folds-federation` (only if the blocker is cleared, decision 7) | `story:domain-folds-over-the-kit` (first unit: federation, `:54-55`) | `crates/mandate-federation/src/record.rs`, `crates/mandate-federation/Cargo.toml`; the workspace `Cargo.toml` admission of tokio and the `eventlog` kit; `dependency-boundaries.json` | none: no change to what the domain decides (`domain-folds-over-the-kit.md:71-75`) | `cargo test -p mandate-federation --locked` with the projection built by `SqliteEventStore::in_memory` and the existing ordering and replay cases unchanged; `cargo xtask boundaries` and `cargo deny --locked check` (`:57-62`) | opus | 4G (tokio and bundled SQLite) | 2 days |

Width: 6, every ready unit with disjoint scope, at the host's limit of six concurrent implementors; U0 is the coordinator's own commit.

Shared, merged by the coordinator, never by a unit: `systems/mandate/{system.yaml,components.yaml,ess-inputs.yaml}`
(U4's domain line, each unit's scenario list and its new commands and events, as wave 8 did,
`docs/plans/2026-10-13-wave-8-execution.md:84`); `generated/**`, which is only ever regenerated with
`cargo xtask generate` on the merged head, never merged by hand; `contracts/{expected-outcomes,coverage}.json`,
`contracts/obligations/*.json`, `contracts/conformance/{injections,obligations-report}.json`;
`Cargo.lock`; `dependency-boundaries.json` where U4 and U6 both add a line; `CHANGELOG.md`.

Build and disk. Every build runs in the background through the host's build ledger, reserving the
measured peak of the same command, at the lowest CPU and I/O priority with 18 build jobs. Units build crate-scoped (`cargo test -p`), and only the
integration tree runs the full `task check`, one at a time. The sizes in the table rest on
wave 10's unit targets, 2.1G each after crate-scoped builds (`du -sb target` in `mandate-w10-u1-manifest`
and `mandate-w10-u3-comments`), plus 20 % rounded up. Each unit measures `du -sb target`
before and after its first build and reports the growth. Free on `/` at dispatch: 53G (94 % used), so six
first builds of 3–4G fit above the 10G floor.

## Overlap with wave 10 and merge order

Wave 10 (`integration/wave-20261015-002`, cut from `cd691e8`) touches, committed or in its unit
trees: `systems/mandate/{components.yaml,domains/identity.yaml,domains/delegation.yaml}`, 26 existing
scenario files, `generated/{conformance/suite.json,coverage/receipt.json}`,
`contracts/{coverage,expected-outcomes}.json`, `contracts/obligations/*.json`,
`contracts/conformance/obligations-report.json`, crates mandate-{authz,conformance,federation,graph,identity,model,policy},
`services/control-plane/src/{adapters,authority}.rs`, `xtask/src/obligations_registry.rs`, and
`docs/public/{federated-login,architecture,roadmap}.md`, `docs/architecture/adapter-contract.md`.

| wave 11 unit | shared with wave 10 | resolution |
|---|---|---|
| U1, U2, U3, U4 | `components.yaml`, `generated/**`, contract ledgers | coordinator-merged after wave 10 is on `main`; `generated/` regenerated |
| U3 | `domains/identity.yaml` (wave 10 edits comments; U3 edits `:82-131,210-372`) | textual merge, then `ess specify validate`; U3 cut or rebased after wave 10 |
| U1, U2, U3 compile spill | mandate-model, mandate-identity, mandate-federation | after wave 10 |
| U6 | `crates/mandate-federation` (wave 10 changes 1 file in u1 and 3 in u3) | U6 merges last, after wave 10 |
| U4, U5 | none (`crates/mandate-client`, `deploy/docker`, `crates/mandate-server`, control-plane `main.rs`/`serve.rs`) | may start and merge before wave 10 lands |

Merge order into `integration/wave-20261015-003`: step 0, then **U5**, then **U4**'s library commits
(its spec commit waits for wave 10, because of the shared ledgers), then wave 10 on `main`, merged in
once more, then **U1 → U2** (U2's client-type and peer scenarios set up U1's fields), then **U3**,
then **U6**. After each spec merge the coordinator regenerates, validates and runs
`cargo xtask conform`. After the last, it runs `task check` on the integration head
(`AGENTS.md:17`), then sends one adversary per unit and one security review for the wave. One pull
request from the integration branch to `main` follows, under the standing cadence (`AGENTS.md`,
"Standing cadence").

ETA: U5 on day 1; U1, U3 and U4 on days 1–2 (U4's two days in parallel); U2 merged half a day after
U1; U6 on day 2; review rework on day 3. The wave closes about 2026-10-19, if wave 10 lands on
`main` by the end of day 1. Each day it lands later moves U1–U3 and U6 by the same day.

## Story moves

Draft → proposed → active at dispatch: `epic:openid-provider`, `story:oidc-static-client-registry`,
`story:oidc-google-upstream`, `story:oidc-signed-tokens-and-key-rotation`,
`story:oidc-discovery-and-code-flow`, `story:oidc-trusted-peers`, `story:oidc-refresh-and-logout`,
`story:token-guard`, `story:oidc-deployment-package`, and `story:domain-folds-over-the-kit` only if
decision 7 is cleared. Each stays active. Only its contract half or first unit ships here, so none
reaches implemented in this wave.

Stay draft: `story:oidc-durable-state`, `story:oidc-gateway-swap-proof`,
`story:oidc-principals-organizations-in-tokens`, `story:oidc-authority-in-tokens`,
`story:oidc-workload-agent-authentication`, `story:epoch-snapshot-generations`,
`story:listener-outbound-stall`.

## Execution

| unit | branch | managed id | stage |
|---|---|---|---|
| U1 `spec-federation` | `impl/w11-spec-federation` | `mandate-w11-spec-federation` | dispatched |
| U2 `spec-credential` | `impl/w11-spec-credential` | `mandate-w11-spec-credential` | dispatched |
| U3 `spec-identity` | `impl/w11-spec-identity` | `mandate-w11-spec-identity` | dispatched |
| U4 `token-guard` | `impl/w11-token-guard` | `mandate-w11-token-guard` | dispatched |
| U5 `deployment-image-health` | `impl/w11-deployment-image-health` | `mandate-w11-deployment-health` | dispatched |
| U6 `domain-folds-federation` | `impl/w11-domain-folds-federation` | `mandate-w11-domain-folds` | dispatched |

## Coordinator's `aep plan artifact move` commands

Run in the integration tree, after step 0 and the operator's approval of this wave. The evidence form
matches the store's earlier moves (`.engineering/planning/story/agent-security.md:68-69`).

```bash
# Operator's act (decision 7); skip it and the two domain-folds moves for a five-unit wave.
aep plan artifact move decision-blocker:async-runtime --to cleared

aep plan artifact move epic:openid-provider --to proposed --evidence review_outcome=1
aep plan artifact move epic:openid-provider --to active --evidence review_outcome=1
for s in oidc-static-client-registry oidc-google-upstream oidc-signed-tokens-and-key-rotation \
         oidc-discovery-and-code-flow oidc-trusted-peers oidc-refresh-and-logout \
         token-guard oidc-deployment-package domain-folds-over-the-kit; do
  aep plan artifact move "story:$s" --to proposed --evidence review_outcome=1
  aep plan artifact move "story:$s" --to active --evidence review_outcome=1
done
aep plan artifact validate
```

Spelled out, the loop is 18 commands, `--to proposed` then `--to active` for each of:
`story:oidc-static-client-registry`, `story:oidc-google-upstream`,
`story:oidc-signed-tokens-and-key-rotation`, `story:oidc-discovery-and-code-flow`,
`story:oidc-trusted-peers`, `story:oidc-refresh-and-logout`, `story:token-guard`,
`story:oidc-deployment-package`, `story:domain-folds-over-the-kit`.
