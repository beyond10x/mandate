# Wave 12 (OpenID Provider, parity runtime): proposal and execution

Opened 2026-10-17 on `integration/wave-20261017-001`, cut from `main` at `99e2855` (0.10.0), which
holds wave 11. Epic: `epic:openid-provider`. This wave builds the runtime of three active stories
whose contract halves wave 11 shipped: `story:oidc-static-client-registry`,
`story:oidc-discovery-and-code-flow` (with the F15 rename, moved here by wave 11's decision 1,
`docs/plans/2026-10-16-wave-11-execution.md:37-45`) and `story:oidc-signed-tokens-and-key-rotation`
(with its keys and JWKS half, P2a, moved here by decision 3, `:52-57`). Forks as decided:
F1 B+A, F2 A, F3 B, F4 B, F5 A, F6 B, F7 A, F8 C, F9 A (`docs/adr/0012-openid-provider.md:151-161`);
F11 C, F13 A, F15 A, F17 C on the recommendations (`docs/adr/0012-openid-provider-forks.md:213,239,265,293`).

## Before any unit (coordinator)

0. The pins already match the host: `xtask/src/main.rs:112` requires `ess 0.60.0` and `:609`
   `aep 0.74.0`, and both are on PATH. No merge from `main` is needed.
1. Validate the head (`ess specify validate --strict-requires --path systems/mandate`), then
   `cargo xtask adopt` once in each fresh unit tree before `cargo xtask generate` (`AGENTS.md:13`).

## What wave 11 left on this head

- **Contract, done.** `OAuthClient` carries `client_type`, `secret_verifiers`, `pkce_required`,
  `trusted_peers`, `post_logout_redirect_uris` (`systems/mandate/domains/federation.yaml:94-107`), as
  do `RegisterOAuthClient` (`:411-442`) and its event (`:592-605`). `RedeemAuthorizationCode` takes
  `client_secret` (`credential.yaml:255-259`), has the outcome `accepted-with-identity-token`
  (`:261-305`), answers `id_token` and `expires_in` (`:347-351`); `IdentityTokenIssued` is
  declared (`:857`); `AuthorizationCode.identity_scopes` exists (`:168-169`); `InvalidClient`
  joined both reason enums (`core.yaml:188,354`).
- **Registry decider, done.** `register_client.rs:204-269` decides the client-type denials and the
  fold carries the fields (`crates/mandate-federation/src/record.rs:140-142`). The four
  `oidc-client-*` rows already pass (`contracts/expected-outcomes.json:140-143`).
- **Not built.** `ClientSeed` has only `public` (`services/control-plane/src/adapters.rs:2049-2071`),
  and the seed writes `secret_verifiers: Vec::new()` and `pkce_required: self.public`
  (`:2096-2105`), so a seeded confidential client today has no secret and *no* PKCE, which is the
  reverse of F3. No runtime reads `client_secret` (`services/sts/src/redemption.rs:265-299`;
  conformance input `crates/mandate-conformance/src/commands/credential.rs:529-535`). The
  authorize path still refuses non-public clients (`crates/mandate-federation/src/publicclient.rs:88`).
  Issuance never consults a `SigningKey` record: the conformance signer is a double
  (`credential.rs:184-215`) and `issue.rs:105-133` signs under whatever key the signer holds.
  The JWK Set and readiness come from `--key` documents (`services/control-plane/src/main.rs:107-109`,
  `serve.rs:540-545`, `adapters.rs:3029-3031`). There is no `/.well-known/openid-configuration`
  (`crates/mandate-server/src/routes.rs:27-28`, eleven routes at `crates/mandate-server/tests/routes.rs:24`).
- **Rename not done.** `AuthorizePublicClient` is still the command (`federation.yaml:358`,
  `components.yaml:38`), named in 65 tracked files outside `.engineering/` and `docs/plans/`, generated output included
  (`git grep -l AuthorizePublicClient`).

## Scenarios: which this wave can flip

| row (`contracts/expected-outcomes.json`) | today | owner unit | flips this wave? |
|---|---|---|---|
| `oidc-sign-with-retired-key-refused` (`:61`) | failed, on this story | U5 | **yes**: issuance refuses when no key is `signing_admitted` (`services/sts/src/keys.rs:261`) |
| `oidc-redeem-client-auth-failed`, `oidc-redeem-public-with-secret-refused` (`:58-59`) | unsupported, `story:declared-writers` | U3 | **only if re-arranged** (see below) |
| `oidc-id-token-issued-on-openid`, `oidc-no-id-token-without-openid` (`:53-54`) | unsupported, `story:declared-writers` | U6 | **only if re-arranged** |
| `AuthorizePublicClient/outcome/{accepted,denied}` (`:104-105`) | unsupported, `story:oauth-integration` | U1 renames | **no** |
| new `oidc-authorize-confidential-without-pkce`, `oidc-authorize-public-without-pkce-refused`, `oidc-authorize-peer-audience-scope` | not yet authored | U4 authors | **no**: enter as unsupported |
| `RedeemAuthorizationCode/outcome/{accepted,denied}` (`:31-32`) | failed, `story:ess-synthesizer-prerequisites` | none | **no** (wave 11 decision 11) |

Why the redemption and identity-token rows are blocked: they arrange `ResourceServer`, `OAuthClient`
and `SigningKey` by `setup:` (`systems/mandate/scenarios/oidc-redeem-client-auth-failed.yaml:5-37`),
and the target establishes only records with an adapter writer. Every other entity is refused
"entity-without-adapter-writer", owner `story:declared-writers`
(`crates/mandate-conformance/src/establish.rs:48-72`; the run's record is
`contracts/conformance/injections.json:1149-1191`). Adding arms there would invent history for
command-created records, which the module refuses on principle (`establish.rs:1-11`). The route
open to this wave is the one `oidc-sign-with-retired-key-refused.yaml` already takes: create the
records with `RegisterResourceServer`, `RegisterOAuthClient` and `RegisterSigningKey` in the
timeline. The code record still comes from `setup:` with literal ids. No scenario uses `$instance`
before `timeline:`, so the literals must equal the target's sequential allocations. U3 and U6 each
try this in their spec-first step. Where it cannot be done, the row stays on
`story:declared-writers`, the unit says why, and the named Rust tests carry the acceptance.

The authorize rows cannot flip: the target answers every authorization command
"input-shape-unrealized", owner `story:oauth-integration`, which is draft
(`crates/mandate-conformance/src/commands/federation.rs:308-330`). The rename keeps that owner.
U4 records the three new scenarios as `unsupported` with that owner, under wave 11's decision 8.
`oidc-authorize-peer-audience-scope` is `story:oidc-trusted-peers`' scenario
(`.engineering/planning/story/oidc-trusted-peers.md:49-51`), moved with the rename. U4 authors
it, and its runtime stays with that story.

Ledger rows the units retire by tests rather than by scenarios: `contracts/obligations/sts.json:466-474`
(two client-authentication clauses, U3), `:494-498` (no key admitted when an ID token is due, U6),
`contracts/obligations/federation.json:493-495` (post-logout redirect URI, U2), and
`contracts/coverage.json:111` (`IdentityScope`, U4) and `:112-113` (`IdentityTokenId`,
`IdentityTokenIssued`, U6).

## Decisions taken for the units

1. **The rename is its own mechanical unit, merged first.** It reaches every file the other units
   edit (`decode.rs:868`, `serve.rs:579-608`, `adapters.rs`, `metadata.rs`, `routes.rs`,
   `services/sts/src/code.rs`). U1 renames the command, its generated code, the two ledger
   rows and every reference, and changes no behaviour. The other units are cut after it merges.
   The widened input (optional PKCE, OIDC scopes, optional target) is U4's spec step.
2. **The keyed-verifier helper belongs to U2** (`mandate-types`: derive a `CredentialVerifier`
   from a secret, compare in constant time; `.engineering/planning/story/oidc-static-client-registry.md:81`).
   U3 authenticates against it. U2 pushes the helper as its first commit; U3 rebases onto it
   before its client-authentication step and merges after U2.
3. **Two contract fields are still to be modelled, both in U6's spec step:** the per-connection
   subject format of F1 (`subject_format`, plus the connector id it replaces, on
   `FederationConnection`, `federation.yaml:52-68`; no domain declares it today) and the
   per-client ES256 choice of F8 (`id_token_signed_response_alg` on `OAuthClient`, `:87-107`).
   If F8 turns out to be deployment configuration rather than record state, U6 writes that down
   and adds no field.
4. **The target of an OIDC authorization is the client's resource server**, the
   `ResourceServer` whose `client_id` names the client (`credential.yaml:49`; wave 11 decision 12),
   so F11 adds no field. Where no such server exists, the authorization is refused. That refusal
   goes in U4's denied clause list (`federation.yaml:400`).
5. **New scenarios are recorded under wave 11's decisions 4 and 8**: failing first, or
   `unsupported` where the run says so, each with the owner the run names.

## Units

| unit | story | owns (files) | spec-first step | acceptance (named) | tier | build | ETA |
|---|---|---|---|---|---|---|---|
| U1 `authorize-client-rename` | `story:oidc-discovery-and-code-flow` (F15) | `federation.yaml:3,358-410` (name only); every `AuthorizePublicClient` reference in `crates/`, `services/`, `xtask/`, `tests/security/cases.json`, `contracts/use-cases/federated-login.json`, `docs/architecture/*.md` | the rename itself (`oidc-discovery-and-code-flow.md:60-62`). No input changes. `ess specify validate` is green and `cargo xtask generate` leaves no drift | `git grep AuthorizePublicClient` finds hits only in history documents (`CHANGELOG.md`, `docs/plans/`, `.engineering/`); the two renamed ledger rows answer as before (`expected-outcomes.json:104-105`); `cargo xtask obligations-registry`, `cargo xtask conform` and the workspace tests are green | sonnet | 4G (workspace-wide) | 0.5 day |
| U2 `client-registry` | `story:oidc-static-client-registry` (runtime) | `services/control-plane/src/adapters.rs` (`ClientSeed`, `ClientSeeding`, secret resolution `:973-1010,1661-1720,2049-2110,2660-2760`); `main.rs:120-126,339` (`--client-secret-file` admits client references); `crates/mandate-types` (verifier helper); `crates/mandate-federation/src/register_client.rs` (post-logout admission); control-plane tests; `docs/public/federated-login.md:107` and the `--client` example | none new: the contract is wave 11's. Realize the deferred clause `federation.json:493-495` | `control_plane::client_secret_reference_resolved`, `::client_secret_reference_unresolved_exits_2`, `::client_secret_two_verifiers`; the four-channel no-secret test (`oidc-static-client-registry.md:61-67`); a seeded confidential client defaults to `pkce_required: true` (F3, against `adapters.rs:2104`) | opus | 3G | 2 days |
| U3 `discovery-client-auth` | `story:oidc-discovery-and-code-flow` (a) | `crates/mandate-server/src/{routes,metadata}.rs` (`Document::OpenIdConfiguration`, one builder for both documents, `metadata.rs:39-128`); `decode.rs:550-565,909-978,1222-1229` (token: `client_secret_basic`/`_post`); `services/sts/src/redemption.rs` (`decide`, `:299-395`); `adapters.rs` `redeem` (`:3581-`); `serve.rs` the discovery arm and `redeemed` (`:769-`, `401` + `WWW-Authenticate: Basic`); conformance `credential.rs:529-535` (`client_secret`); `crates/mandate-server/tests/{routes,metadata}.rs`; `docs/public/federated-login.md:58,72-81`, `docs/public/{architecture,roadmap}.md`, `docs/architecture/adapter-contract.md:57` | re-arrange `oidc-redeem-client-auth-failed` and `oidc-redeem-public-with-secret-refused` through timeline registrations (see above) | `metadata::openid_configuration_members`; `end_to_end::token_client_secret_basic`, `::token_client_secret_post` (`oidc-discovery-and-code-flow.md:72-89`); the two redeem scenarios, if re-arranged; `routes.rs:27-28` and route count at `tests/routes.rs:24` | opus | 3G | 2 days, after U2's helper |
| U4 `browser-session` | `story:oidc-discovery-and-code-flow` (b) | `federation.yaml:358-410` (`AuthorizeClient` input and denied clauses); new `systems/mandate/scenarios/oidc-authorize-*.yaml`; `decode.rs:536-548,844-908,1087-1138` (cookie or bearer, OIDC scopes, optional target); `crates/mandate-federation/src/{publicclient,authorize}.rs` (resolution for both client types, `pkce_required`); `services/sts/src/code.rs:416-600` (`identity_scopes` and optional PKCE on the code); `adapters.rs` `authorize` (`:3344-`) and the pending-authorization store beside `PendingLogin` (`:1123-1296`); `serve.rs:579-626,688-757` (authorize arm; callback resumes); new `contracts/use-cases/oidc-relying-app.json` | `challenge` and `method` become optional (required when `pkce_required`), `identity_scopes` is added, `target` becomes optional (decision 4); the scenarios `oidc-authorize-confidential-without-pkce`, `oidc-authorize-public-without-pkce-refused` and `oidc-authorize-peer-audience-scope`, all `unsupported` | `end_to_end::browser_without_session_is_sent_upstream_and_returns_with_code`, `::session_cookie_skips_upstream` (`prompt=login`, `prompt=none` gives `login_required`), `decode::authorize_oidc_scope`, with the unknown-scope rule written down (`oidc-discovery-and-code-flow.md:80-91`) | opus | 3G | 2 days + a second adversary round |
| U5 `signing-keys-jwks` (P2a) | `story:oidc-signed-tokens-and-key-rotation` (a) | `main.rs:107-109` (`--signing-key NAME=PATH` replaces `--key`, F17 C); `adapters.rs:568-620,3029-3031` (the signer built from registered `SigningKey` records); `metadata.rs:138-388` (`/oauth/jwks` from `CredentialSigner::published_keys`, `crates/mandate-token/src/signing_real.rs:939`); `serve.rs:540-555` (readiness from the signer); `services/sts/src/keys.rs` (revoked keys rehydrated at start); `services/sts/src/issue.rs:105-133` (issuance only under a key that is `signing_admitted`); conformance `credential.rs:174-215`; `docs/public/federated-login.md:153` | none: `oidc-sign-with-retired-key-refused` already states it | the scenario flips to passed (`expected-outcomes.json:61`); `keys::rotation_keeps_old_tokens_valid`, `keys::revocation_removes_key_at_once` (`oidc-signed-tokens-and-key-rotation.md:75-77`); `end_to_end::ready_reflects_signing_key` stays green against the signer | opus | 3G | 2 days |
| U6 `token-issuance` (P2b) | `story:oidc-signed-tokens-and-key-rotation` (b) | `crates/mandate-token/src/{signing_real,projection}.rs` (ID-token claims, `at_hash`, the F1 subject encoder); `redemption.rs` `mint` (`:396-485`); `issue.rs` (a JWT access token under a `SelfContained` profile); `crates/mandate-proto/src/oauth.rs` (`id_token`, `expires_in`); `adapters.rs` `redeem` (the `ProfileClaims` port, a double until `story:oidc-google-upstream`); `serve.rs` `redeemed`; `main.rs` (`--id-token-lifetime`); `metadata.rs` (alg values); `docs/public/federated-login.md:81,86` | decision 3 (`subject_format`, `id_token_signed_response_alg`); re-arrange `oidc-id-token-issued-on-openid` and `oidc-no-id-token-without-openid` | `end_to_end::id_token_verifies_against_published_jwks`, `::id_token_claims`, `::access_token_is_jwt_for_self_contained_profile`, `signing::rs256_default_es256_per_client` (`oidc-signed-tokens-and-key-rotation.md:66-79`); a golden test of the Dex-compatible subject (F1); the two scenarios, if re-arranged | opus | 3G | 2 days, wired after U3, U4, U5 |

Width: 6. All six units are ready. U4 and U6 edit `federation.yaml` after U1, so they are cut once U1 merges; U1, U2, U3 and U5 start together, so
at peak five implementors run at once.

Security-critical, for the wave's one security review and for adversary rounds: **U2** (client
secret verifier: derivation, constant-time comparison, no secret byte on any channel),
**U3** (client authentication at the token endpoint, the `invalid_client` paths), **U4** (the
`__Host-mandate-session` cookie, CSRF on authorize, resumption from the pending store; two
adversary rounds, `oidc-discovery-and-code-flow.md:125-126`), **U5** (signing keys, revocation
taking effect at once) and **U6** (`at_hash`, `nonce`, audience, the subject; the ID token is
signed under U5's keys). U1 gets one adversary pass, to check that no behaviour moved.

## Shared files and merge order

Two or more units edit each of these. They take different regions, and the merge order settles
which unit rebases:

| file | units (regions) | resolution |
|---|---|---|
| `services/control-plane/src/adapters.rs` | U1 refs; U2 seeding `:973-1010,1661-2110`; U3 and U6 `redeem` `:3581-`; U4 `authorize` `:3344-` and pending store `:1123-1296`; U5 `:568-620,3029-3031` | U1 → U2 → U5 → U3 → U4 → U6; U6 rebases onto U3's `redeem` |
| `services/control-plane/src/serve.rs` | U1 `:579-608`; U3 discovery arm and `redeemed`; U4 `:579-626,688-757`; U5 `:540-555`; U6 `redeemed` | same order; U6 after U3 |
| `services/control-plane/src/main.rs` | U2 `:120-126,339`; U5 `:107-109`; U6 a new flag | U2 → U5 → U6 |
| `crates/mandate-server/src/decode.rs` | U1 `:868`; U3 token `:550-565,909-978`; U4 authorize `:536-548,844-908,1087` | U1 → U3 → U4 |
| `crates/mandate-server/src/metadata.rs` | U1 ref; U3 `:39-128`; U5 `:138-388`; U6 alg values in U3's builder | U5 → U3 → U6 |
| `crates/mandate-server/src/routes.rs` | U1; U3 | U1 → U3 |
| `services/sts/src/redemption.rs` | U3 `decide`; U6 `mint` | U3 → U6 |
| `services/sts/src/issue.rs` | U5 key admission; U6 access JWT | U5 → U6 |
| `services/sts/src/code.rs` | U1 ref; U4 `:416-600` | U1 → U4 |
| `crates/mandate-conformance/src/commands/credential.rs` | U3 `:529-535`; U5 `:174-215`; U6 the identity-token response `:580-597` | U5 → U3 → U6 |
| `systems/mandate/domains/federation.yaml` | U1 name; U4 `AuthorizeClient` input; U6 connection and client fields | U1 → U4 → U6, revalidated after each |
| `docs/public/federated-login.md` | U2 `:107`; U3 `:58,72-81`; U5 `:153`; U6 `:81,86` | textual, in the merge order |

Shared, merged by the coordinator, never by a unit: `systems/mandate/{system.yaml,components.yaml,ess-inputs.yaml}`
(U1's `components.yaml:38` line and U4's scenario list); `generated/**`, only regenerated with
`cargo xtask generate` on the merged head; `contracts/{expected-outcomes,coverage}.json`,
`contracts/obligations/*.json`, `contracts/conformance/{injections,obligations-report}.json`;
`Cargo.lock`; `dependency-boundaries.json` (control-plane already depends on `mandate-token`,
`services/control-plane/Cargo.toml`, so none is expected); `CHANGELOG.md`.

Merge order into `integration/wave-20261017-001`: **U1**, then U2, U4 and U5 are cut from that
head; U3 is cut at the same point and rebases onto U2's helper commit. Then **U2 → U5 → U3 → U4 → U6**.
U6 starts its spec step and its `mandate-token` claim renderer once U1 merges, and wires `mint`,
`redeem` and `redeemed` after U3, U4 and U5 have merged. After each spec merge the coordinator
regenerates, validates and runs `cargo xtask conform`. After the last merge it runs `task check` on
the integration head (`AGENTS.md:17`). Then come one adversary per unit (two for U4) and one
security review for the wave. One pull request to `main` follows under the standing cadence.

Build and disk. Every build runs in the background through the host's build ledger, at the
lowest CPU and I/O priority, with 18 build jobs. Units build crate-scoped (`cargo test -p`). Only
the integration tree runs the full `task check`, one tree at a time. Wave 11's unit targets grew
about 2.1G after crate-scoped builds. With 20 % on top that is 2.6G, so each unit reserves 3G. U1
reserves 4G, because the rename needs a workspace-wide build. Each unit measures `du -sb target`
before and after its first build and reports the growth. Free on `/` at proposal: 91G (90 % used).

ETA: U1 on day 1 morning; U2 and U5 on days 1–2; U3 on days 1–3, after U2's helper; U4 on days
1–3, plus its second adversary round; U6's spec step on day 1, its wiring on days 3–4; review
rework on day 5. The wave closes about 2026-10-22.

## Story moves

All three stories stay active while the wave runs. At close, provided every named Rust test
and every flippable row above is green, and each row left red names an owner outside this wave
(`story:declared-writers`, `story:oauth-integration`, `story:oidc-trusted-peers`,
`story:ess-synthesizer-prerequisites`):

- `story:oidc-static-client-registry` reaches implemented (U2).
- `story:oidc-discovery-and-code-flow` reaches implemented (U1, U3, U4).
- `story:oidc-signed-tokens-and-key-rotation` reaches implemented (U5, U6).

If a unit misses its acceptance, its story stays active and the remainder is planned into the
next wave. The epic and every other parity story stay active or draft as wave 11 left them.

## Execution

| unit | branch | managed id | stage |
|---|---|---|---|
| U1 `authorize-client-rename` | `impl/w12-authorize-client-rename` | `mandate-w12-authorize-client-rename` | proposed |
| U2 `client-registry` | `impl/w12-client-registry` | `mandate-w12-client-registry` | proposed |
| U3 `discovery-client-auth` | `impl/w12-discovery-client-auth` | `mandate-w12-discovery-client-auth` | proposed |
| U4 `browser-session` | `impl/w12-browser-session` | `mandate-w12-browser-session` | proposed |
| U5 `signing-keys-jwks` | `impl/w12-signing-keys-jwks` | `mandate-w12-signing-keys-jwks` | proposed |
| U6 `token-issuance` | `impl/w12-token-issuance` | `mandate-w12-token-issuance` | proposed |
