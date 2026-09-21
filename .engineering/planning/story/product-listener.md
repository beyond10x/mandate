---
format: aep.planning-md/1
id: story:product-listener
kind: story
status: implemented
title: Serve the product routes and replace the serve refusal
relations:
- decomposes: epic:sts-credentials
- serves: vision:mandate
- depends_on: story:pkce-sessions
- depends_on: story:federation-linking
- depends_on: story:signing-and-verification
- informed_by: story:protocol-adapters
- depends_on: story:login-adapters
scope:
- confidence: cited
  path: Cargo.lock
- confidence: cited
  path: Cargo.toml
- confidence: cited
  path: crates/mandate-proto/src/oauth.rs
- confidence: cited
  path: crates/mandate-proto/tests/oauth.rs
- confidence: cited
  path: deny.toml
- confidence: cited
  path: dependency-boundaries.json
- confidence: inferred
  path: services/control-plane/Cargo.toml
- confidence: inferred
  path: services/control-plane/src/adapters.rs
- confidence: inferred
  path: services/control-plane/src/lib.rs
- confidence: inferred
  path: services/control-plane/src/main.rs
- confidence: inferred
  path: services/control-plane/src/serve.rs
- confidence: inferred
  path: services/control-plane/tests/adapters.rs
- confidence: inferred
  path: services/control-plane/tests/serve.rs
- confidence: cited
  path: services/sts/src/lib.rs
- confidence: cited
  path: services/sts/src/main.rs
- confidence: inferred
  path: services/sts/src/store.rs
- confidence: cited
  path: xtask/src/main.rs
revision: 24
---
# Serve the product routes

## Acceptance

Given the route table `story:login-adapters` declares, when a client requests any generated `/<domain>/commands/<Command>` path against a running `mandate-control-plane`, then it is refused and the served metadata document lists only product routes; and the four road routes answer end to end over HTTP against in-memory folds — a login opens a session, an authorization request yields a code, the token endpoint issues the credential, introspection answers active for it.

## Required observations

Moved here from `story:protocol-adapters`: a listener behind the route table; the served RFC 8414 metadata document; JWKS key material. The `serve` refusal at `xtask/src/main.rs:259-273` replaced with per-binary milestone checks that keep refusal coverage for still-unimplemented commands — coordinator work under `task:runtime-wave-integration`. An HTTP framework and an async runtime admitted to the service packages. The registered-client port `story:pkce-sessions` declares in `mandate-identity` implemented over `story:federation-linking`'s `OAuthClient` projection.

## Why a separate story

Every item above is blocked by fact 1 (the `serve` assertion) or by a dependency the policy forbids. `story:protocol-adapters` and `story:oauth-integration` deliver their logic as libraries under test; this story binds them to transport.

## Units

Superseded at the wave D opening (2026-09-19) by the Scope's Units table: `composition` (`services/control-plane/src/{lib,adapters}.rs`) and `listener` (`services/control-plane/src/{serve,main}.rs`). The earlier rows naming `services/sts/src/serve.rs` and `crates/mandate-federation/src/adapters.rs` are withdrawn (ruling D1).

## Scope

Re-derived 2026-09-19 by `story-scoper` on `main` at `6f6f639` (wave C merged), replacing the section written before wave B. **cited** = read from the tree; **inferred** = a reading that could be wrong.

- **Primary surface:** `services/control-plane` — the composition binary (ruling D1 below); today a 10-line `clap` stub — cited. `services/sts` is consumed as a library, not edited beyond `src/lib.rs` if a `pub` re-export is needed.
- **Coordinator surface:** `Cargo.toml`, `Cargo.lock`, `deny.toml`, `dependency-boundaries.json`, `xtask/src/main.rs` (`PACKAGES` 22 unchanged, `LIBRARIES` 17 → 18 and its doc comment; the `serve` rows at `:459-474`), `services/control-plane/Cargo.toml` (a `[lib]` target; `mandate-types`, `mandate-model`, `mandate-token`, `mandate-identity`, `mandate-federation`, `mandate-server`, `mandate-proto`, `mandate-sts`, `serde`, `serde_json`, `httparse`) — cited policy, inferred shape.

### The served surface

| # | Route or document | Handler | Authority |
|---|---|---|---|
| 1 | `AuthenticateFederation` | `crates/mandate-federation/src/authenticate.rs:104` | control plane (`ownership.md:15`) |
| 2 | `AuthorizePublicClient` | `crates/mandate-federation/src/authorize.rs:272`, its `IssueAuthorizationCodeInput` by value → `mandate_sts::code::CodeIssuance` | control plane |
| 3 | token endpoint `RedeemAuthorizationCode` | `services/sts/src/redemption.rs:418` (`redeem_and_consume`) | STS |
| 4 | introspection `IntrospectCredential` | `services/sts/src/lib.rs:95` | STS |
| 5, 6 | RFC 8414 metadata and JWKS documents, served | `story:login-adapters`' `metadata` shape | adapters |
| 7 | every `/<domain>/commands/<Command>` path refused | the route table's disjointness proof | this story's acceptance |

`ProvisionExternalPrincipal` (the JIT branch) is left out of the first served vertical: `decision-blocker:jit-provisioning` is open.

### The composition — four port adapters, all cross-crate

| Port | Declared at | Implemented over |
|---|---|---|
| `TargetRegistry` | `crates/mandate-federation/src/authorize.rs:65` | `mandate_sts::registry::ResourceServerReads` |
| `OAuthClientReads` | `services/sts/src/code.rs:83` | `mandate_federation::record::Projection` |
| `SessionReads` | `services/sts/src/binding.rs:100` | `mandate_identity::IdentityRead` |
| `OAuthClientStore` | `crates/mandate-federation/src/publicclient.rs:35` | already implemented for `Projection` (`:44-51`) |

The `port-adapters` unit cannot land in `crates/mandate-federation/src/adapters.rs`: the boundary policy gives `mandate-federation` no `mandate-sts` and `mandate-sts` no `mandate-federation` or `mandate-identity` (`services/sts/src/code.rs:74-82` says so). The adapters land in the composition crate. `mandate-identity` declares no client port; the port `story:pkce-sessions` landed is `OAuthClientStore`, already implemented — the unit's old wording is stale.

### Units — one implementor, cut after `story:login-adapters` merges

| Unit | Files | Delivers | Test |
|---|---|---|---|
| `composition` | `services/control-plane/src/{lib,adapters}.rs` | the three port adapters; the in-memory logs and folds wired (federation `Projection`, `IdentityLog`, the STS `Projection` and `InMemoryCodeLog`); the allowlist, the code lifetime, the signer and verifier constructed from configuration | `tests/adapters.rs` |
| `listener` | `services/control-plane/src/serve.rs`, `src/main.rs` (`serve --listen <addr>`) | a blocking `std::net` HTTP/1.1 accept loop (`Connection: close`) over `httparse`, dispatching `story:login-adapters`' route table and decoders to the four handlers; the metadata and JWKS documents served; every generated command path refused | `tests/serve.rs`: bind `127.0.0.1:0` on a thread, drive the four routes over raw `std::net::TcpStream` (no client crate admission) |

- **Gate:** `cargo fmt -p mandate-control-plane -- --check`; `cargo clippy -p mandate-control-plane --all-targets --locked -- -D warnings`; `cargo test -p mandate-control-plane --locked`, counts reported; `cargo xtask boundaries`, `cargo xtask licenses`, and the `serve` milestone check in `xtask`.
- **`decision-blocker:guards`:** this story produces item 5 (generated command routes not reachable as product endpoints); items 1–3 are `story:login-adapters`', item 4 stays behind `decision-blocker:audit-routing`. The blocker does not clear; the served route carries no denial-audit path — named residue.
- **Persistence:** in-memory folds for the first served vertical; `eventlog-sqlite` (already in the lock and the `external` allowlist, licence-clean: `rusqlite` MIT, `libsqlite3-sys` MIT, `tokio` MIT) is the next milestone, together with the runtime it needs — the kit's API is async (`eventlog-sqlite/src/lib.rs:65-97` at 0.2.1) and the STS `AuthorizationCodeLog` port is synchronous.
- **Drift:** the `serve` refusal is at `xtask/src/main.rs:459-474` over six binaries (the story and `federated-login.md:142` cite `:259-273`).

### Would collide with

The coordinator-only policy files; `story:oauth-integration` (`services/sts/src/main.rs`, `Cargo.toml`) and `story:constrained-exchange` (`services/sts`) — neither selected; not `story:login-adapters` (disjoint by file, sequential by edge).

## Validation and contract

`task check` on the merged head with the replaced `serve` checks; the seven `pkce-*` cases executed over HTTP, counts reported. Blocked on `decision-blocker:guards`.

## Rulings — wave D opening, 2026-09-19

Coordinator, wave D opening. The scoper named four forks; each taken on the reversible side and reported to the operator.

1. **D1 — the composition's home is `services/control-plane`**, gaining a `[lib]` target and its own `dependency-boundaries.json` key (`LIBRARIES` 17 → 18): no edge points into the STS ceiling, every declared crate direction survives, and it is what `ownership.md:15` reads as ("the control plane authenticates and invokes STS code issuance"); hosting both authorities in one process is a deployment decision, not an authority transfer. The `port-adapters` unit moves there; `crates/mandate-federation/src/adapters.rs` is struck from the scope.
2. **D2 — transport is `std::net` + `httparse`** (`httparse 1.10.1`, MIT OR Apache-2.0, already in the lock through `ureq`): zero new lock entries, one array entry. `hyper` + `tokio` is the answer once the eventlog kit's runtime is present.
3. **D3 — the `serve` refusal narrows from six binaries to five**: `mandate-control-plane serve` must bind and answer; the other five keep refusing. The `xtask` rows change in the coordinator's alignment commit that lands with the listener merge, not before.
4. **D4 — in-memory folds for the first served vertical**; `eventlog-sqlite` is the next milestone with the async port rewrite it forces (`docs/plans/2026-09-18-wave-3-execution.md:13`, stop condition S1).
5. **Order.** This story's tree is cut after `story:login-adapters` merges; `depends_on story:login-adapters` recorded and `depends_on story:protocol-adapters` downgraded to `informed_by` (the road subset is what the listener serves).
6. **Residue named:** no denial-audit path on the served route (`decision-blocker:audit-routing`); the JIT branch not served (`decision-blocker:jit-provisioning`).

- Correction at the wave D opening, after `review-result:wave-d-design-r1`: ruling D1's justification cited `ownership.md:15`, which is the credential row ("STS alone issues, resolves, exchanges and revokes credentials and consumes codes"). The composition binary hosts both deployment roles in one process for the first served vertical; the authority rows do not move (the STS handlers still decide issuance and redemption; the control plane's still decide authentication and authorization). `docs/architecture/ownership.md` gains that sentence in the opening commit (coordinator-owned document). The acceptance and the Units table are corrected: a running `mandate-control-plane`, the route table `story:login-adapters` declares.

- Correction at the wave D opening, after `review-result:wave-d-parallel-r1`: the two served documents' paths are entries of `story:login-adapters`' route table; the listener serves that table and hardcodes no path, so the disjointness proof round 1 runs covers everything the listener answers.

- Ruling at the adapters' adversary pass 1 (2026-09-19): the token endpoint's wire form carries `code` (the secret) and no `code_id`, while `RedeemAuthorizationCode` declares `code_id` as input and the contract header assigns its resolution to the trusted adapter. The composition resolves it: `services/sts/src/store.rs` gains a by-verifier read on `AuthorizationCodeReads` (the code's stored domain-separated verifier, `CredentialDomain::AuthorizationCodeVerifier`), and the `composition` unit resolves `code` → `code_id` through it before calling the redemption — constant time, one lookup; a code that resolves to nothing is the declared unknown-code denial. `services/sts/src/store.rs` is added to this story's scope for that one read.

- Ruling from `review-result:wave-d-login-adapters-adversary-2` F4 (2026-09-19): a refusal the authorize endpoint raises before the client and its redirect URI are validated (`ClientUnknown`, `ClientDisabled`, `ClientNotPublic`, a redirect mismatch) is answered by the listener as a rendered response, never by a redirect to the presented `redirect_uri` (RFC 6749 §4.1.2.1); `unauthorized_client` reaches the client by redirect only once the redirect URI is the registered one.

- Implementation result (2026-09-19): the Opus implementor was terminated by the weekly quota after writing `services/control-plane/src/adapters.rs` (the composition: three port adapters, the folds, the session proof, the `code` → `code_id` resolution through the STS's whole-slice by-verifier read in `services/sts/src/store.rs`) and the two test files; the coordinator finished the unit in the main session — `serve.rs` (blocking `std::net` + `httparse` listener, one request per connection, bounded head/headers/body, repeated `Content-Length` and `Transfer-Encoding` refused, dispatch only on `mandate_server::routes`, RFC 6749 error bodies, `no-store` on credential responses, in-place rendering for refusals raised before the redirect URI is validated), `main.rs` (`serve --listen --issuer` over the real verifier, host clock, system secrets and identities; folds start empty, ruling D4), `lib.rs`, and two corrections to the implementor's work (the session issuer states each dimension's first generation before recording the snapshot and refuses the login on a refused append, which the swallowed `record()` had hidden; the adapter test fixture likewise). 22 cases; 220 across `mandate-control-plane` and `mandate-sts`; fmt, clippy, boundaries (22), licenses (225) green. Unit committed `82c6419`, merged `c306da3`; alignment `3cbab1a` narrows the serve refusal to five binaries (ruling D3). **No adversary pass ran on this unit** (the Opus quota); a coordinator self-review covered request framing (duplicate `Content-Length`, chunked, oversize head, header count, incomplete head), `Location` composition (registered redirect, percent-encoded `code` and `state`), the 405 `Allow` row and the introspection caller-vs-token error split. Two adversary passes are owed and recorded as the next wave's first item. Residues unchanged: no denial-audit path on the served route (`decision-blocker:audit-routing`); the JIT branch not served (`decision-blocker:jit-provisioning`); `expires_in` omitted from the token response (not declared by the contract; the descriptor's `expires_at` answers through introspection).

- Correction 1 result (2026-09-19): 203 tests across `mandate-control-plane`, `mandate-proto`, `mandate-server` green (control-plane 15 + 22 + 9 adversary), clippy clean, boundaries 22, documents 10. One redirect composer; the declared `Content-Length` is the frame and an over-bound declaration is refused before any body read; digits-only `Content-Length` (httparse strips OWS); `Limits::request_deadline` 10 s over every read and write, the lapsed-deadline refusal itself written under `write_timeout` (one connection bounded by deadline + write timeout, documented); `Deployment::new` returns `Result<_, ConfigurationRefused>` (`CodeLifetimeUnbounded`, `SessionLifetimeUnbounded`, `Issuer(…)`), `main.rs` exits 2 before any socket; `origin_form` decides the four target forms; `SERVER_ERROR_CLAUSES = ["ExpiryUnbounded"]`; the issuer normalised once. Coordinator deviation: the pass-1 adversary file was amended to the rulings from the implementor's measured patch (a fallible `Deployment::new`; the code-lifetime case asserts the configuration refusal; the slow-client case states a 600 ms deadline). Named, not changed: `ClientUnregistered` (STS) answers `access_denied` where the federation's `ClientUnknown` answers `unauthorized_client`; `SigningRefused`/`AlgorithmPolicy` are deployment-side but never request refusals. Adversary 2 dispatched on the correction tree.

- Correction 2 result (2026-09-21): 225 tests across the three crates green after the coordinator amended three adversary-2 cases that asserted the behaviour the rulings reversed (in-place refusal instead of a redirect for an unusable registered URI or a fragment; the lifetime refused at startup) — deviation 8, same class as 6. Both lifetimes bounded above through the STS reader's own layout rule reproduced in the control plane (`seconds_of` is `pub(crate)` in the STS; a fourth copy, stated); `Host` absent is refused for HTTP/1.1 only; a code is redeemable only while its session is fresh (measured, `SessionUnusable` at 3601 s). Correction unit committed and merged as the bot.
