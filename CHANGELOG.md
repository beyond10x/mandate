# Changelog

All notable changes to Mandate are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are annotated git tags on the `main` merge commit of the pull request that delivered them, created and pushed by the organization bot. Pre-release tags mark the integration batches that led to the first release.

## [Unreleased]

## [0.5.1] - 2026-09-23

Wave L: four stories in three units, each attacked twice.

### Changed

- `ConnectionStore::enabled_for_issuer` may answer connections in any lifecycle state; the crate
  decides which are enabled on an issuer, reading each listed id through `connection(id)` and
  falling back to the listed record, so an implementor cannot widen a decision
  (`story:enabled-for-issuer-filters-in-the-implementor`).

### Fixed

- The federation destination guard folds at most one trailing dot, and only on a name: `localhost..`,
  `127.0.0.1.`, `[::1.]` and any host with an empty label (`.localdomain`, `keys..localdomain`) are
  refused. The control-plane loopback guard folds a trailing dot on names only too, so both refuse
  `127.0.0.1.`. A 12,168-decision sweep moved 685 decisions, all from admitted to refused
  (`story:federation-guard-trailing-dots`, `story:bracketed-literal-trailing-dot`).
- A login whose session opening is refused keeps no security-epoch record it wrote on the way, and a
  refused `--connection` or `--client` document seeds nothing (`story:control-plane-multi-fold-writes`).
- A redelivered `FederationConnectionCreated` for a held connection is an idempotent no-op, so a
  disabled connection can no longer come back `Enabled` beside its own record and refuse another
  organization's logins and registrations (`story:enabled-for-issuer-filters-in-the-implementor`).

### Known

- Two connection documents may state one `external_principal_id`; the second link is dropped
  (`story:seeding-repeated-external-principal-id`).
- A numeric IPv4 shorthand with a trailing dot (`127.1.`) is admitted and cannot be fetched; it fails
  closed (`story:numeric-shorthand-trailing-dot`).

## [0.5.0] - 2026-09-23

Waves I, J and K: nine stories, each attacked twice. The clause count moves for the first time since
wave D: 191 clauses (one split in two), 85 decided on the real path.

### Changed

- **Breaking.** `mandate_sts::IdentityAllocator` requires `reserve_credential_id`,
  `commit_credential_id` and `release_credential_id`; there are no defaults. A reservation holds —
  the next draw skips it — and a released identity an overtaking draw passed stays a gap
  (`story:sts-refusal-draws-nothing`).
- **Breaking.** `IncrementSecurityEpoch` needs the new `TargetTenancy` port beside
  `SecurityEpochWrite` (`story:identity-tenant-containment`).
- The event log is pinned at `0.3.0` (`eventlog-core`, `eventlog-sqlite`); nothing calls it yet
  (`story:eventlog-repin-0-3-0`).
- An obligation clause row may carry `decided_in: <workspace member>` naming the crate whose test
  decides it. The registry refuses the entry's own crate, a non-member, `decided_in` off a clause
  row, an empty or joiner-only clause, one test id under two kinds, paths or doubles, and a double
  whose module path is not public. `AuthorizePublicClient`'s "STS code issuance/narrowing" is split:
  issuance is decided in `mandate-sts`; narrowing is deferred to `story:agent-authority-kernel`
  (`story:cross-crate-clauses`).

### Fixed

- A just-in-time login records the `mandate.identity.Principal` its provisioning event declares, and
  a provisioning either fold refuses keeps neither (`story:jit-principal-record`).
- An issuer's own origin compares two address literals as addresses (`[::1]` and
  `[0:0:0:0:0:0:0:1]` are one origin), and `origin` reads an authority the way the fetcher does:
  nothing but `:` after `]`, only an IPv6 address inside brackets, digits-only ports. A JWKS
  destination `[addr]x:P` is no longer admitted at the default port and fetched on `P`
  (`story:folded-is-not-an-address-fold`).
- `register_resource_server` refuses a profile whose `max_ttl`, added to `3000-01-01T00:00:00Z`,
  leaves the four-digit year, as `ProfileUnadmitted`; both issuance commands and the
  authorization-code redemption refuse, as `ExpiryUnbounded`, any expiry `instant::at` would render
  in a form the crate cannot read back — past `9999-12-31T23:59:59Z` or before
  `0000-01-01T00:00:00Z` (`story:sts-lifetime-bounds`).
- A plaintext issuer's loopback check reads each host form by its own parser: userinfo is refused,
  a bracketed host must be IPv6, an unbracketed host may not contain `:`, at most one trailing dot is
  folded, and a spelled port is digits only. `http://localhost:80@evil.example` is refused
  (`story:control-plane-loopback-fold`).
- `IncrementSecurityEpoch` refuses `TenantMismatch` for a target any record places in another
  organization. The check is a read before the compare-and-set and not atomic with it; that is
  `decision-blocker:epoch-atomicity`'s (`story:identity-tenant-containment`).
- Registration refuses a second organization's tenant rule on one issuer when one proof could
  satisfy both — a rule on a different claim name — as `TenantResolutionUnadmitted`
  (`story:federation-rule-disjointness`).
- A refused STS redemption or self-contained issuance draws nothing from the secret source or the
  identity allocator; a redemption decides every refusal before it mints (`story:sts-refusal-draws-nothing`).
- The login-road test lane takes its child's address from the child's own `listening on` line, and
  its concurrent copies no longer start copies of their own (`story:road-lane-child-prints-address`).

### Known

- A bracketed issuer literal with a trailing dot (`[::1.]`) is admitted as the issuer's own origin
  and cannot be fetched; it fails closed (`story:bracketed-literal-trailing-dot`).
- `DisableOAuthClient`'s "disablement cannot stop the issuance of new authorization codes to it" is
  decided by nothing and deferred to `decision-blocker:epoch-atomicity`.

## [0.4.0] - 2026-09-22

Three defects the previous release's own adversary passes measured and filed, fixed and gated. The
clause count is unchanged at 190 clauses and 83 decided on the real path: none of this touches a
clause, and the number stands on `decision-blocker:guards`.

### Changed

- **Breaking.** `LinkStore` declares one required method, `records_on_key`, answering every record on
  an external key in every lifecycle state. `link` and `key_is_held` moved to a new `LinkResolution`
  trait with a blanket implementation over every `LinkStore`, so the record that holds a key and
  whether a key is held are decided by this crate and cannot be answered by an implementor. Any
  out-of-crate `LinkStore` implementing `link` must move to `records_on_key`; a blanket impl cannot
  be overridden, which is the point — adversary pass 2 of `story:link-absent-discriminates` built a
  store that satisfied every stated requirement and provisioned around a revocation.
- `services/control-plane`'s `Deployment::key_holds_no_record` pre-check is removed with its call
  site. The condition is decided in the library, in one place, and the adapter's own verifier call on
  that path goes with it — one fewer port call per refused provisioning attempt.

### Fixed

- `ProvisionExternalPrincipal` refuses `ExternalKeyExists` for a key **any** record holds in any
  lifecycle state, so a login after `UnlinkExternalPrincipal` no longer provisions around the
  domain's only federated revocation by minting a new `PrincipalId` for the same external subject
  (`story:link-absent-discriminates`). `Projection::link` prefers the smallest `Linked` record and
  falls back to the smallest record in any state only when the key has none, so
  `authenticate_federation`, `LinkConflict` and `Projection::conflicts()` are unchanged — verified
  over eight lifecycle-state masks × eight append orders.
- `UreqJwks::admits` folds the destination host once and hands one name to all three comparisons, so
  a host and its absolute spelling get one answer and `127.0.0.1.` can no longer list its way past
  the SSRF containment (`story:host-spelling-folded`). The class had seven members beyond the one
  reported. Measured over 12,168 base→head decisions: 241 move refused → admitted and every one
  leaves through the issuer's own-origin comparison; 716 move admitted → refused and every one is an
  address literal spelled with a trailing dot. Nothing becomes reachable through the containment
  branch that was not reachable before.
- Every execution of a control-plane test binary gets its own scratch root, and each run sweeps the
  roots of runs whose process id is no longer live, so the parent is bounded by the live runs
  (`story:per-run-test-scratch`). `CARGO_TARGET_TMPDIR` is resolved at compile time, so two
  concurrent copies of one lane clobbered each other's flag documents: 45, 14 and 29 failures
  measured across three lanes before, 0 after, with 3,780 cases at 4-way concurrency clean.

### Added

- `decision-blocker:async-runtime` and `UNMAPPED-RUNTIME` in `docs/architecture/unmapped.md`. ADR
  0009 — event-sourced persistence through the organization `eventlog` kit, accepted 2026-09-18 — is
  implemented by nothing: the kit is pinned and named by two manifests, no Rust file references it,
  and every fold is hand-written and synchronous. One admission stands between the ADR and the code
  and was never taken — the kit's `EventStore` is async and this workspace admits no runtime, which
  wave 3 recorded as stop condition S1 on 2026-09-18 and deferred. `story:domain-folds-over-the-kit`
  is blocked on it; `story:eventlog-repin-0-3-0` moves the pin to the tag released today and says
  plainly that it buys nothing until the admission is taken.
- Five stories filed from what the adversary passes found and this release did not fix, each
  carrying the red case that found it verbatim in its own body:
  `story:control-plane-loopback-fold`, `story:linked-event-method-unenforced`,
  `story:road-lane-child-prints-address`, `story:folded-is-not-an-address-fold`,
  `story:enabled-for-issuer-filters-in-the-implementor`.
- `crates/mandate-conformance`'s completeness guard scans port **declarations** rather than one
  implementation's overrides, so a defaulted port method is no longer invisible to it. Turning it on
  surfaced four methods the override scan had never seen, two of them defective:
  `CredentialResolution::cached` and `::cached_at` answered `None` consulting nothing, which is the
  armed-unreached the guard exists to catch.

### State at this release

| | |
|---|---|
| `task check` | exit 0 — 250 suites, 1,920 tests passed, 0 failed |
| named mutants | 11, each killed by the target it names |
| conformance | 166 scenarios, `error` 0 |
| obligations | 190 clauses · 83 real · 21 double-only · 86 deferred — unchanged |
| coverage map | 292 elements, 0 unexplained |

## [0.3.0] - 2026-09-22

### Added

- The federated-login road runs against the spawned binary. `mandate-control-plane serve` takes four repeatable document flags — `--connection`, `--key`, `--client`, `--resource-server` — and `services/control-plane/tests/end_to_end.rs` stands a loopback OIDC issuer beside the child, mints a proof under the key it publishes, and drives login → authorize → token → introspect over TCP. Driving it found that the binary had refused every login since it was written: `main.rs` built `RealVerifier` and never called `configure_connection`, and 78 green cases said nothing because every one substituted a double.
- A first-time user nobody provisioned completes a login (`decision-blocker:jit-provisioning`, cleared 2026-09-21 for the adapter sequence). `Deployment::authenticate` observes the absent-link refusal, reads `jit_provisioning` off the selected connection, drives `ProvisionExternalPrincipal`, folds its event and authenticates once more; a second refusal is returned rather than retried. A revoked link is not provisioned around: the retry reads the key across every lifecycle state, because `LinkAbsent` stands for both "never linked" and "revoked" (`story:link-absent-discriminates`).
- Every refusal on the road names itself. Eleven refusals across the resolution order are driven against the child, each asserting the clause and the verifier reason the child records on its own stderr — the wire body is unchanged, since one `error_description` per denial is correct and a caller is not owed the cause. `DenialClause::ProofInvalid` covers twenty `RefusalReason`s, so the clause alone would not have discriminated them.
- A flag document is admitted through the command that owns it, so a pair `register_federation_connection` refuses is refused before the socket rather than after a login it silently breaks. `jwks_hosts` lets an issuer publish its key set on a second host, which every real provider does; the containment was correct and unusable.
- `contracts/use-cases/` and `docs/adr/0011-use-cases.md`: a use case is a checked registry — parties and what each delivers, the commands it composes, the routes, the configuration, the evidence by test id, the standards by RFC, and what is not yet true. Every promise carries `locally_refutable`, and nine of seventeen are false: things that would produce no observation here at all if violated. `docs/public/federated-login.md` is the page a customer reads.
- The twenty authored denial scenarios execute. They wrote an explicit `null` for optional fields, which the domain's `Option` refuses, so nineteen errored and the conformance step exited 1. Corpus 146 → 166; `error` 19 → 0; `passed` 30 → 44.

- `crates/mandate-federation::verifier_real`: `RealVerifier` implementing `FederationVerifier` over `jsonwebtoken` (aws-lc): RS256 and ES256 under a deployment-configured allowlist, per-connection algorithm and allowed JWKS hosts, `JwksSource` with an in-memory and a `ureq` implementation (native TLS, platform roots, no redirects, no environment proxy), per-issuer key cache with rate-bounded refetch, max age and `forget(issuer)`; issuer, audience (`azp` for multi-audience), `exp`/`nbf`/lifetime, `typ`, `crit`, `cnf`, `sub` bound; OIDC `_verified` companions decide verified claims. The eight federation cases run through it with real tokens and no double.
- `crates/mandate-token::signing_real`: `CredentialSigner` and `RealSigner` — RS256/ES256 signing under the same allowlist, the standard claims the signer's alone (colliding caller claims refused, bounded map), `kid` selection, a rotation window that keeps a key published through the instant of the last credential's `exp`, permanent revocation by `kid` and RFC 7638 thumbprint, PEM/DER strictness, no key material in `Debug`.
- `crates/mandate-federation`: `DisableFederationConnection`, `UnlinkExternalPrincipal`, `DisableOAuthClient` handlers; events as the declared payload structs with `ess_name()`; agreement, emitted-event and replay tests; refusals name the contract's outcome (`denied` or `wrong-state`).
- `crates/mandate-identity`: the five event-shape drifts corrected; `revoke_session`; `IdentityLog` opens a Session from the generated `FederationAuthenticated` payload (login → refresh → revoke replays from events alone), with the snapshot ordering enforced at append; `ESS_UNREALIZED` names what the crate does not realize.
- `crates/mandate-model`, `crates/mandate-types`: projections, payloads and all 36 `.State` enums agree with the generated shapes with pairings asserted by ESS's name derivation.
- `cargo xtask licenses`: a lock-wide license fold reading `deny.toml`'s allowlist (dev-only crates were unchecked by `cargo deny` here).
- `services/sts` as a library: the audience registry (`RegisterResourceServer`, `DisableResourceServer`), both credential families (`IssueReferenceCredential` — the secret returned once and only its domain-separated digest persisted; `IssueSelfContainedCredential` through `CredentialSigner`), introspection and revocation (`IntrospectCredential` answers `active: false` for a revoked, expired or unknown credential; the caller's authority and the revocation guarantee decided from the issuing registration; the positive-cache bound enforced; `requires_online_authorization` never asks the cache), signing-key registration, retirement and revocation; one realization registry over the 34 `mandate.credential` elements (`story:credential-profiles`).
- `crates/mandate-token::projection` and `::verifier`: `ResourceServer`, `AccessCredential`, `SigningKey` records agreeing with the generated shapes, folds honouring every declared `from:` set, uniqueness indexes as views resolved by one total order; the non-reversible reference verifier with constant-time comparison.
- Contract: `RegisterOAuthClient` → `OAuthClientRegistered` creates `OAuthClient`; `RegisterSigningKey` → `SigningKeyRegistered` creates `SigningKey` (with `thumbprint` and the invariant `not_before < expires_at`); `IntrospectCredential` responds and emits `credential_id` and `active`; `ProvisionExternalPrincipal` responds `display_name`; `Principal` declared as seeded by `ExternalPrincipalProvisioned` (`story:declared-writers`, contract round). 61 commands, 74 events; synthesize 146 scenarios, 52 refusals.
- `crates/mandate-identity` folds the `Principal` record from `ExternalPrincipalProvisioned`, deciding every declared field of the payload; `crates/mandate-federation` creates the `OAuthClient` through its command and `AuthorizePublicClient` reads the registered client from the fold (`story:declared-writers`, realization round).
- `services/sts` issues and redeems authorization codes (`story:oauth-transaction`, split from `story:oauth-integration`): the `AuthorizationCode` record and its events, an event-log port with a compare-and-set on expected stream version (in-memory fake), `IssueAuthorizationCode` (registered, enabled, public client of the context's organization; the exact redirect registered; the code secret minted once with only its domain-separated verifier recorded; the expiry bounded by the deployment's `CodeLifetime`), `RedeemAuthorizationCode` (possession decided before any state re-read; the one-winner race; the credential's fields from the session, the registration and the code) and the `AccessCredential` fold arm from `AuthorizationCodeRedeemed` in `mandate-token`; every `DenialClause` a phrase of a declared denial, mapped both ways for all eleven STS commands.
- Contract: `AuthorizationCodeRedeemed` carries the whole credential record it issues (`credential_id`, `target`, `epochs` from a widened response; `reference_verifier`, `issued_at` minted) and is declared as the `AccessCredential`'s seeding event beside the code's `consume`; the redemption's accepted summary accounts for every field of its generated context (`story:declared-writers`, contract round 2).

- `crates/mandate-server` and `crates/mandate-proto::oauth` (`story:login-adapters`, wave D): the six product routes decoded into the crates' own input structs — every undeclared field, repeated parameter, undeclared component (a body on a query route, a query on a body route), oversize component and free-text control character (Unicode `Cc`) refused before any handler runs; the RFC 8414 metadata and JWKS documents rendered from the admitted public members only (`Jwks::new` refuses a repeated `kid`); every denial clause and reason mapped onto the RFC 6749 error code of the endpoint that answers it, with the check that no clause reachable from a redemption (followed by call through `services/sts`) answers `invalid_client` or `invalid_scope`; `docs/architecture/adapter-contract.md` states the rules and the check behind each.
- `contracts/coverage.json`, `cargo xtask coverage` and `generated/coverage/receipt.json` (`story:coverage-map`, wave D): every compiled contract element mapped to its implementation and the checks that decide it — 201 implemented, 29 declared, 62 deferred of 292; symbols proven by the compiler through `mandate_types::realizes!` registries (now admitting `@ Type::method`), tests proven by `cargo test -- --list` with ignored cases subtracted, a generated contract shape never an implementation, a `declared`/`deferred` story refused on a terminal rung, a `.State` element following its record, and the receipt binding the ESS version and every input digest, byte-compared by `contracts`.
- `services/control-plane` (`story:product-listener`, wave D): the composition — control plane and STS in one process behind three cross-crate port adapters, the session proof a login hands back, the `code` → `code_id` resolution through the STS's whole-slice by-verifier read — and the listener: `mandate-control-plane serve --listen <addr> --issuer <url>`, a blocking `std::net` + `httparse` loop, one request per connection, bounded head, header count and body, dispatch only on the declared route table (a generated command path answers 404), every refusal an RFC 6749 error body, `no-store` on credential responses. The login road runs end to end over raw TCP in `tests/serve.rs`: a login opens a session, an authorization request yields a code, the token endpoint issues the credential, introspection answers active.

- `contracts/obligations/` and `cargo xtask obligations-registry` (`story:obligation-registry`, wave D second half): one document per crate mapping every external denial **clause** an implemented command publishes to the test that decides it, and `contracts/conformance/obligations-report.json` counting `{clauses, real_covered, double_only, deferred}` per crate and in total. A clause is a verbatim substring of the command's declared `condition.cause` and the clauses of one command **tile** that cause, so a clause cannot be dropped to make a count rise; a `double` row never covers a clause and is counted in its own column; every unbound clause carries `blocked_on` naming a story the store holds whose status is not terminal, or an open `decision-blocker`, and the step refuses a deferral to a closed one — which is what turns "the work is planned" into "the work is done" without anyone having to remember to.
- The seven per-crate binding stories (`story:obligations-{sts,federation,identity,graph,model,policy,authz}`, wave D second half): **190 clauses across the seven documents — 83 decided on the real path, 21 reached only by a double, 86 deferred with a named live owner.** Per crate: `mandate-sts` 52/32/0/20, `mandate-federation` 40/28/3/9, `mandate-identity` 12/4/2/6, `mandate-graph` 19/0/8/11, `mandate-model` 42/12/0/30, `mandate-policy` 10/0/6/4, `mandate-authz` 15/7/2/6.
- `executable-system-specification:mandate` (`validated`): the conformance evidence for the tagged tree. `cargo xtask conform` on `09ad164` — 146 scenarios, 29 passed / 54 failed / 0 error / 63 unsupported / 0 skipped, `spec_digest 2f11d2da…`, 318 projections agreeing. Every non-passed scenario names a live `blocked_on` story, checked mechanically on every run.

### Changed

- The `serve` refusal in `cargo xtask check` narrows from six binaries to five: `mandate-control-plane` serves the login road and is proven by its own listener cases (ruling D3).
- `mandate.tenancy.*` commands and `mandate.tenancy.Denied` are `implemented` by `mandate-model` in the coverage manifest, registered by their deciding functions or by the `Tenancy` aggregate where the function takes an `impl Trait` argument.
- Signing-key commands require platform signing-key administration authority; the `IntrospectCredential` denial covers the caller's own invalid, revoked or expired proof and a malformed presented proof, while a well-formed proof that resolves to no record is an accepted inactive answer.
- `aws-lc-rs` and `rand` are dev-dependencies of `mandate-sts` for one end-to-end issuance through a run-time `RealSigner`; `mandate-sts` has its own boundary entry (`LIBRARIES` 17).
- Two links racing on one external key resolve by a total order on the records (smallest id holds the key), so every append order folds to one projection.
- A consumed authorization code at `AuthorizePublicClient` is the declared `denied` outcome; the wrong-state outcome is `RedeemAuthorizationCode`'s.
- Dependencies: `jsonwebtoken` 10.4.0 (`aws_lc_rs`), `ureq` 3.4.2 (`native-tls`), `rand` and `aws-lc-rs` for test-time keys; license allowlist gains `BSD-3-Clause`, `ISC`, `CDLA-Permissive-2.0`.

### What the obligations registry found

**Most of what the contract publishes as a refusal, the crates do not decide.** 86 of 190 clauses are deferred, and the large majority name a path the crate that owns the command cannot reach at all — not work its binding story could have done. Three crates decide nothing or nearly nothing on a shipped path:

- **`mandate-graph` decides 0 of 19.** `admit` propagates `lookup.placement(..)?` and `admission.admits(..)?` and compares nothing itself; every decider is behind `ResourceRegistry`, `ResourceLookup`, `SubjectAdmission`, `RelationshipWriter` or `RevocationWriter`, and `GraphDouble` is the only implementor of each.
- **`mandate-policy` decides 0 of 10.** `impl PolicyAdministration` exists twice in the workspace — the library double and a stub inside a test binary — and no handler names either supersede command.
- **`mandate-model` decides 12 of 42.** No case exists for any of its ten `Caller lacks …` clauses: authority is `mandate-authz`'s, and `MembershipAuthority` is the caller's statement, not a grant.
- **`mandate-authz` decides 7 of 15**, having been published as covering 5 of 5. Two clauses each bundled several conditions behind rows that decided fewer.

A count that can fall by work and cannot fall by deletion is the point of the file. This is the first honest reading of it.

### Pre-existing defects found by the adversary passes

Each is a defect in shipped behaviour, routed to a live story; each adversary case is pinned to the behaviour as it ships and names the story that flips it.

- `collides` compares claim names, so a different-claim pair on one issuer is admitted and makes every login `TenantAmbiguous` (`story:federation-rule-disjointness`).
- A profile bound past the readable year is admitted and issues an expiry the crate reads back as `None` (`story:sts-lifetime-bounds`).
- The losing half of two concurrent redemptions draws a secret and an identity before the compare-and-set refuses (`story:sts-refusal-draws-nothing`).
- A caller verified in one organization advances another organization's security-epoch generation (`story:identity-tenant-containment`).
- `mandate.identity.SessionRefreshed` and `mandate.authorization.DecisionRecorded` are declared, emitted by an accepted outcome and folded nowhere, so accepted and refused leave byte-identical logs (`story:declared-writers`).
- `Resource.space_id` is written as a literal `None` by the only constructor of a `Resource`, so no scope naming a space can ever bind (`story:declared-writers`).
- Graph visibility, hierarchy and membership: `require_revision` is called only by `GraphDouble::check`; an over-deep chain registers and is then unanswerable (`story:graph-policy-adapter`).
- Four crates refuse on conditions their declared cause publishes no clause for, and `mandate-policy` publishes a 409 `wrong-state` refusal its only implementor answers as an accepted repeat (`story:unpublished-refusals`).
- Five gaps in the registry step itself, including that a `double` value is checked only for non-emptiness and that a deferral's owner is never measured (`story:cross-crate-clauses`).

### Three crates route a live gap to a finished story

`mandate.identity.SessionRefreshed` is rowed under `story:session-epochs`, `mandate.authorization.DecisionRecorded` is pointed at `story:check-api`, and the space-binding gap at `story:event-payloads-for-folds` — all three `implemented`. A comment or a manifest row naming a story is a claim about ownership that nothing rechecks when that story closes. The registry step refuses such a deferral; nothing refuses the comment.

### Conformance at this point

Gate on `09ad164`: `task check` exit 0, **1,821 tests across 215 targets** (wave D first half closed at 1518 / 202, wave C at 1306 / 181, wave B at 1205 / 173, wave A at 1025 / 152). 22 packages satisfy metadata and dependency boundaries; 10 declared documents present; 11 named mutants each refused by the target it names; 292 contract elements mapped (201 implemented, 29 declared, 62 deferred); 190 external denial clauses (83 real, 21 double-only, 86 deferred); projections and receipt byte-identical.

`cargo xtask conform`: 146 scenarios — **29 passed, 54 failed, 0 error, 63 unsupported, 0 skipped**, `conformance_status: failed`. Every non-passed scenario names a live `blocked_on` story, and two tests check that mechanically on every run rather than by review. The owners: `story:ess-synthesizer-prerequisites` 53, `story:directory-provenance` 13, `story:testkit-doubles` 13, `story:agent-authority-kernel` 10, `story:graph-policy-adapter` 9, `story:audit-worker-delivery` 6, `story:constrained-exchange` 5, `story:declared-writers` 4, `story:oauth-integration` 2, `story:refusal-discriminators` 1, `story:agent-security` 1.

The login road is served over HTTP against in-memory folds; `serve`d deployments start empty until the event-log adapter lands. Not yet built: the JIT branch on the served route (`decision-blocker:jit-provisioning`), the denial-audit path (`decision-blocker:audit-routing`), creators for the entities outside the login road (`story:declared-writers`), the real graph and policy adapters (`story:graph-policy-adapter`) — which is what would move `mandate-graph` and `mandate-policy` off zero — and the authority decisions behind `decision-blocker:guards`, which 31 clauses defer to.

Built and green in its tree but **not merged**: `story:authored-denial-scenarios` (20 authored denial scenarios, suite 146 → 166). Its commit is refused by the `b10x-gates` pre-commit hook on 13 secret-scanner findings over synthetic JWS fixtures — 12 `jwt`/`jwt-base64` on a fixture decoding to `{"alg":"RS256","typ":"JWT","kid":"k1"}` and `{"iss":"https://other.example.test","aud":"mandate-client","sub":"u-1"}`, and 1 `generic-api-key` on the base64 of the literal string `credential-issued-for-api-b…`. No key material. Admission is a trusted-policy exception and has not been granted; `4f130a6` on `impl/authored-denial-scenarios` carries the one path of 21 the hook admits.

## [0.2.0] - 2026-09-19

Wave E1 of the ESS-to-implementation drift-protection programme: the contract now declares its creators and wrong-state outcomes, the implementation carries generated contract shapes it must agree with, tenancy and resource commands emit their declared events and fold from them, and a harness validates emitted events against the closed contract. The specification changed (widened responses, one outcome per moving command), so this is a minor version under 0.x.

### Added

- `crates/mandate-contract`: structural Rust shapes for all 72 events, 59 command inputs, 24 responses, 11 errors and 36 entities, emitted by `cargo xtask generate` from the compiled model (`generated/ir/system.json`) and byte-compared by `cargo xtask contracts`; `deny_unknown_fields` records, `Presence<T>` for optionals (absent is an absent key, `null` refused), `serde_json::Number` for integers.
- `crates/mandate-testkit::contract`: `assert_event_conforms`, `assert_single_emission`, `assert_payload_sources` — schema validation with format assertions, one emission per accepted outcome and none per denied, and payload sources decided per `target_type` against the IR.
- `crates/mandate-model`: `TenancyEvent` (10) and `ResourceEvent` (2); every tenancy and resource command is `decide` + `apply` + `fold`, replay proofs fold each entity from its events alone.
- `crates/mandate-conformance` and the `mandate-conform` binary (skeleton; refuses until the conformance target lands), ESS 0.26.0 crates and `jsonschema` admitted, `cargo xtask adopt` for ESS output ownership in a fresh checkout, the `realizes!` registry.
- ESS repinned to 0.26.0.

### Changed

- `systems/mandate`: 16 creators declared (`creates:` + `instance:`), every creating event carries its record with truthful sources; 34 moving commands declare a `wrong-state` outcome; a consumed authorization code is that outcome; `AuthenticateFederation` creates the Session and its response carries `session_id`, `organization_id`, `principal_id`, `epochs`, `expires_at`; `RegisterResource`, the three issuance commands and `WriteRelationship` return their new identity. Synthesis 84 → 132 scenarios, refusals 106 → 59.
- `docs/architecture/command-obligations.md` and `federated-login.md` follow the contract.

### Conformance at this release

| Measure | Value |
|---|---|
| Scenarios the specification synthesizes | 132 |
| Scenarios executed against the implementation | 0 (no conformance target yet; `story:conformance-target`) |
| Refusals, named | 59: 57 `ESS-SYNTH-004` on 16 creator-less entities (`story:declared-writers`), 2 `ESS-SYNTH-011` on `Delegation` (invariant read by no view) |
| Entities the log cannot rebuild | 12 (was 14) |
| Events with a generated Rust shape | 72 of 72; agreement of the 11 hand-written event variants with those shapes is `story:federation-identity-alignment` |
| Accepted paths proven only against doubles | unchanged from 0.1.0 |
| Contract-versus-implementation drift surfaced, open | consumed authorization code returns 502 where the contract says 409; four idempotent-accept records where the contract says 409 (routed to `story:federation-identity-alignment`, `story:graph-policy-adapter`) |

### State at this release

777 tests across 127 targets, `task check` exit 0. Not in this release: everything the 0.1.0 entry lists as absent, plus the conformance run itself.

## [0.1.0] - 2026-09-19

The first tagged release: the state of `main` after wave 3 of the ten-wave forecast, plus this changelog. Contents are the sum of the four pre-releases below.

### Added

- `CHANGELOG.md`, with the integration batches since the repository's foundation backfilled as pre-release tags.

### State at this release

| What runs | Where |
|---|---|
| 611 tests across 109 targets, `task check` exit 0 | workspace |
| `mandate.authorization.Check` decided over the graph and policy ports | `crates/mandate-authz` |
| Federation registration, explicit linking, first-login provisioning, authentication, and the non-consuming `AuthorizePublicClient` validation | `crates/mandate-federation` |
| Session security generations, snapshots and refresh | `crates/mandate-identity` |
| Tenancy and resource topology folds | `crates/mandate-model` |
| Graph and policy ports over doubles, deny precedence | `crates/mandate-graph`, `crates/mandate-policy` |
| 72 events, 59 commands, 110 types, 36 entities, regenerated and byte-compared | `systems/mandate`, `generated/` |
| The gate reads its document deliverables (`cargo xtask documents`) | `xtask/` |

Not in this release: a served route (every binary refuses `serve`), a real signature or JWKS verifier (the port has a fixture double), a durable event-log adapter (the kit is wired, folds are in-memory), credential issuance and code redemption at STS, and the customer-facing login flow end to end. Fourteen entities still have no creation event and cannot be rebuilt from the log.

## [0.1.0-alpha.4] - 2026-09-19

Wave 3 of the forecast ([#7](https://github.com/beyond10x/mandate/pull/7)): `story:check-api`, `story:pkce-sessions`, `story:event-payloads-for-folds`, `story:gate-reads-document-deliverables`.

### Added

- `mandate-authz` decides `Check`: context binding (tenant, membership, audience, resource placement, space), one graph read and one policy read folded through deny precedence with the requested `AuthorityScope` and the applicable ceilings, decision assembly with challenges; `CouldNotAnswer` is never an allow; a context carrying an actor, delegation or execution other than the subject is refused closed until the agent stories land.
- `mandate-federation` validates `AuthorizePublicClient` without consuming: the S256 challenge form decided by decoding to 32 bytes, registered public client, exact redirect, target registered inside the tenant, session through `mandate-identity`, state and nonce compared in constant time, expiry; two concurrent callers each obtain a candidate.
- `mandate pkce-challenge`: the S256 challenge for a verifier read from stdin or a positional; RFC 7636 §4.1 form enforced; no message echoes the verifier.
- Seven seeding events no command emits, each published by its domain's component: `SessionOpened`, `EpochSnapshotRecorded`, `SecurityEpochRecorded`, `DirectoryGroupRecorded`, `SyncJobRecorded`, `DirectoryGroupMembershipRecorded`, `MembershipContributionRecorded`.
- Every move-event carries the moved record's identity; creation events carry every required field; `ResourceRegistered` and `RelationshipWritten` carry the exact `resource: ResourceRef` input.
- `cargo xtask documents` in `task check`: every architecture document exists and is non-empty, and every store-derived claim a document states equals `aep plan artifact blocked`.
- The event-log kit (`eventlog-core`, `eventlog-sqlite`, tag 0.2.1) wired for `mandate-provisioning` and `mandate-worker`.

### Changed

- `FederationAuthenticated`, `ExternalPrincipalProvisioned`, `SessionRefreshed` and `AuthorizationCodeIssued` carry explicit fields instead of a generated `VerifiedContext`.
- `generated/` regenerated: events 65 → 72; types, entities and commands unchanged.
- `docs/architecture/runtime-decisions.md`: eight store-derived row sets corrected; the blocker-group count is fourteen.
- `deny.toml` admits the event-log git source and the `Zlib` license (`foldhash`, transitive).

### Deferred

- `story:directory-provenance`: `tokio` admitted nowhere, the worker package cannot name `mandate-provisioning`, and its fold inputs were undeclared until this wave.

### Validation

`task check` on `333a1de`: exit 0; 109 targets; 611 passed; 0 failed. Eight adversary passes, 68 findings: 55 fixed, 9 no-op, 4 escalated and recorded on the stories.

## [0.1.0-alpha.3] - 2026-09-18

Wave 2 of the forecast ([#6](https://github.com/beyond10x/mandate/pull/6)): `story:session-epochs`, `story:tenancy-topology`, `story:federation-linking`, `story:graph-policy`.

### Added

- `mandate-identity`: principal, organization and federation generations as non-negative monotonic stand-ins for u64; epoch snapshots pinned to a session; `IncrementSecurityEpoch` as a compare-and-set that denies at the maximum; `RefreshSession` denying `StaleEpoch`; expiry compares RFC 3339 instants.
- `mandate-model`: organization, membership, team, space and resource folds; `cross_tenant_resource` holds and is mutation-measured; five tenant-scoped readers; a compile-time `PersistedValue` boundary over the projections.
- `mandate-federation`: `RegisterFederationConnection`, `LinkExternalPrincipal`, `AuthenticateFederation`, `ProvisionExternalPrincipal` behind ports; all eleven federation corpus ids execute; canonical key `(organization, connection issuer, subject)`; tenant resolution requires the selected connection's rule.
- `mandate-graph`, `mandate-policy`: sealed ports over doubles for the five graph commands and the two policy supersessions; the revision-bound read denies a revoked grant at every floor; deny precedence has one home and ranks the challenge by a total order.
- `AGENTS.md`: scripts serve quick tests and reviews only; persistent checks are Rust.

### Validation

`task check` on `5cf9fb9`: exit 0; 90 targets; 400 passed (81 at the wave-1 head). Eight adversary passes, 62 findings: 58 fixed, 4 escalated into named stories.

## [0.1.0-alpha.2] - 2026-09-18

Wave 1 of the forecast ([#5](https://github.com/beyond10x/mandate/pull/5)): `story:canonical-types`, `story:runtime-decision-dossier`.

### Added

- The 74 accepted ESS types realized across `mandate-types`, `mandate-model`, `mandate-token` and `mandate-proto`, with a machine-checked inventory binding them to `generated/schema/types`; `compile_fail` doctests enforce identifier non-interchangeability and the transient-credential boundary.
- `docs/architecture/runtime-decisions.md`: one section per open runtime decision blocker, each with a source-cited question, bounded alternatives, a proposed owner, affected stories read from the planning store, and the exact evidence required to clear it.

### Validation

`task check` on `ff31684`: exit 0; 72 tests across 45 targets and 14 doctest lanes (0 at the baseline).

## [0.1.0-alpha.1] - 2026-09-18

The planning batch ([#4](https://github.com/beyond10x/mandate/pull/4)), on top of the foundation chain published directly to `main` on 2026-09-17 (contracts, scaffold and public outlook; Atlas publication contracts; the foundation publication record and the canonical-type handoff).

### Added

- The ten-wave forecast over 22 stories with dependency and ownership boundaries.
- `docs/adr/0008-integration-batches.md`: story branches accumulate on an integration branch, one pull request per selected batch, releases selected separately from `main`.
- The canonical-types driver readiness record.

### Validation

`task check` passed, including AEP validation (72 artifacts), ESS validation and deterministic projections.

[Unreleased]: https://github.com/beyond10x/mandate/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/beyond10x/mandate/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/beyond10x/mandate/compare/v0.1.0-alpha.4...v0.1.0
[0.1.0-alpha.4]: https://github.com/beyond10x/mandate/compare/v0.1.0-alpha.3...v0.1.0-alpha.4
[0.1.0-alpha.3]: https://github.com/beyond10x/mandate/compare/v0.1.0-alpha.2...v0.1.0-alpha.3
[0.1.0-alpha.2]: https://github.com/beyond10x/mandate/compare/v0.1.0-alpha.1...v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/beyond10x/mandate/releases/tag/v0.1.0-alpha.1
