# Architecture forks in the OpenID Provider design

Every fork met while drafting ADR 0012, the epic and its stories. Each has lettered options, what
each costs, and a recommendation. Forks marked **contract** change `systems/mandate` and must be
decided before the spec-first wave; the others can be decided inside the story that meets them.

Decided 2026-10-15: F1–F9 each on its recommendation, as the table in
`docs/adr/0012-openid-provider.md` ("Design forks decided") states. F10–F22 are decided inside
their stories, on the recommendation below unless the story finds it does not hold.

---

## F1 — `sub` stability across the Dex → Mandate move (contract)

Dex's `sub` is base64url of a protobuf `{user_id: <upstream sub>, conn_id: <connector id>}`. Any app
that keys accounts on `sub` sees every user as new when the issuer moves, so "works unchanged" fails
for it — and `iss` changes anyway, so an app keyed on `(iss, sub)` breaks under every option.

- **A. Mandate's own subject** (the `PrincipalId`, a UUID). Clean, stable across upstream changes and
  re-linking. Cost: every app keyed on `sub` needs a one-time remap (by email or by a published
  `dex_sub → principal` table). Breaks "unchanged" for those apps.
- **B. Dex-compatible subject per connection.** A connection may declare `subject_format:
  dex_compatible` with the Dex `connector_id` it replaces; Mandate then emits
  `base64url(protobuf{user_id, conn_id})` byte-identical to Dex. Cost: a second subject format in the
  token renderer, an encoder with a golden test against Dex output, and a subject that leaks the
  upstream subject (as Dex's already does). Ties the subject to the upstream, so re-linking a person
  to another connection changes it.
- **C. Pairwise subjects** (OIDC Core 8.1). Best privacy; breaks every app keyed on `sub`. Wrong
  default for a first-party platform.
- **D. A, plus a published migration table** (`dex_sub`, `principal_id`) produced from the links, and
  `federated_claims` carried for one release. Cost: a migration artifact and its custody.

**Recommendation: B for connections that replace a Dex connector, A everywhere else**, chosen per
connection and immutable once a token was issued under it (changing it is a new connection, like an
issuer change, `federation.yaml:2`). Apps keyed on email or groups are unaffected either way. Record
the app inventory's keying before the cutover; it decides how many apps actually need B.

## F2 — Storing confidential-client secrets (contract)

Dex reads `secret` or `secretEnv` and compares plaintext.

- **A. Secret file reference, verifier only in the record.** The client document names a reference
  (`secret_ref: "NAME"`), resolved like `--client-secret-file NAME=PATH`
  (`services/control-plane/src/main.rs:125`) to a mounted Kubernetes Secret; the process derives a
  keyed verifier (HMAC-SHA-256 under a deployment pepper) at start, compares in constant time, and
  `OAuthClientRegistered` carries the verifier, never the secret. Cost: rotation needs a restart or a
  re-registration event; two secrets during rotation need a list of verifiers.
- **B. Plaintext in the client document.** Dex-like and simplest. Cost: a secret in a config file
  and, once registration is an event, in the event log — violates `combined.md:43`.
- **C. Slow hash (Argon2id) of the secret.** Cost: CPU per token request on a single-threaded
  listener; buys nothing for high-entropy generated secrets.
- **D. `private_key_jwt` only.** Strongest; Envoy Gateway's filter does not speak it. Not parity.

**Recommendation: A**, with up to two active verifiers per client so a secret rotates without
downtime, and a minimum secret entropy refused at startup (exit 2), as other unusable configuration is.

## F3 — PKCE for confidential clients (contract)

Mandate requires S256 on every authorization request (`decode.rs:880`). Dex does not require PKCE.
Whether Envoy's oauth2 filter sends a `code_challenge` depends on the Envoy version Envoy Gateway
ships (recent versions do; older ones do not) — this needs verifying against the deployed
version, not assuming.

- **A. Keep PKCE mandatory for every client.** Strongest; breaks "unchanged" on a gateway that sends
  none.
- **B. Per-client `pkce_required`**, true by default, required true for public clients, settable
  false only for a confidential client. Cost: one more field and a refusal clause; a
  confidential-client code is then bound by client authentication and redirect URI alone (RFC 9700
  still recommends PKCE).
- **C. Optional for all confidential clients, enforced when presented.** Cost: a downgrade path
  nobody chose.

**Recommendation: B.** Record in the use case which gateway version was measured.

## F4 — A browser session at Mandate (contract)

Today `/oauth/authorize` takes the session proof as a bearer header (`decode.rs:870`), which no
browser redirect from a gateway can carry. The relying-party callback hands the session to an
embedding app through a single-use handoff (`routes.rs` `/v1/federation/handoff`).

- **A. No Mandate session (Dex's model).** Every authorization round-trips to the upstream; the
  upstream's own session makes it silent. The pending authorization request is held in the same
  single-use store as the RP flow's pending login (`adapters.rs` `PENDING_LIFETIME`). Cost: no SSO
  across apps beyond the upstream's; logout cannot end anything but tokens; one upstream round-trip
  per app login.
- **B. A host-only session cookie** (`__Host-mandate-session`, `Secure; HttpOnly; SameSite=Lax`),
  carrying a session proof whose verifier is the existing `Session` record, lifetime
  `--session-lifetime`. Cost: a cookie that is a bearer credential; CSRF on the authorize endpoint is
  bounded by `state`/PKCE but logout needs a CSRF-safe form; `prompt=none`/`max_age` semantics to
  implement.
- **C. B plus `prompt`, `max_age`, `acr` handling and front-channel logout.** Cost: much larger;
  nothing in the parity acceptance needs it.

**Recommendation: B, minimally** — it binds every issued token to the `Session` record that the
epochs and revocation already govern, which is what makes end-session and Mandate's security epochs
mean something. `prompt=login` forces a fresh upstream login; `prompt=none` without a session answers
`login_required`; nothing else of C.

## F5 — Consent screen

Dex shows an approval page unless `skipApprovalScreen: true`; deployments behind a gateway set it.

- **A. No consent.** Every client is a first-party static client configured by the operator. Cost:
  none for parity; wrong for third-party clients later.
- **B. Per-client `require_consent`, default false**, with a minimal server-rendered page. Cost: the
  first HTML Mandate renders, its CSRF, its accessibility, and a recorded consent entity.
- **C. Always consent.** Breaks "unchanged".

**Recommendation: A for parity**; B belongs with dynamic or third-party clients, which this decision
excludes.

## F6 — Refresh-token rotation and reuse detection (contract)

`RefreshCredential` exists in the contract (`identity.yaml:82`) but is realized by no crate
(`crates/mandate-identity/src/lib.rs:219`). Rotation needs a family, a successor and a reuse rule.
Envoy's filter refreshes on any request whose access token has expired, so parallel requests from
one browser race to refresh.

- **A. Strict rotation, reuse revokes the family and the session** (RFC 9700 4.14.2). Cost: a racing
  second refresh logs the user out.
- **B. Rotation with a short grace window** (Dex `reuseInterval`, default 3 s): a refresh presented
  again within the window yields a fresh sibling, once; outside it, reuse revokes the family. Cost:
  the window is a replay window for a stolen token; Mandate stores verifiers, not raw tokens, so it
  cannot hand back the *same* successor as Dex does — it must mint a sibling.
- **C. No rotation** (Dex `disableRotation`). Cost: a long-lived bearer credential; fails the BCP.

**Recommendation: B with a 2 s default window, at most one sibling, and the family revoked on any
reuse outside it**; `absolute_lifetime` and `valid_if_not_used_for` as Dex has them; every refresh
compares the session's epochs (`combined.md:47`).

## F7 — Logout and revocation surface

- **A. RP-initiated logout only** (`end_session_endpoint`, `id_token_hint`,
  `post_logout_redirect_uri` exact-match from the client's registration): revokes the Mandate
  session and its refresh families, clears the cookie. Envoy Gateway's `logoutPath` reads
  `end_session_endpoint` from discovery.
- **B. A plus RFC 7009 `/oauth/revoke`.** Cost: one more route; `RevokeAccessCredential`
  (`credential.yaml:186`) is already declared. Useful to apps that revoke on sign-out.
- **C. B plus back-channel logout.** Cost: outbound calls to every app; not parity.

**Recommendation: A in the parity story, B as a small follow-on** (Dex's own RP-initiated logout
support is limited and version-dependent, so A already exceeds what apps rely on today).

## F8 — ID token signing algorithm

The allowlist admits RS256 and ES256 (`signing_real.rs:80`); the existing JWK examples are ES256.
OpenID Connect Core 15.1 makes RS256 mandatory to implement for an OP, Dex signs RS256, Envoy's
`jwt_authn` verifies both, and some app libraries assume RS256.

- **A. RS256 only.** Maximum compatibility; larger keys and tokens (cookie size, F10).
- **B. ES256 only.** Smaller tokens; breaks clients that assume RS256 and violates OIDC Core 15.1.
- **C. RS256 by default, ES256 per client** (`id_token_signed_response_alg`), both keys published.
  Cost: two active keys rotating, two signers.

**Recommendation: C**, with RS256 the default so a Dex-configured app sees what it saw. RSA 2048 at
minimum.

## F9 — Durable state: persistence runtime and backend (contract-adjacent)

ADR 0009 decides the event log; nothing in the control plane uses it (`story:domain-folds-over-the-kit`;
the kit is consumed only by `crates/mandate-provisioning/Cargo.toml:17` and the worker). The kit's
surface is asynchronous and the listener has no runtime (`serve.rs:16-22`, ruling D2). Refresh
tokens, sessions, links and signing keys must survive a pod restart for parity.

- **A. Adopt the async runtime now** (`tokio` + `hyper`, as ruling D2 anticipated), event log on
  SQLite on a PersistentVolume, one replica, `Recreate` strategy. Also fixes
  `story:listener-outbound-stall`. Cost: the largest single change in the epic; the listener and its
  limits are rewritten and re-attacked.
- **B. Keep the sync listener, drive the kit through a current-thread runtime per call.** Cost: a
  second mechanism around the kit; the stall stays.
- **C. Snapshot the folds to a file on shutdown.** Cost: loses state on crash; contradicts ADR 0009.
- **D. A Postgres backend from day one.** Cost: depends on the kit offering one (not verified here);
  enables more replicas later.

**Recommendation: A**, SQLite first, the backend behind the kit so D is a later swap. Until A lands,
the chart is honest that state is lost on restart — every session and refresh token, which with
Envoy means users sign in again after a deploy.

---

## F10 — Groups: source, filter and size

Envoy keeps the ID token (and, with `forwardAccessToken`, the access token) in cookies; a browser
caps one cookie at about 4 KB, and a Workspace user can be in hundreds of groups.

- **Source A. At login and refresh, from the Admin SDK Directory API** (Dex's model): fresh, one
  outbound call per login on the critical path.
- **Source B. Synchronized into `mandate.directory.DirectoryGroup` (`directory.yaml:56`) by the
  worker**, read at issuance. Cost: the directory epic's sync machinery first; staleness bounded by
  sync interval.
- **Filter A. Allowlist per connection** (Dex `groups`): required whenever groups are enabled.
- **Filter B. Per-client groups filter** on top.
- **Size A. Refuse issuance over a cap** with a stated error. **Size B. Truncate.** Truncation can drop
  a group an app authorizes on — fails safe only if every group grants, never if one denies.

**Recommendation: Source A for parity (B later, with the directory epic), Filter A mandatory plus
Filter B optional, Size A** with a configurable cap (default 50 names) and a measured cookie budget in
the use case.

## F11 — Access-token format and audience

`/oauth/token` mints a reference credential for a registered `ResourceServer` named by `target`
(`decode.rs:894`). Envoy sends no `target`; Dex's access token is a JWT with `aud` = the client id.

- **A. JWT access token, `aud` = client id, per client.** Dex parity; apps validating via
  `jwt_authn`/JWKS work. Cost: self-contained credentials are revocable only by expiry (short TTL).
- **B. Keep reference tokens; apps introspect.** Cost: breaks every app that validates the token
  locally.
- **C. Each client names a default `ResourceServer`**, whose profile (`Reference` or
  `SelfContained`, `credential.yaml:11`) decides the format. Cost: one registration per app, but it
  reuses `IssueSelfContainedCredential` (`services/sts/src/issue.rs:411`) and the profile's TTL bound.

**Recommendation: C**, with the static client document able to declare its implicit resource server
inline so "adding an app is config only" holds; a `SelfContained` profile with `aud` = client id
reproduces Dex.

## F12 — Dropping the not-an-OP stance in other documents

- **A. One documentation sweep now**, ahead of the code. Cost: documents describe a surface that does
  not exist yet — the drift ADR 0010 exists to refuse.
- **B. Each story corrects the documents its change falsifies**, in the same change (table in ADR 0012).
  Cost: the stance survives in some documents until the last story lands.

**Recommendation: B.** ADR 0012 lists every location and its owner.

## F13 — Upstream profile attributes in the event log

`email`, `email_verified`, `name`, `groups` must be available at issuance and on refresh, after the
upstream token is gone. Today `VerifiedProof` carries them (`crates/mandate-federation/src/verifier_real.rs:1349-1376`)
and nothing records them.

- **A. A profile snapshot event per login** on the `ExternalPrincipal` (email, email_verified, name,
  groups digest or list). Cost: personal data in an append-only log; erasure by ADR 0009 redaction.
- **B. Held only on the in-memory session.** Cost: refresh after restart cannot render claims;
  contradicts durability.
- **C. Re-fetched from upstream on every refresh** using a stored upstream refresh token. Cost: an
  upstream secret to hold in the encrypted boundary `combined.md:7` requires.

**Recommendation: A**, groups as the filtered list only (never the unfiltered set), with a redaction
test in the story.

## F14 — What ESS can and cannot express here

The discovery document, the JWK Set, cookies and HTTP client authentication are wire forms, not
commands; ESS has no notion of them, exactly as it has none for the RFC 8414 document today.

- **A. Commands and entities in ESS** (client type, secret verifier, ID-token issuance event, refresh
  rotation, end session), **wire forms in the route table and the use-case registry** (ADR 0011
  `route` and `promise` rows), decided by Rust tests.
- **B. Model the documents as ESS views.** Cost: a parallel model of a wire format; refused by the
  spec-first rule's "do not hand-write a parallel model".

**Recommendation: A.** If an implementor finds a command-level behaviour ESS 0.59 cannot express
(for instance the grace-window sibling of F6), stop and report rather than model around it.

## F15 — Extend `AuthorizePublicClient` or add a command (contract)

- **A. Generalize to `mandate.federation.AuthorizeClient`**, deprecating the public-only name. Cost:
  a rename through generated code, scenarios and the obligations registry.
- **B. Add `mandate.federation.AuthorizeConfidentialClient`** beside it. Cost: two near-identical
  deciders.
- **C. Keep the command, add the client type as an input it reads from the record.** Cost: the name
  lies.

**Recommendation: A**, in the spec-first wave, with the old scenarios renamed in the same change.

## F16 — Hosted domains: list or connection per domain

Dex's `hostedDomains` is a list. Mandate's tenant rule binds one validated claim value
(`crates/mandate-federation/src/authenticate.rs:400-415`), and `hd` is a validated string claim from
Google.

- **A. One connection per hosted domain**, each with `verified_claim_name: hd`. No code; one Google
  OAuth client reused across connections. Cost: N connection documents; the RP flow picks a
  connection before the user is known, so a login page or `login_hint`/domain routing is needed.
- **B. `verified_claim_values` as a list** on the rule. Cost: a contract change to
  `TenantResolutionRule`; one organization per connection still holds.

**Recommendation: B** — one Google connector configured once is the stated requirement; also send
`hd=` on the upstream authorization request when exactly one domain is listed (a hint, never the
check).

## F17 — Signing-key rotation and key material

- **A. Operator-driven rotation**: register a new `SigningKey` (`keys.rs:177`), retire the old after
  the overlap. Cost: a forgotten rotation is a never-rotated key.
- **B. Automatic rotation on a schedule** (Dex rotates every 6 h), generating keys in-process. Cost:
  private keys generated and persisted by Mandate — the event log must never hold them, so a key
  store outside it.
- **C. Keys from a mounted Secret, rotation by mounting the next key**; Mandate registers what it
  finds and retires on schedule. Cost: an external process (or the operator) writes keys.

**Recommendation: C for parity** (keys never generated or stored by Mandate, matching "private keys
reside behind a key provider", `combined.md:43`), with the overlap ≥ the longest token TTL enforced
by `RealSigner::new` (`signing_real.rs:763`). B is a later key-provider story.

## F18 — How "works unchanged" is proven

- **A. A real Envoy Gateway in a local cluster** (kind) driven by a Rust test harness: the strongest
  evidence; heavy, slow, and outside `task check`.
- **B. A Rust harness emulating Envoy's oauth2 filter** (discovery, authorize redirect, token form,
  cookie handling, refresh). Cheap and in `task check`; proves only what the emulation encodes.
- **C. B in `task check` plus A as a recorded manual run**, its version recorded in the use case's
  `promise` rows.

**Recommendation: C.**

## F19 — Workspace groups credentials

Reading groups needs a Google service account with domain-wide delegation and an admin subject to
impersonate — a powerful credential.

- **A. Service-account key file mounted as a Secret**, referenced like a client secret, scope
  `admin.directory.group.readonly` only. Cost: a long-lived key.
- **B. Workload identity federation** from the cluster to Google, no key file. Cost: platform setup
  outside this repository.

**Recommendation: A for parity, B documented as preferred where the platform supports it**; the key
stays inside the encrypted secrets boundary of `combined.md:7` and never enters an event or a log.

## F20 — Trusted peers: Dex scope syntax or token exchange only

Dex: client A requests `audience:server:client_id:B`; B lists A in `trustedPeers`; the ID token's
`aud` is `[B, A]`, `azp` A. Mandate already serves subject-only RFC 8693 exchange gated by
`allowed_exchange_sources` (`story:federated-token-exchange`, implemented).

- **A. RFC 8693 only.** One mechanism. Breaks apps using Dex's scope.
- **B. Dex scope as a compatibility alias** that resolves to the same admission decision
  (`trusted_peers` on B maps to B's resource server admitting A), emitting the multi-audience ID
  token. Cost: a second wire form onto one decision; multi-audience tokens need `azp`.
- **C. B, plus A for service-to-service.**

**Recommendation: C** — the alias is thin, and both decide through one admission path.

## F21 — Organization claim and multi-organization users

A parity token needs no organization claim; Mandate sessions are organization-bound.

- **A. No organization claim in parity**; one connection, one organization.
- **B. `org_id` claim from the session**, always. Cost: a Mandate-specific claim apps may start to
  depend on before the beyond-Dex story defines it.

**Recommendation: A for parity; B in `story:oidc-principals-organizations-in-tokens`.**

## F22 — Replicas and availability

- **A. One replica, `Recreate`, a PodDisruptionBudget that admits the restart.** Matches SQLite on
  one volume. Cost: a short outage per deploy; Envoy shows its error page.
- **B. Two replicas with a shared backend.** Cost: needs F9-D and the kit's concurrency guarantees.

**Recommendation: A**, stated as the chart's limit; B after the backend fork.
