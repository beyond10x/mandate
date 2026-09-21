# Federated login

A person is already signed in to your platform. Mandate turns the proof your identity provider issued them into a Mandate session, and that session into a credential your resource server can check — without a second password, a second account, or any per-user administration ahead of the first login.

This page describes what the code in this repository does today. Where a standard is named in the repository but is not on this road, it says so.

## The flow

```mermaid
sequenceDiagram
  participant U as User agent
  participant IdP as Your identity provider
  participant CP as Mandate control plane
  participant RS as Your resource server
  U->>IdP: sign in to your platform
  IdP-->>U: signed proof (JWT)
  U->>CP: POST /v1/federation/login (connection_id, proof)
  CP->>IdP: GET {issuer}/.well-known/openid-configuration
  IdP-->>CP: jwks_uri
  CP->>IdP: GET {jwks_uri}
  IdP-->>CP: JWK Set
  CP->>CP: verify signature, issuer, audience, tenant claim; resolve or provision the link
  CP-->>U: 200 session_id, session_proof, principal_id, organization_id, epochs, expires_at
  U->>CP: GET /oauth/authorize (Bearer session_proof)
  CP-->>U: 302 Location: redirect_uri?code=…&state=…
  U->>CP: POST /oauth/token (code, code_verifier)
  CP-->>U: 200 access_token, token_type, credential_id
  U->>RS: request carrying the credential
  RS->>CP: POST /oauth/introspect (Bearer own credential)
  CP-->>RS: 200 {"active": true, …}
```

| # | Step | What decides it |
|---|---|---|
| 1 | The request names a `connection_id`; the deployment resolves it to a configured, enabled connection. A connection nothing seeded is refused. | `crates/mandate-federation/src/authenticate.rs` |
| 2 | The proof's `iss` must equal the connection's configured issuer. The issuer is never taken from the request. | `crates/mandate-federation/src/verifier_real.rs` |
| 3 | The signature is verified against a key fetched from the issuer's own JWK Set, under the algorithm the connection is configured for. No algorithm is selected from the proof's header, and there is no default. | `verifier_real.rs`, `RefusalReason::ConnectionAlgorithmUnconfigured` |
| 4 | The proof's `aud` must name the client the connection was registered with. | `verifier_real.rs` |
| 5 | The organization comes only from the connection's `tenant_resolution` rule. Zero or several matches deny; nothing is guessed, and no email domain or hostname is consulted. | `crates/mandate-federation/src/authenticate.rs` |
| 6 | The external subject is resolved to a Mandate principal through an explicit link. With no link, a connection whose `jit_provisioning` is `true` creates the principal and the link during this login; `false` refuses and creates nothing. | `services/control-plane/src/adapters.rs`, `Deployment::authenticate` |
| 7 | A session is opened and answered with `session_id` and `session_proof`. | `services/control-plane/src/serve.rs` |
| 8 | `GET /oauth/authorize`, carrying the session proof as a bearer token, returns an authorization code by redirect. The client must be registered, enabled, public, in the session's organization, and must present a redirection URI it registered — compared byte for byte, normalized in no way. | `crates/mandate-federation/src/publicclient.rs` |
| 9 | `POST /oauth/token` exchanges the code and the PKCE verifier for the credential. | `services/sts/src/redemption.rs` |

Just-in-time provisioning is a composition inside the control plane, not a round trip the user agent sees: the adapter calls the login, and on an absent-link refusal from a connection that admits provisioning it creates the principal and calls the login once more. It is taken once, never in a loop, and a second refusal is the login's answer.

One case it deliberately does not cover: an external subject whose link was explicitly unlinked is **not** re-provisioned. Provisioning there would mint a new principal for a revoked subject and defeat the unlinking, so that login stays refused.

## The standards, and what Mandate does with each

| Standard | What is implemented |
|---|---|
| RFC 6749 — OAuth 2.0 | The authorization code grant, and only it. `GET /oauth/authorize` answers `302` with `code` and the exact `state` received; `POST /oauth/token` answers the credential. Every refusal is an RFC 6749 error object of exactly two members, `error` and `error_description`; no description carries a byte the caller sent. |
| RFC 7636 — PKCE | Required, `S256` only. `mandate.core.PkceMethod` declares one variant, the authorization decoder refuses any other `code_challenge_method`, and each registered client states its `pkce_method`. A verifier that does not match the challenge is refused `invalid_grant`. |
| RFC 8414 — Authorization server metadata | `GET /.well-known/oauth-authorization-server` publishes nine members. Every endpoint URL is the configured `issuer` joined with a path read from the same route table the listener dispatches, so the document cannot advertise a path nothing serves. A member naming an endpoint this deployment does not serve — `revocation_endpoint`, `registration_endpoint`, `device_authorization_endpoint` — is absent rather than empty. |
| RFC 7662 — Introspection | `POST /oauth/introspect`, taking `token` and optional `token_type_hint`, and requiring the calling resource server's own credential as a bearer token. Answers `active`, and where the credential resolves, `credential_id`, `aud` and `sub`. A refusal about the *caller* is `401 invalid_client`; anything about the presented token is `200 {"active": false}`. |
| RFC 7517 — JWKS | `GET /oauth/jwks` publishes the key set the `--key` documents configure. The member set is closed: `kty`, `kid`, `use`, `alg`, plus `n`, `e`, `crv`, `x`, `y`. RFC 7517 section 9.2's private members are refused at construction, as is a repeated `kid` anywhere in the set. |
| OpenID Connect Discovery | Consumed, not published. To find a connection's key set, Mandate fetches `{issuer}/.well-known/openid-configuration` and reads `jwks_uri`; the document is read once per issuer and held. Mandate publishes **no** `/.well-known/openid-configuration` of its own — no OpenID Connect command is declared, and the route table has no such path. Mandate is not an OpenID Provider. |

Three further standards are named in this repository's design sources and are **not** implemented on this road. They appear in [the combined architecture](https://github.com/beyond10x/mandate/blob/main/docs/architecture/combined.md) and the preserved design snapshots, and in no crate:

| Standard | Status |
|---|---|
| RFC 8693 — Token Exchange | Not implemented. No exchange grant is admitted at the token endpoint; the only `grant_type` is `authorization_code`. |
| RFC 8707 — Resource Indicators | Not implemented. The authorization request names its target with a `target` parameter carrying a registered resource-server id, which is Mandate's own registration and not RFC 8707's `resource`. |
| RFC 9700 — OAuth 2.0 Security BCP | Named as the intended baseline. No conformance to it is claimed or measured here. |

Token revocation is likewise not on this road: there is no `/oauth/revoke`.

## The endpoints

Six routes. A path not in this table is a path nothing serves — including the generated `/<domain>/commands/<Command>` projections, which are refused like any other unknown path.

| Method | Path | Takes | Answers |
|---|---|---|---|
| `POST` | `/v1/federation/login` | `application/json`: `connection_id`, `proof` (the IdP's JWT, base64) | `200` with `session_id`, `principal_id`, `organization_id`, `epochs`, `expires_at`, `session_proof` |
| `GET` | `/oauth/authorize` | Query: `response_type=code`, `client_id`, `redirect_uri`, `code_challenge`, `code_challenge_method=S256`, `state`, `nonce`, `target`, `scope`. Header: `Authorization: Bearer <session_proof>` | `302` with `Location: <redirect_uri>?code=…&state=…` |
| `POST` | `/oauth/token` | `application/x-www-form-urlencoded`: `grant_type=authorization_code`, `client_id`, `code`, `code_verifier`, `redirect_uri` | `200` with `access_token`, `token_type: "Bearer"`, `credential_id` |
| `POST` | `/oauth/introspect` | `application/x-www-form-urlencoded`: `token`, `token_type_hint`. Header: `Authorization: Bearer <caller's own credential>` | `200` with `active`, and where it resolves `credential_id`, `aud`, `sub` |
| `GET` | `/.well-known/oauth-authorization-server` | nothing | `200` with the RFC 8414 document |
| `GET` | `/oauth/jwks` | nothing | `200` with the RFC 7517 key set |

`expires_in` is absent from the token response: it is RECOMMENDED rather than required by RFC 6749 section 5.1, the contract's response does not declare it, and it is not derived from a clock the response does not carry. Introspection answers the credential's expiry instead.

Responses carrying credentials are sent `no-store`.

## Configuration and deployment

```
mandate-control-plane serve --listen <addr> --issuer <url>
    [--code-lifetime <ISO 8601 duration>] [--session-lifetime <ISO 8601 duration>]
    [--connection <path>]... [--key <path>]... [--client <path>]... [--resource-server <path>]...
```

| Flag | Meaning |
|---|---|
| `--listen` | The socket address to bind. |
| `--issuer` | The issuer identifier this deployment publishes its metadata under, and the base every advertised endpoint URL is built from. |
| `--code-lifetime` | The longest life of an authorization code. Default `PT5M`. |
| `--session-lifetime` | The longest life of a federated session. Default `PT8H`. |
| `--connection` | A federation connection. Repeatable. |
| `--key` | A public JWK the key set publishes. Repeatable. |
| `--client` | A registered OAuth public client. Repeatable. |
| `--resource-server` | A registered resource server. Repeatable. |

Each document is JSON, one per file, and unknown members are refused. A document that configures no deployment exits **2** before the socket is bound, naming the file; a listener that cannot bind exits **1**.

### `--connection`

| Member | Required | Meaning |
|---|---|---|
| `connection_id` | no | Stated, or allocated and printed. |
| `organization` | yes | The organization this connection is bound to. |
| `issuer` | yes | The issuer a proof's `iss` must equal. Immutable: changing it means a new connection. |
| `client_id` | yes | The client identifier your IdP issued Mandate, which a proof's `aud` must name. |
| `algorithm` | no | The signing algorithm this connection's proofs are verified under. **Absent means verification is unconfigured and every login through this connection is refused** — there is no default. `ES256` and `RS256` are the admitted names. |
| `jwks_hosts` | no | Hosts, beside the issuer's own origin, that this connection's key set may be fetched from. An entry is `host` or `host:port`. |
| `tenant_resolution` | yes | How the organization is resolved. `configured_organization` is required; `verified_claim_name` and `verified_claim_value` optionally bind the rule to a validated claim. |
| `jit_provisioning` | yes | Whether a first login with no link may create the principal. Stated, never defaulted. |
| `link` | no | A pre-existing link: `principal_id`, `subject`, `linked_at`, and optionally `external_principal_id`. |

```json
{
  "connection_id": "3f1c…",
  "organization": "0a0a…",
  "issuer": "https://accounts.google.com",
  "client_id": "1234567890-abc.apps.googleusercontent.com",
  "algorithm": "RS256",
  "jwks_hosts": ["www.googleapis.com"],
  "tenant_resolution": { "configured_organization": "0a0a…" },
  "jit_provisioning": true
}
```

`jwks_hosts` is what lets an issuer publish its key set on a second host, as Google and Okta do: Google's discovery document is served by `accounts.google.com` and names a key set on `www.googleapis.com`. With no entry, the issuer's own origin is admitted and nothing else — the discovery document is served by the issuer and is not permitted to introduce a destination the deployment never named. An entry is admitted only over `https`, and never for a literal address or the loopback interface.

### `--key`

One public JWK, published verbatim in the key set. Private members are refused, and two documents naming one `kid` are refused together.

```json
{ "kty": "EC", "kid": "login-key-1", "use": "sig", "alg": "ES256",
  "crv": "P-256", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0" }
```

This composition holds no signer. The keys are published for readers; the credential the token endpoint issues under a `Reference` profile is minted from the host CSPRNG and is not a JWT signed with a published key.

### `--client`

```json
{ "client_id": "…", "organization": "0a0a…", "public": true,
  "redirect_uris": ["https://client.example/callback"], "pkce_method": "S256" }
```

`public` is stated, never defaulted. `redirect_uris` are compared byte for byte: a URI written with a trailing slash the client does not send is a URI the client has not registered.

### `--resource-server`

```json
{ "resource_server_id": "…", "organization": "0a0a…",
  "audience": "https://api.example",
  "profile": { "name": "reference", "kind": "Reference", "revocation": "ImmediateOnline",
               "max_ttl": "PT1H", "positive_cache_ttl": "PT30S",
               "requires_online_authorization": true },
  "allowed_exchange_sources": [] }
```

`allowed_exchange_sources` is stated rather than defaulted — every member widens what may be exchanged into this target — and empty is the ordinary value.

The process prints the connection, client and resource-server identities to stdout before the listener binds, because those are what the three selecting routes are called with.

### Operational truths

- **Nothing is durable.** The folds start empty and are seeded per process from the flags. A restart forgets every provisioned link and every issued session and credential. Event-log-backed persistence is the next milestone.
- **There is no HTTP route that registers a connection.** The flags are the only way in. Registration, linking and mapping routes are later work.
- **This road has never been driven over `https`.** There is no TLS listener in the repository; the end-to-end cases run on loopback `http`, which `UreqJwks::admits` permits for loopback hosts only. Outbound, `admits` requires `https` for any JWKS host that is not the issuer's own origin. Terminate TLS in front of this listener.
- **The listener answers one connection at a time**, with no thread and no async runtime behind it. One client's request bounds every other client's wait.
- A connection admitting just-in-time provisioning trusts the IdP to decide who gets an account in that organization. That is the point of the flag, and the reason it must be stated explicitly.

## What each party delivers

| Party | Provides | Must configure | Can rely on |
|---|---|---|---|
| Customer's IdP | Signed proofs (JWT), an OpenID Connect discovery document, and a reachable JWK Set | A client registration for Mandate, whose identifier appears in each proof's `aud` | Being the only issuer its connection accepts; its `iss` and `aud` are never taken from a request |
| Customer's administrator | The organization the connection is bound to and the tenant rule that selects it | Whether the connection admits just-in-time provisioning; any pre-existing links | Zero or ambiguous tenant matches deny rather than resolve; email equality never links an account |
| Relying application | A public OAuth client | Its registered redirection URIs and `S256` PKCE | Its `state` returned exactly as sent; its code bound to its own client, redirection URI and verifier |
| Resource server | Its registration, audience and credential profile | Its audience, and its own credential for calling introspection | Credentials bound to its audience; introspection answering `active` without it ever seeing the customer's IdP |
| Mandate operator | The running process and its metadata | Every document above, TLS termination, and the process lifetime that bounds all state | A configuration it cannot serve being refused before the socket, not at every login |

A resource server trusts the Mandate credential and never the customer's IdP. That is the boundary the whole road exists to draw.

## What is proven, and what is not

[`services/control-plane/tests/end_to_end.rs`](https://github.com/beyond10x/mandate/blob/main/services/control-plane/tests/end_to_end.rs) spawns the composition binary as a child process and drives all six routes against it over a real socket, with a loopback issuer that really signs the proof with a P-256 key generated when the case runs. The child fetches the discovery document and the key set off that issuer and verifies a signature under a key it fetched. No key is committed.

Fifteen cases: three that complete a login, one that decides the JWKS host wiring in-process, and eleven refusals — each refusal asserted by its whole response body rather than by its status alone.

| Refused | Answer |
|---|---|
| A `connection_id` nothing seeded | `400 access_denied` |
| A proof whose `iss` is not the connection's | `400 access_denied` |
| A proof whose `kid` the published set does not hold | `400 access_denied` |
| A proof signed by a key outside the published set | `400 access_denied` |
| A proof whose `aud` is not the connection's client | `400 invalid_scope` |
| A code verifier that does not match the challenge | `400 invalid_grant` |
| A connection configured for no algorithm | `400 access_denied` |
| A first login a connection does not admit provisioning for | `400 access_denied` |
| A split issuer's key set on a host no document lists | `400 access_denied` |
| A split issuer's key set on loopback, even when listed | `400 access_denied` |
| An ambiguous tenant resolution | exit `2`, before the socket |

The accepted cases cover the full four-step road, a first login that provisioning opens, a connection document naming `jwks_hosts`, and that those hosts reach the verifier.

What this does **not** establish:

- **No TLS.** Every case is loopback `http`. Nothing here measures this road behind TLS.
- **No persistence.** Every case configures a fresh process from flags. Nothing here measures a restart, a shared store, or concurrent writers.
- **No real identity provider.** The issuer is a loopback listener standing in for one. Nothing here measures Google, Okta or Entra, their key rotation, or their discovery documents.
- **No successful cross-host JWKS fetch.** That a listed second host reaches the verifier is decided in-process; a fetch from one has never been driven end to end, because it requires `https` that a loopback case cannot present.
- **One process, one connection at a time.** Nothing here measures load, concurrency or a revocation race.

The [architecture page](architecture.md) has the boundaries this road sits in, and the [contract reference](contracts.md) has the declared model behind it.
