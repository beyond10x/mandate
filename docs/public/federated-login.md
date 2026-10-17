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
| RFC 6749 — OAuth 2.0 | The authorization code grant, and RFC 8693 token exchange at the same endpoint. `GET /oauth/authorize` answers `302` with `code` and the exact `state` received; `POST /oauth/token` answers the credential. A confidential client authenticates there by `client_secret_basic` or `client_secret_post` (one method per request), a public client by neither; a missing or wrong secret, a secret from a public client, or both methods at once answer `401 invalid_client` with `WWW-Authenticate: Basic`. Every refusal is an RFC 6749 error object of exactly two members, `error` and `error_description`; no description carries a byte the caller sent. |
| RFC 7636 — PKCE | Required, `S256` only. `mandate.core.PkceMethod` declares one variant, the authorization decoder refuses any other `code_challenge_method`, and each registered client states its `pkce_method`. A verifier that does not match the challenge is refused `invalid_grant`. |
| RFC 8414 — Authorization server metadata | `GET /.well-known/oauth-authorization-server` publishes nine members. Every endpoint URL is the configured `issuer` joined with a path read from the same route table the listener dispatches, so the document cannot advertise a path nothing serves. A member naming an endpoint this deployment does not serve — `revocation_endpoint`, `registration_endpoint`, `device_authorization_endpoint` — is absent rather than empty. |
| RFC 7662 — Introspection | `POST /oauth/introspect`, taking `token` and optional `token_type_hint`, and requiring the calling resource server's own credential as a bearer token. Answers `active`, and where the credential resolves, `credential_id`, `aud` and `sub`. A refusal about the *caller* is `401 invalid_client`; anything about the presented token is `200 {"active": false}`. |
| RFC 7517 — JWKS | `GET /oauth/jwks` publishes the public half of the signing keys `--signing-key` mounts, each under the identity of its `SigningKey` record as `kid`, and only while that record admits verification: a revoked key leaves the set at once, and a key rotated out stays published for the overlap. The member set is closed: `kty`, `kid`, `use`, `alg`, plus `n`, `e`, `crv`, `x`, `y`. RFC 7517 section 9.2's private members are refused at construction, as is a repeated `kid` anywhere in the set. |
| OpenID Connect Discovery 1.0 | Published and consumed. `GET /.well-known/openid-configuration` publishes the OpenID Provider configuration: the RFC 8414 document's nine members with the same values, built by the same builder from the same route table, plus `subject_types_supported` (`public`), `id_token_signing_alg_values_supported` (`RS256`, then `ES256`: RS256 is every client's default and ES256 a client's registered `id_token_signed_response_alg`), `scopes_supported` and `claims_supported`. `userinfo_endpoint` and `end_session_endpoint` are absent because nothing serves them. To find a connection's key set, Mandate fetches that connection's `{issuer}/.well-known/openid-configuration` and reads `jwks_uri`; the document is read once per issuer and held. |

Three further standards are named in this repository's design sources, in [the combined architecture](https://github.com/beyond10x/mandate/blob/main/docs/architecture/combined.md) and the preserved design snapshots. Two are implemented in part, and one is not:

| Standard | Status |
|---|---|
| RFC 8693 — Token Exchange | Subject-only. `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` exchanges a Mandate access credential for one issued to another registered resource server, provided that server lists the source credential's resource server in `allowed_exchange_sources`. The issued credential keeps the subject and organization, its scope stays inside the source's, and its expiry is no later than the source's. An `actor_token`, or a source credential that names an actor or a delegation, is refused. A refusal about the target answers `invalid_target`, other refusals answer the code the clause table assigns (mostly `invalid_grant`), and each refusal the handler decides is recorded in memory as `TokenExchangeDenied`. |
| RFC 8707 — Resource Indicators | Partial. The exchange grant names its target by `audience` or by `resource`; `resource=urn:uuid:<resource_server_id>` names a registration by identity. The authorization request still names its target with Mandate's own `target` parameter, not RFC 8707's `resource`. |
| RFC 9700 — OAuth 2.0 Security BCP | Named as the intended baseline. No conformance to it is claimed or measured here. |

Token revocation is likewise not on this road: there is no `/oauth/revoke`.

## The endpoints

Twelve routes. A path not in this table is a path nothing serves — including the generated `/<domain>/commands/<Command>` projections, which are refused like any other unknown path.

| Method | Path | Takes | Answers |
|---|---|---|---|
| `POST` | `/v1/federation/login` | `application/json`: `connection_id`, `proof` (the IdP's JWT, base64) | `200` with `session_id`, `principal_id`, `organization_id`, `epochs`, `expires_at`, `session_proof` |
| `GET` | `/v1/federation/authorize` | Query: `connection_id`, optional `app_state` | `302` to the IdP's authorization endpoint, with a `__Host-` binding cookie |
| `GET` | `/v1/federation/callback` | The IdP's `code` (or `error`), `state` and optional `iss`; the binding cookie | `302` to the connection's `return_uri` with a single-use `handoff`, or the handoff as JSON when no `return_uri` is configured |
| `POST` | `/v1/federation/handoff` | `application/json`: `handoff`, optional `app_state` | `200` with the same members as the login answer, including `session_proof`; a handoff redeems once |
| `GET` | `/oauth/authorize` | Query: `response_type=code`, `client_id`, `redirect_uri`, `code_challenge`, `code_challenge_method=S256`, `state`, `nonce`, `target`, `scope`. Header: `Authorization: Bearer <session_proof>` | `302` with `Location: <redirect_uri>?code=…&state=…` |
| `POST` | `/oauth/token` | `application/x-www-form-urlencoded`: `grant_type=authorization_code`, `client_id`, `code`, `code_verifier`, `redirect_uri`, and for a confidential client `client_secret` or instead `Authorization: Basic`; or the token-exchange grant: `subject_token`, `subject_token_type`, `audience` or `resource`, `scope`, optional `requested_token_type` | `200` with `access_token`, `token_type: "Bearer"`, `credential_id`, `expires_in`; for exchange `access_token`, `issued_token_type`, `token_type`, `expires_in` |
| `POST` | `/oauth/introspect` | `application/x-www-form-urlencoded`: `token`, `token_type_hint`. Header: `Authorization: Bearer <caller's own credential>` | `200` with `active`, and where it resolves `credential_id`, `aud`, `sub` |
| `GET` | `/.well-known/oauth-authorization-server` | nothing | `200` with the RFC 8414 document |
| `GET` | `/.well-known/openid-configuration` | nothing | `200` with the OpenID Connect Discovery 1.0 document |
| `GET` | `/oauth/jwks` | nothing | `200` with the RFC 7517 key set |
| `GET` | `/healthz/live` | nothing | `200` with `{"status":"ok"}` while the process answers |
| `GET` | `/healthz/ready` | nothing | `200` once a signing key is admitted, `503` until then |

`expires_in` in the authorization-code grant's response is the number of seconds from the moment the request was served to the credential's expiry (RFC 6749 section 5.1): the earlier of the resource server profile's `max_ttl` and the code's own expiry. A gateway can set its session cookie's lifetime from it. Introspection does not answer the expiry today; it answers `active`, `credential_id`, `aud` and `sub`. The token-exchange response carries `expires_in` too, as RFC 8693 section 2.2.1 describes.

Responses carrying credentials are sent `no-store`.

## Configuration and deployment

```text
mandate-control-plane serve --listen <addr> --issuer <url>
    [--code-lifetime <ISO 8601 duration>] [--session-lifetime <ISO 8601 duration>]
    [--connection <path>]... [--signing-key <NAME=PATH>]... [--client <path>]... [--resource-server <path>]...
    [--client-secret-file <NAME=PATH>]...
```

| Flag | Meaning |
|---|---|
| `--listen` | The socket address to bind. |
| `--issuer` | The issuer identifier this deployment publishes its metadata under, and the base every advertised endpoint URL is built from. |
| `--code-lifetime` | The longest life of an authorization code. Default `PT5M`. |
| `--session-lifetime` | The longest life of a federated session. Default `PT8H`. |
| `--connection` | A federation connection. Repeatable. |
| `--client` | A registered OAuth client, confidential or public. Repeatable. |
| `--signing-key` | `NAME=PATH`: a PEM private key the deployment signs with, registered as a signing-key record. The flag carries where the key is, never the key. Repeatable; a name given twice exits **2**. |
| `--resource-server` | A registered resource server. Repeatable. |
| `--client-secret-file` | `NAME=PATH`: a file holding a secret, named by a connection's `relying_party.client_secret` (the IdP client secret) or by a client's `secret_ref` (that client's own secret). The flag carries where the secret is, never the secret. Repeatable; a name given twice exits **2**. |

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
| `tenant_resolution` | yes | How the organization is resolved. `configured_organization` is required; `verified_claim_name` and `verified_claim_values` optionally bind the rule to a validated claim, matching when the claim carries any one of the listed values. |
| `jit_provisioning` | yes | Whether a first login with no link may create the principal. Stated, never defaulted. |
| `link` | no | A pre-existing link: `principal_id`, `subject`, `linked_at`, and optionally `external_principal_id`. |
| `relying_party` | no | Enables the browser code flow through `/v1/federation/authorize` and `/v1/federation/callback`: `redirect_uri` (this deployment's `/v1/federation/callback` as the browser reaches it), `client_secret` (a `--client-secret-file` name, never the secret), optional `return_uri` (where the callback sends the browser with the handoff), and optional `endpoint_hosts` (hosts beside the issuer's origin the IdP's authorization and token endpoints may be on). A relying-party connection admits no proof at `/v1/federation/login`. |

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

### `--signing-key`

`NAME=PATH` names one PEM private key: `PRIVATE KEY` (PKCS#8) for ES256 or RS256, or `RSA PRIVATE KEY` for RS256. The algorithm is read from the material. The file is read before the socket is bound; a file that cannot be read, or that is not exactly one admitted private key, exits **2** naming the file and never a byte of its content.

```text
mandate-control-plane serve … --signing-key current=/run/secrets/mandate/signing-current.pem
```

Each mounted key is registered as a `SigningKey` record, in the order given, with `NAME` as its key reference and a window opening at startup. The record's identity is the `kid` the key signs and is published under, and it is printed. The signer follows the records: the newest key whose record admits signing is the one it signs with, a key it rotated away from stays in the key set for the overlap, and a revoked key leaves the key set at once and is never installed again. `GET /healthz/ready` answers `200` only while the signer holds a key its record admits for signing.

The credential the token endpoint issues under a `Reference` profile is still minted from the host CSPRNG and is not a JWT.

In a `--config-dir`, a `signing-keys/` directory holds one PEM file per key, and the file name is `NAME`.

### `--client`

Adding an app is one client document and one secret file:

```json
{ "client_id": "…", "organization": "0a0a…", "name": "App A",
  "client_type": "confidential", "secret_ref": "app-a",
  "redirect_uris": ["https://app-a.example/oauth2/callback"], "pkce_method": "S256",
  "post_logout_redirect_uris": ["https://app-a.example/"] }
```

```text
openssl rand -base64 32 > app-a.secret
mandate-control-plane serve … --client app-a.json --client-secret-file app-a=app-a.secret
```

| Member | Required | Meaning |
|---|---|---|
| `client_id` | no | Stated, or allocated and printed. |
| `organization` | yes | The organization the client is bound to: the one the connection resolves to. |
| `name` | no | A label printed beside the client's identity. It is not recorded. |
| `client_type` | yes | `confidential` or `public`. Stated, never defaulted. |
| `secret_ref` | confidential only | A `--client-secret-file` name, or a list of two during a rotation. A public client states none. |
| `redirect_uris` | yes | Compared byte for byte: a URI written with a trailing slash the client does not send is a URI the client has not registered. A URI with a fragment exits **2**. |
| `pkce_method` | yes | `S256`, the one method the contract declares. |
| `pkce_required` | no | Default `true`. Only a confidential client may state `false`. |
| `trusted_peers` | no | Client identities of the same organization that may obtain tokens for this client. Each must be a client this process seeds. |
| `post_logout_redirect_uris` | no | Where the client may send the browser after logout, compared byte for byte. A URI with a fragment exits **2**. |

The secret file is read once at start. The process derives a keyed verifier from it (HMAC-SHA-256 under a key drawn from the host CSPRNG at start) and records only the verifier: the secret appears in no output, no event and no record. A reference no `--client-secret-file` resolves, or a secret under 128 bits of estimated entropy, exits **2** naming the client document; `openssl rand -base64 32` clears the floor. To rotate a secret, list both names in `secret_ref`, restart, move the app to the new secret, then drop the old name and restart again.

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
| Relying application | An OAuth client, confidential with a secret file or public | Its registered redirection URIs, its secret file when confidential, and `S256` PKCE unless a confidential client states `pkce_required: false` | Its `state` returned exactly as sent; its code bound to its own client, redirection URI and verifier |
| Resource server | Its registration, audience and credential profile | Its audience, and its own credential for calling introspection | Credentials bound to its audience; introspection answering `active` without it ever seeing the customer's IdP |
| Mandate operator | The running process and its metadata | Every document above, TLS termination, and the process lifetime that bounds all state | A configuration it cannot serve being refused before the socket, not at every login |

A resource server trusts the Mandate credential and never the customer's IdP. That is the boundary the whole road exists to draw.

## What is proven, and what is not

[`services/control-plane/tests/end_to_end.rs`](https://github.com/beyond10x/mandate/blob/main/services/control-plane/tests/end_to_end.rs) spawns the composition binary as a child process and drives the login road's six routes against it over a real socket, with a loopback issuer that really signs the proof with a P-256 key generated when the case runs. The child fetches the discovery document and the key set off that issuer and verifies a signature under a key it fetched. No key is committed.

Seventeen road cases: three that complete a login, two that check the listener's bound address, one that decides the JWKS host wiring in-process, and eleven refusals — each refusal asserted by its whole response body rather than by its status alone. The same file holds seven further cases about the test lane's own hygiene. The relying-party flow and token exchange are proven in `relying_party.rs` and `exchange.rs` in the same directory.

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
