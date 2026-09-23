# The adapter contract

What a trusted adapter establishes before a command is reached, what it refuses, and what
authority it never derives. `runtime-decisions.md:118` asks for this contract "for every one of
the [61] commands ... A sample is not evidence; the table is the enumeration."

**The normative artefact is `crates/mandate-server/src/obligations.rs`**, a typed registry with
one entry per `operationId` of `generated/openapi/*.yaml`. This document is derived from it.
That order is deliberate: `crates/mandate-server/tests/obligations.rs` decides the registry
against the generated projection and against `command-obligations.md`, and a document cannot be
decided against anything. Where the two disagree, the registry is right and this file is stale.

## Scope, and what it does not cover

`story:login-adapters` delivers the four commands the customer login road serves. The other 57
commands are registered here as reached only through their generated
`POST /<domain>/commands/<Command>` projection: this library declares no product route for them,
decodes nothing for them, and establishes none of their preconditions. Their product routes and
the per-clause enumeration that comes with those routes belong to `story:protocol-adapters`.

Nothing here clears `decision-blocker:guards`. That blocker's evidence is five items; this
library produces three of them (the written contract, the negative case per deny clause of the
commands it serves, and the route-disjointness proof), `story:product-listener` produces the
fourth over HTTP, and the fifth — a `TokenExchangeDenied` durable audit record — is behind
`decision-blocker:audit-routing` and outside `mandate-server`'s dependency ceiling.

## The product route table

`crates/mandate-server/src/routes.rs`. Six entries, and a listener that serves this table serves
nothing else.

| Method | Path | Binds | Source of the path |
|---|---|---|---|
| `POST` | `/v1/federation/login` | `mandate.federation.AuthenticateFederation` | A control-plane product route: it mints a session and issues no credential. `../sources/original-design.md:1784-1796` puts control-plane resources under `/v1/`; `:1871-1875` puts federation there. |
| `GET` | `/oauth/authorize` | `mandate.federation.AuthorizePublicClient` | `../sources/original-design.md:1857`, verbatim. RFC 6749 section 3.1 requires `GET`. |
| `POST` | `/oauth/token` | `mandate.credential.RedeemAuthorizationCode` | `../sources/original-design.md:1858`, verbatim. RFC 6749 section 3.2 requires `POST`. |
| `POST` | `/oauth/introspect` | `mandate.credential.IntrospectCredential` | `../sources/original-design.md:1860`, verbatim. RFC 7662 section 2 requires `POST`. |
| `GET` | `/.well-known/oauth-authorization-server` | the RFC 8414 metadata document | `../sources/original-design.md:1855`, verbatim; RFC 8414 section 3 fixes it at the host root. |
| `GET` | `/oauth/jwks` | the JWK Set document | `../sources/original-design.md:1862`, verbatim. |

`../public/contracts.md:29`: generated command routes "do not implement product routes". The
proof is `crates/mandate-server/tests/routes.rs`, which reads the 61 generated paths from
`generated/openapi/*.yaml` at test time and decides that the intersection with this table is
empty — and, more than that, that no path here has the shape
`/<domain>/commands/<Command>` at all, which holds for the 62nd generated route as well as the
61 that exist.

The paths `original-design.md:1855-1862` lists that are deliberately absent:
`/.well-known/openid-configuration` (no OpenID Connect command is declared), `/oauth/revoke`
(`mandate.credential.RevokeAccessCredential` is off this road), and the `/v1/...` control-plane
resources of `:1784-1796`.

## What every adapter on this road does, and does not

The rules below hold for all four decoders (`crates/mandate-server/src/decode.rs`).

1. **The admitted parameter set is closed.** Each endpoint declares its keys —
   `decode::LOGIN_MEMBERS`, `decode::AUTHORIZE_PARAMETERS`, `decode::TOKEN_PARAMETERS`,
   `decode::INTROSPECT_PARAMETERS` — and anything else is refused. A caller cannot add an
   `organization_id`, an `audience`, a `subject` or an `actor` to a request and have it ignored;
   the request is refused. `combined.md:51` is the rule; a closed set is how it is kept.
2. **No selector becomes authority.** No road command declares a `mandate.core.VerifiedContext`
   input, and none is built in this library. Every organization, audience, principal, session
   and code the handlers use is resolved from validated credential evidence or from a record,
   never from a decoded field.
3. **One declared parameter is never on the wire.** `RedeemAuthorizationCode.code_id` — the
   contract declares it, and `credential.yaml`'s header says it "is resolved by the trusted
   adapter from proof; it is not a public OAuth parameter or authority selector". The decoder
   refuses a caller-presented `code_id` and leaves the field absent. **The resolution itself is
   the composition's, not this library's**: `services/control-plane` resolves the `code_id` from
   the presented `code` through a by-verifier read on the STS's authorization-code store, then
   calls `RedeemAuthorizationCode` with the identifier the server resolved. That read does not
   exist in this crate's dependency ceiling and cannot; `story:product-listener` adds it. Until
   then, `code_id: None` is the whole of what a decoder can honestly produce, and it is what the
   wire form supports.
4. **A repeat is refused, not resolved.** A parameter presented twice and a header presented
   twice are both refusals. Every rule for picking one of two values is a rule an attacker can
   aim at a reader that picked the other. Every decoder reads its headers through
   `Request::single_header`, **including the two that read no `Authorization` at all**, so a
   duplicate is refused on all four and not only where one is consumed.
5. **A credential presented where no input declares one is refused.** `AuthenticateFederation`
   and `RedeemAuthorizationCode` declare no caller credential, so an `Authorization` header at
   `/v1/federation/login` or `/oauth/token` is caller-supplied authority the contract has
   nowhere to put. It is refused in either of RFC 6749 section 2.3.1's presentations — the
   `Basic` header and the body parameter — and answered `invalid_request`, because
   `invalid_client` is the RFC's "client authentication failed" and a road that authenticates
   no client cannot fail to.
6. **An empty credential is not a credential.** `""` is inside the declared base64 form and
   decodes to zero bytes, so every credential field the wire carries — the login `proof`, the
   token endpoint's `code`, the introspection `token`, and the bearer credential of both
   header-bearing routes — goes through one helper that refuses the empty string and any form
   decoding to zero bytes. Otherwise the credential nobody holds reaches a handler as a
   presented credential.
7. **Every request is measured, and the component a route does not read is refused.** One
   helper, `decode::entry`, runs first on all four decoders and does both. The byte ceiling
   `decode::MAX_BODY_BYTES` is measured first, on the body **and** the query string of **all
   four**, before anything is parsed. Then the component that route reads nothing out of is
   refused whole: a body presented to the authorization endpoint, which reads only the query,
   is `BodyNotAdmitted`, and a query string presented to the token, introspection or federation
   login route, which read only the body, is `QueryNotAdmitted`. It is not ignored and it is
   not merely bounded — rule 1 says the request is refused, and a query string a decoder never
   reads is in every access log, referrer and proxy trace the request passes, so a request
   admitted with one is a different request to a reader than to the handler. The order is the
   one stated: an oversized query on a body route is still `BodyTooLarge`, because a request
   nobody will read is refused by its size before any component of it is looked at.
8. **Free text is bounded and control-free.** The four values the contract leaves unconstrained
   — `state`, `nonce`, `redirect_uri` and `scope` — are each at most `decode::MAX_TEXT_BYTES`
   (512) and carry no character of Unicode general category `Cc`: the C0 controls, DEL, **and
   the C1 block U+0080–U+009F**. That is `char::is_control`'s own class, and the C1 half is in
   it for the reason the rest is — U+0085 NEXT LINE is a line terminator to some readers, so a
   value carrying it splits a line in exactly the reader the rule exists for. U+2028 LINE
   SEPARATOR is outside `Cc` and is admitted. They are the four a listener puts back on the
   wire:
   RFC 6749 section 4.1.2.1 has the authorization endpoint redirect to the presented
   `redirect_uri` carrying the presented `state`, and requires the state be "the exact value
   received from the client". *Exact* and *sanitized* cannot both hold, so a value carrying CR,
   LF or any other `Cc` character is **refused** here rather than mangled downstream.
9. **A refusal carries no caller text.** Every refusal value is a unit and every description is
   a fixed string, so nothing a caller sent can reach the error body rendered back to it.
10. **Shape is decided, correctness is not.** The S256 challenge and the RFC 7636 code verifier
    are checked for form only. Whether a verifier redeems a challenge, whether a client is
    registered, whether a session is live — each is a handler's, in `crates/mandate-federation`
    and `services/sts`, which this crate's dependency ceiling cannot reach.

## The four road commands

### `mandate.federation.AuthenticateFederation`

| | |
|---|---|
| Wire form | `POST /v1/federation/login`, `application/json`, a flat object of two string members |
| Decoded | `connection_id` (`mandate.core.FederationConnectionId`), `proof` (`mandate.core.CredentialProof`, base64) |
| Decoder | `decode::authenticate_federation` |
| Refused | another method or media type; an oversized body or query; **a presented query string**; a presented `Authorization` header; a body that is not a flat JSON object of strings; any member outside the declared two; a repeated member or header; a missing member; an empty or zero-byte `proof`; a value outside its declared lexical form |
| Never derived | the organization, the issuer, the principal, the link. All three come from the validated connection and the validated proof (`federation.yaml:1`), and none has a wire form here. |

### `mandate.federation.AuthorizePublicClient`

| | |
|---|---|
| Wire form | `GET /oauth/authorize`, parameters in the query component (RFC 6749 section 3.1); the session proof as a bearer credential (RFC 6750 section 2.1) |
| Decoded | `client_id`, `redirect_uri`, `challenge` (from `code_challenge`), `method` (from `code_challenge_method`), `state`, `nonce`, `session_proof` (from `Authorization`), `target`, `requested_scope` (from `scope`) |
| Decoder | `decode::authorize_public_client` |
| Refused | another method; an oversized query or body; a presented body; an undeclared, repeated or missing parameter; a repeated header; a `state`, `nonce`, `redirect_uri` or `scope` over 512 bytes or carrying a control character; `response_type` other than `code`; `code_challenge_method` other than `S256` (case `pkce-plain`); a challenge outside the S256 shape; an absent, empty or malformed session proof |
| Never derived | the session, the organization, the audience. The session proof is evidence the handler validates; the session identity it resolves to is not a parameter. |

The session proof is carried in a header rather than in the query because a credential in a
query string is a credential in every access log the request passes through. A browser
redirect cannot set that header, so a cookie-borne session adapter is named residue for
`story:protocol-adapters`, which owns the product routes.

### `mandate.credential.RedeemAuthorizationCode`

| | |
|---|---|
| Wire form | `POST /oauth/token`, `application/x-www-form-urlencoded` (RFC 6749 section 4.1.3) |
| Decoded | `client_id`, `code`, `pkce_verifier` (from `code_verifier`), `redirect_uri`; `code_id` absent by construction |
| Decoder | `decode::redeem_authorization_code` |
| Refused | another method or media type; an oversized body or query; **a presented query string**; a presented `Authorization` header in either RFC 6749 section 2.3.1 form; an undeclared, repeated or missing parameter; a repeated header; a caller-presented `code_id`; `grant_type` other than `authorization_code`; an empty or zero-byte `code`; a `redirect_uri` over 512 bytes or carrying a control character; an absent `code_verifier` (case `pkce-missing`); a verifier outside RFC 7636 section 4.1's form |
| Never derived | the code record, the session, the target, the scope, the expiry. The token endpoint admits five parameters and none of them names any of those. |

`client_secret` is not an admitted parameter *and* an `Authorization` header is refused, which
is what makes `token_endpoint_auth_methods_supported: ["none"]` true: RFC 6749 section 2.3.1
declares two presentations of a client secret and names the header the preferred one, so
refusing only the body parameter would have enforced `none` against one of them.

### `mandate.credential.IntrospectCredential`

| | |
|---|---|
| Wire form | `POST /oauth/introspect`, `application/x-www-form-urlencoded` (RFC 7662 section 2.1) |
| Decoded | `caller_proof` (from `Authorization`), `credential_proof` (from the form's `token`) |
| Decoder | `decode::introspect_credential` |
| Refused | another method or media type; an oversized body or query; **a presented query string**; an undeclared, repeated or missing parameter; a repeated header; an absent, empty or malformed caller proof; an absent, empty, zero-byte or malformed presented credential |
| Never derived | the caller's authority, the audience, the organization. `token_type_hint` is admitted because RFC 7662 declares it optional, and it binds to no declared input: it is read and discarded. |

The two proofs are separate inputs in the contract and separate values on the wire, and neither
is read from the other. A caller that holds a credential learns only whether it is usable.

## Which party establishes each declared precondition

One row per phrase of the command's declared `denied` cause, split from its row in
`command-obligations.md` by `obligations::clauses_of`. **Adapter** means the wire form decides
it and the decoder refuses before any handler is reached; **handler** means a deciding handler
establishes it against reads this crate cannot make, and the adapter's obligation is to admit
the request unchanged and pass no selector by which the caller could have established it. Each
row is driven by a case in `crates/mandate-server/tests/obligations.rs` — 25 of them.

### `AuthenticateFederation`

| Declared clause | Established by |
|---|---|
| Connection is disabled/untrusted | handler |
| proof signature/issuer/audience/expiry is invalid | handler |
| tenant resolution has zero or multiple matches | handler |
| principal linking is absent/conflicting | handler |
| any email-domain/unverified-input fallback would be required | adapter — the body admits `connection_id` and `proof`, so there is no unverified input to fall back to |

### `AuthorizePublicClient`

| Declared clause | Established by |
|---|---|
| Session proof is invalid/stale | handler |
| client is not a registered public client | handler |
| the client is disabled | handler |
| exact redirect URI or state/applicable nonce binding fails | handler |
| S256 challenge is absent/invalid | adapter — absent, mis-shaped, or offered under another method |
| target is unregistered/outside tenant | handler |
| STS code issuance/narrowing is refused | handler |

### `RedeemAuthorizationCode`

| Declared clause | Established by |
|---|---|
| Code proof does not match the server-resolved code_id | adapter, in part — "server-resolved" is the adapter's half; the comparison is the STS's |
| code is expired | handler |
| client, redirect URI or S256 verifier mismatches | adapter, in part — the verifier's form; the three mismatches are the STS's |
| the bound client is disabled | handler — and the refusal is answered `invalid_grant`: `binding::bound_client` reaches it through `code::admitted_client`, so it is a clause a redemption raises, and RFC 6749 section 5.2's `invalid_client` is an authentication failure this road has no authentication to have |
| source/session epoch is stale | handler |
| registered target is disabled or outside the verified tenant | handler |
| narrowing/atomic issuance validation fails | handler |

### `IntrospectCredential`

| Declared clause | Established by |
|---|---|
| Caller proof lacks introspection authority for the registered server/tenant or is itself invalid | handler |
| revoked or expired | handler |
| the presented credential proof is malformed | adapter |
| principal/connection/epoch validation fails | handler |
| audience mismatches | handler |
| authoritative online resolution is unavailable | handler |

One reading is recorded rather than smoothed over: the introspection cause reads "... or is
itself invalid, revoked or expired, ...", and the mechanical split makes "revoked or expired" a
clause of its own where the prose means it as the tail of the one before it. The splitter is
kept mechanical — one with an exception list is one that can be taught to miss a clause — and
the prose is a contract observation against `../../systems/mandate/domains/credential.yaml`,
`IntrospectCredential`'s `denied` cause.

## What a refusal looks like on the wire

`crates/mandate-proto/src/oauth.rs`, RFC 6749 section 5.2's JSON body. **The two endpoints
answer from two different code sets, and a refusal is mapped by a different thing at each.**

| | token endpoint (`/oauth/token`, `/oauth/introspect`) | authorization endpoint (`/oauth/authorize`) |
|---|---|---|
| Declared by | RFC 6749 section 5.2 | RFC 6749 section 4.1.2.1 |
| Codes | `invalid_request`, `invalid_client`, `invalid_grant`, `unsupported_grant_type`, `invalid_scope` | `invalid_request`, `unauthorized_client`, `access_denied`, `unsupported_response_type`, `invalid_scope`, `server_error`, `temporarily_unavailable` |
| Mapped from | the clause, `oauth::code_for_clause` | the clause name, then the reason: `oauth::code_for_denial` |

The split is forced, not stylistic. The token endpoint's handlers are `services/sts`, whose
refusals carry `mandate_token::projection::DenialClause`; the authorization endpoint's are
`crates/mandate-federation`, whose refusals carry **that crate's own** `DenialClause` — a
different type, in a crate outside both `mandate-proto`'s and `mandate-server`'s dependency
ceiling. What the two share is `mandate.core.DenialReason`, the contract's only wire field on a
`Denied` error, so that is what the authorization endpoint maps. The composition in
`services/control-plane` picks the mapping by endpoint.

Three refusals at the authorization endpoint are the one exception to *mapped by reason*, and
they are why `unauthorized_client` is in the set above.
`crates/mandate-federation/src/publicclient.rs` refuses a client that is unregistered, disabled
or not public — RFC 6749 section 4.1.2.1's "the client is not authorized to request an
authorization code using this method", verbatim — and all three carry `DenialReason::Denied`,
which by reason alone is `access_denied`: "the resource owner or authorization server denied
the request", which tells a client developer the end user refused. `oauth::code_for_denial`
reads the clause name first for exactly those three (`oauth::UNAUTHORIZED_CLIENT_CLAUSES`) and
falls back to `oauth::code_for_reason` for every other. The names are carried as names because
that crate's `DenialClause` type is outside this crate's dependency ceiling, and
`crates/mandate-proto/tests/oauth.rs` reads `publicclient.rs` so a rename upstream is reported
rather than answered by the fallback. Whether a listener renders such a refusal as a redirect
or as a body is not decided here; that is recorded on `story:product-listener`.

A second exception, from adversary pass 1 on `story:product-listener` (F8), is read the same
way and for the same reason: `oauth::SERVER_ERROR_CLAUSES` names the refusals the **deployment**
caused, and `code_for_denial` answers RFC 6749 section 4.1.2.1's `server_error` for them.
`ExpiryUnbounded` — "the profile's TTL or the request instant does not name a span this
deployment can add" — also carries `DenialReason::Denied`, and `access_denied` told a client
developer the end user had refused something the end user never saw. The token endpoint's
mapping is untouched: section 5.2 declares no `server_error`, so `CLAUSE_CODES` still answers
that clause with `invalid_request` there. The class is closed by a check rather than by the one
correction: `crates/mandate-proto/tests/oauth.rs` follows the calls from
`services/sts/src/code.rs::issue_authorization_code`, the authorization road's own handler, and
requires **every** clause it can raise to be stated as the deployment's own failure, the
client's own standing, or neither — so a clause added upstream is named by that case instead of
falling into the reason mapping. That traversal now follows a call to a free function in the
same module as well as one that crosses modules; the redemption's path crosses a module at
every hop and the authorization road's does not, and four clause names lived behind that
unfollowed hop.

`code_for_reason`'s match is exhaustive and carries no wildcard: `DenialReason` is not
`#[non_exhaustive]`, so a reason added to the contract fails it to compile.
`code_for_clause` cannot have that guarantee — `DenialClause` *is* `#[non_exhaustive]` — and buys
it with a case that reads the variant names from `crates/mandate-token/src/projection.rs` and
requires the table to name every one.

Which code a clause gets follows RFC 6749 section 5.2's own words, and two of them decide cases
that look like taste and are not:

* `invalid_grant` is "invalid, expired, revoked, does not match the redirection URI ... **or was
  issued to another client**", so a code presented by the wrong client is `invalid_grant`, not
  `invalid_client`.
* `invalid_client` is "**client authentication failed**" and `invalid_scope` is "**the requested
  scope** is invalid ...". A redemption on this road authenticates no client (the metadata
  advertises `none`) and sends no `scope` parameter, so **no clause reachable from a redemption
  may answer either**. That is a check, not a convention, and the check **follows the calls**:
  `crates/mandate-proto/tests/oauth.rs` starts at
  `services/sts/src/redemption.rs::redeem_authorization_code`, takes each function's body,
  reads the clauses it names, and walks on through every call into a sibling module of the STS
  crate — a bare name a `use crate::<module>::` import names, or a `<module>::name(` path —
  transitively. The set is therefore the one the calls reach and not the one a pair of file
  names holds: adversary pass 2 found the earlier two-file reader one hop short of
  `binding::bound_client` → `code::admitted_client`, whose four client clauses
  (`ClientUnregistered`, `ClientOutsideOrganization`, `ClientDisabled`, `ClientNotPublic`) were
  never in the set the rule was applied over and all answered `invalid_client`. Pass 1 found
  five clauses on the wrong side of the rule and pass 2 found those four; the rule was right
  both times and the table was not. `invalid_client` now answers only where a caller on this
  road does present a credential — RFC 7662 section 2.1's introspection caller proof.

At the authorization endpoint RFC 6749 section 4.1.2.1 returns an error by redirecting to a
validated redirect URI rather than as a body. This library produces the error value; the
rendering is the listener's, and it cannot redirect to a redirect URI it has not validated.

There is a third answer beside *redirect* and *render the denial*, and it is a class rather
than a case: **a registered redirection URI that can carry no response at all**. RFC 6749
section 4.1.2 adds `code`, `state` and `error` to the *query component* of that URI, and
section 3.1.2 requires a query it already carries to be retained and forbids a fragment
outright — so a URI carrying a fragment (every appended parameter lands inside it, where the
redirection endpoint never sees it), a query that is not an
`application/x-www-form-urlencoded` form, or a query already naming one of those three
parameters is a URI no response can be composed into. The composer in
`services/control-plane/src/serve.rs` parses the registered query before it extends it and
answers all three in place — section 4.1.2.1's "MUST NOT automatically redirect the user-agent
to the invalid redirection URI" — on the success branch and the error branch alike. This is
the **client-registration** class: nothing about the request decides it, `RegisterOAuthClient`
delegates every URI question to a deployment policy hook, and `RedirectUri` is an unvalidated
newtype, so a deployment that would rather refuse the registration than the authorization
enforces the same three rules in that hook. Adversary pass 2 found the class through two of
its members (`…/callback?` composed `?&code=…`, and `…/callback#done` put the code in the
fragment).

## The two documents

`crates/mandate-server/src/metadata.rs` builds the RFC 8414 metadata document and the RFC 7517
JWK Set document and serves neither. Every endpoint in the metadata is read from the route
table at call time, so `original-design.md:1866` — "Endpoint layout can differ, but metadata
MUST accurately advertise it" — is a property rather than a promise.

What is advertised is what is enforced: `code_challenge_methods_supported` is `["S256"]`
because `mandate.core.PkceMethod` declares one variant and the decoder refuses every other
method; `token_endpoint_auth_methods_supported` is `["none"]` because the token endpoint
refuses `client_secret`; `response_types_supported` is the single value the authorization
decoder admits, and `grant_types_supported` is the two grants the token endpoint dispatches on —
`authorization_code` and RFC 8693's `urn:ietf:params:oauth:grant-type:token-exchange`
(`decode::TOKEN_GRANTS`). RFC 8414's optional
`introspection_endpoint_auth_methods_supported` is **absent** for the same reason, read the
other way: the introspection endpoint requires a bearer caller proof (RFC 7662 section 2.1),
and no value in IANA's OAuth Token Endpoint Authentication Methods registry names one — so any
member this deployment could write there would advertise a method it does not enforce, which is
the failure the paragraph above exists to prevent.

The JWK Set carries no key material: this crate holds no signer and no key store, and the
composition in `services/control-plane` fills the list. **Its member set is closed** —
`kty`, `kid`, `use`, `alg` from the typed fields, and `n`, `e`, `crv`, `x`, `y` as
algorithm-specific public parameters. Anything else is refused, including every private member
of RFC 7517 section 9.2 (`d`, `p`, `q`, `dp`, `dq`, `qi`, `k`) and any name colliding with a
declared member. A closed set rather than a denylist of the seven: a JWK member RFC 7517 adds
later is refused until it is admitted, which is the right way round for the document a client
reads a signing key's identity out of. It is enforced in `Jwk::new`, which returns a `Result`,
and there alone: `parameters` is private, so that constructor is the only way a key is built
and the rendering is never handed a name it refused.

The **set** is closed too: `Jwks::new` refuses two keys carrying the same `kid`
(`JwkRefusal::RepeatedKeyId`). RFC 7517 section 4.5's `kid` is what a reader resolves a
signature's key with, so a set naming one twice leaves that resolution undefined — the repeat
is refused rather than resolved, for the reason rule 4 gives for every other repeat on this
road.
