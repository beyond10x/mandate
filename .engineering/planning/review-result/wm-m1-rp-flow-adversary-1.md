---
format: aep.planning-md/1
id: review-result:wm-m1-rp-flow-adversary-1
kind: review-result
status: active
title: Adversary pass 1 on M1 (relying-party-code-flow)
relations:
- reviews: story:relying-party-code-flow
revision: 1
---
unit: story:relying-party-code-flow, working tree at HEAD 70906bc over base 871c11b0, plus one new untracked test file
verdict: red
cases: executed 176→180, red 4
origin: introduced 9, pre-existing 1, undecided 0
wrote-outside-worktree: ~/.cache/claude-tmp/wm/m1/scratch/adv1-suite.log, adv1-suite-nff.log
needs-coordinator: no

Four failing cases, all for the reasons claimed. The most important: an IdP's discovery document can write headers, including Set-Cookie, into Mandate's response.

Cases in services/control-plane/tests/adversary_rp_flow_1.rs (each with its own loopback RS256 test IdP and serve child), all red:
- a_discovered_authorization_endpoint_cannot_write_headers_into_mandates_response — :670, the injected Set-Cookie appears in the 302
- a_callback_without_iss_from_an_idp_that_advertises_it_opens_nothing — :598, a session opens without iss
- an_idp_error_response_naming_the_state_consumes_it — :626, a state a refused callback named was used again
- anonymous_authorize_requests_cannot_lock_every_other_browser_out_of_signing_in — :645, left 400 right 302

Suite: cargo test -p mandate-control-plane --locked --no-fail-fast EXIT=101, 176 passed, 4 failed. clippy --tests clean.

F1 serve.rs:966 (endpoint accepted at crates/mandate-federation/src/idp_token.rs:168) NEEDS-CHANGE introduced blocker: CR LF in the discovered authorization_endpoint is written raw into Location. Reaches: any configured IdP's discovery document (cached, verifier_real.rs:372), triggered by any anonymous authorize.
F2 adapters.rs:3317 CONFIRMED introduced warning: no iss required when the IdP advertises authorization_response_iss_parameter_supported (RFC 9207 section 2.4).
F3 adapters.rs:946 CONFIRMED introduced note: an IdP error response is refused by the decoder (error not accepted, decode.rs:532) before the pending store is touched, so the state survives.
F4 adapters.rs:3256 NEEDS-CHANGE introduced warning: 4096 anonymous authorize requests fill one global store for 600 s.
F5 adapters.rs:3297 CONFIRMED introduced warning: state is not bound to the user agent (login CSRF).
F6 serve.rs:792 CONFIRMED introduced note: the bearer session_proof is returned as JSON to a top-level navigation, with no handoff to the embedding application.
F7 serve.rs:183 CONFIRMED introduced warning: synchronous outbound IdP calls with a 5 s deadline on the single-threaded listener; not measured.
F8 adapters.rs:3206 CONFIRMED introduced note: the PKCE verifier doc says 43 characters; it is 59 (still valid per RFC 7636).
F9 adapters.rs:264 CONFIRMED introduced note: jwks_hosts is reused for the authorization and token endpoints, so a key host also receives the client secret.
F10 authenticate.rs:289 INFEASIBLE pre-existing note: /v1/federation/login accepts the connection's ID tokens without a nonce check.

Not broken: wrong, unknown and replayed state; expiry at 600 s; nonce compared from verified claims, length-checked, not early-exit; PKCE bound per state; token endpoint on another host, plaintext or IP literal refused (twice); 64 KiB and 5 s limits; missing id_token; IdP error bodies not echoed; secret kept out of argv, Debug, Location and logs; iss mismatch and discovery naming another issuer refused.

```findings
- file: services/control-plane/src/serve.rs
  line: 966
  category: contract-drift
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'a CR LF in the discovered authorization_endpoint passes admits and is written raw into the Location header, letting an IdP set headers such as Set-Cookie on the Mandate origin'
- file: services/control-plane/src/adapters.rs
  line: 3317
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: a callback without iss opens a session even when the IdP metadata advertises authorization_response_iss_parameter_supported, contrary to RFC 9207 section 2.4
- file: services/control-plane/src/adapters.rs
  line: 946
  category: contract-drift
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: an IdP error response naming the state is refused by the decoder and leaves the pending sign-in usable, contradicting the documented take-once-whatever-the-outcome rule
- file: services/control-plane/src/adapters.rs
  line: 3256
  category: boundary
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 4096 anonymous authorize requests fill the single global pending store and refuse every other browser a sign-in on every connection for 600 seconds
- file: services/control-plane/src/adapters.rs
  line: 3297
  category: judgement
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: state is not bound to the user agent that started the sign-in, so a callback URL completed by any client opens the session, which is login CSRF
- file: services/control-plane/src/serve.rs
  line: 792
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: the callback returns the bearer session proof as a JSON body to a top-level browser navigation with no handoff to the embedding application
- file: services/control-plane/src/serve.rs
  line: 183
  category: concurrency
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: anonymous authorize and callback requests make synchronous outbound IdP calls with a 5 s deadline on the single-threaded listener, so a slow IdP stalls every route
- file: services/control-plane/src/adapters.rs
  line: 3206
  category: contract-drift
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: the doc says the PKCE verifier is 43 characters, but it is base64url over base64 text and is 59
- file: services/control-plane/src/adapters.rs
  line: 264
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: the jwks_hosts allowlist is reused for the authorization and token endpoints, so a host listed for keys also receives the client secret
- file: crates/mandate-federation/src/authenticate.rs
  line: 289
  category: judgement
  severity: note
  verdict: INFEASIBLE
  origin: pre-existing
  message: /v1/federation/login accepts the same connection's ID tokens with no nonce check, so the callback nonce check only guards the callback path
```
