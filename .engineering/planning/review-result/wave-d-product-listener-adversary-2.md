---
format: aep.planning-md/1
id: review-result:wave-d-product-listener-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — product listener
relations:
- reviews: story:product-listener
revision: 1
---
```
unit: story:product-listener — impl/product-listener-correction-1 on 6d812e0, after correction 1
verdict: NEEDS-CHANGE (0 blockers, 4 warnings, 2 notes)
cases: 203 → 216 executed, 4 red when written
origin: introduced 1 / pre-existing 5
```

```findings
- file: services/control-plane/src/serve.rs
  line: 675
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: pre-existing
  message: 'redirect_to extends the registered query without parsing it: a registered URI ending in "?" composes "?&code=" (MalformedPair) and a registered state parameter is duplicated (DuplicateKey)'
- file: services/control-plane/src/serve.rs
  line: 673
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: pre-existing
  message: 'RFC 6749 section 3.1.2 "MUST NOT include a fragment" is enforced nowhere, so a registered redirect with a fragment composes a Location whose code and state sit inside the fragment'
- file: services/control-plane/src/serve.rs
  line: 315
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: pre-existing
  message: 'an HTTP/1.1 request with no Host header, or two, is served 200 where RFC 9112 section 3.2 says the server MUST respond 400'
- file: services/control-plane/src/adapters.rs
  line: 518
  category: acceptance
  severity: warning
  verdict: NEEDS-CHANGE
  origin: pre-existing
  message: '--code-lifetime PT99999999H is admitted and every authorization then answers server_error: the lifetime is bounded below and not above'
- file: services/control-plane/src/serve.rs
  line: 711
  category: judgement
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'the module doc states the per-connection bound as request_deadline + write_timeout while the response is written in two bounded writes, so the bound is request_deadline + 2 x write_timeout; no reachable response is large enough to block'
- file: services/control-plane/src/adapters.rs
  line: 505
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: 'Configuration::checked admits a session lifetime shorter than the code lifetime and no document says whether that is intended'
```

Held: the deadline under a dribbling, a silent and a non-reading client; every request-target form; the redirect composer's exact `state` round-trip; the clause classification (`ClientUnregistered` unreachable at the authorize road — both readers share one projection); the configuration matrix; double redemption (second answers `invalid_grant`, the first credential stays active); a proof past the session's expiry; an unregistered client rendered in place; cross-audience introspection refused; unknown token `active: false`; `token_type_hint` admitted and discarded.

Rulings (correction round 2, the last): F1 — the composer parses the registered query as a form first and refuses, in place, a registered URI whose query is not a form or already names `code`, `state` or `error`; F2 — a registered URI carrying a fragment is refused in place (RFC 6749 §3.1.2); both refusals are the client-registration class and are named in the adapter contract. F3 — `Host` is read: absent or repeated is 400. F4 — `Configuration::checked` bounds both lifetimes above: a span whose instant this deployment cannot render and read back is refused at startup (`CodeLifetimeUnbounded`/`SessionLifetimeUnbounded`). F5 — the doc states the bound as `request_deadline + 2 × write_timeout`. F6 — the doc states that a code is redeemable only while its session is fresh, so a session lifetime shorter than the code lifetime shortens the code's usable life and is admitted.
