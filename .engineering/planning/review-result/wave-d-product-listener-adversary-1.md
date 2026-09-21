---
format: aep.planning-md/1
id: review-result:wave-d-product-listener-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — product listener (post-merge)
relations:
- reviews: story:product-listener
revision: 1
---
```
unit: story:product-listener — merged at 82c6419/3cbab1a (PR #14); pass owed after the merge
verdict: NEEDS-CHANGE (3 blockers, 4 warnings, 2 notes)
cases: 22 → 31 executed, 8 red when written
origin: introduced 9 / pre-existing 0
```

```findings
- file: services/control-plane/src/serve.rs
  line: 364
  category: contract-drift
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'the success redirect joins the registered redirect URI with a literal "?", so a client whose registered URI carries a query (RFC 6749 section 3.1.2 admits and retains one) is sent a Location whose query parses to no code parameter'
- file: services/control-plane/src/serve.rs
  line: 379
  category: contract-drift
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'the error redirect composes its Location the same way, so error is not a parameter of the query when the registered URI already carries one'
- file: services/control-plane/src/serve.rs
  line: 257
  category: boundary
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'the truncate never truncates below the bytes already read, so the declared Content-Length is not the frame: trailing bytes in the same segment are decoded as part of the request, and a POST declaring Content-Length 0 with a token form behind its head is answered 200 with an access_token'
- file: services/control-plane/src/serve.rs
  line: 216
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'str::parse admits a leading "+", so Content-Length +83 is read as 83 where RFC 9112 section 6.3 requires 1*DIGIT'
- file: services/control-plane/src/serve.rs
  line: 105
  category: concurrency
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the accept loop answers one connection at a time and nothing states so; a second client waited 2.50 s behind one connection dribbling a byte every 300 ms, and at Limits::default one client can hold the listener for roughly eleven hours'
- file: services/control-plane/src/main.rs
  line: 73
  category: acceptance
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'a --code-lifetime naming no span becomes zero through unwrap_or(0) at adapters.rs:818, so the process starts and serves logins while refusing every authorization with no startup error; --session-lifetime has the same shape'
- file: services/control-plane/src/serve.rs
  line: 292
  category: contract-drift
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'route_path splits only on "?", so an absolute-form target is answered 404 where RFC 9112 section 3.2.2 says a server MUST accept it'
- file: services/control-plane/src/serve.rs
  line: 378
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'a deployment-side expiry failure (ExpiryUnbounded, reason Denied) is rendered as access_denied, which a developer reads as the end user declining; server_error is the code'
- file: services/control-plane/src/adapters.rs
  line: 583
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'Configuration.issuer is trimmed of a trailing slash for the metadata document and used untrimmed as the federation audience'
```

Held: the by-verifier read (no trait object, whole-slice scan), a duplicate verifier unreachable, exact `state` round-trip for `&`, `#`, `%`, space, U+00E9, U+2028, header injection through `Location`, repeated `Content-Length` and `Transfer-Encoding` refused, encoded and traversal paths 404 by construction, `token_endpoint_auth_methods_supported: ["none"]` consistent with the token endpoint. Not reached: double redemption, cross-audience introspection, session-proof replay and expiry, an unbindable `--listen`, the write timeout, a head exactly at the limit, `HTTP/1.0`, a fragment in the target.

Rulings (correction round 1): F1/F2 — the redirect joins with `&` when the registered URI already carries a query, `?` otherwise; both branches share one composer. F3 — `body.truncate(wanted)`: the declared length is the frame, and a declared length above the read bound is refused before any body byte is read. F4 — `Content-Length` is ASCII digits only. F5 — a per-connection deadline (`Limits::request_deadline`, default 10 s) across all reads and writes, and the module doc states that the first served vertical answers one connection at a time. F6 — `Deployment::new` returns `Result<_, ConfigurationRefused>` and refuses a lifetime naming no span (the `unwrap_or(0)` sites go); `main.rs` exits 2 with the refusal. F7 — an absolute-form target is reduced to its origin-form path before the route lookup. F8 — `ExpiryUnbounded` answers `server_error` through a `SERVER_ERROR_CLAUSES` list beside `UNAUTHORIZED_CLIENT_CLAUSES` in `mandate-proto` (scope extended). F9 — the issuer is normalised once in `Deployment::new` (one trailing slash trimmed) and both consumers read the normalised value.
