---
format: aep.planning-md/1
id: review-result:wm-m1-rp-flow-adversary-2
kind: review-result
status: active
title: Adversary pass 2 on M1 (relying-party-code-flow)
relations:
- reviews: story:relying-party-code-flow
revision: 1
---
unit: story:relying-party-code-flow, HEAD c387293 (base 871c11b0) plus one new untracked test file
verdict: red
cases: executed 188→194, red 6
origin: introduced 6, pre-existing 0, undecided 0
wrote-outside-worktree: ~/.cache/claude-tmp/wm/m1/scratch/{adv2-cases.log, adv2-cases-2.log, adv2-suite.log, adv2-suite-2.log}
needs-coordinator: no

Cases in services/control-plane/tests/adversary_rp_flow_2.rs (harness with a cookie Jar; success judged only by redeeming the handoff): :867 the victim's own callback after an unrelated one signed nobody in; :895 a stale tab's return killed the held sign-in; :924 4096 anonymous authorize requests evicted a waiting browser; :949 an admitted return_uri answered a completed sign-in with 400; :1009 plaintext non-loopback return URIs admitted (localhost.attacker.example, 127.0.0.1.attacker.example, localhost@attacker.example, localhostattacker.example); :1031 return URIs the seed admits and the callback cannot use.

Suite: cargo test -p mandate-control-plane --locked --no-fail-fast EXIT=101, 188 passed, 6 failed. clippy clean.

A serve.rs:743 NEEDS-CHANGE introduced warning: every callback clears the binding cookie, including an unknown state; reached by a top-level navigation to /v1/federation/callback?state=x within 600 s, or a second tab.
B adapters.rs:1032 CONFIRMED introduced warning: 4096 anonymous authorize requests in under a second evict a waiting browser; one store for all connections; the doc defers to an ingress rate limit (not checked).
C adapters.rs:962 NEEDS-CHANGE introduced warning: the seed refuses only a literal handoff; redirect_to refuses code/state/error and non-form queries; hand%6Fff doubles handoff.
D adapters.rs:960 CONFIRMED introduced note: the loopback rule is a string prefix.
E adapters.rs:3618 NEEDS-CHANGE introduced warning: a handoff is redeemed by its bare code; FEDERATION_AUTHORIZE_PARAMETERS (decode.rs:545) admits only connection_id, so the app cannot bind its own state; an attacker's own handoff delivered to a victim reopens login CSRF; the code is a bearer credential in a URL.

Not broken: handoff replay and unknown code; 256-bit codes; __Host- attributes and duplicate cookie; CR LF 500 path; RFC 9207 iss; IdP error consumes state; direct login single caller; SameSite=Lax vs form_post (GET only).

```findings
- file: services/control-plane/src/serve.rs
  line: 743
  category: boundary
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: every callback, including one naming a state nobody issued, clears the binding cookie, so a cross-site top-level navigation or a stale second tab kills the sign-in the browser holds
- file: services/control-plane/src/adapters.rs
  line: 1032
  category: boundary
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 4096 anonymous authorize requests, sent in under a second, evict a waiting browser's pending sign-in from the one store shared by every connection
- file: services/control-plane/src/adapters.rs
  line: 962
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: the seed admits return_uri queries that redirect_to then refuses (state, code, error, not a form) or doubles (percent-encoded handoff), so every sign-in opens a session and answers 400
- file: services/control-plane/src/adapters.rs
  line: 960
  category: contract-drift
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the loopback-only http rule is a string prefix, so http://localhost.attacker.example and http://localhost@attacker.example are admitted'
- file: services/control-plane/src/adapters.rs
  line: 3618
  category: judgement
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: a handoff is redeemed by its bare code with nothing tying it to the initiating browser or application, so an attacker's own handoff code delivered to a victim reopens login CSRF one hop after the binding cookie
```
