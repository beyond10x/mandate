---
format: aep.planning-md/1
id: review-result:wijk-j1-loopback-adversary-2
kind: review-result
status: active
title: Adversary pass 2 on J1 (control-plane-loopback-fold)
relations:
- reviews: story:control-plane-loopback-fold
revision: 1
---
unit: story:control-plane-loopback-fold, working tree at bd882e1 plus one untracked test file
verdict: red
cases: executed 162→164, red 1
origin: introduced 0, pre-existing 1, undecided 0
wrote-outside-worktree: ~/.cache/claude-tmp/wijk/j1/scratch/adv2/{probe.rs,main.rs,probe,alone.log,suite.log}
needs-coordinator: yes (the federation guard has the same parse::<u16> at verifier_real.rs:462 and :487; not tested, outside this unit)

Cases in services/control-plane/tests/adversary_loopback_fold_2.rs:
- a_plaintext_port_that_is_not_all_digits_is_not_admitted — red: admitted ["http://localhost:+80", "http://127.0.0.1:+8080", "http://[::1]:+80"] (RFC 3986 3.2.3 port = *DIGIT)
- every_loopback_issuer_the_repository_uses_is_still_admitted — green, 15 issuers incl. format!("http://{SocketAddr}") for v4 and v6

Suite: cargo test -p mandate-control-plane --locked --no-fail-fast EXIT=101, 164 ran, 163 passed, 1 failed.

F1 adapters.rs:661 CONFIRMED pre-existing note: spelled.parse::<u16>() accepts a leading +. Base 9a68796's is_loopback, copied to scratch and run, admits all three too. Fix: also require spelled.bytes().all(|b| b.is_ascii_digit()). Reaches: only the operator's --issuer flag (main.rs:93 → :227); no fixture, doc or workflow; the host is still loopback.

Over-refusal: none found. docs/public/federated-login.md:90 gives only --issuer <url>; tests use http://127.0.0.1:8080, http://localhost:8080, http://[::1]:8080 (tests/adapters.rs:639-641) and format!("http://{address}") (end_to_end.rs:216,251; adversary_login_road.rs:167), all admitted. Of 26 spellings base vs bd882e1, the correction newly refuses only localhost:+, localhost:٨٠ and localhost: 80.

```findings
- file: services/control-plane/src/adapters.rs
  line: 661
  category: boundary
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: 'the spelled-port check is str::parse::<u16>, which accepts a leading +, so http://localhost:+80 is admitted as a plaintext loopback issuer although RFC 3986 port is *DIGIT'
```
