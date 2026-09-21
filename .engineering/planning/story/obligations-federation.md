---
format: aep.planning-md/1
id: story:obligations-federation
kind: story
status: implemented
title: Bind mandate-federation's denial clauses to real-path tests
relations:
- decomposes: epic:foundations
- informed_by: initiative:drift-enforcement
- depends_on: story:obligation-registry
- serves: vision:mandate
scope:
- confidence: cited
  path: contracts/obligations/federation.json
- confidence: cited
  path: crates/mandate-federation/tests/obligations.rs
revision: 9
---
## Why

`story:obligation-registry` (wave D second half) authors `contracts/obligations.json`, the clause-level map from every implemented command's external denial clauses to the real-path tests that decide them. The binding for `mandate-federation` is one file this story owns: 9 commands, ~49 clauses (scoper's estimate on `6d812e0`, split of each IR `condition.cause` on comma/`or`; granularity checked against `services/sts/tests/declared_denials.rs:108`). Until it lands, the registry carries `blocked_on: story:obligations-federation` for every unbound clause of this crate and the step stays green.

## Outcome

`crates/mandate-federation/tests/obligations.rs` decides every clause of the crate's implemented commands on the real path — one denial case per clause naming the clause verbatim, one no-state-change case per command — and `contracts/obligations.json` names each; the crate's rows in `contracts/conformance/obligations-report.json` move from `deferred` to `real_covered`.

## Acceptance

`cargo xtask obligations-registry` reports no clause of a `mandate-federation` command as `deferred` on this story, and `cargo test -p mandate-federation --locked --test obligations` is green.

- Implementor result (2026-09-21): 11 of the 20 deferred clauses bound with 16 new real-path cases in `crates/mandate-federation/tests/obligations.rs` (the four proof clauses through `RealVerifier` over `InMemoryJwks` with real ES256 tokens; every case red under a mutation of the guard it names, sources restored); the `pkce-state-nonce` case row bound to two existing cases; 9 clauses re-pointed per the rule — 4 authority clauses to `decision-blocker:guards`, 2 durable-commit clauses to `decision-blocker:epoch-atomicity`, 1 to `decision-blocker:audit-routing`, 2 to `story:oauth-integration` (STS code issuance at authorization; new-code issuance after disablement), each with the source line saying the crate does not decide it; 0 left on this story. Table: `mandate-federation` 31 real / 9 deferred; all 79 / 8 / 89. 299 federation tests; the step green. Named for a person: three near-identical authority clauses are re-pointed while `RegisterOAuthClient`'s is bound, because only that command has an admission port. Adversary dispatched.

- Adversary 1 ruled (2026-09-21, `review-result:wave-d-obligations-federation-adversary-1`): the implementor line above overstates "the four proof clauses through `RealVerifier`" — the issuer and audience cases are decided by `authenticate.rs:249` and `:256` before the verifier's own binding is consulted (green with the verifier's issuer and audience checks removed); only the signature and expiry cases are decided by `RealVerifier`, and `tests/verifier_real.rs` covers the verifier half of the other two. Rows unchanged. F1 (`collides` on different claim names) → `story:federation-rule-disjointness`; F3 (two rows no test of this crate can bind) → `story:cross-crate-clauses`; F4 (the four authority handlers lack the admission port) → `story:federation-admission-port`; F2 → correction 1.

- Result (2026-09-21): unit commit `ecd2471`, merge `7275385`. 11 clauses bound on the real path, 3 `RegisterOAuthClient` clauses bound as `double` rows on `ConfiguredAdmission` deferring to `decision-blocker:guards`, 6 re-pointed (4 → `story:federation-admission-port`, 2 → `story:cross-crate-clauses`), 3 to blockers; `mandate-federation 40 / 28 / 3 / 9`; 304 federation tests; two adversary passes (`review-result:wave-d-obligations-federation-adversary-{1,2}`), two corrections. The Outcome above ("every clause … on the real path") is not what the crate can deliver: 9 clauses name paths this crate does not decide and 3 are decided by a standing double; the Acceptance sentence holds.
