---
format: aep.planning-md/1
id: review-result:federated-login-design-r2
kind: review-result
status: active
title: Design critic, round 2 — federated login story set
tags:
- model-deviation-opus
relations:
- reviews: story:domain-runtime
- reviews: story:federation-linking
- reviews: story:session-epochs
- reviews: story:pkce-sessions
- reviews: story:credential-profiles
- reviews: story:tenancy-topology
- reviews: story:check-api
- reviews: story:graph-policy
- reviews: story:protocol-adapters
- reviews: story:oauth-integration
- reviews: decision-blocker:jit-provisioning
- reviews: story:signing-and-verification
- reviews: story:graph-policy-adapter
- reviews: story:product-listener
revision: 1
---
needs-revision

story:product-listener — its Acceptance requires "the redemption transaction `story:oauth-integration` implements" while `story:oauth-integration` declares `depends_on: story:product-listener` for its own acceptance's "actual OAuth endpoint", so neither acceptance can be demonstrated before the other's and the edge that would record this story's half closes a cycle — .engineering/planning/story/product-listener.md:31 with .engineering/planning/story/oauth-integration.md:14

story:product-listener — its `port-adapters` unit implements the registered-client port over `story:federation-linking`'s `OAuthClient` projection inside `crates/mandate-federation`, and that story's scope line records the pair as `depends_on`, but no such edge exists in the graph — only a transitive one through `story:protocol-adapters` — .engineering/planning/story/federation-linking.md:109

## Round-1 findings: all six no longer hold

| r1 finding | closed by |
|---|---|
| federation-linking missing `depends_on story:domain-runtime` | `story/federation-linking.md:13`, plus the Sequencing paragraph at `:151` |
| graph-policy missing the same edge | `story/graph-policy.md:13`, Sequencing at `:78` |
| tenancy-topology / graph-policy contradicting orderings | both now say no ordering exists — `story/tenancy-topology.md:78`, `story/graph-policy.md:85` |
| `AccessCredential` with two homes | `story/oauth-integration.md:85` declares `AuthorizationCode` only and consumes the type |
| two of three `ownership.md` departures owned by no unit | `story/domain-runtime.md:85` coordinator row now carries `:11-12`, `:14`, `:15`, `:16` |
| pkce-sessions unit B's split abstraction | `story/pkce-sessions.md:53` — port + `pub` double here, real impl assigned to a later story |

## What I read

All 14 judged artifacts in full, plus `story:constrained-exchange`, `story:product-cli` and `review-result:federated-login-design-r1`; `aep plan artifact show/relations/graph/waves/validate`, and a DFS for cycles over **all 565 declared edges among all 87 artifacts** — not only the judged ids — in three passes (`depends_on` alone; `depends_on`+`blocks`; all ten relation kinds present). **No declared cycle in any pass.** The set is not a chain: waves 4 and 5 each hold four of the judged stories (`aep plan artifact waves`).

## What I could not establish

- Why `story:credential-profiles` carries `depends_on story:pkce-sessions`; nothing in its body names that story, and the edge costs it two waves. Not a defect I can name a fix for, so not a finding.
- Whether finding 2 is worth more than the transitive path: ordering is enforced today through `story:protocol-adapters`, so the cost is a body asserting an edge the store does not hold, not a schedulable-too-early story. Recorded `warning` for that reason.
- Out of my lane, stated and not counted: `story:product-listener`, `story:signing-and-verification` and `story:graph-policy-adapter` each add a module file to a crate root (`crates/mandate-federation/src/lib.rs`, `crates/mandate-token/src/lib.rs`, `crates/mandate-graph|policy/src/lib.rs`) that a parent story declares coordinator-owned, and none of the three lists that root in scope — two items touching one file without saying so is `plan-critic-parallel-safety`'s rule, as are the 16 collisions `waves` prints including `oauth-integration`/`product-listener` on `services/sts/src/main.rs`. `story:check-api`'s Scope block still lists `precedence.rs`/`tests/precedence.rs` after the unit was renamed `ceilings` (`story/check-api.md` Scope) — a stale line, not a coupling defect. `aep plan artifact validate` returns `valid` with 10 review-results lacking a findings block; relayed, not my finding.
- An unease, not a finding: `story:product-listener` is the bucket for three unrelated deferrals (a listener, the `xtask` `serve` replacement, a federation port adapter), and only the first is covered by its acceptance.

```findings
- file: .engineering/planning/story/product-listener.md
  line: 31
  category: design
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: "its Acceptance requires the redemption transaction `story:oauth-integration` implements while `story:oauth-integration` declares `depends_on: story:product-listener` for its own acceptance's actual OAuth endpoint, so neither acceptance can be demonstrated before the other's and the edge that would record this story's half closes a cycle"
- file: .engineering/planning/story/federation-linking.md
  line: 109
  category: design
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: "its `port-adapters` unit implements the registered-client port over `story:federation-linking`'s `OAuthClient` projection inside `crates/mandate-federation`, and that story's scope line records the pair as `depends_on`, but no such edge exists in the graph — only a transitive one through `story:protocol-adapters`"
```
