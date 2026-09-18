---
format: aep.planning-md/1
id: review-result:federated-login-parallel-r2
kind: review-result
status: active
title: Parallel-safety critic, round 2 — federated login story set
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
approve → no. Here is the report.

---

needs-revision

**Findings**

`story:signing-and-verification` — both this and `story:product-listener` add a module file under `crates/mandate-federation/src/` (`verifier_real.rs`; `adapters.rs`) and so both must edit `crates/mandate-federation/src/lib.rs`, which is four `//!` lines with no `mod` line today and which `federation-linking.md:59` says must carry one ("a `pub mod` line against a file that does not exist does not compile"), yet neither declares that file in `scope:`, neither body names the other, and no `depends_on` path orders them, so `aep plan artifact waves` reports no collision between them — .engineering/planning/story/signing-and-verification.md:47

`story:product-listener` — its coordinator row claims `Cargo.toml`, `Cargo.lock`, `dependency-boundaries.json` and `deny.toml` as this story's own coordinator work ("the transport dependency") while `scope:` declares only the same row's other two files, so `waves` sees none of the four and reports no collision with `story:signing-and-verification`, whose line 49 claims the same four and which no edge orders against this story — .engineering/planning/story/product-listener.md:47

`story:graph-policy-adapter` — its Scope names `Cargo.toml`, `Cargo.lock`, `dependency-boundaries.json` and `deny.toml` as the coordinator surfaces its engine admission needs but omits all four from `scope:`, so `waves` places it in wave 3 beside `story:pkce-sessions`, which declares `Cargo.lock` (`pkce-sessions.md:15`, annotated "coordinator; `sha2`" at `:94`) and names "any unit editing … `Cargo.lock`" as a collision at `:96`, and reports the pair as independent — .engineering/planning/story/graph-policy-adapter.md:50

**What I read**

All 13 stories and `decision-blocker:jit-provisioning` in full from `.engineering/planning/{story,decision-blocker}/`, plus `task:runtime-wave-integration`; `aep plan artifact show review-result:federated-login-parallel-r1`; `aep plan artifact waves --kind story --status draft --format json` (10 waves, 10 collisions, 1 unassessed, 0 cycles) cross-tabulated path-by-path across the set, and `aep plan artifact graph --format json` for every edge touching it; in the same worktree `cat` of `crates/mandate-{federation,graph,policy,identity}/src/lib.rs` (4 lines each, no `mod`), `crates/mandate-token/src/lib.rs:1-12`, `services/sts/src/main.rs` (10 lines, no `lib.rs` in the package), `dependency-boundaries.json`, root `Cargo.toml`.

**Surface establishment (part 3)**

13 of 13 stories placed **cited** — each carries a `scope:` block and a `## Scope` section marking every path `cited` or `inferred`; 0 placed by grep or noun inference; 0 unplaceable. `decision-blocker:jit-provisioning` declares no `scope:`, is not a work item and `waves --kind story` never sees it — unassessed by design, as in round 1. Beyond the declared blocks I established two further surfaces: the four root config files (**cited**, from the three new bodies' own prose at `signing-and-verification.md:49`, `graph-policy-adapter.md:50`, `product-listener.md:47`) and `crates/mandate-federation/src/lib.rs` for the two module-adding stories (**inferred**, from the Rust module rule that `federation-linking.md:59` states). Finding 1 rests on that inferred surface; findings 2 and 3 on cited ones.

**Round-1 findings, re-checked**

Both no longer hold, and I am not repeating either. `story:federation-linking` now carries `depends_on: story:domain-runtime` (`federation-linking.md:13`), justifies it at `:55` and names the story in its collision line at `:109`. `story:domain-runtime` now states the exclusivity in edge terms — "This story runs alone in its wave: `story:federation-linking`, `story:graph-policy` and `story:tenancy-topology` all `depends_on` it, so nothing else is dependency-ready beside it" (`domain-runtime.md:89`) — and `waves` puts it alone in wave 1. (The sentence lists three of the four dependants; `story:session-epochs` also carries the edge. `waves` confirms the wave regardless, so it is not a finding.)

**Wave 2 and the five reported collisions**

Wave 2's four stories claim 53 paths and **no path appears twice**: `mandate-federation`, `mandate-graph`+`mandate-policy`, `mandate-identity`, `mandate-model`, one crate root each, and all four bodies forbid their units `Cargo.toml`/`Cargo.lock`/`dependency-boundaries.json`. The two cross-crate couplings are named on both sides — `Resource` at `graph-policy.md:85` and `tenancy-topology.md:78` (round 1's inverted-order sentence at that line is gone; the two now agree that no ordering exists), and `federation-linking`/`mandate-model` at `tenancy-topology.md:78`. The coordinator's reading of all five collisions holds: `credential-profiles`/`domain-runtime` sequential by the 4-edge chain domain-runtime → session-epochs → pkce-sessions → credential-profiles; `credential-profiles`/`oauth-integration` by a direct edge, named in both bodies (`credential-profiles.md:78`, `oauth-integration.md:113`); `oauth-integration`/`product-listener` by the new `oauth-integration depends_on story:product-listener` edge, named at `product-listener.md:47` and `oauth-integration.md:109`.

**What I could not establish**

- Whether `crates/mandate-federation/src/lib.rs` is genuinely the registration point for both new modules is **inferred**: neither new body names the file, and I read the rule from `federation-linking.md:59` and the four-line scaffold, not from a merged head that does not exist.
- `story:product-listener` also lands on `services/sts/src/lib.rs` (its `serve.rs` needs a `mod` line) without declaring it; `credential-profiles.md:78` seeds that file's `mod` lines for `oauth-integration` and `constrained-exchange` and does not mention `serve`. Every claimant of that file is ordered by an edge, so it is not a collision and not a finding — but the surface is undeclared.
- Out of my lane: `decision-blocker:jit-provisioning` is `status: open` and `blocks` `story:domain-runtime`, which `waves` schedules in wave 1; five more open blockers sit on the three new stories (`algorithm-policy`, `backend`, `subject-relations`, `lifecycle`, `guards`). That is a status/acceptance question and does not set my verdict. `story:gate-reads-document-deliverables` is `unassessed` in the `waves` output and outside my set; I report nothing about it. Wave-mates outside my set (`story:directory-provenance` in wave 3, `constrained-exchange`/`recovery-runbooks` in wave 6, `advanced-delegation`/`audit-recovery-conformance` in wave 8) I did not judge.

```findings
- file: .engineering/planning/story/signing-and-verification.md
  line: 47
  category: parallel-safety
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: "both this and `story:product-listener` add a module file under `crates/mandate-federation/src/` and so both must edit `crates/mandate-federation/src/lib.rs` (inferred surface; the file is four `//!` lines with no `mod` line and `federation-linking.md:59` states a `pub mod` line is required), yet neither declares that file in `scope:`, neither body names the other, and no `depends_on` path orders them, so `aep plan artifact waves` reports no collision between them"
- file: .engineering/planning/story/product-listener.md
  line: 47
  category: parallel-safety
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: "its coordinator row claims `Cargo.toml`, `Cargo.lock`, `dependency-boundaries.json` and `deny.toml` as this story's own coordinator work while `scope:` declares only the same row's other two files, so `waves` sees none of the four and reports no collision with `story:signing-and-verification`, whose line 49 claims the same four and which no edge orders against this story"
- file: .engineering/planning/story/graph-policy-adapter.md
  line: 50
  category: parallel-safety
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: "its Scope names `Cargo.toml`, `Cargo.lock`, `dependency-boundaries.json` and `deny.toml` as the coordinator surfaces its engine admission needs but omits all four from `scope:`, so `waves` places it in wave 3 beside `story:pkce-sessions`, which declares `Cargo.lock` at `pkce-sessions.md:15` and names any unit editing `Cargo.lock` as a collision at `:96`, and reports the pair as independent"
```
