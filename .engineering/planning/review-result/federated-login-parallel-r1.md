---
format: aep.planning-md/1
id: review-result:federated-login-parallel-r1
kind: review-result
status: active
title: Parallel-safety critic, round 1 — federated login story set
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
revision: 1
---
needs-revision

**Findings**

`story:federation-linking` — its `authenticate` unit realizes `ProvisionExternalPrincipal`, a command that exists nowhere in `systems/` or `generated/` and is created by `story:domain-runtime`'s `jit-command` unit, yet the body declares no `depends_on: story:domain-runtime` and its "Would collide with" line omits that story, so `aep plan artifact waves` schedules both in wave 1 — .engineering/planning/story/federation-linking.md:106

`story:domain-runtime` — the body requires exclusive scheduling ("no other story runs beside this one"; ":130" freeze "before the concurrent federation and graph units begin") in prose only and declares no relation or scope entry that expresses it, so `waves` places it in wave 1 beside `story:federation-linking` and `story:graph-policy` — .engineering/planning/story/domain-runtime.md:122

**What I read**

All 11 artifacts in full from `.engineering/planning/{story,decision-blocker}/`; `aep plan artifact waves --kind story --status draft --format json` (9 waves, 9 collisions, 1 unassessed, 0 cycles) and `aep plan artifact graph --format json`; tree checks in the same worktree — `grep -rn ProvisionExternalPrincipal systems/ generated/` and `grep -rn jit_provisioning systems/` (both empty), `git grep -n "generated/"` in `crates services bins xtask`, and `sed -n '460,500p' crates/mandate-types/src/inventory.rs` plus `128,165p` of its test.

**Surface establishment (part 3)**

10 of 10 stories placed **cited** — each carries a `scope:` block and a `## Scope` section marking every path; 0 placed by grep/noun inference; 0 unplaceable. `decision-blocker:jit-provisioning` declares no `scope:` and is not a work item (`waves --kind story` never sees it); its surfaces are domain-runtime's, named at its line 26-28 — unassessed by design, not a gap. Within the ten, 153 scope entries: 32 `cited`, 121 `inferred`, nearly all because the file does not yet exist and the body says so. Both findings rest on **cited** surfaces.

**What I could not establish**

- Whether wave 1's co-scheduling breaks a gate mechanically: `generated/schema` is read at test time only by `mandate-types`, `mandate-model`, `mandate-proto`, `mandate-token` — not by `mandate-federation`, `mandate-graph` or `mandate-policy`. So the collision is on the contract and on the shared `task check` (`domain-runtime.md:109` keeps it red on "projection drift" until its own coordinator regenerates, while every story's "Validation and contract" section claims `task check`), not on a compiled input. I could not read `xtask/src/main.rs:90-91` against a merged wave-1 head that does not exist.
- Whether the missing `depends_on` on `federation-linking` predates today: `protocol-adapters` has `aep.relation.create/v1` events in the journal (it says so at its line 100) and `federation-linking` has none, and the JIT content entered `domain-runtime` at revision 10 today — hence `introduced`, read from the journal rather than from a diff.

**Verified, not findings**

- `credential-profiles`/`domain-runtime` on `crates/mandate-types/{src,tests}/inventory.rs`: sequential by a real 4-edge chain (domain-runtime → session-epochs → pkce-sessions → credential-profiles), and the two regions are disjoint in the file as it stands — `EXCLUDED_ENTITIES` at `src/inventory.rs:464-487` (domain-runtime) vs `EXCLUDED_SEMANTICS` at `:490-498`, entries 3-5 (credential-profiles). The coordinator's reading holds. `credential-profiles.md:120` still omits `story:domain-runtime` from its collision list, but `waves` prints that pair itself, so it is not mine to restate.
- `credential-profiles`/`oauth-integration` on `services/sts/{Cargo.toml,src/lib.rs}`: direct `depends_on` edge, and **both** bodies name it (`credential-profiles.md:78,120`; `oauth-integration.md:113`).
- `session-epochs`/`pkce-sessions` on `crates/mandate-identity/src/lib.rs`: the deliberate non-declaration is sound — `pkce-sessions.md:95-96` states it and points at the holder, `session-epochs.md:99` holds the cited entry and names the pair back.
- The coordinator's three structural claims check out mechanically: exactly 4 paths are claimed by two of the ten, exactly 1 directory entry survives (`generated`, justified at `domain-runtime.md:120` as one atomic 267-file surface), and no file appears in two rows of any unit table.
- `tenancy-topology`/`graph-policy` on `Resource` do not share a file (`crates/mandate-model` vs `crates/mandate-graph`) and both bodies name the coupling (`tenancy-topology.md:78`; `graph-policy.md:86`). **Out of my lane:** `tenancy-topology.md:78` asserts `Resource` is frozen "before `graph-policy` dispatches", and `waves` runs graph-policy in wave 1 and tenancy-topology in wave 2 — the stated order is inverted. Sequencing is the operator's; it does not set my verdict.
- **Out of my lane:** `decision-blocker:jit-provisioning` is `status: open` and `blocks` both wave-1 stories, yet `waves` schedules them — that is a status/acceptance question. The directory-scoped stories named at `pkce-sessions.md:82`, `graph-policy.md:130` and `check-api.md:98` (`product-cli`, `agent-authority-kernel`, `agent-security`) are outside the set I was given; each hazard is already recorded in the in-set body, and I report nothing about the out-of-set artifacts themselves.

```findings
- file: .engineering/planning/story/federation-linking.md
  line: 106
  category: parallel-safety
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: "its `authenticate` unit realizes `ProvisionExternalPrincipal`, a command that exists nowhere in `systems/` or `generated/` and is created by `story:domain-runtime`'s `jit-command` unit, yet the body declares no `depends_on: story:domain-runtime` and its \"Would collide with\" line omits that story, so `aep plan artifact waves` schedules both in wave 1"
- file: .engineering/planning/story/domain-runtime.md
  line: 122
  category: parallel-safety
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: "the body requires exclusive scheduling (\"no other story runs beside this one\"; line 130 freeze \"before the concurrent federation and graph units begin\") in prose only and declares no relation or scope entry that expresses it, so `waves` places it in wave 1 beside `story:federation-linking` and `story:graph-policy`"
```
