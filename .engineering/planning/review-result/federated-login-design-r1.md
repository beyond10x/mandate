---
format: aep.planning-md/1
id: review-result:federated-login-design-r1
kind: review-result
status: active
title: Design critic, round 1 — federated login story set
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
approve — no. Report follows.

needs-revision

story:federation-linking — its `authenticate` unit realizes `ProvisionExternalPrincipal` and the JIT path, whose command, event and `jit_provisioning` field are declared by `story:domain-runtime`, but it declares no `depends_on: story:domain-runtime`, so `aep plan artifact waves` places both in wave 3 — .engineering/planning/story/domain-runtime.md:82
story:graph-policy — its `policy-record` unit lands `Policy` and `AuthorizationModel` projections with the `State` enums that `story:domain-runtime`'s `lifecycle-a` unit first declares in `policy.yaml`, and it declares no `depends_on: story:domain-runtime` although `story:tenancy-topology` carries exactly that edge for the same reason — .engineering/planning/story/domain-runtime.md:83
story:tenancy-topology — its sequencing note asserts `story:graph-policy` consumes the `Resource` struct it writes and must dispatch after its merge, while `story:graph-policy` states it reaches `Resource` only through a port "because it carries no `depends_on` edge to that story", and `aep plan artifact waves` dispatches graph-policy one wave earlier — .engineering/planning/story/graph-policy.md:86
story:oauth-integration — it declares the `AccessCredential` projection in `services/sts/src/store.rs` while `story:credential-profiles`' `projection` unit declares `AccessCredential` and its `State` enum in `crates/mandate-token/src/projection.rs`, so one entity projection has two homes and no line says which is authoritative — .engineering/planning/story/credential-profiles.md:83
story:domain-runtime — its coordinator row produces only the `ownership.md:14` revision, while `story:credential-profiles` routes `ownership.md:15` and `story:graph-policy` routes `ownership.md:11-12` to this same story, so two of the three ownership departures the set rests on are owned by no unit — .engineering/planning/story/credential-profiles.md:74
story:pkce-sessions — unit B declares the registered-client port whose only implementation it places in `crates/mandate-federation`, a crate `story:federation-linking` finishes two waves earlier and whose unit table produces no such implementation, so the abstraction's two halves are split in the order that cannot be built — .engineering/planning/story/federation-linking.md:88

## What I read

All 11 judged artifacts in full plus `decision-blocker:lifecycle`, `docs/architecture/ownership.md` and the `feature-design:federated-login` edges; `aep plan artifact show/relations/graph/waves/validate`, `git diff` on the ten rewritten story files, and a full DFS over the graph.

## What I could not establish

- Cycles: none. I walked all 502 declared edges over all 79 artifacts, not only the judged ids, in three passes — `depends_on` alone, `depends_on`+`blocks`, and every relation kind — and found no cycle in any of them. The set is not a chain either: waves 3, 4, 5 each hold two or three of the judged stories.
- The prompt's statement that `waves` puts `story:domain-runtime` in wave 1 does not match the CLI, which prints wave 3 for it beside `federation-linking` and `graph-policy`; the co-scheduling it describes is real, the wave number is not.
- `story:oauth-integration:84` and `:59` cite `ownership.md:16` for the credential/registry row, which is the `mandate.delegation` row; `:15` is the credential row. A wrong line reference is not mine to rule on, and I did not let it set the verdict.
- Out of my lane, stated and not counted: `aep plan artifact validate` reports 9 review-results with no findings block (relayed, not my finding); the 15 collisions `waves` prints — including `credential-profiles`/`domain-runtime` on `crates/mandate-types/src/inventory.rs` and `credential-profiles`/`oauth-integration` on `services/sts/src/lib.rs` — are `plan-critic-parallel-safety`'s; whether each Acceptance is checkable is `plan-critic-acceptance`'s; whether the coordinator owning every `src/lib.rs` is workable is a scheduling question, not a split abstraction, since each story names one owner for it.

```findings
- file: .engineering/planning/story/domain-runtime.md
  line: 82
  category: design
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: "its `authenticate` unit realizes `ProvisionExternalPrincipal` and the JIT path, whose command, event and `jit_provisioning` field are declared by `story:domain-runtime`, but it declares no `depends_on: story:domain-runtime`, so `aep plan artifact waves` places both in wave 3"
- file: .engineering/planning/story/domain-runtime.md
  line: 83
  category: design
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: "its `policy-record` unit lands `Policy` and `AuthorizationModel` projections with the `State` enums that `story:domain-runtime`'s `lifecycle-a` unit first declares in `policy.yaml`, and it declares no `depends_on: story:domain-runtime` although `story:tenancy-topology` carries exactly that edge for the same reason"
- file: .engineering/planning/story/graph-policy.md
  line: 86
  category: design
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: "its sequencing note asserts `story:graph-policy` consumes the `Resource` struct it writes and must dispatch after its merge, while `story:graph-policy` states it reaches `Resource` only through a port \"because it carries no `depends_on` edge to that story\", and `aep plan artifact waves` dispatches graph-policy one wave earlier"
- file: .engineering/planning/story/credential-profiles.md
  line: 83
  category: design
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: "it declares the `AccessCredential` projection in `services/sts/src/store.rs` while `story:credential-profiles`' `projection` unit declares `AccessCredential` and its `State` enum in `crates/mandate-token/src/projection.rs`, so one entity projection has two homes and no line says which is authoritative"
- file: .engineering/planning/story/credential-profiles.md
  line: 74
  category: design
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: "its coordinator row produces only the `ownership.md:14` revision, while `story:credential-profiles` routes `ownership.md:15` and `story:graph-policy` routes `ownership.md:11-12` to this same story, so two of the three ownership departures the set rests on are owned by no unit"
- file: .engineering/planning/story/federation-linking.md
  line: 88
  category: design
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: "unit B declares the registered-client port whose only implementation it places in `crates/mandate-federation`, a crate `story:federation-linking` finishes two waves earlier and whose unit table produces no such implementation, so the abstraction's two halves are split in the order that cannot be built"
```

Store root read: `.engineering/planning`
