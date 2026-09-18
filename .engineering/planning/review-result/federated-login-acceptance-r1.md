---
format: aep.planning-md/1
id: review-result:federated-login-acceptance-r1
kind: review-result
status: active
title: Acceptance critic, round 1 — federated login story set
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

story:federation-linking — the acceptance is discharged in full by the eight cases this wave's units land (`tests/authenticate.rs`, `tests/link.rs`), while the new section says the story ends `active`, not `implemented`, so nothing in the body names the observation that moves it to `implemented` — .engineering/planning/story/federation-linking.md:50
story:credential-profiles — the acceptance's revoke-then-introspect is the `resolve` unit's named deliverable this wave, yet the same body says "This story ends its first wave `active`", so the acceptance cannot distinguish the state the story ends in from the state in which it is done — .engineering/planning/story/credential-profiles.md:70
story:graph-policy — "This story's own acceptance is the `revocation` unit's revision-bound denial suite exiting zero" (line 110) is satisfied without the chosen adapter the title and the new section make the reason for ending `active`, so the acceptance names no outcome the story lacks at wave end — .engineering/planning/story/graph-policy.md:78
story:protocol-adapters — the acceptance is case `credential-containment`, which the `context` unit is marked "now", while the section says the story ends `active` with no listener behind any of it, so the acceptance neither states that a library-level decode satisfies "a product adapter decodes the request" nor names what is still missing — .engineering/planning/story/protocol-adapters.md:69

What I read: all 11 ids I was given, all 11 read in full — ten story bodies and `decision-blocker:jit-provisioning` — via `cat`/`Read` on the store files, `aep plan artifact kinds`, `aep plan artifact lifecycle story`, `aep plan artifact lifecycle decision-blocker`, the rubric and `references/store-conventions.md:94` ("what counts as done"), plus `git show HEAD:…` on four stories to establish that the acceptance sentences are unchanged and the "Cannot be completed" sections are new today, and `grep` in the tree for the named case ids (`tenant-valid`, `reference-revoked`, `credential-containment`, `cross-tenant-resource`, `pdp-outage`, `graph-revocation` all exist in `tests/security/cases.json`).

What I could not establish:
- Whether `story:oauth-integration` is the intended pattern for the other four: it alone names the thing it cannot yet have ("the actual OAuth endpoint") inside its acceptance, so its `active` ending follows from its own acceptance. I judged it correct, not defective.
- `story:session-epochs`' acceptance carries a second assertion ("without changing eligibility in unrelated organization sessions") that maps to a separate case, `epoch-isolation`. I read it as one conjunctive scenario, decidable either way, and did not flag it; a stricter reading of the one-statement convention would.
- `story:domain-runtime`'s acceptance turns on "every formerly unresolved mutation", and `docs/architecture/unmapped.md` UNMAPPED-LIFECYCLE names classes ("deletion, reactivation, retention, execution completion or mapping transaction lifecycle") rather than an enumerated set; the story's `lifecycle-a`/`lifecycle-b` rows do enumerate the entities, which is what made me treat it as checkable. I could not confirm that `ess specify validate` — the story's named evidence — would fail if no transition were added.
- Out of my lane: `decision-blocker:jit-provisioning`'s clearance bullet requiring a concurrency case for two simultaneous first logins is disclaimed by `story:federation-linking` ("not expressible in this crate … belongs to the storage adapter"), and no artifact in this set owns the storage adapter. That is coverage, for `plan-critic-scope`, and it did not set my verdict. Likewise `story:credential-profiles` says `services/sts` cannot compile until `task:runtime-wave-integration` acts, while its own coordinator row owns `services/sts/Cargo.toml` and its `[lib]` target — a coupling/sequencing contradiction for `plan-critic-design`.

```findings
- file: .engineering/planning/story/federation-linking.md
  line: 50
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: "the acceptance is discharged in full by the eight cases this wave's units land (tests/authenticate.rs, tests/link.rs), while the new section says the story ends active, not implemented, so nothing in the body names the observation that moves it to implemented"
- file: .engineering/planning/story/credential-profiles.md
  line: 70
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: "the acceptance's revoke-then-introspect is the resolve unit's named deliverable this wave, yet the same body says \"This story ends its first wave `active`\", so the acceptance cannot distinguish the state the story ends in from the state in which it is done"
- file: .engineering/planning/story/graph-policy.md
  line: 78
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: "\"This story's own acceptance is the revocation unit's revision-bound denial suite exiting zero\" (line 110) is satisfied without the chosen adapter the title and the new section make the reason for ending active, so the acceptance names no outcome the story lacks at wave end"
- file: .engineering/planning/story/protocol-adapters.md
  line: 69
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: "the acceptance is case credential-containment, which the context unit is marked \"now\", while the section says the story ends active with no listener behind any of it, so the acceptance neither states that a library-level decode satisfies \"a product adapter decodes the request\" nor names what is still missing"
```
