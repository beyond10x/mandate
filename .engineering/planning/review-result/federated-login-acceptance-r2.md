---
format: aep.planning-md/1
id: review-result:federated-login-acceptance-r2
kind: review-result
status: active
title: Acceptance critic, round 2 — federated login story set
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

story:signing-and-verification — the acceptance joins two independent outcomes with `and` under contradictory givens — "the eight federation cases pass with no test double in the chain **and** a token signed under a non-admitted algorithm is refused" — so the refusal can fail while the eight cases pass and the story is neither done nor not done — .engineering/planning/story/signing-and-verification.md:28
story:graph-policy-adapter — the acceptance joins two outcomes, "it exits zero **and** `graph-revocation` passes at the required revision with a consistency token the engine issued", and the second executes in `story:check-api`'s crate (graph-policy.md:109, `cases.json:615` carries `story: story:graph-policy` on a `mandate.authorization.Check` case) which the story's own `cargo test -p mandate-graph -p mandate-policy` does not run — .engineering/planning/story/graph-policy-adapter.md:28
story:product-listener — the acceptance joins two independent outcomes, "exactly one correctly scoped credential is issued **and** the generated `/<domain>/commands/<Command>` paths are not reachable", so a listener that issues the credential and also exposes the generated paths satisfies one half and fails the other — .engineering/planning/story/product-listener.md:31
story:product-listener — the acceptance's *given* is "the redemption transaction `story:oauth-integration` implements", and that story carries `depends_on story:product-listener` (oauth-integration.md:14) while this one carries no edge to it, so at the moment this story's units land the thing its check reads does not exist and the body names no observation that can be made instead — .engineering/planning/story/product-listener.md:31

**What I read:** all 14 ids I was given, all 14 read in full — `aep plan artifact show review-result:federated-login-acceptance-r1`, `aep plan artifact kinds`, `aep plan artifact lifecycle story`, `aep plan artifact lifecycle decision-blocker`, `cat -n` on the 13 story files and `decision-blocker/jit-provisioning.md` in the worktree store, the rubric, plus `grep` in the tree for `graph-revocation` in `tests/security/cases.json:613-619` and `ls docs/adr/` (no `0010-*`).

**Round-1 findings, all four:** fixed, and I do not repeat them. `story:federation-linking` now names the observation that moves it (`federation-linking.md:51`, "the story moves to `implemented`"); `story:credential-profiles` likewise (`credential-profiles.md:70`); `story:graph-policy` names the suite and drops the adapter from the title (`graph-policy.md:77`, `:6`); `story:protocol-adapters` now states that a library-level decode satisfies "a product adapter decodes the request" and names the listener as the follow-on (`protocol-adapters.md:69`).

**What I could not establish:**
- `story:session-epochs`' acceptance still carries "without changing eligibility in unrelated organization sessions", mapping to a separate case `epoch-isolation`. Round 1 read it as one conjunctive scenario and did not flag it; I read it the same way again with no new evidence, and a stricter reading of the one-statement rule would flag it.
- `story:domain-runtime`'s "every formerly unresolved mutation" is still enumerated only by the `lifecycle-a`/`lifecycle-b` rows against `unmapped.md` UNMAPPED-LIFECYCLE's classes; I could not confirm that `ess specify validate` — the story's named evidence — fails if a transition were omitted.
- Three of the new stories have units their one acceptance sentence does not reach (`signing-and-verification`'s `token-signer`, `product-listener`'s `port-adapters` and metadata document, `graph-policy-adapter`'s ADR row). Round 1 did not flag the same shape on `story:graph-policy` (11 units, one unit's suite) or `story:check-api`, so I did not flag it here either; whether that is an acceptance defect or a decomposition one I could not settle.
- Out of my lane, and not setting my verdict: the direction of the `story:oauth-integration` ↔ `story:product-listener` pair is sequencing for `plan-critic-design` — I filed only the acceptance half, that `story:product-listener`'s check cannot be performed when that story completes. `decision-blocker:jit-provisioning`'s concurrency bullet (`jit-provisioning.md:35`) is still disclaimed by `story:federation-linking:81` and owned by no artifact in this set — coverage, for `plan-critic-scope`, unchanged from round 1.

```findings
- file: .engineering/planning/story/signing-and-verification.md
  line: 28
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: "the acceptance joins two independent outcomes with and under contradictory givens — \"the eight federation cases pass with no test double in the chain and a token signed under a non-admitted algorithm is refused\" — so the refusal can fail while the eight cases pass and the story is neither done nor not done"
- file: .engineering/planning/story/graph-policy-adapter.md
  line: 28
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: "the acceptance joins two outcomes, \"it exits zero and graph-revocation passes at the required revision with a consistency token the engine issued\", and the second executes in story:check-api's crate (graph-policy.md:109, cases.json:615 carries story: story:graph-policy on a mandate.authorization.Check case) which the story's own cargo test -p mandate-graph -p mandate-policy does not run"
- file: .engineering/planning/story/product-listener.md
  line: 31
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: "the acceptance joins two independent outcomes, \"exactly one correctly scoped credential is issued and the generated /<domain>/commands/<Command> paths are not reachable\", so a listener that issues the credential and also exposes the generated paths satisfies one half and fails the other"
- file: .engineering/planning/story/product-listener.md
  line: 31
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: "the acceptance's given is \"the redemption transaction story:oauth-integration implements\", and that story carries depends_on story:product-listener (oauth-integration.md:14) while this one carries no edge to it, so at the moment this story's units land the thing its check reads does not exist and the body names no observation that can be made instead"
```
