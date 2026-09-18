---
format: aep.planning-md/1
id: review-result:federated-login-scope-r1
kind: review-result
status: active
title: Scope critic, round 1 — federated login story set
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
- reviews: epic:authentication
revision: 1
---
needs-revision

`epic:authentication` — "public authorization-code/S256 PKCE" is promised and no drafted item claims `mandate.federation.AuthorizePublicClient`, the command that validates session/client/redirect/S256/state and issues the code: `story/federation-linking.md:88` excludes it as "owned with `story:pkce-sessions` and `story:oauth-integration`", `story/oauth-integration.md:100` excludes it and stands in with a fixture at `:80` ("control-plane-owned"), `story:pkce-sessions` never names it, and `services/control-plane` is in no story's scope — `.engineering/planning/epic/authentication.md:16`

`story:check-api` — its `precedence` unit produces "ceiling intersection; denies override grants", the same outcome `story:graph-policy`'s `precedence` unit produces and lists at `story/graph-policy.md:114` as "the deny-precedence combinator" it supplies to this story, so one promise will be marked done twice — `.engineering/planning/story/check-api.md:71`

**What I read.** 4 parent bodies first and their promise lists written down before any item; then all 11 judged items plus 8 sibling/context artifacts (`story:audit-client`, `constrained-exchange`, `directory-provenance`, `audit-worker-delivery`, `foundation-contracts`, `agent-authority-kernel`, `agent-security`, `task:runtime-wave-integration`), `decision-blocker:lifecycle`, and the two prior scope reviews — via `aep plan artifact show`, plus `graph`, `kinds`, `relations`, `validate`; in the tree `systems/mandate/domains/*.yaml` (full command inventory), `docs/requirements.md:138-158`, `docs/architecture/ownership.md:20-30`, `combined.md:51-56`, and `git show HEAD:` on two story files to set origin. **47 promises extracted from the four parents; 45 traced fully to a claiming item, 1 traced only in part (finding 1), 1 traced to a recorded conditional deferral (tenancy creation, below).**

**What I could not establish.**
- I did not read `feature-design:federated-login`'s body or `docs/architecture/federated-login.md`; a recursive grep of the store shows neither names `AuthorizePublicClient`, but a decision recorded in the tree document could assign it.
- Origin of finding 1 is mixed: at `HEAD` no artifact named `AuthorizePublicClient` at all, so the uncovered command predates today, while the false ownership pointer in `story:federation-linking` is new; I recorded `introduced` rather than guess `pre-existing`.
- Whether `mandate.identity.DisablePrincipal` is deliberately unowned: `story:session-epochs:278` excludes "`DisablePrincipal`'s authority half" and nothing names the other half.

**Closing, out of my lane and not setting my verdict.** Tenancy creation is my closest call and I did not make it a finding: `epic:authorization.md:16` promises "org memberships, teams, spaces" and no item's outcome claims creating them, but `story:tenancy-topology:41-44` and `story:domain-runtime:110` both record the deferral and name the re-scope, which the rubric treats as an honest omission — my unease is that, unlike JIT, no blocker holds it (`decision-blocker:lifecycle` names deletion, reactivation, retention, execution completion and mapping transactions, not creation) and the disposition rests on a unit's report; raising the JIT-shaped blocker would settle it. `RevokeRefreshCredential` and `UnlinkExternalPrincipal` are declared commands no story owns, both recorded as unowned/excluded and neither a sentence in any parent, so they are not gaps by my rule. `story:domain-runtime`'s acceptance covers only lifecycle transitions while its body now also delivers the JIT command and three epoch fields — acceptance's lane. `story:protocol-adapters` decomposes `epic:sts-credentials` but delivers metadata (`epic:authentication`) and audit ingress (`epic:authorization`/`epic:hardening`); each outcome is claimed exactly once, so how they were divided is design's lane.

```findings
- file: .engineering/planning/epic/authentication.md
  line: 16
  category: scope
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: "\"public authorization-code/S256 PKCE\" is promised and no drafted item claims mandate.federation.AuthorizePublicClient, the command that validates session/client/redirect/S256/state and issues the code: story/federation-linking.md:88 excludes it as \"owned with story:pkce-sessions and story:oauth-integration\", story/oauth-integration.md:100 excludes it and stands in with a fixture at :80 (\"control-plane-owned\"), story:pkce-sessions never names it, and services/control-plane is in no story's scope"
- file: .engineering/planning/story/check-api.md
  line: 71
  category: scope
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: "its precedence unit produces \"ceiling intersection; denies override grants\", the same outcome story:graph-policy's precedence unit produces and lists at story/graph-policy.md:114 as \"the deny-precedence combinator\" it supplies to this story, so one promise will be marked done twice"
```
