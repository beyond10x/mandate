---
format: aep.planning-md/1
id: review-result:federated-login-scope-r2
kind: review-result
status: active
title: Scope critic, round 2 — federated login story set
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
- reviews: epic:authentication
revision: 1
---
needs-revision

`story:signing-and-verification` — it claims "verify configured issuer/signature/client" as "Moved here from `story:federation-linking`", but that story retains "verify configured issuer and client binding" in its own Required observations and its moved-to sentence names only "signature verification, OIDC discovery/JWKS caching and key rollover" (`story/federation-linking.md:47`), so issuer and client verification will be marked done twice — `.engineering/planning/story/signing-and-verification.md:32`

`story:graph-policy-adapter` — it claims "backend types do not leak into domain" as "Moved here from `story:graph-policy`", but that story retains the same clause in its own Required observations and its moved-to sentence names only "choose graph and policy engine in ADR; concrete adapters; engine-issued consistency tokens; storage-level enforcement" (`story/graph-policy.md:73`), so one promise will be marked done twice — `.engineering/planning/story/graph-policy-adapter.md:32`

**Round-1 findings, both fixed.** Finding 1 (`epic:authentication`, "public authorization-code/S256 PKCE" unclaimed) is closed: `story/pkce-sessions.md:120` claims the command by name and `:54` gives it to the `candidate` unit up to the STS `IssueAuthorizationCode` port call, with `story/federation-linking.md:93` and `story/oauth-integration.md:81` now pointing at it consistently. Finding 2 (`story:check-api`, duplicate precedence) is closed: the unit is `ceilings` and reads "deny precedence itself is `story:graph-policy`'s `precedence` unit and is consumed through the port, not re-implemented" (`story/check-api.md:71`), matched by "the single home of precedence, consumed by `story:check-api`" (`story/graph-policy.md:102`).

**What I read.** The 4 parent bodies first, promise list written before any item; then all 14 judged items whole, my round-1 record, and sibling claimants reached by `rg` (`story:audit-client`, `story:constrained-exchange`, `story:agent-security`) — via `aep plan artifact show`, plus `graph`, `kinds`, `relations`, `validate`; in the tree `docs/architecture/combined.md:45-70` (the product-adapter route list) and `systems/mandate/components.yaml:1-80`. **47 promises extracted from the four parents; 46 traced to a claiming item, 1 traced to a recorded conditional deferral (tenancy creation, below).** The three new stories close round 1's only gap-adjacent holes cleanly: `story:product-listener` is the model — its "Moved here" list at `:35` matches `story/protocol-adapters.md:65` clause for clause, and `epic:authorization`'s "graph adapter" now has a story of its own.

**What I could not establish.**
- Whether `story:signing-and-verification`'s "an exercised emergency revocation path" is genuinely inherited: it is attributed to `story:credential-profiles`, whose body never names it and whose moved-to sentence at `:66` does not list it. It traces to `epic:sts-credentials`'s "revocation" and "JWKS/key rotation", so I did not call it reach.
- "service principals" (`epic/sts-credentials.md:16`) traces only to `story:agent-security` (`epic:agents-workloads`), outside this set; covered elsewhere is covered by my rule, but I read that story only through `rg`, not whole.
- Origin of both findings: the parent stories' retained sentences predate this round and the "Moved here" claims are new, so I recorded `introduced` rather than guess `pre-existing`.
- I did not read `feature-design:federated-login` or `docs/architecture/federated-login.md`.

**Closing, out of my lane and not setting my verdict.** `story:pkce-sessions:120` says `AuthorizePublicClient` "is control-plane-owned (`components.yaml`); the deployment that hosts it is `story:product-listener`'s", but `story:product-listener`'s scope is `services/sts`, `xtask` and `mandate-federation` — `services/control-plane` is in no item's scope, and `components.yaml:22` assigns the command to `mandate-control-plane`. I did not make it a gap: `combined.md:61`'s product-adapter list includes the OAuth authorization endpoint, so `story:protocol-adapters`' `routes` unit plus `story:product-listener`'s `listener` unit do claim serving it; which deployment serves it is design's. Same call as round 1 on parentage: `story:signing-and-verification` decomposes `epic:authentication` while carrying `epic:sts-credentials`' "asymmetric authentication" and "JWKS/key rotation", and `story:product-listener` decomposes `epic:sts-credentials` while serving `epic:authentication`'s "metadata" — each outcome is claimed exactly once, so how they were divided is design's. `story:check-api`'s body Scope section still lists `precedence.rs` and `tests/precedence.rs` (`story/check-api.md:107-108`) after the unit became `ceilings`; housekeeping, not coverage. Tenancy creation remains my closest call and still is not a finding: `epic/authorization.md:16` promises "org memberships, teams, spaces" and the disposition rests on a unit's report (`story/domain-runtime.md:132-134`, `story/tenancy-topology.md:44`) with no blocker holding it — unchanged from round 1. The validator's 10 prose-only review records are its own output and not restated here.

```findings
- file: .engineering/planning/story/signing-and-verification.md
  line: 32
  category: scope
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: "it claims \"verify configured issuer/signature/client\" as \"Moved here from story:federation-linking\", but that story retains \"verify configured issuer and client binding\" in its own Required observations and its moved-to sentence names only \"signature verification, OIDC discovery/JWKS caching and key rollover\" (story/federation-linking.md:47), so issuer and client verification will be marked done twice"
- file: .engineering/planning/story/graph-policy-adapter.md
  line: 32
  category: scope
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: "it claims \"backend types do not leak into domain\" as \"Moved here from story:graph-policy\", but that story retains the same clause in its own Required observations and its moved-to sentence names only \"choose graph and policy engine in ADR; concrete adapters; engine-issued consistency tokens; storage-level enforcement\" (story/graph-policy.md:73), so one promise will be marked done twice"
```
