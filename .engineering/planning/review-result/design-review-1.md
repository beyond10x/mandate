---
format: aep.planning-md/1
id: review-result:design-review-1
kind: review-result
status: active
title: 'Design review 1: combined architecture against components, sources and gate'
relations:
- reviews: architecture-design:foundations
- reviews: specification:combined
- reviews: story:canonical-types
revision: 1
---
needs-revision

architecture-design:foundations — one-time code redemption is split into `federation.ConsumeAuthorizationCode` on the control plane and `credential.RedeemAuthorizationCode` on STS with no binding between them, so the atomic one-use consumption the body requires spans two deployment boundaries and the body does not say which one is authoritative — .engineering/planning/architecture-design/foundations.md:63; systems/mandate/domains/federation.yaml:189-207; systems/mandate/domains/credential.yaml:120-149; systems/mandate/components.yaml:23; systems/mandate/components.yaml:87; generated/docs/interactions.md:14

architecture-design:foundations — the body assigns asynchronous audit/export, cleanup and synchronization orchestration to the worker, but `components.yaml` gives the worker only `mandate.audit` with no accepted command and places `SyncJob` and `SyncDirectoryMembership` on the control plane — .engineering/planning/architecture-design/foundations.md:25; systems/mandate/components.yaml:32; systems/mandate/components.yaml:104-115; systems/mandate/domains/directory.yaml:162-189

architecture-design:foundations — `components.yaml` says library ownership is documented separately and no document maps the 12 ESS domains to the 14 library crates, so the body's finer library boundaries cannot be checked against the contract — systems/mandate/components.yaml:12; .engineering/planning/architecture-design/foundations.md:25; grep -rn "mandate-model" docs/ .engineering/planning/architecture-design (no mapping hit); dependency-boundaries.json:2-58

architecture-design:foundations — `components.yaml` assigns `mandate.core` to the control-plane deployment although all four deployments consume it, so the shared vocabulary has a single deployment owner the body does not name — systems/mandate/components.yaml:5; .engineering/planning/architecture-design/foundations.md:25

architecture-design:foundations — the body exists twice, here and in `docs/architecture/combined.md`, and the two already differ at one line, so neither copy is named normative — .engineering/planning/architecture-design/foundations.md:29; docs/architecture/combined.md:19; diff docs/architecture/combined.md against the artifact body (1 hunk)

architecture-design:foundations — `docs/requirements.md` assigns 7 non-audit original sections (§19 consistency and caching, §30 threat model, §33 tests, §34 observability, §35 availability, §36 administrative security, §52 release checklist) to `mandate.audit` as ESS owner, so the traceability column names a domain that owns none of that content — docs/requirements.md:26; docs/requirements.md:37; docs/requirements.md:40-43; docs/requirements.md:59

story:canonical-types — the dependency gate allows a library only the mandate crates listed for it and no external crate, so the deterministic serialization this story requires cannot pass `cargo xtask boundaries` without editing `dependency-boundaries.json`, which is outside the story's declared scope — xtask/src/main.rs:119; dependency-boundaries.json:3; .engineering/planning/story/canonical-types.md:30; .engineering/planning/story/canonical-types.md:32-38

Read: `aep plan artifact show architecture-design:foundations`, `specification:combined`, `vision:mandate`, `epic:foundations`, `story:foundation-contracts`, `story:canonical-types`, `task:canonical-types-drive`, 7 decision-blockers and 6 earlier review-results; `docs/architecture/combined.md`, `docs/architecture/unmapped.md`, `docs/requirements.md` (282 lines), `docs/threat-model/README.md`, 7 ADRs, `docs/vision.md`, `docs/handoff.md`, `docs/verification.md`, `docs/review-provenance.md`, `AGENTS.md`, `README.md`; original §9, §11, §48, §49 and addendum §6, §7, §14, §15 by line range; all 16 ESS files, `components.yaml`, `dependency-boundaries.json`, `xtask/src/main.rs`, `.github/workflows/*.yml`, `generated/docs/{interactions,topology,crossings}.md`. Ran `diff` between the two design copies (1 hunk), `grep -rn` for a crate-to-domain mapping (none), `cargo xtask corpus|boundaries|contracts` (each exit 0), `aep plan artifact validate` (valid, 4 advisories).

Could not establish: whether ESS bindings are the intended mechanism for the STS-to-control-plane code consumption or a runtime adapter is; the body says neither.
Could not establish: any runtime behaviour; none exists in the scaffold.
Outside this lane: the 16 contract-level type findings are recorded in `review-result:contracts-review-1`; plan shape, acceptance wording, coverage and parallel safety were judged by the four earlier critic rounds and are not re-judged here.

```findings
- file: .engineering/planning/architecture-design/foundations.md
  line: 63
  category: design
  severity: blocker
  verdict: needs-revision
  origin: pre-existing
  message: "one-time code redemption is split into `federation.ConsumeAuthorizationCode` on the control plane and `credential.RedeemAuthorizationCode` on STS with no binding between them, so the atomic one-use consumption the body requires spans two deployment boundaries and the body does not say which one is authoritative"
- file: .engineering/planning/architecture-design/foundations.md
  line: 25
  category: design
  severity: blocker
  verdict: needs-revision
  origin: pre-existing
  message: "the body assigns asynchronous audit/export, cleanup and synchronization orchestration to the worker, but `components.yaml` gives the worker only `mandate.audit` with no accepted command and places `SyncJob` and `SyncDirectoryMembership` on the control plane"
- file: systems/mandate/components.yaml
  line: 12
  category: design
  severity: warning
  verdict: needs-revision
  origin: pre-existing
  message: "`components.yaml` says library ownership is documented separately and no document maps the 12 ESS domains to the 14 library crates, so the body's finer library boundaries cannot be checked against the contract"
- file: systems/mandate/components.yaml
  line: 5
  category: design
  severity: warning
  verdict: needs-revision
  origin: pre-existing
  message: "`components.yaml` assigns `mandate.core` to the control-plane deployment although all four deployments consume it, so the shared vocabulary has a single deployment owner the body does not name"
- file: .engineering/planning/architecture-design/foundations.md
  line: 29
  category: design
  severity: warning
  verdict: needs-revision
  origin: pre-existing
  message: "the body exists twice, here and in `docs/architecture/combined.md`, and the two already differ at one line, so neither copy is named normative"
- file: docs/requirements.md
  line: 26
  category: design
  severity: warning
  verdict: needs-revision
  origin: pre-existing
  message: "`docs/requirements.md` assigns 7 non-audit original sections (§19 consistency and caching, §30 threat model, §33 tests, §34 observability, §35 availability, §36 administrative security, §52 release checklist) to `mandate.audit` as ESS owner, so the traceability column names a domain that owns none of that content"
- file: xtask/src/main.rs
  line: 119
  category: design
  severity: warning
  verdict: needs-revision
  origin: pre-existing
  message: "the dependency gate allows a library only the mandate crates listed for it and no external crate, so the deterministic serialization this story requires cannot pass `cargo xtask boundaries` without editing `dependency-boundaries.json`, which is outside the story's declared scope"
```
