---
format: aep.planning-md/1
id: story:authored-denial-scenarios
kind: story
status: active
title: Authored scenarios drive the real denial paths the synthesizer cannot express
relations:
- decomposes: epic:foundations
- serves: vision:mandate
- depends_on: story:contract-creates
- informed_by: initiative:drift-enforcement
scope:
- confidence: cited
  path: systems/mandate/ess-inputs.yaml
- confidence: inferred
  path: systems/mandate/scenarios
revision: 8
---
## Acceptance

Given `systems/mandate/scenarios/*.yaml` (`ess-scenario/2`) listed in `systems/mandate/ess-inputs.yaml`, when `ess verify conform synthesize --path systems/mandate --scenarios systems/mandate --target ir` runs, then every authored scenario compiles into the suite, and each names a denial the real handler decides from a malformed or mismatched input rather than an injected fault.

## Why

Synthesized denials arm `configure_external_outcome` — a fault the runner injects. Mandate's standard requires the real validation path: a malformed proof through the verifier, a mismatched issuer, an ambiguous tenant, a wrong redirect.

## Scope

Derived 2026-09-19 by `story-scoper` at `integration/wave-20260919-005` `75f41b5`. **cited** = read or measured with `ess 0.26.0`; **inferred** = a reading that could be wrong.

- **Primary surface:** `systems/mandate/scenarios/` (new) and `systems/mandate/ess-inputs.yaml:17` (`scenarios: []` today; `--scenarios systems/mandate` refuses against an empty list).
- **Format, verified by compiling a probe against the model:** `type: ess-scenario/2`, `domain`, `scenario`, `summary`, `arrange[].{instance, entity, setup?}`, `timeline[].{at, command, input, outcome, error, events, no_events, capture}`; `outcome` must be a declared outcome name (`accepted`/`denied`/`wrong-state`); a `denied` outcome compiles to `expect_outcome` + `expect_error` and is never armed — the real handler decides; `input` is total (every declared field, `null` for optionals); `Bytes` newtypes need padded base64. `arrange` without `setup` is a capture name; `setup:` compiles to `establish_entity` (a target capability). Probes at `<scratch>/probe-issuer-mismatch.yaml`, `probe-pkce-redirect.yaml`.
- **Cases (each with the landed clause):** federation — issuer mismatch (`authenticate.rs:252`), audience mismatch (`:259`), empty subject (`:268`), untrimmed subject (`:275`), `ConfiguredFederation` on an explicit link (`link.rs:93-97`), ambiguous tenant (`:349`), disabled connection (`:243`), resolution-order precedence, malformed proof (`verifier_real.rs:1281`); STS — malformed PKCE challenge (`code.rs:641`), redirect mismatch (`binding.rs:219`), wrong-org target (`binding.rs:316-326`), `pkce-wrong` (`redemption.rs:240`), `pkce-reuse` (`wrong-state`, `redemption.rs:321`), code expired (`:330`), stale session epoch (`binding.rs:277`), introspection audience mismatch (`resolve.rs:492`), revoked-then-introspect (`:582`), the disabled-registration caller (`registry.rs:258`/`code.rs:436`); identity — stale epoch on refresh (`snapshot.rs:73`); authz — cross-tenant resource (`context.rs:107`), missing approval (`decision.rs:232`). ~22 files.
- **Sequencing:** lands first — synthesize counts authored files with no target (146 → 147 with one probe; 52 refusals unchanged); scenarios that need a Session use `setup:` and report `unsupported` until `story:conformance-target`'s `establish_entity` supports it (recorded there as ruling 4).
- **Gate:** `ess verify conform author --path systems/mandate --scenarios systems/mandate --out <scratch>/authored.json` (refuses any unresolved name) and `ess verify conform synthesize … --suite-format 5 --out <scratch>/suite.json`, both counts reported; `ess specify validate` unaffected. No cargo step; no `generated/` byte moves until the target lands.
- **Would collide with:** any unit editing `ess-inputs.yaml`; semantically with `story:declared-writers`' domain yamls (file-disjoint, model-coupled; no unit of it runs this wave).

## Rulings — wave D enforcement track, 2026-09-19

Coordinator, wave D enforcement track, 2026-09-19.

1. The story lands first in the enforcement track; its files are authored against the model at `75f41b5`; the coordinator re-runs the two `ess` gates at every later merge of the wave.
2. Scenarios needing a live Session are authored with `setup:` on `mandate.identity.Session` and are the reason `story:conformance-target` supports `establish_entity` for it.
3. `pkce-reuse` is authored as the `wrong-state` outcome (the contract's), not `denied`.
4. `DenialClause` is crate-local; authored scenarios assert `DenialReason` on the wire error and name the clause in `summary`.
5. The wave B/C denials with landed clauses are in scope (22 files, not 15).

- Note after `review-result:wave-d-enforcement-design-r1`: three federation scenarios (issuer mismatch, empty subject, untrimmed subject) share `DenialReason::InvalidCredential` on the wire and therefore pass on each other's clause; clause-level binding is `story:obligation-registry`'s, which binds each clause to a real-path Rust test. The suite proves the outcome and reason; the registry proves the clause.
