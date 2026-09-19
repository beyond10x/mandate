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
revision: 13
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

- From the implementor (2026-09-19): 23 files (the disabled-registration caller is two refusals in two commands); `summary` has a 200-character cap (`ess-conformance/src/scenario.rs:995`); redirect mismatch answers `DenialReason::Denied` (`services/sts/src/binding.rs:217-221`, `code.rs:489-492`), not `InvalidCredential` as the scoper's probe claimed; the link path reads the federation link projection, so the entity the target seeds for it is `mandate.federation.ExternalPrincipal`, not `mandate.identity.Principal` (routed to `story:conformance-target`); `pkce-reuse` uses `setup:` on `mandate.credential.AuthorizationCode` in `Consumed`; introspecting a revoked credential is `accepted` with `active: false` (`registry.rs:216-222`), so the revoked case is the second revocation's `wrong-state`. Suite 146 → 169 scenarios, 23 authored, 52 refusals unchanged, 0 `configure_external_outcome` steps in the authored half. Cases whose intended clause a file cannot reach (proofs the real verifier refuses; minted secrets a file cannot capture; tenancy state no port seeds) are named in the story's report and hit an earlier clause with the same reason in most cases.

- Correction 1 result (2026-09-19): 21 files (23 → 21: `identity-stale-epoch-refresh` dropped per ruling 5; `authz-missing-approval` dropped because `decision.rs:232` sits behind the audience and placement guards in `context.rs`, neither establishable while `mandate.graph.RegisterResource` has no port — routed to `story:graph-policy-adapter`); suite 146 → 167, refusals 52 → 52; probes `clauses`, `files`, `reason_vs_clause` exit 0; 0 duplicated corpus rows; every file's asserted clause is the first-firing guard, table in the implementor's report. Two rulings measured wrong and replaced by the reachable first guard: (1) `setup:` on `AccessCredential` cannot carry `target` (`ESS-AUTHOR-015`, the entity declares `descriptor, reference_verifier, epochs, issued_at`), so the introspection file asserts `CallerProofInvalid` (`resolve.rs:427`) as `introspect-caller-proof-malformed`; (2) an ESS input admits `$instance` only at the top level of a field, never inside a struct, so `Check` cannot name the organization a `CreateOrganization` step allocated and the authz file asserts `InvalidCredential` from `context.rs:103` as `authz-unadmitted-organization`. The seeded redemption files bind the suite to `Sha256Digest` (verifier `f7fc02f9…` for `presented-authorization-code`); a target installing another `CredentialDigest` reds all four with `CodeProofMismatch` — recorded on `story:conformance-target`.

- Correction (2026-09-19): the routing above to `story:session-epochs` is withdrawn — that story is `implemented`; the live home is `story:epoch-snapshot-generations`.

- Correction 2 result (2026-09-19): 20 files, suite 167 → 166, refusals 52; the five claim-driven summaries name `mandate_conformance::external::ScenarioVerifier`; `pkce-stale-session-epoch` dropped → `story:epoch-snapshot-generations`; routing comment names live stories only (`epoch-snapshot-generations`, `graph-policy-adapter`, `declared-writers`); the dangling `server` step removed; the precedence file's proof is one opaque segment no verifier decodes. Unit committed as the bot and merged. Coordinator deviation: the adversary file `crates/mandate-token/tests/adversary_authored_2.rs` (counts 21 → 20 and 4 → 3, rustfmt, cases 2 and 3 rewritten to the rulings: the double named by symbol; the payload carries the claims the decode-only double reads) is held back and lands in the alignment commit after the conformance unit merges, since its case 2 reads `crates/mandate-conformance/src/external.rs` and is red until then. Acceptance evidence for "a wrong reason is detected" is the coordinator's `mandate-conform` run over the merged head, recorded at wave close.

- Correction (2026-09-19): the sentence "Unit committed as the bot and merged" above is wrong — the bot commit was refused by the `b10x-gates` pre-commit hook: 13 secret-scanner findings (`jwt` and `jwt-base64` on the six federation files' base64-encoded compact-JWS proofs; `generic-api-key` on `introspect-caller-proof-malformed.yaml:11`). The fixtures are synthetic (signature segment is the ASCII word `signature`); admitting them is a trusted-policy change (`b10x-gates policy except`), which is the operator's. The unit stays uncommitted in its tree until then; the merge order moves it last.
