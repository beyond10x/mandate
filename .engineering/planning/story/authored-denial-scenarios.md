---
format: aep.planning-md/1
id: story:authored-denial-scenarios
kind: story
status: draft
title: Authored scenarios drive the real denial paths the synthesizer cannot express
relations:
- decomposes: epic:foundations
- serves: vision:mandate
- depends_on: story:contract-creates
scope:
- confidence: cited
  path: systems/mandate/ess-inputs.yaml
- confidence: inferred
  path: systems/mandate/scenarios
revision: 3
---
## Acceptance

Given `systems/mandate/scenarios/*.yaml` (`ess-scenario/2`) listed in `systems/mandate/ess-inputs.yaml`, when `ess verify conform synthesize --path systems/mandate --scenarios systems/mandate --target ir` runs, then every authored scenario compiles into the suite, and each names a denial the real handler decides from a malformed or mismatched input rather than an injected fault.

## Why

Synthesized denials arm `configure_external_outcome` — a fault the runner injects. Mandate's standard requires the real validation path: a malformed proof through the verifier, a mismatched issuer, an ambiguous tenant, a wrong redirect.

## Scope

- `systems/mandate/scenarios/federation-issuer-mismatch.yaml`, `federation-audience-mismatch.yaml`, `federation-empty-subject.yaml`, `federation-untrimmed-subject.yaml`, `federation-configured-method-on-explicit-link.yaml`, `federation-ambiguous-tenant.yaml`, `federation-disabled-connection.yaml`, `federation-resolution-precedence.yaml` (1 → 3 → 2 → 4 → 6), `federation-malformed-proof.yaml` (double-backed until `story:signing-and-verification`), `pkce-malformed-challenge.yaml`, `pkce-redirect-mismatch.yaml`, `pkce-wrong-org-target.yaml`, `identity-stale-epoch-refresh.yaml`, `authz-cross-tenant-resource.yaml`, `authz-missing-approval.yaml` — inferred; ~15 files.
- `systems/mandate/ess-inputs.yaml` — cited; `scenarios:` lists them.

Format (`ess-scenario/2`): `arrange` (entity setup → `EstablishEntity`), `timeline` (`command`, `input`, `outcome: denied`, no `events`), `capture` where a later act needs an id. Each file's `summary` names the `command-obligations.md` clause it exercises.

### Units

One agent.

### Excluded

`systems/mandate/domains/*.yaml`, `generated/`, every crate.

### Gate

`ess verify conform synthesize --path systems/mandate --scenarios systems/mandate --target ir --compact --out <scratch>/suite.json` exit 0; report the authored count and the total.
