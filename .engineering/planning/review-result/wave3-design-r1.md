---
format: aep.planning-md/1
id: review-result:wave3-design-r1
kind: review-result
status: active
title: Design critic, round 1 — wave 3 set
relations:
- reviews: story:check-api
- reviews: story:pkce-sessions
- reviews: story:event-payloads-for-folds
- reviews: story:gate-reads-document-deliverables
revision: 1
---
```
set: story:check-api, story:pkce-sessions, story:event-payloads-for-folds, story:gate-reads-document-deliverables — execution wave 3
verdict: needs-revision
findings: 1 (medium)
```

## Findings

```yaml
verdict: needs-revision
findings:
  - id: D1
    severity: medium
    artifact: story:event-payloads-for-folds
    location: ".engineering/planning/story/event-payloads-for-folds.md:123-127"
    message: "the story's own Gate lists only schema-level coordinator duties (ess validate, xtask generate/contracts, raise the 65-event pin, retire the adversary_tenancy_topology tripwire) and never names who edits crates/mandate-federation/src/record.rs to fold the four new ExternalPrincipalLinked fields this story adds; pkce-sessions flags the same gap as an unresolved 'semantic hazard' (.engineering/planning/story/pkce-sessions.md:102) but neither story, nor a coordinator ruling here, assigns an owner"
```

## Summary

The four items share no files and no `depends_on` edges among themselves or with `directory-provenance`/`declared-writers`/`testkit-doubles` — 44 `depends_on` edges reachable from the set plus reverse edges from those three artifacts all terminate at already-`implemented` ancestors (`canonical-types`, `domain-runtime`, `runtime-decision-dossier`, `foundation-contracts`); no cycle. The `pkce-sessions` → `Projection::clients()` gap onto `story:declared-writers` is disclosed in `pkce-sessions`' "Not established". The `crates/mandate-federation/src/lib.rs` edit each of `pkce-sessions`, `signing-and-verification`, `product-listener` makes is bounded (mod lines / `DenialClause` only) and ordered by `depends_on`. The one open seam is D1.

## Read

The four story bodies in full; `story:signing-and-verification` and `story:product-listener` for the `lib.rs` bound; `aep plan artifact relations`, `graph` (full and filtered), `validate` (valid). Not read: `crates/mandate-federation/src/record.rs`'s body, so whether D1 is cosmetic or functionally blocking was not established by the critic.

## Noted, not judged

`story:declared-writers`' "must not share a wave" collision with `story:event-payloads-for-folds` (six shared domain-yaml files) has no `blocks` edge in the graph; `declared-writers` is not in this wave's set.
