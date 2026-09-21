---
format: aep.planning-md/1
id: story:ess-evidence-suite-version
kind: story
status: draft
title: The store can record the conformance run this repository produces
relations:
- decomposes: epic:foundations
- serves: vision:mandate
revision: 1
---
# AEP cannot read the suite this repository synthesizes

## Why

`docs/adr/0010-drift-enforcement.md` binds conformance evidence to
`executable-system-specification:mandate` through
`aep plan artifact evidence --from <report> --suite <suite>`. That call is
refused:

```
error: UnsupportedSuiteVersion at $.suite.version: ess-conformance/9
```

`generated/conformance/suite.json` declares `suite_version:
ess-conformance/9` in its provenance. AEP at protocol 0.55.0 admits
`ess-conformance/1` through `/6`. Measured 2026-09-22.

So no wave can record a conformance run against the ESS artifact through the
sanctioned path, and this recurs at every close until it is fixed. The
artifact's `model_digest` and its `validated` rung are unaffected — neither takes
a suite — and `conforming` is unreachable for an unrelated reason (59 unmet
scenarios), so nothing is currently blocked **except the record itself**.

That is the point. The evidence rung exists so a later reader can check which run
a claim rests on. A wave that cannot write it leaves the artifact saying what was
true at some earlier head.

## What this story delivers

One of:

- AEP admits `ess-conformance/7` through `/9`. That work is in the `aep`
  repository, not here; this story tracks the change and the repin. The pin is
  `.engineering/project.yaml`.
- Or `docs/adr/0010-drift-enforcement.md` is amended to say which record carries
  the run when the store cannot, and where a reader finds it.

The first is right if the suite format is stable. The second is right if this
repository will keep moving ahead of AEP, in which case ADR 0010 currently
describes a path that does not exist.

Do not take the third option of writing the evidence some other way. The store is
AEP's to write, and a hand-made record is the unvalidated claim the whole
registry programme exists to refuse.

## Acceptance

`aep plan artifact evidence executable-system-specification:mandate --from
generated/conformance/report.json --suite generated/conformance/suite.json`
exits 0 on a current head, or ADR 0010 names what replaces it and the wave-close
sequence is corrected to match.

## Out of scope

Reaching `conforming`. That needs the 59 unmet scenarios, not this.
