---
format: aep.planning-md/1
id: architecture-design:foundations
kind: architecture-design
status: draft
title: Four deployment boundaries and shared contracts
relations:
- designs: specification:combined
revision: 2
---
# Four deployment boundaries and shared contracts

The normative combined design is `docs/architecture/combined.md`, which applies the architecture addendum ahead of the preserved original design. This record references that source instead of maintaining an independently editable duplicate.

`docs/architecture/ownership.md` maps all twelve ESS domains to the original fourteen libraries and the control-plane, authorization, STS and worker deployments. Core vocabulary is compiled into all deployments; its control-plane ESS publisher is not a remote runtime dependency. STS alone owns authorization-code verifier storage and atomic consumption/credential creation. Worker synchronization, cleanup and transport behavior remain explicit UNMAPPED obligations.

`docs/architecture/command-obligations.md` records the per-command adapter denial conditions from ESS. `docs/architecture/unmapped.md` and linked AEP blockers retain exact unsigned epoch values, conditional subject references, composite uniqueness, algorithm policy, durable audit, worker orchestration and other unsettled semantics. No lifecycle or runtime behavior is inferred from generated schemas.

The technical review records remain immutable. Source corrections and their validation are documented separately; this reference update is not a new critic verdict or a third planning review round.
