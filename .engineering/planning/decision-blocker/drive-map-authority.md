---
format: aep.planning-md/1
id: decision-blocker:drive-map-authority
kind: decision-blocker
status: open
title: Reconcile driver artifact-write prompts with denied planning scope
relations:
- blocks: task:canonical-types-drive
revision: 1
---
# Driver map write ownership is undecided

The canonical map asks receive/specify/decompose model steps to write AEP artifacts while denying .engineering/planning/** in their first scope rule. Evidence: .engineering/drivers/canonical-types.yaml:15, :44, :60, :74 and :90; verification-report:canonical-driver-readiness.

Before launch, explicitly decide whether those artifacts are prepared externally or written by an admitted driver-controlled writer, revise prompts/scopes consistently, and demonstrate required artifact/evidence production with the intended hook configuration. Preserve a single planning-store writer and driver lifecycle ownership; do not bypass hooks, ignore missing evidence or simply broaden every model step's scope. Clear only on reviewed design and observed verification. The separate missing property verifier remains blocked independently.
