---
format: aep.planning-md/1
id: decision-blocker:drive-verifier
kind: decision-blocker
status: open
title: Mandate property evidence verifier is required before Drive launch
relations:
- blocks: task:canonical-types-drive
revision: 1
---
Implement and independently review the evidence-producing `cargo xtask type-properties --out <record>` verifier before any Drive launch; match AEP property_test_result schema and retained observed evidence. No missing evidence bypass. Spending limits and explicit task review are separately required.
