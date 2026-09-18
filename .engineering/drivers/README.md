# Driver step maps

`canonical-types.yaml` is an AEP execution recipe for the separate task in
`../tasks/canonical-types.yaml`, derived from `story:canonical-types`. It maps workflow
states to model, command and operator steps, declares write scopes, and names the evidence
required to proceed. It is an alternative lifecycle owner to an interactive Wave, not a
CI workflow, branch integration policy or record of a completed run.

As checked on 2026-09-18, **no local run is recorded**, and the original handoff says it
was never launched. `aep drive status` reports `no runs in ./.engineering/runs`.
The task resolves under the pinned protocol root,
and a disposable tree containing that protocol snapshot plus this map passes
`aep govern validate` (61 documents, three step maps). These are configuration checks,
not successful execution evidence.

It is **not launch-ready**:

- `cargo xtask type-properties --out <record>` is required by the map but is absent from
  the current xtask command enum. `decision-blocker:drive-verifier` remains open.
- The receive/specify/decompose prompts require planning-store writes, while each model
  step explicitly denies `.engineering/planning/**`. The write-owner design must be
  reconciled before launch; silently removing the denial is not an approved fix.
- Task review, a complete accepted-type/exclusion inventory, an admitted harness/plugin
  configuration, and operator-supplied budget and assumed cost remain required. Model
  execution and task-specific evidence production have not been demonstrated here.

`verification-report:canonical-driver-readiness` records these observations and
`decision-blocker:drive-map-authority` tracks the scope/prompt conflict. No run was launched
to answer the readiness question. The normal Mandate delivery flow is documented in
`../../docs/adr/0008-integration-batches.md`; a future driven run must feed that integration
branch and must not compete with a Wave for the same story's lifecycle.
