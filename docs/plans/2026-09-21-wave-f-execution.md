# Wave F — clear `decision-blocker:guards`

Opened 2026-09-21. Integration branch `integration/wave-20260921-006`, cut from `997100d` — the
last all-bot commit, whose tree equals `main`'s at `8fcec8e`. Cutting from `main` itself would make
GitHub's own merge commits ancestors, and the organization push guard refuses a lineage containing
a commit whose committer is `GitHub <noreply@github.com>`; that is what broke publication at
`7650d7e` during wave D's close.

Skill version: `aep-drive:wave` 0.9.2. AEP protocol 0.55.0.

## Why this wave

Wave D's second half measured what the contract publishes as a refusal against what the crates
decide: **190 clauses, 83 real, 21 double-only, 86 deferred**. Counting every `blocked_on`
reference across `contracts/obligations/*.json` (136), three items hold 99:

| blocker | refs | crates |
|---|---|---|
| `decision-blocker:guards` | 45 | sts 13 · model 14 · authz 5 · graph 5 · federation 3 · identity 3 · policy 2 |
| `story:graph-policy-adapter` | 31 | graph 19 · policy 10 · authz 2 |
| `decision-blocker:epoch-atomicity` | 23 | sts 7 · model 9 · identity 4 · federation 2 · graph 1 |

`guards` is the largest and the only one of the three needing no third-party engine selection. The
other two stay blocked: `graph-policy-adapter` on `decision-blocker:backend`, `:lifecycle` and
`:subject-relations`; `epoch-atomicity` on a persistence design that does not exist.

The 45 clauses classify: **31 caller authority**, 8 credential-derived context, 4 value admission,
2 trusted caller context.

## The selection

`aep plan artifact waves --kind story --status draft --format json` returned five waves, eight
collisions and eleven unassessed stories. Its output is reproduced in the wave-F proposal report and
is **not** the selection this wave ran, for one reason: the verb reads typed scope entries and does
not read blockers. Every story in its wave 1 — `agent-authority-kernel`, `audit-client`,
`directory-provenance`, `graph-policy-adapter` — carries an open `decision-blocker`.

Wave F is built instead from stories that **clear** a blocker rather than wait on one. Three were
created for it on 2026-09-21: `story:caller-authority-split`, `story:tenancy-authority`,
`story:credential-context-guards`.

**Selection path:** the verb was run and its three lists recorded; the set was then chosen by
reading blockers, which the verb does not model. Scope entries were written by the coordinator from
the bodies it authored, not by `story-scoper` agents — every entry is `cited` because every path is
named in the body it came from. Stated here so a reader can tell a coordinator-written scope from a
scoped one.

## Units

Two rounds. `story:caller-authority-split` gates rounds 2, so nothing is dispatched against an
assumed split.

### Round 1 — disjoint, dispatched together

| unit | story | surface | tree | branch | build dir | scratch |
|---|---|---|---|---|---|---|
| F1 | `story:authored-denial-scenarios` | `systems/mandate/scenarios/*.yaml` | `mandate-wf-scenarios` | `impl/authored-scenarios-execute` | its own `target/` | `~/.cache/claude-tmp/wavef/f1-scenarios/` |
| F2 | `story:caller-authority-split` | `contracts/obligations/*.json` | `mandate-wf-authority-split` | `impl/caller-authority-split` | its own `target/` | `~/.cache/claude-tmp/wavef/f2-split/` |

### Round 2 — after F2's measurement merges

| unit | story | surface |
|---|---|---|
| F3 | `story:tenancy-authority` | `crates/mandate-model/src/{tenancy,authority}.rs`, `crates/mandate-model/tests/obligations.rs` |
| F4 | `story:credential-context-guards` | `crates/mandate-authz/src/context.rs`, `crates/mandate-authz/tests/obligations.rs` |

`story:invariant-boundary-validation` (the 4 value-admission clauses) is held for wave G: the verb
reports it colliding with `story:protocol-adapters` on `crates/mandate-server/src/lib.rs`, and
neither is scoped tightly enough to split today.

## F1 — what the wave found before it opened

`story:authored-denial-scenarios` was recorded `implemented` in wave D. Its 20 scenarios have
**never executed**. The unit's own gate ran a 146-scenario suite that did not contain them, because
`ess-inputs.yaml` and the scenario files were staged and uncommitted while the secrets scanner
refused the fixtures.

The operator granted the trusted-policy exception on 2026-09-21 (7 entries, by location and
content, for 13 synthetic findings carrying no key material). `a4843f3` committed the 20;
`86f529e` merged them; `cargo xtask generate` took the suite from 146 to 166. Then:

| outcome | total | authored |
|---|---|---|
| error | 19 | **19** |
| passed | 30 | 1 |
| failed | 54 | 0 |
| unsupported | 63 | 0 |

`conformance_status=Failed`. From `run.json`:

```
ESS-CF-TARGET  invoking `mandate.tenancy.CreateOrganization`
observed: reading the input `context` failed: invalid type: null, expected a string
```

136 explicit `null` values across exactly those 19 files — `actor`, `delegation`, `execution` 36
each, `verified_claim_name`, `verified_claim_value`, `space` 8 each, `connection_id` 4.
`introspect-caller-proof-malformed.yaml` carries none and is the one that passes. Optional means
absent; the domain's `Option<T>` deserialization refuses `null` by a decision recorded in the
drift-protection plan.

**The integration branch's `conform` step is red from the opening commit** and stays red until F1
merges. That is the true state: `ess-inputs.yaml` lists 20 scenarios and the corpus now contains
them. The alternative — leaving `suite.json` at 146 — makes `xtask contracts` red instead, on a
suite that disagrees with its own input list.

## Commits this wave authorises

The opening commit; one commit per unit; the merges into `integration/wave-20260921-006`; the
coordinator's alignment commits; the closing store commit; the merge into `main`. Nothing else —
no tag, no release, no work outside these units.

## Stage log

- **11:0x** Opened. `86f529e` merges `impl/authored-denial-scenarios` (`a4843f3`, 20 scenarios).
- **11:0x** Six wave-D trees collected after PR #15 reached `main` (`mandate-wd-conformance`,
  `-mutants`, `-listener-adv`, `-obligations`, `-conform-gate`, `-mutants-2`). `mandate-w1-canonical-types`
  and `mandate-w1-runtime-decision-dossier` remain retained on `no-remote-recovery-proof` — wave 1
  work that was never published.
- **11:0x** Three stories created and scoped; suite regenerated 146 → 166; opening commit.

## Carried, not this wave's

- The bot App bypasses `creation` and `update` on `main`'s ruleset. It did so twice during wave D's
  publish.
- `b10x/aep` 45G, `b10x/ess` 12G of build output.
- `/tmp/s8-pend-binding-policy.py`, deleted during wave D on a sub-agent's say-so; five days old,
  another session's, not recoverable.

## Close — 2026-09-22

Re-pointed mid-wave. Wave F opened on `decision-blocker:guards` and the operator set the
federated-login use case as the session goal, so the guards stories were created, scoped and left
undispatched. The clause count did not move: **190 clauses, 83 real, 21 double-only, 86 deferred**,
unchanged from wave D. The 31 *caller lacks authority* clauses are still decided by nothing,
including on the commands this road drives.

What the wave did instead: the road runs.

| merge | |
|---|---|
| `f1d2d28` | `--connection`, `--key` — the road runs in-process |
| `066c341` | `decision-blocker:jit-provisioning` cleared |
| `b8cb155` | a user nobody provisioned completes a first login |
| `4be1090` | the spawned binary, a real issuer, a signed proof |
| `2f6f370` | eight refusals against the binary |
| `1b1c12e` | a revoked link stays revoked |
| `90ec4a5` | flag documents run the command's own guards |
| `efcb0e5` | every refusal names itself |
| `69d40c2` | an issuer may publish its keys elsewhere |
| `abadfb8` | the authored corpus executes |
| `209b173` | the conformance fixtures earn their assertions |
| `79a7053` | the public page |
| `621f564` | ADR 0011 and the use-case registry |

Gate on the head: `task check` exit 0. 1,860 workspace tests, 0 failed. 292 elements. 190 clauses.
166 scenarios, `error` 0. 11 named mutants, each killed by the target it names. 231 store artifacts.

### Adversary passes

Three, one per merged login unit, by operator decision of 2026-09-21 rather than the protocol's two.
**The second pass is owed on `story:served-login-configurable`, `story:federated-jit-login` and
`story:served-login-end-to-end`** and is carried to the next wave. Four corrections were run; every
blocker was closed.

### What a unit found and could not fix, filed rather than carried

`story:link-absent-discriminates` · `story:jit-principal-record` · `story:host-spelling-folded` ·
`story:ess-evidence-suite-version`.

### Refused by the store, and not routed around

`aep plan artifact evidence --from … --suite …` is refused:
`UnsupportedSuiteVersion at $.suite.version: ess-conformance/9`. AEP 0.55.0 admits 1 through 6. The
ESS artifact keeps its `model_digest` and its `validated` rung; this run has no evidence row.
`story:ess-evidence-suite-version` carries it. ADR 0010 describes a path that does not currently
exist, and that is the thing to fix.

### Coordinator errors, recorded

1. 69 tracked story files deleted by a glob over a directory holding read-only copies; restored from
   `4be1090` in full.
2. `story:served-login-end-to-end.md` deleted as though it were a copy; it was a real artifact, never
   committed, and survived only because a unit tree happened to hold one. There was no safety net.
3. Three claims handed to the public-docs unit were wrong — eight refusals against eleven, three RFCs
   claimed as present that appear nowhere outside preserved sources, and OIDC discovery described as
   served when it is consumed. The unit checked each against code and refused all three.
4. The recipe given to the fixtures unit was insufficient and it measured that rather than following
   it: emptying the scenario list moves a corpus that is byte-compared at three places.
