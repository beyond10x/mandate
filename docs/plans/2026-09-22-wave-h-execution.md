# Wave H — the defects waves F and G measured and filed

Opened 2026-09-22. Integration branch `integration/wave-20260922-008`, cut from `8af63ab` — the last
all-bot commit, whose tree equals `main`'s at `b9923e4`. Cutting from `main` itself would make
GitHub's own merge commit an ancestor, and the organization push guard refuses a lineage containing a
commit whose committer is `GitHub <noreply@github.com>`; that is what broke publication during wave
D's close.

Skill version: `aep-drive:wave` 0.9.3. AEP protocol 0.55.0. Agent types dispatched:
`aep-drive:story-scoper`, `aep-drive:implementor`, `aep-drive:adversary`.

## Why this wave

Waves F and G shipped the federated-login road and released it as `v0.3.0`. Four of their units
measured a defect in shipped code, were told not to fix it in place, and filed a story instead. Three
of those are behaviour defects on the road that just shipped; the fourth is a test-harness collision
that produced 422 spurious failures under concurrency.

The clause count does not move here. `83 / 190` real and `0 of 31` caller-authority clauses decidable
from a fold both stand on `decision-blocker:guards`, which is an operator decision and not a wave.

## The selection

The operator approved this set as a plan before stage 1 ran. `aep plan artifact waves --kind story
--status draft --format json` exits 0 and returns:

**Waves**

| wave | stories |
|---|---|
| 1 | `story:agent-authority-kernel`, `story:audit-client`, `story:credential-context-guards`, `story:directory-provenance`, `story:graph-policy-adapter` |
| 2 | `story:audit-worker-delivery`, `story:constrained-exchange`, `story:testkit-doubles` |
| 3 | `story:agent-security`, `story:protocol-adapters`, `story:recovery-runbooks` |
| 4 | `story:advanced-delegation`, `story:audit-recovery-conformance`, `story:invariant-boundary-validation`, `story:oauth-integration` |
| 5 | `story:product-cli`, `story:runtime-service-qualification` |

**Collisions the verb excluded**

| a | b | path | confidence |
|---|---|---|---|
| `story:agent-authority-kernel` | `story:agent-security` | `crates/mandate-authz` | inferred |
| `story:agent-authority-kernel` | `story:agent-security` | `crates/mandate-policy` | inferred |
| `story:audit-recovery-conformance` | `story:audit-worker-delivery` | `services/worker` | inferred |
| `story:graph-policy-adapter` | `story:testkit-doubles` | `Cargo.lock` | cited |
| `story:graph-policy-adapter` | `story:testkit-doubles` | `crates/mandate-graph/src/lib.rs` | cited |
| `story:graph-policy-adapter` | `story:testkit-doubles` | `crates/mandate-policy/src/lib.rs` | cited |
| `story:graph-policy-adapter` | `story:testkit-doubles` | `dependency-boundaries.json` | cited |
| `story:invariant-boundary-validation` | `story:protocol-adapters` | `crates/mandate-server/src/lib.rs` | cited |

**Unassessed — 16, and all four of this wave's units were among them**

`story:conformance-denial-reasons`, `story:cross-crate-clauses`, `story:epoch-snapshot-generations`,
`story:ess-evidence-suite-version`, `story:ess-synthesizer-prerequisites`,
`story:federation-admission-port`, `story:federation-rule-disjointness`, `story:host-spelling-folded`,
`story:identity-tenant-containment`, `story:jit-principal-record`,
`story:link-absent-discriminates`, `story:per-run-test-scratch`, `story:refusal-discriminators`,
`story:sts-lifetime-bounds`, `story:sts-refusal-draws-nothing`, `story:unpublished-refusals`.

Every wave the verb returned is built from stories carrying an open `decision-blocker` — its first
wave alone holds `graph-policy-adapter`, `audit-client`, `directory-provenance` and
`agent-authority-kernel`, all blocked. The verb reads typed scope entries and does not read blockers.
So this wave is selected from the unassessed list instead, on the three properties the skill names,
and its four stories were scoped by `aep-drive:story-scoper` — one agent per story — before dispatch.

## Units

Two rounds. H3 waits on H1 because both write `services/control-plane/src`.

### Round 1 — disjoint, dispatched together

| unit | story | branch | tree | build dir | scratch |
|---|---|---|---|---|---|
| H1 | `story:link-absent-discriminates` | `impl/link-absent-discriminates` | `mandate-wh-link-absent` | its own `target/` | `~/.cache/claude-tmp/waveh/h1-link-absent/` |
| H2 | `story:host-spelling-folded` | `impl/host-spelling-folded` | `mandate-wh-host-spelling` | its own `target/` | `~/.cache/claude-tmp/waveh/h2-host-spelling/` |
| H4 | `story:per-run-test-scratch` | `impl/per-run-test-scratch` | `mandate-wh-test-scratch` | its own `target/` | `~/.cache/claude-tmp/waveh/h4-test-scratch/` |

H1 and H2 are both in `crates/mandate-federation` and in different files: `src/record.rs` and
`src/verifier_real.rs`. H1 is the only round-1 unit permitted to write `services/control-plane/src`.

### Round 2 — after H1 merges

| unit | story | branch | tree | build dir | scratch |
|---|---|---|---|---|---|
| H3 | `story:jit-principal-record` | `impl/jit-principal-record` | `mandate-wh-jit-principal` | its own `target/` | `~/.cache/claude-tmp/waveh/h3-jit-principal/` |

### The choice H1 forces

`story:link-absent-discriminates` names two fixes and picks neither. The operator approved the
second: **a state-blind key read**, so `ExternalKeyExists` refuses a key any record holds in any
state. A handler change, no contract edit. The first — splitting `LinkAbsent` into two clauses —
would additionally require the declared cause of `AuthenticateFederation` to tile the new clause in
`contracts/obligations/federation.json`, and follows as its own story if the clause budget is worked.

## Pre-flight

| check | reading |
|---|---|
| primary checkout | `main` at `b9923e4`, clean but for untracked `.agents/` — two `worktree` skill files, touched by no unit's surface, left where they are |
| leftover worktrees | `mandate-w1-canonical-types` and `mandate-w1-runtime-decision-dossier`, both retained by `worktree gc` on `no-remote-recovery-proof`; neither holds a branch this wave uses |
| free disk | 20G, `/` at 98% |
| compiler cache | `sccache` present and wired: 83,047 compile requests, 30,565 hits |
| model budget | none stated; the skill's default of 4 applies and round 1 runs 3 |
| one measured build | `cargo test -p mandate-federation --locked --no-run` in `mandate-wh-coordinator`: exit 0, 39 s, **503 MB** of `target/`. Three round-1 trees therefore cost about 1.5 GB against 19 GB free. The 6.3 GB figure from wave G was a whole-workspace gate with every test binary, which runs once, on this tree, at the close |

## Commits this wave authorises

One commit per unit; each adversary pass's test file committed at the moment the pass reports; the
merges into `integration/wave-20260922-008`; the closing store commit; the publication of that branch
for recovery proof. Nothing else — no PR, no merge into `main`, no tag, no release, no work outside
these four units.

## Filed by the scoping pass, not this wave's work

`services/control-plane/src/adapters.rs:626` holds a second `is_loopback` fold, on plaintext issuer
admission rather than on the JWKS destination: no trailing-dot trim at all, `[::1]` compared as a
string, and only `Ipv4Addr` parsed. Same class of defect as H2's, different guard, and
`story:host-spelling-folded`'s acceptance is scoped to `mandate-federation`. It gets its own story at
the close rather than widening H2.

## Stage log

- **09:5x** Opened. Integration branch cut from `8af63ab`. Four scopers dispatched.
