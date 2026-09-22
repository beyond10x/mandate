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

- **09:5x** Opened. Integration branch cut from `8af63ab`. Four scopers dispatched, one per story.
- **10:0x** All four returned `high` confidence. 18 typed scope entries and four `## Scope` sections
  written. The four stories moved `draft → proposed → active`. Opening commit `06c6747`;
  `cargo xtask documents` and `cargo xtask boundaries` on it both exit 0 — 22 packages satisfy
  metadata and dependency boundaries.
- **10:0x** Three round-1 trees created at `06c6747`, each on its own branch, each with its own
  `target/` and its own scratch under `~/.cache/claude-tmp/waveh/`. One `aep-drive:implementor`
  dispatched per unit, each given its brief by path.
- **10:1x** H2 green — `d6b1876`, `mandate-federation` 304 → 305 executed, 0 failed. The class it
  found had six more members than the one reported. Adversary pass 1 dispatched.
- **10:1x** H4 green — `08f68a5`, `mandate-control-plane` 137 → 141 executed, 0 failed; the
  concurrent probe went 45 / 14 / 29 failures to 0 / 0 / 0. Adversary pass 1 dispatched.
- **10:2x** H1 returned red on one case — `serve.rs:2208`, a file H4 owns, asserting the login
  consults the verifier four times where removing `key_holds_no_record` makes it three. The
  implementor wrote the patch and left it unapplied, which is the rule. The coordinator applied it:
  `mandate-control-plane` 137 executed, 0 failed, `cargo fmt` clean. Committed as `e9f69cf`, one
  commit for the unit, and adversary pass 1 dispatched.
- **10:2x** H1 measured its own brief wrong and said so. The `## Scope` section claims that removing
  the `Linked` filter from `Projection::link` alone leaves `authenticate_federation` unchanged; it
  does not — the projection answers `min_by_key(id)`, so a key whose smallest record is revoked
  stops promoting the surviving linked one, and `tests/replay.rs` caught it. What landed prefers the
  smallest `Linked` record and falls back only when the key has none. **The section is rewritten at
  the close.**
- **10:4x** H2 adversary pass 1 red: 7 findings, 5 introduced, 2 pre-existing, 0 undecided.
  Recorded as `review-result:wave-h-host-spelling-adversary-1`, findings block byte for byte. Five
  routed back to the same implementor, which still holds its context; one is the coordinator's,
  because it is a stale quote in a file H4 owns; one is filed as
  `story:control-plane-loopback-fold`.
- The pre-existing one it filed is the sibling guard: `is_loopback`
  (`services/control-plane/src/adapters.rs:626`) splits the authority on its last `:`, so
  `http://localhost:80@evil.example` is admitted as a plaintext issuer naming `evil.example`, where
  `origin` refuses any `@` outright. `INFEASIBLE` — the string is the operator's own issuer and no
  path was found that produces it. The adversary's 75-line case is **inside that story's body**,
  because a red case cannot be committed and its worktree will not outlive the wave.
- **10:5x** H1 adversary pass 1: 6 findings, 3 introduced, 3 pre-existing, one red case. It could
  not break the preference-with-fallback — 8 state masks × 8 append orders — and confirmed the 4 → 3
  verifier bound and that the removed pre-check took no second condition with it. Three routed back;
  two filed as `story:linked-event-method-unenforced`; one is this document's own.
  `review-result:wave-h-link-absent-adversary-1`.
- **11:0x** H2 correction 1 green and committed as `af2982c`, with the adversary's own file. The
  correction folded the third comparison and measured the change monotone: 77 pairs move base → head
  across 39 spellings and two schemes, every one from refused to admitted on the issuer's own origin,
  zero the other way. Adversary pass 2 dispatched.
- **11:0x** H4 adversary pass 1: 5 findings, 3 introduced, 2 pre-existing, two red cases. It could
  not break the acceptance — 576 concurrent copies of `end_to_end`, 10,368 cases, 0 failures — and
  confirmed all five write sites moved. Four routed back;
  `story:road-lane-child-prints-address` filed for the port race, with its 16-way case in the story
  body. `review-result:wave-h-test-scratch-adversary-1`.
- **11:0x** The adversary's probes took H4's `target/tmp` from 37 MB to 644 MB, which is finding F2
  acting on the disk. Cleared by the coordinator; `/` at 16G free, 99%.
- Disk during round 1: 19G free at dispatch, 16G after two adversary passes; four trees holding 5.3G
  of build output between them.

- **11:2x** H1 correction 1 green and committed as `8b7a6e0`. It closed the finding in the **port**
  rather than in prose: `LinkStore` now has one required method, `records_on_key`, and `link` is
  derived from it inside the crate — which also closes a second member of the class the adversary did
  not report, the holder rule that `authenticate_federation` and `link_external_principal` depend on.
  Adversary pass 2 dispatched.
- **11:3x** H4 correction 1 green and committed as `d08e7f4`. `target/tmp` 644 MB → 3.1 MB; 140 runs
  across four lanes with no parent growing. Adversary pass 2 dispatched.
- **11:3x** H2 pass 2: 7 findings, 6 introduced, 1 pre-existing. The ledger the store computed
  between the two passes: **carried 0, new 7, resolved 7.** The monotonicity claim survived —
  12,168 base → head decisions, 269 refused → admitted and every one through the issuer's own-origin
  comparison, zero through the containment branch. Recorded as
  `review-result:wave-h-host-spelling-adversary-2`. Two scalars of its findings block are
  single-quoted so the store can parse them; no character of either message changed.
- **11:4x** H2's correction 2 answered four of the five routed items and reported the remaining three
  adversary cases as **not honestly satisfiable** — measured: two are green exactly when the SSRF
  containment branch is deleted. That is the "wrong now" row of the skill's table, not a fifth row:
  two are rewritten to assert the corpus property they actually found, and the third leaves the unit
  with its own story. The attacking budget is spent; the coordinator verifies this correction.

## Disk, and what it cost

`/` reached **6.8G free at 100%** during round 1's corrections. Attribution at that moment: another
session's `~/.cache/b10x-target/aep` at 13G and being written to, `sccache` at 13G of a 30G cap, and
two stale caches — `ess` 3.7G untouched since 2026-09-20, `epistemic-knowledge-runtime` 3.2G since
2026-09-21. The wave freed what was its own first (H1's 2.5G `target/`, H4's 644 MB `target/tmp`),
then asked the operator, because deleting another session's build output is his rule to waive. He
waived it for the two stale ones; `/` returned to **28G**.

## Filed by the wave, for other waves

| story | why it is not this wave's |
|---|---|
| `story:control-plane-loopback-fold` | `is_loopback` at `adapters.rs:626` — userinfo defeats it, and no trailing-dot fold. Pre-existing, and no path was found that reaches it |
| `story:linked-event-method-unenforced` | the fold admits an `ExternalPrincipalLinked` carrying a `link_method` no command emits, and two fixtures already rest on it. Pre-existing |
| `story:road-lane-child-prints-address` | `adversary_login_road.rs` picks its child's port by dropping a listener; four or more concurrent copies collide. Pre-existing, byte-identical at the wave base, and wave G already fixed this class one lane over |
| `story:folded-is-not-an-address-fold` | the own-origin comparison is string equality where the containment halves parse addresses, so one loopback address spelled two valid ways gets two answers. Fails closed, reproduces at the wave base |
| `story:enabled-for-issuer-filters-in-the-implementor` | the same class H1 closed for `LinkStore`, one port over. The failure direction is closed — a non-filtering store can only add denials — so it is a note, and it is untouched by this wave |

Each of the five carries the adversary case that found it, verbatim, in its own body. A red case
cannot be committed and a worktree does not outlive the wave; the store does.

## Close — 2026-09-22

Three units, three merges, one gate. Nothing left the wave.

| merge | |
|---|---|
| `4adbffd` | `impl/host-spelling-folded` — one host, one answer, at every comparison |
| `a99df9d` | `impl/link-absent-discriminates` — the key is not free while a record holds it |
| `0059381` | `impl/per-run-test-scratch` — a run's scratch is its own, and bounded |
| `89d5bc9`, `9b3aeb1` | the coordinator's two alignment commits: the import the sealed derivation made unused, and the rewrap the gate's first step demanded |

**Gate on `9b3aeb1`: `task check` exit 0.** 250 suites, 1,920 tests passed, 0 failed, from the
wave-G baseline of 244 and 1,894. 11 named mutants, each killed by the target it names. 166 scenarios,
`error` 0. The clause count did not move and was not expected to: 190 clauses, 83 real, 21
double-only, 86 deferred.

**The first whole-gate run exited 201 and the harness reported it as exit 0.** It refused at step 1,
`cargo fmt --all --check`, on the import line the coordinator's own commit had shortened, and ran
nothing else. The only reason that is in this document rather than in a claim of a green gate is that
the run captured `GATE_EXIT` itself instead of reading the wrapper's status — which is the failure
this skill's own rules were written about.

### What each unit found beyond what it was sent for

| unit | sent for | found |
|---|---|---|
| H1 | one clause covering two conditions | the fix's own guarantee lived in one implementation of a port, twice over: first in `Projection` rather than in `LinkStore`, then in a defaulted method any implementor could overwrite. It ends as a blanket `LinkResolution` no downstream crate can write, and the conformance guard that was supposed to notice such a method was scanning one implementation's overrides — turning it on surfaced four more, two of them defective |
| H2 | one host spelling reaching the allowed list | the class had seven members, and the fold reached two of the three places `admits` compares a host. The second pass then found the property test asserting things it could not reach — 14 of 16 rows comparing a refusal against a refusal |
| H4 | one test binary's scratch directory | the parent grew by one directory per process id that had ever run the binary, and the liveness guard that fixed it would have deleted a **running** run's scratch on a host whose `/proc` is an unmounted mount point |

### The adversary ledger

| unit | pass 1 | pass 2 | carried | new | resolved |
|---|---|---|---|---|---|
| H1 | 6 — 3 introduced, 3 pre-existing | 6 — 4 introduced, 2 pre-existing | 0 | 6 | 6 |
| H2 | 7 — 5 introduced, 2 pre-existing | 7 — 6 introduced, 1 pre-existing | 0 | 7 | 7 |
| H4 | 5 — 3 introduced, 2 pre-existing | 6 — 6 introduced, 0 pre-existing | 0 | 6 | 5 |

Nothing carried between passes in any unit. Each second pass attacked what the first pass's correction
claimed, and in all three the claim was narrower than it read.

**Three of H2's pass-2 cases could not be made green honestly, and that was measured rather than
argued:** two were green exactly when the SSRF containment branch was deleted. They are the skill's
*wrong now* row — rewritten to assert the corpus property they had actually found, which survives all
four mutations including the one the old form passed under, and goes red when either site is made
vacuous. The third left with its own story.

### What the wave cost

**≈2.28 million sub-agent tokens across 13 dispatches** — four scopers (238k), three implementors over
ten rounds (H1 381k, H4 351k, H2 258k) and six adversary passes (159k–206k each). Roughly 1,200 tool
calls. Six of the ten implementor rounds were corrections, and every one of them was work no plan
predicted.

### Coordinator errors, recorded

1. The opening `--id` loop was written in a shell whose variables do not word-split, so the first
   `worktree gc --dry-run` ran against the whole profile rather than the mandate ids. Harmless, and
   it is why the exact-id form is in the log twice.
2. The cross-unit import fix landed unformatted, refused the gate at its first step, and cost a
   second whole-gate run.
3. Two adversary findings blocks were refused by the store as unparseable YAML — a `"Out of scope:
   Widening"` inside an unquoted scalar. The blocks are recorded with those two scalars single-quoted
   and no character of either message changed. **The dispatch brief now tells adversaries to quote
   them**, which is why only the first two passes hit it.
4. Disk reached 6.8G free at 100% mid-wave. The wave freed its own first and then asked, because the
   rest belonged to other sessions.

### Owed, and not this wave's

`story:jit-principal-record` — H3, which the plan put in round 2 because it writes the same
`services/control-plane/src/adapters.rs` H1 does. It was never dispatched: H1 took three rounds and
two of them changed that file. It is `active` in the store, scoped, and the next wave's first
candidate.

**This wave stops at the integration branch.** `AGENTS.md` § Integration batches: the pull request to
`main` and its merge are separate operator decisions, and no tag is cut from an integration branch.
