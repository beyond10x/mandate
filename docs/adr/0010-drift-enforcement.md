# Drift enforcement: what this repository proves about itself, and how

Status: accepted for the wave D enforcement track, 2026-09-19.

## Decision

A specification-first repository is only specification-first while something refuses the moment the
code and the contract disagree. This record states the whole standard in one place: the six things
that are machine-checked on every `task check`, the vocabulary each of them answers in, and what a
release may claim on the strength of them.

Every one of the six is a step of `cargo xtask`, written in Rust, gated in `check`, and reading a
committed artifact rather than regenerating one and believing it. No step in this standard is a
script, and no step's green exit means "this ran and found nothing" — each names its subject and
its count, because a green exit from a check that selected nothing is the failure this whole
standard exists to make impossible.

## 1. The generated projections are byte-compared

`cargo xtask generate` writes seven kinds under `generated/`: the four ESS projections (`schema`,
`openapi`, `docs`, `docs-ir`), the compiled model itself (`ir/system.json`), the emitted Rust
shapes (`rust/mandate-contract`), and the coverage receipt. `cargo xtask contracts` regenerates all
seven into a scratch root and compares the whole tree byte for byte. A projection edited by hand, a
model changed without regeneration, and an ESS repin that moves an emission are the same failure
and all three are refused by the same comparison.

`generated/conformance/suite.json` joins that set as an eighth kind. It is an ESS projection like
the others — `ess verify conform synthesize --path systems/mandate --suite-format 5` — and
`generated/` holds ESS output only, which is why the *target's* outputs are not committed there
(§3).

## 2. The coverage map and its receipt

`contracts/coverage.json` maps every element the compiled model declares to what implements it and
to the checks that decide it, one entry to a line. It is authored, not generated: a map derived
from the registries could not disagree with them, and a map that cannot disagree is not evidence.
`cargo xtask coverage` decides every way the authored map can be wrong — the element set both ways,
one entry per element, a symbol rooted in a workspace member and never in the generated crate, a
test id a compiled binary lists *and runs*, a story the store holds and that is not on a terminal
rung, a blocker the store reports open.

An entry is `implemented`, `declared` or `deferred`. **`implemented`** names a crate, at least one
symbol and at least one test. **`declared`** names the story that will implement it and states a
reason, and carries no implementation at all. **`deferred`** additionally names an open
`decision-blocker` that holds its story: the work is not merely unstarted, it is waiting on a
decision a person owes. A `declared` entry whose story the store reports blocked is a `deferred`
entry that was relabelled, and is refused as such.

`generated/coverage/receipt.json` binds the map to what it was written against: the ESS toolchain's
own version, a digest over `systems/mandate`, the compiled model, the emitted contract crate, the
manifest, and the per-kind counts. It is written by `generate()` and byte-compared by `contracts()`
like every other projection, so a manifest edited without regenerating is a failing gate.

The receipt's `source_digest` is a digest over the `systems/mandate` **tree** — each file framed by
its path, its length and its bytes, in sorted path order — and is **not** ESS's own `source_digest`
for the same sources. The two are different quantities and do not compare; anything that wants to
know "were these projections made from these sources" asks the receipt, and anything that wants to
know "is this artifact a projection of this specification" asks the `x-ess-provenance` digest (§3).

## 3. The conformance gate

`crates/mandate-conformance` runs the synthesized suite against the real handlers through
`ess_conformance::ConformanceTarget` and reports what it observed — never a manufactured
expectation. `cargo xtask conform` is what makes that a gate, and it decides five things.

**The suite is a fresh synthesis.** `generated/conformance/suite.json` is byte-compared with what
`ess verify conform synthesize --suite-format 5` writes from `systems/mandate` today. The
synthesizer exits 1 on the 52 scenarios the contract cannot synthesize while writing a complete
suite for the other 146, so it is spawned tolerantly and decided on its artifact, never its status.

**The synthesizer is the one that reads `ess-inputs.yaml`.** The step runs

```
ess verify conform synthesize --path <s> --scenarios <s> --suite-format 5 --out <suite>
```

and, only when that refuses with ESS's own words for an empty list — `the explicit scenarios list
selected no authored files`, exit 1, no suite written — re-runs it without `--scenarios`. Any other
refusal is the gate's refusal. `cargo xtask generate` makes the same two invocations. The rule is
shaped that way because both halves have to hold — ESS refuses the flag against an empty list, and
dropping the flag once the list is filled would leave every authored scenario outside the corpus the
gate compares — and because every attempt to decide it *here*, by reading the YAML with `str`, got
it wrong: one reading called `scenarios: []  # a note` non-empty, the next let a comment line end a
list that had items. The question is ESS's to answer and the answer is its exit.

The toolchain is held too: the coverage receipt's `ess_version` must be both the pin and the `ess`
that just synthesized the suite, because a repin changes the projections while every digest stays
equal.

**The suite is a synthesis of this specification.** Its `provenance.spec_digest` must equal the
`x-ess-provenance.source_digest` that *every* generated schema carries — all 318 of them, since a
single projection regenerated from other sources and committed beside the rest is exactly the drift
the digest is carried for — and the coverage receipt must be current for `systems/mandate`.

**The outcomes are the ones the tree expects.** `contracts/expected-outcomes.json`
(`mandate-expected-outcomes/1`) states per scenario `{id, outcome, blocked_on?}` with `outcome` one
of `passed`, `failed`, `unsupported`, `error`. The comparison with the report is set equality both
ways and then column by column, so a scenario that vanished, one that appeared, one whose outcome
moved and a count that moved are four failures with four messages. `skipped` must be zero: a
skipped scenario decides nothing, and a suite that skips is a suite that can go green by selecting
less.

**The honesty ledger did not move.** `contracts/conformance/injections.json` is byte-compared with
the run's. Every standing double, every armed port, every refusal before dispatch and every
unsupported command is a row in it, so a double that quietly started answering differently is a
failing gate rather than a passing scenario.

**Every gap has a live owner.** No scenario that did not pass is unattributed, none is attributed
twice, and no attribution names a story on a terminal rung.

`report.json` and `run.json` are **computed, not committed**. They are 0.92 MB (measured: 59,608 and
856,728 bytes) that move on every source change, and the binding the acceptance wants — this report, from this tree — is supplied by
the coverage receipt plus the report's own implementation digest recorded as AEP evidence at wave
close, not by recommitting the bytes.

### The two ledgers, and which one answers

`injections.json` is the target's own output and is compiled into `crates/mandate-conformance`. It
is the authority for every scenario the target **refused before dispatch or does not support**, and
such a row moves by changing that crate.

`contracts/expected-outcomes.json` is authored and is the authority for a scenario that **executed
and whose expectation was unmet**. The target marks those `story:conform-gate`, which is not an
attribution but a statement that the attribution is not made there; the gate refuses that marker
appearing as an owner in the authored ledger.

A scenario named by both with two different stories is refused: one gap, one owner. A row moves in
the file that holds it, and in that file only.

### How a scenario whose expectation was unmet is attributed

Fifty-four scenarios execute against a real handler and are refused by it. Fifty-three of them share
one cause — **the synthesizer arranges no prerequisite and its placeholder values are not ones the
handler admits**: `CreateTeam` on a fold holding no `Organization`, `RegisterFederationConnection`
with a rule resolving to a foreign organization, `RegisterSigningKey` with `algorithm: "algorithm"`
and `not_before == expires_at`. They are attributed to `story:ess-synthesizer-prerequisites`, the
Mandate-side home for that cause until the ESS-side fix lands and this repository repins. The
fifty-fourth expected `wrong-state` and observed `denied`: that is the discriminator, and it belongs
to `story:refusal-discriminators`, whose own text names it.

Never `story:conform-gate`, which owns the gate and no handler; never the story that *realized* the
command, because all five of those are `implemented` and a terminal rung answers nothing.

**The split is deliberately no finer than the evidence.** Every one of the fifty-three has the same
first unmet check and `run.json` records no denial reason, so a per-command attribution would rest
on a hand reading of each handler's first guard that no artifact carries and no comparison could
falsify. `story:conformance-denial-reasons` is the follow-up that fixes that: the run records the
`reason` and the crate-local clause of every denial, the ledger carries both per row, and the gate
refuses a row whose recorded clause is not the one the run observed. Until it lands, one cause is
one row and the ledger says so.

When a named story reaches a terminal rung the gate goes red and the row must move to the next live
owner. That is the intended forcing function, not an accident: the ledger is a list of open gaps,
and a gap whose owner finished is either closed or misattributed.

## 4. The obligations registry

`contracts/obligations/<crate>.json` (`mandate-obligations/1`) binds every external denial clause
of every implemented command to a test, and `cargo xtask obligations-registry` decides it against
the compiled model and the compiled test binaries. Its report is
`contracts/conformance/obligations-report.json`, computed by that step and compared by it, and it
carries per crate `{clauses, real_covered, double_only, deferred}`.

**`real_covered`** is a clause driven through the real validation path with a malformed or
mismatched input: the handler decided it. **`double_only`** is a clause only a substituted port can
reach today; it is counted in its own column and **never** as conforming, because a double proves
that the code calls the port, not that the deployment refuses. **`deferred`** is a clause with no
binding test at all, carrying `blocked_on` its crate's live binding story; it is excluded from the
numerator and stays visible in the denominator, so the fraction cannot improve by looking away.

The same three words mean the same three things wherever they appear in this standard: covered by
the real path, covered only by a stand-in, or not covered and owned by somebody.

## 5. The mutation controls

A check nobody has seen fail is a check nobody has evidence for. `tests/mutants/<name>.{patch,json}`
is a catalogue of named faults; `cargo xtask mutants` applies each to a scratch copy of the tree and
requires the named kill: a `test-fails` record's target test fails on the mutated copy and passes on
the unmutated one, a `compile-fails` record's target does not build, a `check-fails` record's xtask
step exits non-zero with the record's refusal substring in its stderr. A patch that no longer
applies, an anchor outside the rewritten lines, a kill that is not observed and a killing run that
does not terminate within its bound each fail the step by name. Ten of ten are killed today.

## 6. Evidence binding, and what a release may claim

The AEP artifact `executable-system-specification:mandate` carries the conformance evidence: the
report it was read from, the suite, the specification digest and the implementation digest. It is
created and recorded by the coordinator at wave close, from a run on the merged head.

`cargo xtask conform --release` reads **what the store writes and nothing that looks like it**.

The artifact's frontmatter `model_digest` — what `aep plan artifact set --model-digest` writes, and
the only digest the document holds — must be the suite's `spec_digest`. The evidence itself is an
`aep.evidence.record/v1` line in `.engineering/planning/journal.jsonl`; the one a release is decided
on is the **latest by `payload.at`** whose `args.kind` is `ess_conformance`, because the recorder
takes `--kind` freely and `--ref` on every kind, so an approval recorded afterwards would otherwise
supply the commit. Its `ref` is `git:<sha>`, and two things are then asked of the checkout the
implementation digest was taken over:

- `git status --porcelain -- crates/*/src/* services/*/src/* systems` is empty. Everything else in
  the gate reads the working tree — the digest, the build, the run — so a rule that compared two
  commits alone would bless sources nothing ran.
- `git diff --quiet <sha> HEAD -- crates/*/src/* services/*/src/* systems` reports no change. The
  pathspec is the digest's own set, so a test-only commit between the evidence run and the release
  is not drift. Each component ends in `/*` because `crates/*/src` alone selects **nothing** in git
  — measured here — and a pathspec that selects nothing is a check that always passes.

The recorder command is therefore

```
aep plan artifact evidence executable-system-specification:mandate \
  --kind ess_conformance --source 'cargo xtask conform' --ref git:<sha> --at <instant>
```

`--ref` is not optional: with `--from` it would default to the report's own path, and a path is not
a commit. The `--from report.json --suite suite.json` route is unavailable at this pin — AEP 0.55.0
answers `UnsupportedSuiteVersion at $.suite.version: ess-conformance/9`, measured against a scratch
copy of this store — so the kind, the source and the reference are given explicitly until that
lands.

Ordinary `task check` does not read any of this: evidence is recorded at a wave boundary, and
requiring it on every run would make every commit between two waves red for a reason that is not
drift.

**A library tag may ship with `conformance_status: failed`.** Mandate is a library whose contract is
ahead of its realization by construction, and a gate that required `passed` would be a gate that
required either finishing everything or weakening the suite. What a tag must carry instead is
honesty about the number: every failed scenario names a live `blocked_on` story, and the CHANGELOG
records the counts — `passed`, `failed`, `unsupported` — for the tagged commit.

`Unsupported` is reserved for a **permanent property of the target**: an unrealized command, a port
that cannot be substituted, an input shape nothing realizes. It never means "not run today".
`Unavailable`, which reports as `error`, is reserved for a check the runner could not execute; the
gate requires `error` to be zero as surely as `skipped`, because an inconclusive run is not a
verdict.

No tag is cut from an integration branch, and source publication authorizes nothing further
(`docs/adr/0008-integration-batches.md`).

## Not decided here

Runtime enforcement. Every one of these six steps decides a property of the corpus, the contract and
the library; none of them observes a deployment serving a request. Corpus validation is not security
implementation, and no count in this record may be read as one.
