# A use case is a checked registry, not a page

Status: proposed 2026-09-21 for the composition track. The registry format and its first instance
are written; the `xtask` step that decides them is specified here and is not implemented.

## Decision

A **use case** is one thing a customer buys, described as the composition that delivers it: the
commands it runs in order, the routes it is reached through, the parties on every end of it, the
configuration each party supplies, the evidence that each step is decided, the standards it
implements, and the things about it that are not true yet.

It is an authored JSON document under `contracts/use-cases/<slug>.json`, format
`mandate-use-case/1`, one document per use case, decided by `cargo xtask use-cases` against the
compiled model, the route table, the flag readers, the conformance ledger, the compiled test
binaries and the planning store — and reported into `contracts/conformance/use-case-report.json`,
which that step writes and byte-compares. It is the fifth registry in the standard
`docs/adr/0010-drift-enforcement.md` sets out, and it is held to that standard's rules: it names
its subject, it names its count, and a green exit from it means something was selected.

Every claim in a use-case document is one of **seven kinds**, and each row says which kind it is.
Six of them resolve against something in this repository and are refused when they do not. The
seventh is a **promise**: a statement about a party outside this system, which nothing here can
check and which is therefore marked, never counted, and required to say what would refute it.

## What a use case composes

| Section | What it holds | Resolved against |
|---|---|---|
| `parties` | every actor the road touches, inside this system and outside it, each with what it **delivers** and what it **relies on** | nothing directly; each `delivers`/`relies_on` row carries its own kind |
| `steps` | the ordered commands, by their IR names, each with the party that acts and the evidence that decides it | `generated/ir/system.json`, `contracts/coverage.json` |
| `routes` | the served surface, method and path | `mandate_server::routes::ROUTES` |
| `configuration` | the documents and flags each party must supply, field by field | the real `serde` readers in `services/control-plane/src/adapters.rs` |
| `evidence` | on each step: scenarios by id and tests by id | `contracts/expected-outcomes.json`, the compiled test binaries |
| `standards` | the RFCs the road implements, each tied to the part of the flow it governs and to a file that cites it | the tree |
| `not_yet_true` | the gaps, each with what it costs a customer and the live artifact that owns it — or, where nothing owns it, the file the gap is written down in | the planning store, or a verbatim substring of that file |

A use case composes **commands**, not crates and not stories. A crate is where code lives and a
story is work somebody is doing; neither is a thing a customer buys. `mandate-federation` is not
federated login — federated login is eleven commands, five of them realized in `mandate-sts`,
reached over four command routes and two document routes, configured through five command-line
flags and thirty-three fields, and owed by seven parties of which six are outside this repository.

## What a use case may claim

Seven kinds. The kind is a field on the row, not a guess the reader makes.

| kind | the claim | how it is resolved |
|---|---|---|
| `contract` | an element the model declares | present in `generated/ir/system.json` under the stated kind |
| `route` | a method and path this deployment serves | equal to a member of `ROUTES`, binding what the row says it binds |
| `configuration` | a field of a flag document an operator writes | the named type deserializes the row's example through the real reader |
| `scenario` | a corpus scenario, **and its outcome** | present in `contracts/expected-outcomes.json` with exactly the stated `outcome` |
| `test` | a case that decides a step | listed **and run** by a compiled test binary |
| `artifact` | a story or blocker that owns a gap | held by the planning store and not on a terminal rung |
| `promise` | something a party outside this system does | **nothing.** See below. |

## What nothing may claim

1. **A command the model does not declare.** The IR is the authority on what exists; a use case
   citing `mandate.federation.AuthorizeTheUser` names nothing and is refused.
2. **A route nothing serves.** `ROUTES` is the whole served surface (`crates/mandate-server/src/routes.rs:97`).
   A use case may not describe a road through a path this deployment does not answer.
3. **A scenario the corpus does not contain, or one whose outcome moved.** A step whose evidence is
   `mandate.federation.AuthenticateFederation/outcome/denied: passed` stops being evidence the day
   that row goes `failed`, and the step refuses the document rather than the ledger.
4. **A test that does not run.** The id must be one a compiled binary lists **and** runs; an
   `#[ignore]`d case is subtracted, exactly as `contracts/coverage.json` subtracts it
   (`xtask/src/coverage.rs:187-249`).
5. **A gap attributed to a finished owner.** `not_yet_true` is a list of open gaps; a row naming a
   story on a terminal rung is a gap that was closed or was never that story's, and either way the
   row is wrong. This is the forcing function `docs/adr/0010-drift-enforcement.md` §3 already
   relies on. A gap that genuinely has no owner says so — see below — and is counted apart.
6. **A configuration field the reader does not have.** All four flag documents are
   `#[serde(deny_unknown_fields)]`, so a row naming a field that was renamed is refused by the
   reader itself rather than by a second copy of the field list.
7. **A promise dressed as evidence.** A `promise` row carries no test, no scenario and no route,
   and is counted in its own column of the report and in no other.

## The line between a check and a promise, and why it is drawn in the format

A use case names parties **outside this system**. Nothing in this repository can observe that a
customer's identity provider signs with the key its discovery document publishes, that a customer's
administrator registered the issuer they meant to, or that a relying application keeps its
`code_verifier` secret. A registry that blurred those into its covered count would publish a number
that means less the more of them it holds — and would be worse than no registry, because it would be
read as one.

So the split is in the data and not in the prose. Every `delivers` and `relies_on` row carries
`kind`. Where `kind` is `promise`, three further fields are **required**:

- `party` — whose promise it is. A promise with no owner is a wish.
- `locally_refutable` — whether anything in this deployment would be observed at all if the promise
  were false. A boolean, stated, never inferred.
- `refuted_by` — when `locally_refutable` is true, what an operator would observe: the refusal or
  the symptom, in one sentence. *"every login through this connection is refused at resolution-order
  step 3"* is a refutation; *"login would break"* is not. When it is false, the same field says what
  is **believed instead**, and why nothing here observes it.

`refuted_by` is what keeps a promise honest without pretending to check it. It cannot be run, but it
can be read by the person holding the incident, and it is the one thing a promise can be held to: a
promise nobody can say they would notice the breaking of is not a dependency, it is decoration.

`locally_refutable` is separate from it because the two answer different questions and the
interesting one is the count. *"Nothing here would notice"* is the honest answer for a real share of
what a use case rests on, and a format that let it hide inside a sentence would lose it. Stated as a
boolean, it becomes `unrefuted` in the report — a number that goes up when somebody adds a
dependency nobody can see failing.

The report therefore carries three counts that partition the rows — `checked`, `promises`, `gaps` —
and never sums the first two, plus `unowned` printed beside `gaps`. The vocabulary is deliberately
not `real_covered` / `double_only` / `deferred`: a double is a stand-in this repository runs and a
promise is a party this repository never sees, and giving them one word would invite exactly the
reading that word was chosen to stop.

In the first instance the split is **129 checked, 17 promises, 9 of them unrefuted**. That last
number is the one worth having. Nine of the things federated login rests on would produce no
observation here at all if they were false:

| party | what is believed |
|---|---|
| customer identity provider | the claim the tenant rule reads is true of the user, and no claim it has not verified is emitted |
| customer identity provider | `sub` is stable and is never reissued to a different person |
| customer administrator | the principal a seeded link names exists and is theirs |
| relying application | the `state` it sent is checked before the code is used |
| relying application | the credential never reaches a URL, a log or a referrer |
| resource server | it trusts the Mandate credential and never the identity provider's proof |
| resource server | it caches no longer than the profile it registered under allows |
| Mandate operator | the private half of every published key is held by this deployment alone |
| Mandate operator | the routes are not exposed on a plaintext interface |

That table is the actual security perimeter of this use case. Before this file existed it was
written down nowhere, and the last row of it is a gap this repository has never closed.

## A gap nobody owns is written down as unowned, not attached to the nearest story

`not_yet_true` rows name a live story or an open blocker, and the step refuses one on a terminal
rung. That is the forcing function, and it has a hole: some gaps have no owner at all, and the
easiest way to satisfy the rule is to attach the nearest plausible story. Two of the six gaps in
the first instance are exactly that case — **no transport security** and **no real identity provider
has been driven** — and no story in the store names either as its work. The closest live story says
so in its own words, under *Out of scope*: *"TLS — the cases stay on loopback `http` … a real issuer
over `https` is a road this repository has never driven."*

Attaching those to `story:runtime-service-qualification` because its title mentions security would
have satisfied the check and taught the reader something false. So such a row carries `unowned`
instead of `blocked_on`, naming the file the gap is recorded in and a **verbatim substring** of it —
the same device `contracts/obligations/README.md` uses for a clause against its declared cause, and
for the same reason: a citation that is merely *about* a file cannot be falsified, and one that
quotes it can. The step refuses an `unowned` row whose words are not in that file.

`unowned` is counted in its own column, beside `gaps` and never inside it, because an unowned gap is
a worse fact than an owned one and a registry that averaged the two would hide it. It is not a
resting place; it is a request for a story, addressed to whoever reads the count. The two rows that
carry it here are the ADR's own evidence that the field is needed.

## How a claim is refused

`cargo xtask use-cases` exits non-zero naming the document, the row and the reason. It is gated in
`cargo xtask check`, so a merge that renames a command, drops a route, retires a test, moves a
scenario's outcome or finishes a story that owns a gap turns a use case red at the same moment it
turns the other four registries red. A use case is not a thing somebody remembers to revisit.

## Why this is not a document, measured

This repository already has the document. `docs/architecture/federated-login.md` is 164 lines
written for this exact road, with source citations on nearly every line and a self-check table at
the end. Read at `b534a03` against the tree it sits in:

| The document says | The tree says | Measured |
|---|---|---|
| "no crate implements any command named below" (`:9`) | all seven are `implemented` | `contracts/coverage.json` |
| `commands/` = 59, `events/` = 65 (claim FL2) | 61 and 74 | `ls generated/schema/commands \| wc -l` |
| "the HTTP surface in the diagram … cannot exist until `task:runtime-wave-integration` replaces that assertion" | six routes are served and `mandate-control-plane` is exempt from the `serve` refusal | `crates/mandate-server/src/routes.rs:97`, `xtask/src/main.rs:601` |
| `ProvisionExternalPrincipal` is "new" and `decision-blocker:jit-provisioning` is being decided | the command is declared and implemented; the blocker is `cleared` | `generated/ir/system.json`, `.engineering/planning/decision-blocker/jit-provisioning.md` |

Three of those four are load-bearing: a reader deciding whether federated login works would be
wrong about whether any of it is implemented, wrong about whether it is served, and wrong about the
size of the contract. The document is careful, sourced and recent. It rotted anyway, because prose
has no failing state.

The fourth row is the one that settles the argument. FL2 states its own enforcement as
"`ls generated/schema/<dir> | wc -l` **at the commit this document was written against**" — an
enforcement that by construction can never fail a second time. That is the difference this ADR is
about: not whether a claim is checked once, but whether it is checkable *again*, by something that
runs without being asked.

**The document is not replaced and is not deleted.** It holds the reasons — why JIT is a command
and not a second accepted outcome, why a Boolean and not a rule type, what the operator decided and
foreclosed on 2026-09-18. Reasons are not claims and do not rot the same way. The registry takes the
claims; the document keeps the argument and drops the counts. Correcting the four rows above is work
this ADR does not do: `docs/architecture/` is owned elsewhere, and the correction is named here so
it is not lost.

## The alternatives, and why each was rejected

### An AEP planning artifact — a new `use-case` kind

`aep plan artifact kinds` lists no use-case kind, and its help says the list is "the compiled
vocabulary, plus every kind the **document tree** declares a lifecycle for". The document tree is
the `protocols:` source pinned in `.engineering/project.yaml`
(`git+https://github.com/beyond10x/aep.git#28abe09`), not this repository. Three kinds already come
from there that the binary did not ship knowing — `blocker`, `obligation`, `outbound-claim` — so a
fourth **is** addable, and the cost is bounded and knowable: one `artifacts/lifecycles/use-case.yaml`,
one `artifacts/kinds/use-case.yaml`, probably one row in `artifacts/relations/relations.yaml`, an AEP
release, and a repin of one line here. That is a day, not a quarter.

It is rejected on what it would buy, not on what it costs.

1. **AEP cannot check the claims.** The kind files say so in their own first sentence: *"Advisory
   until the artifact validator reads these files"* (`artifacts/kinds/obligation.yaml:1-3`).
   `required_sections` is a note to a reviewer. Even fully enforced, AEP validates frontmatter,
   relations and ladders; it has no reader for `generated/ir/system.json`, cannot ask a compiled test
   binary what it runs, and does not know what a route is. A use case in the planning store would be
   a page with a status — which is the option below, wearing a ladder.
2. **A use case has no ladder.** Every AEP kind carries a lifecycle, and `implemented` is meaningless
   for "federated login": the road is not work somebody finishes, it is a standing description that
   is more or less true at each commit. Giving it rungs would invent a state machine nobody would
   honour and would let a use case be marked done while the road it describes was red.
3. **The store is not writable by the units that change the road.** `AGENTS.md:13`: AEP is the sole
   writer of `.engineering/planning`, and the coordinator alone writes it. A use case that must move
   whenever a route or a command moves cannot live in a store the changing unit may not touch.

What survives from this alternative is the link, not the kind: the registry names stories and
blockers by id, and the step resolves them live through the same `terminal_rung` reader the coverage
step already has (`xtask/src/coverage.rs:548`). The planning store stays the authority on whether an
owner is live; it is simply not the place the use case is kept.

### An ESS concept — declared in `systems/mandate/`

The IR has an `actors` slot and it is empty (`generated/ir/system.json`, `"actors": {}`), which makes
this the most tempting alternative: parties are actors, and actors are already in the vocabulary.

Rejected on three counts.

1. **Most of what a use case claims is not contract.** Routes, flag documents, test ids, scenario
   outcomes and story ownership are facts about *this deployment and this repository*, not about what
   the system means. `docs/public/contracts.md:29` puts the product routes deliberately outside the
   generated command surface, and `crates/mandate-server/tests/routes.rs` decides that the two are
   disjoint. A use case that must match `routes.rs` cannot be expressed in the contract `routes.rs`
   is disjoint from.
2. **ESS is a pinned toolchain in another repository.** `ess/4` at 0.26.0 owns
   `systems/mandate` and writes every projection; a new concept is a language change, a release, and
   a repin. It would move `x-ess-provenance.source_digest` on all 318 generated schemas and the
   suite's `spec_digest` with them — the whole of §1 and §3 of `docs/adr/0010-drift-enforcement.md`
   churns for a change that adds no meaning to any command.
3. **The synthesizer would have to learn it.** The value of an ESS concept is that
   `ess verify conform synthesize` turns it into scenarios. Fifty-three scenarios already fail
   because the synthesizer arranges no prerequisite (`story:ess-synthesizer-prerequisites`); a
   multi-command ordered flow with external parties is strictly harder than the case that is already
   open.

What survives: the use case **cites** IR names and the step resolves every one of them against
`generated/ir/system.json`. ESS remains the sole authority on what a command is. It is simply not
asked a question about a deployment.

### A row in `contracts/coverage.json`

Rejected because the coverage manifest answers a different question and answering two in one file
would weaken both. Coverage is one row per element: *does anything implement this, and does any test
decide it*. A use case is a statement about an **ordering** of several elements plus things that are
not elements at all. `contracts/obligations/README.md` makes the same argument one level down — the
clause registry exists because coverage cannot answer per-condition — and the answer there was a new
registry beside coverage, not a wider row inside it. This follows that precedent.

### A document under `docs/architecture/`

Rejected on the measurement above.

## The enforcement step: `cargo xtask use-cases`

Specified, not implemented. A later unit builds it; this section is what it builds against.

### Where it sits

`xtask/src/use_cases.rs`, dispatched from `Action::UseCases { root, write }`, gated in
`Action::Check` **after** `obligations_registry_step` and **before** `conform_step`. That position is
not arbitrary: it needs the compiled test index, which `coverage::compiled()` memoizes in a
`OnceLock` and the coverage step has already paid for, and it reads
`contracts/expected-outcomes.json`, which the conformance step owns and does not mutate.

### What it reads

| Source | For |
|---|---|
| `contracts/use-cases/*.json` | the documents, whole directory |
| `generated/ir/system.json` | every `contract` row's element and kind |
| `contracts/coverage.json` | the element's `status` and `crate`, which a step row may not contradict |
| `contracts/expected-outcomes.json` | every `scenario` row's id and outcome |
| `coverage::compiled()` | every `test` row's id, listed and not ignored |
| `.engineering/planning/story/*.md`, `.../decision-blocker/*.md` | every `artifact` row's rung, through `coverage::terminal_rung` |
| `contracts/obligations/*.json` | each `addendum_steps` entry a step may cite, which must be one the obligations registry already names |

It does **not** read `crates/mandate-server/src/routes.rs` or `services/control-plane/src/adapters.rs`
as text. Parsing Rust to learn a route table is a second answer to a question the `const` already
answers, and the two would drift. Those two sections are decided **in the crate that owns them**,
the way `contract_agreement` cases already decide the coverage manifest inside each accounting
crate:

- `crates/mandate-server/tests/use_cases.rs` reads every `contracts/use-cases/*.json`, and asserts
  each `routes` row is a member of `ROUTES` with the same binding, and that no member of `ROUTES` is
  reachable on this road and unnamed by it.
- `services/control-plane/tests/use_cases.rs` reads the same files and deserializes each
  `configuration` row's `example` through the real reader named in `type` — `ConnectionSeed`,
  `PrincipalLinkSeed`, `ClientSeed`, `ResourceServerSeed`. `deny_unknown_fields` does the work; a
  renamed or deleted field fails the case with serde's own message.

The xtask step then **requires those two cases to exist and to run**, by id, through the same
compiled index. That is what stops the well-known failure: a delegated lane that selects nothing
exits 0, and an absent check is indistinguishable from a passing one unless something counts it.

### What it refuses

Each refusal names the document, the row and the subject.

1. A `format` that is not `mandate-use-case/1`, or a `use_case` that is not the file's stem.
2. A `contract` row whose element the IR does not declare, or declares under a different kind.
3. A `contract` row on a step whose element `contracts/coverage.json` does not call `implemented`,
   unless the step carries `not_yet_true` naming that element — a use case may describe a road that
   is not finished, but not silently.
4. A `steps` list whose `step` numbers are not `1..n` without gaps, or whose `addendum_steps`, where
   present, is not one of the nine the obligations registry's `addendum` rows already name.
5. A `route` row not equal to a member of `ROUTES`, or binding something else — refused in
   `crates/mandate-server/tests/use_cases.rs`; the xtask step refuses the **absence** of that case.
6. A `configuration` row whose `example` the named reader rejects, or which names a `type` that is
   not one of the four — likewise, in `services/control-plane/tests/use_cases.rs`.
7. A `scenario` row whose id `contracts/expected-outcomes.json` does not carry, **or carries with a
   different outcome**.
8. A `test` row whose id no compiled binary lists, or lists only as `#[ignore]`d.
9. **A step whose command `contracts/coverage.json` calls `implemented` and that carries no
   evidence.** A step with a shipped path and nothing deciding it is a step the use case asserts on
   nobody's authority, and no gap excuses it: a gap says the road is incomplete, not that the part
   that exists is unchecked. A step whose command is *not* implemented may carry no evidence — there
   is no shipped path for evidence to be about — and must then be named by a `not_yet_true` row.

   This rule was weaker in the first draft: *no evidence and no gap naming the step*. A mutation
   control killed that version — emptying the evidence of step 3, `RegisterResourceServer`, which is
   implemented and which a gap happens to name for an unrelated reason, was not refused. One gap
   about a missing route would have bought silence for every step it listed.
10. A `promise` row missing `party`, `locally_refutable` or `refuted_by`, or carrying a `tests`,
    `scenarios` or `routes` member, or appearing in a `relies_on` list. A promise that names
    evidence is a checked row filed in the wrong column; a promise restated as somebody else's
    reliance is one obligation counted twice and movable in two places.
11. A `not_yet_true` row whose `blocked_on` the store does not hold, or holds on a terminal rung —
    or, where the row is `unowned` instead, one whose `noted_words` do not appear **verbatim** in
    its `noted_in` file.
12. A `standards` row whose `cited_at` path does not exist or does not contain the RFC number it
    claims — a standard nothing in the tree references is a standard this road does not implement.
13. A report that differs by a byte from `contracts/conformance/use-case-report.json`.

### What it writes

`contracts/conformance/use-case-report.json`, beside `obligations-report.json`, computed by the step
and byte-compared by it; `--write` is how it is moved. Per use case and in total:

```json
{"use_case": "federated-login",
 "steps": 11, "routes": 6, "configuration": 33,
 "checked": 129, "promises": 17, "unrefuted": 9, "gaps": 6, "unowned": 2,
 "evidence": {"scenarios": 25, "tests": 72},
 "standards": 12}
```

Those are the figures `contracts/use-cases/federated-login.json` produces today, taken from a probe
that applies every rule above that can be decided without linking the two crates. `checked`,
`promises` and `gaps` partition every `delivers`, `relies_on` and step-evidence row; the report never
sums the first two. `unrefuted` is a subset of `promises` and `unowned` is a subset of `gaps`; both
are printed beside their parent and never inside it, because each names the part of its parent that
is worse, and an average would hide it. The step prints the per-use-case table, as the other four
registries print theirs.

### What it costs

| Item | Estimate | Read from |
|---|---|---|
| `xtask/src/use_cases.rs` | 600–900 lines | `xtask/src/obligations_registry.rs` is 1001 for a comparable job |
| the two in-crate cases | ~150 lines each | they parse JSON and compare against a `const` and four `Deserialize` types |
| new external dependencies | none | the step needs `serde_json` only, which `xtask` already has |
| `dependency-boundaries.json` | no change | the route and configuration checks live in the crates that already own those types, so `xtask` links no library |
| a mutation control | one record in `tests/mutants/` | §5 of `docs/adr/0010-drift-enforcement.md` requires a named kill per protection |
| added gate wall-clock | near zero | the expensive input, `cargo test --workspace --no-run`, is already paid by the coverage step and memoized |

The registry is authored before its step exists, which is how `contracts/coverage.json` began. Until
`cargo xtask use-cases` is gated, **every claim in `contracts/use-cases/` is a claim a human made**,
and `contracts/use-cases/README.md` says so at the top. That banner is removed by the unit that
lands the step, and by nothing else.

### What the rules have already been measured against

The rules above are not a wish list; every one of them that can be decided without linking the two
crates was run against the first instance by a throwaway review probe, and the probe was then held
to §5's own standard — twenty-one named faults injected into the instance, each with the refusal it
must produce, **twenty-one of twenty-one refused**. The list is the numbered refusals above, one
mutant apiece: an undeclared command, a route path nothing serves, a served route the document stops
naming, a renamed configuration field, an example the reader would reject, a scenario whose outcome
moved, a scenario the corpus lost, a test id no binary runs, a gap whose owner finished, a gap whose
owner the store never held, an unowned gap whose words are not in the file it cites, a promise with
no refutation, a promise that does not say whether anything would refute it, a promise carrying
evidence, a promise in the wrong section, an outside party claiming a checked row, gapped step
numbers, an invented addendum step, a step stripped of its evidence, an RFC the cited file does not
carry, and an element claimed under the wrong kind.

The first run of that exercise is why refusal 9 reads as it does: emptying the evidence of step 3
was **not** refused, because the rule as first written let any `not_yet_true` row naming a step buy
that step silence. The probe is a review tool
and is **not committed** — `AGENTS.md` is explicit that a check worth keeping is written in Rust —
so the unit that implements the step reproduces these twenty as a `tests/mutants/` record, which is
what §5 requires of a protection before it counts as one.

## Not decided here

**What makes a use case worth writing.** This ADR decides the form. Which roads get one, and when a
road is enough of a product to deserve one, is a product question, and a registry that answered it
would be inventing a reason to refuse somebody's document.

**Whether a use case is published.** `contracts/use-cases/` is internal, like the other registries;
`b10x.docs.yaml` includes `README.md`, `docs/public/**` and `generated/docs/**` and nothing here.
A customer-facing rendering of a use case is a different artifact with a different audience and is
not this one with the gaps removed.

**Runtime enforcement.** As with every step in `docs/adr/0010-drift-enforcement.md`: this decides a
property of the registry, the contract, the route table and the test corpus. Nothing in it observes a
deployment serving a customer's request, and no count it prints may be read as one.
