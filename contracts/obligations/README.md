# `mandate-obligations/1`

The clause-level map from every external denial an implemented command can produce to the
real-path test that decides it. One document per crate, named after the crate with the
`mandate-` prefix dropped: `sts.json` is `mandate-sts`.

`cargo xtask obligations-registry` reads this directory whole. It writes
`contracts/conformance/obligations-report.json` and compares it byte-for-byte with the
committed one; `cargo xtask obligations-registry --write` is how that file is moved.

## Why a clause and not a command

`contracts/coverage.json` already answers "does anything implement this command, and does
any test decide it" — one row per element. It cannot answer the question a denial contract
is read for, which is whether *each* condition the contract publishes as a refusal is one
something actually refuses on. A command whose `denied` outcome names six conditions and
whose only test drives one of them is `implemented` in the coverage manifest and always
will be. Splitting the declared cause into its clauses is what makes the other five
countable, and a count is the only thing that can fall.

## What a document states

```json
{
  "format": "mandate-obligations/1",
  "crate": "mandate-sts",
  "domains": ["mandate.credential"],
  "commands": [ … ],
  "addendum": [ … ],
  "cases": [ … ]
}
```

`domains` are the contract domains this document answers for. Across the seven documents
they partition every domain the compiled model gives a command to, so every one of the
model's commands has exactly one document and no command has two. A command the coverage
manifest calls `implemented` must sit in the document whose `crate` that manifest names for
it — that rule is what keeps the partition from being arbitrary where it matters. A command
nothing implements has no crate to be checked against, and its document is a filing choice:
`mandate.audit`, `mandate.directory` and `mandate.workload` are filed with `mandate-model`
and `mandate.delegation` with `mandate-authz`, following the Rust-ownership column of
`docs/architecture/ownership.md` where one of these seven crates appears in it.

### A command

```json
{
  "command": "mandate.credential.RegisterResourceServer",
  "status": "implemented",
  "clauses": [
    {"clause": "audience registration is ambiguous",
     "tests": [{"id": "mandate-sts::declared_denials::every_refusal_register_resource_server_produces_has_a_row",
                "kind": "denial", "path": "real"}]},
    {"clause": "Caller lacks resource-server administration authority",
     "tests": [], "blocked_on": "story:obligations-sts"}
  ],
  "no_state_change": [{"id": "…", "kind": "no-state-change", "path": "real"}],
  "denial_audit": {"status": "deferred", "blocker": "decision-blocker:audit-routing", "tests": []}
}
```

`status` follows `contracts/coverage.json` and may not disagree with it: a command that
manifest calls `implemented` is `implemented` here, and any other status there is `deferred`
here carrying that manifest's own `story` and, where it has one, its `blocker`. A `deferred`
command carries no clause — there is no implementation for a clause to be a claim about.

Every `clause` is a **verbatim substring** of its command's declared `condition.cause` in
`generated/ir/system.json`, and the clauses of one command **tile** that cause: read in order,
they account for every character of it exactly once apart from the separators that join a list
— whitespace, `,`, `;`, `/`, `.` and the words `or` and `and`. A clause the contract does not
carry is refused; so is a clause list that has lost one, which would otherwise stop publishing
that condition and take `clauses` and `deferred` down with it, and so is a clause nested inside
another, which claims one position of the cause twice and can raise `real_covered` with nothing
new decided. The weaker rule — each clause is *a* substring — admits both, which is why the
step walks the cause rather than searching it. The granularity is the one
`services/sts/tests/declared_denials.rs` established by hand for the eleven STS commands —
one clause per condition the cause enumerates, so several of that file's discriminators may
answer to one clause.

`no_state_change` names the case that decides the command refuses without moving its
projection. `denial_audit` is the obligation that a refusal is audited; it is `deferred` for
every command while `decision-blocker:audit-routing` is open, and it is counted in neither
the numerator nor the denominator of the report — an obligation nothing can discharge is not
a gap in this crate's work.

### A test row

```json
{"id": "<package>::<target>::<function>", "kind": "denial", "path": "real"}
{"id": "…", "kind": "denial", "path": "double", "double": "mandate_graph::double::GraphDouble"}
```

`id` is one `cargo test -- --list` lists **and runs**: an `#[ignore]`d case is subtracted, so
a clause whose only named check is ignored names a check that decides nothing. It names a test
of the entry's own crate — for a `cases` row, of that crate or of one of the two wire packages
above. `kind` is one of `denial`, `accepted`, `no-state-change`, `precedence`, `denial-audit`. A row inside
`clauses` is a `denial`, `accepted` or `precedence`; a row inside `no_state_change` is a
`no-state-change`; a row inside `denial_audit` is a `denial-audit`.

`path` says what decided the clause. `real` is the crate's own shipped decision path — a
handler, a fold, a validator — reached with a mismatched or malformed input. `double` is a
stand-in **for the deciding code itself**, such as `mandate_graph::double::GraphDouble`,
whose refusals are the double's own and not the adapter's. An in-memory port that merely
*supplies* input to a real handler leaves the row `real`: what is classified is the code that
makes the decision, not the code that holds the data.

**A `double` row never covers a clause, and a clause carries rows of one path only.** A
double-backed clause is counted in its own column of the report and still carries `blocked_on`.
This is the rule the whole file exists for: a double refuses because it was written to refuse,
so a clause whose only evidence is a double has no evidence that the shipped path refuses at
all.

A double-backed clause's `blocked_on` names the story that owns the **port's real
implementation**, never `story:obligations-<crate>`: if the only evidence is a double then the
deciding code is not shipped, and no test the binding story writes can bind the clause. The
eight double-backed clauses defer to `story:graph-policy-adapter`, which owns
`mandate_policy::port::PolicyAdministration` and `mandate_graph::topology::ResourceRegistry` —
each crate's own `double` is their only implementor today. The step refuses a double-backed
clause that defers to its crate's binding story.

A double row sitting *beside* a real row on one clause is refused, because it would be counted
in no column at all — not `real_covered`, which the real row already holds, and not
`double_only` — and the condition it stands in for would be published as decided on the real
path. So **where two conditions of one clause have different deciders, the clause is split into
those conditions**, each still a verbatim substring and the set still tiling the cause.
`mandate.graph.RegisterResource` is the worked example: "parent is unresolved" and "belongs to
another organization" are two clauses, because the shipped registry answers `Unavailable` for a
parent that does not resolve and only the tenant half produces the declared denial.

### `blocked_on`

A clause with no `path: real` `denial` row carries `blocked_on` naming a story the planning
store holds **and whose frontmatter `status:` is not a terminal rung** (`implemented`,
`archived`, `rejected`). For an unbound clause that story is `story:obligations-<crate>`,
the binding story that owns the crate's `tests/obligations.rs`.

Where the shipped path *cannot* produce the declared denial at all, the deferral names the story
that owns that path instead: no test the binding story could write would bind the clause until
the path answers with a denial. "parent is unresolved" defers to `story:graph-policy-adapter`
for that reason, and so does every clause whose only evidence is a `double` row — the two are
one rule read from two directions. Once that story reaches
`implemented` the step refuses every clause still deferred to it, which is what turns "the
work is planned" into "the work is done" without anyone having to remember to.

A command-level `blocked_on` carries the `no_state_change` obligation under the same rule.

## `addendum`

One row per step of the resolution order at `docs/sources/architecture-addendum.md` §5.2,
which is the order tenant context must be established in. `requirement` is the step's own
line, verbatim; `step` is its number.

```json
{"step": 2, "requirement": "validate issuer", "tests": [{"id": "…", "kind": "denial", "path": "real"}]}
```

Each of the nine steps is named by at least one document. More than one crate may decide one
step — step 5 is decided at authorization by `mandate-federation` and again at redemption by
`mandate-sts` — so a step may appear in several documents, but never twice in one.

## `cases`

One row per id in `tests/security/cases.json`, across the directory: every id appears exactly
once and no row names an id that file does not carry.

```json
{"case": "tenant-ambiguous", "tests": [{"id": "…", "kind": "denial", "path": "real"}]}
```

A case row's tests may name the entry's own crate **or `mandate-proto` or `mandate-server`, and
no other package**. A security case is a scenario decided end to end, and `pkce-missing` and
`pkce-plain` are decided at the wire — the request never reaches a handler. The allowance is
those two packages and is bounded in the step; it is not the exemption it was, which let a case
row of any document name a test of any package. Clause, `no_state_change` and `addendum` rows
are held to the entry's crate alone.

## The report

`contracts/conformance/obligations-report.json` carries, per crate and in total,
`{clauses, real_covered, double_only, deferred}` over the clauses of `implemented` commands.
The three partition `clauses`: a clause with a `path: real` `denial` row is `real_covered`;
one with no such row but at least one `path: double` row is `double_only`; the rest are
`deferred`.
