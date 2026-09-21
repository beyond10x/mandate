# `mandate-use-case/1`

> **This registry is authored ahead of its check.** `cargo xtask use-cases` is specified in
> `docs/adr/0011-use-cases.md` and is not implemented, so nothing in `task check` reads this
> directory today and **every claim in it is a claim a human made**. The unit that lands the step
> removes this banner, and nothing else does.

One thing a customer buys, written as the composition that delivers it: the commands it runs in
order, the routes it is reached through, the parties on every end of it, the configuration each
party supplies, the evidence that each step is decided, the standards it implements, and the things
about it that are not true yet.

One document per use case, named after it: `federated-login.json` is the use case `federated-login`,
and the `use_case` member is the file's stem.

`cargo xtask use-cases` reads this directory whole. It writes
`contracts/conformance/use-case-report.json` and compares it byte-for-byte with the committed one;
`cargo xtask use-cases --write` is how that file is moved. The rules the step enforces are the ones
below, and the reasons for them are in `../../docs/adr/0011-use-cases.md`.

## Why a use case and not a coverage row

`contracts/coverage.json` answers, one row per element, "does anything implement this and does any
test decide it". `contracts/obligations/*.json` answers, one row per denial clause, "does the
shipped path refuse on *this* condition". Neither can answer the question a customer asks, which is
whether **this road** works: an ordering of several commands, reached over routes that are not part
of the contract at all, configured by people who are not in this repository, against standards the
contract does not name.

That question was previously answered by reading four documents and a test file. A use case is one
file, and it is refused the moment any part of the answer stops being true.

## What a document states

```json
{
  "format": "mandate-use-case/1",
  "use_case": "federated-login",
  "title": "…",
  "summary": "…",
  "serves": { … },
  "parties": [ … ],
  "steps": [ … ],
  "routes": [ … ],
  "configuration": [ … ],
  "standards": [ … ],
  "not_yet_true": [ … ]
}
```

Every member is required and none may be empty, except `not_yet_true`, which is empty only for a use
case with no gaps at all.

## The seven kinds, and the one that is not checked

Every row inside `parties` carries a `kind`, and the kind decides what the step resolves it against.
This is the whole of the format's honesty: a claim says what sort of claim it is, and one sort is
marked as unresolvable rather than quietly counted with the rest.

| `kind` | further members | resolved against |
|---|---|---|
| `contract` | `element`, `element_kind` | `generated/ir/system.json` declares that element under that kind |
| `route` | `method`, `path`, `binds` | a member of `mandate_server::routes::ROUTES`, binding the same thing |
| `configuration` | `flag`, `type`, `field` | the row appears in this document's own `configuration` section |
| `scenario` | `id`, `outcome` | `contracts/expected-outcomes.json` carries that id with **exactly** that outcome |
| `test` | `id` | a compiled test binary lists it **and runs** it |
| `artifact` | `id` | the planning store holds it and it is not on a terminal rung |
| `promise` | `party`, `locally_refutable`, `refuted_by` | **nothing here checks it.** See below. |

Every kind also carries `statement`: one sentence, in the present tense, saying what this row means
for the road. It is prose and the step does not read it; it is what a person reads first.

### `promise`

A use case names parties **outside this system**, and no check in this repository can observe what a
customer's identity provider does. A registry that counted those claims with the checked ones would
publish a number that means less the more of them it holds, and would be read as though it did not.

So a promise is marked, and three members are required of it:

- `party` — whose promise it is, matching a `party` in this document with `"outside": true`. A
  promise with no owner is a wish.
- `locally_refutable` — a boolean, stated and never inferred: whether anything in this deployment
  would be observed at all if the promise were false.
- `refuted_by` — when `locally_refutable` is true, what an operator would observe: the refusal or
  the symptom. *"every login through this connection is refused at resolution-order step 3"* is a
  refutation; *"login would break"* is not. When it is false, the same field says what is
  **believed instead**, and why nothing here observes it.

`locally_refutable: false` is the honest answer for a real share of what any use case rests on —
nine of `federated-login.json`'s seventeen promises. It is a separate boolean rather than a turn of
phrase inside `refuted_by` because the interesting thing about it is the **count**: `unrefuted` in
the report goes up when somebody adds a dependency nobody could see fail, and a sentence would not.

A `promise` row carrying `tests`, `scenarios` or `routes` is **refused**: it is a checked row that
was filed in the wrong column. So is a promise appearing in a `relies_on` list. A promise is never
counted in `checked`, never in `gaps`, and never in the numerator of anything.

## `parties`

One row per actor the road touches, inside this system and outside it.

```json
{"party": "customer-identity-provider",
 "outside": true,
 "role": "…",
 "delivers": [ {kind row}, … ],
 "relies_on": [ {kind row}, … ]}
```

`delivers` is what this party must supply for the road to work. `relies_on` is what it is entitled
to assume the other parties supply. Exactly one party carries `"outside": false` — the Mandate
deployment itself — and it is the only party whose `delivers` rows may be `contract`, `route` or
`test`: those are the only claims this repository can make on somebody's behalf. Every `delivers`
row of an outside party is `promise` or `configuration`.

That constraint is the registry's whole position on the question. What Mandate delivers is checked
because Mandate is here. What a customer delivers is promised because they are not.

**A promise is stated exactly once, in the `delivers` of the party that owes it.** A `relies_on` row
is never a `promise`: it points at something *checked* that another party delivers, and a promise
restated as somebody else's reliance would be one obligation counted twice and movable in two
places. What the deployment relies on from outside parties is therefore read by looking at those
parties' `delivers`, which is where their promises are — and there is exactly one copy to correct
when one changes.

`configuration` rows appear in both sections and in the `configuration` section, and that is not
duplication: `parties` says whose obligation a field is, and `configuration` says what the field is
and what the reader does with it. The `field` and `type` are the join.

## `steps`

The ordered commands. One command per step, numbered `1..n` with no gaps, in the order the road runs
them.

```json
{"step": 6,
 "actor": "customer-end-user",
 "command": "mandate.federation.AuthenticateFederation",
 "when": "every login",
 "addendum_steps": [1, 2, 3, 4, 6, 7, 8],
 "evidence": [ {kind row}, … ]}
```

`command` is an IR name and the step refuses one the model does not declare. `actor` names a party
of this document. `when` says when the step runs — `configuration`, `every login`, `first login
only`, and so on — because a road whose steps all read as "then" hides which ones a customer does
once and which ones happen per request.

`addendum_steps` cites the resolution order at `docs/sources/architecture-addendum.md` §5.2 by
number. It does **not** restate the requirement: `contracts/obligations/*.json` already carries each
of the nine verbatim and binds it to a test, and a second copy here would be a second answer to one
question. The step checks only that each number is one the obligations registry names.

`evidence` carries `scenario` and `test` rows, and nothing else.

**A step whose command `contracts/coverage.json` calls `implemented` and that carries no evidence is
refused**, and no `not_yet_true` row excuses it: a gap says the road is incomplete, not that the
part of it that exists is unchecked. A step whose command is *not* implemented may carry no
evidence — there is no shipped path for evidence to be about — and must then be named by a
`not_yet_true` row.

## `routes`

The served surface, as `crates/mandate-server/src/routes.rs` holds it.

```json
{"method": "POST", "path": "/v1/federation/login",
 "binds": {"command": "mandate.federation.AuthenticateFederation"},
 "statement": "…"}
{"method": "GET", "path": "/oauth/jwks",
 "binds": {"document": "Jwks"},
 "statement": "…"}
```

A row must equal a member of `ROUTES` and bind the same thing. That comparison is made in
`crates/mandate-server/tests/use_cases.rs`, in the crate that owns the table, because parsing Rust
from `xtask` to learn a route table would be a second answer that can disagree with the first. The
`xtask` step refuses the **absence** of that case: a lane that runs nothing exits 0, and an absent
check is indistinguishable from a passing one unless something counts it.

## `configuration`

One row per field an operator writes, across every flag the road is configured through.

```json
{"party": "customer-administrator",
 "flag": "--connection",
 "type": "ConnectionSeed",
 "field": "tenant_resolution",
 "required": true,
 "statement": "…",
 "example": { … }}
```

`type` is one of the four readers in `services/control-plane/src/adapters.rs` — `ConnectionSeed`,
`PrincipalLinkSeed`, `ClientSeed`, `ResourceServerSeed` — or `argument` for a bare command-line
argument of `services/control-plane/src/main.rs`, which has no document to deserialize.

`example` is a complete document of that type, carrying this field. It is validated by
**deserializing it through the real reader** in `services/control-plane/tests/use_cases.rs`: all
four are `#[serde(deny_unknown_fields)]`, so a field renamed in the reader fails the case with
serde's own message, and a required field this registry forgot fails it the same way. There is no
second copy of the field list anywhere.

`required: false` means the reader defaults it. Where the default is security-relevant the
`statement` says what absence buys — for `algorithm`, absence is the operator declining to configure
verification and the deployment refusing every login through that connection.

## `standards`

One row per RFC the road implements, tied to the part of the flow it governs and to a file that
cites it.

```json
{"rfc": 7636, "section": "4.2",
 "governs": "the code challenge the authorization request carries",
 "steps": [8, 10],
 "cited_at": "crates/mandate-federation/src/pkce.rs"}
```

`cited_at` must exist and must contain the string `RFC <number>`. A standard nothing in the tree
references is a standard this road does not implement, whatever a document says. `steps` names the
steps it governs, each one of this document's own.

## `not_yet_true`

One row per gap: something a reader would otherwise assume and that is false today.

```json
{"gap": "no persistence",
 "costs": "…",
 "today": "…",
 "blocked_on": "story:declared-writers"}
```

`costs` is what a customer loses. `today` is what actually happens instead, in one sentence a person
can check by running the thing.

`blocked_on` names a story or blocker the planning store holds **whose rung is not terminal**
(`implemented`, `archived`, `rejected`, `cleared`). When the owner finishes, the row goes red and
must move or be deleted — the same forcing function `contracts/expected-outcomes.json` uses, and the
reason a gap list does not quietly outlive its gaps.

### A gap nobody owns

Some gaps have no live owner, and the registry says so rather than attaching the nearest plausible
story. Such a row replaces `blocked_on` with:

```json
{"unowned": {"noted_in": "<path>", "noted_words": "<verbatim substring of that file>"}}
```

`noted_words` must appear **verbatim** in `noted_in` — the same rule
`contracts/obligations/README.md` applies to a clause against its declared cause, and for the same
reason: a citation that is merely *about* a file cannot be falsified, and one that quotes it can.
The words must be somebody's own record that the gap exists, not a sentence written to satisfy this
field.

These rows are counted in their own column of the report, `unowned`, because an unowned gap is a
worse fact than an owned one and a registry that averaged the two would hide it. **An unowned row is
not a resting place.** It is a request for a story, addressed to whoever reads the count.

## The report

`contracts/conformance/use-case-report.json` carries, per use case and in total:

```json
{"use_case": "federated-login",
 "steps": 11, "routes": 6, "configuration": 33,
 "checked": 129, "promises": 17, "unrefuted": 9, "gaps": 6, "unowned": 2,
 "evidence": {"scenarios": 25, "tests": 72},
 "standards": 12}
```

Those are `federated-login.json`'s figures today, and they are what the step must reproduce.

`checked`, `promises` and `gaps` partition every `delivers`, `relies_on` and `evidence` row; the
report never sums the first two. `unrefuted` is a subset of `promises` and `unowned` is a subset of
`gaps`. Both are printed beside their parent and never inside it: each names the part of its parent
that is worse, and an average would hide exactly the thing the column exists to show.
