---
format: aep.planning-md/1
id: review-result:wijk-i3-sts-lifetime-adversary-1
kind: review-result
status: active
title: Adversary pass 1 on I3 (sts-lifetime-bounds)
relations:
- reviews: story:sts-lifetime-bounds
revision: 1
---
unit: story:sts-lifetime-bounds, commit 0817c1e on base 86a32ae, plus an untracked adversary test file in the working tree
verdict: red (one CONFIRMED doc-vs-code finding, warning; it is reached only through a registration record I built by hand)
cases: executed 211→213, red 1
origin: introduced 1, pre-existing 0, undecided 0
wrote-outside-worktree: ~/.cache/claude-tmp/wijk/i3/scratch/adv1-suite.log
needs-coordinator: no

**1. Diff stat.** `git --no-pager diff --stat` is empty. `git status --short` shows one untracked file, `?? services/sts/tests/adversary_lifetime_bounds_1.rs`, which is a test file. No implementation file was touched.

**2. Cases added** in `services/sts/tests/adversary_lifetime_bounds_1.rs`:

| case | what it checks | now |
|---|---|---|
| `a_profile_the_registration_refuses_issues_nothing_as_its_doc_says` | Registration refuses `P2600000D` (about 7,118 years). A registration record with that profile, built by hand, then gets a reference credential issued at 2026-09-23. `registry.rs:139-140` says every issuance under such a profile is refused as `ExpiryUnbounded`. | red |
| `the_registration_bound_is_the_last_readable_second_from_the_year_3000` | `PT220898620799S` is admitted and `PT220898620800S` is refused. This pins the bound to the exact second. | green |

The red output, from running this file alone before the suite:
```
assertion `left == right` failed: registry.rs: a bound `admits_profile` refuses is one under which `every issuance under it would be refused as ExpiryUnbounded`
  left: Ok(Timestamp("9145-04-15T00:00:00Z"))
 right: Err(Denied { reason: Denied, clause: ExpiryUnbounded, outcome: Denied })
```

**3. Suite run, after the cases existed.** `cargo test -p mandate-sts --locked --no-fail-fast` gave EXIT=101 with 212 passed and 1 failed (the case above). Leaving out my 2 cases, 211 ran. `cargo clippy -p mandate-sts --all-targets --locked -- -D warnings` printed `Finished \`dev\` profile [unoptimized + debuginfo] target(s) in 0.13s`.

**4. Findings** (they cover 0817c1e plus the untracked file):

| # | file:line | verdict | origin | measured | what reaches it |
|---|---|---|---|---|---|
| F1 | services/sts/src/registry.rs:139 | CONFIRMED | introduced | Registration checks the bound from the year 3000. Profiles with a `max_ttl` of roughly 7,000 to 7,970 years are refused, but issuing under one today works and gives a readable expiry (year 9145). So the doc sentence "every issuance under it would be refused" is false. The fix is to reword the sentence to "issuance at a request instant after 9999 minus max_ttl would be refused". | Nothing found. The only other writer of `ResourceServerRegistered` is `ResourceServerSeed::events` (`services/control-plane/src/adapters.rs:1543`), and only tests call it. The binary seeds through `TargetSeeding::admit`, which calls `register_resource_server`. |
| F2 | services/sts/tests/adversary_obligations_sts_1.rs:386 | CONFIRMED | introduced | The shipped suite admits `P36500D` and refuses `P3650000D`. That still passes if `LATEST_CHECKED_REQUEST_INSTANT` (`lib.rs:437`) is changed to any year from 0 to 9899. The new boundary case would catch that change, but I did not build a mutated copy to prove it. | Every registration goes through `admits_profile`. |
| F3 | services/sts/tests/obligations.rs:48 | CONFIRMED | introduced | Two tests (`narrowing_refuses…`, `a_redemption_refused_on_the_narrowing_clause…`) moved from records made by the real registration handler to records built by hand. Their assertions were not weakened, but the narrowing clause is now "arranged" rather than "decided" in that file's own terms. The admitted path the doc points to uses a request dated 0000-01-01+01:00, which no system clock produces. This is the price of meeting the acceptance statement, not a defect. | Nothing found. |
| F4 | story Outcome | CONFIRMED | introduced | Read literally, the Outcome ("added to any instant the crate renders") would refuse every positive `max_ttl`. The code applies it from 3000-01-01, the same point control-plane uses. The Acceptance statement is met exactly. | Not applicable (it is wording in the story). |

**5. Attacked and could not break:**
- There is only one place that produces an expiry timestamp (`lib.rs` `at`). All three issuance sites now refuse when it returns nothing: `issue.rs:303` (reference and self-contained) and `redemption.rs:350`.
- `CodeIssuance::issue` and `SigningKeys::register` store the caller's `expires_at` word for word, after `seconds_of` has already read it. They are readable by construction.
- `at`'s round-trip check holds at the year -1, the year 10000, requests with a UTC offset, and leap second 60.
- The Acceptance case `a_profile_bound_past_the_readable_year_is_refused_or_renders_readably` is present, asserts `ProfileUnadmitted`, and passes.
- The `adversary_transaction_1.rs` rewrite still asserts the handler's refusal: the only `max_ttl` values allowed to take the hand-built fallback are `P3650000D` and `P999999999D`.
- Profiles are admitted from 3000 on, so a real request (year up to 2999) never produces an expiry that cannot be rendered.

**6. Paths written outside the worktree:** ~/.cache/claude-tmp/wijk/i3/scratch/adv1-suite.log

Left in the working tree: services/sts/tests/adversary_lifetime_bounds_1.rs (1 red, 1 green).

**7. Findings block:**
```findings
- file: services/sts/src/registry.rs
  line: 139
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'admits_profile doc claims every issuance under a refused bound is refused, but the bound is decided from 3000 so a 7118-year profile issues a readable 9145 expiry from a 2026 request'
- file: services/sts/tests/adversary_obligations_sts_1.rs
  line: 386
  category: mutant
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the shipped admitted/refused pair (P36500D, P3650000D) leaves LATEST_CHECKED_REQUEST_INSTANT unpinned anywhere from year 0 to 9899; the exact-second boundary case now pins it'
- file: services/sts/tests/obligations.rs
  line: 48
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the narrowing-clause cases moved from handler-registered to hand-built records, and the only admitted-path reach cited needs a year-0 request instant no clock produces'
- file: story:sts-lifetime-bounds
  category: acceptance
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'Outcome wording (any instant the crate renders) is unsatisfiable literally; the implementation applies it from 3000-01-01 and meets the Acceptance statement exactly'
```
