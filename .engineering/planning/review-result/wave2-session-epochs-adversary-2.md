---
format: aep.planning-md/1
id: review-result:wave2-session-epochs-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — story:session-epochs
tags:
- model-deviation-opus
relations:
- reviews: story:session-epochs
revision: 1
---
```
unit: story:session-epochs, pass 2 — working tree <worktree>, branch impl/session-epochs, uncommitted over base 11ce4818f1280791b77a99577680c888d37af69f
verdict: NEEDS-CHANGE
cases: executed 64→72, red 8
origin: introduced 5 / pre-existing 2 / undecided 0
wrote-outside-worktree: 12 paths (11 files + the assigned scratch directory), plus the coordinator's build directory — part 6
needs-coordinator: the `## Acceptance` sentence is still the one at the base commit and the architecture contradicts it (`docs/architecture/combined.md:47`); only the coordinator can change it
```

## 1. `git --no-pager diff --stat`

```
 crates/mandate-identity/src/lib.rs | 159 ++++++++++++++++++++++++++++++++++++-
 1 file changed, 157 insertions(+), 2 deletions(-)
```

That one tracked modification is the **implementor's**. The rest of the unit is untracked, so `diff --stat` cannot show the bound held by itself; `git status --short` plus mtimes can:

```
 M crates/mandate-identity/src/lib.rs      21:30  implementor
?? crates/mandate-identity/src/*.rs        21:06-21:32  implementor
?? crates/mandate-identity/tests/          21:03-21:32 implementor; 21:17 pass-1 adversary; 21:43-21:44 mine
?? target                                  a symlink to the coordinator's build directory
```

I created exactly four files, all `crates/mandate-identity/tests/adversary_*.rs`: `adversary_timestamp_form.rs`, `adversary_acceptance.rs`, `adversary_surface.rs`, `adversary_ordering.rs`. No `src/**` file, no implementor test file, and none of pass 1's four files were touched (all still 21:17) — their green result below is therefore evidence about the fixes, not about me. No non-test path in my contribution.

## 2. The cases I added, run alone, before the suite

**`crates/mandate-identity/tests/adversary_timestamp_form.rs`** — 4 cases, all red now. The expiry decision is `self.expires_at <= *as_of` over a `String` newtype; RFC 3339 `date-time` — the form `Timestamp` declares — has several lexical spellings of one instant and does not order chronologically.

```
running 4 tests
test a_session_is_expired_at_an_instant_that_names_a_fraction_of_a_second_after_its_expiry ... FAILED
test a_session_that_has_not_expired_is_not_refused_because_its_expiry_carries_an_offset ... FAILED
test an_expired_session_does_not_refresh_because_the_readers_instant_carries_an_offset ... FAILED
test the_expiry_boundary_holds_for_the_same_instant_written_in_the_other_declared_utc_form ... FAILED

panicked at crates/mandate-identity/tests/adversary_timestamp_form.rs:132:5:
2026-09-18T12:00:00.500Z is after 2026-09-18T12:00:00Z, so the session has expired

panicked at crates/mandate-identity/tests/adversary_timestamp_form.rs:144:5:
the session is refreshable for another hour; `expires_at` is 2026-09-19T01:00:00Z written with a -05:00 offset

panicked at crates/mandate-identity/tests/adversary_timestamp_form.rs:105:14:
the session expired half an hour before the instant this read is evaluated at: SessionRefreshed { session_id: SessionId(Uuid([20, ...])) }

panicked at crates/mandate-identity/tests/adversary_timestamp_form.rs:119:5:
2026-09-18T12:00:00+00:00 is the instant the session expires at, and the pinned boundary (`expires_at <= as_of`) makes that instant expired

test result: FAILED. 0 passed; 4 failed; 0 ignored; 0 measured; 0 filtered out
```

**`crates/mandate-identity/tests/adversary_acceptance.rs`** — 1 case, red. The unit's `## Acceptance` statement asserted as written. Note the first clause passes; only the second fails.

```
running 1 test
test an_authoritative_increment_rejects_the_session_without_changing_an_unrelated_organizations ... FAILED

panicked at crates/mandate-identity/tests/adversary_acceptance.rs:133:5:
the second clause of the acceptance statement: "without changing eligibility in unrelated organization sessions". Organization B is named by no part of this increment and holds its own generation, and its session's eligibility changed

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out
```

**`crates/mandate-identity/tests/adversary_surface.rs`** — 2 cases, both red. An integration test is a separate crate, so what it reaches is what `mandate-federation` reaches.

```
running 2 tests
test a_crate_outside_mandate_identity_cannot_advance_a_generation_without_the_compare_and_set ... FAILED
test a_crate_outside_mandate_identity_cannot_deny_every_future_increment_for_a_target ... FAILED

panicked at crates/mandate-identity/tests/adversary_surface.rs:102:5:
assertion `left == right` failed: src/port.rs:11-13: "A holder of a read port cannot advance a generation through the type it holds." A holder of the concrete `IdentityLog` advanced it to 2 without ever calling the write port and without a compare-and-set
  left: Generation(2)
 right: Generation(0)

panicked at crates/mandate-identity/tests/adversary_surface.rs:74:5:
assertion `left == right` failed: a crate outside `mandate-identity` put the organization's authoritative generation at `Generation::MAX`, and `IncrementSecurityEpoch` now denies for that target forever ... `src/port.rs:136-137` says the shipped surface of this module is the two port traits, and it is not
  left: Some(Denied)
 right: None

test result: FAILED. 0 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out
```

**`crates/mandate-identity/tests/adversary_ordering.rs`** — 1 case, red. Did the terminal-state fix hold or move?

```
running 1 test
test a_recorded_revocation_is_not_undone_by_an_opening_that_arrives_after_it ... FAILED

panicked at crates/mandate-identity/tests/adversary_ordering.rs:55:5:
`Revoked` is declared terminal (`identity.yaml`, `terminal: [Revoked]`) and `src/port.rs:142-145` rests that on `try_record` refusing the second open; the log holds this identity's revocation, accepted the open anyway, and the session resolves Some(Active)

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out
```

## 3. The suite, after the cases in part 2 existed

`cargo fmt -p mandate-identity -- --check` → exit 0, no output.
`cargo clippy -p mandate-identity --all-targets --locked -- -D warnings` → exit 0, `Finished dev profile`.
`cargo test -p mandate-identity --locked --no-fail-fast` → **exit 101**:

```
 Running unittests src/lib.rs             running 0 tests   ok. 0 passed
 Running tests/adversary_acceptance.rs    running 1 test    FAILED. 0 passed; 1 failed
 Running tests/adversary_expiry.rs        running 2 tests   ok. 2 passed; 0 failed
 Running tests/adversary_lifecycle.rs     running 2 tests   ok. 2 passed; 0 failed
 Running tests/adversary_monotonic.rs     running 3 tests   ok. 3 passed; 0 failed
 Running tests/adversary_ordering.rs      running 1 test    FAILED. 0 passed; 1 failed
 Running tests/adversary_surface.rs       running 2 tests   FAILED. 0 passed; 2 failed
 Running tests/adversary_timestamp_form.rs running 4 tests  FAILED. 0 passed; 4 failed
 Running tests/adversary_version.rs       running 1 test    ok. 1 passed; 0 failed
 Running tests/generation.rs              running 6 tests   ok. 6 passed; 0 failed
 Running tests/increment.rs               running 7 tests   ok. 7 passed; 0 failed
 Running tests/port.rs                    running 14 tests  ok. 14 passed; 0 failed
 Running tests/refresh.rs                 running 11 tests  ok. 11 passed; 0 failed
 Running tests/staleness.rs               running 9 tests   ok. 9 passed; 0 failed
 Running tests/surface.rs                 running 6 tests   ok. 6 passed; 0 failed
 Doc-tests mandate_identity               running 2 tests   ok. 2 passed; 0 failed
                                          running 1 test    ok. 1 passed; 0 failed
```

`<after>` = 72; subtracting my four targets (1+1+2+4 = 8) gives 64, which is the number the implementing state reported. **All four of pass 1's files are green**: the four fixes held under the cases that found them. I deleted, skipped and weakened nothing.

## 4. Findings — working tree above, base 11ce4818

| # | file:line | What is wrong | What was measured | What reaches it | Verdict | Origin |
|---|---|---|---|---|---|---|
| F1 | `crates/mandate-identity/src/session.rs:169` (doc at `:163-171`) | `is_expired_at` is `self.expires_at <= *as_of`, a byte comparison of two `String`s. The declared type is `Timestamp` = RFC 3339 `date-time` (`format: date-time`, no pattern), which admits `+hh:mm`/`-hh:mm` offsets and `time-secfrac`, and whose lexical order is not its chronological order. The sentence above the function hedges on "two `Z`-form instants"; nothing requires that form — `Timestamp::new`, `Session::new`, `with_as_of` and `IdentityRead::as_of` all take any string, and `mandate-types` says outright that validating the form "is a runtime obligation this milestone does not discharge" (`crates/mandate-types/src/value.rs:219-220`). The equality boundary the unit pinned at `tests/refresh.rs:344` is form-dependent. | `adversary_timestamp_form.rs:105` — a session that expired at 12:00:00Z refreshes `Ok` at 11:30:00-01:00 (= 12:30Z); `:119` the same instant in the other UTC spelling is not the boundary; `:132` a half-second-later instant is not expired; `:144` a live session is refused. exit 101 | *Nothing found* as a producer — no host in this repository constructs a `Session` or supplies `as_of`. But the crate's only instant-supplying API is `with_as_of(Timestamp)`, it refuses no form, and the two ordinary Rust renderings of "now" (`chrono` `to_rfc3339()` → `+00:00` and fractional seconds; `time` `Rfc3339` → fractional seconds) are both in the broken set. Fix: state the precondition (UTC `Z`, whole seconds) at `Session::new`, `with_as_of` and `IdentityRead::as_of`, or compare a normalized form. | `NEEDS-CHANGE` | `introduced` (`src/session.rs` does not exist at the base) |
| F2 | `.engineering/planning/story/session-epochs.md`, `## Acceptance` | "…then it is rejected as stale **without changing eligibility in unrelated organization sessions**." A principal-target increment changes it: organization B is named by no part of the increment and its session goes from eligible to `StaleEpoch`. Correction round 1 pinned that behaviour deliberately (`tests/refresh.rs:309-331`) and said the coordinator would clarify the sentence; the sentence is byte-identical to the base commit. The suite now pins the reading the gate criterion denies. | `adversary_acceptance.rs:133` — B refreshes `Ok` before the increment and `StaleEpoch` after it; the case's first clause (A denies `StaleEpoch`) passes. exit 101 | The acceptance statement is the gate criterion. **The architecture is on the implementation's side**: `docs/architecture/combined.md:47` says "Changes in organization A do not invalidate unrelated organization B sessions, **except a deliberately global principal reset**", and `runtime-decisions.md:72` names both cases as required — both exist and pass. So the defect is the story sentence, which dropped the exception. Fix: add the exception clause to `## Acceptance`; no code change. Then `adversary_acceptance.rs` is the case that should be deleted, by whoever owns the story — not by me. | `NEEDS-CHANGE` | `pre-existing` (identical at 11ce4818) |
| F3 | `crates/mandate-identity/src/port.rs:136-137` | "the shipped surface of this module is the two port traits, and these variants are how a host or a test seeds the fold." It is not. `#[doc(hidden)]` is a rustdoc directive and removes nothing from the API: `IdentityEvent` and its variants are `pub`, `IdentityLog::{new, with_as_of, record, try_record, events}` are `pub`, none is behind `#[cfg(test)]`, a feature or a seal. Pass 1's F5 therefore still stands with the surface unchanged — the documentation moved, the reach did not. `SecurityEpochIncremented` carries no `#[doc(hidden)]` at all, so the *fully documented* API advances the authoritative generation with no compare-and-set, which is the one thing `decision-blocker:epoch-atomicity` and `src/port.rs:6-9` say the write port is for. | `adversary_surface.rs:102` — two `record` calls from an outside crate move the generation `0 → 2` with no expected version anywhere; `:74` — one `record` call puts a target at `Generation::MAX` and `IncrementSecurityEpoch` returns `Denied` for it from then on, permanently. exit 101 | The dependency edge already exists: `crates/mandate-federation/Cargo.toml:16` and `crates/mandate-provisioning/Cargo.toml:16` both declare `mandate-identity`. Neither crate has a body yet (`src/lib.rs` only), so no call site exists **today**. Fix: `#[cfg(feature = "testkit")]` or a sealed seeding builder, or keep the deferral and change the sentence to say what is actually shipped. | `CONFIRMED` | `introduced` |
| F4 | `crates/mandate-identity/src/port.rs:234` (with `:256-274`) | The terminal-state fix is keyed on `resolve(id).is_some()`, i.e. "this identity currently projects to a session", not "this identity was revoked". `resolve` returns `None` when the only recorded event for an identity is its `SessionRevoked` — the fold has nothing to apply `revoke` to. So a `SessionOpened` that arrives after a recorded revocation is refused by neither `try_record` arm, and the session resolves `Active`. The fix closed the replay instance; the class it was written for ("`Revoked` is declared terminal and no transition leaves it", `:142-145`) is order-dependent. | `adversary_ordering.rs:55` — after `record(SessionRevoked(id))`, `try_record(SessionOpened(…))` returns `Ok` and the session resolves `Some(Active)`. exit 101 | *Nothing found.* I built the ordering: the log is append-only, this crate emits neither event, and no producer of either exists. Fix: refuse a `SessionOpened` for an identity any `SessionRevoked` names, rather than for one `resolve` currently returns. | `INFEASIBLE` (a state I built; no producer) | `introduced` |
| F5 | `crates/mandate-identity/src/port.rs:229-233` | The lowering guard is `*generation < current`, so re-recording the **equal** generation is accepted. It changes no projection and still consumes a stream version, which invalidates every concurrent writer's compare-and-set token for that target — and it can be repeated without bound, starving `IncrementSecurityEpoch` indefinitely. `:212-215` describes `record` as refusing an event that "would move a monotonic projection backwards, leave a terminal lifecycle state or rewrite an immutable record"; this one does none of those and is not a no-op either. | Scratch probe `probe.bin` (a): `gen=5 ver=1` → equal re-record accepted → `gen=5 ver=2` → a writer holding the pre-record token gets `Some(Unavailable)`. No case added: no document promises that an event changing nothing costs no version, and I will not invent one. | Same surface as F3, so the same reach: no in-repo caller today. Fix: refuse `*generation <= current` when the target already holds a recorded generation, or exclude a no-op recording from the version count. | `CONFIRMED` | `introduced` |
| F6 | `crates/mandate-identity/src/session.rs:234-238` | The brief's question, answered by measurement: yes, the fail-closed ordering distinguishes a current session from a stale one with no instant, because `Unavailable` is returned *only* for a session that passed everything else. `refresh_session` takes a `&SessionId` and performs no proof verification (that is "the credential domain's", `:190`), so the oracle is available to anyone who can name a session id. Separately, `DenialReason::Unavailable` means "the stream moved, read again and retry" at `port.rs:335` and "this reader has no clock, retrying will never help" here; a caller cannot tell them apart and a host that retries on `Unavailable` spins. | Scratch probe `probe.bin` (b), undated reader: current → `Unavailable`, stale → `StaleEpoch`, revoked → `InvalidCredential`, unknown → `InvalidCredential`. | The trade-off is real and was chosen knowingly — the alternative order loses the `StaleEpoch` denial correction round 1 asked for. My judgement: acceptable **if said out loud**, not acceptable silently. Fix: one sentence at `refresh_session` that it presumes an authenticated caller and that the refusal order is observable, and a second that `Unavailable` here is terminal, not retryable. | `CONFIRMED` | `introduced` |
| F7 | `docs/architecture/federated-login.md:130` | Repeated from pass 1, unfixed, with one correction to pass 1's wording: the citation `command-obligations.md:36` for "at the maximum the increment is denied and an out-of-band reset is required" points at the `mandate.federation.AuthorizePublicClient` row (pass 1 said `DisableFederationConnection`, which is `:37`). The `mandate.identity.IncrementSecurityEpoch` row is `:49`. Repeated at `runtime-decisions.md:59` and in the story body's "The stand-in, recorded". | Read both files at the working tree and at 11ce4818 — identical. | A reader following the citation to check the epoch decision. Outside this unit's writable scope. | `CONFIRMED` | `pre-existing` |

## 5. What I attacked and could not break

- **Every pass-1 fix held rather than moved, as measured by the cases that found them**: `adversary_lifecycle` 2/2, `adversary_monotonic` 3/3, `adversary_expiry` 2/2, `adversary_version` 1/1, all green, all files untouched at 21:17.
- The `compile_fail` doctest still fails for exactly the property it names after the trait grew `as_of` — I compiled the snippet standalone against the built rlib and got `error[E0599]: no method named 'increment' found for reference '&dyn IdentityRead'` and nothing else.
- The refused-lowering guard: a strictly lower `SecurityEpochRecorded` is refused by `try_record` and ignored by the fold; an equal one is accepted but moves no generation (its only effect is F5's version).
- The `max` fold cannot exceed what an increment issued: `increment` takes `&mut self`, so the borrow checker forbids two of them interleaving, and the version it returns is what `current` recomputes afterwards.
- `saturating_add` at saturation: the compare-and-set refuses, because `advance()` returns the same value and `port.rs:341-343` rejects `version <= state.version()`. That guard is unreachable (2^128 appends) and therefore untested by construction — the type's own documentation says so, so I am not filing it.
- `StreamVersion::new` takes `u64` into a `u128`: widening, no truncation; `INITIAL`, `Default` and `advance` agree; there is no `From`, so no constructible path to saturation.
- Cross-principal leakage on the principal dimension: incrementing principal 1 in an organization leaves principal 2's session in **that same organization** eligible (probe (c): `p1=StaleEpoch, p2=None`). An organization increment invalidating every principal in that organization is the declared `epoch-org` behaviour, not a leak.
- Object safety survived the new trait method; `&dyn IdentityRead` still compiles (`tests/port.rs:177`, `tests/surface.rs:281`).
- `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` both exit 0 with my four files present.
- Dependency ceiling: my files name `mandate-identity` and `mandate-types` only; no `[dev-dependencies]` added, no `std` item beyond the prelude.

## 6. Paths written outside the worktree

All eleven files are under the assigned scratch `<scratch>/`:

```
<scratch>/            (the directory)
<scratch>/case-timestamp-form.log
<scratch>/case-acceptance.log
<scratch>/case-surface.log
<scratch>/case-ordering.log
<scratch>/suite.log
<scratch>/fmt.log
<scratch>/clippy.log
<scratch>/compile_fail_probe.rs
<scratch>/compile_fail_probe.log
<scratch>/probe.rs
<scratch>/probe.bin      (4.7 MB)
```

Both `rustc` probes linked against the rlibs already in the build directory and wrote their binary to scratch. `cargo` wrote into **`<build-dir>`**, which is where the worktree's `target` symlink points — the coordinator's build directory, which I did not create and have not deleted. `CARGO_TARGET_DIR` was never set. No worktree was created, removed or pruned; no `git` write, no `aep` command of any kind. The lease `adversary-session-epochs-2` was started, heartbeated once and released; no other session's lease was touched. Disk before the run: 36G free on `/`.

## 7. Findings block

```findings
- file: crates/mandate-identity/src/session.rs
  line: 169
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: "the expiry decision is a byte comparison of two RFC 3339 strings, and the declared date-time form admits offsets and fractional seconds whose lexical order is not their chronological order, so a session that expired half an hour ago refreshes and a session that is live for another hour is refused, with no API refusing either form."
- file: .engineering/planning/story/session-epochs.md
  category: acceptance
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: pre-existing
  message: "the `## Acceptance` sentence still says an increment rejects the session \"without changing eligibility in unrelated organization sessions\", correction round 1 pinned the opposite for a principal target at tests/refresh.rs:309, and the architecture at docs/architecture/combined.md:47 supports the implementation by naming an exception the story sentence omits."
- file: crates/mandate-identity/src/port.rs
  line: 136
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: "\"the shipped surface of this module is the two port traits\" is false: `#[doc(hidden)]` removed the seeding variants from rustdoc and not from the API, so a crate outside mandate-identity still advances the authoritative generation with no compare-and-set and still puts a target at Generation::MAX, denying every future increment for it forever."
- file: crates/mandate-identity/src/port.rs
  line: 234
  category: boundary
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: "the terminal-state guard tests `resolve(id).is_some()` rather than whether the identity was revoked, and resolve returns None for a session whose only recorded event is its revocation, so a SessionOpened arriving after a recorded SessionRevoked is refused by neither try_record arm and the session resolves Active; I built that ordering and no producer of either event exists."
- file: crates/mandate-identity/src/port.rs
  line: 229
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: "the lowering guard refuses only a strictly lower recorded generation, so re-recording the equal value is accepted, changes no projection and still consumes a stream version, invalidating every concurrent writer's compare-and-set token and starving IncrementSecurityEpoch for that target without bound."
- file: crates/mandate-identity/src/session.rs
  line: 234
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: "deciding everything that needs no instant first makes Unavailable the unique signal for a session that passed every other check, so an undated reader distinguishes current from stale for anyone who can name a session id, and the same DenialReason means \"retry\" at port.rs:335 and \"never retry\" here."
- file: docs/architecture/federated-login.md
  line: 130
  category: contract-drift
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: "the citation command-obligations.md:36 for the deny-at-maximum decision points at the mandate.federation.AuthorizePublicClient row; the mandate.identity.IncrementSecurityEpoch row is :49, and the wrong line is repeated at runtime-decisions.md:59 and in the story body."
```