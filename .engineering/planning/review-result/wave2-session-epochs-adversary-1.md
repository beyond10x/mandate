---
format: aep.planning-md/1
id: review-result:wave2-session-epochs-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — story:session-epochs
tags:
- model-deviation-opus
- scratch-path-redacted
relations:
- reviews: story:session-epochs
revision: 1
---
```
unit: story:session-epochs — working tree at <worktree>, branch impl/session-epochs, uncommitted over base 11ce4818f1280791b77a99577680c888d37af69f
verdict: NEEDS-CHANGE
cases: executed 48→56, red 7
origin: introduced 5 / pre-existing 2 / undecided 0
wrote-outside-worktree: 11 paths, all under the assigned scratch (part 6)
needs-coordinator: whether session expiry belongs to this story or to one nobody owns yet; whether the out-of-band epoch reset needs a guard story; which reading of "unrelated organization sessions" the acceptance statement intends for a principal-scoped increment
```

## 1. `git --no-pager diff --stat`

```
 crates/mandate-identity/src/lib.rs | 146 ++++++++++++++++++++++++++++++++++++-
 1 file changed, 144 insertions(+), 2 deletions(-)
```

The one tracked modification is the **implementor's**, not mine. Everything else in this unit is untracked, so `diff --stat` cannot show the bound held on its own; `git status --short` plus mtimes do:

```
 M crates/mandate-identity/src/lib.rs      21:07  (implementor)
?? crates/mandate-identity/src/*.rs        21:06-21:07  (implementor)
?? crates/mandate-identity/tests/          21:03-21:07 implementor; 21:17 the four adversary_*.rs
```

I created exactly four files, all test files, all matching `crates/mandate-identity/tests/adversary_*.rs`: `adversary_lifecycle.rs`, `adversary_monotonic.rs`, `adversary_expiry.rs`, `adversary_version.rs`. No `src/**` file, no implementor test file, nothing outside the crate was touched. No non-test path in my contribution.

## 2. The cases I added, and their red output when written (each run alone, before the suite)

**`crates/mandate-identity/tests/adversary_lifecycle.rs`** — 2 cases, both red now. Asserts the declared `terminal: [Revoked]` lifecycle survives a replayed `SessionOpened`.

```
running 2 tests
test a_replayed_session_opened_does_not_leave_the_terminal_revoked_state ... FAILED
test a_replayed_session_opened_does_not_make_a_revoked_session_refreshable_again ... FAILED

panicked at crates/mandate-identity/tests/adversary_lifecycle.rs:97:5:
assertion `left == right` failed: `Revoked` is declared terminal; a replayed `SessionOpened` must not reopen it
  left: Active
 right: Revoked

panicked at crates/mandate-identity/tests/adversary_lifecycle.rs:117:5:
a revoked session does not refresh, however many times it was opened

test result: FAILED. 0 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out
```

**`crates/mandate-identity/tests/adversary_monotonic.rs`** — 3 cases, all red now. Asserts the authoritative generation never moves backwards, that a session already denied `StaleEpoch` stays denied, and that the out-of-band reset does not resurrect snapshots holding a reused generation.

```
running 3 tests
test a_generation_reset_to_zero_does_not_resurrect_every_snapshot_that_recorded_zero ... FAILED
test a_session_denied_as_stale_is_not_made_current_again_by_reusing_its_generation ... FAILED
test an_out_of_band_record_never_moves_the_authoritative_generation_backwards ... FAILED

panicked at crates/mandate-identity/tests/adversary_monotonic.rs:96:5:
the generation is declared monotonic; it went from 42 to 41

panicked at crates/mandate-identity/tests/adversary_monotonic.rs:119:14:
generation 41 was already issued against and is not reusable: SessionRefreshed { session_id: SessionId(Uuid([20, 20, ...])) }

panicked at crates/mandate-identity/tests/adversary_monotonic.rs:165:5:
the reset reused generation 0 and made the stale session current again

test result: FAILED. 0 passed; 3 failed; 0 ignored; 0 measured; 0 filtered out
```

**`crates/mandate-identity/tests/adversary_expiry.rs`** — 2 cases, 1 red, 1 green. The green one is deliberate: it shows `Timestamp: Ord` already orders the two instants this crate's own fixtures use, so the recorded reason for leaving expiry unevaluated does not hold up.

```
running 2 tests
test the_declared_expiry_is_comparable_without_arithmetic ... ok
test a_session_past_its_declared_expiry_does_not_refresh ... FAILED

panicked at crates/mandate-identity/tests/adversary_expiry.rs:84:5:
`RefreshSession` denies an expired record (identity.yaml:274) and `Session::expires_at` is 'when the session stops being refreshable'

test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out
```

**`crates/mandate-identity/tests/adversary_version.rs`** — 1 case, red now. `StreamVersion::advance` is the unchecked sibling of `Generation::advance`.

```
running 1 test
test advancing_the_maximum_stream_version_does_not_wrap_to_the_initial_one ... FAILED

panicked at crates/mandate-identity/src/port.rs:45:14:
attempt to add with overflow

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out
```

## 3. The suite run, after the cases above existed

`cargo fmt -p mandate-identity -- --check` → exit 0, no output.
`cargo clippy -p mandate-identity --all-targets --locked -- -D warnings` → exit 0, `Finished dev profile`.
`cargo test -p mandate-identity --locked --no-fail-fast` → **exit 101**:

```
     Running unittests src/lib.rs           running 0 tests   test result: ok. 0 passed; 0 failed
     Running tests/adversary_expiry.rs      running 2 tests   test result: FAILED. 1 passed; 1 failed
     Running tests/adversary_lifecycle.rs   running 2 tests   test result: FAILED. 0 passed; 2 failed
     Running tests/adversary_monotonic.rs   running 3 tests   test result: FAILED. 0 passed; 3 failed
     Running tests/adversary_version.rs     running 1 test    test result: FAILED. 0 passed; 1 failed
     Running tests/generation.rs            running 6 tests   test result: ok. 6 passed; 0 failed
     Running tests/increment.rs             running 7 tests   test result: ok. 7 passed; 0 failed
     Running tests/port.rs                  running 9 tests   test result: ok. 9 passed; 0 failed
     Running tests/refresh.rs               running 8 tests   test result: ok. 8 passed; 0 failed
     Running tests/staleness.rs             running 9 tests   test result: ok. 9 passed; 0 failed
     Running tests/surface.rs               running 6 tests   test result: ok. 6 passed; 0 failed
   Doc-tests mandate_identity               running 2 tests   test result: ok. 2 passed; 0 failed
                                            running 1 test    test result: ok. 1 passed; 0 failed
```

`<before>` = 48 is the implementing state's own reported number and is confirmed by this run with my four targets deselected: 0+6+7+9+8+9+6 = 45 integration/unit plus 3 doctests. `<after>` = 56. Every existing case still passes; I deleted, skipped and weakened nothing.

Plain `cargo test -p mandate-identity --locked` (the gate command as the brief states it) stops at the first failing target and reports exit 101 after `tests/adversary_expiry.rs`; `--no-fail-fast` is what produced the counts above.

## 4. Findings

| # | file:line | What is wrong | Measured | What reaches it | Verdict | Origin |
|---|---|---|---|---|---|---|
| F1 | `crates/mandate-identity/src/port.rs:164-178` | `IdentityLog::resolve` rebuilds the projection from the last `SessionOpened` it sees, so a duplicate one puts a revoked session back into `Active` and it refreshes. `identity.yaml:30-53` declares `terminal: [Revoked]` and one transition, `revoke: Active -> Revoked`. | `adversary_lifecycle.rs:97` `left: Active / right: Revoked`; `:117` refresh returns Ok; exit 101 | *Nothing found.* `SessionOpened` is not a declared contract event and has no producer; I appended the duplicate with the public `record`. Fix: fold `SessionOpened` only when the projection is absent. | `INFEASIBLE` (state I built; no producer exists) | `introduced` |
| F2 | `crates/mandate-identity/src/port.rs:180-205` (with `:120-127`, `:152`) | The fold applies any `SecurityEpochRecorded` value, including one below the generation already folded. The authority moves backwards, a generation already issued against is reused, and a session denied `StaleEpoch` refreshes. Contradicts `identity.yaml:1` "exact u64 monotonic semantics", `cases.json:321-330` `epoch-overflow` "no wrap **or reuse**", and the crate's own `src/lib.rs:14-15` "never wrapped and never reused". | `adversary_monotonic.rs:96` "went from 42 to 41"; `:119` `Ok(SessionRefreshed)` where `StaleEpoch` was expected; `:165` reset-to-zero re-validates a stale session; exit 101 | The documented workflow. `runtime-decisions.md:59` and `federated-login.md:130` **require** an out-of-band reset at the maximum; `src/port.rs:120-123` names this event as that reset; every value ≤ `MAX` has been issued, so the required procedure necessarily reuses one and nothing refuses it. Fix: fold `max(recorded, folded)` and have `record` refuse a lowering `SecurityEpochRecorded`, or carry a reset epoch that invalidates every prior snapshot. | `CONFIRMED` | `introduced` |
| F3 | `crates/mandate-identity/src/session.rs:173-186` | `Session::refresh` never reads `expires_at`, so an expired session refreshes. `identity.yaml:273-275` declares `denied` for "record is expired/revoked"; `src/session.rs:123` documents the field as "When the session stops being refreshable". The signature takes no instant, so the declared denial is unreachable through it at all. | `adversary_expiry.rs:84` refresh returns Ok for a session that expired 2020-01-01; exit 101 | `refresh_session` is this crate's realization of `mandate.identity.RefreshSession`; any host calling it with an expired session. The recorded reason ("`Timestamp` is a lexical string") does not hold: `Timestamp` derives `Ord` (`mandate-types/src/value.rs:221`) and `adversary_expiry.rs:91` passes. Fix: `refresh(&self, epochs, as_of: &Timestamp)`, or strike the `expires_at` doc claim and state the obligation as the host's. | `NEEDS-CHANGE` | `introduced` |
| F4 | `crates/mandate-identity/src/port.rs:44-46` | `StreamVersion::advance` is `Self(self.0 + 1)` unchecked, on a public type with public `new(u64)`, while `Generation::advance` (`generation.rs:52-58`) tests `is_at_maximum` first. At `u64::MAX` it panics with overflow checks and wraps to `INITIAL` without them — the one value the CAS at `port.rs:227` accepts for an untouched stream. | `adversary_version.rs` → `panicked at src/port.rs:45:14: attempt to add with overflow`; exit 101 | *Nothing found* — 2^64 recorded events. A property of the type, not a state anybody arrives at. Fix: `checked_add`, returning `Option<Self>` as `Generation::advance` does. | `INFEASIBLE` (2^64 events) | `introduced` |
| F5 | `crates/mandate-identity/src/port.rs:107-129` | Three of the five `IdentityEvent` variants — `SessionOpened`, `EpochSnapshotRecorded`, `SecurityEpochRecorded` — are declared by no `events:` entry in `identity.yaml` (which declares `PrincipalDisabled`, `SessionRevoked`, `RefreshCredentialRevoked`, `SessionRefreshed`, `SecurityEpochIncremented`, `Denied`). Under ADR-0009 the events are the record; these are unvalidated state-seeding constructs in a production crate's public API, and they are the vector both F1 and F2 land through. | Read: `identity.yaml` events list vs `src/port.rs:107-129` | Any holder of `&mut IdentityLog`; all six implementor test files seed through them. Fix: declare them in the contract, or put the seeding surface behind `#[doc(hidden)]`/a test-only builder so the shipped port is the two traits only. | `CONFIRMED` | `introduced` |
| F6 | `crates/mandate-identity/tests/refresh.rs:382-395` | No case asserts what a principal increment does to the same principal's session in an unrelated organization. `world()` builds exactly that (`refresh.rs:301-374`, one principal, sessions in A and B) and the principal case then asserts only `session_in_a`. Measured behaviour (scratch probe): `before: A=true B=true` → `after principal increment: A=false B=false`. Globally-scoped principal disablement is the sensible design and `cases.json:308-318` scopes `epoch-isolation` to an org reset — but the story's `## Acceptance` says "without changing eligibility in unrelated organization sessions" without qualification, and the suite pins neither reading. | `<scratch>/adversary/probe2` | The acceptance statement is the gate criterion. Fix: one case pinning B's denial after a principal increment, and one clause in the acceptance statement saying the exemption is organization-scoped. | `INFEASIBLE` (the story text does not decide it; an operator must) | `pre-existing` (acceptance text is at 11ce4818) |
| F7 | `docs/architecture/federated-login.md:130` | The citation `command-obligations.md:36` for "at the maximum the increment is denied and an out-of-band reset is required" points at the `mandate.federation.DisableFederationConnection` row. The `mandate.identity.IncrementSecurityEpoch` row is line 49. Repeated at `runtime-decisions.md:59` and in the story body's "The stand-in, recorded". | Read both files | A reader following the citation to check the epoch decision. Outside this unit's writable scope. | `CONFIRMED` | `pre-existing` |

## 5. What I attacked and could not break

- The `compile_fail` doctest (`src/lib.rs:92-99`) fails for exactly the property it names — I compiled the snippet standalone against the built rlib: `error[E0599]: no method named 'increment' found for reference '&dyn IdentityRead'`, and nothing else.
- No read-port method takes `&mut self`; `IdentityRead` is object-safe and exercised as `&dyn` in the implementor's own `port.rs:417-428`.
- Neither `Session` nor `SecurityEpochSnapshot` carries a `CredentialSecret`, `CredentialProof` or `CredentialVerifier`; the crate names no secret type at all.
- `IdentityLog::resolve` and `::snapshot` return `None` with no matching event — the fold fabricates no projection row.
- `Generation` boundaries: `MAX-1 → MAX` allowed, `MAX → None`, `new(-1)` and `new(i64::MIN)` → `None`, `new(i64::MAX) == MAX`; `advance` guards before it adds, so there is no wrap and no `checked_add` misuse.
- The CAS: `!=` refuses an expected version both behind and ahead; two writers at one version → exactly one commits, the second gets `Unavailable`; an unrecorded target is at `INITIAL` and increments from it once.
- Organization and federation isolation: an increment on one target moves no other target's generation or version, and `recorded()` returns `None` for a target the snapshot does not name.
- The snapshot compares every dimension it records, and a session whose `connection_id` disagrees with its snapshot's is refused `TenantMismatch` rather than silently skipping the federation dimension; a session with `connection_id: None` is exempt from that dimension and survives an unrelated connection's increment.
- Dependency ceiling: `Cargo.toml` names `mandate-types` and `mandate-model` only, no `[dev-dependencies]`; my four files add none, and `std::hint::black_box` is the only `std` item I reached for.
- `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` both pass with my files present.

## 6. Paths written outside the worktree

All eleven are under the assigned scratch `<scratch>/adversary/`:

```
<scratch>/adversary/monotonic.log
<scratch>/adversary/expiry.log
<scratch>/adversary/version.log
<scratch>/adversary/fmt.log
<scratch>/adversary/clippy.log
<scratch>/adversary/suite.log
<scratch>/adversary/suite-full.log
<scratch>/adversary/compile_fail_probe.rs
<scratch>/adversary/principal_reach_probe.rs
<scratch>/adversary/probe2          (5.8 MB binary)
<scratch>/adversary/                (the directory itself)
```

The two `rustc` probes linked against the existing rlibs in the worktree's `target/` symlink and wrote their binary to scratch; `cargo build`/`cargo test` wrote into that same sanctioned build directory. `CARGO_TARGET_DIR` was never set. No worktree was created, removed or pruned; the lease `adversary-session-epochs` was started, heartbeated once and ended, and no other session's lease was touched.

## 7. Findings block

```findings
- file: crates/mandate-identity/src/port.rs
  line: 164
  category: concurrency
  severity: warning
  verdict: INFEASIBLE
  origin: introduced
  message: "IdentityLog::resolve rebuilds the projection from the last SessionOpened, so a duplicate or replayed append leaves the contract's terminal Revoked state and the session refreshes again; no producer of SessionOpened exists, so the duplicate is one I appended."
- file: crates/mandate-identity/src/port.rs
  line: 180
  category: property
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: "the fold applies any SecurityEpochRecorded value including one below the generation already folded, so the out-of-band reset the architecture requires at the maximum moves the authority backwards, reuses a generation and makes a session already denied StaleEpoch refresh successfully."
- file: crates/mandate-identity/src/session.rs
  line: 173
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: "Session::refresh never reads expires_at and its signature carries no instant, so an expired session refreshes although identity.yaml:274 declares the denial and session.rs:123 documents the field as when the session stops being refreshable."
- file: crates/mandate-identity/src/port.rs
  line: 44
  category: boundary
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: "StreamVersion::advance adds unchecked on a public type while its sibling Generation::advance guards first, so at u64::MAX it panics with overflow checks and wraps to the INITIAL version the compare-and-set accepts without them; reaching it needs 2^64 events."
- file: crates/mandate-identity/src/port.rs
  line: 107
  category: judgement
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: "SessionOpened, EpochSnapshotRecorded and SecurityEpochRecorded are declared by no events entry in identity.yaml yet form the public, unvalidated state-seeding half of a crate whose ADR says the events are the record, and they are the vector both the terminal-state and the monotonicity defects land through."
- file: crates/mandate-identity/tests/refresh.rs
  line: 382
  category: mutant
  severity: note
  verdict: INFEASIBLE
  origin: pre-existing
  message: "no case asserts what a principal increment does to the same principal's session in an unrelated organization although the fixture builds exactly that world, and the acceptance statement's unqualified \"without changing eligibility in unrelated organization sessions\" is contradicted by the measured behaviour without the story deciding which reading is intended."
- file: docs/architecture/federated-login.md
  line: 130
  category: contract-drift
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: "the citation command-obligations.md:36 for the deny-at-maximum and out-of-band reset decision points at the DisableFederationConnection row; the IncrementSecurityEpoch row is line 49, and the wrong line is repeated in runtime-decisions.md:59 and in the story body."
```