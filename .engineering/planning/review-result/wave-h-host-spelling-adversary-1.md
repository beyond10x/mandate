---
format: aep.planning-md/1
id: review-result:wave-h-host-spelling-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — host-spelling-folded
relations:
- reviews: story:host-spelling-folded
revision: 1
---
# Adversary pass 1 — `story:host-spelling-folded`

Against `d6b1876` in `mandate-wh-host-spelling`, base `06c6747`. Returned 2026-09-22.

```
unit: story:host-spelling-folded
verdict: red
cases: executed 442→445, red 3
origin: introduced 5, pre-existing 2, undecided 0
wrote-outside-worktree: 10 paths under ~/.cache/claude-tmp/waveh/h2-host-spelling/adv1/
needs-coordinator: yes — whether the pre-existing control-plane case stays in this tree or routes to its own story
```

No implementation file was edited. Two untracked test files were added:
`crates/mandate-federation/tests/adversary_host_spelling_1.rs` and
`services/control-plane/tests/adversary_host_spelling_1.rs`.

## Red output as captured

`cargo test -p mandate-federation --locked --test adversary_host_spelling_1`, exit 101:

```
test a_host_and_its_absolute_spelling_get_one_answer_for_a_plaintext_loopback_issuer ... FAILED
test a_host_and_its_absolute_spelling_get_one_answer_under_the_default_host_list ... FAILED

panicked at crates/mandate-federation/tests/adversary_host_spelling_1.rs:97:5:
assertion `left == right` failed: localhost and localhost. are one interface and the guard gave
them two answers: relative=true, absolute=false
  left: true
 right: false

panicked at crates/mandate-federation/tests/adversary_host_spelling_1.rs:64:5:
assertion `left == right` failed: idp.example and idp.example. are one host and the guard gave
them two answers: relative=true, absolute=false
  left: true
 right: false

test result: FAILED. 0 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out
```

`cargo test -p mandate-control-plane --locked --test adversary_host_spelling_1`, exit 101:

```
test a_plaintext_issuer_naming_another_host_behind_userinfo_is_not_the_loopback ... FAILED

panicked at services/control-plane/tests/adversary_host_spelling_1.rs:66:9:
assertion `left == right` failed: http://localhost:80@evil.example is a plaintext issuer
identifier naming evil.example, and `http` is admitted on the loopback and nowhere else
  left: None
 right: Some(Issuer(SchemeUnadmitted))
```

## What it attacked and could not break

- every row of the unit's two module-doc tables (25 + 8), replayed against verbatim copies of
  `origin`, `folded`, `literal_address`, `loopback` and `listed` at base and at head: every
  transition is correct as written
- whether `listed()` can now be reached by anything it could not reach before: **no.**
  `literal_address(folded(h)) ⊇ literal_address(h)` and `loopback(folded(h)) ⊇ loopback_base(h)` for
  every input, because a host carrying a trailing dot never parsed as an `IpAddr` at the base. 49
  spellings measured, zero `false → true` on the containment branch
- the claimed `origin()` boundary is genuinely pinned: folding in `origin`, in `admits` before
  `listed`, or inside `listed` each make `tests/verifier_real.rs:2361` red
- IPv6 forms — bracket, zero-compression, mixed case, IPv4-mapped, IPv4-embedded, explicit port,
  trailing dot inside and outside the bracket, `[::1]x` — all refused, all as documented

## Findings

```findings
- file: crates/mandate-federation/src/verifier_real.rs
  line: 337
  category: property
  severity: warning
  verdict: CONFIRMED
  origin: pre-existing
  message: admits compares the destination host in three places and the fold reached two, so the issuer's own-origin equality at :337 gives one host two answers under the empty host list JwksSource::jwks passes and under any plaintext loopback issuer.
- file: crates/mandate-federation/tests/verifier_real.rs
  line: 2313
  category: acceptance
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: the shipped property test asserts a property it cannot reach, because its loop fixes the issuer at a third host and lists both spellings, so its claim that a host added later is covered without editing an enumeration is false.
- file: crates/mandate-federation/src/verifier_real.rs
  line: 338
  category: acceptance
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: the diff widens what admits allows on the plaintext own-origin branch for seven measured spellings where the commit message reports two, and the story's Out of scope forbids widening; the widening is inert because document() already fetches the issuer's own origin unguarded.
- file: crates/mandate-federation/tests/verifier_real.rs
  line: 2283
  category: mutant
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: the comment states the wrong evaluation order and claims the eight IPv6 rows assert the guard, but listed can never match a host carrying a colon so deleting the literal_address and loopback clauses leaves every IPv6 row green.
- file: services/control-plane/tests/end_to_end.rs
  line: 1877
  category: contract-drift
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: a verbatim quote of the branch under attack was accurate at 06c6747 and is stale at d6b1876, still reading literal_address(&target.host) where the code now reads literal_address(host).
- file: crates/mandate-federation/tests/verifier_real.rs
  line: 67
  category: boundary
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: the residue table enumerating spellings a C resolver folds omits 0, the canonical http://0/ loopback spelling, and 127.0.0.001, both measured reaching the list at base and head.
- file: services/control-plane/src/adapters.rs
  line: 626
  category: judgement
  severity: warning
  verdict: INFEASIBLE
  origin: pre-existing
  message: is_loopback splits the authority on its last colon so userinfo defeats it and Configuration::checked accepts the plaintext issuer http://localhost:80@evil.example, but no path was found that produces that operator-supplied string.
```

## How the coordinator routed each

| finding | row taken |
|---|---|
| `verifier_real.rs:337` — the third, unfolded comparison | back to the implementor. It is pre-existing, and the unit's own headline claim is false while it stands: the property test cannot be made to reach the property without it |
| `tests/verifier_real.rs:2313` — the property test is an enumeration | back to the implementor |
| `verifier_real.rs:338` — seven widened spellings, two reported | back to the implementor for the count, in the test documentation. The widening itself is kept: an absolute spelling of the loopback **is** the loopback, and the contract admits plaintext there |
| `tests/verifier_real.rs:2283` — wrong order, vacuous IPv6 rows | back to the implementor |
| `tests/end_to_end.rs:1877` — stale quote | the coordinator's: that file belongs to unit H4 |
| `tests/verifier_real.rs:67` — residue table omits `0` and `127.0.0.001` | back to the implementor |
| `adapters.rs:626` — userinfo defeats `is_loopback` | filed as its own story with the second loopback fold on the same line; not this unit's crate, and no path reaches it |
