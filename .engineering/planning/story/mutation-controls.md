---
format: aep.planning-md/1
id: story:mutation-controls
kind: story
status: draft
title: Named red/green mutation controls prove the protections detect faults
relations:
- decomposes: epic:foundations
- serves: vision:mandate
- depends_on: story:coverage-map
scope:
- confidence: inferred
  path: tests/mutants
- confidence: inferred
  path: xtask/src/mutants.rs
- confidence: inferred
  path: xtask/tests/coverage_mutants.rs
revision: 2
---
## Acceptance

Given `tests/mutants/<name>.{patch,json}`, when `cargo xtask mutants` runs, then every named mutant applies cleanly to a scratch copy of the tree, the named target test fails (or compilation fails where declared), and a mutant whose patch no longer applies fails the step loudly; and given `xtask/tests/coverage_mutants.rs`, data mutations of the coverage manifest and the generated artifacts are each refused by the step they target.

## Scope

- `xtask/src/mutants.rs` — inferred; copies the tree (xtask's `files()` walker; excludes `target/`, `.git/`) to `target/mutants/<name>/`, `git apply`s the patch, runs `cargo test --locked -p <crate> --test <target> <test>` under `CARGO_TARGET_DIR=target/mutants-build`, asserts the declared kill.
- `xtask/tests/coverage_mutants.rs` — inferred; data mutants: drop a manifest entry; relabel `deferred → implemented` with no tests; cite a non-existent test; add an IR event with no entry; strip `additionalProperties: false` from one event schema; each must be refused by `cargo xtask coverage --root <scratch>` / `contracts`.
- `tests/mutants/event-field-obsolete.{patch,json}`, `event-dropped`, `tenant-mapping-corrupt`, `revocation-bypass`, `lifecycle-transition-wrong`, `deny-unknown-fields-removed`, `manifest-relabel` — inferred; each `.json` = `{crate, test_target, test, kill: test-fails|compile-fails}`.
- Receipt: the mutant set (name, patch digest, target test) is part of `generated/coverage/receipt.json` (`story:coverage-map`'s writer reads `tests/mutants/`).

### Units

One agent: `step`, `data-mutants`, `code-mutants` serially. The coordinator wires `mod mutants;`, the `Action`, and the last `Check` line.

### Excluded

`xtask/src/main.rs`, every crate's `src/` (mutations are patches, never committed changes), `Cargo.*`.

### Gate

`cargo test -p xtask --locked`; `cargo xtask mutants` on the tree (every mutant killed); wall-clock measured and reported.
