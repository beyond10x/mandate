---
format: aep.planning-md/1
id: review-result:wave-d-authored-denials-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — authored denial scenarios
relations:
- reviews: story:authored-denial-scenarios
revision: 1
---
```
unit: story:authored-denial-scenarios — 21 files on fe03999, after correction 1
verdict: NEEDS-CHANGE (3 blockers, 5 warnings, 2 notes)
cases: ESS suite 167 / 21 authored unchanged; mandate-token 121 → 126, 3 red
origin: introduced 8 / pre-existing 1 / undecided 1
```

```findings
- file: crates/mandate-federation/src/verifier.rs
  line: 148
  category: contract-drift
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'five scenario summaries name a standing decode-only verifier double that exists nowhere in this tree; the only non-real FederationVerifier ignores its proof, so no federation file is decided by the proof bytes it carries'
- file: systems/mandate/scenarios/federation-audience-mismatch.yaml
  line: 47
  category: acceptance
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'AudienceMismatch is reachable only through a verifier that admits a mismatched audience, since RealVerifier refuses the placeholder signature at verifier_real.rs:1281 and the aud itself at :1257-1262'
- file: systems/mandate/scenarios/federation-ambiguous-tenant.yaml
  line: 71
  category: acceptance
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'the two-connection construction is sound but TenantMismatch needs a verifier that surfaces tid and dept as validated claims; RealVerifier answers InvalidCredential at verifier_real.rs:1281'
- file: systems/mandate/scenarios/pkce-stale-session-epoch.yaml
  line: 13
  category: acceptance
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'StaleEpoch at binding.rs:280-285 turns on the snapshot''s recorded generation, which SecurityEpochSnapshot does not declare and EpochSnapshotRecorded does not carry, so setup: cannot establish it'
- file: systems/mandate/scenarios/pkce-stale-session-epoch.yaml
  line: 11
  category: boundary
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'generation: 0 on an Integer field compiles to "generation": 0.0, the only float-shaped number in the 167-scenario suite'
- file: systems/mandate/ess-inputs.yaml
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the trailing comment routes three of the four dropped cases to story:session-epochs and story:check-api, both implemented, so nothing will pick that work up'
- file: systems/mandate/scenarios/federation-issuer-mismatch.yaml
  line: 47
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'green only by coincidence under RealVerifier: ProofInvalid and IssuerMismatch share InvalidCredential, so this file and the two subject files assert the right reason on a clause their proof never reaches'
- file: .engineering/planning/story/authored-denial-scenarios.md
  line: 20
  category: acceptance
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'nothing detects a wrong reason: mutating one reason, all 21, an outcome name, or an error name to another domain''s leaves both gates at 0 refusals and 167 selected; only the conformance run can catch them'
- file: systems/mandate/scenarios/introspect-caller-proof-malformed.yaml
  line: 6
  category: boundary
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the arranged instance server is captured from a RegisterResourceServer step and read by nothing'
- file: .engineering/planning/story/authored-denial-scenarios.md
  line: 46
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: 'author exits 0 while synthesize --suite-format 5 exits 1 on the 52 pre-existing refusals, and compared on counts is a convention no CI step reads'
```

Held: the four seeded digests (recomputed independently), the PKCE pair, all 21 citations, the four corpus ids, the inputs list, the two-connection registration, the STS files' guard order, zero unresolved `$instance` in the suite. Pass 1's `link.rs` blocker is closed by the seeded `ExternalPrincipal`. Mutant table: a wrong reason, all reasons, a wrong outcome name and a cross-domain error name pass both gates; a removed `setup:` and a reason typo are caught.

Rulings (correction round 2, the last): F1–F3 and the issuer warning resolve at integration — the standing decode-only double is `mandate_conformance::external::ScenarioVerifier` (sibling unit `story:conformance-target`, reads the JWS claims unsigned, first row of `standing_doubles` in `injections.json`); the five summaries cite it by that name; the real-verifier path stays `story:signing-and-verification`'s residue. F4/F5: `pkce-stale-session-epoch` is dropped and routed with `identity-stale-epoch-refresh` to `story:epoch-snapshot-generations` (new); the float-shaped integer is an ESS gap on the tracker and a decoder note on `story:conformance-target`. F6: the routing comment names live stories only (`story:epoch-snapshot-generations`, `story:graph-policy-adapter`, `story:declared-writers`). F7: the `RegisterResourceServer` step is removed. F8 → `story:conform-gate`. F9: the precedence file carries a proof `ScenarioVerifier` refuses (not a decodable JWS), so it is distinguishable from `federation-disabled-connection`. The wrong-reason acceptance is evidenced by the coordinator's `mandate-conform` run over the merged head (167 → 166 scenarios), recorded on this story at wave close.
