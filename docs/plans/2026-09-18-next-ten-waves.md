# Mandate: the next ten waves

Status: proposal only, prepared 2026-09-18. This is an interactive planning session. No implementation execution approval, lifecycle promotion, implementation dispatch, release or Drive launch is recorded. The operator subsequently requested committing this preparation batch and adopting the integration/PR/tag workflow.

**Skill version 0.8.1** — the version in `.claude-plugin/plugin.json`; the stage-1 proposal quotes it.

Owner: `initiative:next-ten-waves`; all 22 selected stories serve `vision:mandate` (trusted identity, tenant isolation and constrained authority). Scope is Mandate only. Baseline: `ef912c8dce291f706b59f7a3d35e82d75d0a5043`, clean local `main`. This is not a claim about current remote state.

## What the ten waves mean

Only wave 1 contains currently dependency-ready work. Waves 2–10 are conditional forecasts, not ten pre-approved work orders. Re-read the store, blockers, typed scopes, source interfaces and resource measurements after every completed wave; regenerate the proposal before its next dispatch. Never infer that completing a decision dossier clears the decisions it describes.

Selection uses AEP 0.55.0 `aep plan artifact waves`, separately for draft and proposed stories, then the coordinator intersects that output with readiness. The verb ignores decision blockers and treats dependencies outside its status filter as outside the schedule; its first printed wave is not proof of readiness. Both raw outputs, with every wave, collision, unassessed id and cycle, are retained verbatim below. The proposed canonical story and draft dossier are explicitly checked together: their seven code/dependency surfaces and architecture-document surface are disjoint. No fallback pairwise selector was needed.

The new scope entries retain inferred confidence for proposed packages/files. Existing entries remain cited. `docs/architecture` was added beside the dossier's inferred leaf because AEP does not normalize ancestor/file overlaps; this exposes its real collision with domain-runtime. No scope was narrowed merely to manufacture concurrency.

## Sequence and exit evidence

Each row also requires every incoming `depends_on` terminal and every applicable blocker cleared on actual evidence. Every unit preserves its initially failing cases, executed test counts, independent adversary result and package checks. The coordinator alone writes the AEP store and runs the whole `task check` gate at integration. Corpus structure and generated schemas never substitute for runtime tests.

| Wave | Stories (all serve `vision:mandate`) | Observable exit |
|---|---|---|
| 1. Accepted types and runtime decision preparation | `story:canonical-types`; `story:runtime-decision-dossier` | Round-trip/identifier separation and containment suite; complete eleven-decision dossier without auto-clearing blockers. |
| 2. Runtime contracts, federation and graph ports | `story:domain-runtime`; `story:federation-linking`; `story:graph-policy` | Reviewed lifecycle/retention contract, exact verified federation resolution, revision-bound graph/policy tests. Domain model changes must preserve the frozen canonical interface or replan the consumers. |
| 3. Session invalidation and tenancy | `story:session-epochs`; `story:tenancy-topology` | Stale/overflow/concurrent invalidation cases and cross-tenant topology denial. |
| 4. Authorization, directory provenance and public-client core | `story:check-api`; `story:directory-provenance`; `story:pkce-sessions` | Credential-derived Check decisions, contribution-preserving directory removal and non-consuming S256/client/redirect validation cases. |
| 5. Audit/client integration and shared agent authority | `story:agent-authority-kernel`; `story:audit-client` | Revision-bound PEP denial with redacted correlation; property-tested subject/actor/ceiling/delegation intersection. |
| 6. Credential profiles and durable audit worker | `story:audit-worker-delivery`; `story:credential-profiles` | ImmediateOnline reference revocation and signed-profile tests; durable worker crash/retry/deduplication cases. |
| 7. Constrained exchange and operational runbooks | `story:constrained-exchange`; `story:recovery-runbooks` | No-widening STS exchange; tabletop runbooks tied to implemented service operations and declared online/offline guarantees. |
| 8. Agent enforcement and trusted product adapters | `story:agent-security`; `story:protocol-adapters` | Per-tool actor/approval/ceiling enforcement; adapters reject spoofed context and satisfy actual protocol contracts. |
| 9. Real OAuth redemption and audit recovery tests | `story:audit-recovery-conformance`; `story:oauth-integration` | Two concurrent OAuth redeemers produce one issuance/outbox commit; real worker ingress recovery and tenant-isolated audit results. |
| 10. Management CLI and service qualification | `story:product-cli`; `story:runtime-service-qualification` | CLI grant/check decision agrees with resulting revision; actual service qualification executes its entire selected security manifest. |

## Required refinements and boundaries

The prior exchange story required agent ceilings/delegation while agent-security came later. `story:agent-authority-kernel` now owns reusable checks before exchange; agent-security retains tool-call/execution integration. This ordering is an inference from those two story bodies and `docs/architecture/combined.md:7`; the underlying authority requirements are unchanged.

Review correction: pkce-sessions only validates and returns a non-consuming candidate. oauth-integration revalidates current state and commits one-use consumption, credential issuance and the outbox in one STS transaction; a separate consumed redemption result is forbidden. The temporary direct atomicity blocker on validation-only pkce-sessions was removed; the blocker remains on oauth-integration and the existing session-epoch prerequisite remains. Source: `docs/architecture/ownership.md:28` and `docs/architecture/unmapped.md:25`.

The six added stories decompose existing foundation, agent and hardening deliverables; they add no public domain noun. Their bodies cite existing ESS entities and source requirements. `ess specify validate --path systems/mandate` reports `mandate v1 — 14 file(s), valid`; `ess specify compile --path systems/mandate --format json` exits 0. ESS 0.25.0 / ess/4 remains authoritative. No ESS source or generated projection changes are proposed in this planning pass. Epoch values, conditional references and other UNMAPPED semantics remain explicit; no String/Integer/UUID substitute is introduced.

The first wave preserves the accepted canonical scope even though it spans four crates; this is an explicit exception to the skill's preferred one-package blast radius, justified by the existing reviewed type handoff. Its dependencies/policy changes stay with its single implementor. In later waves shared Cargo manifests/lockfiles, dependency policy, xtask, ESS and generated artifacts are coordinator-only serialized integration surfaces. Any newly required shared API, dependency or generated-output change must be designed and gated before unit dispatch, or the unit leaves that wave. No two live units edit these files. `task:runtime-wave-integration` owns this future coordinator work, including replacement of scaffold-only executable refusals with milestone-specific runtime checks and explicit per-service dependency admission.

## Readiness, scope and blocker inventory

Status and blockers below are observations from `aep plan artifact list --format json`, not a promise that they will clear. Every scope is a planned write boundary; package-local manifests and tests are included.

| Story | Current status | Planned scope confidence | Open blockers |
|---|---|---|---|
| `story:canonical-types` | proposed | `Cargo.lock` (cited); `Cargo.toml` (cited); `crates/mandate-model` (cited); `crates/mandate-proto` (cited); `crates/mandate-token` (cited); `crates/mandate-types` (cited); `dependency-boundaries.json` (cited) | none directly; dependency chain still applies |
| `story:runtime-decision-dossier` | draft | `docs/architecture` (cited); `docs/architecture/runtime-decisions.md` (inferred) | none directly; dependency chain still applies |
| `story:domain-runtime` | draft | `docs/architecture` (cited); `systems/mandate` (cited); `generated` (cited) | `decision-blocker:lifecycle`, `decision-blocker:worker-orchestration` |
| `story:federation-linking` | draft | `crates/mandate-federation` (cited) | `decision-blocker:algorithm-policy`, `decision-blocker:identity-uniqueness` |
| `story:graph-policy` | draft | `crates/mandate-graph` (cited); `crates/mandate-policy` (cited) | `decision-blocker:backend`, `decision-blocker:subject-relations` |
| `story:session-epochs` | draft | `crates/mandate-identity` (cited) | `decision-blocker:epoch`, `decision-blocker:epoch-atomicity` |
| `story:tenancy-topology` | draft | `crates/mandate-model` (cited); `services/control-plane` (cited) | none directly; dependency chain still applies |
| `story:check-api` | draft | `crates/mandate-authz` (cited); `services/authorization` (cited) | none directly; dependency chain still applies |
| `story:directory-provenance` | draft | `crates/mandate-provisioning` (cited); `services/worker` (cited) | `decision-blocker:epoch-atomicity`, `decision-blocker:worker-orchestration` |
| `story:pkce-sessions` | draft | `bins/mandate` (cited); `crates/mandate-identity` (cited) | none directly; dependency chain still applies |
| `story:agent-authority-kernel` | draft | `crates/mandate-authz` (inferred); `crates/mandate-policy` (inferred) | `decision-blocker:identity-uniqueness` |
| `story:audit-client` | draft | `crates/mandate-audit` (cited); `crates/mandate-client` (cited); `examples/axum-service` (cited) | `decision-blocker:audit-routing`, `decision-blocker:guards` |
| `story:audit-worker-delivery` | draft | `services/worker` (inferred) | `decision-blocker:audit-routing`, `decision-blocker:lifecycle`, `decision-blocker:worker-orchestration` |
| `story:credential-profiles` | draft | `crates/mandate-token` (cited); `services/sts` (cited) | `decision-blocker:algorithm-policy`, `decision-blocker:identity-uniqueness` |
| `story:constrained-exchange` | draft | `services/sts` (cited) | `decision-blocker:audit-routing` |
| `story:recovery-runbooks` | draft | `docs/runbooks` (inferred) | none directly; dependency chain still applies |
| `story:agent-security` | draft | `crates/mandate-authz` (cited); `crates/mandate-policy` (cited) | `decision-blocker:identity-uniqueness` |
| `story:protocol-adapters` | draft | `crates/mandate-proto` (cited); `crates/mandate-server` (cited) | `decision-blocker:guards` |
| `story:audit-recovery-conformance` | draft | `services/worker` (cited) | none directly; dependency chain still applies |
| `story:oauth-integration` | draft | `crates/mandate-server` (cited); `services/sts` (cited) | `decision-blocker:epoch-atomicity` |
| `story:product-cli` | draft | `bins/mandate` (cited) | none directly; dependency chain still applies |
| `story:runtime-service-qualification` | draft | `crates/mandate-testkit` (inferred) | none directly; dependency chain still applies |

## Deliberately left out

`story:foundation-contracts` is already implemented. `story:advanced-delegation` is printed by the raw verb but remains excluded: global linking/trust, chains, transaction/task capabilities, simulation and access review remain deferred under `decision-blocker:global-trust`. Its presence in the raw ninth wave does not admit it into this proposal.

The separate canonical Drive task remains blocked by `decision-blocker:drive-verifier`, `decision-blocker:drive-map-authority`, task review and missing operator budget/assumed cost. Configuration-only validation and the absence of recorded runs are documented in `verification-report:canonical-driver-readiness`. Wave and Drive must never own the same story simultaneously. This mandate prepares waves only.

This horizon does not complete the entire roadmap. Full SAML/SCIM product coverage, workload federation and sender constraints, audit export/analytics product APIs, batch/list/AuthZEN/SDK work, policy rollout/rollback, multi-region scaling and the full production checklist remain with their existing epics. No release, deployment, Identity migration, other-repository change or Website publication is included.

## Preflight and future dispatch

Observed: clean primary main at the baseline above; one retained foundations worktree is Active and has 391 untracked entries, two ignored entries, no live lease, and approximately 257.5 MB allocated (254.4 MB target). It is not this session's work and was not cleaned. Under the wave skill, its unresolved ownership/lifecycle is a launch blocker, not permission to delete it.

Disk observation: 47 GiB available on the worktree filesystem (95% used). Proposed dispatch floor: 10 GiB, to be rechecked before dispatch and after each unit. Current plan caps concurrent implementors at three (root plus three worker slots); the skill's default budget cap is four, but available slots are the tighter bound. Remaining model budget was not supplied; request it only when an execution is requested. No cost estimate is represented as an operator grant.

Measured planning scaffold gate: 37.398 seconds, 255,971,328 bytes of target allocation (244.1 MiB), two Cargo jobs, sccache explicitly enabled; all 34 Rust test targets contained zero executed tests. The gate separately checked 47 structural corpus scenarios and deterministic ESS projections. This is a scaffold measurement, not runtime evidence. Final gate evidence is linked below. Runtime builds can be larger than this scaffold and require renewed measurement. Compiler cache observation: sccache is available but RUSTC_WRAPPER is unset. The planning check uses it explicitly; an execution launch must wire it and recheck it.

Required dispatch roles: `aep-drive:story-scoper`, `aep-drive:implementor`, `aep-drive:adversary`; critic roles: `aep-plan:plan-critic-acceptance`, `aep-plan:plan-critic-design`, `aep-plan:plan-critic-scope`, `aep-plan:plan-critic-parallel-safety`. This harness exposes generic collaboration agents, not plugin `subagent_type` selection, so read-only scopers/critics use those installed charters on the inherited model. Critics request Sonnet/high, unavailable here; this is a disclosed harness/model deviation. Four independent critics read one frozen draft, with at most three active together; the fourth starts when a slot opens and sees no other verdict. No implementor or adversary is dispatched for this planning mandate.

For an approved wave W, reuse the active managed integration checkout and create one managed unit tree per selected story. Use the active integration batch coordinator tree across successive approved waves; proposed unit names: `mandate-wW-<story>`; record the CLI-returned id, branch, HEAD, relative worktree path, lease owner, `<tree>/target`, assigned `<wave-scratch>/<story>` and stage before dispatch. These are reservations only; no implementation trees exist. Keep private absolute paths/session provenance in the local handoff, outside public source. Refresh/record this table in the wave's own execution page at every stage change.

Per-wave approval authorizes its N unit commits, reviewed merges and closing store commit on the active integration/wave-YYYYMMDD-NNN branch, plus a bounded opening integration commit when stated in the concrete proposal. It does not automatically merge to main. The operator selects the accumulated batch for one PR; a release tag follows the resulting main commit and its separate release checks. This repository-specific override is recorded in AGENTS.md and docs/adr/0008-integration-batches.md. The subsequent operator instruction authorizes committing this planning/workflow batch, not executing the forecast. The current preparation batch is integration/wave-20260918-001. Publish through Mandate's Atlas bot path and retain worktrees until wanted commits have recovery proof. Release remains a separate human stop.

## Review and validation

Round 1: acceptance and design requested revisions (three acceptance findings, two design findings); scope and parallel-safety approved. All five findings were addressed and recorded as fixed against their immutable review-results. The corrected PKCE transaction ownership and explicit adapter-to-worker dependency are included above. Round 2: design, scope and parallel-safety approved; acceptance requested explicit PKCE candidate/refusal inputs. That sixth finding was corrected with a concrete input/result matrix and recorded as fixed after the final round. The correction is coordinator-checked and has not had a third independent review; the needs-revision verdict remains immutable. All eight verbatim verdicts are review-result:ten-waves-{acceptance,design,scope,parallel}-r{1,2}. Six findings have fixed outcomes; none is silently dropped. Historical immutable reviews lacking findings blocks are preserved, not rewritten. AEP 0.55.0 also reports the new approving records as lacking findings blocks despite their explicit fenced `findings` block containing `[]`; those bodies are preserved verbatim and the exact diagnostic is retained in the validation evidence. Planning is not runtime security evidence.

Validation record: [exact commands and output](2026-09-18-next-ten-waves-validation.md).

## Raw AEP draft output (verbatim)

Command: `aep plan artifact waves --kind story --status draft --format json` (exit 0).

```json
{
  "waves": [
    {
      "wave": 1,
      "artifacts": [
        {
          "id": "story:runtime-decision-dossier",
          "inferred": true,
          "scope": [
            {
              "confidence": "cited",
              "path": "docs/architecture"
            },
            {
              "confidence": "inferred",
              "path": "docs/architecture/runtime-decisions.md"
            }
          ]
        }
      ]
    },
    {
      "wave": 2,
      "artifacts": [
        {
          "id": "story:domain-runtime",
          "inferred": false,
          "scope": [
            {
              "confidence": "cited",
              "path": "docs/architecture"
            },
            {
              "confidence": "cited",
              "path": "generated"
            },
            {
              "confidence": "cited",
              "path": "systems/mandate"
            }
          ]
        },
        {
          "id": "story:federation-linking",
          "inferred": false,
          "scope": [
            {
              "confidence": "cited",
              "path": "crates/mandate-federation"
            }
          ]
        },
        {
          "id": "story:graph-policy",
          "inferred": false,
          "scope": [
            {
              "confidence": "cited",
              "path": "crates/mandate-graph"
            },
            {
              "confidence": "cited",
              "path": "crates/mandate-policy"
            }
          ]
        }
      ]
    },
    {
      "wave": 3,
      "artifacts": [
        {
          "id": "story:session-epochs",
          "inferred": false,
          "scope": [
            {
              "confidence": "cited",
              "path": "crates/mandate-identity"
            }
          ]
        },
        {
          "id": "story:tenancy-topology",
          "inferred": false,
          "scope": [
            {
              "confidence": "cited",
              "path": "crates/mandate-model"
            },
            {
              "confidence": "cited",
              "path": "services/control-plane"
            }
          ]
        }
      ]
    },
    {
      "wave": 4,
      "artifacts": [
        {
          "id": "story:check-api",
          "inferred": false,
          "scope": [
            {
              "confidence": "cited",
              "path": "crates/mandate-authz"
            },
            {
              "confidence": "cited",
              "path": "services/authorization"
            }
          ]
        },
        {
          "id": "story:directory-provenance",
          "inferred": false,
          "scope": [
            {
              "confidence": "cited",
              "path": "crates/mandate-provisioning"
            },
            {
              "confidence": "cited",
              "path": "services/worker"
            }
          ]
        },
        {
          "id": "story:pkce-sessions",
          "inferred": false,
          "scope": [
            {
              "confidence": "cited",
              "path": "bins/mandate"
            },
            {
              "confidence": "cited",
              "path": "crates/mandate-identity"
            }
          ]
        }
      ]
    },
    {
      "wave": 5,
      "artifacts": [
        {
          "id": "story:agent-authority-kernel",
          "inferred": true,
          "scope": [
            {
              "confidence": "inferred",
              "path": "crates/mandate-authz"
            },
            {
              "confidence": "inferred",
              "path": "crates/mandate-policy"
            }
          ]
        },
        {
          "id": "story:audit-client",
          "inferred": false,
          "scope": [
            {
              "confidence": "cited",
              "path": "crates/mandate-audit"
            },
            {
              "confidence": "cited",
              "path": "crates/mandate-client"
            },
            {
              "confidence": "cited",
              "path": "examples/axum-service"
            }
          ]
        }
      ]
    },
    {
      "wave": 6,
      "artifacts": [
        {
          "id": "story:audit-worker-delivery",
          "inferred": true,
          "scope": [
            {
              "confidence": "inferred",
              "path": "services/worker"
            }
          ]
        },
        {
          "id": "story:credential-profiles",
          "inferred": false,
          "scope": [
            {
              "confidence": "cited",
              "path": "crates/mandate-token"
            },
            {
              "confidence": "cited",
              "path": "services/sts"
            }
          ]
        }
      ]
    },
    {
      "wave": 7,
      "artifacts": [
        {
          "id": "story:constrained-exchange",
          "inferred": false,
          "scope": [
            {
              "confidence": "cited",
              "path": "services/sts"
            }
          ]
        },
        {
          "id": "story:recovery-runbooks",
          "inferred": true,
          "scope": [
            {
              "confidence": "inferred",
              "path": "docs/runbooks"
            }
          ]
        }
      ]
    },
    {
      "wave": 8,
      "artifacts": [
        {
          "id": "story:agent-security",
          "inferred": false,
          "scope": [
            {
              "confidence": "cited",
              "path": "crates/mandate-authz"
            },
            {
              "confidence": "cited",
              "path": "crates/mandate-policy"
            }
          ]
        },
        {
          "id": "story:protocol-adapters",
          "inferred": false,
          "scope": [
            {
              "confidence": "cited",
              "path": "crates/mandate-proto"
            },
            {
              "confidence": "cited",
              "path": "crates/mandate-server"
            }
          ]
        }
      ]
    },
    {
      "wave": 9,
      "artifacts": [
        {
          "id": "story:advanced-delegation",
          "inferred": false,
          "scope": [
            {
              "confidence": "cited",
              "path": "docs/rfcs"
            }
          ]
        },
        {
          "id": "story:audit-recovery-conformance",
          "inferred": false,
          "scope": [
            {
              "confidence": "cited",
              "path": "services/worker"
            }
          ]
        },
        {
          "id": "story:oauth-integration",
          "inferred": false,
          "scope": [
            {
              "confidence": "cited",
              "path": "crates/mandate-server"
            },
            {
              "confidence": "cited",
              "path": "services/sts"
            }
          ]
        }
      ]
    },
    {
      "wave": 10,
      "artifacts": [
        {
          "id": "story:product-cli",
          "inferred": false,
          "scope": [
            {
              "confidence": "cited",
              "path": "bins/mandate"
            }
          ]
        },
        {
          "id": "story:runtime-service-qualification",
          "inferred": true,
          "scope": [
            {
              "confidence": "inferred",
              "path": "crates/mandate-testkit"
            }
          ]
        }
      ]
    }
  ],
  "collisions": [
    {
      "a": "story:agent-authority-kernel",
      "b": "story:agent-security",
      "path": "crates/mandate-authz",
      "confidence": "inferred"
    },
    {
      "a": "story:agent-authority-kernel",
      "b": "story:agent-security",
      "path": "crates/mandate-policy",
      "confidence": "inferred"
    },
    {
      "a": "story:agent-authority-kernel",
      "b": "story:check-api",
      "path": "crates/mandate-authz",
      "confidence": "inferred"
    },
    {
      "a": "story:agent-authority-kernel",
      "b": "story:graph-policy",
      "path": "crates/mandate-policy",
      "confidence": "inferred"
    },
    {
      "a": "story:agent-security",
      "b": "story:check-api",
      "path": "crates/mandate-authz",
      "confidence": "cited"
    },
    {
      "a": "story:agent-security",
      "b": "story:graph-policy",
      "path": "crates/mandate-policy",
      "confidence": "cited"
    },
    {
      "a": "story:audit-recovery-conformance",
      "b": "story:audit-worker-delivery",
      "path": "services/worker",
      "confidence": "inferred"
    },
    {
      "a": "story:audit-recovery-conformance",
      "b": "story:directory-provenance",
      "path": "services/worker",
      "confidence": "cited"
    },
    {
      "a": "story:audit-worker-delivery",
      "b": "story:directory-provenance",
      "path": "services/worker",
      "confidence": "inferred"
    },
    {
      "a": "story:constrained-exchange",
      "b": "story:credential-profiles",
      "path": "services/sts",
      "confidence": "cited"
    },
    {
      "a": "story:constrained-exchange",
      "b": "story:oauth-integration",
      "path": "services/sts",
      "confidence": "cited"
    },
    {
      "a": "story:credential-profiles",
      "b": "story:oauth-integration",
      "path": "services/sts",
      "confidence": "cited"
    },
    {
      "a": "story:domain-runtime",
      "b": "story:runtime-decision-dossier",
      "path": "docs/architecture",
      "confidence": "cited"
    },
    {
      "a": "story:oauth-integration",
      "b": "story:protocol-adapters",
      "path": "crates/mandate-server",
      "confidence": "cited"
    },
    {
      "a": "story:pkce-sessions",
      "b": "story:product-cli",
      "path": "bins/mandate",
      "confidence": "cited"
    },
    {
      "a": "story:pkce-sessions",
      "b": "story:session-epochs",
      "path": "crates/mandate-identity",
      "confidence": "cited"
    }
  ],
  "unassessed": [],
  "cycles": []
}
```

## Raw AEP proposed output (verbatim)

Command: `aep plan artifact waves --kind story --status proposed --format json` (exit 0).

```json
{
  "waves": [
    {
      "wave": 1,
      "artifacts": [
        {
          "id": "story:canonical-types",
          "inferred": false,
          "scope": [
            {
              "confidence": "cited",
              "path": "Cargo.lock"
            },
            {
              "confidence": "cited",
              "path": "Cargo.toml"
            },
            {
              "confidence": "cited",
              "path": "crates/mandate-model"
            },
            {
              "confidence": "cited",
              "path": "crates/mandate-proto"
            },
            {
              "confidence": "cited",
              "path": "crates/mandate-token"
            },
            {
              "confidence": "cited",
              "path": "crates/mandate-types"
            },
            {
              "confidence": "cited",
              "path": "dependency-boundaries.json"
            }
          ]
        }
      ]
    }
  ],
  "collisions": [],
  "unassessed": [],
  "cycles": []
}
```
