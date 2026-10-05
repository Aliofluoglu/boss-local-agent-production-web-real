# P1 Evidence Requirements (frozen)

Project: BOSS LOCAL AGENT PRODUCTION + MCP INTEGRATION · Phase: **P1** (read-only) · Status of this document: FROZEN requirements, not findings.

This file freezes **what evidence must have actually been inspected** before P1 may return `READY_FOR_CONTROLLED_IMPLEMENTATION`. It contains no findings about the live BOSS system; none were reachable (see `P1_REMOTE_PREFLIGHT_STATUS.md`).

## 1. Evidence classes (never mix them)

| Class | Meaning | May prove |
|---|---|---|
| `UPSTREAM_ACCEPTED` | Facts handed in by the Boss/charter from closed, final-locked projects (4B_6B qualification, ATR_HERDR integration). Consumed, **not re-verified, not reopened.** | Accepted history only |
| `STATIC_GITHUB_EVIDENCE` | Content of repositories reachable from the cloud session. | Static source facts, only if it is real BOSS source. **Currently none.** |
| `LIVE_HOST_EVIDENCE` | Collected by `scripts/p1/collect_boss_preflight.sh` on the Mac mini; recorded in a verified manifest. | Current file contents/hashes, live references, runtime baseline |
| `DERIVED_P1_ANALYSIS` | Conclusions produced by P1 from the above, each citing manifest entry IDs (`E####`). | The 22 P1 outputs |

A runtime claim (e.g. "endpoint X serves model Y now") is valid only with a `LIVE_HOST_EVIDENCE` entry. A static reference is never reported as a live fact.

## 2. The 22 P1 outputs → required evidence

Manifest categories and `refs/*.tsv` index files are produced by the collector. "Gap rule": if the evidence is absent, the output is reported `UNPROVEN` — never inferred.

| # | P1 output | Required evidence (manifest category / artifact) | Gap rule |
|---|---|---|---|
| 1 | CURRENT_TOPOLOGY | `TOPOLOGY` entries (boss-agent-route, Herdr, adapter/bridge, launchd plists), `runtime/launchctl_list`, `runtime/listening_ports`, `refs/route_entrypoints.tsv`, `meta/search_scope.json` | UNPROVEN components named explicitly |
| 2 | CURRENT_LOCAL_AGENT_PATH | Copies of boss-agent-route/adapter/bridge sources (not hash-only), `refs/local_agent.tsv`, endpoint probes | Chain break points listed |
| 3 | CURRENT_LOCAL_GENERAL_MAPPING | `refs/local_general.tsv`, provider/role configs, Ollama manifests + `/api/tags` probe, `env_keys` | Do **not** assume historical `igorls/gemma-4-E4B-it-heretic-GGUF:Q5_K_M`; report what is live |
| 4 | MCP_TOOL_INVENTORY | `MCP_TOOL_SURFACE` entries, `refs/mcp_tools.tsv` | "No MCP surface in scope" is valid only with scope proof |
| 5–8 | SAFE_BASELINE / BOUNDED_WRITE / HIGH_RISK / NOT_AUTHORIZED tool sets | Per-tool definition (name, side effects, args, paths/hosts reachable, current allowlist) from #4 | Unclassifiable tool → `NOT_AUTHORIZED` (fail-closed) |
| 9 | LOCAL_AGENT_INTEGRATION_CONTRACT | Adapter source, launch/argument passthrough, `ACCEPTED_PROJECT_EVIDENCE` entries | Contract fields without evidence marked open |
| 10 | CONFIG_OWNERSHIP_MATRIX | All `ROLE_PROVIDER_REFERENCES`/`ROUTING`/`MCP_TOOL_SURFACE` configs, env key names, plists, `refs/*` | See collision detectors §4 |
| 11 | EXISTING_PROJECT_IMPACT_MATRIX | `refs/project_contracts.tsv`, callers in `refs/route_entrypoints.tsv`, project roots in scope | Unscanned roots listed as UNPROVEN |
| 12 | PROTECTED_ASSET_MATRIX | `inventory/model_payload_inventory.tsv`, FINAL_LOCK evidence, `source_sha256` of governed files | Missing hash → asset treated as protected, unverified |
| 13–14 | EXACT_FILES_TO_CHANGE / NOT_TO_CHANGE | #10 + #11; default is NOT_TO_CHANGE | Any file not proven owned by this project → NOT_TO_CHANGE |
| 15–17 | CURRENT_ROUTING_AUTHORITY / FALLBACK_CHAIN / ESCALATION_CHAIN | Router source copies, `ROUTING` entries, `refs/fallback_escalation.tsv` | Fall-through/dead-ends only if statically observable in copied source |
| 18 | P2_REQUIRED_ROUTING_DELTA | #15–17 + #9 | Minimal opt-in delta only; no global rewrite |
| 19 | ROLLBACK_PLAN | `source_sha256` baseline for every file in #13, launchd state, previous-state recoverability | Rollback not viable → P1 cannot go READY |
| 20 | PRODUCTION_ACTIVATION_PLAN | #9, #18, #19 | — |
| 21 | REAL_E2E_PLAN | #1–2, runtime baseline, accepted ATR/Herdr chain description | Model-inclusive run is P3, not P1 |
| 22 | RESOURCE_GATE_PLAN | `RUNTIME_RESOURCE` entries (§5) | Thresholds must come from evidence, not guesses |
| — | P1_EVIDENCE_INDEX | `manifest.json` (every claim cites `E####`) | — |

## 3. Tool tier rubric (applied in P1 analysis to #4)

| Tier | Criteria |
|---|---|
| `SAFE_BASELINE` | Read-only; no network egress beyond localhost; no secrets reachable; bounded path scope; deterministic |
| `BOUNDED_WRITE` | Writes only to an explicitly scoped sandbox path; reversible; auditable; scoped allowlist exists |
| `HIGH_RISK` | Shell/exec, arbitrary network, writes outside sandbox, process/service control, credential reach |
| `NOT_AUTHORIZED` | Unknown/undocumented, broader than needed, or evidence missing (**default**) |

Local-agent access is least-privilege, capability-scoped, allowlist-based, auditable, fail-closed. Nothing is promoted by model text; effects are verified from external evidence.

## 4. Collision / authority detectors (must be answered from evidence)

For each of: logical roles · project opt-in · provider/profile binding · model identity · endpoint identity · runtime/context profile · MCP registration · tool capability registration · allowlists · project permissions · fallback · escalation · evidence schema · resource gate · rollback state — record the **single writable source of truth** or flag one of:
`DUPLICATE_AUTHORITY`, `AMBIGUOUS_PRECEDENCE`, `MULTIPLE_WRITABLE_SOURCES`, `HIDDEN_DEFAULT`, `UNVERSIONED_CROSS_PROJECT_CONTRACT`, `ROLE_NAME_COLLISION`, `PROVIDER_MAP_COLLISION`.

## 5. Runtime / resource evidence for P3 admission design (collected lightly, nothing loaded)

Metrics: `hw.memsize`, `vm_stat`, `memory_pressure`, swap usage, resident model list (`/api/ps`), RSS of competing inference/automation workloads, free space on the models volume, listening endpoints. From these P1 defines: metrics to inspect, relevant competing workloads, safe admission condition, stop condition, **resource-only block semantics** (a block before model load is `RESOURCE_BLOCK_BEFORE_MODEL_LOAD`, never a capability failure), and safe retry condition (re-measure shows the gate satisfied after an explicit state change; **no blind retry loop**). Numeric thresholds are set in the P1 freeze from the evidence plus the accepted historical host-gate record — not invented here. Qwen3.5-9B is not an automatic substitute.

## 6. Sufficiency gate for `READY_FOR_CONTROLLED_IMPLEMENTATION`

All must hold, each checked by inspection of the actual bundle:

- **G1** `verify_preflight_bundle.py` → `VERIFY_STATUS=PASS`, `SECRET_SCAN=CLEAN`.
- **G2** `COVERAGE_GAPS=NONE` (TOPOLOGY, ROLE_PROVIDER_REFERENCES, ROUTING, MCP_TOOL_SURFACE, GOVERNED_FILE_INTEGRITY, RUNTIME_RESOURCE each have real content).
- **G3** Router/adapter/bridge sources needed for #2, #9, #15–17 are present as sanitized copies (not hash-only, not truncated).
- **G4** `local_general` live mapping located (or explicitly proven absent) with provenance.
- **G5** MCP/tool surface inventoried, or proven absent within a stated scope.
- **G6** Every file in EXACT_FILES_TO_CHANGE and every protected file has a `source_sha256`.
- **G7** Runtime baseline captured (memory pressure, resident models, competing workloads, volume free space).
- **G8** Protected-asset inventory observed (Track-B Qwen3-VL-4B frozen; Qwen3.5-9B decommission state observed, not acted on).
- **G9** Ownership matrix has no unresolved collision; any collision is either resolved by an explicit Boss decision or makes P1 `BLOCKED` (not READY).
- **G10** Rollback is demonstrably viable (baseline hashes + restorable previous state).
- **G11** `P1_PLANNED_LOCAL_GENERAL_CHANGE=NO` unless evidence proves a hard dependency and the Boss explicitly authorizes.

Any unmet gate ⇒ P1 stays open (`AWAITING_BOUNDED_HOST_EVIDENCE` or `BLOCKED_<reason>`). Only the **independent Codex audit (P4)** may close the project; the implementer never self-certifies.

## 7. Secret-handling rule for evidence

Key **names** and structure only. Values become `<REDACTED>`. Credential-like files are never opened; `.env` files are reduced to names; files containing private-key blocks are withheld. The bundle is never committed to the public control repo (`evidence/p1/*` is git-ignored).
