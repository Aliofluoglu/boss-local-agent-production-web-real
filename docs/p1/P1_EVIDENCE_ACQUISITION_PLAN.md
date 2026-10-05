# P1 Evidence Acquisition Plan

Goal: get the minimum safe, sanitized, verifiable evidence from the real Mac mini (+ `/Volumes/BOSS_AI_MODELS`) into the P1 analysis, with **one command** and **no production mutation**.

## 1. The single command (run on the Mac mini, from a checkout of this control repo)

```bash
bash scripts/p1/collect_boss_preflight.sh --output "$HOME/p1_host_evidence/$(date -u +%Y%m%dT%H%M%SZ)"
```

Output-directory convention: `$HOME/p1_host_evidence/<UTC-timestamp>/` — must not exist or must be empty, and must be **outside** every searched root (the script refuses otherwise). Do not use a path inside this repo's tracked tree; `evidence/p1/*` is git-ignored as a last-resort guard. Use a neutral name here, not one containing `boss`/`herdr`/`local_agent`/`atr` — a prior output directory matching those tokens will itself be auto-discovered as a search root on the *next* run and the script will then correctly refuse to write inside it. For repeat collections, either (A) pass explicit `--root`/`--models-volume` so discovery is fixed and predictable, or (B) keep using an output directory whose name doesn't match the auto-discovery tokens.

The script collects, verifies, and prints:

```
COLLECTION_STATUS=COMPLETE | COMPLETE_WITH_COVERAGE_GAPS | COMPLETE_WITH_SECRET_FINDINGS | INVALID_BUNDLE | FAILED
OUTPUT_PATH=…
MANIFEST_PATH=…/manifest.json
VERIFY_COMMAND=python3 …/verify_preflight_bundle.py <OUTPUT_PATH>
SAFE_TO_UPLOAD_OR_COMMIT=YES|NO
```

Requirements on the host: `bash`, `python3` (stdlib only; Xcode Command Line Tools provide it). Nothing is installed.

Optional (only if auto-discovery misses something): `--root <dir>` (repeatable; replaces auto-discovery), `--models-volume <dir>`, `--probe-endpoint http://127.0.0.1:<port>/<allowlisted path>`.

## 2. What it does

1. **Runtime baseline** — fixed read-only commands (`uname`, `sw_vers`, `sysctl hw.*`, `vm_stat`, `memory_pressure`, `uptime`, `df -k`, filtered `ps` using command names only, filtered `launchctl list`, `lsof` listing of listening TCP ports). Each missing command is recorded as a failed-but-non-fatal entry.
2. **Localhost GETs** — `http://127.0.0.1:11434/api/tags`, `/api/ps`, `http://127.0.0.1:1234/v1/models` (model *lists*; nothing is loaded).
3. **Bounded discovery** — roots: `$HOME` directories (depth ≤ 2) whose names match `boss|herdr|local_agent|atr`, plus `/Volumes/BOSS_AI_MODELS` and `~/.ollama/models/manifests`. Depth ≤ 8, ≤ 400 copied files, hidden directories and credential/browser/VCS/cache directories pruned. The exact scope used is written to `meta/search_scope.json`.
4. **Candidate files** (by name: boss-agent-route, herdr, local_agent, registry/manifest, provider/profile, route/fallback/escalation, MCP/tool/allowlist/permission, adapters/bridges, launch plists, FINAL_LOCK/qualification reports) are copied **sanitized** if ≤ 256 KiB, otherwise recorded hash-only (`source_sha256` ≤ 64 MiB).
5. **Reference indexes** (`refs/*.tsv`): path:line:truncated-redacted line for `local_agent`, `local_general`, Gemma 4, Qwen3.5, Qwen3-VL, fallback/escalation, MCP/allowlist, entrypoints/registries, project contracts.
6. **Protected-asset inventory**: model payload files (`.gguf`, `.safetensors`, …) → path/size/mtime only, never read or hashed.
7. **Manifest + verification** — `manifest.json` (schema: `schemas/p1/preflight_manifest.schema.json`), then `verify_preflight_bundle.py` (structure, hashes, missing/zero-byte/undeclared files, path escape, independent secret scan, coverage).

## 3. Safety contract (what it cannot do)

| Forbidden | How it is prevented |
|---|---|
| Modify BOSS files/registries/Git/env/launchd/permissions | Sources opened read-only; no write path outside `--output`; no `git`, `chmod`, `launchctl load/bootout`, `kill`, `pip`, `brew` anywhere in the code; refuses output dir inside any searched root |
| Run/stop/load/unload processes or models | Runtime commands are a fixed read-only argv list (no shell); HTTP is GET-only to localhost on an allowlist of listing paths |
| Execute collected scripts/configs | Content is read as text only; verifier never executes it |
| Expose secrets | Value redaction (`<REDACTED>`), token-shape redaction, URL-credential redaction, plist `EnvironmentVariables` blanked, `.env` → names only, credential-like file names never opened, private-key files withheld, credential/browser/SSH/keychain directories never entered, bundle independently scanned |
| Over-collect | Name-targeted candidates, caps on files/bytes/depth, model payloads never read |
| Publish | No outbound network except localhost GET; bundle must not be committed to the public repo |

Note: reading a file can update its access time on macOS; no content or modification time changes.

## 4. If the output says…

| Result | Action |
|---|---|
| `SAFE_TO_UPLOAD_OR_COMMIT=YES`, `COVERAGE_GAPS=NONE` | Hand the bundle over privately (§5) |
| `…=YES`, `COMPLETE_WITH_COVERAGE_GAPS` | Hand over anyway; P1 will name the exact gap and request a narrowly scoped delta (e.g. `--root <dir>`); do not guess |
| `SAFE_TO_UPLOAD_OR_COMMIT=NO` | Do **not** share. Delete the files named in `SECRET_FINDING`/`PROBLEM` lines (or the whole output dir), fix the source of the leak if appropriate, re-run into a **new** output dir |
| `FAILED` / `INVALID_BUNDLE` | Send only the printed lines (they contain no secrets) |

## 5. Hand-off of the bundle

The bundle is sanitized but may contain host source/config text; treat it as private. Do **not** push it to this public repo. Provide it to the P1 session via a private channel it can read (private repository/branch attached to the session, or a direct upload in the session). The script prints an `ARCHIVE_COMMAND` (not executed) to make a single `.tar.gz`.

## 6. After the bundle arrives (still P1)

1. Re-run `verify_preflight_bundle.py` on the received copy (hash chain intact).
2. Evaluate gates G1–G11 (`P1_EVIDENCE_REQUIREMENTS.md` §6).
3. Produce the 22 P1 outputs with every claim citing `E####` and an evidence class.
4. Return `READY_FOR_CONTROLLED_IMPLEMENTATION` only if all gates are met; otherwise a precise `BLOCKED`/`AWAITING` state. P2 starts only on explicit Boss authorization.

## 6b. Known limits (honest scope)

- Auto-discovery finds roots by directory name under `$HOME` (depth ≤ 2); a BOSS tree elsewhere needs `--root`.
- Files > 256 KiB are hash-only; if a router/adapter is that large, P1 will request a targeted `--max-copy-bytes` rerun.
- Redaction is pattern-based; the independent scan is a second net, not a proof of absence. Review `SECRET_FINDING` output, and treat the bundle as private regardless.
- Verified only against a synthetic fixture on Linux in the cloud session; macOS-only commands (`vm_stat`, `memory_pressure`, `launchctl`, `sw_vers`) were not exercised there and will report "command unavailable" on non-macOS hosts.
