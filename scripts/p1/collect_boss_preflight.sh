#!/usr/bin/env bash
# BOSS P1 preflight evidence collector — READ-ONLY with respect to BOSS production state.
#
#   bash scripts/p1/collect_boss_preflight.sh --output <NEW_EMPTY_DIR_OUTSIDE_BOSS_ROOTS>
#
# Optional: --root <dir> (repeatable, overrides auto-discovery)  --models-volume <dir>
#           --probe-endpoint <http://127.0.0.1:PORT/PATH> (repeatable; GET, localhost, allowlisted paths)
#           --approved-root <dir> (repeatable; required container for --exact-file)
#           --exact-file <path> (repeatable; absolute, no symlink, no glob, must resolve inside an
#                                --approved-root; model-payload extensions rejected before any read)
#           --exact-files-only (disables directory auto-discovery entirely; search_scope.roots == [])
#
# Writes ONLY inside --output. Does not: modify BOSS files/registries/Git/env/launchd, start or kill
# processes, load/unload models, install packages, change permissions, or touch the network beyond
# GET requests to localhost. Reads no credential stores; .env files are reduced to key NAMES.
set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT=""; PASS_ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --output) OUT="${2:-}"; shift 2 ;;
    --root|--models-volume|--probe-endpoint|--max-depth|--max-files|--max-copy-bytes|--max-hash-bytes|--approved-root|--exact-file)
      PASS_ARGS+=("$1" "${2:-}"); shift 2 ;;
    --exact-files-only)
      PASS_ARGS+=("$1"); shift 1 ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "COLLECTION_STATUS=FAILED"; echo "REASON=unknown argument: $1"; exit 2 ;;
  esac
done
if [ -z "$OUT" ]; then
  echo "COLLECTION_STATUS=FAILED"
  echo "REASON=--output <dir> is required, e.g. --output \"\$HOME/p1_host_evidence/\$(date -u +%Y%m%dT%H%M%SZ)\" (use a name that won't match auto-discovery tokens boss|herdr|local_agent|atr)"
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "COLLECTION_STATUS=FAILED"; echo "REASON=python3 not found (Xcode Command Line Tools provide it)"; exit 2
fi

if ! python3 "$HERE/p1_build.py" --output "$OUT" ${PASS_ARGS[@]+"${PASS_ARGS[@]}"}; then
  echo "COLLECTION_STATUS=FAILED"; echo "OUTPUT_PATH=$OUT"; echo "SAFE_TO_UPLOAD_OR_COMMIT=NO"; exit 1
fi
OUT_ABS="$(cd "$OUT" && pwd)"
VERIFY_CMD="python3 \"$HERE/verify_preflight_bundle.py\" \"$OUT_ABS\""
VERIFY_OUT="$(python3 "$HERE/verify_preflight_bundle.py" "$OUT_ABS")"; VRC=$?
printf '%s\n' "$VERIFY_OUT"

case $VRC in
  0) STATUS="COMPLETE"; SAFE="YES" ;;
  3) STATUS="COMPLETE_WITH_SECRET_FINDINGS"; SAFE="NO" ;;
  *) STATUS="INVALID_BUNDLE"; SAFE="NO" ;;
esac
if printf '%s' "$VERIFY_OUT" | grep -q 'COVERAGE_SUFFICIENT_FOR_P1_ANALYSIS=NO' && [ "$STATUS" = "COMPLETE" ]; then
  STATUS="COMPLETE_WITH_COVERAGE_GAPS"
fi

echo "COLLECTION_STATUS=$STATUS"
echo "OUTPUT_PATH=$OUT_ABS"
echo "MANIFEST_PATH=$OUT_ABS/manifest.json"
echo "VERIFY_COMMAND=$VERIFY_CMD"
echo "SAFE_TO_UPLOAD_OR_COMMIT=$SAFE"
echo "PUBLIC_REPO_COMMIT_ALLOWED=NO (bundle may hold sanitized host source/config; share privately, never commit to the public control repo)"
echo "ARCHIVE_COMMAND_(not executed)=tar -czf \"$OUT_ABS.tar.gz\" -C \"$(dirname "$OUT_ABS")\" \"$(basename "$OUT_ABS")\""
if [ "$SAFE" = "NO" ]; then
  echo "ACTION_REQUIRED=Do NOT share this bundle. Delete the files named in SECRET_FINDING/PROBLEM lines above (or the whole output dir) and re-run into a NEW output dir."
fi
[ "$SAFE" = "YES" ]
