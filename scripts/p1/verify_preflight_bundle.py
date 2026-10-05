#!/usr/bin/env python3
"""Verify a P1 preflight evidence bundle. Read-only, stdlib only; never executes bundle content.

Usage: python3 verify_preflight_bundle.py <bundle_dir>

Prints VERIFY_STATUS, SECRET_SCAN, COVERAGE and a list of problems.
Exit codes: 0 = structure PASS and secret scan clean; 1 = structure FAIL; 3 = secret-like findings.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from p1_common import (CATEGORIES, COVERAGE_REQUIRED, ARTIFACT_TYPES, SANITIZATION,  # noqa: E402
                       COLLECTION_CLASSES, SCHEMA_VERSION, scan_text_for_secrets)
from p1_build import sha256_file  # noqa: E402

SHA_RE = re.compile(r"^[0-9a-f]{64}$")
TOP_REQUIRED = {"schema_version": str, "collector_version": str, "collection_timestamp": str,
                "host_id": str, "output_root": str, "search_scope": dict, "entries": list}
ENTRY_REQUIRED = {"id": str, "category": str, "artifact_type": str, "collection_class": str,
                  "sanitization_status": str, "success": bool, "required": bool, "notes": str}
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def is_legit_empty_source_copy(e):
    """Narrow exception for a zero-byte artifact that is a verified, exact copy of a
    zero-byte source file (e.g. an empty __init__.py). Every other zero-byte artifact
    — required, generated/runtime, wrong-provenance, or wrong-hash — still fails."""
    return (
        e.get("required") is False
        and e.get("success") is True
        and e.get("collection_class") == "file_copy_sanitized"
        and e.get("source_size_bytes") == 0
        and e.get("source_sha256") == EMPTY_SHA256
        and e.get("sha256") == EMPTY_SHA256
    )


def validate_manifest(m, problems):
    for k, t in TOP_REQUIRED.items():
        if not isinstance(m.get(k), t):
            problems.append(f"manifest: field '{k}' missing or not {t.__name__}")
    if m.get("schema_version") != SCHEMA_VERSION:
        problems.append(f"manifest: schema_version must be {SCHEMA_VERSION}")
    if isinstance(m.get("collection_timestamp"), str) and \
            not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", m["collection_timestamp"]):
        problems.append("manifest: collection_timestamp must be UTC ISO-8601 (…Z)")
    seen = set()
    for i, e in enumerate(m.get("entries", []) if isinstance(m.get("entries"), list) else []):
        tag = f"entry[{i}]"
        if not isinstance(e, dict):
            problems.append(f"{tag}: not an object")
            continue
        for k, t in ENTRY_REQUIRED.items():
            if not isinstance(e.get(k), t):
                problems.append(f"{tag}: field '{k}' missing or not {t.__name__}")
        tag = f"{e.get('id', tag)}"
        if e.get("id") in seen:
            problems.append(f"{tag}: duplicate id")
        seen.add(e.get("id"))
        for k, allowed in (("category", CATEGORIES), ("artifact_type", ARTIFACT_TYPES),
                           ("sanitization_status", SANITIZATION), ("collection_class", COLLECTION_CLASSES)):
            if e.get(k) not in allowed:
                problems.append(f"{tag}: {k}='{e.get(k)}' not in allowed set")
        for k in ("sha256", "source_sha256"):
            if e.get(k) is not None and not (isinstance(e[k], str) and SHA_RE.match(e[k])):
                problems.append(f"{tag}: {k} is not a 64-hex SHA-256")
        if e.get("bundle_path") is not None and e.get("sha256") is None:
            problems.append(f"{tag}: bundle_path declared without sha256")


def check_files(bundle, m, problems):
    root = os.path.realpath(bundle)
    declared = {"manifest.json"}
    for e in m.get("entries", []):
        if not isinstance(e, dict):
            continue
        bp, tag = e.get("bundle_path"), e.get("id")
        if bp is None:
            if e.get("required"):
                problems.append(f"{tag}: required artifact has no bundle_path")
            continue
        if not isinstance(bp, str) or os.path.isabs(bp) or ".." in bp.replace("\\", "/").split("/"):
            problems.append(f"{tag}: bundle_path escapes the bundle: {bp!r}")
            continue
        full = os.path.join(root, bp)
        if os.path.islink(full) or not os.path.realpath(full).startswith(root + os.sep):
            problems.append(f"{tag}: bundle_path is a symlink or resolves outside the bundle: {bp}")
            continue
        declared.add(os.path.normpath(bp))
        if not os.path.isfile(full):
            problems.append(f"{tag}: MISSING file {bp}")
            continue
        size = os.path.getsize(full)
        if size == 0 and (e.get("required") or e.get("success")) and not is_legit_empty_source_copy(e):
            problems.append(f"{tag}: zero-byte artifact {bp}")
        if e.get("size_bytes") is not None and e["size_bytes"] != size:
            problems.append(f"{tag}: size mismatch for {bp} (declared {e['size_bytes']}, actual {size})")
        if e.get("sha256") and sha256_file(full) != e["sha256"]:
            problems.append(f"{tag}: SHA-256 mismatch for {bp}")
    return root, declared


def secret_scan(root, findings):
    for dirpath, _, files in os.walk(root, followlinks=False):
        for fn in files:
            p = os.path.join(dirpath, fn)
            try:
                with open(p, "rb") as f:
                    raw = f.read(8_000_000)
            except OSError:
                continue
            if b"\0" in raw[:4096]:
                findings.append((os.path.relpath(p, root), 0, "binary_file_in_bundle"))
                continue
            for ln, rule in scan_text_for_secrets(raw.decode("utf-8", "replace")):
                findings.append((os.path.relpath(p, root), ln, rule))


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: verify_preflight_bundle.py <bundle_dir>")
    bundle = sys.argv[1]
    problems, findings = [], []
    mpath = os.path.join(bundle, "manifest.json")
    if not os.path.isfile(mpath) or os.path.getsize(mpath) == 0:
        print("VERIFY_STATUS=FAIL\nPROBLEM: manifest.json missing or empty")
        return 1
    try:
        with open(mpath, encoding="utf-8") as f:
            m = json.load(f)
    except (ValueError, OSError) as ex:
        print(f"VERIFY_STATUS=FAIL\nPROBLEM: manifest.json unreadable: {ex}")
        return 1
    validate_manifest(m, problems)
    root, declared = check_files(bundle, m, problems)
    for dirpath, _, files in os.walk(root, followlinks=False):
        for fn in files:
            rel = os.path.normpath(os.path.relpath(os.path.join(dirpath, fn), root))
            if rel not in declared:
                problems.append(f"UNDECLARED file in bundle (not in manifest): {rel}")
    secret_scan(root, findings)

    entries = [e for e in m.get("entries", []) if isinstance(e, dict)]
    def covered(c):
        if c == "GOVERNED_FILE_INTEGRITY":  # any host file with a recorded source hash
            return any(e.get("success") and e.get("source_sha256") for e in entries)
        return any(e.get("category") == c and e.get("success") and e.get("item_count") != 0
                   and (e.get("bundle_path") or e.get("source_sha256")) for e in entries)
    gaps = [c for c in COVERAGE_REQUIRED if not covered(c)]
    print(f"VERIFY_STATUS={'FAIL' if problems else 'PASS'}")
    print(f"SECRET_SCAN={'FINDINGS' if findings else 'CLEAN'}")
    print(f"ENTRIES={len(entries)} FAILED_COLLECTIONS={sum(1 for e in entries if not e.get('success'))}")
    print("COVERAGE_GAPS=" + (",".join(gaps) if gaps else "NONE"))
    print("COVERAGE_SUFFICIENT_FOR_P1_ANALYSIS=" + ("NO" if gaps else "YES"))
    for p in problems[:50]:
        print(f"PROBLEM: {p}")
    for rel, ln, rule in findings[:50]:
        print(f"SECRET_FINDING: file={rel} line={ln} rule={rule} -> remove or re-sanitize this file before sharing")
    if findings:
        return 3
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
