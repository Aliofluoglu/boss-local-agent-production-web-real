#!/usr/bin/env python3
"""Regression tests for the P1 bundle verifier's zero-byte artifact handling (stdlib unittest).

Run: python3 scripts/p1/test_verify_preflight_bundle.py
"""
import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verify_preflight_bundle as vpb  # noqa: E402

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
NONEMPTY = b"print('hello')\n"
NONEMPTY_SHA256 = hashlib.sha256(NONEMPTY).hexdigest()


def base_entry(**kw):
    e = {
        "id": "E0001", "category": "ROUTING", "artifact_type": "code",
        "collection_class": "file_copy_sanitized", "sanitization_status": "clean",
        "success": True, "required": False, "notes": "",
        "bundle_path": None, "sha256": None, "source_sha256": None,
        "size_bytes": None, "source_size_bytes": None, "mtime_utc": None,
        "item_count": None,
    }
    e.update(kw)
    return e


class ZeroByteVerifierTests(unittest.TestCase):
    def _run(self, entry, content):
        with tempfile.TemporaryDirectory() as bundle:
            bp = "artifacts/routing/sample.txt"
            full = os.path.join(bundle, bp)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as f:
                f.write(content)
            entry = dict(entry, bundle_path=bp)
            problems = []
            vpb.check_files(bundle, {"entries": [entry]}, problems)
            return problems

    # --- PASS ---

    def test_pass_legit_empty_source_copy(self):
        e = base_entry(id="E0014", required=False, success=True,
                        collection_class="file_copy_sanitized",
                        source_size_bytes=0, source_sha256=EMPTY_SHA256,
                        sha256=EMPTY_SHA256, size_bytes=0)
        problems = self._run(e, content=b"")
        self.assertEqual(problems, [], problems)

    def test_pass_normal_nonzero_artifact_unaffected(self):
        e = base_entry(id="E0008", required=False, success=True,
                        collection_class="file_copy_sanitized",
                        source_size_bytes=len(NONEMPTY), source_sha256=NONEMPTY_SHA256,
                        sha256=NONEMPTY_SHA256, size_bytes=len(NONEMPTY))
        problems = self._run(e, content=NONEMPTY)
        self.assertEqual(problems, [], problems)

    # --- FAIL (must remain fail-closed) ---

    def test_fail_required_zero_byte(self):
        e = base_entry(id="E0002", required=True, success=True,
                        collection_class="file_copy_sanitized",
                        source_size_bytes=0, source_sha256=EMPTY_SHA256,
                        sha256=EMPTY_SHA256, size_bytes=0)
        problems = self._run(e, content=b"")
        self.assertTrue(any("zero-byte artifact" in p for p in problems), problems)

    def test_fail_nonzero_source_size(self):
        e = base_entry(id="E0003", required=False, success=True,
                        collection_class="file_copy_sanitized",
                        source_size_bytes=4096, source_sha256=EMPTY_SHA256,
                        sha256=EMPTY_SHA256, size_bytes=0)
        problems = self._run(e, content=b"")
        self.assertTrue(any("zero-byte artifact" in p for p in problems), problems)

    def test_fail_wrong_source_hash(self):
        e = base_entry(id="E0004", required=False, success=True,
                        collection_class="file_copy_sanitized",
                        source_size_bytes=0, source_sha256=NONEMPTY_SHA256,
                        sha256=EMPTY_SHA256, size_bytes=0)
        problems = self._run(e, content=b"")
        self.assertTrue(any("zero-byte artifact" in p for p in problems), problems)

    def test_fail_generated_runtime_zero_byte(self):
        e = base_entry(id="E0005", required=False, success=True,
                        collection_class="safe_command", artifact_type="runtime_command",
                        category="RUNTIME_RESOURCE",
                        source_size_bytes=None, source_sha256=None,
                        sha256=EMPTY_SHA256, size_bytes=0)
        problems = self._run(e, content=b"")
        self.assertTrue(any("zero-byte artifact" in p for p in problems), problems)

    def test_fail_missing_artifact(self):
        with tempfile.TemporaryDirectory() as bundle:
            e = base_entry(id="E0006", bundle_path="artifacts/routing/missing.txt",
                            required=False, success=True,
                            collection_class="file_copy_sanitized",
                            source_size_bytes=0, source_sha256=EMPTY_SHA256,
                            sha256=EMPTY_SHA256, size_bytes=0)
            problems = []
            vpb.check_files(bundle, {"entries": [e]}, problems)
            self.assertTrue(any("MISSING file" in p for p in problems), problems)

    def test_fail_hash_mismatch_nonzero_content(self):
        e = base_entry(id="E0007", required=False, success=True,
                        collection_class="file_copy_sanitized",
                        source_size_bytes=len(NONEMPTY), source_sha256=NONEMPTY_SHA256,
                        sha256=NONEMPTY_SHA256, size_bytes=len(NONEMPTY))
        tampered = b"X" * len(NONEMPTY)  # same length, different content/hash
        problems = self._run(e, content=tampered)
        self.assertTrue(any("SHA-256 mismatch" in p for p in problems), problems)


if __name__ == "__main__":
    unittest.main()
