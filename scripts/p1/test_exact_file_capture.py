#!/usr/bin/env python3
"""Regression tests for the P1 bounded exact-file evidence capture feature (stdlib unittest).

Run: python3 scripts/p1/test_exact_file_capture.py
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p1_build  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def run_build(args):
    return subprocess.run([sys.executable, os.path.join(HERE, "p1_build.py")] + args,
                           capture_output=True, text=True)


class ValidateExactFilesFailTests(unittest.TestCase):
    """Unit-level: validate_exact_files() must fail closed (SystemExit) and never read content
    for any of these cases."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.approved = os.path.join(self.tmp.name, "approved")
        os.makedirs(self.approved)
        self.approved_real = [os.path.realpath(self.approved)]

    def tearDown(self):
        self.tmp.cleanup()

    def test_fail_relative_path(self):
        with self.assertRaises(SystemExit):
            p1_build.validate_exact_files(["relative/path.txt"], self.approved_real)

    def test_fail_nonexistent_file(self):
        with self.assertRaises(SystemExit):
            p1_build.validate_exact_files([os.path.join(self.approved, "nope.txt")], self.approved_real)

    def test_fail_symlink(self):
        real = os.path.join(self.approved, "real.txt")
        with open(real, "w") as f:
            f.write("hello")
        link = os.path.join(self.approved, "link.txt")
        os.symlink(real, link)
        with self.assertRaises(SystemExit):
            p1_build.validate_exact_files([link], self.approved_real)

    def test_fail_outside_approved_root(self):
        outside = os.path.join(self.tmp.name, "outside.txt")
        with open(outside, "w") as f:
            f.write("hello")
        with self.assertRaises(SystemExit):
            p1_build.validate_exact_files([outside], self.approved_real)

    def test_fail_model_payload_extension(self):
        payload = os.path.join(self.approved, "weights.gguf")
        with open(payload, "w") as f:
            f.write("fake")
        with self.assertRaises(SystemExit):
            p1_build.validate_exact_files([payload], self.approved_real)

    def test_fail_traversal_escape(self):
        escaped_dir = os.path.join(self.tmp.name, "escaped")
        os.makedirs(escaped_dir)
        target = os.path.join(escaped_dir, "secret.txt")
        with open(target, "w") as f:
            f.write("hello")
        traversal_path = os.path.join(self.approved, "..", "escaped", "secret.txt")
        with self.assertRaises(SystemExit):
            p1_build.validate_exact_files([traversal_path], self.approved_real)


class ExactFileCaptureEndToEndTests(unittest.TestCase):
    """End-to-end: invoke p1_build.py as a real subprocess, inspect the resulting manifest."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.approved = os.path.join(self.tmp.name, "approved")
        os.makedirs(self.approved)
        self.output_base = os.path.join(self.tmp.name, "out_base")

    def tearDown(self):
        self.tmp.cleanup()

    def _out(self, name):
        return os.path.join(self.output_base, name)

    def test_pass_sanitized_text_file(self):
        f = os.path.join(self.approved, "note.txt")
        with open(f, "w") as fh:
            fh.write("api_key=SUPERSECRET123456\nhello world\n")
        out = self._out("t1")
        r = run_build(["--output", out, "--exact-files-only",
                       "--approved-root", self.approved, "--exact-file", f])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        m = json.load(open(os.path.join(out, "manifest.json")))
        self.assertEqual(m["search_scope"]["roots"], [])
        entries = [e for e in m["entries"] if e.get("source_path") == os.path.realpath(f)]
        self.assertEqual(len(entries), 1)
        e = entries[0]
        self.assertEqual(e["collection_class"], "file_copy_sanitized")
        self.assertIsNotNone(e["source_sha256"])
        bundle_text = open(os.path.join(out, e["bundle_path"])).read()
        self.assertNotIn("SUPERSECRET123456", bundle_text)
        self.assertIn("hello world", bundle_text)

    def test_pass_multiple_exact_files(self):
        f1 = os.path.join(self.approved, "a.txt")
        with open(f1, "w") as fh:
            fh.write("alpha")
        f2 = os.path.join(self.approved, "b.md")
        with open(f2, "w") as fh:
            fh.write("beta")
        out = self._out("t2")
        r = run_build(["--output", out, "--exact-files-only", "--approved-root", self.approved,
                       "--exact-file", f1, "--exact-file", f2])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        m = json.load(open(os.path.join(out, "manifest.json")))
        want = {os.path.realpath(f1), os.path.realpath(f2)}
        got = {e.get("source_path") for e in m["entries"] if e.get("source_path") in want}
        self.assertEqual(got, want)

    def test_pass_binary_metadata_only_no_content_read(self):
        f = os.path.join(self.approved, "boss_memory.db")
        with open(f, "wb") as fh:
            fh.write(b"SQLITE FORMAT 3\x00" + b"\x01" * 100)
        os.chmod(f, 0)  # zero permissions: any open() of this file's content would raise/fail
        try:
            out = self._out("t3")
            r = run_build(["--output", out, "--exact-files-only", "--approved-root", self.approved,
                           "--exact-file", f])
            # Success despite zero read permission proves the implementation never opened the
            # file's content (only os.stat(), which needs no read permission on the file itself).
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            m = json.load(open(os.path.join(out, "manifest.json")))
            entries = [e for e in m["entries"] if e.get("source_path") == os.path.realpath(f)]
            self.assertEqual(len(entries), 1)
            e = entries[0]
            self.assertEqual(e["collection_class"], "metadata")
            self.assertIsNone(e["source_sha256"])
            self.assertIn("content_read=false", e["notes"])
            self.assertIn("content_hashed=false", e["notes"])
            meta = json.loads(open(os.path.join(out, e["bundle_path"])).read())
            self.assertFalse(meta["content_read"])
            self.assertFalse(meta["content_hashed"])
        finally:
            os.chmod(f, 0o600)  # restore so tempdir cleanup can remove it

    def test_pass_exact_files_only_zero_roots(self):
        out = self._out("t4")
        r = run_build(["--output", out, "--exact-files-only"])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        m = json.load(open(os.path.join(out, "manifest.json")))
        self.assertEqual(m["search_scope"]["roots"], [])

    def test_pass_normal_directory_mode_unaffected(self):
        root = os.path.join(self.tmp.name, "myroot")
        os.makedirs(os.path.join(root, "sub"))
        with open(os.path.join(root, "sub", "router_config.json"), "w") as fh:
            fh.write('{"route": "ok"}')
        out = self._out("t5")
        r = run_build(["--output", out, "--root", root, "--models-volume", ""])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        m = json.load(open(os.path.join(out, "manifest.json")))
        self.assertEqual(m["search_scope"]["roots"], [os.path.abspath(root)])
        self.assertTrue(any("router_config.json" in (e.get("source_path") or "") for e in m["entries"]))

    def test_fail_output_inside_approved_root(self):
        out = os.path.join(self.approved, "out_inside")
        r = run_build(["--output", out, "--exact-files-only", "--approved-root", self.approved])
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("approved root", (r.stdout + r.stderr))


if __name__ == "__main__":
    unittest.main()
