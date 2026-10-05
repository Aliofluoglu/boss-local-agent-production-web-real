#!/usr/bin/env python3
"""P1 bounded, read-only evidence builder (stdlib only). Invoked by collect_boss_preflight.sh.

Reads BOSS host files strictly read-only and writes ONLY inside --output:
  manifest.json, meta/, runtime/, artifacts/, refs/, inventory/
It never executes collected files, never enters credential/browser directories, never
copies .env values (names only), and sanitizes every copied text before writing.
Model payloads are never read or hashed; only path/size/mtime are inventoried.
"""
import argparse
import datetime
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from p1_common import (COLLECTOR_VERSION, SCHEMA_VERSION, EXCLUDED_DIRS, NEVER_READ_NAME_RE,  # noqa: E402
                       ENV_FILE_RE, MODEL_PAYLOAD_EXT, redact_text, has_private_key_block)

TEXT_EXT = {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".plist", ".py", ".sh",
            ".zsh", ".bash", ".js", ".mjs", ".ts", ".md", ".txt", ""}
# (regex on lower-cased relative path, category) — first match wins.
CLASSIFY = [
    (r"final[_-]?lock|qualification|accepted|_report|evidence_index|closure", "ACCEPTED_PROJECT_EVIDENCE"),
    (r"mcp|tool[_-]?registry|(^|/)tools?\.(json|ya?ml|toml)$|allowlist|permission|capabilit", "MCP_TOOL_SURFACE"),
    (r"boss-agent-route|herdr|local[_-]?agent", "TOPOLOGY"),
    (r"route|router|routing|fallback|escalat", "ROUTING"),
    (r"role[_-]?registry|agent[_-]?manifest|provider|profile|registry|(^|/)models?\.(json|ya?ml|toml)$",
     "ROLE_PROVIDER_REFERENCES"),
    (r"boss-agent-route|herdr|local[_-]?agent|adapter|bridge|manifest|launch", "TOPOLOGY"),
]
TERM_CLASSES = [  # (class, regex, category the index file feeds)
    ("local_agent", r"local[_-]?agent", "ROLE_PROVIDER_REFERENCES"),
    ("local_general", r"local[_-]?general", "ROLE_PROVIDER_REFERENCES"),
    ("gemma", r"gemma[-_ ]?4|gemma4", "ROLE_PROVIDER_REFERENCES"),
    ("qwen35", r"qwen[-_ ]?3\.5", "ROLE_PROVIDER_REFERENCES"),
    ("qwen3_vl", r"qwen3[-_ ]?vl", "ROLE_PROVIDER_REFERENCES"),
    ("fallback_escalation", r"fallback|escalat", "ROUTING"),
    ("mcp_tools", r"\bmcp\b|allowlist|tool[_-]?registry", "MCP_TOOL_SURFACE"),
    ("route_entrypoints", r"boss-agent-route|herdr|role[_-]?registry|agent[_-]?manifest|BOSS_AI_MODELS",
     "TOPOLOGY"),
    ("project_contracts", r"FINAL_LOCK|opt[_-]?in|active[_-]?projects?|project[_-]?registry",
     "CROSS_PROJECT_DEPENDENCIES"),
]
RUNTIME_COMMANDS = [  # fixed argv, no shell; every one is a read-only query
    ("uname", ["uname", "-srm"], None),
    ("sw_vers", ["sw_vers"], None),
    ("sysctl_hw", ["sysctl", "hw.memsize", "hw.ncpu", "hw.model", "vm.swapusage"], None),
    ("vm_stat", ["vm_stat"], None),
    ("memory_pressure", ["memory_pressure"], None),
    ("uptime", ["uptime"], None),
    ("df_k", ["df", "-k"], None),
    ("ps_inference_workloads", ["ps", "-axo", "pid=,ppid=,rss=,comm="],
     r"ollama|llama|lmstudio|mlx|gemma|qwen|herdr|boss|python|node|codex|claude"),
    ("launchctl_list", ["launchctl", "list"], r"boss|herdr|ollama|llama|lmstudio|mlx"),
    ("listening_ports", ["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], None),
]
DEFAULT_PROBES = ["http://127.0.0.1:11434/api/tags", "http://127.0.0.1:11434/api/ps",
                  "http://127.0.0.1:1234/v1/models"]
PROBE_PATHS = {"/api/tags", "/api/ps", "/api/version", "/v1/models", "/health", "/props"}
PROBE_HOSTS = {"127.0.0.1", "localhost", "[::1]"}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def utc(ts=None):
    t = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc) if ts is not None \
        else datetime.datetime.now(datetime.timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_name(s):
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)[:80] or "file"


class Bundle:
    def __init__(self, out):
        self.out = out
        self.entries = []

    def write(self, rel, data):
        p = os.path.join(self.out, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode("utf-8"))
        return p

    def add(self, **kw):
        e = {"id": f"E{len(self.entries) + 1:04d}", "source_path": None, "bundle_path": None,
             "sha256": None, "source_sha256": None, "size_bytes": None, "source_size_bytes": None, "mtime_utc": None,
             "item_count": None, "required": False, "notes": ""}
        e.update(kw)
        self.entries.append(e)
        return e

    def add_text(self, rel, text, **kw):
        san, _ = redact_text(text)
        data = san.encode("utf-8")
        self.write(rel, data)
        return self.add(bundle_path=rel, sha256=sha256_bytes(data), size_bytes=len(data),
                        sanitization_status="redacted" if san != text else "clean", **kw)


def run_runtime(b):
    for name, argv, keep in RUNTIME_COMMANDS:
        rel = f"runtime/{name}.txt"
        kw = dict(category="RUNTIME_RESOURCE", artifact_type="runtime_command",
                  collection_class="safe_command", source_path=" ".join(argv))
        if shutil.which(argv[0]) is None:
            b.add_text(rel, f"# command unavailable on this host: {argv[0]}\n", success=False,
                       notes="command not found (expected on non-macOS hosts)", **kw)
            continue
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=20, stdin=subprocess.DEVNULL)
            out = r.stdout
            if keep:
                out = "\n".join(l for l in out.splitlines()
                                if re.search(keep, l, re.I) or l.lstrip().startswith(("COMMAND", "PID")))
            out = out[:400_000] or f"# no output (exit {r.returncode})\n"
            b.add_text(rel, out, success=r.returncode == 0,
                       notes=f"exit={r.returncode}" + (f" stderr={r.stderr.strip()[:120]}" if r.stderr.strip() else ""),
                       **kw)
        except Exception as ex:  # noqa: BLE001
            b.add_text(rel, f"# command failed: {type(ex).__name__}\n", success=False, notes=str(ex)[:160], **kw)


def probe_endpoints(b, urls):
    for url in urls:
        m = re.match(r"^http://([^/:]+|\[::1\])(:\d+)?(/[A-Za-z0-9/_.-]*)$", url)
        rel = f"runtime/probe_{safe_name(url)}.txt"
        kw = dict(category="RUNTIME_RESOURCE", artifact_type="endpoint_probe",
                  collection_class="localhost_get", source_path=url)
        if not m or m.group(1) not in PROBE_HOSTS or m.group(3) not in PROBE_PATHS:
            b.add_text(rel, "# rejected: only GET on localhost with an allowlisted path\n",
                       success=False, notes="probe URL rejected by allowlist", **kw)
            continue
        try:
            with urllib.request.urlopen(urllib.request.Request(url, method="GET"), timeout=5) as r:
                body = r.read(262_144).decode("utf-8", "replace")
            b.add_text(rel, body, success=True, notes="HTTP GET only; no model load", **kw)
        except Exception as ex:  # noqa: BLE001
            b.add_text(rel, f"# unreachable: {type(ex).__name__}\n", success=False,
                       notes="endpoint not listening or refused (informative, not an error)", **kw)


def discover_roots(explicit, models_volume):
    home = os.path.expanduser("~")
    roots, notes = [], []
    if explicit:
        roots = [os.path.abspath(r) for r in explicit]
        notes.append("roots supplied explicitly via --root")
    else:
        pat = re.compile(r"(?i)boss|herdr|local[_-]?agent|(^|[_-])atr($|[_-])")
        try:
            for d1 in sorted(os.listdir(home)):
                p1 = os.path.join(home, d1)
                if d1.startswith(".") or d1 in EXCLUDED_DIRS or not os.path.isdir(p1) or os.path.islink(p1):
                    continue
                if pat.search(d1):
                    roots.append(p1)
                    continue
                for d2 in sorted(os.listdir(p1))[:300]:
                    p2 = os.path.join(p1, d2)
                    if (not d2.startswith(".") and d2 not in EXCLUDED_DIRS and pat.search(d2)
                            and os.path.isdir(p2) and not os.path.islink(p2)):
                        roots.append(p2)
        except OSError as ex:
            notes.append(f"home scan failed: {ex}")
        notes.append("auto-discovery: $HOME depth<=2 directory names matching boss|herdr|local_agent|atr")
    if models_volume and os.path.isdir(models_volume) and models_volume not in roots:
        roots.append(models_volume)
    roots = [r for r in dict.fromkeys(roots) if os.path.isdir(r)]
    roots = [r for r in roots if not any(r != o and r.startswith(o.rstrip("/") + "/") for o in roots)]
    return roots, notes


def classify(rel_lower):
    for rx, cat in CLASSIFY:
        if re.search(rx, rel_lower):
            return cat
    return None


def artifact_type(path):
    n, ext = os.path.basename(path).lower(), os.path.splitext(path)[1].lower()
    if ext == ".plist":
        return "launchd_plist"
    if "registry" in n:
        return "registry"
    if "manifest" in n:
        return "manifest"
    if ext in (".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf"):
        return "config"
    if ext in (".md", ".txt"):
        return "doc"
    return "code"


def looks_text(path):
    try:
        with open(path, "rb") as f:
            return b"\0" not in f.read(4096)
    except OSError:
        return False


def iter_files(root, max_depth):
    base_depth = root.rstrip("/").count("/")
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        depth = dirpath.rstrip("/").count("/") - base_depth
        dirnames[:] = sorted(d for d in dirnames if not d.startswith(".") and d not in EXCLUDED_DIRS
                             and not os.path.islink(os.path.join(dirpath, d)))
        if depth >= max_depth:
            dirnames[:] = []
        for fn in sorted(filenames):
            p = os.path.join(dirpath, fn)
            if not os.path.islink(p):
                yield p


def collect_files(b, roots, a, scope):
    refs = {c: [] for c, _, _ in TERM_CLASSES}
    term_rx = [(c, re.compile(rx, re.I)) for c, rx, _ in TERM_CLASSES]
    copied = scanned = ref_total = 0
    inventory = []
    extra = [(os.path.expanduser("~/.ollama/models/manifests"), "ollama_manifests")]
    work = [(r, "root") for r in roots] + [(p, k) for p, k in extra if os.path.isdir(p)]
    for root, kind in work:
        for p in iter_files(root, a.max_depth):
            if copied >= a.max_files:
                scope["truncated"] = True
                break
            ext = os.path.splitext(p)[1].lower()
            try:
                st = os.stat(p)
            except OSError:
                continue
            if ext in MODEL_PAYLOAD_EXT:
                if len(inventory) < 5000:
                    inventory.append((p, st.st_size, utc(st.st_mtime)))
                continue
            rel = os.path.relpath(p, root).lower()
            cat = "ROLE_PROVIDER_REFERENCES" if kind == "ollama_manifests" else classify(rel)
            common = dict(source_path=p, source_size_bytes=st.st_size, mtime_utc=utc(st.st_mtime))
            if NEVER_READ_NAME_RE.search(p):
                b.add(category="GOVERNED_FILE_INTEGRITY", artifact_type="file_record",
                      collection_class="file_never_read", sanitization_status="not_copied_never_read",
                      success=True, notes="credential-like file name: path/size/mtime only, never opened",
                      **common)
                continue
            if ENV_FILE_RE.search(p):
                try:
                    with open(p, encoding="utf-8", errors="replace") as f:
                        names = [m.group(2) for m in (re.match(r"^\s*(export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=", l)
                                                      for l in f) if m]
                except OSError:
                    continue
                rel_out = f"artifacts/env_keys/{sha256_bytes(p.encode())[:10]}__{safe_name(os.path.basename(p))}.txt"
                b.add_text(rel_out, "".join(f"{n}={'<REDACTED>'}\n" for n in names) or "# no assignments\n",
                           category="ROLE_PROVIDER_REFERENCES", artifact_type="env_keys",
                           collection_class="file_copy_sanitized", success=True, item_count=len(names),
                           notes="key NAMES only; values never read into the bundle", **common)
                b.entries[-1]["sanitization_status"] = "names_only"
                copied += 1
                continue
            if ext not in TEXT_EXT or not looks_text(p):
                continue
            # lightweight term-reference scan (bounded) on every text file in scope
            if st.st_size <= 1_048_576 and scanned < 20_000 and ref_total < 20_000:
                scanned += 1
                n_file = 0
                try:
                    with open(p, encoding="utf-8", errors="replace") as f:
                        for ln, line in enumerate(f, 1):
                            for c, rx in term_rx:
                                if rx.search(line) and n_file < 50:
                                    t, _ = redact_text(line.strip()[:240])
                                    refs[c].append(f"{c}\t{p}\t{ln}\t{t}")
                                    n_file += 1
                                    ref_total += 1
                                    break
                except OSError:
                    pass
            if not cat:
                continue
            at = artifact_type(p)
            if st.st_size <= a.max_copy_bytes:
                try:
                    text = open(p, encoding="utf-8", errors="replace").read()
                except OSError as ex:
                    b.add(category=cat, artifact_type=at, collection_class="file_copy_sanitized",
                          success=False, sanitization_status="not_applicable", notes=f"read failed: {ex}", **common)
                    continue
                src_hash = sha256_file(p)
                if has_private_key_block(text):
                    b.add(category=cat, artifact_type=at, collection_class="file_hash_only", success=True,
                          source_sha256=src_hash, sanitization_status="withheld_secret_material",
                          notes="private key block detected: file withheld; REMOVE from host config scope", **common)
                    continue
                rel_out = f"artifacts/{cat.lower()}/{sha256_bytes(p.encode())[:10]}__{safe_name(os.path.basename(p))}.txt"
                b.add_text(rel_out, text, category=cat, artifact_type=at, collection_class="file_copy_sanitized",
                           success=True, source_sha256=src_hash, notes=f"kind={kind}", **common)
                copied += 1
            else:
                h = sha256_file(p) if st.st_size <= a.max_hash_bytes else None
                b.add(category=cat, artifact_type=at, collection_class="file_hash_only", success=True,
                      source_sha256=h, sanitization_status="not_copied_hash_only",
                      notes="larger than --max-copy-bytes" + ("" if h else "; larger than --max-hash-bytes: not hashed"),
                      **common)
    for c, _, cat in TERM_CLASSES:
        body = "class\tpath\tline\ttext\n" + "\n".join(refs[c]) + ("\n" if refs[c] else "")
        b.add_text(f"refs/{c}.tsv", body, category=cat, artifact_type="reference_index",
                   collection_class="grep_references", success=True, item_count=len(refs[c]),
                   notes=f"term-class index (path/line/truncated redacted line); hits={len(refs[c])}")
    scope["files_scanned_for_terms"] = scanned
    scope["files_copied"] = copied
    return inventory


def write_inventory(b, inventory, models_volume):
    body = "path\tsize_bytes\tmtime_utc\n" + "\n".join(f"{p}\t{s}\t{m}" for p, s, m in inventory) + \
           ("\n" if inventory else "")
    b.add_text("inventory/model_payload_inventory.tsv", body, category="PROTECTED_ASSET_INVENTORY",
               artifact_type="model_inventory", collection_class="metadata", success=True,
               item_count=len(inventory),
               notes=f"model payload files found under discovered roots/{models_volume}: path/size/mtime only, never hashed")


def validate_exact_files(exact_files, approved_roots):
    """Validate --exact-file candidates. Exits (fail-closed) on any violation; never reads
    file content here -- model-payload rejection and containment happen before any open()."""
    validated = []
    for f in exact_files:
        if not os.path.isabs(f):
            sys.exit(f"ERROR: --exact-file must be an absolute path: {f}")
        if os.path.islink(f):
            sys.exit(f"ERROR: --exact-file must not be a symlink: {f}")
        if not os.path.isfile(f):
            sys.exit(f"ERROR: --exact-file does not exist or is not a regular file: {f}")
        ext = os.path.splitext(f)[1].lower()
        if ext in MODEL_PAYLOAD_EXT:
            sys.exit(f"ERROR: --exact-file rejected, model payload extension forbidden: {f}")
        real = os.path.realpath(f)
        if not approved_roots or not any(
                real == ar or real.startswith(ar.rstrip("/") + "/") for ar in approved_roots):
            sys.exit(f"ERROR: --exact-file does not resolve inside any --approved-root: {f}")
        validated.append(real)
    return validated


def collect_exact_files(b, exact_files):
    """Capture explicitly-named files only. Text: existing redaction path, hashed.
    Binary/non-text: metadata only, never opened, never hashed."""
    for p in exact_files:
        st = os.stat(p)
        common = dict(source_path=p, source_size_bytes=st.st_size, mtime_utc=utc(st.st_mtime))
        if NEVER_READ_NAME_RE.search(p):
            b.add(category="GOVERNED_FILE_INTEGRITY", artifact_type="file_record",
                  collection_class="file_never_read", sanitization_status="not_copied_never_read",
                  success=True, required=False,
                  notes="exact_file_capture=true; credential-like file name: path/size/mtime only, never opened",
                  **common)
            continue
        if ENV_FILE_RE.search(p):
            try:
                with open(p, encoding="utf-8", errors="replace") as f:
                    names = [m.group(2) for m in (re.match(r"^\s*(export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=", l)
                                                  for l in f) if m]
            except OSError:
                names = []
            rel_out = f"artifacts/exact_files/{sha256_bytes(p.encode())[:10]}__{safe_name(os.path.basename(p))}.txt"
            e = b.add_text(rel_out, "".join(f"{n}=<REDACTED>\n" for n in names) or "# no assignments\n",
                       category="GOVERNED_FILE_INTEGRITY", artifact_type="env_keys",
                       collection_class="file_copy_sanitized", success=True, required=False,
                       item_count=len(names),
                       notes="exact_file_capture=true; key NAMES only; values never read into the bundle",
                       **common)
            e["sanitization_status"] = "names_only"
            continue
        ext = os.path.splitext(p)[1].lower()
        if ext in TEXT_EXT and looks_text(p):
            try:
                text = open(p, encoding="utf-8", errors="replace").read()
            except OSError as ex:
                b.add(category="GOVERNED_FILE_INTEGRITY", artifact_type=artifact_type(p),
                      collection_class="file_copy_sanitized", success=False,
                      sanitization_status="not_applicable", required=False,
                      notes=f"exact_file_capture=true; read failed: {ex}", **common)
                continue
            src_hash = sha256_file(p)
            if has_private_key_block(text):
                b.add(category="GOVERNED_FILE_INTEGRITY", artifact_type=artifact_type(p),
                      collection_class="file_hash_only", success=True, source_sha256=src_hash,
                      sanitization_status="withheld_secret_material", required=False,
                      notes="exact_file_capture=true; private key block detected: file withheld", **common)
                continue
            rel_out = f"artifacts/exact_files/{sha256_bytes(p.encode())[:10]}__{safe_name(os.path.basename(p))}.txt"
            b.add_text(rel_out, text, category="GOVERNED_FILE_INTEGRITY", artifact_type=artifact_type(p),
                       collection_class="file_copy_sanitized", success=True, required=False,
                       source_sha256=src_hash, notes="exact_file_capture=true", **common)
        else:
            meta_obj = {"source_path": p, "source_size_bytes": st.st_size, "mtime_utc": utc(st.st_mtime),
                        "content_read": False, "content_hashed": False}
            rel_out = f"artifacts/exact_files_meta/{sha256_bytes(p.encode())[:10]}__{safe_name(os.path.basename(p))}.json"
            b.add_text(rel_out, json.dumps(meta_obj, indent=2) + "\n",
                       category="GOVERNED_FILE_INTEGRITY", artifact_type="file_record",
                       collection_class="metadata", success=True, required=False, source_sha256=None,
                       notes="exact_file_capture=true; content_read=false; content_hashed=false", **common)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", required=True)
    ap.add_argument("--root", action="append", default=[])
    ap.add_argument("--models-volume", default="/Volumes/BOSS_AI_MODELS")
    ap.add_argument("--probe-endpoint", action="append", default=[])
    ap.add_argument("--max-depth", type=int, default=8)
    ap.add_argument("--max-files", type=int, default=400)
    ap.add_argument("--max-copy-bytes", type=int, default=262_144)
    ap.add_argument("--max-hash-bytes", type=int, default=67_108_864)
    ap.add_argument("--approved-root", action="append", default=[])
    ap.add_argument("--exact-file", action="append", default=[])
    ap.add_argument("--exact-files-only", action="store_true")
    a = ap.parse_args()

    out = os.path.abspath(a.output)
    if os.path.exists(out) and (not os.path.isdir(out) or os.listdir(out)):
        sys.exit(f"ERROR: output dir exists and is not empty: {out}")

    approved_roots = [os.path.realpath(r) for r in a.approved_root]
    out_real = os.path.realpath(out)
    for ar in approved_roots:
        if not os.path.isdir(ar):
            sys.exit(f"ERROR: --approved-root is not a directory: {ar}")
        if out_real == ar or out_real.startswith(ar.rstrip("/") + "/") or ar.startswith(out_real.rstrip("/") + "/"):
            sys.exit(f"ERROR: output dir must be outside every approved root (read-only contract): {out} vs {ar}")
    validated_exact_files = validate_exact_files(a.exact_file, approved_roots)

    if a.exact_files_only:
        roots, notes = [], ["exact-files-only mode: directory auto-discovery disabled"]
    else:
        roots, notes = discover_roots(a.root, a.models_volume)
    for r in roots:
        if out == r or out.startswith(r.rstrip("/") + "/") or r.startswith(out.rstrip("/") + "/"):
            sys.exit(f"ERROR: output dir must be outside every searched root (read-only contract): {out} vs {r}")
    os.makedirs(out, exist_ok=True)
    b = Bundle(out)
    now = utc()
    host_id = "host-" + sha256_bytes((platform.node() + platform.platform()).encode())[:12]

    scope = {"roots": roots, "discovery_notes": notes, "excluded_dir_names": sorted(EXCLUDED_DIRS),
             "hidden_dirs_pruned": True, "max_depth": a.max_depth, "max_files": a.max_files,
             "max_copy_bytes": a.max_copy_bytes, "max_hash_bytes": a.max_hash_bytes,
             "models_volume": a.models_volume, "models_volume_present": os.path.isdir(a.models_volume),
             "model_payload_extensions_never_read": sorted(MODEL_PAYLOAD_EXT), "truncated": False,
             "approved_roots": approved_roots, "exact_files": validated_exact_files,
             "exact_files_only": a.exact_files_only}
    run_runtime(b)
    probe_endpoints(b, DEFAULT_PROBES + a.probe_endpoint)
    inventory = [] if a.exact_files_only else collect_files(b, roots, a, scope)
    if validated_exact_files:
        collect_exact_files(b, validated_exact_files)
    write_inventory(b, inventory, a.models_volume)
    b.add_text("meta/search_scope.json", json.dumps(scope, indent=2, sort_keys=True) + "\n",
               category="COLLECTION_META", artifact_type="search_scope", collection_class="metadata",
               success=True, required=True, notes="exact discovery scope used")
    b.add_text("meta/host_meta.txt",
               f"host_id={host_id}\nplatform={platform.platform()}\nmachine={platform.machine()}\n"
               f"python={platform.python_version()}\ncollector_version={COLLECTOR_VERSION}\ncollected_utc={now}\n",
               category="COLLECTION_META", artifact_type="host_meta", collection_class="metadata",
               success=True, required=True, notes="hostname is not recorded; host_id is a salted-free hash prefix")
    manifest = {"schema_version": SCHEMA_VERSION, "collector_version": COLLECTOR_VERSION,
                "collection_timestamp": now, "host_id": host_id, "output_root": out,
                "search_scope": scope, "entries": b.entries}
    with open(os.path.join(out, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"BUILD_ENTRIES={len(b.entries)} ROOTS={len(roots)}")


if __name__ == "__main__":
    main()
