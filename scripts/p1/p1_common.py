"""Shared constants and redaction helpers for the P1 evidence tooling (stdlib only).

Used by p1_build.py (sanitize while collecting) and verify_preflight_bundle.py
(independent secret scan of the finished bundle). Nothing here executes collected content.
"""
import re

COLLECTOR_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0"
REDACTED = "<REDACTED>"

CATEGORIES = [
    "COLLECTION_META",
    "TOPOLOGY",
    "ROLE_PROVIDER_REFERENCES",
    "ROUTING",
    "CROSS_PROJECT_DEPENDENCIES",
    "MCP_TOOL_SURFACE",
    "GOVERNED_FILE_INTEGRITY",
    "RUNTIME_RESOURCE",
    "PROTECTED_ASSET_INVENTORY",
    "ACCEPTED_PROJECT_EVIDENCE",
]
# Categories that must each hold at least one successful entry before the bundle is
# considered sufficient input for the real P1 analysis (coverage gate, not structure gate).
COVERAGE_REQUIRED = [
    "TOPOLOGY",
    "ROLE_PROVIDER_REFERENCES",
    "ROUTING",
    "MCP_TOOL_SURFACE",
    "GOVERNED_FILE_INTEGRITY",
    "RUNTIME_RESOURCE",
]
ARTIFACT_TYPES = [
    "config", "registry", "manifest", "code", "doc", "launchd_plist", "env_keys",
    "runtime_command", "endpoint_probe", "reference_index", "model_inventory",
    "search_scope", "host_meta", "file_record",
]
SANITIZATION = [
    "clean", "redacted", "names_only", "withheld_secret_material",
    "not_copied_hash_only", "not_copied_never_read", "not_applicable",
]
COLLECTION_CLASSES = [
    "file_copy_sanitized", "file_hash_only", "file_never_read", "grep_references",
    "safe_command", "localhost_get", "metadata",
]

# Directory names never entered during discovery (credentials, browsers, VCS internals, payloads).
EXCLUDED_DIRS = {
    ".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", "Keychains", ".Trash",
    "Safari", "Chrome", "Firefox", "BraveSoftware", "Cookies", ".git", ".hg", ".svn",
    "node_modules", "venv", ".venv", "__pycache__", "site-packages", ".cache",
    "Application Support", "Library", ".config", ".local", "Pictures", "Movies",
    "Music", "Downloads", "Desktop", "Documents", ".npm", ".cargo", ".rustup",
}
# File names/extensions that are never opened (not even hashed).
NEVER_READ_NAME_RE = re.compile(
    r"(^|/)(\.netrc|\.npmrc|\.pypirc|id_(rsa|dsa|ecdsa|ed25519)[^/]*|credentials[^/]*|"
    r"[^/]*\.(pem|key|p12|pfx|keychain|keychain-db|kdbx|jks|cer|crt|gpg|asc))$",
    re.IGNORECASE,
)
ENV_FILE_RE = re.compile(r"(^|/)\.env(\.[^/]*)?$|(^|/)[^/]*\.env$", re.IGNORECASE)
MODEL_PAYLOAD_EXT = {".gguf", ".safetensors", ".bin", ".pt", ".pth", ".onnx", ".mlmodel",
                     ".npz", ".ckpt", ".mlpackage"}

_KEY = (r"(?:api[_-]?key|apikey|secret|token|passw(?:or)?d|pwd|authorization|credential|"
        r"private[_-]?key|cookie|session[_-]?id|access[_-]?key|client[_-]?secret)")
# key = value / "key": "value" with a secret-like key name. Group 3 is the value.
ASSIGN_RE = re.compile(
    r"(?i)([\"']?[\w.\-]*" + _KEY + r"[\w.\-]*[\"']?\s*[:=]\s*)([\"']?)([^\s\"',;}#]+)")
# Keys that merely contain "token" but are numeric limits (context profile evidence: keep).
BENIGN_KEY_RE = re.compile(
    r"(?i)(max|num|n|total|prompt|completion|context|ctx)[_-]?tokens?|tokens?[_-]?(count|limit|budget|per)")
TOKEN_SHAPES = [
    ("private_key_block", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("openai_style_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}")),
    ("nvidia_api_key", re.compile(r"\bnvapi-[A-Za-z0-9_-]{20,}")),
    ("huggingface_token", re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
    ("bearer_or_basic_credential", re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}")),
    ("url_userinfo_password", re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:[^/\s@]+@")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
]
PLIST_ENV_BLOCK_RE = re.compile(
    r"(<key>EnvironmentVariables</key>\s*<dict>)(.*?)(</dict>)", re.DOTALL)
PLIST_STRING_RE = re.compile(r"(<string>)(.*?)(</string>)", re.DOTALL)


def _assign_sub(m):
    key, quote, value = m.group(1), m.group(2), m.group(3)
    if value.startswith("<REDACTED"):
        return m.group(0)
    if BENIGN_KEY_RE.search(key) and re.fullmatch(r"[0-9._-]+|true|false|null|none", value, re.I):
        return m.group(0)
    return f"{key}{quote}{REDACTED}"


def redact_text(text):
    """Return (sanitized_text, changed). Values are replaced, key names are kept."""
    original = text
    text = PLIST_ENV_BLOCK_RE.sub(
        lambda m: m.group(1) + PLIST_STRING_RE.sub(r"\1" + REDACTED + r"\3", m.group(2)) + m.group(3),
        text)
    for name, rx in TOKEN_SHAPES:
        if name == "private_key_block":
            continue  # handled by withholding the whole file
        if name == "url_userinfo_password":
            text = rx.sub(lambda m: m.group(0).split("://")[0] + "://" + REDACTED + "@", text)
        elif name == "bearer_or_basic_credential":
            text = rx.sub(lambda m: m.group(0).split()[0] + " " + REDACTED, text)
        else:
            text = rx.sub(REDACTED, text)
    text = ASSIGN_RE.sub(_assign_sub, text)
    return text, text != original


def has_private_key_block(text):
    return TOKEN_SHAPES[0][1].search(text) is not None


def scan_text_for_secrets(text):
    """Independent detector used on the finished bundle. Returns [(line_no, rule_name)]; never values."""
    hits = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for name, rx in TOKEN_SHAPES:
            m = rx.search(line)
            if not m:
                continue
            if name in ("bearer_or_basic_credential", "url_userinfo_password") and REDACTED in line[m.start():m.end() + 12]:
                continue
            hits.append((lineno, name))
        for m in ASSIGN_RE.finditer(line):
            value = m.group(3)
            if value.startswith("<REDACTED"):
                continue
            if BENIGN_KEY_RE.search(m.group(1)) and re.fullmatch(r"[0-9._-]+|true|false|null|none", value, re.I):
                continue
            hits.append((lineno, "secret_named_assignment_with_value"))
            break
    return hits
