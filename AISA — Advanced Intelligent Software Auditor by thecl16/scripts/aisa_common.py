#!/usr/bin/env python3
"""Shared helpers for AISA scripts. Standard library only.

Everything here is deliberately boring: file walking, JSON I/O, path
classification, and the candidate-finding constructor that every scanner uses.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "1.0"

DOMAINS = {
    "STR": "Structure & Project Completeness",
    "ARC": "Architecture & System Design",
    "QUA": "Code Quality",
    "LOG": "Logic & Functionality",
    "SEC": "Security",
    "DAT": "Database & Data Integrity",
    "API": "API & Communication",
    "UIX": "Frontend & UI/UX",
    "BIZ": "Backend & Business Logic",
    "INT": "External Integration & Dependencies",
    "PRF": "Performance & Optimization",
    "TST": "Testing & Reliability",
    "OPS": "DevOps & Deployment",
    "DOC": "Documentation & Standards",
    "CMP": "Compliance & Privacy",
    "SLP": "Anti-Slop Audit",
}
SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}
STATUSES = ["Confirmed", "Potential", "Unverified", "Not Applicable"]

# Verification methods and whether they may justify the status "Confirmed".
# A regex hit alone is a lead, never a proof.
CONFIRMING_METHODS = {
    "manual-code-read",   # Claude opened the file and read the surrounding code
    "executed-test",      # a test/command was actually run and produced the result
    "executed-runtime",   # behaviour was observed at runtime in the sandbox
    "static-ast",         # deterministic structural fact from parsing the code
    "inventory",          # deterministic fact about files present/absent
    "tool-confirmed",     # an external analyzer reported it AND it was reviewed
    "config-inspection",  # configuration read and interpreted directly
}
ALL_METHODS = CONFIRMING_METHODS | {"static-pattern", "tool-reported", "documentation-review", "not-verified"}

IGNORE_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "dist", "build", ".next", ".nuxt", "target", "vendor",
    ".idea", ".vscode", ".dart_tool", ".gradle", "Pods", "coverage", ".cache",
    ".terraform", "bower_components", "site-packages", ".eggs",
}

LANG_BY_EXT = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript",
    ".cjs": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript", ".dart": "Dart",
    ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin", ".go": "Go", ".rs": "Rust",
    ".rb": "Ruby", ".php": "PHP", ".cs": "C#", ".c": "C", ".h": "C", ".cpp": "C++",
    ".hpp": "C++", ".cc": "C++", ".swift": "Swift", ".sh": "Shell", ".bash": "Shell",
    ".sql": "SQL", ".vue": "Vue", ".svelte": "Svelte", ".html": "HTML", ".htm": "HTML",
    ".css": "CSS", ".scss": "CSS", ".less": "CSS", ".yml": "YAML", ".yaml": "YAML",
    ".json": "JSON", ".toml": "TOML", ".md": "Markdown", ".rst": "reStructuredText",
    ".tf": "Terraform", ".gradle": "Gradle", ".xml": "XML", ".ini": "INI", ".cfg": "INI",
    ".env": "Env",
}
CODE_LANGS = {
    "Python", "JavaScript", "TypeScript", "Dart", "Java", "Kotlin", "Go", "Rust", "Ruby",
    "PHP", "C#", "C", "C++", "Swift", "Shell", "SQL", "Vue", "Svelte",
}
LOCKFILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock",
    "composer.lock", "Cargo.lock", "go.sum", "pubspec.lock", "Gemfile.lock",
}
MAX_TEXT_BYTES = 1_500_000


# ----------------------------------------------------------------------------- JSON

def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_json(path, default=None):
    p = Path(path)
    if not p.exists():
        return default
    with p.open(encoding="utf-8") as f:
        return json.load(f)


def save_json(path, data) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp, p)


def die(message: str, code: int = 2) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(code)


# ----------------------------------------------------------------------------- files

def language_of(rel: str) -> str | None:
    name = rel.rsplit("/", 1)[-1]
    if name == "Dockerfile" or name.startswith("Dockerfile."):
        return "Dockerfile"
    if name == "Makefile":
        return "Makefile"
    return LANG_BY_EXT.get(Path(name).suffix.lower())


def iter_files(root, ignore: bool = True, skipped: list | None = None):
    """Yield (absolute Path, posix relative path). Never follows symlinks, never enters .git."""
    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dp = Path(dirpath)
        keep = []
        for d in sorted(dirnames):
            full = dp / d
            if d == ".git" or full.is_symlink():
                continue
            if ignore and (d in IGNORE_DIRS or (full / "pyvenv.cfg").exists()):
                if skipped is not None:
                    skipped.append(full.relative_to(root).as_posix())
                continue
            keep.append(d)
        dirnames[:] = keep
        for fn in sorted(filenames):
            p = dp / fn
            if p.is_symlink():
                continue
            yield p, p.relative_to(root).as_posix()


def read_text(path, limit: int = MAX_TEXT_BYTES):
    """Return decoded text, or None for binary / oversized / unreadable files."""
    try:
        if os.path.getsize(path) > limit:
            return None
        data = Path(path).read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def is_noise_file(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1]
    return name in LOCKFILES or name.endswith((".min.js", ".min.css", ".map", ".svg"))


TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "e2e", "fixtures", "__mocks__", "cypress", "testing"}


def is_test_path(rel: str) -> bool:
    parts = rel.lower().split("/")
    if any(p in TEST_DIRS for p in parts[:-1]):
        return True
    return bool(re.match(r"(test_.*|.*_test\.\w+|.*\.test\.\w+|.*\.spec\.\w+|conftest\.py)$", parts[-1]))


def is_doc_path(rel: str) -> bool:
    low = rel.lower()
    return low.endswith((".md", ".rst", ".txt", ".adoc")) or low.startswith(("docs/", "doc/"))


def is_example_path(rel: str) -> bool:
    return bool(re.search(r"(example|sample|template|\.dist$|\.sample$)", rel.rsplit("/", 1)[-1].lower()))


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def tree_hash(root) -> tuple[str, int]:
    """Deterministic SHA-256 over every file (ignoring .git). Used to prove read-only audits."""
    h = hashlib.sha256()
    count = 0
    for p, rel in iter_files(root, ignore=False):
        fh = hashlib.sha256()
        try:
            with open(p, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    fh.update(chunk)
        except OSError:
            continue
        h.update(rel.encode("utf-8") + b"\0" + fh.digest())
        count += 1
    return h.hexdigest(), count


def make_writable(root) -> None:
    root = str(root)
    for dp, dn, fn in os.walk(root):
        for n in dn + fn:
            p = os.path.join(dp, n)
            if not os.path.islink(p):
                try:
                    os.chmod(p, os.stat(p).st_mode | stat.S_IWUSR)
                except OSError:
                    pass
    try:
        os.chmod(root, os.stat(root).st_mode | stat.S_IWUSR)
    except OSError:
        pass


def make_readonly(root) -> None:
    mask = ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
    for dp, dn, fn in os.walk(str(root)):
        for n in dn + fn:
            p = os.path.join(dp, n)
            if not os.path.islink(p):
                try:
                    os.chmod(p, os.stat(p).st_mode & mask)
                except OSError:
                    pass


def copy_tree_writable(src, dst, skip_git: bool = False) -> None:
    ignore = shutil.ignore_patterns(".git") if skip_git else None
    shutil.copytree(src, dst, symlinks=True, ignore=ignore)
    make_writable(dst)


def rmtree_force(path) -> None:
    if Path(path).exists():
        make_writable(path)
        shutil.rmtree(path, ignore_errors=True)


def run_tool(cmd: list[str], timeout: int = 300, cwd=None):
    """Run an external tool. Returns (returncode, stdout, stderr); returncode None on timeout/failure to start."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return None, "", f"timeout after {timeout}s"
    except OSError as exc:
        return None, "", str(exc)


# ----------------------------------------------------------------------------- findings

def mask_secret(value: str) -> str:
    """Never let a real secret reach a report."""
    if len(value) <= 8:
        return "****"
    return f"{value[:3]}…[{len(value)} chars masked]"


def downgrade(severity: str) -> str:
    i = SEVERITY_ORDER[severity]
    return SEVERITIES[min(i + 1, len(SEVERITIES) - 1)]


def candidate(rule_id, domain, severity, title, file=None, line=None, evidence="",
              explanation="", impact="", recommendation="", cwe=None, status="Potential",
              tool="aisa-builtin", method="static-pattern", locations=None, masked=False,
              verbatim=False):
    """Build a raw scanner candidate. `findings.py merge` turns candidates into findings."""
    if locations is None:
        locations = []
        if file:
            loc = {"file": file}
            if line:
                loc["line"] = int(line)
            locations.append(loc)
    return {
        "rule_id": rule_id, "domain": domain, "severity": severity, "status": status,
        "title": title, "locations": locations, "evidence": evidence,
        "explanation": explanation, "impact": impact, "recommendation": recommendation,
        "references": [cwe] if cwe else [], "tool": tool, "method": method, "masked": masked,
        "verbatim": verbatim,
    }


# ----------------------------------------------------------------------------- CLI

def scanner_parser(description: str) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=description)
    p.add_argument("--workspace", required=True, help="AISA workspace directory")
    p.add_argument("--source", help="Source tree to scan (default: <workspace>/source)")
    p.add_argument("--out", help="Output JSON (default: <workspace>/scan/<name>.json)")
    return p


def resolve_paths(args, name: str):
    ws = Path(args.workspace)
    src = Path(args.source) if args.source else ws / "source"
    out = Path(args.out) if args.out else ws / "scan" / f"{name}.json"
    if not src.is_dir():
        die(f"source directory not found: {src}")
    return ws, src, out


def write_scan(out, scanner: str, candidates: list, **meta) -> None:
    save_json(out, {
        "schema_version": SCHEMA_VERSION, "scanner": scanner, "generated_at": now_iso(),
        **meta, "candidates": candidates,
    })
    by_sev: dict[str, int] = {}
    for c in candidates:
        by_sev[c["severity"]] = by_sev.get(c["severity"], 0) + 1
    summary = ", ".join(f"{k}={v}" for k, v in sorted(by_sev.items(), key=lambda kv: SEVERITY_ORDER[kv[0]]))
    print(f"[{scanner}] {len(candidates)} candidate(s) -> {out}" + (f"  ({summary})" if summary else ""))
