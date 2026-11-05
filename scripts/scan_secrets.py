#!/usr/bin/env python3
"""AISA secret scanner. Built-in regexes always run; gitleaks is added when installed.

Real secret values are NEVER written to any output: evidence is masked.
"""
from __future__ import annotations

import json
import re
import shutil
import tempfile
from pathlib import Path

from aisa_common import (candidate, downgrade, is_doc_path, is_example_path, is_noise_file, is_test_path,
                         iter_files, line_of, mask_secret, read_text, resolve_paths, run_tool, scanner_parser,
                         write_scan, read_text as _rt)

PROVIDER = [
    ("AWS access key ID", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", "High"),
    ("Private key block", r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----", "Critical"),
    ("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "Critical"),
    ("Slack token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "High"),
    ("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "High"),
    ("Stripe live secret key", r"\bsk_live_[0-9a-zA-Z]{20,}\b", "Critical"),
    ("JSON Web Token", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "Medium"),
]
GENERIC = re.compile(
    r"(?i)[A-Za-z0-9_]*(password|passwd|pwd|secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token|client[_-]?secret|"
    r"private[_-]?key)[A-Za-z0-9_]*[\"']?\s*[:=]\s*[\"']([^\"'\s]{6,})[\"']")
ENV_LINE = re.compile(r"(?im)^\s*(?:export\s+)?[A-Z0-9_]*(PASSWORD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY)[A-Z0-9_]*\s*=\s*([^\s#\"']{6,})")
DSN = re.compile(r"(?i)\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/\"']+:([^\s@/\"']+)@")
PLACEHOLDER = re.compile(
    r"(?i)(your[_-]|example|changeme|change[_-]me|xxxx|\*{3,}|<[^>]+>|\$\{|\{\{|process\.env|os\.environ|getenv|"
    r"placeholder|todo|insert|replace|^env|^none$|^null$|^true$|^false$|\.\.\.)")


def is_placeholder(value: str) -> bool:
    return bool(PLACEHOLDER.search(value))


def mask_line(line: str, secret: str) -> str:
    return line.replace(secret, mask_secret(secret)).strip()[:240]


def scan_builtin(source: Path):
    out, seen = [], set()
    for p, rel in iter_files(source):
        if is_noise_file(rel):
            continue
        text = read_text(p)
        if text is None:
            continue
        lines = text.split("\n")
        weak_ctx = is_test_path(rel) or is_example_path(rel) or is_doc_path(rel)
        def add(rule, title, sev, value, idx, extra=""):
            ln = line_of(text, idx)
            if (rel, ln) in seen:
                return
            seen.add((rel, ln))
            sev2 = downgrade(downgrade(sev)) if weak_ctx else sev
            out.append(candidate(
                rule, "SEC", sev2, f"Hard-coded secret: {title}", file=rel, line=ln,
                evidence=mask_line(lines[ln - 1], value) + (f" {extra}" if extra else ""), masked=True,
                explanation="A credential-like value is committed in source.",
                impact="Anyone with repository access (or the shipped artifact) can use the credential; "
                       "it also remains in version-control history after removal.",
                recommendation="Revoke/rotate the credential, load it from the environment or a secret manager, "
                               "and purge it from history if the repository is shared.",
                cwe="CWE-798"))
        for title, pat, sev in PROVIDER:
            for m in re.finditer(pat, text):
                add("SECRET-PROVIDER", title, sev, m.group(0), m.start())
        for m in GENERIC.finditer(text):
            if not is_placeholder(m.group(2)):
                add("SECRET-GENERIC", f"value assigned to '{m.group(1)}'", "Medium", m.group(2), m.start())
        if rel.rsplit("/", 1)[-1].startswith(".env"):
            for m in ENV_LINE.finditer(text):
                if not is_placeholder(m.group(2)):
                    add("SECRET-GENERIC", f"value assigned to a '{m.group(1).lower()}' variable", "Medium", m.group(2), m.start())
        for m in DSN.finditer(text):
            if not is_placeholder(m.group(2)):
                add("SECRET-DSN", f"password inside {m.group(1)}:// connection string", "High", m.group(2), m.start())
    return out


def env_file_checks(source: Path):
    out = []
    gitignore = read_text(source / ".gitignore") or ""
    ignored = bool(re.search(r"^\s*\.env\b", gitignore, re.M))
    for p, rel in iter_files(source):
        name = rel.rsplit("/", 1)[-1]
        if re.match(r"^\.env(\..+)?$", name) and not re.search(r"(example|sample|template|dist)$", name):
            out.append(candidate(
                "ENV-COMMITTED", "SEC", "Low" if ignored else "Medium",
                "Environment file present in the project snapshot", file=rel,
                evidence=f"{rel} present; .gitignore {'lists' if ignored else 'does not list'} .env",
                explanation="Environment files usually hold real credentials.",
                impact="Secrets may be distributed with the code.",
                recommendation="Remove from version control, add to .gitignore, keep a .env.example with dummy values.",
                cwe="CWE-538", method="inventory", status="Confirmed" if not ignored else "Potential"))
    return out


def run_gitleaks(source: Path, history: bool):
    exe = shutil.which("gitleaks")
    if not exe:
        return [], "not installed"
    with tempfile.TemporaryDirectory() as td:
        report = Path(td) / "gl.json"
        cmd = [exe, "detect", "--source", str(source), "--report-format", "json", "--report-path", str(report),
               "--no-banner", "--exit-code", "0"]
        if not (history and (source / ".git").exists()):
            cmd.append("--no-git")
        rc, _, err = run_tool(cmd, timeout=600)
        if rc is None or not report.exists():
            return [], f"failed: {err[:200]}"
        try:
            data = json.loads(report.read_text() or "[]") or []
        except json.JSONDecodeError:
            return [], "failed: unreadable report"
    out = []
    for d in data:
        f = d.get("File", "")
        try:
            f = str(Path(f).resolve().relative_to(source.resolve())) if f else f
        except ValueError:
            pass
        sec = d.get("Secret", "")
        out.append(candidate(
            f"GITLEAKS-{d.get('RuleID', 'rule')}", "SEC", "High", f"Hard-coded secret: {d.get('Description', 'secret')}",
            file=f, line=d.get("StartLine"), evidence=f"gitleaks rule {d.get('RuleID')} matched; value masked ({mask_secret(sec)})",
            masked=True, explanation="gitleaks matched a credential pattern.",
            impact="Credential exposure.", recommendation="Rotate and move to a secret manager.", cwe="CWE-798",
            tool="gitleaks", method="tool-reported"))
    return out, "used (history scanned)" if history and (source / ".git").exists() else "used (working tree only)"


def main() -> None:
    ap = scanner_parser("Secret scan")
    ap.add_argument("--history", action="store_true", help="also scan git history (needs gitleaks and a .git directory)")
    args = ap.parse_args()
    ws, src, out = resolve_paths(args, "secrets")
    cands = scan_builtin(src) + env_file_checks(src)
    gl, status = run_gitleaks(src, args.history)
    keys = {(c["locations"][0]["file"], c["locations"][0].get("line")) for c in cands if c["locations"]}
    cands += [c for c in gl if not c["locations"] or (c["locations"][0]["file"], c["locations"][0].get("line")) not in keys]
    note = []
    if not args.history:
        note.append("git history not scanned (use --history with gitleaks and a full clone)")
    write_scan(out, "secrets", cands, tools={"builtin-regex": "used", "gitleaks": status}, limitations=note)


if __name__ == "__main__":
    main()
