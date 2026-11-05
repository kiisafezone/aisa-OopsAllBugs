#!/usr/bin/env python3
"""AISA external-tool bridge: runs bandit / semgrep / ruff when installed and normalises their JSON.

Findings from these tools are method 'tool-reported' (Potential) until reviewed. Missing tools are recorded
in the scan metadata so the report can state exactly what was and was not used.
Parsers follow each tool's documented JSON schema; verify on first use with a real installation.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from aisa_common import candidate, resolve_paths, run_tool, scanner_parser, write_scan

SEV = {"HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "ERROR": "High", "WARNING": "Medium", "INFO": "Low",
       "CRITICAL": "Critical"}


def rel(path: str, source: Path) -> str:
    try:
        return Path(path).resolve().relative_to(source.resolve()).as_posix()
    except ValueError:
        return path.lstrip("./")


def parse_bandit(data: dict, source: Path):
    out = []
    for r in data.get("results", []):
        cwe = (r.get("issue_cwe") or {}).get("id")
        out.append(candidate(f"BANDIT-{r.get('test_id')}", "SEC", SEV.get(str(r.get("issue_severity")).upper(), "Medium"),
                             f"bandit: {r.get('issue_text', r.get('test_name'))}", file=rel(r.get("filename", ""), source),
                             line=r.get("line_number"), evidence=(r.get("code") or "").strip()[:240],
                             explanation=f"bandit test {r.get('test_name')} (confidence {r.get('issue_confidence')}).",
                             impact="See bandit documentation for the test id.", recommendation="Review and remediate per bandit guidance.",
                             cwe=f"CWE-{cwe}" if cwe else None, tool="bandit", method="tool-reported"))
    return out


def parse_semgrep(data: dict, source: Path):
    out = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        cwe = extra.get("metadata", {}).get("cwe")
        cwe = cwe[0] if isinstance(cwe, list) and cwe else cwe
        out.append(candidate(f"SEMGREP-{r.get('check_id', 'rule').split('.')[-1]}", "SEC",
                             SEV.get(str(extra.get("severity")).upper(), "Medium"), f"semgrep: {extra.get('message', '')[:160]}",
                             file=rel(r.get("path", ""), source), line=(r.get("start") or {}).get("line"),
                             evidence=(extra.get("lines") or "").strip()[:240], explanation=extra.get("message", "")[:400],
                             impact="See rule documentation.", recommendation="Review and remediate per rule guidance.",
                             cwe=str(cwe)[:40] if cwe else None, tool="semgrep", method="tool-reported"))
    return out


def parse_ruff(data: list, source: Path):
    out = []
    for r in data:
        code = r.get("code") or "ruff"
        sev = "High" if code in {"F821", "E902", "F811"} or code.startswith("E9") else "Medium"
        out.append(candidate(f"RUFF-{code}", "LOG", sev, f"ruff {code}: {r.get('message', '')[:160]}",
                             file=rel(r.get("filename", ""), source), line=(r.get("location") or {}).get("row"),
                             explanation=r.get("message", ""), impact="Likely runtime error (undefined name, syntax error, redefinition).",
                             recommendation="Fix per ruff message.", tool="ruff", method="tool-reported"))
    return out


def main() -> None:
    args = scanner_parser("External analyzers").parse_args()
    ws, src, out = resolve_paths(args, "tools")
    tools, cands = {}, []
    specs = [
        ("bandit", ["bandit", "-r", str(src), "-f", "json", "-q", "--exit-zero"], parse_bandit),
        ("semgrep", ["semgrep", "scan", "--config", "auto", "--json", "--metrics", "off", "--disable-version-check", str(src)], parse_semgrep),
        ("ruff", ["ruff", "check", str(src), "--select", "F821,F811,E9", "--output-format", "json", "--exit-zero", "--no-cache"], parse_ruff),
    ]
    for name, cmd, parser in specs:
        if not shutil.which(name):
            tools[name] = "not installed"
            continue
        rc, so, se = run_tool(cmd, timeout=900)
        if rc is None:
            tools[name] = f"failed: {se[:160]}"
            continue
        try:
            data = json.loads(so or ("[]" if name == "ruff" else "{}"))
        except json.JSONDecodeError:
            tools[name] = f"failed: unparsable output (exit {rc}) {se[:120]}"
            continue
        found = parser(data, src)
        cands += found
        tools[name] = f"used ({len(found)} result(s))"
        if name == "semgrep" and data.get("errors"):
            tools[name] += f"; {len(data['errors'])} engine error(s), rules may not have loaded (offline?)"
    limitations = [f"{n} was not run ({s})" for n, s in tools.items() if not s.startswith("used")]
    write_scan(out, "tools", cands, tools=tools, limitations=limitations)


if __name__ == "__main__":
    main()
