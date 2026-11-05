#!/usr/bin/env python3
"""AISA orchestrator: runs inventory + all scanners, then merges candidates into findings.json.

    python run_scans.py --workspace WS                       # normal audit of WS/source
    python run_scans.py --workspace WS --source TREE --out-dir DIR --findings FILE   # re-scan another tree
Scanners only read the source tree; all output goes under the workspace.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCANNERS = ["scan_structure", "scan_patterns", "scan_secrets", "scan_quality", "scan_antislop",
            "check_deps", "trace_api", "detect_duplicates", "scan_tools"]


def run(script: str, extra: list[str]) -> int:
    r = subprocess.run([sys.executable, str(HERE / f"{script}.py"), *extra])
    if r.returncode != 0:
        print(f"WARNING: {script} exited with {r.returncode}; its results are missing and must be listed as a limitation",
              file=sys.stderr)
    return r.returncode


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--source")
    ap.add_argument("--out-dir", help="scan output directory (default: <workspace>/scan)")
    ap.add_argument("--findings", help="merged findings file (default: <workspace>/findings.json)")
    ap.add_argument("--inventory", help="inventory output (default: <workspace>/inventory.json)")
    ap.add_argument("--history", action="store_true", help="pass --history to the secret scanner")
    args = ap.parse_args()
    ws = Path(args.workspace)
    out_dir = Path(args.out_dir) if args.out_dir else ws / "scan"
    out_dir.mkdir(parents=True, exist_ok=True)
    base = ["--workspace", str(ws)] + (["--source", args.source] if args.source else [])
    failed = []
    if run("inventory", base + ["--out", args.inventory or str(ws / "inventory.json")]):
        failed.append("inventory")
    for s in SCANNERS:
        extra = base + ["--out", str(out_dir / f"{s.replace('scan_', '').replace('check_', '')}.json")]
        if s == "scan_secrets" and args.history:
            extra.append("--history")
        if run(s, extra):
            failed.append(s)
    merge = ["--workspace", str(ws), "merge", "--scan-dir", str(out_dir)]
    if args.findings:
        merge += ["--findings", args.findings]
    if args.source:
        merge += ["--source", args.source]
    run("findings", merge)
    if failed:
        print("Scanners that failed (record as limitations):", ", ".join(failed))


if __name__ == "__main__":
    main()
