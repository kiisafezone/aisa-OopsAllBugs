#!/usr/bin/env python3
"""AISA sandbox runner: execute tests/builds on a THROWAWAY COPY of the source, never on the snapshot.

    sandbox_run.py --workspace WS --detect
    sandbox_run.py --workspace WS --label baseline --kind syntax          # safe: compiles, never executes project code
    sandbox_run.py --workspace WS --label tests --command "python -m pytest -x -q"
    sandbox_run.py --workspace WS --label tests --overlay WS/verification --command "python -m pytest verification -q"
    sandbox_run.py ... --install-command "python -m venv .venv" --install-command ".venv/bin/pip install -r requirements.txt" --allow-install

Safety model (best effort - this is NOT a VM; recommend a container for untrusted code):
  * runs in a temp copy; the audited snapshot is untouched
  * minimal environment (no inherited secrets), HOME/TMPDIR inside the temp dir
  * network isolation via `unshare -rn` when available; otherwise refuses unless --accept-no-isolation
  * CPU / file-size / open-file limits, hard wall-clock timeout, whole process group killed on timeout
  * refuses commands (and package.json test scripts) matching destructive/exfiltrating patterns
  * dependency installation only with --allow-install (network allowed ONLY for that phase)
Every run is logged to <workspace>/runs/<label>.json (verdict: executed | refused).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import resource
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from aisa_common import SCHEMA_VERSION, copy_tree_writable, die, load_json, now_iso, read_text, rmtree_force, save_json

DANGER = [
    (r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+(/|~|\$HOME|\*)(\s|$)", "recursive delete of root/home"),
    (r"(curl|wget)[^|;\n]*\|\s*(sudo\s+)?(ba|z)?sh", "pipes a download into a shell"),
    (r"\bsudo\b", "uses sudo"), (r"\bmkfs\b|\bdd\s+if=", "disk-level operation"), (r":\(\)\s*\{", "fork bomb"),
    (r"\b(ssh|scp|sftp|nc|ncat|netcat|socat)\b", "network/remote shell tool"),
    (r"base64\s+(-d|--decode)[^|\n]*\|\s*(ba)?sh", "decodes and executes a payload"),
    (r"\bchmod\s+-R\s+777\s+/", "recursive chmod on root"), (r">\s*/dev/sd", "writes to a block device"),
    (r"\bgit\s+push\b", "pushes to a remote"), (r"\bdocker\s+(run|push|login)\b", "controls Docker/registries"),
]


def danger_check(text: str) -> list[str]:
    return [why for pat, why in DANGER if re.search(pat, text)]


def detect(source: Path) -> list[dict]:
    cmds = []
    py_files = list(source.rglob("*.py"))
    if py_files:
        cmds.append({"kind": "syntax", "ecosystem": "python", "command": "python3 -m compileall -q .",
                     "risk": "safe (compiles only, does not execute project code)"})
        req = " ".join((read_text(p) or "") for p in source.rglob("requirements*.txt")) + (read_text(source / "pyproject.toml") or "")
        tests_exist = any(re.match(r"(test_.*|.*_test)\.py$", p.name) or "tests" in p.parts for p in py_files)
        if tests_exist:
            runner = "python3 -m pytest -x -q" if "pytest" in req.lower() or (source / "pytest.ini").exists() else "python3 -m unittest discover -v"
            cmds.append({"kind": "test", "ecosystem": "python", "command": runner, "risk": "executes project test code"})
    pj = source / "package.json"
    if pj.exists():
        try:
            scripts = json.loads(read_text(pj) or "{}").get("scripts", {})
        except json.JSONDecodeError:
            scripts = {}
        for name, kind in (("test", "test"), ("build", "build"), ("lint", "lint")):
            if name in scripts:
                why = danger_check(" ".join(scripts.get(k, "") for k in (f"pre{name}", name, f"post{name}")))
                cmds.append({"kind": kind, "ecosystem": "node", "command": f"npm run {name}" if name != "test" else "npm test",
                             "risk": "executes package.json scripts" + (f"; DANGEROUS: {', '.join(why)}" if why else ""),
                             "needs": "node_modules (run --install-command 'npm ci --ignore-scripts' with --allow-install)"})
    if (source / "go.mod").exists():
        cmds.append({"kind": "test", "ecosystem": "go", "command": "go test ./...", "risk": "executes project test code"})
    if (source / "Cargo.toml").exists():
        cmds.append({"kind": "test", "ecosystem": "rust", "command": "cargo test --offline", "risk": "executes build scripts + tests"})
    if (source / "pubspec.yaml").exists():
        cmds.append({"kind": "test", "ecosystem": "flutter", "command": "flutter test", "risk": "executes project test code"})
    return cmds


def isolation_prefix() -> tuple[list[str], str]:
    exe = shutil.which("unshare")
    if exe:
        try:
            r = subprocess.run([exe, "-rn", "true"], capture_output=True, timeout=10)
            if r.returncode == 0:
                return [exe, "-rn", "--"], "network-namespace (unshare -rn)"
        except (OSError, subprocess.TimeoutExpired):
            pass
    return [], "none"


def limits(cpu: int):
    def apply():
        os.setsid()
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        resource.setrlimit(resource.RLIMIT_FSIZE, (200 << 20, 200 << 20))
        resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    return apply


def clean_env(tmp: Path, extra: dict) -> dict:
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(tmp / "home"), "TMPDIR": str(tmp / "tmp"),
           "LANG": "C.UTF-8", "CI": "1", "PYTHONDONTWRITEBYTECODE": "1", "NO_COLOR": "1",
           "HTTP_PROXY": "http://127.0.0.1:9", "HTTPS_PROXY": "http://127.0.0.1:9", "NO_PROXY": "localhost,127.0.0.1"}
    env.update(extra)
    return env


def execute(cmd: list[str], cwd: Path, env: dict, timeout: int, prefix: list[str]):
    start = time.time()
    try:
        proc = subprocess.Popen(prefix + cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                preexec_fn=limits(timeout + 15))
    except OSError as exc:
        return {"exit_code": None, "timed_out": False, "output_tail": f"could not start: {exc}", "seconds": 0.0}
    try:
        out, _ = proc.communicate(timeout=timeout)
        timed_out = False
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        out, _ = proc.communicate()
        timed_out = True
    lines = (out or "").splitlines()
    return {"exit_code": proc.returncode, "timed_out": timed_out, "seconds": round(time.time() - start, 2),
            "output_tail": "\n".join(lines[-80:])[-6000:], "output_lines": len(lines)}


def parse_counts(output: str) -> dict:
    counts = {}
    for key, rx in (("passed", r"(\d+) passed"), ("failed", r"(\d+) failed"), ("errors", r"(\d+) errors?"),
                    ("skipped", r"(\d+) skipped")):
        m = re.search(rx, output)
        if m:
            counts[key] = int(m.group(1))
    m = re.search(r"Ran (\d+) tests?", output)
    if m:
        counts["ran"] = int(m.group(1))
        counts["failed"] = counts.get("failed", 0) + (int(f.group(1)) if (f := re.search(r"failures=(\d+)", output)) else 0)
    m = re.search(r"Tests:\s+(?:(\d+) failed, )?(?:\d+ skipped, )?(\d+) passed", output)
    if m:
        counts["passed"], counts["failed"] = int(m.group(2)), int(m.group(1) or 0)
    return counts


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--source")
    ap.add_argument("--detect", action="store_true")
    ap.add_argument("--label", default="run")
    ap.add_argument("--kind", choices=["syntax"], help="shortcut for the safe syntax-only check")
    ap.add_argument("--command")
    ap.add_argument("--install-command", action="append", default=[])
    ap.add_argument("--allow-install", action="store_true")
    ap.add_argument("--overlay", help="directory copied into the temp copy (Claude's own verification tests)")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--env", action="append", default=[], help="KEY=VALUE passed into the sandbox")
    ap.add_argument("--accept-no-isolation", action="store_true",
                    help="run even though no network isolation is available (needs the user's explicit consent)")
    ap.add_argument("--out")
    args = ap.parse_args()

    ws = Path(args.workspace)
    src = Path(args.source) if args.source else ws / "source"
    if not src.is_dir():
        die(f"source not found: {src}")
    if args.detect:
        found = detect(src)
        print(json.dumps(found, indent=2))
        prefix, iso = isolation_prefix()
        print(f"network isolation available: {iso}")
        return
    command = "python3 -m compileall -q ." if args.kind == "syntax" else args.command
    if not command:
        die("give --command, --kind syntax, or --detect")
    out_path = Path(args.out) if args.out else ws / "runs" / f"{args.label}.json"
    record = {"schema_version": SCHEMA_VERSION, "label": args.label, "command": command, "started_at": now_iso(),
              "source": str(src), "install_commands": args.install_command}

    def refuse(reason: str):
        record.update({"verdict": "refused", "reason": reason})
        save_json(out_path, record)
        print(f"REFUSED: {reason}\n -> {out_path}")
        sys.exit(3)

    problems = danger_check(command + " " + " ".join(args.install_command))
    if problems:
        refuse("command matches dangerous patterns: " + ", ".join(problems))
    pj = src / "package.json"
    if pj.exists() and re.match(r"(npm|yarn|pnpm)\b", command):
        try:
            scripts = json.loads(read_text(pj) or "{}").get("scripts", {})
        except json.JSONDecodeError:
            scripts = {}
        bad = danger_check(" ".join(str(v) for v in scripts.values()))
        if bad:
            refuse("package.json scripts match dangerous patterns: " + ", ".join(bad))
    if args.install_command and not args.allow_install:
        refuse("--install-command needs --allow-install (the user must approve running dependency installers)")
    is_safe_syntax = args.kind == "syntax"
    prefix, iso = isolation_prefix()
    if not is_safe_syntax and iso == "none" and not args.accept_no_isolation:
        refuse("no network isolation is available on this machine; ask the user whether to proceed with --accept-no-isolation, "
               "or mark the dependent features Unverified")
    env_extra = dict(kv.split("=", 1) for kv in args.env if "=" in kv)
    tmp = Path(tempfile.mkdtemp(prefix="aisa-sbx-"))
    try:
        work = tmp / "work"
        copy_tree_writable(src, work)
        (tmp / "home").mkdir()
        (tmp / "tmp").mkdir()
        if args.overlay:
            ov = Path(args.overlay)
            if not ov.is_dir():
                refuse(f"overlay directory not found: {ov}")
            shutil.copytree(ov, work / ov.name, dirs_exist_ok=True)
        env = clean_env(tmp, env_extra)
        installs = []
        for ic in args.install_command:
            installs.append({"command": ic, **execute(shlex.split(ic), work, {**env, "HTTP_PROXY": "", "HTTPS_PROXY": ""},
                                                      args.timeout, [])})
        parts = shlex.split(command)
        venv_py = work / ".venv" / "bin" / "python"
        if parts and parts[0] in {"python", "python3"} and venv_py.exists():
            parts[0] = str(venv_py)
        result = execute(parts, work, env, args.timeout, [] if is_safe_syntax else prefix)
        record.update({"verdict": "executed", "isolation": "n/a (compile-only)" if is_safe_syntax else iso, "installs": installs, **result,
                       "counts": parse_counts(result["output_tail"]), "finished_at": now_iso(),
                       "sandbox_note": "best-effort sandbox on a temporary copy; not a VM"})
    finally:
        rmtree_force(tmp)
    save_json(out_path, record)
    print(f"[sandbox] {args.label}: exit={record['exit_code']} timed_out={record['timed_out']} counts={record['counts']} "
          f"isolation={record['isolation']} -> {out_path}")
    sys.exit(0)


if __name__ == "__main__":
    main()
