#!/usr/bin/env python3
"""AISA intake: put exactly ONE project into <workspace>/source as a read-only snapshot.

Sources: --github URL | --zip FILE | --path DIR_OR_FILE (repeatable).
The snapshot is chmod'ed read-only and its tree hash is recorded in session.json so that
verify_readonly.py can prove later that the audit never modified the code.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

from aisa_common import (SCHEMA_VERSION, die, iter_files, load_json, make_readonly, make_writable,
                         now_iso, save_json, tree_hash, copy_tree_writable)

MAX_ZIP_BYTES = 1 << 30      # 1 GiB uncompressed
MAX_ZIP_FILES = 200_000
GITHUB_RE = re.compile(r"^(https://github\.com/[\w.-]+/[\w.-]+?(\.git)?/?|git@github\.com:[\w.-]+/[\w.-]+?(\.git)?)$")
MANIFESTS = {"package.json", "pyproject.toml", "setup.py", "requirements.txt", "go.mod", "Cargo.toml",
             "pubspec.yaml", "pom.xml", "build.gradle", "build.gradle.kts", "composer.json", "Gemfile"}
WORKSPACE_MARKERS = {"lerna.json", "pnpm-workspace.yaml", "nx.json", "turbo.json", "docker-compose.yml",
                     "docker-compose.yaml", "Makefile"}
COMPONENT_NAMES = {"backend", "frontend", "api", "web", "mobile", "server", "client", "app", "worker",
                   "admin", "services", "packages", "apps", "ui", "core"}


def safe_extract(zip_path: Path, dest: Path) -> None:
    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_ZIP_FILES:
            die(f"ZIP has {len(infos)} entries (limit {MAX_ZIP_FILES}); refusing")
        if sum(i.file_size for i in infos) > MAX_ZIP_BYTES:
            die("ZIP expands beyond 1 GiB; refusing (possible zip bomb)")
        root = dest.resolve()
        for i in infos:
            target = (dest / i.filename).resolve()
            if root != target and root not in target.parents:
                die(f"unsafe path in ZIP (path traversal): {i.filename}")
            if (i.external_attr >> 16) & 0o170000 == 0o120000:
                continue  # skip symlinks entirely
        for i in infos:
            if (i.external_attr >> 16) & 0o170000 == 0o120000:
                continue
            zf.extract(i, dest)


def flatten_single_root(dest: Path) -> None:
    entries = [e for e in dest.iterdir() if e.name not in {"__MACOSX"}]
    if len(entries) == 1 and entries[0].is_dir() and entries[0].name != ".git":
        inner = entries[0]
        for child in list(inner.iterdir()):
            shutil.move(str(child), str(dest / child.name))
        inner.rmdir()
    mac = dest / "__MACOSX"
    if mac.exists():
        shutil.rmtree(mac, ignore_errors=True)


def clone_github(url: str, dest: Path, ref: str | None, depth: int) -> str:
    if not GITHUB_RE.match(url):
        die("--github expects https://github.com/<owner>/<repo> (no embedded credentials) or git@github.com:<owner>/<repo>")
    cmd = ["git", "clone", "--quiet"]
    if depth > 0:
        cmd += ["--depth", str(depth)]
    if ref:
        cmd += ["--branch", ref]
    cmd += [url, str(dest)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except (subprocess.TimeoutExpired, OSError) as exc:
        die(f"git clone failed: {exc}. If the network is unavailable, ask the user to upload a ZIP instead.")
    if r.returncode != 0:
        die("git clone failed: " + r.stderr.strip()[-400:] + "\nIf the repo is private or the network is blocked, "
            "ask the user to upload a ZIP or clone it locally and use --path.")
    head = subprocess.run(["git", "-C", str(dest), "-c", "safe.directory=*", "rev-parse", "HEAD"],
                          capture_output=True, text=True)
    return head.stdout.strip()


def detect_project_shape(source: Path) -> dict:
    top = {p.name for p in source.iterdir() if p.is_file()}
    if top & MANIFESTS:
        return {"status": "single", "notes": "Root contains a dependency manifest."}
    sub = [d for d in sorted(source.iterdir())
           if d.is_dir() and d.name not in {".git", "node_modules", "__pycache__"}
           and any((d / m).exists() for m in MANIFESTS)]
    if len(sub) >= 2:
        names = {d.name.lower() for d in sub}
        if top & WORKSPACE_MARKERS or names <= COMPONENT_NAMES:
            return {"status": "multi-component",
                    "notes": f"Components {sorted(names)} look like parts of one product; treated as ONE project."}
        return {"status": "ambiguous",
                "notes": f"Several independent-looking projects found ({sorted(names)}). AISA audits ONE project per "
                         "session: ask the user which one to audit."}
    return {"status": "single", "notes": "No competing project roots detected."}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--github")
    src.add_argument("--zip")
    src.add_argument("--path", action="append")
    ap.add_argument("--ref", help="branch or tag for --github")
    ap.add_argument("--depth", type=int, default=0, help="git clone depth (0 = full history; needed for history scans)")
    args = ap.parse_args()

    ws = Path(args.workspace)
    source = ws / "source"
    ident = args.github or args.zip or ",".join(sorted(args.path))
    session = load_json(ws / "session.json")
    if session:
        if session.get("source_ref") != ident:
            die("this workspace already holds a different project "
                f"({session.get('source_ref')}). AISA audits exactly one project per session: use a new workspace.")
        print("Workspace already initialised for this project; nothing to do.")
        return
    if source.exists():
        die(f"{source} exists but session.json is missing; use a fresh workspace directory")
    ws.mkdir(parents=True, exist_ok=True)
    commit = None

    if args.github:
        source_type = "github"
        commit = clone_github(args.github, source, args.ref, args.depth)
    elif args.zip:
        source_type = "zip"
        zp = Path(args.zip)
        if not zp.is_file() or not zipfile.is_zipfile(zp):
            die(f"not a valid ZIP file: {zp}")
        source.mkdir()
        safe_extract(zp, source)
        flatten_single_root(source)
    else:
        source_type = "path"
        paths = [Path(p) for p in args.path]
        for p in paths:
            if not p.exists():
                die(f"path not found: {p}")
        if len(paths) == 1 and paths[0].is_dir():
            copy_tree_writable(paths[0], source)
        else:
            source.mkdir()
            common = Path(os.path.commonpath([str(p.resolve().parent) for p in paths]))
            for p in paths:
                rel = p.resolve().relative_to(common) if p.is_file() else Path(p.name)
                target = source / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                if p.is_dir():
                    copy_tree_writable(p, target)
                else:
                    shutil.copy2(p, target)
    make_writable(source)
    shape = detect_project_shape(source)
    th, count = tree_hash(source)
    make_readonly(source)
    save_json(ws / "session.json", {
        "schema_version": SCHEMA_VERSION, "created_at": now_iso(), "source_type": source_type,
        "source_ref": ident, "git_ref": args.ref, "commit": commit, "tree_hash": th, "file_count": count,
        "project_shape": shape, "mode": "AUDIT", "approved_finding_ids": [],
    })
    print(f"Snapshot ready: {source}  files={count}  tree_hash={th[:16]}…")
    print(f"Project shape: {shape['status']} - {shape['notes']}")
    if shape["status"] == "ambiguous":
        print("ACTION REQUIRED: ask the user which single project to audit before continuing.")
    print("Source is read-only. Mode: AUDIT (no modifications permitted).")


if __name__ == "__main__":
    main()
