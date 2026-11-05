#!/usr/bin/env python3
"""AISA dependency checker (offline). Parses manifests, flags pinning/lockfile/deprecation issues.

It does NOT query vulnerability databases. If the network is available, run pip-audit / npm audit
yourself and record results with findings.py add (see references/tooling.md).
"""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from aisa_common import candidate, iter_files, read_text, resolve_paths, save_json, scanner_parser, write_scan

DEPRECATED = {
    "pycrypto": "unmaintained since 2013 with known vulnerabilities; use pycryptodome or cryptography",
    "nose": "unmaintained; use pytest",
    "request": "npm 'request' is deprecated; use fetch/axios/undici",
    "node-sass": "deprecated; use sass (Dart Sass)",
    "tslint": "deprecated in favour of ESLint",
}


def parse_requirements(text):
    deps = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*(.*)$", line)
        if m:
            deps.append((re.sub(r"\[.*\]", "", m.group(1)), m.group(2).strip()))
    return deps


def parse_package_json(text):
    try:
        d = json.loads(text)
    except json.JSONDecodeError:
        return [], True
    deps = []
    for sec in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        for k, v in (d.get(sec) or {}).items():
            deps.append((k, str(v), sec))
    return deps, False


def parse_pyproject(text):
    try:
        d = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    deps = list((d.get("project") or {}).get("dependencies") or [])
    return [(re.split(r"[ <>=!~;\[]", s, 1)[0], s[len(re.split(r"[ <>=!~;\[]", s, 1)[0]):].strip()) for s in deps]


def parse_pubspec(text):
    deps, section = [], None
    for line in text.splitlines():
        if re.match(r"^(dependencies|dev_dependencies):", line):
            section = line.split(":")[0]
            continue
        if re.match(r"^\S", line):
            section = None
        m = re.match(r"^  ([a-z0-9_]+):\s*(.*)$", line)
        if section and m:
            deps.append((m.group(1), m.group(2).strip(), section))
    return deps


def main() -> None:
    args = scanner_parser("Dependency manifest analysis").parse_args()
    ws, src, out = resolve_paths(args, "deps")
    cands, inventory = [], []
    names = {rel.rsplit("/", 1)[-1] for _, rel in iter_files(src)}
    for p, rel in iter_files(src):
        name = rel.rsplit("/", 1)[-1]
        text = read_text(p)
        if text is None:
            continue
        entry = {"manifest": rel, "dependencies": []}
        if name.startswith("requirements") and name.endswith(".txt"):
            for pkg, spec in parse_requirements(text):
                entry["dependencies"].append({"name": pkg, "spec": spec})
                if not re.search(r"==|~=|===", spec):
                    cands.append(candidate("DEP-UNPINNED", "INT", "Low", f"Unpinned Python dependency '{pkg}'",
                                           file=rel, evidence=f"{pkg}{spec}", verbatim=False,
                                           explanation="No exact (==) or compatible (~=) version pin.",
                                           impact="Builds are not reproducible; upgrades can break or introduce vulnerabilities.",
                                           recommendation="Pin versions and keep a lockfile (pip-tools/poetry/uv).",
                                           method="config-inspection"))
        elif name == "package.json":
            deps, bad = parse_package_json(text)
            if bad:
                cands.append(candidate("DEP-BADJSON", "STR", "Medium", "package.json is not valid JSON", file=rel,
                                       explanation="npm cannot parse this manifest.", impact="Install fails.",
                                       recommendation="Fix the JSON syntax.", status="Confirmed", method="static-ast"))
            for pkg, spec, sec in deps:
                entry["dependencies"].append({"name": pkg, "spec": spec, "section": sec})
                if spec in {"*", "latest", ""} or spec.startswith(("git", "http")):
                    cands.append(candidate("DEP-UNPINNED", "INT", "Medium", f"Unbounded npm dependency '{pkg}'", file=rel,
                                           evidence=f'"{pkg}": "{spec}"', explanation="Version range is unbounded or a raw URL.",
                                           impact="Non-reproducible builds, supply-chain risk.",
                                           recommendation="Use a semver range and commit a lockfile.", method="config-inspection"))
        elif name == "pyproject.toml":
            for pkg, spec in parse_pyproject(text):
                entry["dependencies"].append({"name": pkg, "spec": spec})
        elif name == "pubspec.yaml":
            for pkg, spec, sec in parse_pubspec(text):
                entry["dependencies"].append({"name": pkg, "spec": spec, "section": sec})
                if spec in {"any"}:
                    cands.append(candidate("DEP-UNPINNED", "INT", "Low", f"Dart dependency '{pkg}' uses 'any'", file=rel,
                                           evidence=f"{pkg}: any", explanation="No version constraint.",
                                           impact="Non-reproducible builds.", recommendation="Constrain with ^x.y.z.",
                                           method="config-inspection"))
        else:
            continue
        for d in entry["dependencies"]:
            key = d["name"].lower()
            if key in DEPRECATED:
                cands.append(candidate("DEP-DEPRECATED", "INT", "Low", f"Deprecated/unmaintained dependency '{d['name']}'",
                                       file=rel, explanation=DEPRECATED[key], impact="No security fixes upstream.",
                                       recommendation="Migrate to the maintained alternative.", method="config-inspection"))
        inventory.append(entry)
    has_py = any(e["manifest"].startswith("requirements") or e["manifest"].endswith("pyproject.toml") for e in inventory)
    has_js = any(e["manifest"].endswith("package.json") for e in inventory)
    if has_js and not names & {"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}:
        cands.append(candidate("NO-LOCKFILE", "INT", "Low", "No npm lockfile", evidence="no package-lock.json / yarn.lock / pnpm-lock.yaml",
                               explanation="Transitive versions are not frozen.", impact="Non-reproducible installs.",
                               recommendation="Commit a lockfile.", status="Confirmed", method="inventory"))
    if has_py and not names & {"poetry.lock", "Pipfile.lock", "uv.lock"} and not any(
            d["spec"] and "==" in d["spec"] for e in inventory for d in e["dependencies"]):
        cands.append(candidate("NO-LOCKFILE", "INT", "Low", "No Python lockfile or pinned requirements",
                               evidence="no poetry.lock/Pipfile.lock/uv.lock and no '==' pins", explanation="Versions float.",
                               impact="Non-reproducible installs.", recommendation="Pin or lock dependencies.",
                               status="Confirmed", method="inventory"))
    save_json(out.with_name("deps_inventory.json"), {"manifests": inventory})
    write_scan(out, "deps", cands, tools={"builtin": "used", "advisory-database": "not queried (offline analysis)"},
               limitations=["No vulnerability-advisory lookup was performed; known-CVE exposure of dependencies is Unverified."])


if __name__ == "__main__":
    main()
