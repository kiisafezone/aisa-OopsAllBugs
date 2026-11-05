#!/usr/bin/env python3
"""AISA structure scanner: project completeness facts turned into candidate findings.
Deterministic facts (file absent/present) are marked Confirmed with method 'inventory'.
"""
from __future__ import annotations

from inventory import build_inventory
from aisa_common import candidate, resolve_paths, scanner_parser, write_scan


def scan(source):
    inv = build_inventory(source)
    t, out = inv["totals"], []
    non_trivial = t["code_loc"] >= 150

    def fact(rule, dom, sev, title, expl, impact, rec, evidence):
        out.append(candidate(rule, dom, sev, title, evidence=evidence, explanation=expl, impact=impact,
                             recommendation=rec, status="Confirmed", method="inventory"))

    docs = inv["documentation"]
    if "readme" not in docs:
        fact("NO-README", "DOC", "Medium", "No README at the project root",
             "New contributors and operators have no entry point to the project.",
             "Slower onboarding; undocumented setup and run steps.",
             "Add a README with purpose, setup, configuration, run and test instructions.",
             "No README* file found at repository root.")
    if "license" not in docs:
        fact("NO-LICENSE", "CMP", "Low", "No LICENSE file",
             "Without a license, reuse and redistribution terms are undefined.",
             "Legal ambiguity for users and contributors.", "Add a license that matches the intended use.",
             "No LICENSE* file found at repository root.")
    if t["code_files"] and t["test_files"] == 0:
        fact("NO-TESTS", "TST", "High" if non_trivial else "Medium", "No automated tests found",
             "No test files were detected anywhere in the project.",
             "Behaviour and regressions cannot be verified automatically; every change is a risk.",
             "Add unit tests for core logic and integration tests for critical flows; run them in CI.",
             f"{t['code_files']} source file(s), 0 test files (by naming/location heuristics).")
    elif t["code_files"] and t["test_files"] / max(t["code_files"], 1) < 0.15 and non_trivial:
        out.append(candidate("LOW-TEST-RATIO", "TST", "Low", "Few test files relative to source files",
                             evidence=f"{t['test_files']} test file(s) vs {t['code_files']} source file(s)",
                             explanation="Test files are under 15% of source files. This is a coarse heuristic; "
                                         "coverage was not measured.",
                             impact="Large parts of the code may be untested.",
                             recommendation="Measure coverage and add tests around critical paths.",
                             status="Potential", method="inventory"))
    ci = [k for k in ("GitHub Actions", "GitLab CI", "Jenkinsfile") if k in inv["infrastructure"]]
    if non_trivial and not ci:
        fact("NO-CI", "OPS", "Low", "No CI configuration found",
             "No GitHub Actions, GitLab CI or Jenkinsfile detected.",
             "Tests, linting and builds are not enforced on change.",
             "Add a CI pipeline running lint, tests and build on every pull request.",
             "No CI configuration files found.")
    if not inv["manifests"] and t["code_files"]:
        fact("NO-MANIFEST", "STR", "Medium", "No dependency manifest",
             "No requirements.txt / package.json / pubspec.yaml / go.mod etc. found.",
             "The project cannot be installed reproducibly.", "Declare dependencies with pinned versions.",
             "No recognised manifest files.")
    if not (source / ".gitignore").exists():
        fact("NO-GITIGNORE", "STR", "Low", "No .gitignore", "Build artifacts and secrets can be committed by accident.",
             "Repository pollution / secret leakage.", "Add a .gitignore for the stack in use.",
             "No .gitignore at repository root.")
    heavy = [d for d in inv["skipped_directories"]
             if d.rsplit("/", 1)[-1] in {"node_modules", "__pycache__", ".venv", "venv", "dist", "build"}]
    if heavy:
        out.append(candidate("BUNDLED-ARTIFACTS", "STR", "Low", "Dependency/build directories included in the snapshot",
                             evidence=", ".join(heavy[:8]), explanation="Installed dependencies or build output are part of "
                             "the delivered project (they were excluded from scanning).",
                             impact="Bloat, potential committed secrets or stale code; scanned code excludes them.",
                             recommendation="Exclude from version control and distribution; rebuild from manifests.",
                             status="Confirmed", method="inventory"))
    if inv["binary_files"] and len(inv["binary_files"]) > 50:
        out.append(candidate("MANY-BINARIES", "STR", "Informational", "Many binary files in repository",
                             evidence=f"{len(inv['binary_files'])} binary files", explanation="Binary assets in source control "
                             "are hard to review and diff.", impact="Repo bloat.", recommendation="Use artifact storage / LFS.",
                             status="Confirmed", method="inventory"))
    return out, inv


def main() -> None:
    args = scanner_parser("Structure completeness scan").parse_args()
    ws, src, out = resolve_paths(args, "structure")
    cands, inv = scan(src)
    write_scan(out, "structure", cands, tools={"builtin": "used"})


if __name__ == "__main__":
    main()
