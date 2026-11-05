# Scripts and tooling reference

All scripts are standard-library Python 3.11+ (needs `tomllib`). Run them from anywhere with
`python3 <skill>/scripts/<name>.py`. Every script takes `--workspace WS`; scanners also accept `--source DIR` and `--out FILE`.

Workspace layout:

```
WS/
  session.json          project identity, tree hash, mode, approvals
  source/               READ-ONLY snapshot of the audited project
  inventory.json        facts: languages, manifests, infra, tests, git
  scan/*.json           raw scanner output (candidates) + claims.json, api_map.json, deps_inventory.json, duplicates_detail.json
  findings.json         merged, validated findings (single source of truth)
  features.json         feature verification matrix (Claude writes)
  narrative.json        report prose (Claude writes)
  runs/*.json           every sandbox run, including refusals
  verification/         Claude's own verification tests (run with --overlay; never inside source/)
  readonly_check.json   proof the snapshot is unchanged
  reports/              aisa-report.md / .html / .json
  remediation/          approval, work copy, patches, validation (only in remediation)
```

## Scripts

| Script | Purpose |
|---|---|
| `intake.py` | Bring ONE project in (`--github URL [--ref R] [--depth N]`, `--zip F`, `--path P` repeatable). Safe ZIP extraction, one-project enforcement, read-only snapshot, tree hash. |
| `inventory.py` | Facts only: languages/LOC, manifests, frameworks, infra, docs, tests, git info, skipped dirs. |
| `run_scans.py` | Runs inventory + every scanner below and merges into `findings.json`. Supports `--source/--out-dir/--findings` for re-scans. |
| `scan_structure.py` | Completeness: README, license, tests, CI, manifests, .gitignore, bundled artifacts. |
| `scan_patterns.py` | ~25 regex rules (injection, eval, TLS off, CORS, weak crypto, XSS sinks, debug mode, Docker, noise-controlled). |
| `scan_secrets.py` | Provider-format keys, generic assignments, DSNs, `.env`; values masked; adds gitleaks when installed (`--history` scans git history). |
| `scan_quality.py` | Python AST: stubs, constant-return "actions", complexity, long functions, swallowed exceptions, unreachable code, mutable defaults. |
| `scan_antislop.py` | Mock leakage, fake async, dead handlers, README claims vs. code (`claims.json`), phantom dependencies (Py/JS/Dart), commented-out code, AI residue. |
| `check_deps.py` | Manifest parsing: pinning, lockfiles, deprecated packages. **Offline - no advisory lookup.** |
| `trace_api.py` | Backend routes vs. client calls (Flask, FastAPI, Express, Django, Spring; fetch/axios/jQuery/dio/requests) -> `api_map.json`. Heuristic. |
| `detect_duplicates.py` | Copy-pasted blocks across files (normalised windows). |
| `scan_tools.py` | bandit / semgrep / ruff when installed. |
| `findings.py` | merge / validate / add / update / list / summary / diff. Enforces the evidence rules. |
| `sandbox_run.py` | Detect and run tests/builds on a throwaway copy with isolation and limits. |
| `verify_readonly.py` | Re-hash the snapshot; exit 1 if anything changed. |
| `generate_report.py` | 17-section report in Markdown, HTML, JSON. Refuses invalid input. |
| `remediation.py` | approve / init / record / diff / validate / verify-manual / apply-to. |

## Optional external tools (used automatically if on PATH)

| Tool | Adds | Install hint |
|---|---|---|
| `gitleaks` | entropy/rule-based secret detection, git history with `--history` | `brew install gitleaks` |
| `bandit` | Python security checks | `pip install bandit` |
| `semgrep` | multi-language rules (`--config auto` needs network; offline it reports engine errors and AISA records "rules may not have loaded") | `pip install semgrep` |
| `ruff` | undefined names, redefinitions, syntax errors | `pip install ruff` |

`run_scans.py` records which tools ran, were missing, or failed; the report's methodology section shows it.
Parsers follow each tool's documented JSON; they are unit-tested against sample shapes (not against live installs),
so check the first real result for sanity.

## Things the scripts deliberately do NOT do

- **Vulnerability advisories** (CVEs for dependencies). With network access, run and then record with `findings.py add`:
  `pip-audit -r requirements.txt -f json` / `npm audit --json` / `osv-scanner -r .` / `flutter pub outdated`.
  Without network, state "dependency advisories not checked" under limitations.
- **Dynamic security testing** (fuzzing, authenticated crawling). Out of scope; mention as a limitation.
- **Judging business correctness** - that is Claude's reading work.

## Sandbox model (`sandbox_run.py`)

- Runs in a temp **copy**; deleted afterwards. The snapshot is never the working directory.
- Environment is rebuilt from scratch (no inherited tokens), `HOME`/`TMPDIR` inside the temp dir, proxies pointed at a dead port.
- Network namespace isolation via `unshare -rn` when available. If not available the run is **refused** unless the user agrees and you pass `--accept-no-isolation`.
- Limits: CPU seconds, max file size, open files, wall-clock timeout, process group kill.
- Refuses commands/scripts that pipe downloads into shells, use sudo/ssh/nc, `docker run`, `git push`, destructive `rm -rf /` etc.
- Dependency install needs `--allow-install` + the user's approval; install phase has network, test phase does not. Prefer `npm ci --ignore-scripts`.
- `--kind syntax` (`compileall`) never executes project code and is always allowed.
- **This is best-effort, not a VM.** Tests and `conftest.py` are arbitrary code. For untrusted repositories recommend running AISA inside a disposable container/VM.

## Writing your own verification tests

Put them in `WS/verification/` (never in `source/`), then:
`sandbox_run.py --workspace WS --label products-endpoint --overlay WS/verification --command "python3 -m pytest verification -q"`.
The overlay is copied into the temp copy next to the project's code. Reference the run in `features.json` via `run_ref`.
Tests you write are evidence only if they ran: quote the run, including failures.

## Tests for AISA itself

`python3 -m unittest discover -s tests -v` from the skill root (about 10 s, no network). `tests/fixtures/shopmate` is a
deliberately flawed sample project used by the tests and the evals; do not "fix" it.
