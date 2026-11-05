# AISA - Advanced Intelligent Source-code Auditor

A Claude skill that audits **one** software project at a time (GitHub repo, ZIP, or uploaded files) across 16 domains,
verifies whether features really work, and produces an evidence-based 17-section report. Optional, approval-gated
remediation, validation and re-audit.

Read-only by default. Nothing in the audited project is ever modified without your explicit approval.

## Install (Claude Code)

```bash
# personal (all projects)
mkdir -p ~/.claude/skills && cp -r aisa ~/.claude/skills/aisa
# or per project
mkdir -p .claude/skills && cp -r aisa .claude/skills/aisa
```
Requirements: Python 3.11+ (stdlib only), `git` for GitHub intake and patch application.
Optional (used automatically when present): `gitleaks`, `bandit`, `semgrep`, `ruff`. On Linux, `unshare` gives network
isolation for the sandbox.

## Use

AISA activates only on explicit requests, for example:

- "Run AISA audit on this repository: https://github.com/owner/repo"
- "Audit this uploaded ZIP." / "Perform a complete source code audit."
- "Check this project for security issues and Anti-Slop."
- "Verify whether all implemented features actually work."
- "Re-audit the project after applying fixes."

It does not activate for ordinary programming questions or explaining a single function.

Typical flow: intake -> automated scans -> Claude reads the project and triages leads -> sandboxed verification ->
report (`WS/reports/aisa-report.md|html|json`) -> you decide about remediation.

## Modes

| Mode | What happens | Changes your code? |
|---|---|---|
| AUDIT (default) | scan, read, verify, report | Never |
| REMEDIATION | after you approve specific finding IDs: fixes made in a work copy, delivered as patch + ZIP | Only the copy; applying to your checkout needs a second explicit approval |
| VALIDATION | tests before/after, full re-scan, regression detection, final verdict | No |

## How AISA avoids fabrication

- Scanner hits are leads (`Potential`). `Confirmed` needs a confirming method (code read with notes, executed run, AST/inventory fact).
- `findings.py` rejects findings whose file or line does not exist or whose quoted snippet is not in the file.
- `generate_report.py` refuses to build a report from invalid evidence, from `Verified Working` features without a real run,
  or from a readiness verdict that contradicts confirmed Critical/High findings.
- Missing narrative sections are shown as **NOT PROVIDED**, never invented. Domains without declared coverage are flagged.
- Every sandbox run (including refusals) is recorded; the report lists which tools ran and which did not.
- Secret values are masked everywhere.

## Layout

```
SKILL.md              workflow and rules Claude follows
references/           domains.md, anti-slop.md, report-schema.md, modes.md, tooling.md
scripts/              intake, inventory, scanners, findings, sandbox_run, generate_report, remediation, verify_readonly
tests/                34 unit/integration tests + a deliberately flawed fixture project (shopmate)
evals/                3 eval cases (full audit, no-trigger, fix-requires-approval)
```

## Tests

```bash
python3 -m unittest discover -s tests -v      # about 10 s, no network
```

## Known limitations (read these)

- **The sandbox is best-effort, not a VM.** It runs on a temp copy with a scrubbed environment, resource limits, and network
  namespaces when available, and refuses obviously dangerous commands. Test code and `conftest.py` are arbitrary code: for
  untrusted projects run AISA inside a disposable container or VM.
- **No dependency vulnerability database lookup** (offline). Run `pip-audit` / `npm audit` / `osv-scanner` yourself when you
  have network access; the report lists this as a limitation otherwise.
- AST analysis covers **Python only**; other languages get pattern, size, route-tracing and claim checks plus Claude's reading.
- Route/client matching is heuristic (regex). Dynamic URLs, generated clients and gateways can cause misses or false leads.
- The bandit/semgrep/ruff/gitleaks bridges were tested against documented output shapes and a fake `gitleaks` binary,
  not against live installs. Check the first real result.
- Findings about compliance/privacy are technical observations, not legal advice.
- Audit quality depends on how much of the project Claude reads. The report states what was read in full, sampled, or skipped.
