<a id="readme-top"></a>

<div align="center">

# AISA (Advanced Intelligent Source-code Auditor) 

###

**Evidence-based source-code audits for Claude Code.**

Audit one project at a time, verify that its features really work, and get a report where every finding is backed by evidence. Nothing is changed without your explicit approval.

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![Claude Code](https://img.shields.io/badge/Platform-Claude%20Code%20Skill-6B5B95)
![Dependencies](https://img.shields.io/badge/Dependencies-Python%20stdlib%20only-success)
![Default mode](https://img.shields.io/badge/Default%20mode-Read--only-blue)

[Report a bug](https://github.com/thecl16/aisa-OopsAllBugs/issues) · [Request a feature](https://github.com/thecl16/aisa-OopsAllBugs/issues)

</div>

<details>
<summary>Table of contents</summary>

1. [About the project](#about-the-project)
2. [How it works](#how-it-works)
3. [Getting started](#getting-started)
4. [Usage](#usage)
5. [Operating modes](#operating-modes)
6. [How AISA avoids fabrication](#how-aisa-avoids-fabrication)
7. [Audit domains](#audit-domains)
8. [Example finding](#example-finding)
9. [Repository layout](#repository-layout)
10. [Testing](#testing)
11. [Security model](#security-model)
12. [Known limitations](#known-limitations)
13. [Contributing](#contributing)
14. [License](#license)

</details>

## About the project

A passing build or a green test suite does not prove that a project is secure, complete, or production-ready. AISA is a **Claude Code Skill** that gives Claude a strict, repeatable workflow for auditing a whole codebase:

- **One project per run.** Input can be a GitHub repository, a ZIP archive, or uploaded files.
- **16 audit domains**, from security and data integrity to an Anti-Slop audit that looks for facade code, stubs, and fake functionality.
- **Feature verification.** Claims in the README or UI are checked against the implementation, and run in a sandbox where possible.
- **A 17-section report** in Markdown, HTML, and JSON.
- **Read-only by default.** Fixes are optional, approval-gated, and made only in a separate work copy.

AISA treats a scanner hit as a *lead*, not a verdict. A finding becomes `Confirmed` only when the code was read and traced, a run was executed, or the fact is deterministic (for example, from AST analysis).

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## How it works

```text
GitHub repository / ZIP / uploaded files
                  |
                  v
             Project intake
                  |
                  v
       Inventory and automated scans
                  |
                  v
   Claude reads the project and triages leads
                  |
                  v
        Sandboxed verification runs
                  |
                  v
   Evidence validation  ->  Audit report (MD / HTML / JSON)
                  |
          You review the findings
                  |
        Explicit approval (specific finding IDs)
                  |
                  v
   Remediation in an isolated work copy
                  |
                  v
      Validation and re-audit
```

Scripts do the mechanical work (inventory, scanning, evidence checks, sandboxed runs, report assembly). Claude does the reading and judgement. The report states what was read in full, sampled, or skipped.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Getting started

### Prerequisites

- [Claude Code](https://docs.claude.com/en/docs/claude-code/overview)
- Python **3.11 or later**. Core scripts use the standard library only; no `pip install` is needed.
- `git`, used for GitHub intake and applying patches.

Optional tools are used automatically when found. If one is missing, the report records it as unavailable.

| Tool | Used for |
| --- | --- |
| `gitleaks` | Secret scanning |
| `bandit` | Python security analysis |
| `semgrep` | Static analysis |
| `ruff` | Python linting |
| `unshare` (Linux) | Network isolation for the sandbox |

### Installation

This repository **is** the skill folder (`SKILL.md` is at the root), so clone it straight into a skills directory under the name `aisa-OopsAllBugs`.

**For all your projects:**

```bash
mkdir -p ~/.claude/skills
git clone https://github.com/thecl16/aisa-OopsAllBugs.git ~/.claude/skills/aisa-OopsAllBugs
```

**For one project only**, from that project's root:

```bash
mkdir -p .claude/skills
git clone https://github.com/thecl16/aisa-OopsAllBugs.git .claude/skills/aisa-OopsAllBugs
```

Check that it landed correctly:

```bash
ls ~/.claude/skills/aisa-OopsAllBugs/SKILL.md
```

Expected output: the path is printed back. If you see `No such file or directory`, the clone went to the wrong place.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Usage

AISA activates only on **explicit** audit requests. Example prompts:

```text
Run AISA audit on this repository: https://github.com/owner/repo
```

```text
Audit this uploaded ZIP and give me the complete source code audit report.
```

```text
Check this project for security issues and Anti-Slop.
```

```text
Verify whether all implemented features actually work.
```

```text
Re-audit the project after applying the approved fixes.
```

It does **not** activate for ordinary programming questions or for explaining a single function.

Reports are written to the audit workspace:

```text
WS/
└── reports/
    ├── aisa-OopsAllBugs-report.md
    ├── aisa-OopsAllBugs-report.html
    └── aisa-OopsAllBugs-report.json
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Operating modes

| Mode | What happens | Changes your code? |
| --- | --- | --- |
| **AUDIT** (default) | Scan, read, verify, report | Never |
| **REMEDIATION** | After you approve specific finding IDs, fixes are made in a work copy and delivered as a patch plus ZIP | Only the copy. Applying to your checkout needs a second explicit approval |
| **VALIDATION** | Tests before and after, full re-scan, regression detection, final verdict | No |

Details for each mode are in [`references/modes.md`](references/modes.md).

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## How AISA avoids fabrication

| Rule | Enforced by |
| --- | --- |
| Scanner hits are `Potential`. `Confirmed` needs a confirming method (code read with notes, executed run, or AST/inventory fact). | `findings.py` |
| Findings are rejected if the file or line does not exist, or the quoted snippet is not in the file. | `findings.py` |
| A report is refused if evidence is invalid, if a feature is `Verified Working` without a real run, or if the readiness verdict contradicts confirmed Critical/High findings. | `generate_report.py` |
| Missing narrative sections appear as **NOT PROVIDED**, never invented. Domains without declared coverage are flagged. | `generate_report.py` |
| Every sandbox run, including refusals, is recorded. The report lists which tools ran and which did not. | `sandbox_run.py` |
| Secret values are masked everywhere. | `scan_secrets.py` and report generation |

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Audit domains

Finding IDs use the domain code, for example `AISA-SEC-001`. Full criteria are in [`references/domains.md`](references/domains.md).

| Code | Domain | Code | Domain |
| --- | --- | --- | --- |
| STR | Structure & Project Completeness | INT | External Integration & Dependencies |
| ARC | Architecture & System Design | PRF | Performance & Optimization |
| QUA | Code Quality | TST | Testing & Reliability |
| LOG | Logic & Functionality | OPS | DevOps & Deployment |
| SEC | Security | DOC | Documentation & Standards |
| DAT | Database & Data Integrity | CMP | Compliance & Privacy |
| API | API & Communication | SLP | Anti-Slop Audit |
| UIX | Frontend & UI/UX | BIZ | Backend & Business Logic |

For each domain the report distinguishes `Reviewed`, `Partially reviewed`, `Not reviewed`, and `Not applicable`. "Reviewed, nothing found" is never conflated with "not reviewed".

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Example finding

Manual findings are added as JSON and validated against the real source before they are accepted:

```json
{
  "domain": "BIZ",
  "title": "Negative quantities pass cart validation when the loop raises",
  "severity": "Medium",
  "status": "Confirmed",
  "locations": [{ "file": "backend/app.py", "line": 73 }],
  "evidence": {
    "snippet": "if i[\"qty\"] < 0:",
    "details": "except: pass at line 75 turns any error into success"
  },
  "impact": "Orders with malformed items are accepted.",
  "recommendation": "Catch KeyError/TypeError explicitly and return False.",
  "references": ["CWE-20"],
  "verification": {
    "method": "manual-code-read",
    "notes": "Read validate_cart and its caller create_order; traced malformed item"
  }
}
```

The `findings.py add` command rejects it if `backend/app.py` or line 73 does not exist, if the snippet is not in that file, or if `Confirmed` is set without a confirming verification method. The full field list, severity rubric, and status meanings are in [`references/report-schema.md`](references/report-schema.md).

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Repository layout

```text
SKILL.md              Workflow and rules Claude follows
references/           domains.md, anti-slop.md, report-schema.md, modes.md, tooling.md
scripts/              intake, inventory, run_scans, scan_*, trace_api, check_deps,
                      detect_duplicates, findings, sandbox_run, generate_report,
                      remediation, verify_readonly
tests/                Unit/integration tests and a deliberately flawed fixture project (shopmate)
evals/                3 eval cases: full-audit-zip, no-trigger-explain-function, fix-requires-approval
```

| Document | Purpose |
| --- | --- |
| [`SKILL.md`](SKILL.md) | Skill entry point and audit workflow |
| [`references/domains.md`](references/domains.md) | The 16 audit domains and how to verify each |
| [`references/anti-slop.md`](references/anti-slop.md) | Anti-Slop criteria |
| [`references/report-schema.md`](references/report-schema.md) | Finding fields, narrative inputs, report contract |
| [`references/modes.md`](references/modes.md) | AUDIT, REMEDIATION, and VALIDATION behavior |
| [`references/tooling.md`](references/tooling.md) | Scripts, workspace layout, and tool integration |

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Testing

From the repository root:

```bash
python3 -m unittest discover -s tests -v
```

Expected result: a few seconds, no network needed, ending with:

```text
Ran 34 tests in ...s

OK
```

The tests run against a fixture project, `shopmate`, that contains planted defects (SQL injection, `eval`, hard-coded secrets, an API path mismatch, README claims without implementation, a stubbed payment). The three eval cases in `evals/` check end-to-end behavior: a full audit, not triggering on a plain "explain this function" request, and refusing to fix anything before approval.

Passing tests do not prove that the optional scanner bridges work against every live tool version. See the limitations below.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Security model

AISA runs verification in a **best-effort sandbox, not a virtual machine**. It works on a temporary copy, scrubs the environment, applies resource limits, uses network namespaces when available, and refuses obviously dangerous commands.

> **Warning**
> Test code and files such as `conftest.py` are arbitrary code. For untrusted repositories, run AISA inside a disposable container or VM with no credentials or host data mounted.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Known limitations

- **Best-effort sandbox.** Isolation depends on the host OS and available facilities.
- **No dependency vulnerability lookup.** AISA works offline. Run `pip-audit`, `npm audit`, or `osv-scanner` yourself when you have network access.
- **AST analysis is Python-only.** Other languages get pattern, size, route-tracing, and claim checks plus Claude's reading.
- **Heuristic route matching.** Dynamic URLs, generated clients, and gateways can cause misses or false leads.
- **Scanner bridges.** The `bandit`, `semgrep`, `ruff`, and `gitleaks` bridges were tested against documented output shapes and a fake `gitleaks` binary, not live installs. Check the first real result.
- **Compliance and privacy findings** are technical observations, not legal advice.
- **Audit depth** depends on how much of the project Claude reads. The report states what was read in full, sampled, or skipped.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Contributing

Contributions are welcome. Please preserve AISA's core guarantees:

1. Keep audit mode read-only.
2. Never promote scanner output to `Confirmed` without supporting evidence.
3. Never invent source locations, snippets, execution results, or coverage.
4. Keep remediation approval-gated and separate from the user's original checkout.
5. Add or update tests when changing scripts, evidence rules, or report generation.
6. Document new limitations and tool-availability assumptions.

Workflow:

1. Fork the repository and create a branch (`git checkout -b feature/my-change`).
2. Make your change and run the test suite (see [Testing](#testing)).
3. Commit and push your branch.
4. Open a pull request describing the behavior change, test evidence, and any impact on report compatibility.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## License

This repository does not include a license file yet, so all rights are reserved by the author until one is added.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

<div align="center">

**AISA: audit with evidence, report with precision, remediate only with approval.**

</div>
