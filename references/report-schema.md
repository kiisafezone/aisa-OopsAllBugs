# Report inputs Claude must author

`generate_report.py` builds the 17-section report from workspace files. Scanners create most of them; Claude writes
`narrative.json` and `features.json`, and adds manual findings with `findings.py add`.

A missing narrative key is rendered as an explicit **NOT PROVIDED** warning - the report never invents text.

## Finding fields (every finding has all of them)

`id`, `severity` (Critical/High/Medium/Low/Informational), `status` (Confirmed/Potential/Unverified/Not Applicable),
`locations[]` (`file`, `line`, optional `end_line`), `evidence` (`snippet` = verbatim code, checked against the file;
`details` = free text), `explanation`, `impact`, `recommendation`, `verification` (`method`, `status`, `notes`),
`references[]` (CWE etc.), `source` (primary scanner/tool/rule), `evidence_sources[]` (one evidence and provenance record per scanner/tool/rule that produced the deduplicated finding), `history[]`.


### Scanner evidence provenance

Scanner-produced findings may include `evidence_sources[]`. Each record preserves the originating
`scanner`, `tool`, and `rule_id`, its `locations[]`, its own `evidence` (`snippet`, `details`,
and `masked`), and its `references[]`. The top-level `source`, `locations`, and `evidence`
remain the primary finding fields for backward compatibility. When multiple scanner candidates share
a finding fingerprint, the merge keeps one finding and appends distinct evidence-source records;
re-running the merge does not append the same record twice. Older findings without
`evidence_sources[]` remain valid and are upgraded in memory when a matching duplicate is merged.

### Status meanings
- **Confirmed** - proven: Claude read the code and traced the behaviour, or it was executed, or it is a deterministic fact (AST/inventory).
- **Potential** - credible lead not yet proven (scanner hit, plausible path, depends on deployment).
- **Unverified** - could not be checked (no execution possible, external system, missing artefact). State what would verify it.
- **Not Applicable** - investigated and dismissed (false positive, test-only, abstract stub). Needs a written reason.

### Verification methods
`manual-code-read` (needs notes), `executed-test` / `executed-runtime` (needs notes naming the run), `static-ast`,
`inventory`, `config-inspection`, `tool-confirmed`, plus the non-confirming `static-pattern`, `tool-reported`,
`documentation-review`, `not-verified`. Only the first group can justify `Confirmed`.

### Severity rubric
- **Critical** - exploitable now with severe impact (RCE, auth bypass, secret exposure of live credentials, data destruction) or a core function that cannot work.
- **High** - serious weakness/defect on an important path, or fake/broken behaviour of a key feature.
- **Medium** - real defect or weakness with limited blast radius or needing preconditions.
- **Low** - minor defect, hygiene, maintainability.
- **Informational** - observation, no defect.
Rate by impact x likelihood *given the evidence*. A `Potential` finding rarely deserves `Critical` until verified.

## Manual finding (`findings.py --workspace WS add --json finding.json`)

```json
{
  "domain": "BIZ",
  "title": "Negative quantities pass cart validation when the loop raises",
  "severity": "Medium",
  "status": "Confirmed",
  "locations": [{"file": "backend/app.py", "line": 73}],
  "evidence": {"snippet": "if i[\"qty\"] < 0:", "details": "except: pass at line 75 turns any error into success"},
  "explanation": "validate_cart returns True when the try block raises ...",
  "impact": "Orders with malformed items are accepted.",
  "recommendation": "Catch KeyError/TypeError explicitly and return False.",
  "references": ["CWE-20"],
  "verification": {"method": "manual-code-read", "notes": "Read validate_cart and its caller create_order; traced malformed item"}
}
```
The command **rejects** the finding if a cited file or line does not exist, the snippet is not in the file, or `Confirmed` lacks a confirming method.

## narrative.json

```json
{
  "executive_summary": "markdown: scope, headline results, top risks, overall verdict (5-10 sentences)",
  "architecture_overview": "markdown: components, data flow, technologies, boundaries, deployment shape",
  "methodology_notes": "markdown: how the audit was done, what was read in full vs. sampled, tools used",
  "security_assessment": "markdown: posture summary - authn/authz, input handling, secrets, crypto, supply chain",
  "anti_slop_assessment": "markdown: how much of the project is real vs. facade, with the strongest examples",
  "cross_component_analysis": "markdown: frontend <-> API <-> DB <-> integrations; contract mismatches; auth flow end to end",
  "domain_coverage": {
    "SEC": {"status": "Reviewed", "notes": "all routes and auth module read; no dynamic testing"},
    "PRF": {"status": "Partially reviewed", "notes": "static reasoning only"}
  },
  "technical_debt": [
    {"item": "Order formatting duplicated in export.py and reports.py", "domain": "QUA", "impact": "bug fixes must be doubled",
     "effort": "S", "finding_ids": ["AISA-QUA-001"]}
  ],
  "recommendations": [
    {"priority": "P0", "title": "Parameterise all SQL", "rationale": "...", "effort": "M", "finding_ids": ["AISA-SEC-002", "AISA-SEC-003"]}
  ],
  "roadmap": [
    {"phase": "1 - Stop the bleeding", "timeframe": "days 0-3", "goals": "rotate secrets, remove eval, fix SQLi", "finding_ids": ["AISA-SEC-001"]}
  ],
  "production_readiness": {
    "verdict": "Not ready",
    "rationale": "markdown",
    "blockers": ["Confirmed SQL injection on order creation"],
    "criteria": [{"name": "Security", "status": "Fail", "notes": "..."}, {"name": "Tests", "status": "Fail", "notes": "none exist"}]
  },
  "conclusion": "markdown: final judgement and the single most important next step",
  "limitations": ["Payment provider sandbox not reachable; payment flow unverified"]
}
```
Verdict values: `Ready`, `Ready with conditions`, `Not ready`. The generator **refuses** `Ready` when Confirmed Critical
findings exist (or Confirmed High, unless "with conditions").
Coverage statuses: `Reviewed`, `Partially reviewed`, `Not reviewed`, `Not applicable`.
Write every domain; the report flags domains without declared coverage.

## features.json (Feature Verification Matrix)

```json
{"features": [
  {"feature": "Place an order", "claimed_in": "README.md:12", "implemented_in": "backend/app.py:40-48",
   "result": "Broken", "method": "manual-code-read",
   "evidence": "client posts /api/orders, server only defines /api/order (api_map.json)"},
  {"feature": "Product listing", "claimed_in": "README.md:8", "implemented_in": "backend/app.py:26",
   "result": "Verified Working", "method": "executed-runtime", "run_ref": "products-endpoint",
   "evidence": "Flask test client returned 200 with 2 items (runs/products-endpoint.json)"}
]}
```
Results: `Verified Working` (must be executed; needs `run_ref` pointing at `runs/<ref>.json` whose verdict is `executed`),
`Appears Working (not executed)`, `Partially Working`, `Broken`, `Not Implemented`, `Fake / Mocked`, `Not Verified`.
Include **every** user-facing capability the project claims, not just the ones that work.
