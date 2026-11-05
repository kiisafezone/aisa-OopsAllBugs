#!/usr/bin/env python3
"""AISA report generator: 17-section audit report as Markdown + HTML + JSON.

    generate_report.py --workspace WS [--remediation] [--allow-invalid]

Inputs (all under the workspace): session.json, inventory.json, findings.json, narrative.json (written by Claude),
features.json (feature verification matrix), runs/*.json, scan/*.json, scan/claims.json, scan/api_map.json,
readonly_check.json and, for remediation, remediation/*.json.

Gate: the report is refused (exit 3) if findings fail validation, the feature matrix claims unproven results, or the
readiness verdict contradicts Confirmed Critical/High findings. Missing narrative is shown as an explicit NOT PROVIDED
marker, never silently dropped or invented.
"""
from __future__ import annotations

import argparse
import html
import json
import re
from pathlib import Path

from aisa_common import DOMAINS, SEVERITIES, SEVERITY_ORDER, STATUSES, die, load_json, now_iso, save_json
from findings import validate_all

MISSING = "NOT PROVIDED - this section was not written during the audit; treat the report as incomplete."
FEATURE_RESULTS = ["Verified Working", "Appears Working (not executed)", "Partially Working", "Broken", "Not Implemented",
                   "Fake / Mocked", "Not Verified"]
NARRATIVE_KEYS = ["executive_summary", "architecture_overview", "methodology_notes", "security_assessment",
                  "anti_slop_assessment", "cross_component_analysis", "technical_debt", "recommendations", "roadmap",
                  "production_readiness", "conclusion", "limitations", "domain_coverage"]
SEV_DEF = {"Critical": "Exploitable now or total failure of a core function; fix before any release.",
           "High": "Serious weakness or broken important behaviour; fix before production.",
           "Medium": "Real defect or weakness with limited blast radius; schedule soon.",
           "Low": "Minor defect, hygiene or maintainability issue.",
           "Informational": "Observation with no direct defect."}


# ----------------------------------------------------------------------------- helpers

def loc_text(f) -> str:
    parts = []
    for l in f["locations"]:
        s = l["file"] + (f":{l['line']}" if l.get("line") else "")
        if l.get("end_line") and l.get("line") and l["end_line"] != l["line"]:
            s += f"-{l['end_line']}"
        parts.append(s)
    return ", ".join(parts[:6]) + (f" (+{len(parts) - 6} more)" if len(parts) > 6 else "") if parts else "(project-level)"


def validate_features(features, ws: Path):
    errs = []
    for i, ft in enumerate(features):
        name = ft.get("feature", f"#{i}")
        if ft.get("result") not in FEATURE_RESULTS:
            errs.append(f"feature '{name}': result must be one of {FEATURE_RESULTS}")
            continue
        if ft["result"] == "Verified Working":
            ref = ft.get("run_ref", "")
            if ft.get("method") not in {"executed-test", "executed-runtime"} or not ref:
                errs.append(f"feature '{name}': 'Verified Working' needs method executed-test/executed-runtime and a run_ref")
            elif not (ws / "runs" / f"{ref}.json").exists() and not (ws / ref).exists():
                errs.append(f"feature '{name}': run_ref '{ref}' does not exist under runs/")
            else:
                run = load_json(ws / "runs" / f"{ref}.json") or load_json(ws / ref) or {}
                if run.get("verdict") != "executed":
                    errs.append(f"feature '{name}': run '{ref}' was not executed")
    return errs


def counts_matrix(findings):
    m = {s: {st: 0 for st in STATUSES} for s in SEVERITIES}
    for f in findings:
        m[f["severity"]][f["status"]] += 1
    return m


# ----------------------------------------------------------------------------- build sections

def build(ws: Path, include_remediation: bool):
    sess = load_json(ws / "session.json", {})
    inv = load_json(ws / "inventory.json", {})
    store = load_json(ws / "findings.json", {"findings": [], "scan_meta": []})
    findings = store["findings"]
    nar = load_json(ws / "narrative.json", {})
    feats = (load_json(ws / "features.json", {}) or {}).get("features", [])
    claims = (load_json(ws / "scan" / "claims.json", {}) or {}).get("claims", [])
    api = load_json(ws / "scan" / "api_map.json", {})
    ro = load_json(ws / "readonly_check.json")
    runs = [load_json(p) for p in sorted((ws / "runs").glob("*.json"))] if (ws / "runs").is_dir() else []
    live = [f for f in findings if f["status"] != "Not Applicable"]
    dismissed = [f for f in findings if f["status"] == "Not Applicable"]
    matrix = counts_matrix(live)
    cov = nar.get("domain_coverage", {})
    missing = [k for k in NARRATIVE_KEYS if k not in nar or not nar[k]]
    S: list[dict] = []

    def sec(title, *blocks):
        S.append({"num": len(S) + 1, "title": title, "blocks": [b for b in blocks if b]})

    def md(key, fallback=MISSING):
        v = nar.get(key)
        return ("md", v) if v else ("warn", fallback)

    # 1
    verdict = (nar.get("production_readiness") or {}).get("verdict", "Not assessed")
    sec("Executive Summary", md("executive_summary"),
        ("table", ["Item", "Value"], [
            ["Project source", f"{sess.get('source_type', '?')}: {sess.get('source_ref', '?')}"],
            ["Commit / snapshot hash", f"{sess.get('commit') or 'n/a'} / {str(sess.get('tree_hash', ''))[:16]}"],
            ["Audit mode", sess.get("mode", "AUDIT")], ["Report generated", now_iso()],
            ["Findings (excl. dismissed)", str(len(live))],
            ["Confirmed Critical / High", f"{sum(matrix[s]['Confirmed'] for s in ('Critical',))} / {matrix['High']['Confirmed']}"],
            ["Production readiness verdict", verdict]]))
    # 2
    t = inv.get("totals", {})
    sec("Project Inventory",
        ("table", ["Metric", "Value"], [["Files scanned", t.get("files_scanned")], ["Source files", t.get("code_files")],
                                       ["Test files", t.get("test_files")], ["Source lines (non-blank)", t.get("code_loc")]]),
        ("table", ["Language", "Files", "Lines"], [[l["language"], l["files"], l["loc"]] for l in inv.get("languages", [])]),
        ("list", [f"Frameworks/libraries detected: {', '.join(inv.get('frameworks_detected', [])) or 'none detected'}",
                  "Manifests: " + (", ".join(m["path"] for m in inv.get("manifests", [])) or "none"),
                  "Infrastructure files: " + (", ".join(f"{k} ({len(v)})" for k, v in inv.get("infrastructure", {}).items()) or "none"),
                  "Documentation: " + (", ".join(inv.get("documentation", {}).values()) or "none"),
                  "Entry points (heuristic): " + (", ".join(inv.get("entrypoints", [])[:10]) or "none"),
                  "Directories skipped: " + (", ".join(inv.get("skipped_directories", [])[:10]) or "none")]),
        ("table", ["Top-level entry", "Files"], [[k, v] for k, v in inv.get("top_level", {}).items()]))
    # 3
    sec("Architecture Overview", md("architecture_overview"))
    # 4
    tools_rows, lims = [], []
    for sm in store.get("scan_meta", []):
        for tool, status in (sm.get("tools") or {}).items():
            tools_rows.append([sm["scanner"], tool, str(status)])
        lims += sm.get("limitations", [])
    run_rows = [[r.get("label"), r.get("command"), r.get("verdict"), str(r.get("exit_code")), r.get("isolation", r.get("reason", ""))]
                for r in runs]
    cov_rows = [[f"{k} {v}", (cov.get(k) or {}).get("status", "Coverage not declared"), (cov.get(k) or {}).get("notes", "")]
                for k, v in DOMAINS.items()]
    sec("Audit Scope and Methodology", md("methodology_notes"),
        ("list", ["Read-only verification: " + ("source snapshot unchanged (hash match)" if ro and ro.get("unchanged") else
                                               "SOURCE MODIFIED" if ro else "not performed")]),
        ("table", ["Scanner", "Tool", "Status"], tools_rows),
        ("table", ["Run", "Command", "Verdict", "Exit", "Isolation / reason"], run_rows) if run_rows else
        ("warn", "No sandbox runs were performed: behaviour was not verified by execution."),
        ("table", ["Domain", "Coverage", "Notes"], cov_rows))
    # 5
    blocks = []
    for code, name in DOMAINS.items():
        fs = [f for f in live if f["domain"] == code]
        c = cov.get(code, {})
        blocks.append(("h", f"{code} - {name}"))
        blocks.append(("p", f"Coverage: {c.get('status', 'not declared')}. {c.get('notes', '')}".strip()))
        if not fs:
            blocks.append(("p", "No findings recorded in this domain." + (" (Coverage was not declared, so absence of findings is not evidence of absence.)"
                                                                          if code not in cov else "")))
        for f in fs:
            blocks.append(("finding", f))
    if dismissed:
        blocks.append(("h", "Dismissed leads (Not Applicable)"))
        blocks.append(("table", ["ID", "Title", "Reason"], [[f["id"], f["title"], f["verification"].get("notes", "")] for f in dismissed]))
    sec("Findings by Audit Domain", *blocks)
    # 6
    sec_f = [f for f in live if f["domain"] in {"SEC", "CMP"}]
    sec("Security Assessment", md("security_assessment"),
        ("table", ["ID", "Severity", "Status", "Location", "Title"], [[f["id"], f["severity"], f["status"], loc_text(f), f["title"]] for f in sec_f]) if sec_f
        else ("p", "No security or compliance findings were recorded."),
        ("p", "Secret values are masked in this report; any credential listed must be considered exposed and rotated."))
    # 7
    slp = [f for f in live if f["domain"] == "SLP"]
    sec("Anti-Slop Assessment", md("anti_slop_assessment"),
        ("table", ["ID", "Severity", "Status", "Location", "Title"], [[f["id"], f["severity"], f["status"], loc_text(f), f["title"]] for f in slp]) if slp
        else ("p", "No Anti-Slop findings were recorded."),
        ("table", ["Claim", "Where", "Probe result", "Evidence"], [[c["claim"], f"{c['file']}:{c['line']}", c["probe_result"], c["evidence"]] for c in claims])
        if claims else ("p", "No documentation claims were extracted."))
    # 8
    sec("Feature Verification Matrix",
        ("table", ["Feature", "Claimed in", "Implemented in", "Result", "Method", "Evidence"],
         [[x.get("feature"), x.get("claimed_in", ""), x.get("implemented_in", ""), x.get("result"), x.get("method", ""), x.get("evidence", "")]
          for x in feats]) if feats else ("warn", "features.json was not provided: feature behaviour was not verified."),
        ("p", "Results: " + "; ".join(FEATURE_RESULTS) + ". 'Verified Working' is only used when the feature was actually executed."))
    # 9
    api_rows = []
    if api:
        api_rows = [["Backend routes extracted", len(api.get("routes", []))], ["Client calls extracted", len(api.get("calls", []))],
                    ["Matched", len(api.get("matched", []))], ["Client calls without a route", len(api.get("unmatched_calls", []))],
                    ["Routes never called", len(api.get("unused_routes", []))], ["External URLs", len(api.get("external_urls", []))]]
    sec("Cross-Component Analysis", md("cross_component_analysis"),
        ("table", ["API trace metric (heuristic)", "Count"], api_rows) if api_rows else None)
    # 10
    top = [f for f in live if f["severity"] in {"Critical", "High"}]
    sec("Risk Classification",
        ("table", ["Severity"] + STATUSES, [[s] + [matrix[s][st] for st in STATUSES] for s in SEVERITIES]),
        ("table", ["Severity", "Meaning"], [[s, SEV_DEF[s]] for s in SEVERITIES]),
        ("p", "Status meanings - Confirmed: proven by code reading, execution or deterministic analysis. Potential: credible lead not yet proven. "
              "Unverified: could not be checked. Not Applicable: investigated and dismissed."),
        ("table", ["ID", "Severity", "Status", "Title"], [[f["id"], f["severity"], f["status"], f["title"]] for f in top]) if top else None)
    # 11
    sec("Evidence Index", ("table", ["ID", "Severity", "Status", "Location", "Verification method", "Source tool"],
                           [[f["id"], f["severity"], f["status"], loc_text(f), f["verification"]["method"], f["source"]["tool"]] for f in live]))
    # 12
    auto_lims = [l for l in lims if l]
    unver = [f for f in live if f["status"] in {"Unverified", "Potential"}]
    auto_lims.append(f"{len([f for f in live if f['status'] == 'Potential'])} finding(s) remain 'Potential' and "
                     f"{len([f for f in live if f['status'] == 'Unverified'])} 'Unverified': they are leads, not proven defects.")
    if not runs:
        auto_lims.append("No code was executed; runtime behaviour, test results and build health are Unverified.")
    if inv.get("oversized_unread_files") or inv.get("binary_files"):
        auto_lims.append(f"{len(inv.get('oversized_unread_files', []))} oversized and {len(inv.get('binary_files', []))} binary files were not read.")
    nr = [k for k, v in DOMAINS.items() if (cov.get(k) or {}).get("status", "") in {"", "Not reviewed", "Partially reviewed"} or k not in cov]
    if nr:
        auto_lims.append("Domains not fully reviewed or without declared coverage: " + ", ".join(nr))
    nv = [x["feature"] for x in feats if x.get("result") in {"Not Verified", "Appears Working (not executed)"}]
    if nv:
        auto_lims.append("Features not verified by execution: " + ", ".join(nv))
    sec("Unverified Areas and Audit Limitations", ("list", auto_lims + list(nar.get("limitations") or [])),
        ("table", ["ID", "Severity", "Status", "Title"], [[f["id"], f["severity"], f["status"], f["title"]] for f in unver[:60]]) if unver else None)
    # 13
    debt = nar.get("technical_debt")
    if debt:
        sec("Technical Debt Register", ("table", ["Item", "Domain", "Impact", "Effort", "Findings"],
                                        [[d.get("item"), d.get("domain", ""), d.get("impact", ""), d.get("effort", ""), ", ".join(d.get("finding_ids", []))] for d in debt]))
    else:
        d_auto = [f for f in live if f["domain"] in {"QUA", "ARC", "TST", "DOC", "STR", "OPS", "INT"} and f["status"] != "Unverified"]
        sec("Technical Debt Register", ("warn", "Narrative register not provided; the list below is auto-derived from findings in QUA/ARC/TST/DOC/STR/OPS/INT."),
            ("table", ["ID", "Domain", "Severity", "Title"], [[f["id"], f["domain"], f["severity"], f["title"]] for f in d_auto]))
    # 14
    recs = nar.get("recommendations")
    if recs:
        sec("Prioritized Recommendations", ("table", ["#", "Priority", "Recommendation", "Rationale", "Effort", "Findings"],
                                            [[i + 1, r.get("priority", ""), r.get("title"), r.get("rationale", ""), r.get("effort", ""), ", ".join(r.get("finding_ids", []))]
                                             for i, r in enumerate(recs)]))
    else:
        auto = sorted([f for f in live if f["status"] in {"Confirmed", "Potential"}], key=lambda f: (SEVERITY_ORDER[f["severity"]], f["status"] != "Confirmed"))
        sec("Prioritized Recommendations", ("warn", "Narrative recommendations not provided; auto-ordered by severity then confirmation status."),
            ("table", ["#", "Severity", "ID", "Recommended fix"], [[i + 1, f["severity"], f["id"], f["recommendation"]] for i, f in enumerate(auto[:40])]))
    # 15
    road = nar.get("roadmap")
    if road:
        sec("Remediation Roadmap", ("table", ["Phase", "Timeframe", "Goals", "Findings"],
                                    [[r.get("phase"), r.get("timeframe", ""), r.get("goals", ""), ", ".join(r.get("finding_ids", []))] for r in road]))
    else:
        def ids(sev, st=None):
            return ", ".join(f["id"] for f in live if f["severity"] in sev and (st is None or f["status"] in st)) or "-"
        sec("Remediation Roadmap", ("warn", "Narrative roadmap not provided; phases below are auto-derived from severity."),
            ("table", ["Phase", "Findings"], [["1 Immediate: Confirmed Critical/High", ids({"Critical", "High"}, {"Confirmed"})],
                                              ["2 Verify then fix: Potential Critical/High", ids({"Critical", "High"}, {"Potential"})],
                                              ["3 Next iteration: Medium", ids({"Medium"})], ["4 Hygiene: Low/Informational", ids({"Low", "Informational"})]]))
    # 16
    pr = nar.get("production_readiness")
    if pr:
        sec("Production Readiness Assessment", ("p", f"Verdict: {pr.get('verdict')}"), ("md", pr.get("rationale", "")),
            ("list", [f"Blocker: {b}" for b in pr.get("blockers", [])]) if pr.get("blockers") else None,
            ("table", ["Criterion", "Status", "Notes"], [[c.get("name"), c.get("status"), c.get("notes", "")] for c in pr.get("criteria", [])]) if pr.get("criteria") else None)
    else:
        sec("Production Readiness Assessment", ("warn", MISSING))
    # 17
    sec("Final Audit Conclusion", md("conclusion"))
    # remediation appendix
    rem = {}
    if include_remediation:
        rd = ws / "remediation"
        rem = {"approval": load_json(rd / "approval.json"), "changes": (load_json(rd / "changes.json", {}) or {}).get("changes", []),
               "diff": load_json(rd / "diff_summary.json"), "validation": load_json(rd / "validation.json"),
               "manual": (load_json(rd / "manual_verification.json", {}) or {}).get("results", [])}
        v = rem["validation"] or {}
        ba = v.get("before_after", {})
        title = {f["id"]: f["title"] for f in findings}
        sec("Appendix A - Remediation: Changes Made",
            ("p", f"Approved by user: {(rem['approval'] or {}).get('user_statement', 'NO APPROVAL RECORD')}"),
            ("table", ["Finding", "Files", "Change"], [[c["finding_id"], ", ".join(c["files"]), c["description"]] for c in rem["changes"]]),
            ("list", [f"{c['kind']}: {c['file']}" for c in (rem["diff"] or {}).get("changed", [])]),
            ("p", "Deliverables: remediation/patches/aisa-remediation.patch, remediation/aisa-remediation.zip, remediation/patches/CHANGES.md"))
        sec("Appendix B - Remediation: Tests Performed",
            ("table", ["Check", "Result"], [[k, json.dumps(val, ensure_ascii=False)] for k, val in (v.get("checks") or {}).items()]) if v else ("warn", "validation.json missing"))
        sec("Appendix C - Remediation: Before and After Findings",
            ("p", f"Before: {v.get('counts', {}).get('before', '?')} finding(s); after: {v.get('counts', {}).get('after', '?')}."),
            ("table", ["State", "Findings"], [["Resolved", ", ".join(f"{i} ({title.get(i, '')})" for i in ba.get("resolved", [])) or "-"],
                                              ["Persisting", ", ".join(ba.get("persisting", [])) or "-"],
                                              ["Needs manual re-verification", ", ".join(ba.get("manual_findings_needing_reverification", [])) or "-"]]),
            ("table", ["ID", "Manual result", "Notes"], [[m["id"], m["result"], m["notes"]] for m in rem["manual"]]) if rem["manual"] else None)
        sec("Appendix D - Remediation: Regression Verification",
            ("table", ["ID", "Severity", "Title"], [[r["id"], r["severity"], r["title"]] for r in ba.get("new_regressions", [])]) if ba.get("new_regressions")
            else ("p", "No new findings were introduced by the changes (scanner-detectable)."),
            ("p", "Claimed fixed but still detected: " + (", ".join(ba.get("claimed_fixed_but_still_detected", [])) or "none")))
        sec("Appendix E - Final Validation Report", ("p", f"Verdict: {v.get('verdict', 'NOT VALIDATED')}"),
            ("list", [f"Unverified: {u}" for u in v.get("unverified", [])]) if v.get("unverified") else ("p", "Nothing left unverified."))
    return S, {"session": sess, "inventory": inv, "findings": findings, "matrix": matrix, "features": feats, "claims": claims,
               "narrative": nar, "runs": runs, "remediation": rem,
               "completeness": {"missing_narrative": missing, "domains_without_coverage": [k for k in DOMAINS if k not in cov]},
               "generated_at": now_iso()}


# ----------------------------------------------------------------------------- renderers

def esc_cell(x) -> str:
    return str(x if x is not None else "").replace("|", "\\|").replace("\n", " ")


def render_md(S, title) -> str:
    out = [f"# {title}", ""]
    for s in S:
        out += [f"## {s['num']}. {s['title']}", ""]
        for b in s["blocks"]:
            k = b[0]
            if k == "md":
                out += [b[1], ""]
            elif k == "p":
                out += [b[1], ""]
            elif k == "warn":
                out += [f"> **Warning:** {b[1]}", ""]
            elif k == "h":
                out += [f"### {b[1]}", ""]
            elif k == "list":
                out += [f"- {i}" for i in b[1]] + [""]
            elif k == "table" and b[2]:
                out += ["| " + " | ".join(b[1]) + " |", "|" + "---|" * len(b[1])]
                out += ["| " + " | ".join(esc_cell(c) for c in r) + " |" for r in b[2]] + [""]
            elif k == "finding":
                f = b[1]
                ev = f["evidence"]
                out += [f"#### {f['id']} · {f['severity']} · {f['status']} - {f['title']}", "",
                        f"- **Location:** {loc_text(f)}"]
                if ev.get("snippet"):
                    out += ["- **Evidence (verbatim from source):**", "", "  ```", "  " + ev["snippet"].replace("\n", "\n  "), "  ```"]
                if ev.get("details"):
                    out.append(f"- **Evidence (details):** {ev['details']}")
                if ev.get("masked"):
                    out.append("- **Note:** secret value masked.")
                v = f["verification"]
                out += [f"- **Explanation:** {f['explanation']}", f"- **Impact:** {f['impact']}", f"- **Recommended fix:** {f['recommendation']}",
                        f"- **Verification:** {f['status']} via `{v['method']}` ({v['status']})" + (f" - {v['notes']}" if v.get("notes") else ""),
                        ("- **References:** " + ", ".join(f["references"])) if f.get("references") else "", ""]
    return "\n".join(x for x in out if x is not None) + "\n"


def inline(t: str) -> str:
    t = html.escape(t)
    t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
    return re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", t)


def md_to_html(text: str) -> str:
    out, para, items = [], [], []
    def flush():
        nonlocal para, items
        if para:
            out.append("<p>" + inline(" ".join(para)) + "</p>")
        if items:
            out.append("<ul>" + "".join(f"<li>{inline(i)}</li>" for i in items) + "</ul>")
        para, items = [], []
    for line in text.split("\n"):
        s = line.strip()
        if not s:
            flush()
        elif s.startswith(("- ", "* ")):
            if para:
                flush()
            items.append(s[2:])
        elif s.startswith("#"):
            flush()
            out.append(f"<h4>{inline(s.lstrip('# '))}</h4>")
        else:
            if items:
                flush()
            para.append(s)
    flush()
    return "\n".join(out)


CSS = """:root{--bg:#fff;--fg:#1b1f24;--mut:#59636e;--bd:#d0d7de;--card:#f6f8fa;--crit:#a40e26;--high:#c2410c;--med:#a16207;--low:#1d4ed8;--info:#59636e}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--mut:#9198a1;--bd:#30363d;--card:#161b22;--crit:#ff7b72;--high:#ffa657;--med:#e3b341;--low:#79c0ff;--info:#9198a1}}
body{font:15px/1.55 system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0 auto;max-width:1100px;padding:24px}
h1,h2,h3,h4{line-height:1.25}h2{border-bottom:1px solid var(--bd);padding-bottom:6px;margin-top:2.2em}
table{border-collapse:collapse;width:100%;margin:12px 0;display:block;overflow-x:auto}th,td{border:1px solid var(--bd);padding:6px 9px;text-align:left;vertical-align:top;font-size:13.5px}th{background:var(--card)}
code,pre{background:var(--card);border-radius:4px;font-family:ui-monospace,monospace;font-size:13px}code{padding:1px 4px}pre{padding:10px;overflow-x:auto;white-space:pre-wrap}
.warn{border-left:4px solid var(--med);background:var(--card);padding:8px 12px;margin:10px 0}
details.f{border:1px solid var(--bd);border-radius:6px;margin:8px 0;background:var(--card)}details.f>summary{cursor:pointer;padding:8px 12px;font-weight:600}details.f>div{padding:0 14px 10px}
.b{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:700;border:1px solid currentColor}
.Critical{color:var(--crit)}.High{color:var(--high)}.Medium{color:var(--med)}.Low{color:var(--low)}.Informational{color:var(--info)}
nav a{margin-right:10px;font-size:13px}"""


def render_html(S, title) -> str:
    h = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
         f"<title>{html.escape(title)}</title><style>{CSS}</style></head><body><h1>{html.escape(title)}</h1><nav>"]
    h += [f"<a href='#s{s['num']}'>{s['num']}. {html.escape(s['title'])}</a>" for s in S]
    h.append("</nav>")
    for s in S:
        h.append(f"<h2 id='s{s['num']}'>{s['num']}. {html.escape(s['title'])}</h2>")
        for b in s["blocks"]:
            k = b[0]
            if k == "md":
                h.append(md_to_html(b[1]))
            elif k == "p":
                h.append(f"<p>{inline(str(b[1]))}</p>")
            elif k == "warn":
                h.append(f"<div class='warn'><strong>Warning:</strong> {html.escape(b[1])}</div>")
            elif k == "h":
                h.append(f"<h3>{html.escape(b[1])}</h3>")
            elif k == "list":
                h.append("<ul>" + "".join(f"<li>{inline(str(i))}</li>" for i in b[1]) + "</ul>")
            elif k == "table" and b[2]:
                h.append("<table><thead><tr>" + "".join(f"<th>{html.escape(c)}</th>" for c in b[1]) + "</tr></thead><tbody>")
                for r in b[2]:
                    h.append("<tr>" + "".join(
                        f"<td><span class='b {html.escape(str(c))}'>{html.escape(str(c))}</span></td>" if str(c) in SEVERITIES
                        else f"<td>{html.escape(str(c if c is not None else ''))}</td>" for c in r) + "</tr>")
                h.append("</tbody></table>")
            elif k == "finding":
                f, ev, v = b[1], b[1]["evidence"], b[1]["verification"]
                h.append(f"<details class='f'><summary><span class='b {f['severity']}'>{f['severity']}</span> {html.escape(f['id'])} · "
                         f"{html.escape(f['status'])} - {html.escape(f['title'])}</summary><div>")
                h.append(f"<p><strong>Location:</strong> {html.escape(loc_text(f))}</p>")
                if ev.get("snippet"):
                    h.append(f"<p><strong>Evidence (verbatim):</strong></p><pre>{html.escape(ev['snippet'])}</pre>")
                if ev.get("details"):
                    h.append(f"<p><strong>Evidence (details):</strong> {html.escape(ev['details'])}</p>")
                if ev.get("masked"):
                    h.append("<p><em>Secret value masked.</em></p>")
                h.append(f"<p><strong>Explanation:</strong> {html.escape(f['explanation'])}</p><p><strong>Impact:</strong> {html.escape(f['impact'])}</p>"
                         f"<p><strong>Recommended fix:</strong> {html.escape(f['recommendation'])}</p>"
                         f"<p><strong>Verification:</strong> {html.escape(f['status'])} via <code>{html.escape(v['method'])}</code> ({html.escape(v['status'])})"
                         f"{' - ' + html.escape(v['notes']) if v.get('notes') else ''}</p>")
                if f.get("references"):
                    h.append(f"<p><strong>References:</strong> {html.escape(', '.join(f['references']))}</p>")
                h.append("</div></details>")
    h.append("</body></html>")
    return "\n".join(h)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--remediation", action="store_true", help="append remediation appendices (A-E)")
    ap.add_argument("--allow-invalid", action="store_true", help="render despite validation errors (they are printed in the report)")
    ap.add_argument("--title")
    ap.add_argument("--out-dir")
    args = ap.parse_args()
    ws = Path(args.workspace)
    store = load_json(ws / "findings.json")
    if not store:
        die("findings.json missing; run run_scans.py first")
    include_rem = args.remediation or (ws / "remediation" / "validation.json").exists()
    errs, _ = validate_all(store, ws / "source" if (ws / "source").is_dir() else None)
    feats = (load_json(ws / "features.json", {}) or {}).get("features", [])
    errs += validate_features(feats, ws)
    nar = load_json(ws / "narrative.json", {})
    pr = nar.get("production_readiness") or {}
    verdict = str(pr.get("verdict", "")).strip().lower()
    crit = [f["id"] for f in store["findings"] if f["status"] == "Confirmed" and f["severity"] == "Critical"]
    high = [f["id"] for f in store["findings"] if f["status"] == "Confirmed" and f["severity"] == "High"]
    if verdict.startswith("ready") and "not" not in verdict:
        conditional = "condition" in verdict
        if crit:
            errs.append(f"readiness verdict '{pr.get('verdict')}' contradicts Confirmed Critical findings: {', '.join(crit)}")
        elif high and not conditional:
            errs.append(f"readiness verdict '{pr.get('verdict')}' contradicts Confirmed High findings: {', '.join(high)}; "
                        "use 'Ready with conditions' and list them as blockers, or 'Not ready'")
    if errs and not args.allow_invalid:
        print("REPORT REFUSED - fix these first:", *errs[:25], sep="\n  ")
        raise SystemExit(3)
    S, data = build(ws, include_rem)
    if errs:
        S.insert(0, {"num": 0, "title": "VALIDATION ERRORS (report generated with --allow-invalid)", "blocks": [("list", errs)]})
    title = args.title or f"AISA Audit Report - {Path(str((load_json(ws / 'session.json', {}) or {}).get('source_ref', 'project'))).name or 'project'}"
    out = Path(args.out_dir) if args.out_dir else ws / "reports"
    out.mkdir(parents=True, exist_ok=True)
    (out / "aisa-report.md").write_text(render_md(S, title), encoding="utf-8")
    (out / "aisa-report.html").write_text(render_html(S, title), encoding="utf-8")
    data["validation_errors"] = errs
    save_json(out / "aisa-report.json", data)
    print(f"[report] {len(S)} sections, {len(data['findings'])} findings -> {out}/aisa-report.(md|html|json)")
    if data["completeness"]["missing_narrative"]:
        print("INCOMPLETE narrative sections:", ", ".join(data["completeness"]["missing_narrative"]))


if __name__ == "__main__":
    main()
