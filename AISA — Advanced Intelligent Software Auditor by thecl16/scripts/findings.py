#!/usr/bin/env python3
"""AISA findings manager. The single source of truth is <workspace>/findings.json.

    findings.py --workspace WS merge   [--scan-dir DIR] [--findings FILE] [--source DIR]
    findings.py --workspace WS validate [--findings FILE] [--source DIR]
    findings.py --workspace WS add --json FILE
    findings.py --workspace WS update ID --status Confirmed --method manual-code-read --notes "..."
    findings.py --workspace WS list [--domain SEC] [--severity High] [--status Potential]
    findings.py --workspace WS summary [--json]
    findings.py --workspace WS diff --before A.json --after B.json

Anti-fabrication rules enforced by `validate` (and by add/update before saving):
  * every cited file must exist and every cited line must be within the file;
  * every verbatim snippet must actually occur in the cited file;
  * 'Confirmed' requires a confirming verification method (a regex hit alone is never enough);
  * 'Not Applicable' requires a written reason.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

from aisa_common import (ALL_METHODS, CONFIRMING_METHODS, DOMAINS, SCHEMA_VERSION, SEVERITIES, SEVERITY_ORDER, STATUSES,
                         die, load_json, now_iso, read_text, save_json)

REQUIRED = ["id", "domain", "title", "severity", "status", "locations", "evidence", "explanation", "impact",
            "recommendation", "verification"]


def ws_norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def fingerprint(c: dict) -> str:
    files = sorted({loc["file"] for loc in c.get("locations", [])})
    ev = c["evidence"] if c.get("verbatim") else re.sub(r"\d+", "#", c["title"])
    key = "|".join([c["rule_id"], ",".join(files[:4]), ws_norm(ev)[:160]])
    return hashlib.sha1(key.encode()).hexdigest()[:12]


def next_id(findings: list, domain: str) -> str:
    nums = [int(m.group(1)) for f in findings if (m := re.match(rf"AISA-{domain}-(\d+)$", f["id"]))]
    return f"AISA-{domain}-{(max(nums) if nums else 0) + 1:03d}"


def from_candidate(c: dict, findings: list) -> dict:
    status, method = c["status"], c["method"]
    if status == "Confirmed" and method not in CONFIRMING_METHODS:
        status = "Potential"
    f = {
        "id": next_id(findings, c["domain"]), "fingerprint": fingerprint(c), "domain": c["domain"],
        "domain_name": DOMAINS[c["domain"]], "title": c["title"], "severity": c["severity"], "status": status,
        "locations": c["locations"],
        "evidence": {"snippet": c["evidence"] if c.get("verbatim") else "",
                     "details": "" if c.get("verbatim") else c["evidence"], "masked": bool(c.get("masked"))},
        "explanation": c["explanation"], "impact": c["impact"], "recommendation": c["recommendation"],
        "verification": {"method": method, "status": "Verified" if status == "Confirmed" else "Pending",
                         "notes": "", "verified_at": now_iso() if status == "Confirmed" else None},
        "references": c.get("references", []), "source": {"tool": c["tool"], "rule_id": c["rule_id"]},
        "history": [{"at": now_iso(), "change": f"created by {c['tool']} as {status}"}],
    }
    return f


# ----------------------------------------------------------------------------- validation

def validate_finding(f: dict, source: Path | None, cache: dict) -> tuple[list, list]:
    errs, warns = [], []
    fid = f.get("id", "<no id>")
    for k in REQUIRED:
        if k not in f:
            errs.append(f"{fid}: missing field '{k}'")
    if errs:
        return errs, warns
    if f["domain"] not in DOMAINS:
        errs.append(f"{fid}: unknown domain '{f['domain']}'")
    if f["severity"] not in SEVERITIES:
        errs.append(f"{fid}: invalid severity '{f['severity']}'")
    if f["status"] not in STATUSES:
        errs.append(f"{fid}: invalid status '{f['status']}'")
    for k in ("title", "explanation", "impact", "recommendation"):
        if not str(f[k]).strip():
            errs.append(f"{fid}: '{k}' is empty")
    v, ev = f["verification"], f["evidence"]
    method = v.get("method", "")
    if method not in ALL_METHODS:
        errs.append(f"{fid}: unknown verification method '{method}'")
    texts = []
    for loc in f["locations"]:
        file = loc.get("file")
        if not file:
            errs.append(f"{fid}: location without file")
            continue
        if source is not None:
            if file not in cache:
                p = source / file
                cache[file] = read_text(p) if p.is_file() else False
            text = cache[file]
            if text is False:
                errs.append(f"{fid}: cited file does not exist in source: {file}")
                continue
            if text is not None:
                texts.append(text)
                n = text.count("\n") + 1
                for key in ("line", "end_line"):
                    if loc.get(key) and not 1 <= int(loc[key]) <= n:
                        errs.append(f"{fid}: {file} has {n} lines; cited {key} {loc[key]} is out of range")
    snippet = ev.get("snippet", "")
    if snippet and not ev.get("masked") and texts:
        s = ws_norm(snippet)
        if not any(s in ws_norm(t) for t in texts):
            errs.append(f"{fid}: evidence snippet does not occur in the cited file(s) (possible fabricated evidence)")
    if f["status"] == "Confirmed":
        if method not in CONFIRMING_METHODS:
            errs.append(f"{fid}: 'Confirmed' requires a confirming method ({', '.join(sorted(CONFIRMING_METHODS))}); got '{method}'")
        if not (snippet or ev.get("details")):
            errs.append(f"{fid}: 'Confirmed' requires evidence (snippet or details)")
        lineless_ok = {"inventory", "config-inspection", "executed-test", "executed-runtime"}
        if f["locations"] and not any(l.get("line") for l in f["locations"]) and method not in lineless_ok:
            errs.append(f"{fid}: 'Confirmed' with locations requires at least one line number")
        if method in {"executed-test", "executed-runtime"} and not str(v.get("notes", "")).strip():
            errs.append(f"{fid}: executed verification needs notes naming the command/run that was executed")
        if method == "manual-code-read" and not str(v.get("notes", "")).strip():
            errs.append(f"{fid}: manual-code-read needs notes saying what was read and why it proves the issue")
    if f["status"] == "Not Applicable" and not str(v.get("notes", "")).strip():
        errs.append(f"{fid}: 'Not Applicable' requires notes explaining why (e.g. false positive reasoning)")
    if f["status"] == "Potential" and f["severity"] == "Critical":
        warns.append(f"{fid}: Critical but only 'Potential' - verify before reporting")
    return errs, warns


def validate_all(data: dict, source: Path | None):
    errs, warns, cache, seen = [], [], {}, set()
    for f in data.get("findings", []):
        if f.get("id") in seen:
            errs.append(f"duplicate id {f.get('id')}")
        seen.add(f.get("id"))
        e, w = validate_finding(f, source, cache)
        errs += e
        warns += w
    return errs, warns


# ----------------------------------------------------------------------------- commands

def paths(args):
    ws = Path(args.workspace)
    return ws, Path(getattr(args, "findings", None) or ws / "findings.json"), \
        (Path(args.source) if getattr(args, "source", None) else ws / "source")


def load_store(path: Path, ws: Path) -> dict:
    d = load_json(path)
    if d:
        return d
    sess = load_json(ws / "session.json", {})
    return {"schema_version": SCHEMA_VERSION, "created_at": now_iso(), "source": {
        k: sess.get(k) for k in ("source_type", "source_ref", "commit", "tree_hash")}, "scan_meta": [], "findings": []}


def cmd_merge(args):
    ws, fpath, src = paths(args)
    store = load_store(fpath, ws)
    scan_dir = Path(args.scan_dir) if args.scan_dir else ws / "scan"
    known = {f["fingerprint"] for f in store["findings"] if "fingerprint" in f}
    added = 0
    store["scan_meta"] = []
    for p in sorted(scan_dir.glob("*.json")):
        d = load_json(p)
        if not isinstance(d, dict) or "candidates" not in d:
            continue
        store["scan_meta"].append({"scanner": d.get("scanner"), "tools": d.get("tools", {}),
                                   "limitations": d.get("limitations", []), "stats": d.get("stats", {})})
        for c in d["candidates"]:
            fp = fingerprint(c)
            if fp in known:
                continue
            store["findings"].append(from_candidate(c, store["findings"]))
            known.add(fp)
            added += 1
    store["findings"].sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["id"]))
    store["updated_at"] = now_iso()
    errs, warns = validate_all(store, src if src.is_dir() else None)
    save_json(fpath, store)
    print(f"[merge] +{added} new, {len(store['findings'])} total -> {fpath}")
    if errs:
        print(f"WARNING: {len(errs)} validation problem(s) in scanner output (first 5):", *errs[:5], sep="\n  ")


def cmd_validate(args):
    ws, fpath, src = paths(args)
    data = load_json(fpath)
    if not data:
        die(f"no findings file at {fpath}")
    errs, warns = validate_all(data, src if src.is_dir() else None)
    for w in warns:
        print("warn :", w)
    for e in errs:
        print("ERROR:", e)
    print(f"[validate] {len(data['findings'])} finding(s), {len(errs)} error(s), {len(warns)} warning(s)")
    sys.exit(1 if errs else 0)


def cmd_add(args):
    ws, fpath, src = paths(args)
    store = load_store(fpath, ws)
    raw = load_json(args.json)
    items = raw if isinstance(raw, list) else [raw]
    for it in items:
        dom = it.get("domain")
        if dom not in DOMAINS:
            die(f"unknown domain {dom!r}; use one of {', '.join(DOMAINS)}")
        ev = it.get("evidence", {})
        if isinstance(ev, str):
            ev = {"snippet": "", "details": ev}
        ev.setdefault("masked", False)
        ver = it.get("verification") or {}
        status = it.get("status", "Potential")
        f = {"id": next_id(store["findings"], dom), "fingerprint": "manual-" + hashlib.sha1(json.dumps(it, sort_keys=True).encode()).hexdigest()[:8],
             "domain": dom, "domain_name": DOMAINS[dom], "title": it.get("title", ""), "severity": it.get("severity", "Medium"),
             "status": status, "locations": it.get("locations", []), "evidence": ev, "explanation": it.get("explanation", ""),
             "impact": it.get("impact", ""), "recommendation": it.get("recommendation", ""),
             "verification": {"method": ver.get("method", "manual-code-read"),
                              "status": "Verified" if status == "Confirmed" else "Pending", "notes": ver.get("notes", ""),
                              "verified_at": now_iso() if status == "Confirmed" else None},
             "references": it.get("references", []), "source": {"tool": "claude-manual", "rule_id": "MANUAL"},
             "history": [{"at": now_iso(), "change": f"added manually as {status}"}]}
        e, _ = validate_finding(f, src if src.is_dir() else None, {})
        if e:
            die("finding rejected:\n  " + "\n  ".join(e))
        store["findings"].append(f)
        print(f"[add] {f['id']} {f['severity']} {f['status']} - {f['title']}")
    store["findings"].sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["id"]))
    store["updated_at"] = now_iso()
    save_json(fpath, store)


def cmd_update(args):
    ws, fpath, src = paths(args)
    store = load_store(fpath, ws)
    idx = next((i for i, f in enumerate(store["findings"]) if f["id"] == args.id), None)
    if idx is None:
        die(f"unknown finding id {args.id}")
    f = copy.deepcopy(store["findings"][idx])
    changes = []
    for key in ("severity", "status", "title", "explanation", "impact", "recommendation"):
        val = getattr(args, key, None)
        if val is not None and val != f[key]:
            changes.append(f"{key}: {f[key]!r} -> {val!r}")
            f[key] = val
    if args.method:
        f["verification"]["method"] = args.method
    if args.notes is not None:
        f["verification"]["notes"] = args.notes
    if args.snippet is not None:
        f["evidence"]["snippet"], f["evidence"]["masked"] = args.snippet, False
    if args.details is not None:
        f["evidence"]["details"] = args.details
    for loc in args.add_location or []:
        file, _, line = loc.partition(":")
        f["locations"].append({"file": file, **({"line": int(line)} if line else {})})
    st = f["status"]
    f["verification"]["status"] = {"Confirmed": "Verified", "Not Applicable": "Refuted"}.get(st, "Pending")
    f["verification"]["verified_at"] = now_iso() if st in {"Confirmed", "Not Applicable"} else None
    e, _ = validate_finding(f, src if src.is_dir() else None, {})
    if e:
        die("update rejected (nothing saved):\n  " + "\n  ".join(e))
    f["history"].append({"at": now_iso(), "change": "; ".join(changes + ([f"method -> {args.method}"] if args.method else [])) or "updated"})
    store["findings"][idx] = f
    store["findings"].sort(key=lambda x: (SEVERITY_ORDER[x["severity"]], x["id"]))
    store["updated_at"] = now_iso()
    save_json(fpath, store)
    print(f"[update] {f['id']} now {f['severity']} / {f['status']} (method {f['verification']['method']})")


def loc_str(f):
    if not f["locations"]:
        return "(project-level)"
    l = f["locations"][0]
    return f"{l['file']}:{l['line']}" if l.get("line") else l["file"]


def cmd_list(args):
    ws, fpath, _ = paths(args)
    data = load_json(fpath, {"findings": []})
    for f in data["findings"]:
        if args.domain and f["domain"] != args.domain:
            continue
        if args.severity and f["severity"] != args.severity:
            continue
        if args.status and f["status"] != args.status:
            continue
        print(f"{f['id']:<14} {f['severity']:<13} {f['status']:<14} {loc_str(f):<40} {f['title'][:90]}")


def cmd_summary(args):
    ws, fpath, _ = paths(args)
    data = load_json(fpath, {"findings": []})
    fs = data["findings"]
    matrix = {s: {st: 0 for st in STATUSES} for s in SEVERITIES}
    for f in fs:
        matrix[f["severity"]][f["status"]] += 1
    by_domain = Counter(f["domain"] for f in fs)
    if args.json:
        print(json.dumps({"total": len(fs), "matrix": matrix, "by_domain": by_domain}, indent=2))
        return
    print(f"Total findings: {len(fs)}")
    print(f"{'':<14}" + "".join(f"{s:>16}" for s in STATUSES))
    for sev in SEVERITIES:
        print(f"{sev:<14}" + "".join(f"{matrix[sev][st]:>16}" for st in STATUSES))
    print("By domain:", ", ".join(f"{d}={n}" for d, n in sorted(by_domain.items())))


def cmd_diff(args):
    a, b = load_json(args.before), load_json(args.after)
    if not a or not b:
        die("both --before and --after must exist")
    fa = {f.get("fingerprint"): f for f in a["findings"] if f["status"] != "Not Applicable"}
    fb = {f.get("fingerprint"): f for f in b["findings"] if f["status"] != "Not Applicable"}
    result = {"resolved": [fa[k]["id"] for k in fa if k not in fb], "persisting": [fb[k]["id"] for k in fb if k in fa],
              "new": [fb[k]["id"] for k in fb if k not in fa]}
    if args.out:
        save_json(args.out, result)
    print(f"resolved={len(result['resolved'])} persisting={len(result['persisting'])} new(regressions)={len(result['new'])}")
    for k, v in result.items():
        if v:
            print(f"  {k}: {', '.join(v[:20])}{' …' if len(v) > 20 else ''}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    sub = ap.add_subparsers(dest="cmd", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--findings")
    common.add_argument("--source")
    m = sub.add_parser("merge", parents=[common]); m.add_argument("--scan-dir")
    sub.add_parser("validate", parents=[common])
    a = sub.add_parser("add", parents=[common]); a.add_argument("--json", required=True)
    u = sub.add_parser("update", parents=[common]); u.add_argument("id")
    for k, choices in (("severity", SEVERITIES), ("status", STATUSES)):
        u.add_argument(f"--{k}", choices=choices)
    for k in ("title", "explanation", "impact", "recommendation", "notes", "snippet", "details"):
        u.add_argument(f"--{k}")
    u.add_argument("--method", choices=sorted(ALL_METHODS))
    u.add_argument("--add-location", action="append", help="file[:line]")
    l = sub.add_parser("list", parents=[common])
    for k in ("domain", "severity", "status"):
        l.add_argument(f"--{k}")
    s = sub.add_parser("summary", parents=[common]); s.add_argument("--json", action="store_true")
    d = sub.add_parser("diff"); d.add_argument("--before", required=True); d.add_argument("--after", required=True); d.add_argument("--out")
    args = ap.parse_args()
    {"merge": cmd_merge, "validate": cmd_validate, "add": cmd_add, "update": cmd_update, "list": cmd_list,
     "summary": cmd_summary, "diff": cmd_diff}[args.cmd](args)


if __name__ == "__main__":
    main()
