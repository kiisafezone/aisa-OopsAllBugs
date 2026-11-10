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
  * every verbatim snippet must occur within its cited line range (or cited file when no line is supplied);
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

from secret_mask import mask_text, mask_value

from aisa_common import (ALL_METHODS, CONFIRMING_METHODS, DOMAINS, SCHEMA_VERSION, SEVERITIES, SEVERITY_ORDER, STATUSES,
                         die, load_json, now_iso, read_text, save_json)

REQUIRED = ["id", "domain", "title", "severity", "status", "locations", "evidence", "explanation", "impact",
            "recommendation", "verification"]


def ws_norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def fingerprint(c: dict) -> str:
    """Legacy rule-specific fingerprint retained for compatibility with existing reports."""
    files = sorted({loc["file"] for loc in c.get("locations", [])})
    ev = c["evidence"] if c.get("verbatim") else re.sub(r"\d+", "#", c["title"])
    key = "|".join([c["rule_id"], ",".join(files[:4]), ws_norm(ev)[:160]])
    return hashlib.sha1(key.encode()).hexdigest()[:12]


def _identity_locations(locations: list) -> list:
    """Canonicalise source coordinates without discarding line-level distinctions."""
    normalised = set()
    for loc in locations or []:
        file = re.sub(r"/+", "/", str(loc.get("file", "")).replace("\\", "/")).removeprefix("./")
        if not file:
            continue
        normalised.add((file, str(loc.get("line") or ""), str(loc.get("end_line") or "")))
    return [list(item) for item in sorted(normalised)]


def _identity_text(value: str, *, title: bool = False) -> str:
    value = ws_norm(str(value or ""))
    if title:
        value = re.sub(r"^(?:bandit|semgrep|ruff)\s*(?::|#|-)\s*", "", value, flags=re.IGNORECASE)
        value = value.casefold()
    return value


def normalized_identity(candidate: dict) -> str | None:
    """Versioned, rule-independent identity; conservative coordinates prevent merging separate occurrences."""
    verbatim = bool(candidate.get("verbatim"))
    value = _identity_text(candidate.get("evidence", "")) if verbatim else _identity_text(candidate.get("title", ""), title=True)
    if not value:
        return None
    payload = {
        "version": 1,
        "domain": str(candidate.get("domain", "")).upper(),
        "locations": _identity_locations(candidate.get("locations", [])),
        "basis": "snippet" if verbatim else "title",
        "value": value,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "v1:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def normalized_identity_from_finding(finding: dict) -> str | None:
    evidence = finding.get("evidence", {}) or {}
    snippet = evidence.get("snippet", "")
    return normalized_identity({
        "domain": finding.get("domain", ""),
        "locations": finding.get("locations", []),
        "verbatim": bool(snippet),
        "evidence": snippet or evidence.get("details", ""),
        "title": finding.get("title", ""),
    })


def _line_range(location: dict) -> tuple[int, int] | None:
    """Return a valid inclusive source line range; unlocated evidence cannot establish overlap."""
    start, end = location.get("line"), location.get("end_line", location.get("line"))
    if isinstance(start, bool) or isinstance(end, bool):
        return None
    if not isinstance(start, (int, str)) or not isinstance(end, (int, str)):
        return None
    if not str(start).isdigit() or not str(end).isdigit():
        return None
    start, end = int(start), int(end)
    if start < 1 or end < start:
        return None
    return start, end


def _overlapping_locations(left: dict, right: dict) -> list[dict]:
    """Find exact same-file intersections between two findings' inclusive line ranges."""
    overlaps = set()
    for a in left.get("locations", []) or []:
        path_a = re.sub(r"/+", "/", str(a.get("file", "")).replace("\\", "/")).removeprefix("./")
        range_a = _line_range(a)
        if not path_a or range_a is None:
            continue
        for b in right.get("locations", []) or []:
            path_b = re.sub(r"/+", "/", str(b.get("file", "")).replace("\\", "/")).removeprefix("./")
            range_b = _line_range(b)
            if path_a != path_b or range_b is None:
                continue
            start, end = max(range_a[0], range_b[0]), min(range_a[1], range_b[1])
            if start <= end:
                overlaps.add((path_a, start, end))
    return [{"file": path, "start_line": start, "end_line": end}
            for path, start, end in sorted(overlaps)]


def build_root_cause_groups(findings: list[dict]) -> list[dict]:
    """Build deterministic, explicitly heuristic groups; never merge or mutate findings."""
    nodes = {f.get("id"): f for f in findings if f.get("id")}
    adjacency = {fid: set() for fid in nodes}
    edges = []
    ids = sorted(nodes)
    for index, left_id in enumerate(ids):
        left = nodes[left_id]
        for right_id in ids[index + 1:]:
            right = nodes[right_id]
            if str(left.get("domain", "")).upper() != str(right.get("domain", "")).upper():
                continue
            overlaps = _overlapping_locations(left, right)
            if overlaps:
                adjacency[left_id].add(right_id)
                adjacency[right_id].add(left_id)
                edges.append({"finding_ids": [left_id, right_id], "overlapping_locations": overlaps})

    groups = []
    visited = set()
    for start in ids:
        if start in visited or not adjacency[start]:
            continue
        stack, members = [start], []
        visited.add(start)
        while stack:
            current = stack.pop()
            members.append(current)
            for neighbour in sorted(adjacency[current], reverse=True):
                if neighbour not in visited:
                    visited.add(neighbour)
                    stack.append(neighbour)
        members = sorted(members)
        member_set = set(members)
        group_edges = [edge for edge in edges if set(edge["finding_ids"]).issubset(member_set)]
        domain = str(nodes[members[0]].get("domain", "")).upper()
        identity_payload = {"domain": domain, "members": members, "overlaps": group_edges}
        digest = hashlib.sha256(json.dumps(
            identity_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")).hexdigest()[:16]
        groups.append({
            "group_id": "RCG-" + digest,
            "domain": domain,
            "member_finding_ids": members,
            "basis": "same_domain_and_overlapping_source_line_ranges",
            "assessment": "heuristic_suggestion_not_verified_root_cause",
            "overlaps": group_edges,
        })
    return sorted(groups, key=lambda group: group["group_id"])


def next_id(findings: list, domain: str) -> str:
    nums = [int(m.group(1)) for f in findings if (m := re.match(rf"AISA-{domain}-(\d+)$", f["id"]))]
    return f"AISA-{domain}-{(max(nums) if nums else 0) + 1:03d}"


def evidence_source(c: dict, scanner: str | None = None) -> dict:
    """Return a stable, self-contained provenance record for one scanner candidate."""
    verbatim = bool(c.get("verbatim"))
    return {
        "scanner": scanner or "unknown",
        "tool": c.get("tool", "unknown"),
        "rule_id": c.get("rule_id", "unknown"),
        "locations": copy.deepcopy(c.get("locations", [])),
        "evidence": {
            "snippet": c.get("evidence", "") if verbatim else "",
            "details": "" if verbatim else c.get("evidence", ""),
            "masked": bool(c.get("masked")),
        },
        "references": copy.deepcopy(c.get("references", [])),
    }


def _source_key(record: dict) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def preserve_evidence_source(finding: dict, candidate: dict, scanner: str | None = None) -> bool:
    """Merge a scanner's evidence/provenance once; return True only when new evidence was added."""
    sources = finding.setdefault("evidence_sources", [])
    if not sources:
        primary = finding.get("source", {})
        sources.append({
            "scanner": primary.get("scanner", "unknown"),
            "tool": primary.get("tool", "unknown"),
            "rule_id": primary.get("rule_id", "unknown"),
            "locations": copy.deepcopy(finding.get("locations", [])),
            "evidence": copy.deepcopy(finding.get("evidence", {})),
            "references": copy.deepcopy(finding.get("references", [])),
        })
    record = evidence_source(candidate, scanner)
    existing = {_source_key(item) for item in sources}
    key = _source_key(record)
    if key in existing:
        return False
    # Upgrade legacy primary provenance in place when its evidence is identical;
    # otherwise retain a separate record for the additional scanner.
    for item in sources:
        if item.get("scanner") == "unknown" and {
            k: v for k, v in item.items() if k != "scanner"
        } == {k: v for k, v in record.items() if k != "scanner"}:
            item["scanner"] = record["scanner"]
            return True
    sources.append(record)
    return True


def from_candidate(c: dict, findings: list, scanner: str | None = None) -> dict:
    status, method = c["status"], c["method"]
    if status == "Confirmed" and method not in CONFIRMING_METHODS:
        status = "Potential"
    f = {
        "id": next_id(findings, c["domain"]), "fingerprint": fingerprint(c),
        "identity_key": normalized_identity(c), "domain": c["domain"],
        "domain_name": DOMAINS[c["domain"]], "title": c["title"], "severity": c["severity"], "status": status,
        "locations": c["locations"],
        "evidence": {"snippet": c["evidence"] if c.get("verbatim") else "",
                     "details": "" if c.get("verbatim") else c["evidence"], "masked": bool(c.get("masked"))},
        "explanation": c["explanation"], "impact": c["impact"], "recommendation": c["recommendation"],
        "verification": {"method": method, "status": "Verified" if status == "Confirmed" else "Pending",
                         "notes": "", "verified_at": now_iso() if status == "Confirmed" else None},
        "references": c.get("references", []),
        "source": {"scanner": scanner or "unknown", "tool": c["tool"], "rule_id": c["rule_id"]},
        "evidence_sources": [evidence_source(c, scanner)],
        "history": [{"at": now_iso(), "change": f"created by {c['tool']} as {status}"}],
    }
    return f


# ----------------------------------------------------------------------------- validation

def positive_int(value):
    """value as a positive int, else None. Rejects bool, float, 0, negatives and non-numeric strings."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        n = value
    elif isinstance(value, str) and value.strip().isdigit():
        n = int(value.strip())
    else:
        return None
    return n if n >= 1 else None

def cited_range(text: str, line: int, end_line: int | None = None) -> str:
    """Exact source text of lines line..end_line (1-based, inclusive). Callers validate the bounds first."""
    return "\n".join(text.split("\n")[line - 1:(end_line or line)])

def validate_finding_ex(f: dict, source: Path | None, cache: dict) -> tuple[list, list, dict]:
    """Returns (errors, warnings, info). info['snippet_check'] says how the snippet was verified:
    verbatim-range-match | verbatim-file-match | masked-range-match | masked-file-match | not-checked.

    Snippet rule: the whitespace-normalised snippet must occur inside the text of at least one explicitly cited
    location - the line (or line..end_line range) when the location has a line, the whole file only when the location
    names a file without any line. Multi-line snippets match multi-line ranges after collapsing all whitespace runs
    (indentation / line wrapping do not matter; a snippet that runs past the end of the range fails). Findings with no
    locations (project-level) have nothing to match and keep their documented behaviour. A masked snippet is checked
    against the *masked* form of each cited range (same secret_mask rules), never by direct equality.
    """
    errs, warns, info = [], [], {"snippet_check": "not-checked"}
    fid = f.get("id", "<no id>")
    for k in REQUIRED:
        if k not in f:
            errs.append(f"{fid}: missing field '{k}'")
    if errs:
        return errs, warns, info
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

    ranges, unreadable = [], False  # ranges: (file, text_of_cited_range, has_line)
    for loc in f["locations"]:
        file = loc.get("file")
        if not file:
            errs.append(f"{fid}: location without file")
            continue
        pp = Path(str(file))
        if pp.is_absolute() or ".." in pp.parts:
            errs.append(f"{fid}: cited path must be relative and inside the source tree: {file}")
            continue
        nums, bad = {}, False
        for key in ("line", "end_line"):
            if loc.get(key) is not None:
                n = positive_int(loc[key])
                if n is None:
                    errs.append(f"{fid}: {file}: '{key}' must be a positive integer, got {loc[key]!r}")
                    bad = True
                else:
                    nums[key] = n
        if "end_line" in nums and "line" not in nums and not bad:
            errs.append(f"{fid}: {file}: 'end_line' given without 'line'")
            bad = True
        if "line" in nums and "end_line" in nums and nums["end_line"] < nums["line"]:
            errs.append(f"{fid}: {file}: end_line {nums['end_line']} precedes line {nums['line']}")
            bad = True
        if source is None:
            continue
        if file not in cache:
            p = source / file
            cache[file] = read_text(p) if p.is_file() else False
        text = cache[file]
        if text is False:
            errs.append(f"{fid}: cited file does not exist in source: {file}")
            continue
        if text is None:
            unreadable = True  # binary / oversized: cannot be verified, never silently treated as verified
            continue
        n_lines = text.count("\n") + 1
        for key, val in nums.items():
            if val > n_lines:
                errs.append(f"{fid}: {file} has {n_lines} lines; cited {key} {val} is out of range")
                bad = True
        if bad:
            continue
        ranges.append((file, cited_range(text, nums["line"], nums.get("end_line")) if "line" in nums else text, "line" in nums))

    snippet = ev.get("snippet", "")
    if snippet and ranges:
        s, masked = ws_norm(snippet), bool(ev.get("masked"))
        hit = next((has_line for _file, r, has_line in ranges
                    if s in ws_norm(mask_text(r)[0] if masked else r)), None)
        if hit is None:
            kind = "masked evidence snippet does not match the masked form of any cited location/range" if masked else \
                "evidence snippet does not occur within any cited line range"
            errs.append(f"{fid}: {kind} (possible fabricated evidence)")
        else:
            info["snippet_check"] = f"{'masked' if masked else 'verbatim'}-{'range' if hit else 'file'}-match"
    elif snippet and unreadable:
        warns.append(f"{fid}: evidence snippet could not be verified (cited file is binary or too large)")
    if mask_value(f)[1]:
        warns.append(f"{fid}: stored content still contains secret-like values; re-add or update it so it is masked")

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
    return errs, warns, info

def validate_finding(f: dict, source: Path | None, cache: dict) -> tuple[list, list]:
    errs, warns, _info = validate_finding_ex(f, source, cache)
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
    by_fingerprint = {f["fingerprint"]: f for f in store["findings"] if "fingerprint" in f}
    by_identity = {}
    for existing in store["findings"]:
        key = existing.get("identity_key") or normalized_identity_from_finding(existing)
        if key:
            by_identity[key] = existing if key not in by_identity else None
    added = 0
    evidence_added = 0
    store["scan_meta"] = []
    for p in sorted(scan_dir.glob("*.json")):
        d = load_json(p)
        if not isinstance(d, dict) or "candidates" not in d:
            continue
        scanner = d.get("scanner") or p.stem
        store["scan_meta"].append({"scanner": d.get("scanner"), "tools": d.get("tools", {}),
                                   "limitations": d.get("limitations", []), "stats": d.get("stats", {})})
        for c in d["candidates"]:
            fp = fingerprint(c)
            identity = normalized_identity(c)
            match = by_identity.get(identity) if identity else None
            if match is None:
                match = by_fingerprint.get(fp)
            if match is not None:
                if identity and not match.get("identity_key"):
                    match["identity_key"] = identity
                if preserve_evidence_source(match, c, scanner):
                    evidence_added += 1
                continue
            finding = from_candidate(c, store["findings"], scanner)
            store["findings"].append(finding)
            by_fingerprint[fp] = finding
            if identity:
                by_identity[identity] = finding
            added += 1
    store["findings"].sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["id"]))
    store["root_cause_groups"] = build_root_cause_groups(store["findings"])
    store["updated_at"] = now_iso()
    errs, warns = validate_all(store, src if src.is_dir() else None)
    save_json(fpath, store)
    print(f"[merge] +{added} new, +{evidence_added} evidence sources, {len(store['findings'])} total -> {fpath}")
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
    for original in items:
        dom = original.get("domain")
        if dom not in DOMAINS:
            die(f"unknown domain {dom!r}; use one of {', '.join(DOMAINS)}")
        # Mask EVERYTHING the auditor supplied before it is used for anything (fingerprint, validation, messages, storage).
        it, _ = mask_value(original)
        masked_fields = sorted(k for k in it if it[k] != original.get(k))
        ev_changed = it.get("evidence") != original.get("evidence")
        ev = it.get("evidence", {})
        if isinstance(ev, str):
            ev = {"snippet": "", "details": ev}
        ev = dict(ev)
        ev["masked"] = bool(ev.get("masked")) or ev_changed
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
             "history": [{"at": now_iso(), "change": f"added manually as {status}" +
                          (f"; secret masking applied to: {', '.join(masked_fields)}" if masked_fields else "")}]}
        e, _w, info = validate_finding_ex(f, src if src.is_dir() else None, {})
        if e:
            die("finding rejected:\n  " + "\n  ".join(e))
        if ev["masked"]:  # masked evidence stays explicitly masked and records HOW its location was verified
            ev["masking"] = {"method": "secret_mask.mask_text" if ev_changed else "caller-declared",
                             "snippet_check": info["snippet_check"] if ev.get("snippet") else "no-snippet"}
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
    evidence_was_masked = bool(f["evidence"].get("masked"))
    for key in ("severity", "status", "title", "explanation", "impact", "recommendation"):
        val = getattr(args, key, None)
        if isinstance(val, str):
            val = mask_text(val)[0]
        if val is not None and val != f[key]:
            changes.append(f"{key}: {f[key]!r} -> {val!r}")
            f[key] = val
    if args.method:
        f["verification"]["method"] = args.method
    if args.notes is not None:
        f["verification"]["notes"] = mask_text(args.notes)[0]
    if args.snippet is not None:
        snip, ch = mask_text(args.snippet)
        f["evidence"]["snippet"], f["evidence"]["masked"] = snip, ch
        if ch:
            f["evidence"]["masking"] = {"method": "secret_mask.mask_text", "snippet_check": "pending-validation"}
        else:
            f["evidence"].pop("masking", None)
    if args.details is not None:
        det, ch = mask_text(args.details)
        f["evidence"]["details"] = det
        if ch:
            f["evidence"]["masking"] = {"method": "secret_mask.mask_text", "snippet_check": "pending-validation"}
    # A plain-text replacement of one field must not clear masking on the other field.
    f["evidence"]["masked"] = bool(evidence_was_masked or f["evidence"].get("masked") or
                                     mask_text(f["evidence"].get("snippet", ""))[1] or
                                     mask_text(f["evidence"].get("details", ""))[1] or
                                     f["evidence"].get("masking"))
    for loc in args.add_location or []:
        file, _, line = loc.partition(":")
        f["locations"].append({"file": file, **({"line": int(line)} if line else {})})
    st = f["status"]
    f["verification"]["status"] = {"Confirmed": "Verified", "Not Applicable": "Refuted"}.get(st, "Pending")
    f["verification"]["verified_at"] = now_iso() if st in {"Confirmed", "Not Applicable"} else None
    e, _w, info = validate_finding_ex(f, src if src.is_dir() else None, {})
    if e:
        die("update rejected (nothing saved):\n  " + "\n  ".join(e))
    if f["evidence"].get("masking", {}).get("snippet_check") == "pending-validation":
        f["evidence"]["masking"]["snippet_check"] = info["snippet_check"]
    f["history"].append({"at": now_iso(), "change": mask_text("; ".join(changes + ([f"method -> {args.method}"] if args.method else [])))[0] or "updated"})
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
