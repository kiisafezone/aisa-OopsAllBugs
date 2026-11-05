#!/usr/bin/env python3
"""AISA API tracer: extracts backend routes and client calls, then matches them (heuristic).

Supports Flask/Blueprint, FastAPI/APIRouter, Express, Django urls, Spring mappings on the server side and
fetch/axios/jQuery/dio/http on the client side. Output: scan/api_map.json + candidates for broken links.
All matches are heuristics: unmatched calls are 'Potential', never 'Confirmed', until Claude verifies them.
"""
from __future__ import annotations

import re
from pathlib import Path

from aisa_common import (candidate, is_noise_file, is_test_path, iter_files, line_of, read_text, resolve_paths,
                         save_json, scanner_parser, write_scan)

METHODS = {"get", "post", "put", "delete", "patch", "options", "head"}


def norm_path(raw: str) -> str:
    p = raw.strip()
    p = re.sub(r"^https?://[^/]+", "", p)
    p = re.sub(r"^\$\{[^}]*\}", "", p)           # leading ${BASE_URL}
    p = re.sub(r"^\{\{[^}]*\}\}", "", p)
    p = p.split("?")[0].split("#")[0]
    p = re.sub(r"<[^>]+>|\{[^}]*\}|:[A-Za-z_]\w*|\[[^\]]+\]|\$\{[^}]*\}|\$[A-Za-z_]\w*", "{}", p)
    p = re.sub(r"/+", "/", p)
    if not p.startswith("/"):
        p = "/" + p
    return (p.rstrip("/") or "/").lower()


def is_external(raw: str) -> bool:
    m = re.match(r"^https?://([^/:]+)", raw.strip())
    return bool(m) and m.group(1) not in {"localhost", "127.0.0.1", "0.0.0.0"}


def extract_server(source: Path):
    routes, decl_prefix, inc_prefix = [], {}, {}
    for p, rel in iter_files(source):
        ext = p.suffix.lower()
        if ext not in {".py", ".js", ".ts", ".mjs", ".cjs", ".java", ".kt"} or is_test_path(rel) or is_noise_file(rel):
            continue
        t = read_text(p)
        if t is None:
            continue
        if ext == ".py":
            for m in re.finditer(r"(\w+)\s*=\s*APIRouter\(([^)]*)\)", t):
                pm = re.search(r"prefix\s*=\s*['\"]([^'\"]*)", m.group(2))
                if pm:
                    decl_prefix[m.group(1)] = pm.group(1)
            for m in re.finditer(r"(\w+)\s*=\s*Blueprint\(([^)]*)\)", t):
                pm = re.search(r"url_prefix\s*=\s*['\"]([^'\"]*)", m.group(2))
                if pm:
                    decl_prefix[m.group(1)] = pm.group(1)
            for m in re.finditer(r"(?:include_router|register_blueprint)\(\s*(?:[\w.]*?\.)?(\w+)\s*,[^)]*?(?:prefix|url_prefix)\s*=\s*['\"]([^'\"]*)", t):
                inc_prefix[m.group(1)] = m.group(2)
            for m in re.finditer(r"@(\w+)\.route\(\s*['\"]([^'\"]*)['\"](?:\s*,[^)]*?methods\s*=\s*\[([^\]]*)\])?", t):
                ms = [x.strip(" '\"").lower() for x in (m.group(3) or "get").split(",") if x.strip(" '\"")]
                routes.append({"file": rel, "line": line_of(t, m.start()), "owner": m.group(1), "path": m.group(2),
                               "methods": ms, "framework": "flask"})
            for m in re.finditer(r"@(\w+)\.(get|post|put|delete|patch|options|head)\(\s*['\"]([^'\"]*)['\"]", t):
                routes.append({"file": rel, "line": line_of(t, m.start()), "owner": m.group(1), "path": m.group(3),
                               "methods": [m.group(2)], "framework": "fastapi"})
            if rel.endswith("urls.py"):
                for m in re.finditer(r"\b(?:re_)?path\(\s*r?['\"]([^'\"]*)['\"]", t):
                    routes.append({"file": rel, "line": line_of(t, m.start()), "owner": "", "path": m.group(1),
                                   "methods": ["any"], "framework": "django", "relative": True})
        elif ext in {".js", ".ts", ".mjs", ".cjs"}:
            for m in re.finditer(r"(\w+)\.use\(\s*['\"](/[^'\"]*)['\"]\s*,\s*(\w+)", t):
                inc_prefix[m.group(3)] = m.group(2)
            for m in re.finditer(r"\b(app|router|\w*[Rr]outer|\w*[Rr]outes|server)\.(get|post|put|delete|patch|all)\(\s*['\"`](/[^'\"`]*)['\"`]", t):
                routes.append({"file": rel, "line": line_of(t, m.start()), "owner": m.group(1), "path": m.group(3),
                               "methods": ["any"] if m.group(2) == "all" else [m.group(2)], "framework": "express"})
        else:
            for m in re.finditer(r"@(Get|Post|Put|Delete|Patch|Request)Mapping\(\s*(?:value\s*=\s*|path\s*=\s*)?\{?\s*\"([^\"]*)\"", t):
                routes.append({"file": rel, "line": line_of(t, m.start()), "owner": "", "path": m.group(2),
                               "methods": ["any" if m.group(1) == "Request" else m.group(1).lower()],
                               "framework": "spring", "relative": True})
    for r in routes:
        pre = inc_prefix.get(r["owner"], "") + decl_prefix.get(r["owner"], "")
        r["full_path"] = norm_path((pre.rstrip("/") + "/" + r["path"].lstrip("/")) if pre else r["path"])
    return routes


CLIENT_PATTERNS = [
    (r"\bfetch\(\s*['\"`]([^'\"`]+)['\"`](?:\s*,\s*\{[^}]*?method\s*:\s*['\"](\w+)['\"])?", "fetch"),
    (r"\baxios\.(get|post|put|delete|patch)\(\s*['\"`]([^'\"`]+)['\"`]", "axios"),
    (r"\b(?:api|http|client|request|apiClient|httpClient)\.(get|post|put|delete|patch)\(\s*['\"`]([^'\"`]+)['\"`]", "client"),
    (r"\$\.(get|post|getJSON)\(\s*['\"`]([^'\"`]+)['\"`]", "jquery"),
    (r"\bdio\.(get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]", "dio"),
    (r"\bhttp\.(get|post|put|delete|patch)\(\s*Uri\.parse\(\s*['\"]([^'\"]+)['\"]", "dart-http"),
    (r"\brequests\.(get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]", "requests"),
]


def extract_clients(source: Path):
    calls = []
    for p, rel in iter_files(source):
        ext = p.suffix.lower()
        if ext not in {".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".html", ".dart", ".mjs", ".py"} or is_test_path(rel) or is_noise_file(rel):
            continue
        t = read_text(p)
        if t is None:
            continue
        for pat, kind in CLIENT_PATTERNS:
            if kind == "requests" and ext != ".py":
                continue
            if kind not in {"requests"} and ext == ".py":
                continue
            for m in re.finditer(pat, t):
                if kind == "fetch":
                    raw, method = m.group(1), (m.group(2) or "get").lower()
                else:
                    method, raw = m.group(1).lower(), m.group(2)
                    method = "get" if method == "getjson" else method
                if not (raw.startswith(("/", "http", "${", "{{"))):
                    continue
                calls.append({"file": rel, "line": line_of(t, m.start()), "raw": raw, "method": method, "kind": kind,
                              "external": is_external(raw), "path": None if is_external(raw) else norm_path(raw)})
    return calls


def match(calls, routes):
    matched, unmatched, used = [], [], set()
    for c in calls:
        if c["external"]:
            continue
        hit = None
        for i, r in enumerate(routes):
            rp = r["full_path"]
            same = rp == c["path"]
            suffix = r.get("relative") and (c["path"].endswith(rp) or rp.endswith(c["path"]))
            prefix_base = not same and not suffix and (c["path"].endswith(rp) and rp != "/" and len(rp) > 3)
            if same or suffix or prefix_base:
                hit = (i, r)
                break
        if hit:
            used.add(hit[0])
            r = hit[1]
            ok_method = "any" in r["methods"] or c["method"] in r["methods"]
            matched.append({"call": c, "route": r, "method_ok": ok_method})
        else:
            unmatched.append(c)
    return matched, unmatched, used


def main() -> None:
    args = scanner_parser("Frontend/backend API tracer").parse_args()
    ws, src, out = resolve_paths(args, "api")
    routes, calls = extract_server(src), extract_clients(src)
    matched, unmatched, used = match(calls, routes)
    unused = [r for i, r in enumerate(routes) if i not in used]
    external = sorted({c["raw"] for c in calls if c["external"]})
    save_json(out.with_name("api_map.json"), {
        "routes": routes, "calls": calls, "matched": [{"call": m["call"]["raw"], "route": m["route"]["full_path"],
                                                      "method_ok": m["method_ok"]} for m in matched],
        "unmatched_calls": unmatched, "unused_routes": unused, "external_urls": external,
        "note": "Heuristic extraction; verify dynamic URLs, API gateways, proxies and generated clients manually."})
    cands = []
    for c in unmatched:
        cands.append(candidate("API-NO-ROUTE", "API", "Medium", f"Client calls {c['method'].upper()} {c['path']} but no matching backend route was found",
                               file=c["file"], line=c["line"], evidence=f"{c['kind']}: {c['raw']}",
                               explanation="No route with this path was found in the scanned server code. It may be a typo, a renamed "
                                           "endpoint, an unimplemented backend feature, or served by something outside this project.",
                               impact="The feature backed by this call fails at runtime (404/network error).",
                               recommendation="Align the client path with a real route, or implement the endpoint.",
                               cwe=None, method="static-pattern"))
    for m in matched:
        if not m["method_ok"]:
            c, r = m["call"], m["route"]
            cands.append(candidate("API-METHOD-MISMATCH", "API", "Medium", f"Client uses {c['method'].upper()} on {c['path']} but route allows {','.join(r['methods']).upper()}",
                                   file=c["file"], line=c["line"], evidence=f"{c['kind']}: {c['raw']} vs {r['file']}:{r['line']}",
                                   explanation="HTTP method differs between caller and handler.", impact="405 Method Not Allowed at runtime.",
                                   recommendation="Use the method the route accepts or extend the route.", method="static-pattern"))
    if unused:
        cands.append(candidate("API-UNUSED-ROUTE", "API", "Informational", f"{len(unused)} backend route(s) are never called by the scanned client code",
                               locations=[{"file": r["file"], "line": r["line"]} for r in unused[:15]],
                               evidence="; ".join(f"{r['full_path']}" for r in unused[:8]),
                               explanation="Routes may be used by other clients, webhooks or be dead code.",
                               impact="Dead or undocumented attack surface.", recommendation="Confirm each is intended; remove or document.",
                               method="static-pattern"))
    if calls and not routes:
        cands.append(candidate("API-NO-BACKEND", "ARC", "Medium", "Client makes internal API calls but no backend routes were found",
                               evidence=f"{len([c for c in calls if not c['external']])} internal call(s), 0 routes extracted",
                               explanation="The backend may live elsewhere or use an unsupported framework.",
                               impact="Cannot verify frontend/backend integration.", recommendation="Verify manually; record scope limitation.",
                               status="Unverified", method="not-verified"))
    write_scan(out, "api", cands, tools={"builtin": "used"},
               limitations=["Route/call matching is regex-based and heuristic (no framework execution)."],
               stats={"routes": len(routes), "calls": len(calls), "matched": len(matched), "unmatched": len(unmatched)})


if __name__ == "__main__":
    main()
