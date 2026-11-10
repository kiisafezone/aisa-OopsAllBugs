#!/usr/bin/env python3
"""AISA Anti-Slop scanner.

'Slop' = code or claims that look like finished work but are not: mock data in production paths, fake
async, dead buttons, stubs, README claims with nothing behind them, imports of packages nobody declared
(hallucinated dependencies), leftover AI artifacts, commented-out code.
Outputs scan/antislop.json (candidates) and scan/claims.json (claim-vs-evidence table).
"""
from __future__ import annotations

import ast
import json
import re
import sys
import tomllib
from pathlib import Path

from aisa_common import (candidate, downgrade, is_doc_path, is_noise_file, is_test_path, iter_files, language_of,
                         read_text, resolve_paths, save_json, scanner_parser, write_scan)
from scan_patterns import R, SRC, JS, PY, DART, WEB, scan_rules

SLOP_RULES = [
    R("SLOP-LOREM", "SLP", "Medium", "Placeholder text (lorem ipsum) in source", r"lorem ipsum|dolor sit amet", WEB | PY | DART,
      "Filler text shipped in application code.", "Users may see placeholder content.", "Replace with real content or remove.",
      flags=re.M | re.I),
    R("SLOP-MOCK-LIB", "SLP", "Medium", "Mock/fake-data library used outside tests",
      r"(from faker import|import faker\b|require\(['\"]faker|@faker-js/faker|from unittest\.mock|^import mock\b|jest\.mock\(|\bsinon\b|from mockito|package:mocktail)",
      SRC, "Mocking/fake-data tooling imported in non-test code.", "Mock data or behaviour can leak into production paths.",
      "Move mocks into tests or behind an explicit dev-only flag.", flags=re.M),
    R("SLOP-MOCK-DATA", "SLP", "Medium", "Hard-coded mock/dummy data structure",
      r"\b(mock|dummy|fake|sample|stub)_?(data|users?|response|items|products|orders|list|api|results?)\b\s*[:=]",
      SRC, "Variables named as mock data are assigned in application code.",
      "The UI/API may display or return fabricated data as if it were real.",
      "Replace with real data access or isolate behind a clearly named dev fixture.", flags=re.M | re.I, max_hits=6),
    R("SLOP-FAKE-ASYNC", "SLP", "Medium", "Simulated network delay (fake async)",
      r"new Promise\(\s*\(?\s*resolve[^)]*\)?\s*=>\s*setTimeout|\bFuture\.delayed\(", JS | DART,
      "A timer stands in for a real request.", "Feature looks wired up but never talks to a backend.",
      "Call the real API; keep artificial delays only in tests/demos.", max_hits=6),
    R("SLOP-DEAD-HANDLER", "UIX", "Medium", "Empty event handler (dead button/control)",
      r"on(Click|Press|Pressed|Tap|Submit|Change)\s*[=:]\s*\{?\s*\(\s*\)\s*(=>\s*\{\s*\}|\{\s*(//[^\n]*)?\s*\})\s*\}?|onPressed\s*:\s*null|addEventListener\([^,]+,\s*\(\s*\)\s*=>\s*\{\s*\}\s*\)",
      JS | DART, "The control renders but does nothing when used.", "Users cannot complete the advertised action.",
      "Implement the handler or remove/disable the control.", max_hits=6),
    R("SLOP-DEAD-LINK", "UIX", "Low", "Link to '#' placeholder", r"href\s*=\s*[\"']#[\"']", {".html", ".htm", ".jsx", ".tsx", ".vue"},
      "Navigation element points nowhere.", "Dead navigation.", "Point to a real route or use a button.", aggregate=True),
    R("SLOP-ELISION", "SLP", "Medium", "Elided code marker left in source",
      r"(#|//)\s*\.\.\.\s*(rest|existing|remaining|other)\b|(#|//)\s*(rest|remaining) of (the )?(code|implementation|file)|as an ai language model|here is the (updated|complete|full) (code|file)",
      None, "Typical leftover from pasting AI-generated snippets where part of the code was replaced by a comment.",
      "Required logic may be missing entirely.", "Inspect the surrounding code and restore the omitted implementation.",
      in_comments=True, flags=re.M | re.I, skip_tests=False),
    R("SLOP-SHORTCUT-NOTES", "SLP", "Low", "Comments admitting shortcuts",
      r"(#|//)\s*(in a real (app|world|implementation)|in production,? (you|this|we)|for (now|demo|demonstration)|demo only|simplified|temporary (fix|hack)|quick (fix|hack)|hardcoded for)",
      None, "The authors note the code is not production-grade.", "Known shortcuts may ship unnoticed.",
      "Track each shortcut as a ticket or fix it.", in_comments=True, aggregate=True, flags=re.M | re.I),
    R("SLOP-PLACEHOLDER-ID", "SLP", "Low", "Placeholder identities/emails in non-test code",
      r"\b(john\.?doe|jane\.?doe|foo@bar\.com|test@test\.com|user@example\.com|example@example\.com|admin@admin\.com)\b",
      SRC | {".html"}, "Dummy identities appear in application code.", "Fake accounts or contact data may be live.",
      "Remove or isolate in seed/test data.", flags=re.M | re.I, aggregate=True),
]

CLAIMS = [
    ("production-ready", r"production[- ]ready|enterprise[- ]grade|battle[- ]tested", None,
     "Readiness claims need independent verification (see Production Readiness Assessment)."),
    ("fully tested", r"fully tested|100\s?% (test )?coverage|comprehensive (test|tests|testing)|well[- ]tested|extensively tested",
     "tests", "Tests are claimed."),
    ("secure", r"\b(bank|military)[- ]grade\b|highly secure|fully secure|end[- ]to[- ]end encrypt", None,
     "Security claims need verification in the Security domain."),
    ("ci/cd", r"\bci/cd\b|continuous (integration|delivery|deployment)|github actions", "ci", "A CI/CD pipeline is claimed."),
    ("docker", r"\bdocker(ized|ised)?\b|\bkubernetes\b|\bk8s\b|\bhelm\b", "docker", "Containerisation is claimed."),
    ("realtime", r"real[- ]time|websockets?|socket\.io|server[- ]sent events", r"websocket|socket\.io|\bsse\b|EventSource|channels|signalr",
     "Real-time behaviour is claimed."),
    ("ai/ml", r"\bai[- ]powered\b|machine learning|\bllm\b|\bgpt\b|neural|recommendation engine|smart (assistant|analysis)",
     r"openai|anthropic|tensorflow|torch|sklearn|scikit|transformers|langchain|keras|xgboost|gemini|huggingface|onnx|llama",
     "AI/ML capability is claimed."),
    ("scalable", r"highly scalable|infinitely scalable|scales to|horizontal(ly)? scal", None, "Scalability claims need load evidence."),
    ("payments", r"payment (gateway|processing)|stripe|midtrans|xendit|paypal", r"stripe|midtrans|xendit|paypal|payment",
     "Payment processing is claimed."),
    ("auth", r"\boauth\b|\bsso\b|two[- ]factor|\b2fa\b|role[- ]based access|\brbac\b", r"oauth|jwt|passport|authlib|totp|pyotp|rbac|role",
     "An authentication/authorisation capability is claimed."),
]

STDLIB = set(getattr(sys, "stdlib_module_names", set())) | {"__future__"}
PY_DIST_ALIASES = {
    "yaml": "pyyaml", "pil": "pillow", "cv2": "opencv-python", "sklearn": "scikit-learn", "bs4": "beautifulsoup4",
    "dotenv": "python-dotenv", "jwt": "pyjwt", "dateutil": "python-dateutil", "psycopg2": "psycopg2-binary",
    "flask_cors": "flask-cors", "flask_sqlalchemy": "flask-sqlalchemy", "flask_migrate": "flask-migrate",
    "google": "protobuf", "serial": "pyserial", "attr": "attrs", "magic": "python-magic", "OpenSSL": "pyopenssl",
    "Crypto": "pycryptodome", "jose": "python-jose", "multipart": "python-multipart", "socketio": "python-socketio",
    "engineio": "python-engineio", "markdown": "markdown", "docx": "python-docx", "pptx": "python-pptx",
}
NODE_BUILTINS = {"assert", "async_hooks", "buffer", "child_process", "cluster", "console", "constants", "crypto", "dgram",
                 "dns", "domain", "events", "fs", "http", "http2", "https", "inspector", "module", "net", "os", "path",
                 "perf_hooks", "process", "punycode", "querystring", "readline", "repl", "stream", "string_decoder",
                 "timers", "tls", "trace_events", "tty", "url", "util", "v8", "vm", "worker_threads", "zlib", "test"}


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def collect_py_declared(source: Path):
    declared, found = set(), False
    for p, rel in iter_files(source):
        name = rel.rsplit("/", 1)[-1]
        t = read_text(p)
        if t is None:
            continue
        if name.startswith("requirements") and name.endswith(".txt"):
            found = True
            for ln in t.splitlines():
                ln = ln.split("#", 1)[0].strip()
                m = re.match(r"^([A-Za-z0-9_.\-]+)", ln)
                if m and not ln.startswith("-"):
                    declared.add(norm(m.group(1)))
        elif name == "pyproject.toml":
            found = True
            try:
                d = tomllib.loads(t)
            except tomllib.TOMLDecodeError:
                continue
            for s in (d.get("project") or {}).get("dependencies", []) or []:
                declared.add(norm(re.split(r"[ <>=!~;\[]", s, 1)[0]))
            for s in ((d.get("tool") or {}).get("poetry") or {}).get("dependencies", {}) or {}:
                declared.add(norm(s))
        elif name in {"Pipfile", "setup.py", "setup.cfg"}:
            found = True
            for m in re.finditer(r"['\"]?([A-Za-z0-9_.\-]+)['\"]?\s*(?:[=<>~!]=|=\s*['\"]\*)", t):
                declared.add(norm(m.group(1)))
            for m in re.finditer(r"['\"]([A-Za-z0-9_.\-]+)(?:[<>=!~][^'\"]*)?['\"]", t):
                declared.add(norm(m.group(1)))
    return declared, found


def local_python_names(source: Path):
    names = set()
    for p, rel in iter_files(source):
        parts = rel.split("/")
        for d in parts[:-1]:
            names.add(d)
        if rel.endswith(".py"):
            names.add(parts[-1][:-3])
    return names


def phantom_python(source: Path):
    declared, found = collect_py_declared(source)
    out = []
    if not found:
        return out, "no Python dependency manifest; import check skipped"
    local = local_python_names(source)
    seen = {}
    for p, rel in iter_files(source):
        if not rel.endswith(".py") or is_test_path(rel):
            continue
        t = read_text(p)
        if t is None:
            continue
        try:
            tree = ast.parse(t)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            mods = []
            if isinstance(node, ast.Import):
                mods = [(a.name.split(".")[0], node.lineno) for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                mods = [(node.module.split(".")[0], node.lineno)]
            for top, ln in mods:
                if top in STDLIB or top in local:
                    continue
                dist = norm(PY_DIST_ALIASES.get(top, PY_DIST_ALIASES.get(top.lower(), top)))
                if dist in declared or norm(top) in declared:
                    continue
                seen.setdefault(top, []).append((rel, ln))
    for top, locs in sorted(seen.items()):
        out.append(candidate(
            "PHANTOM-DEP-PY", "SLP", "Medium", f"Import '{top}' is not declared, local, or standard library",
            locations=[{"file": f, "line": l} for f, l in locs[:8]],
            evidence=f"import of '{top}' in {len(locs)} place(s); not found in requirements/pyproject",
            explanation="The code imports a package that no manifest declares. It may be a hallucinated/misnamed "
                        "dependency, a transitive dependency relied on by accident, or an import-name/package-name mismatch.",
            impact="Fresh installs fail with ImportError, or a typo-squatted package could be installed.",
            recommendation="Verify the package exists on PyPI under the intended name and declare it with a pinned version.",
            method="static-ast"))
    return out, None


def phantom_js(source: Path):
    declared, found, manifests = set(), False, 0
    for p, rel in iter_files(source):
        if rel.rsplit("/", 1)[-1] == "package.json":
            t = read_text(p) or ""
            try:
                d = json.loads(t)
            except json.JSONDecodeError:
                continue
            manifests += 1
            found = True
            for sec in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                declared |= set((d.get(sec) or {}).keys())
            if d.get("name"):
                declared.add(d["name"])
    if not found:
        return [], "no package.json; JS import check skipped"
    dirs = set()
    for p, rel in iter_files(source):
        for d in rel.split("/")[:-1]:
            dirs.add(d)
    rx = re.compile(r"(?:import\s+(?:[^'\"`;]*?\s+from\s+)?|require\(\s*|import\(\s*)['\"]([^'\"]+)['\"]")
    seen = {}
    for p, rel in iter_files(source):
        if p.suffix.lower() not in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte"} or is_test_path(rel):
            continue
        t = read_text(p)
        if t is None:
            continue
        for m in rx.finditer(t):
            spec = m.group(1)
            if spec.startswith((".", "/", "@/", "~", "#", "node:", "http:", "https:", "data:")):
                continue
            pkg = "/".join(spec.split("/")[:2]) if spec.startswith("@") else spec.split("/")[0]
            if pkg in NODE_BUILTINS or pkg in declared or pkg in dirs:
                continue
            seen.setdefault(pkg, []).append((rel, t.count("\n", 0, m.start()) + 1))
    out = []
    for pkg, locs in sorted(seen.items()):
        out.append(candidate(
            "PHANTOM-DEP-JS", "SLP", "Medium", f"Import '{pkg}' is not declared in any package.json",
            locations=[{"file": f, "line": l} for f, l in locs[:8]],
            evidence=f"import of '{pkg}' in {len(locs)} place(s); not in dependencies/devDependencies",
            explanation="Possible hallucinated or undeclared dependency (or a path alias this check cannot resolve).",
            impact="Build/runtime failure on a clean install.", recommendation="Verify the package exists and declare it, or fix the import path.",
            method="static-ast"))
    return out, None


def phantom_dart(source: Path):
    declared, own, found = set(), set(), False
    for p, rel in iter_files(source):
        if rel.rsplit("/", 1)[-1] == "pubspec.yaml":
            found = True
            t = read_text(p) or ""
            declared |= set(re.findall(r"^  ([a-z0-9_]+):", t, re.M))
            m = re.search(r"^name:\s*([a-z0-9_]+)", t, re.M)
            if m:
                own.add(m.group(1))
    if not found:
        return [], None
    seen = {}
    for p, rel in iter_files(source):
        if p.suffix != ".dart":
            continue
        t = read_text(p) or ""
        for m in re.finditer(r"import\s+['\"]package:([a-z0-9_]+)/", t):
            pkg = m.group(1)
            if pkg not in declared and pkg not in own and pkg != "flutter":
                seen.setdefault(pkg, []).append((rel, t.count("\n", 0, m.start()) + 1))
    return [candidate("PHANTOM-DEP-DART", "SLP", "Medium", f"Dart package '{pkg}' imported but not in pubspec.yaml",
                      locations=[{"file": f, "line": l} for f, l in locs[:8]],
                      evidence=f"package:{pkg} imported in {len(locs)} place(s)", explanation="Undeclared dependency.",
                      impact="Build failure on clean checkout.", recommendation="Add it to pubspec.yaml or remove the import.",
                      method="static-ast") for pkg, locs in sorted(seen.items())], None


def commented_code(source: Path):
    py = re.compile(r"^\s*#\s*(def |class |import |from \w+ import |return\b|if .*:\s*$|for .*:\s*$|print\(|\w+\s*=\s*\S)")
    js = re.compile(r"^\s*//\s*(function |const |let |var |import |return\b|if \(|for \(|console\.|\w+\s*=\s*\S.*;\s*$)")
    out = []
    for p, rel in iter_files(source):
        lang = language_of(rel)
        if lang not in {"Python", "JavaScript", "TypeScript", "Dart", "Java", "Go"} or is_test_path(rel):
            continue
        t = read_text(p)
        if t is None:
            continue
        rx = py if lang == "Python" else js
        hits = [i + 1 for i, ln in enumerate(t.splitlines()) if rx.match(ln)]
        if len(hits) >= 6:
            out.append(candidate("SLOP-COMMENTED-CODE", "SLP", "Low", f"Large amount of commented-out code ({len(hits)} lines)",
                                 file=rel, line=hits[0], evidence=f"{len(hits)} commented lines look like code",
                                 explanation="Dead code kept in comments instead of version control.",
                                 impact="Noise; hides what is really active.", recommendation="Delete it; git remembers.",
                                 method="static-pattern"))
    return out


def claims_vs_reality(source: Path):
    docs = []
    for p, rel in iter_files(source):
        if "/" not in rel and re.match(r"(?i)^(readme|docs?)(\.\w+)?$", rel) or (rel.lower().startswith("docs/") and rel.endswith(".md")):
            t = read_text(p)
            if t:
                docs.append((rel, t))
    code_blob, test_files, ci, docker = [], 0, False, False
    for p, rel in iter_files(source):
        if re.match(r"^\.github/workflows/", rel) or rel.endswith((".gitlab-ci.yml", "Jenkinsfile")):
            ci = True
        if re.search(r"(^|/)(Dockerfile(\..+)?|docker-compose\.ya?ml)$", rel) or re.search(r"(^|/)(k8s|kubernetes|helm)/", rel):
            docker = True
        if is_test_path(rel) and language_of(rel) in {"Python", "JavaScript", "TypeScript", "Dart", "Java", "Go"}:
            test_files += 1
        if not is_doc_path(rel) and language_of(rel):
            t = read_text(p)
            if t:
                code_blob.append(t.lower())
    blob = "\n".join(code_blob)
    cands, table = [], []
    for rel, text in docs:
        for label, claim_rx, probe, note in CLAIMS:
            m = re.search(claim_rx, text, re.I)
            if not m:
                continue
            ln = text.count("\n", 0, m.start()) + 1
            if probe == "tests":
                ok, ev = test_files > 0, f"{test_files} test file(s)"
            elif probe == "ci":
                ok, ev = ci, "CI configuration present" if ci else "no CI configuration"
            elif probe == "docker":
                ok, ev = docker, "container files present" if docker else "no Dockerfile/compose/k8s files"
            elif probe:
                hit = re.search(probe, blob, re.I)
                ok, ev = bool(hit), f"code mentions '{hit.group(0)}'" if hit else "no matching library or usage found in code"
            else:
                ok, ev = None, "cannot be verified from presence alone"
            row = {"claim": label, "file": rel, "line": ln, "text": m.group(0), "probe_result":
                   "supported-by-presence" if ok else ("unverified" if ok is None else "no-evidence"), "evidence": ev}
            table.append(row)
            if ok is False:
                cands.append(candidate(
                    "CLAIM-NO-EVIDENCE", "SLP", "Medium" if label in {"fully tested", "ai/ml", "payments", "auth"} else "Low",
                    f"Documentation claims '{m.group(0)}' but the code shows no evidence", file=rel, line=ln,
                    evidence=f"{note} Probe: {ev}.", explanation="A feature or quality claim in the docs has nothing behind it in the code.",
                    impact="Misleading documentation; users and stakeholders may rely on capabilities that do not exist.",
                    recommendation="Implement the capability or correct the documentation.", method="documentation-review"))
            elif ok is None:
                cands.append(candidate(
                    "CLAIM-UNVERIFIED", "SLP", "Informational", f"Unverified claim: '{m.group(0)}'", file=rel, line=ln,
                    evidence=note, explanation="A strong claim that presence-checks cannot confirm.",
                    impact="Claim may be unsupported.", recommendation="Verify during the relevant audit domain; qualify or remove the claim if unsupported.",
                    status="Unverified", method="documentation-review"))
    return cands, table


NOTIMPL_PATTERN = re.compile(
    r"""NotImplementedError|unimplemented!\\(\\)|UnimplementedError\\(|throw new Error\\(["']not implemented|coming soon|under construction""",
    re.M | re.I,
)


def _decorator_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    return ""


def _protocol_base(node):
    if isinstance(node, ast.Name):
        return node.id == "Protocol"
    if isinstance(node, ast.Attribute):
        return node.attr == "Protocol"
    return False


def intentional_python_stub_lines(source_text):
    """Return lines inside explicitly abstract methods or direct Protocol methods.

    Deliberately does not exempt every method on an ABC: ABCs may contain concrete
    methods, and a NotImplementedError there can still indicate unfinished work.
    """
    try:
        tree = ast.parse(source_text)
    except SyntaxError:
        return set()

    intentional = set()

    class StubVisitor(ast.NodeVisitor):
        def visit_ClassDef(self, node):
            protocol = any(_protocol_base(base) for base in node.bases)
            for member in node.body:
                if not isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                decorators = {_decorator_name(item) for item in member.decorator_list}
                if protocol or decorators.intersection({"abstractmethod", "abstractclassmethod", "abstractstaticmethod"}):
                    end = getattr(member, "end_lineno", member.lineno) or member.lineno
                    intentional.update(range(member.lineno, end + 1))
            self.generic_visit(node)

    StubVisitor().visit(tree)
    return intentional


def scan_not_implemented(source):
    """Find unfinished markers, excluding only statically recognized Python stubs."""
    hits = []
    for path, rel in iter_files(source):
        if is_noise_file(rel) or is_test_path(rel) or is_doc_path(rel):
            continue
        if path.suffix.lower() not in SRC:
            continue
        text = read_text(path)
        if text is None:
            continue
        intentional = intentional_python_stub_lines(text) if path.suffix.lower() == ".py" else set()
        lines = text.splitlines()
        for match in NOTIMPL_PATTERN.finditer(text):
            line = text.count("\\n", 0, match.start()) + 1
            if line in intentional:
                continue
            snippet = lines[line - 1].strip() if line <= len(lines) else ""
            hits.append((rel, line, snippet[:240]))

    if not hits:
        return []
    locations = [{"file": rel, "line": line} for rel, line, _ in hits[:15]]
    files_count = len({rel for rel, _, _ in hits})
    severity = downgrade("Medium") if len(hits) > 25 else "Medium"
    return [candidate(
        "SLOP-NOTIMPL", "LOG", severity,
        f"Explicit 'not implemented' marker ({len(hits)} occurrence(s) in {files_count} file(s))",
        locations=locations,
        evidence="; ".join(f"{rel}:{line}: {snippet[:90]}" for rel, line, snippet in hits[:5])
                 + (" …" if len(hits) > 5 else ""),
        explanation="Code contains an explicit marker that may indicate unfinished functionality.",
        impact="A live code path may be incomplete at runtime.",
        recommendation="Implement the behaviour, or keep the limitation explicit and out of live paths.",
    )]


def main() -> None:
    args = scanner_parser("Anti-Slop scan").parse_args()
    ws, src, out = resolve_paths(args, "antislop")
    cands, _ = scan_rules(src, SLOP_RULES, with_ops_checks=False)
    cands += scan_not_implemented(src)
    limitations = []
    for fn in (phantom_python, phantom_js, phantom_dart):
        c, note = fn(src)
        cands += c
        if note:
            limitations.append(note)
    cands += commented_code(src)
    c, table = claims_vs_reality(src)
    cands += c
    save_json(out.with_name("claims.json"), {"claims": table})
    write_scan(out, "antislop", cands, tools={"builtin": "used"}, limitations=limitations)


if __name__ == "__main__":
    main()
