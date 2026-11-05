#!/usr/bin/env python3
"""AISA pattern scanner: a regex rule engine with noise control.

Every hit is a LEAD with status 'Potential' and method 'static-pattern'. It becomes 'Confirmed'
only after Claude reads the code (findings.py update ... --method manual-code-read).
"""
from __future__ import annotations

import re
from collections import defaultdict

from aisa_common import (candidate, downgrade, is_doc_path, is_example_path, is_noise_file, is_test_path,
                         iter_files, language_of, line_of, read_text, resolve_paths, scanner_parser, write_scan)

PY, JS = {".py"}, {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte"}
DART = {".dart"}
WEB = JS | {".html", ".htm"}
SRC = PY | JS | DART | {".java", ".kt", ".go", ".rs", ".rb", ".php", ".cs", ".swift"}


KW = r"\b(select|insert|update|delete)\b"
SQLI_PY = (r"\.(execute|executemany|raw)\(\s*(f\"[^\"\n]*" + KW + r"[^\"\n]*\{|f'[^'\n]*" + KW + r"[^'\n]*\{"
           r"|\"[^\"\n]*" + KW + r"[^\"\n]*\"\s*(%|\+|\.format)|'[^'\n]*" + KW + r"[^'\n]*'\s*(%|\+|\.format))")
SQLI_JS = (r"\.(query|execute|raw)\(\s*(`[^`\n]*" + KW + r"[^`\n]*\$\{|\"[^\"\n]*" + KW + r"[^\"\n]*\"\s*\+|'[^'\n]*" + KW + r"[^'\n]*'\s*\+)")


def R(id, domain, severity, title, pattern, exts=None, explanation="", impact="", recommendation="",
      cwe=None, flags=re.M, aggregate=False, skip_tests=True, in_comments=False, names=None, max_hits=10):
    return dict(id=id, domain=domain, severity=severity, title=title, pattern=pattern, exts=exts, names=names,
                explanation=explanation, impact=impact, recommendation=recommendation, cwe=cwe, flags=flags,
                aggregate=aggregate, skip_tests=skip_tests, in_comments=in_comments, max_hits=max_hits)


RULES = [
    # ---------------------------------------------------------------- security
    R("PY-EVAL", "SEC", "High", "Dynamic code execution (eval/exec)", r"(?<![\w.])(eval|exec)\s*\(", PY | JS,
      "eval/exec runs a string as code.", "If any part of the string is user-influenced this is remote code execution.",
      "Replace with a safe parser (ast.literal_eval, json.loads) or an explicit dispatch table.", "CWE-95"),
    R("PY-SHELL", "SEC", "High", "Shell command execution",
      r"subprocess\.\w+\([^)\n]*shell\s*=\s*True|\bos\.(system|popen)\(", PY,
      "Commands run through a shell are vulnerable to injection when any argument is dynamic.",
      "Command injection can give an attacker code execution on the host.",
      "Use subprocess with an argument list and shell=False; validate/allow-list arguments.", "CWE-78"),
    R("JS-CMD", "SEC", "High", "Child process execution", r"child_process|\b(execSync|spawnSync)\(|(?<![\w.])exec\(\s*[`'\"]", JS,
      "Spawning processes with interpolated strings invites command injection.", "Command injection.",
      "Use execFile/spawn with argument arrays and validate inputs.", "CWE-78"),
    R("PY-DESER", "SEC", "Medium", "Unsafe deserialization", r"\b(c?[Pp]ickle|marshal)\.loads?\(|\bshelve\.open\(", PY,
      "pickle/marshal can execute arbitrary code when loading untrusted bytes.", "Remote code execution via crafted payload.",
      "Use JSON or another data-only format for untrusted input.", "CWE-502"),
    R("PY-YAML", "SEC", "Medium", "yaml.load without a safe loader", r"yaml\.load\((?![^)\n]*Safe)", PY,
      "yaml.load with the default loader can construct arbitrary objects.", "Code execution from crafted YAML.",
      "Use yaml.safe_load.", "CWE-502"),
    R("SQLI-PY", "SEC", "High", "SQL built by string formatting", SQLI_PY, PY,
      "Queries assembled with f-strings, %, + or .format bypass parameter binding.",
      "SQL injection: data theft, modification or destruction.",
      "Use parameterised queries / ORM bind parameters.", "CWE-89", flags=re.M | re.I),
    R("SQLI-JS", "SEC", "High", "SQL built by string concatenation / template literal", SQLI_JS, JS,
      "Queries assembled from variables bypass parameter binding.", "SQL injection.",
      "Use placeholders ($1/?) and pass values separately.", "CWE-89", flags=re.M | re.I),
    R("TLS-OFF", "SEC", "Medium", "TLS certificate verification disabled",
      r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0|InsecureSkipVerify\s*:\s*true",
      SRC, "Disabling certificate checks removes protection against interception.", "Man-in-the-middle attacks.",
      "Keep verification on; trust a private CA explicitly if needed.", "CWE-295"),
    R("DEBUG-ON", "OPS", "Medium", "Debug mode enabled in code",
      r"app\.run\([^)\n]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True\b", PY,
      "Debug servers expose stack traces and, in Flask/Werkzeug, an interactive console.",
      "Information disclosure and possible remote code execution if reachable.",
      "Drive debug from an environment variable that defaults to off.", "CWE-489"),
    R("CORS-WILD", "API", "Medium", "Wildcard CORS policy",
      r"\bCORS\(\s*app\s*\)|origins?\s*=\s*[\"']\*[\"']|allow_origins\s*=\s*\[\s*[\"']\*|Access-Control-Allow-Origin[\"']?\s*[:,]\s*[\"']\*|origin\s*:\s*[\"']\*[\"']|\bcors\(\s*\)",
      SRC, "Any website can call this API from a user's browser.",
      "Cross-site request abuse, especially if cookies or tokens are used.",
      "Restrict to an explicit allow-list of origins.", "CWE-942"),
    R("WEAK-HASH", "SEC", "Medium", "Weak hash algorithm (MD5/SHA-1)",
      r"hashlib\.(md5|sha1)\(|createHash\(\s*[\"'](md5|sha1)[\"']|MessageDigest\.getInstance\(\s*\"(MD5|SHA-?1)\"",
      SRC, "MD5/SHA-1 are broken for security purposes (fine for non-security checksums).",
      "If used for passwords or signatures, they can be cracked or forged.",
      "Use bcrypt/argon2/scrypt for passwords and SHA-256+ for integrity.", "CWE-327"),
    R("JWT-UNVERIFIED", "SEC", "High", "JWT signature verification disabled",
      r"jwt\.decode\([^)\n]*verify\s*=\s*False|verify_signature[\"']\s*:\s*False|algorithms\s*=\s*\[\s*[\"']none",
      SRC, "Tokens are accepted without checking their signature.", "Authentication bypass by forging tokens.",
      "Always verify signature and pin the algorithm list.", "CWE-347"),
    R("WEAK-RANDOM", "SEC", "Medium", "Non-cryptographic RNG used near secrets/tokens",
      r"(token|secret|password|otp|session|nonce)[^\n]*(Math\.random\(|\brandom\.(random|randint|choice)\()|(Math\.random\(|\brandom\.(random|randint|choice)\()[^\n]*(token|secret|password|otp|session|nonce)",
      PY | JS, "Predictable RNG output can be guessed.", "Token/OTP prediction.",
      "Use secrets / crypto.randomBytes / crypto.getRandomValues.", "CWE-338", flags=re.M | re.I),
    R("XSS-SINK", "SEC", "Medium", "Unsafe HTML injection sink",
      r"\.innerHTML\s*=|\.outerHTML\s*=|dangerouslySetInnerHTML|document\.write\(|\bv-html\b|insertAdjacentHTML\(",
      WEB, "Assigning strings to HTML sinks executes embedded scripts.", "Cross-site scripting.",
      "Use textContent / framework escaping; sanitise with a vetted library if HTML is required.", "CWE-79"),
    R("HARDCODED-LOGIN", "SEC", "High", "Credentials compared against literals",
      r"(password|passwd|pwd)\s*(==|===)\s*[\"'][^\"']{3,}[\"']|(username|user)\s*(==|===)\s*[\"']admin[\"']",
      PY | JS | DART | {".java", ".php"}, "A login check against a literal means a built-in backdoor or fake auth.",
      "Anyone who reads the source (or guesses) can authenticate.", "Verify against hashed credentials in a user store.",
      "CWE-798", flags=re.M | re.I),
    R("OPEN-REDIRECT", "SEC", "Low", "Redirect to request-controlled URL",
      r"redirect\(\s*request\.(args|values|form)|res\.redirect\(\s*req\.(query|body|params)", PY | JS,
      "Redirect targets taken directly from the request.", "Phishing via trusted domain.",
      "Allow-list redirect targets.", "CWE-601"),
    R("PATH-TRAVERSAL", "SEC", "Medium", "File path built from request data",
      r"(open|send_file|send_from_directory|readFile(Sync)?|createReadStream)\([^)\n]*(request\.(args|form|values|json)|req\.(query|params|body))",
      PY | JS, "User-controlled path segments can escape the intended directory.", "Arbitrary file read.",
      "Resolve and verify the final path stays inside an allow-listed base directory.", "CWE-22"),
    # ---------------------------------------------------------------- ops / config
    R("DOCKER-LATEST", "OPS", "Low", "Docker base image not pinned", r"^FROM\s+(\S+:latest|[^:\s@]+)(\s+AS\s+\S+)?\s*$",
      {".dockerfile"}, "Unpinned base images make builds non-reproducible.", "Surprise breakage or supply-chain drift.",
      "Pin to a specific version or digest.", names={"Dockerfile"}),
    R("CURL-PIPE-SH", "OPS", "Medium", "Remote script piped into a shell",
      r"(curl|wget)[^|\n]*\|\s*(sudo\s+)?(ba)?sh\b", None, "Executes unreviewed remote code during build/deploy.",
      "Supply-chain compromise.", "Download, verify checksum/signature, then execute.", "CWE-494", skip_tests=False),
    R("CHMOD-777", "OPS", "Medium", "World-writable permissions", r"chmod\s+(-R\s+)?777", None,
      "Any user on the host can modify these files.", "Privilege escalation / tampering.",
      "Use the minimum permissions required.", "CWE-732"),
    R("HARDCODED-LOCALHOST", "OPS", "Low", "Hard-coded localhost URL in source",
      r"https?://(localhost|127\.0\.0\.1|0\.0\.0\.0)[:/]", SRC | {".html"}, "Environment-specific endpoints are baked in.",
      "Breaks outside the developer machine.", "Read base URLs from configuration.", aggregate=True),
    # ---------------------------------------------------------------- quality / logic
    R("EMPTY-CATCH", "QUA", "Low", "Empty catch block swallows errors", r"catch\s*(\([^)]*\))?\s*\{\s*\}", JS | {".java", ".dart", ".cs"},
      "Errors are silently ignored.", "Failures go unnoticed; state may be corrupt.",
      "Handle, log, or re-throw the error.", "CWE-390", max_hits=5),
    R("BARE-EXCEPT", "QUA", "Low", "Bare except clause", r"^\s*except\s*:", PY, "Catches SystemExit/KeyboardInterrupt and hides bugs.",
      "Masks failures.", "Catch specific exception types.", "CWE-396", max_hits=5),
    R("TODO-MARKERS", "STR", "Low", "TODO/FIXME/HACK markers left in code",
      r"(#|//|/\*|<!--)\s*(TODO|FIXME|HACK|XXX)\b", None, "Unfinished work is flagged by the authors themselves.",
      "Incomplete behaviour may ship.", "Triage each marker: implement, ticket, or delete.", aggregate=True, in_comments=True),
    R("DEBUG-PRINT", "QUA", "Informational", "Debug output left in source", r"^\s*print\(|console\.(log|debug)\(",
      PY | JS, "Debug statements clutter logs and may leak data.", "Noise / information leakage.",
      "Use a structured logger with levels.", aggregate=True),
]


def scan_rules(source, rules, with_ops_checks: bool = True):
    compiled = [(r, re.compile(r["pattern"], r["flags"])) for r in rules]
    hits = defaultdict(list)
    files_scanned = 0
    for p, rel in iter_files(source):
        if is_noise_file(rel):
            continue
        text = read_text(p)
        if text is None:
            continue
        name = rel.rsplit("/", 1)[-1]
        ext = p.suffix.lower()
        files_scanned += 1
        lines = None
        for r, rx in compiled:
            exts, names = r["exts"], r["names"] or ()
            if exts is not None and ext not in exts and name not in names and not any(name.startswith(n) for n in names):
                continue
            if r["skip_tests"] and is_test_path(rel):
                continue
            if is_doc_path(rel) and not (exts and ext in exts):
                continue
            for m in rx.finditer(text):
                if lines is None:
                    lines = text.split("\n")
                ln = line_of(text, m.start())
                snippet = lines[ln - 1].strip()
                if not r["in_comments"] and snippet.startswith(("#", "//", "*", "/*")):
                    continue
                if len(snippet) > 2000:
                    continue
                hits[r["id"]].append((rel, ln, snippet[:240]))
    out = []
    for r in rules:
        h = hits.get(r["id"], [])
        if not h:
            continue
        sev = r["severity"]
        collapse = r["aggregate"] or len(h) > r["max_hits"]
        if collapse:
            nfiles = len({f for f, _, _ in h})
            locs = [{"file": f, "line": ln} for f, ln, _ in h[:15]]
            out.append(candidate(
                r["id"], r["domain"], downgrade(sev) if len(h) > 25 and sev != "Informational" and r["aggregate"] else sev,
                f'{r["title"]} ({len(h)} occurrence(s) in {nfiles} file(s))', locations=locs,
                evidence="; ".join(f"{f}:{ln}: {s[:90]}" for f, ln, s in h[:5]) + (" …" if len(h) > 5 else ""),
                explanation=r["explanation"], impact=r["impact"], recommendation=r["recommendation"], cwe=r["cwe"]))
        else:
            for f, ln, s in h:
                s_sev = downgrade(sev) if is_example_path(f) else sev
                out.append(candidate(r["id"], r["domain"], s_sev, r["title"], file=f, line=ln, evidence=s, verbatim=True,
                                     explanation=r["explanation"], impact=r["impact"],
                                     recommendation=r["recommendation"], cwe=r["cwe"]))
    if with_ops_checks:
        out += dockerfile_checks(source)
    return out, files_scanned


def dockerfile_checks(source):
    out = []
    for p, rel in iter_files(source):
        name = rel.rsplit("/", 1)[-1]
        if name != "Dockerfile" and not name.startswith("Dockerfile."):
            continue
        text = read_text(p) or ""
        users = re.findall(r"^\s*USER\s+(\S+)", text, re.M)
        if not users or users[-1] in {"root", "0"}:
            out.append(candidate("DOCKER-ROOT", "OPS", "Low", "Container runs as root", file=rel,
                                 evidence="no non-root USER instruction" if not users else f"USER {users[-1]}",
                                 explanation="Without a non-root USER the process runs with root privileges inside the container.",
                                 impact="A container escape or app compromise has higher blast radius.",
                                 recommendation="Create an unprivileged user and add a USER instruction.",
                                 cwe="CWE-250", method="config-inspection", status="Confirmed"))
    return out


def main() -> None:
    args = scanner_parser("Regex rule scan (security, ops, quality)").parse_args()
    ws, src, out = resolve_paths(args, "patterns")
    cands, n = scan_rules(src, RULES)
    write_scan(out, "patterns", cands, files_scanned=n, tools={"builtin-rules": len(RULES)})


if __name__ == "__main__":
    main()
