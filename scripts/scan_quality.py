#!/usr/bin/env python3
"""AISA quality scanner: Python AST analysis (stubs, complexity, swallowed errors, dead code)
plus size outliers for every language. AST facts are deterministic -> method 'static-ast'.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

from aisa_common import (CODE_LANGS, candidate, is_noise_file, is_test_path, iter_files, language_of, read_text,
                         resolve_paths, scanner_parser, write_scan)

ACTION_NAMES = re.compile(
    r"^(validate|verify|authenticate|authorize|check_?(auth|permission|password)|save|send|process|encrypt|decrypt|hash|"
    r"sanitize|sanitise|charge|pay|refund|notify|sync|upload|delete|create|update|calculate|compute|login|logout|"
    r"register|sign_?in|sign_?up|submit|publish|transfer|withdraw|deposit)", re.I)
MUTABLE_DEFAULTS = (ast.List, ast.Dict, ast.Set)


def complexity(fn) -> int:
    n = 1
    for node in ast.walk(fn):
        if isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.IfExp, ast.Assert)):
            n += 1
        elif isinstance(node, ast.BoolOp):
            n += len(node.values) - 1
        elif isinstance(node, ast.comprehension):
            n += 1 + len(node.ifs)
        elif hasattr(ast, "match_case") and isinstance(node, ast.match_case):
            n += 1
    return n


def max_depth(node, d=0) -> int:
    best = d
    for child in ast.iter_child_nodes(node):
        inc = 1 if isinstance(child, (ast.If, ast.For, ast.While, ast.Try, ast.With, ast.AsyncFor, ast.AsyncWith)) else 0
        best = max(best, max_depth(child, d + inc))
    return best


def body_without_doc(fn):
    body = list(fn.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) \
            and isinstance(body[0].value.value, str):
        body = body[1:]
    return body


def is_const_return(stmt) -> bool:
    if not isinstance(stmt, ast.Return):
        return False
    v = stmt.value
    if v is None or isinstance(v, ast.Constant):
        return True
    return isinstance(v, (ast.List, ast.Dict, ast.Tuple)) and not (getattr(v, "elts", None) or getattr(v, "keys", None))


def analyze_python(rel, text, src_lines):
    out = []
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        return [candidate("PY-SYNTAX", "LOG", "High", "Python file does not parse", file=rel, line=exc.lineno,
                          evidence=f"SyntaxError: {exc.msg} (parsed with Python {sys.version_info.major}.{sys.version_info.minor})",
                          explanation="The file cannot be imported/executed under this interpreter. If it targets a different "
                                      "Python version, verify before treating as a defect.",
                          impact="Module fails at import time.", recommendation="Fix the syntax error.",
                          method="static-ast", status="Potential")]
    def ast_name(value):
        if isinstance(value, ast.Name):
            return value.id
        if isinstance(value, ast.Attribute):
            return value.attr
        if isinstance(value, ast.Subscript):
            return ast_name(value.value)
        if isinstance(value, ast.Call):
            return ast_name(value.func)
        return ""

    class_nodes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
    protocol_nodes = {
        id(node) for node in class_nodes
        if any(ast_name(base) == "Protocol" for base in node.bases)
    }
    protocol_names = {node.name for node in class_nodes if id(node) in protocol_nodes}
    changed = True
    while changed:
        changed = False
        for cls in class_nodes:
            if id(cls) not in protocol_nodes and any(ast_name(base) in protocol_names for base in cls.bases):
                protocol_nodes.add(id(cls))
                protocol_names.add(cls.name)
                changed = True

    protocol_methods = set()
    for cls in class_nodes:
        if id(cls) in protocol_nodes:
            protocol_methods.update(id(item) for item in cls.body
                                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)))

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            name, line = node.name, node.lineno
            decos = {ast_name(d) for d in node.decorator_list}
            body = body_without_doc(node)
            protocol_stub = id(node) in protocol_methods and len(body) == 1 and (
                isinstance(body[0], ast.Pass)
                or (isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant)
                    and body[0].value.value is Ellipsis))
            abstractish = bool(decos & {"abstractmethod", "overload"}) or protocol_stub
            dunder = name.startswith("__") and name.endswith("__")
            end = getattr(node, "end_lineno", line) or line
            if not abstractish and not dunder and len(body) == 1 and (
                    isinstance(body[0], ast.Pass)
                    or (isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant)
                        and body[0].value.value is Ellipsis)):
                out.append(candidate("PY-STUB", "SLP", "Medium", f"Stub function '{name}' has no implementation", file=rel,
                                     line=line, evidence=f"def {name}(...): body is only pass/Ellipsis",
                                     explanation="The function exists but does nothing.", impact="Callers get silent no-ops; "
                                     "the feature appears present but is not implemented.",
                                     recommendation="Implement it, raise NotImplementedError explicitly, or remove it.",
                                     method="static-ast", status="Confirmed"))
            elif not abstractish and not dunder and body and all(is_const_return(s) for s in body) and ACTION_NAMES.match(name):
                seg = "\n".join(src_lines[line - 1:end]).lower()
                has_marker = bool(re.search(r"todo|fixme|placeholder|stub|mock|fake|not implemented|for now|temporary", seg))
                out.append(candidate("PY-FAKE-ACTION", "SLP", "Medium" if has_marker else "Low",
                                     f"Function '{name}' only returns a constant", file=rel, line=line,
                                     evidence=f"def {name}(...): returns a constant" + (" (with TODO/placeholder marker)" if has_marker else ""),
                                     explanation="Its name promises real work (validation, payment, persistence, auth ...) but the body "
                                                 "just returns a fixed value.",
                                     impact="Behaviour is faked: callers believe the action happened.",
                                     recommendation="Implement the real behaviour or make the limitation explicit.",
                                     method="static-ast", status="Potential"))
            for default in list(node.args.defaults) + [d for d in node.args.kw_defaults if d is not None]:
                if isinstance(default, MUTABLE_DEFAULTS):
                    out.append(candidate("PY-MUTABLE-DEFAULT", "LOG", "Low", f"Mutable default argument in '{name}'", file=rel,
                                         line=line, evidence="mutable list/dict/set used as default value",
                                         explanation="Default objects are created once and shared across calls.",
                                         impact="State leaks between calls.", recommendation="Default to None and create inside.",
                                         method="static-ast", status="Confirmed", cwe="CWE-1188"))
                    break
            cx = complexity(node)
            if cx >= 11:
                out.append(candidate("PY-COMPLEXITY", "QUA", "Medium" if cx >= 20 else "Low",
                                     f"High cyclomatic complexity in '{name}' ({cx})", file=rel, line=line,
                                     evidence=f"cyclomatic complexity {cx}", explanation="Many branches make the function hard to "
                                     "test and reason about.", impact="Bug-prone, hard to modify.",
                                     recommendation="Split into smaller functions; replace branching with data/dispatch.",
                                     method="static-ast", status="Confirmed"))
            length = end - line + 1
            if length > 100:
                out.append(candidate("PY-LONG-FUNC", "QUA", "Medium" if length > 200 else "Low",
                                     f"Long function '{name}' ({length} lines)", file=rel, line=line,
                                     evidence=f"{length} lines", explanation="Long functions mix responsibilities.",
                                     impact="Hard to review and test.", recommendation="Extract cohesive helpers.",
                                     method="static-ast", status="Confirmed"))
            nparams = len(node.args.args) + len(node.args.kwonlyargs)
            if nparams > 8:
                out.append(candidate("PY-MANY-PARAMS", "QUA", "Low", f"Function '{name}' takes {nparams} parameters", file=rel,
                                     line=line, evidence=f"{nparams} parameters", explanation="Wide signatures hint at missing abstractions.",
                                     impact="Error-prone call sites.", recommendation="Group related parameters into objects.",
                                     method="static-ast", status="Confirmed"))
            if max_depth(node) > 4:
                out.append(candidate("PY-DEEP-NESTING", "QUA", "Low", f"Deep nesting in '{name}'", file=rel, line=line,
                                     evidence=f"nesting depth {max_depth(node)}", explanation="Deeply nested control flow is hard to follow.",
                                     impact="Readability and bug risk.", recommendation="Use early returns and helper functions.",
                                     method="static-ast", status="Confirmed"))
        if isinstance(node, ast.ExceptHandler):
            only_pass = len(node.body) == 1 and isinstance(node.body[0], (ast.Pass, ast.Continue))
            if only_pass:
                broad = node.type is None or (isinstance(node.type, ast.Name) and node.type.id in {"Exception", "BaseException"})
                out.append(candidate("PY-SWALLOW", "LOG", "Medium" if broad else "Low", "Exception swallowed silently", file=rel,
                                     line=node.lineno, evidence="except block contains only pass/continue",
                                     explanation="Errors are caught and discarded.", impact="Failures go unnoticed and state may be inconsistent.",
                                     recommendation="Log and handle, or narrow the exception and re-raise.",
                                     method="static-ast", status="Confirmed", cwe="CWE-390"))
        for attr in ("body", "orelse", "finalbody"):
            block = getattr(node, attr, None)
            if isinstance(block, list):
                for i, stmt in enumerate(block[:-1]):
                    if isinstance(stmt, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
                        nxt = block[i + 1]
                        out.append(candidate("PY-UNREACHABLE", "LOG", "Low", "Unreachable code after return/raise/break",
                                             file=rel, line=nxt.lineno, evidence=f"statement at line {nxt.lineno} can never run",
                                             explanation="Code follows an unconditional exit in the same block.",
                                             impact="Dead code, often a sign of a logic error.", recommendation="Remove or fix the control flow.",
                                             method="static-ast", status="Confirmed"))
                        break
    return out


def scan(source):
    cands, big = [], []
    for p, rel in iter_files(source):
        if is_noise_file(rel):
            continue
        lang = language_of(rel)
        if lang not in CODE_LANGS:
            continue
        text = read_text(p)
        if text is None:
            continue
        nloc = sum(1 for ln in text.splitlines() if ln.strip())
        if nloc > 1000 and not is_test_path(rel):
            big.append((nloc, rel))
        if lang == "Python" and not is_test_path(rel):
            cands += analyze_python(rel, text, text.split("\n"))
    for nloc, rel in sorted(big, reverse=True)[:10]:
        cands.append(candidate("BIG-FILE", "QUA", "Low", f"Very large source file ({nloc} lines)", file=rel,
                               evidence=f"{nloc} non-blank lines", explanation="Large files usually mix responsibilities.",
                               impact="Merge conflicts, hard navigation.", recommendation="Split by responsibility.",
                               method="static-ast", status="Confirmed"))
    return cands


def main() -> None:
    args = scanner_parser("Python AST quality scan").parse_args()
    ws, src, out = resolve_paths(args, "quality")
    write_scan(out, "quality", scan(src), tools={"python-ast": "used"},
               limitations=["AST analysis covers Python only; other languages receive pattern and size checks."])


if __name__ == "__main__":
    main()
