#!/usr/bin/env python3
"""AISA central secret masking (standard library only).

One masking implementation for manual finding ingestion, verification notes and report output.
Detection patterns are imported from scan_secrets.py so the scanner path and the manual path cannot drift apart.
Masking is one-way: this module never stores, logs or returns an original secret value.

    mask_text(text, known=())  -> (masked_text, changed)
    mask_value(obj)            -> (masked_copy, changed)   # str / list / tuple / dict, recursive, input untouched

Secrets found anywhere inside one object are also masked wherever else they appear verbatim in that object
(e.g. a password quoted in the evidence and repeated bare in the explanation).

Heuristics are best-effort: a bare secret with no assignment context, provider prefix or connection-string shape
cannot be recognised. Masked output never equals the source text, so callers must label it as masked.
"""
from __future__ import annotations

import re

from aisa_common import mask_secret
from scan_secrets import DSN, ENV_LINE, GENERIC, PROVIDER, is_placeholder

PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----|\Z)")
# Prose / notes / env-style assignments that GENERIC (quoted literals only) does not cover.
LOOSE = re.compile(
    r"(?i)\b(?P<key>password|passwd|pwd|secret|api[_-]?key|apikey|(?:access|auth|bearer)[_-]?token|token|"
    r"client[_-]?secret|private[_-]?key)\b\s*(?P<sep>[:=]|\bis\b|\bwas\b)\s*[\"']?(?P<val>[^\s\"',;)]{6,})")
ALREADY_MASKED = re.compile(r"…\[|^\*{3,}$")
MIN_PROPAGATE = 8  # shorter values are masked in place only; replacing them everywhere would mangle ordinary text


def _looks_like_code(val: str) -> bool:
    """`password = request.form[...]` and `token = os.getenv(` are code, not credentials."""
    return bool(re.match(r"^[A-Za-z_]\w*(?:\.\w+)+[\[(]?", val) or re.match(r"^[A-Za-z_]\w*\(", val) or val.endswith(("(", "[")))


def _spans(text: str) -> list:
    spans = []
    for m in PRIVATE_KEY_BLOCK.finditer(text):
        spans.append((m.start(), m.end(), "[private key masked]"))
    for _title, pat, _sev in PROVIDER:
        for m in re.finditer(pat, text):
            spans.append((m.start(), m.end(), None))
    for rx in (GENERIC, ENV_LINE, DSN):
        for m in rx.finditer(text):
            val = m.group(2)
            if not val or is_placeholder(val) or ALREADY_MASKED.search(val):
                continue
            if rx is ENV_LINE and _looks_like_code(val):  # ENV_LINE is case-insensitive: `password = request.form[` is code
                continue
            spans.append((m.start(2), m.end(2), None))
    for m in LOOSE.finditer(text):
        val, sep = m.group("val"), m.group("sep").lower()
        if is_placeholder(val) or ALREADY_MASKED.search(val) or _looks_like_code(val):
            continue
        if sep in ("is", "was") and not re.search(r"[\d\W_]", val):
            continue  # "the token is validated" is prose, not a credential
        spans.append((m.start("val"), m.end("val"), None))
    return spans


def _merge(spans: list) -> list:
    out = []
    for s, e, label in sorted(spans, key=lambda x: (x[0], -x[1])):
        if out and s < out[-1][1]:
            continue
        out.append((s, e, label))
    return out


def secret_values(text: str) -> set:
    """Secret values detected in `text` (used only to mask repeats elsewhere; never persisted or returned to callers' output)."""
    if not isinstance(text, str):
        return set()
    return {text[s:e] for s, e, label in _merge(_spans(text)) if label is None and e - s >= MIN_PROPAGATE}


def mask_text(text, known=()):
    """Return (masked_text, changed). Non-strings pass through unchanged."""
    if not isinstance(text, str) or not text:
        return text, False
    spans = _spans(text)
    for k in known:
        i = text.find(k)
        while i != -1:
            spans.append((i, i + len(k), None))
            i = text.find(k, i + len(k))
    spans = _merge(spans)
    if not spans:
        return text, False
    parts, last = [], 0
    for s, e, label in spans:
        parts += [text[last:s], label or mask_secret(text[s:e])]
        last = e
    parts.append(text[last:])
    return "".join(parts), True


def _collect(obj, acc: set) -> None:
    if isinstance(obj, str):
        acc |= secret_values(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _collect(v, acc)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _collect(v, acc)


def mask_value(obj):
    """Return (masked_copy, changed) for nested str/list/tuple/dict data. Dict keys are left as they are."""
    known: set = set()
    _collect(obj, known)
    changed = False

    def walk(o):
        nonlocal changed
        if isinstance(o, str):
            new, ch = mask_text(o, known)
            changed = changed or ch
            return new
        if isinstance(o, dict):
            return {k: walk(v) for k, v in o.items()}
        if isinstance(o, list):
            return [walk(v) for v in o]
        if isinstance(o, tuple):
            return tuple(walk(v) for v in o)
        return o

    return walk(obj), changed
