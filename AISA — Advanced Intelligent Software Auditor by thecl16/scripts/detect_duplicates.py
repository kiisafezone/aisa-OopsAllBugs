#!/usr/bin/env python3
"""AISA duplicate detector: finds copy-pasted blocks via normalised line-window hashing (no dependencies)."""
from __future__ import annotations

import re
from collections import defaultdict
from itertools import combinations

from aisa_common import (CODE_LANGS, candidate, is_noise_file, is_test_path, iter_files, language_of, read_text,
                         resolve_paths, save_json, scanner_parser, write_scan)

WINDOW = 6
MIN_BLOCK = 8
BOILER = re.compile(r"^(import |from \S+ import |using |#include|package |use |require\(|export \{|\}|\{|\)|\]|\);?|end|else:?|try:|finally:|pass)$|^(import |from \S+ import )")
COMMENT = re.compile(r"^(#|//|/\*|\*|--)")


def kept_lines(text):
    out = []
    for i, raw in enumerate(text.split("\n"), 1):
        s = re.sub(r"\s+", " ", raw.strip())
        if not s or COMMENT.match(s) or BOILER.match(s) or len(s) < 4:
            continue
        out.append((i, s))
    return out


def find_blocks(source):
    files, index, total = {}, defaultdict(list), 0
    for p, rel in iter_files(source):
        if is_noise_file(rel) or is_test_path(rel) or language_of(rel) not in CODE_LANGS:
            continue
        t = read_text(p)
        if t is None:
            continue
        kl = kept_lines(t)
        total += len(kl)
        files[rel] = kl
        for i in range(len(kl) - WINDOW + 1):
            index[hash(tuple(s for _, s in kl[i:i + WINDOW]))].append((rel, i))
    runs = defaultdict(list)
    for h, occ in index.items():
        if not 2 <= len(occ) <= 10:
            continue
        for a, b in combinations(sorted(set(occ)), 2):
            if a[0] == b[0] and abs(a[1] - b[1]) < WINDOW:
                continue
            runs[(a[0], b[0], a[1] - b[1])].append(a[1])
    blocks, dup_lines = [], set()
    for (fa, fb, off), starts in runs.items():
        starts.sort()
        s = prev = starts[0]
        for x in starts[1:] + [None]:
            if x is not None and x == prev + 1:
                prev = x
                continue
            length = prev - s + WINDOW
            if length >= MIN_BLOCK:
                la, lb = files[fa], files[fb]
                blocks.append({"length": length,
                               "a": {"file": fa, "start": la[s][0], "end": la[s + length - 1][0]},
                               "b": {"file": fb, "start": lb[s - off][0], "end": lb[s - off + length - 1][0]}})
                dup_lines.update((fa, k) for k in range(s, s + length))
            if x is not None:
                s = prev = x
    seen, uniq = set(), []
    for b in sorted(blocks, key=lambda b: -b["length"]):
        key = (b["a"]["file"], b["a"]["start"], b["b"]["file"], b["b"]["start"])
        rkey = (b["b"]["file"], b["b"]["start"], b["a"]["file"], b["a"]["start"])
        if key in seen or rkey in seen:
            continue
        seen.add(key)
        uniq.append(b)
    return uniq, total, len(dup_lines)


def main() -> None:
    args = scanner_parser("Duplicate block detection").parse_args()
    ws, src, out = resolve_paths(args, "duplicates")
    blocks, total, dup = find_blocks(src)
    ratio = round(100 * dup / total, 1) if total else 0.0
    save_json(out.with_name("duplicates_detail.json"), {"blocks": blocks, "kept_lines": total, "duplicated_lines_approx": dup,
                                                         "duplication_percent_approx": ratio})
    cands = []
    for b in blocks[:25]:
        cands.append(candidate("DUP-BLOCK", "QUA", "Medium" if b["length"] >= 30 else "Low",
                               f"Duplicated code block ({b['length']} significant lines)",
                               locations=[{"file": b["a"]["file"], "line": b["a"]["start"], "end_line": b["a"]["end"]},
                                          {"file": b["b"]["file"], "line": b["b"]["start"], "end_line": b["b"]["end"]}],
                               evidence=f"{b['a']['file']}:{b['a']['start']}-{b['a']['end']} ~ {b['b']['file']}:{b['b']['start']}-{b['b']['end']}",
                               explanation="The same sequence of statements appears in two places (whitespace/comments ignored).",
                               impact="Fixes must be applied twice; copies drift apart and diverge in behaviour.",
                               recommendation="Extract a shared function/module.", method="static-pattern"))
    write_scan(out, "duplicates", cands, tools={"builtin": "used"}, stats={"duplication_percent_approx": ratio, "blocks_total": len(blocks)})


if __name__ == "__main__":
    main()
