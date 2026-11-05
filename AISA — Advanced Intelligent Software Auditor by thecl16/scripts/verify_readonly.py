#!/usr/bin/env python3
"""AISA read-only proof: recompute the snapshot tree hash and compare it to the one recorded at intake.

    verify_readonly.py --workspace WS        # exit 0 = source unchanged, exit 1 = MODIFIED
Run this at the end of every AUDIT-mode session and quote the result in the report's methodology section.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from aisa_common import die, load_json, now_iso, save_json, tree_hash


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    args = ap.parse_args()
    ws = Path(args.workspace)
    sess = load_json(ws / "session.json")
    if not sess:
        die("session.json missing; run intake.py first")
    current, count = tree_hash(ws / "source")
    ok = current == sess["tree_hash"]
    save_json(ws / "readonly_check.json", {"checked_at": now_iso(), "recorded_hash": sess["tree_hash"], "current_hash": current,
                                          "files": count, "unchanged": ok})
    print(("OK: source snapshot unchanged" if ok else "FAIL: source snapshot was MODIFIED") + f" ({count} files, sha256 {current[:16]}…)")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
