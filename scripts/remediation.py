#!/usr/bin/env python3
"""AISA REMEDIATION and VALIDATION modes.

The audited snapshot (WS/source) is NEVER edited. Fixes are made in a copy (WS/remediation/work) and shipped
as a patch + ZIP. Nothing happens before the user has approved specific finding IDs.

    remediation.py --workspace WS approve --ids AISA-SEC-001,AISA-SEC-002 --statement "user: fix the SQL injections"
    remediation.py --workspace WS init                       # creates the writable work copy
    ... edit files under WS/remediation/work ...
    remediation.py --workspace WS record --id AISA-SEC-001 --files backend/app.py --description "parameterised query"
    remediation.py --workspace WS diff                       # patch + ZIP + CHANGES.md
    remediation.py --workspace WS validate [--test-command "python3 -m pytest -q"]
    remediation.py --workspace WS verify-manual --id AISA-X --result resolved --notes "re-read file, fixed"
    remediation.py --workspace WS apply-to --target /path/to/checkout --confirm   # only after validation PASS
"""
from __future__ import annotations

import argparse
import difflib
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

from aisa_common import (copy_tree_writable, die, iter_files, load_json, now_iso, read_text, save_json, tree_hash)

HERE = Path(__file__).resolve().parent


def rem_dir(ws: Path) -> Path:
    return ws / "remediation"


def need_approval(ws: Path) -> dict:
    a = load_json(rem_dir(ws) / "approval.json")
    if not a or not a.get("approved_ids"):
        die("NO APPROVAL RECORDED. Ask the user which findings to fix and run `remediation.py approve` first. "
            "AISA never changes code without explicit approval.")
    return a


def source_unchanged(ws: Path) -> None:
    sess = load_json(ws / "session.json") or {}
    h, _ = tree_hash(ws / "source")
    if h != sess.get("tree_hash"):
        die("the audited snapshot (WS/source) no longer matches its recorded hash; refusing to continue. "
            "Re-run intake in a fresh workspace.")


def cmd_approve(args, ws):
    store = load_json(ws / "findings.json")
    if not store:
        die("no findings.json; run the audit first")
    by_id = {f["id"]: f for f in store["findings"]}
    if args.all_confirmed:
        ids = [i for i, f in by_id.items() if f["status"] == "Confirmed"]
    else:
        ids = [x.strip() for x in (args.ids or "").split(",") if x.strip()]
    if not ids:
        die("give --ids ID[,ID...] or --all-confirmed")
    unknown = [i for i in ids if i not in by_id]
    if unknown:
        die(f"unknown finding id(s): {', '.join(unknown)}")
    if not args.statement.strip():
        die("--statement must quote what the user actually said to approve the changes")
    save_json(rem_dir(ws) / "approval.json", {"approved_at": now_iso(), "approved_ids": ids, "user_statement": args.statement})
    sess = load_json(ws / "session.json")
    sess["mode"], sess["approved_finding_ids"] = "REMEDIATION", ids
    save_json(ws / "session.json", sess)
    print(f"[approve] {len(ids)} finding(s) approved for remediation. Mode: REMEDIATION")


def cmd_init(args, ws):
    need_approval(ws)
    source_unchanged(ws)
    work = rem_dir(ws) / "work"
    if work.exists():
        die(f"{work} already exists")
    copy_tree_writable(ws / "source", work)
    save_json(rem_dir(ws) / "changes.json", {"changes": []})
    print(f"[init] writable work copy at {work}. Edit ONLY files there.")


def cmd_record(args, ws):
    appr = need_approval(ws)
    if args.id not in appr["approved_ids"]:
        die(f"{args.id} was not approved by the user; refusing to record a change for it")
    ch = load_json(rem_dir(ws) / "changes.json", {"changes": []})
    ch["changes"].append({"finding_id": args.id, "files": [f.strip() for f in args.files.split(",")],
                          "description": args.description, "recorded_at": now_iso()})
    save_json(rem_dir(ws) / "changes.json", ch)
    print(f"[record] {args.id}: {args.files}")


def unified(rel, a_text, b_text):
    a = a_text.splitlines(keepends=True) if a_text is not None else []
    b = b_text.splitlines(keepends=True) if b_text is not None else []
    diff = difflib.unified_diff(a, b, fromfile="/dev/null" if a_text is None else f"a/{rel}",
                                tofile="/dev/null" if b_text is None else f"b/{rel}", n=3)
    return "".join(ln if ln.endswith("\n") else ln + "\n\\ No newline at end of file\n" for ln in diff)


def cmd_diff(args, ws):
    appr = need_approval(ws)
    source_unchanged(ws)
    src, work = ws / "source", rem_dir(ws) / "work"
    if not work.is_dir():
        die("run `init` first")
    a = {rel: p for p, rel in iter_files(src, ignore=False)}
    b = {rel: p for p, rel in iter_files(work, ignore=False)}
    patch, changed, binary = [], [], []
    for rel in sorted(set(a) | set(b)):
        ab = a[rel].read_bytes() if rel in a else None
        bb = b[rel].read_bytes() if rel in b else None
        if ab == bb:
            continue
        changed.append({"file": rel, "kind": "added" if ab is None else "deleted" if bb is None else "modified"})
        at = None if ab is None else read_text(a[rel])
        bt = None if bb is None else read_text(b[rel])
        if (ab is not None and at is None) or (bb is not None and bt is None):
            binary.append(rel)
            continue
        patch.append(unified(rel, at, bt))
    out_dir = rem_dir(ws) / "patches"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "aisa-remediation.patch").write_text("".join(patch), encoding="utf-8")
    ch = load_json(rem_dir(ws) / "changes.json", {"changes": []})["changes"]
    recorded = {f for c in ch for f in c["files"]}
    unrecorded = [c["file"] for c in changed if c["file"] not in recorded]
    md = ["# AISA remediation changes", "", f"Generated {now_iso()}", "", f"Approved findings: {', '.join(appr['approved_ids'])}", ""]
    for c in ch:
        md.append(f"- **{c['finding_id']}**: {c['description']} (`{'`, `'.join(c['files'])}`)")
    if unrecorded:
        md += ["", "## Changed files with no recorded finding (review!)", *[f"- `{f}`" for f in unrecorded]]
    (out_dir / "CHANGES.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    zpath = rem_dir(ws) / "aisa-remediation.zip"
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(out_dir / "aisa-remediation.patch", "aisa-remediation.patch")
        zf.write(out_dir / "CHANGES.md", "CHANGES.md")
        for c in changed:
            if c["kind"] != "deleted":
                zf.write(work / c["file"], f"changed-files/{c['file']}")
    save_json(rem_dir(ws) / "diff_summary.json", {"changed": changed, "binary_files_not_in_patch": binary,
                                                    "unrecorded_changes": unrecorded, "generated_at": now_iso()})
    print(f"[diff] {len(changed)} file(s) changed; patch -> {out_dir / 'aisa-remediation.patch'}; zip -> {zpath}")
    if unrecorded:
        print("WARNING: changed files without a recorded finding:", ", ".join(unrecorded))
    if binary:
        print("NOTE: binary files changed; they are in the ZIP but not in the patch:", ", ".join(binary))


def run_script(name, *a):
    return subprocess.run([sys.executable, str(HERE / name), *a], capture_output=True, text=True)


def cmd_validate(args, ws):
    appr = need_approval(ws)
    source_unchanged(ws)
    work = rem_dir(ws) / "work"
    if not work.is_dir():
        die("run `init` and make the fixes first")
    after = rem_dir(ws) / "after"
    result = {"validated_at": now_iso(), "checks": {}}
    r = run_script("sandbox_run.py", "--workspace", str(ws), "--source", str(work), "--kind", "syntax", "--label", "after-syntax")
    syn = load_json(ws / "runs" / "after-syntax.json", {})
    result["checks"]["syntax"] = {"exit_code": syn.get("exit_code"), "ok": syn.get("exit_code") == 0}
    tests_ok, test_info = True, None
    if args.test_command:
        extra = ["--accept-no-isolation"] if args.accept_no_isolation else []
        run_script("sandbox_run.py", "--workspace", str(ws), "--source", str(ws / "source"), "--label", "before-tests",
                   "--command", args.test_command, *extra)
        run_script("sandbox_run.py", "--workspace", str(ws), "--source", str(work), "--label", "after-tests",
                   "--command", args.test_command, *extra)
        b, a = load_json(ws / "runs" / "before-tests.json", {}), load_json(ws / "runs" / "after-tests.json", {})
        if a.get("verdict") != "executed" or b.get("verdict") != "executed":
            tests_ok = False
            test_info = {"note": "tests could not be executed (refused or failed to start); regression status Unverified",
                         "before": b.get("reason"), "after": a.get("reason")}
        else:
            bc, ac = b.get("counts", {}), a.get("counts", {})
            regress = (ac.get("failed", 0) > bc.get("failed", 0)) or (ac.get("passed", 0) < bc.get("passed", 0)) or \
                      (a.get("exit_code") != 0 and b.get("exit_code") == 0)
            tests_ok = not regress
            test_info = {"before": {"exit_code": b.get("exit_code"), "counts": bc}, "after": {"exit_code": a.get("exit_code"), "counts": ac},
                         "regression": regress}
    result["checks"]["tests"] = test_info or {"note": "no --test-command given; test regression Unverified"}
    run_script("run_scans.py", "--workspace", str(ws), "--source", str(work), "--out-dir", str(after / "scan"),
               "--findings", str(after / "findings.json"), "--inventory", str(after / "inventory.json"))
    before_f, after_f = load_json(ws / "findings.json", {"findings": []}), load_json(after / "findings.json", {"findings": []})
    live_before = {f["fingerprint"]: f for f in before_f["findings"] if f["status"] != "Not Applicable"}
    live_after = {f["fingerprint"]: f for f in after_f["findings"] if f["status"] != "Not Applicable"}
    manual = {k: f for k, f in live_before.items() if k.startswith("manual-") or f.get("source", {}).get("tool") == "claude-manual"}
    resolved = [f["id"] for k, f in live_before.items() if k not in live_after and k not in manual]
    persisting = [f["id"] for k, f in live_before.items() if k in live_after]
    regressions = [{"id": f["id"], "title": f["title"], "severity": f["severity"], "locations": f["locations"][:2]}
                   for k, f in live_after.items() if k not in live_before]
    mv = load_json(rem_dir(ws) / "manual_verification.json", {"results": []})["results"]
    manual_pending = [f["id"] for f in manual.values() if f["id"] not in {m["id"] for m in mv}]
    claimed = {c["finding_id"] for c in load_json(rem_dir(ws) / "changes.json", {"changes": []})["changes"]}
    still = [i for i in claimed if i in persisting]
    result.update({"before_after": {"resolved": resolved, "persisting": persisting, "new_regressions": regressions,
                                    "manual_findings_needing_reverification": manual_pending,
                                    "claimed_fixed_but_still_detected": still},
                   "counts": {"before": len(live_before), "after": len(live_after)}})
    ok = result["checks"]["syntax"]["ok"] and tests_ok and not regressions and not still
    result["verdict"] = "PASS" if ok else "FAIL"
    result["unverified"] = ([] if args.test_command else ["test regression (no test command provided)"]) + \
                           ([f"manual findings not yet re-verified: {', '.join(manual_pending)}"] if manual_pending else [])
    save_json(rem_dir(ws) / "validation.json", result)
    print(f"[validate] verdict={result['verdict']} resolved={len(resolved)} persisting={len(persisting)} "
          f"regressions={len(regressions)} before={len(live_before)} after={len(live_after)}")
    for k in ("claimed_fixed_but_still_detected",):
        if still:
            print("  claimed fixed but still detected:", ", ".join(still))
    for reg in regressions:
        print(f"  REGRESSION: {reg['id']} {reg['severity']} {reg['title']}")
    if manual_pending:
        print("  re-verify manually (then `verify-manual`):", ", ".join(manual_pending))
    sys.exit(0 if ok else 1)


def cmd_verify_manual(args, ws):
    need_approval(ws)
    if not args.notes.strip():
        die("--notes must say what was re-read/run to reach this conclusion")
    p = rem_dir(ws) / "manual_verification.json"
    d = load_json(p, {"results": []})
    d["results"] = [r for r in d["results"] if r["id"] != args.id] + [
        {"id": args.id, "result": args.result, "notes": args.notes, "at": now_iso()}]
    save_json(p, d)
    print(f"[verify-manual] {args.id}: {args.result}")


def cmd_apply_to(args, ws):
    need_approval(ws)
    val = load_json(rem_dir(ws) / "validation.json")
    if not val or val.get("verdict") != "PASS":
        die("validation has not passed; refusing to apply. Run `validate` and fix regressions first.")
    if not args.confirm:
        die("add --confirm (only after the user explicitly agreed to modify the target)")
    target = Path(args.target)
    patch = rem_dir(ws) / "patches" / "aisa-remediation.patch"
    if not target.is_dir() or not patch.exists():
        die("target directory or patch missing")
    if (target / ".git").exists() and not args.allow_dirty:
        st = subprocess.run(["git", "-C", str(target), "status", "--porcelain"], capture_output=True, text=True)
        if st.stdout.strip():
            die("target has uncommitted changes; commit/stash them or pass --allow-dirty")
    if shutil.which("git"):
        chk = subprocess.run(["git", "apply", "--check", str(patch.resolve())], cwd=target, capture_output=True, text=True)
        if chk.returncode != 0:
            die("patch does not apply cleanly:\n" + chk.stderr[-600:])
        r = subprocess.run(["git", "apply", str(patch.resolve())], cwd=target, capture_output=True, text=True)
    else:
        r = subprocess.run(["patch", "-p1", "-i", str(patch.resolve())], cwd=target, capture_output=True, text=True)
    if r.returncode != 0:
        die("applying the patch failed:\n" + (r.stderr or r.stdout)[-600:])
    save_json(rem_dir(ws) / "applied.json", {"applied_at": now_iso(), "target": str(target)})
    print(f"[apply-to] patch applied to {target}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("approve"); a.add_argument("--ids"); a.add_argument("--all-confirmed", action="store_true")
    a.add_argument("--statement", required=True)
    sub.add_parser("init")
    r = sub.add_parser("record"); r.add_argument("--id", required=True); r.add_argument("--files", required=True); r.add_argument("--description", required=True)
    sub.add_parser("diff")
    v = sub.add_parser("validate"); v.add_argument("--test-command"); v.add_argument("--accept-no-isolation", action="store_true")
    m = sub.add_parser("verify-manual"); m.add_argument("--id", required=True); m.add_argument("--result", required=True, choices=["resolved", "persisting"])
    m.add_argument("--notes", required=True)
    t = sub.add_parser("apply-to"); t.add_argument("--target", required=True); t.add_argument("--confirm", action="store_true"); t.add_argument("--allow-dirty", action="store_true")
    args = ap.parse_args()
    ws = Path(args.workspace)
    {"approve": cmd_approve, "init": cmd_init, "record": cmd_record, "diff": cmd_diff, "validate": cmd_validate,
     "verify-manual": cmd_verify_manual, "apply-to": cmd_apply_to}[args.cmd](args, ws)


if __name__ == "__main__":
    main()
