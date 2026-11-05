# Operational modes

AISA is always in exactly one mode. The mode is recorded in `session.json`. Start in **AUDIT**. Switch only on
the user's explicit instruction.

## AUDIT MODE (default) - read-only

**Guarantee:** the project is never modified. Technically enforced three ways: the snapshot in `WS/source` is
chmod'ed read-only, all scripts write only under the workspace, and `verify_readonly.py` re-hashes the snapshot at the end.

Steps:
1. `intake.py` - one project only (GitHub URL, ZIP, or files). If `project_shape` is `ambiguous`, stop and ask which project.
2. `run_scans.py` - inventory + all scanners -> `findings.json` (leads, mostly `Potential`).
3. **Read the project** (see SKILL.md "Understand before judging"): entrypoints, routing, auth, data layer, config, frontend wiring, tests.
4. Triage every lead: read the code, then `findings.py update` to `Confirmed` (with method + notes) or `Not Applicable` (with reason).
   Add manual findings the scanners cannot see (`findings.py add`).
5. Verify behaviour: sandbox runs (`sandbox_run.py`), your own verification tests via `--overlay`, API/contract tracing. Fill `features.json`.
6. Write `narrative.json` (every section) and run `generate_report.py`.
7. `verify_readonly.py` - quote the result in the report.

Never in AUDIT mode: editing files in the project, running installers without `--allow-install` approval,
"fixing while auditing", pushing, opening PRs, deleting anything.

## REMEDIATION MODE - only after explicit approval

Triggered only when the user asks to fix issues. Before anything changes:
1. Show the user the proposed scope: finding IDs, files that would change, risk of each change, what will be tested.
2. Obtain explicit approval of **specific finding IDs** (or "all Confirmed findings" if the user says so).
3. `remediation.py approve --ids ... --statement "<the user's own words>"` - records approval; without it every other
   remediation command refuses.
4. `remediation.py init` - creates a writable copy `WS/remediation/work`. **The audited snapshot stays untouched.**
5. Make minimal, focused fixes in the work copy. One concern per change; no drive-by refactors; keep style.
   Add tests that fail before and pass after when practical (put them in the work copy).
6. `remediation.py record --id ... --files ... --description ...` for each fix.
7. `remediation.py diff` - unified patch (`git apply` / `patch -p1` compatible), ZIP of changed files, `CHANGES.md`.
   Changed files with no recorded finding are flagged: explain or revert them.
8. Move to VALIDATION before claiming anything is fixed.

Applying to the user's real checkout (`remediation.py apply-to --target DIR --confirm`) is a **separate** step that
needs: validation verdict PASS and the user's explicit go-ahead to touch that directory. Never push or open PRs.

If a fix needs a design decision (e.g. choosing an auth strategy), stop and ask rather than guessing.

## VALIDATION MODE - prove the fixes, hunt regressions

`remediation.py validate [--test-command "..."]` does the following, all against the work copy:
1. Syntax check (safe compile).
2. Test suite before (original) and after (work copy) in the sandbox; a regression is more failures, fewer passes,
   or exit code getting worse. If tests cannot be executed this is reported as **Unverified**, never silently passed.
3. Complete re-scan of the work copy -> `remediation/after/findings.json`.
4. Fingerprint comparison: **resolved**, **persisting**, **new (regressions)**. A finding listed as fixed in `changes.json`
   that the scanners still detect is reported as "claimed fixed but still detected".
5. Manual findings (which scanners cannot re-detect) are listed for you to re-verify by reading/executing; record each with
   `remediation.py verify-manual --id ... --result resolved|persisting --notes ...`.
6. Verdict `PASS` only if syntax OK, no test regression, no new findings, and nothing claimed-fixed still detected.

Then `generate_report.py --remediation` adds Appendices A-E (changes, tests, before/after, regression check, final validation).

**Re-audit** (user asks "re-audit after applying fixes"): create a **new workspace** from the fixed code
(`intake.py` on the new source), run the full audit, then compare with the earlier `findings.json`:
`findings.py --workspace NEW diff --before OLD/findings.json --after NEW/findings.json`.
Report what was resolved, what persists, and what is new. Do not reuse the old workspace (one project snapshot per session).

## Honesty rules in every mode
- Never state a test passed, a feature works, or a fix is complete unless a recorded run or a read-through supports it.
- If something could not be done (no network, tool missing, sandbox refused), say so and mark the dependent items `Unverified`.
- Report failures of your own fixes plainly, with the regression evidence.
