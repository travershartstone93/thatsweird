import contextlib
import io
import json
import os
import re
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

from fixtures import make_proc, make_stub_file  # noqa: E402
from helpers import scan_args  # noqa: E402
from test_arch import ARCH, ArchBox  # noqa: E402

TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
POINTS = re.compile(r"\(([+-]\d+)\)$")
MEMFD_MAPS = [
    "5648cf883000-5648cf885000 r--p 00000000 00:23 1725820                    /tmp/.x/helper",
    "5648cf885000-5648cf890000 r-xp 00002000 00:23 1725820                    /tmp/.x/helper",
    "7f10a0000000-7f10a0100000 r-xp 00000000 00:01 4242                       /memfd:payload (deleted)",
    "7ffd0d3e5000-7ffd0d406000 rw-p 00000000 00:00 0                          [stack]",
]


def reason_points(reasons):
    total = 0
    for reason in reasons:
        match = POINTS.search(reason)
        assert match is not None, reason
        total += int(match.group(1))
    return total


class ReasonBox(ArchBox):
    def flagged(self):
        make_stub_file(self.sysroot, "/tmp/.x/helper")
        self.table[("pacman", "-Qo", "/tmp/.x/helper")] = None
        make_proc(self.proc, 700, "/tmp/.x/helper", maps=MEMFD_MAPS)

    def clean(self):
        self.add_pkg("bash", "5.3.15-2", "/usr/bin/bash", repo="core", packager=ARCH)
        make_proc(self.proc, 100, "/usr/bin/bash")

    def cmd_scan(self, **overrides):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = self.weird.cmd_scan(scan_args(**overrides))
        return out.getvalue(), code


class SignalTable(ReasonBox):
    def test_every_signal_has_technique(self):
        scores = self.weird.load_policy()["scores"]
        table = self.weird.SIGNAL_ATTACK
        self.assertEqual(set(scores), set(table))
        self.assertTrue(self.weird.NON_TECHNIQUE <= set(scores))
        for key, technique in table.items():
            if key in self.weird.NON_TECHNIQUE:
                self.assertEqual(technique, "", key)
            else:
                self.assertRegex(technique, TECHNIQUE, key)
        for key in ("masquerade", "ld_preload", "traced", "elevated_caps", "raw_ip_outbound"):
            self.assertIn(key, scores)


class ReasonsSum(ReasonBox):
    def test_reasons_sum_to_score(self):
        self.flagged()
        proc, alerts, code = self.scan_pid(700)
        self.assertTrue(proc.is_memfd, proc.evidence)
        self.assertIn("memfd_exec", proc.signal_keys)
        self.assertIn("suspicious_path", proc.signal_keys)
        self.assertEqual(len(proc.reasons), len(proc.signal_keys))
        self.assertGreaterEqual(len(proc.reasons), 2)
        self.assertEqual(reason_points(proc.reasons), proc.weirdness_score)
        self.assertEqual(proc.attack[:2], ["T1620", "T1036.005"])
        self.assertEqual(len(proc.attack), len(set(proc.attack)))
        self.assertEqual(self.weird.verdict_for(proc), "Likely malicious")
        self.assertEqual(code, 2)
        self.assertEqual(alerts[0]["verdict"], "Likely malicious")

    def test_rule_upgrade_appends_reason(self):
        self.flagged()
        proc, _, _ = self.scan_pid(700)
        before = proc.weirdness_score
        with mock.patch.object(self.weird, "load_rules", return_value={
            "profiles": {}, "allow": [],
            "rules": [{"id": "helper-in-tmp", "path": {"contains": "/tmp/.x/"}, "action": "upgrade", "add": 7}],
        }):
            self.weird.apply_rules([proc])
        self.assertEqual(proc.weirdness_score, before + 7)
        self.assertEqual(proc.reasons[-1], "Rule helper-in-tmp: upgraded (+7)")
        self.assertEqual(reason_points(proc.reasons), proc.weirdness_score)


class JsonFields(ReasonBox):
    def test_json_contains_attack_and_reasons(self):
        self.clean()
        self.flagged()
        text, code = self.cmd_scan(json=True, verbose=True)
        self.assertEqual(code, 2)
        data = json.loads(text)
        by_pid = {p["pid"]: p for p in data["processes"]}
        self.assertEqual(set(by_pid), {100, 700})
        for p in by_pid.values():
            for key in ("reasons", "attack", "signals", "verdict"):
                self.assertIn(key, p)
            self.assertEqual(reason_points(p["reasons"]), p["weirdness_score"])
        self.assertEqual(by_pid[100]["reasons"], [])
        self.assertEqual(by_pid[100]["attack"], [])
        self.assertEqual(by_pid[100]["verdict"], "")
        self.assertIn("T1620", by_pid[700]["attack"])
        self.assertEqual(by_pid[700]["verdict"], "Likely malicious")

    def test_ndjson_has_same_fields(self):
        self.flagged()
        text, _ = self.cmd_scan(ndjson=True)
        items = [json.loads(line) for line in text.splitlines() if line.strip()]
        self.assertEqual([i["pid"] for i in items], [700])
        self.assertIn("T1620", items[0]["attack"])
        self.assertTrue(items[0]["reasons"])
        self.assertEqual(items[0]["verdict"], "Likely malicious")


class TableReasons(ReasonBox):
    def test_report_items_explain_each_sign(self):
        self.clean()
        self.flagged()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.weird.cmd_scan(scan_args(verbose=True))
        flat = " ".join(out.getvalue().split())
        self.assertIn("helper (pid 700) runs from memory, with no file on disk", flat)
        self.assertIn("It runs code straight from memory instead of a file on disk", flat)
        self.assertIn("It runs from /tmp/.x/helper, where programs are not normally installed.", flat)
        self.assertIn("T1620, T1036.005", flat)
        self.assertIn("bash (pid 100): It comes from the bash package", flat)
        self.assertEqual(flat.count("(pid 100)"), 1)


if __name__ == "__main__":
    unittest.main()
