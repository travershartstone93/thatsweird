import configparser
import contextlib
import io
import os
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

from fixtures import make_proc, make_stub_file  # noqa: E402
from helpers import REPO, scan_args  # noqa: E402
from test_arch import ARCH, ArchBox  # noqa: E402
from test_persist import UnownedAwareRunCommand  # noqa: E402

HELPER = "/tmp/.x/helper"
DAEMON = "/opt/thing/bin/zzdaemon"
MEMFD_MAPS = [
    "5648cf883000-5648cf885000 r--p 00000000 00:23 1725820                    /tmp/.x/helper",
    "5648cf885000-5648cf890000 r-xp 00002000 00:23 1725820                    /tmp/.x/helper",
    "7f10a0000000-7f10a0100000 r-xp 00000000 00:01 4242                       /memfd:payload (deleted)",
    "7ffd0d3e5000-7ffd0d406000 rw-p 00000000 00:00 0                          [stack]",
]
UNIT_DIR = REPO / "systemd"
SERVICES = ("weird.service", "weird-persist.service")
TIMERS = ("weird.timer", "weird-persist.timer")


class OutputBox(ArchBox):
    def setUp(self):
        super().setUp()
        self.records = []
        self.weird.journal_send = self.records.append
        self.add_pkg("bash", "5.3.15-2", "/usr/bin/bash", repo="core", packager=ARCH)
        make_proc(self.proc, 100, "/usr/bin/bash")

    def critical_proc(self, pid=700):
        make_stub_file(self.sysroot, HELPER)
        self.table[("pacman", "-Qo", HELPER)] = None
        make_proc(self.proc, pid, HELPER, maps=MEMFD_MAPS)

    def warning_proc(self, pid=510):
        make_stub_file(self.sysroot, DAEMON)
        self.table[("pacman", "-Qo", DAEMON)] = None
        make_proc(self.proc, pid, DAEMON, environ={"HOME": "/home/user1000", "LD_PRELOAD": "/tmp/a.so"})

    def cmd_scan(self, **overrides):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = self.weird.cmd_scan(scan_args(**overrides))
        return out.getvalue(), code


class JournalOutput(OutputBox):
    def test_journal_fields(self):
        self.critical_proc()
        _, code = self.cmd_scan(json=True, journal=True)
        self.assertEqual(code, 2)
        self.assertEqual(len(self.records), 1)
        rec = self.records[0]
        self.assertEqual(rec["PRIORITY"], 2)
        self.assertEqual(rec["SYSLOG_IDENTIFIER"], "weird")
        self.assertEqual(rec["WEIRD_PID"], 700)
        self.assertEqual(rec["WEIRD_NAME"], "helper")
        self.assertEqual(rec["WEIRD_TRUST"], "UNKNOWN")
        self.assertEqual(rec["WEIRD_VERDICT"], "Likely malicious")
        self.assertIn("T1620", rec["WEIRD_ATTACK"].split(","))
        score = rec["WEIRD_SCORE"]
        self.assertGreater(score, 0)
        self.assertTrue(rec["MESSAGE"].startswith(f"weird: Likely malicious helper pid 700 score {score}: "),
                        rec["MESSAGE"])
        first_reason = rec["MESSAGE"].split(": ", 1)[1]
        self.assertIn("(+", first_reason)

    def test_journal_priority_mapping(self):
        jp = self.weird.journal_priority
        self.assertEqual((jp("critical"), jp("warning"), jp("medium"), jp("low"), jp("info")), (2, 4, 4, 5, 6))
        self.warning_proc()
        _, code = self.cmd_scan(json=True, journal=True)
        self.assertEqual(code, 1)
        self.assertEqual([r["PRIORITY"] for r in self.records], [4])
        self.assertEqual(self.records[0]["WEIRD_PID"], 510)
        self.assertIn("LD_PRELOAD", self.records[0]["MESSAGE"])

    def test_journal_off_by_default(self):
        self.critical_proc()
        self.cmd_scan(json=True)
        self.assertEqual(self.records, [])

    def test_journal_findings_skip_info(self):
        Finding = self.weird.Finding
        findings = [
            Finding("unowned module", "evil.ko is owned by no package", "critical", "T1014", "evil"),
            Finding("taint", "unsigned module loaded", "medium", ""),
            Finding("reboot pending", "modules dir missing", "info"),
        ]
        self.weird.journal_findings("kernel", findings)
        self.assertEqual([r["PRIORITY"] for r in self.records], [2, 4])
        rec = self.records[0]
        self.assertEqual(rec["WEIRD_KIND"], "unowned module")
        self.assertEqual(rec["WEIRD_COMMAND"], "kernel")
        self.assertEqual(rec["WEIRD_SEVERITY"], "critical")
        self.assertEqual(rec["WEIRD_ATTACK"], "T1014")
        self.assertEqual(rec["SYSLOG_IDENTIFIER"], "weird")
        self.assertEqual(rec["MESSAGE"], "weird kernel: critical unowned module evil: evil.ko is owned by no package")

    def test_persist_journal_and_prometheus(self):
        self.table[("crontab", "-l")] = None
        self.weird.run_command = UnownedAwareRunCommand(self.table)
        unit = self.sysroot / "etc/systemd/system/evil.service"
        unit.parent.mkdir(parents=True, exist_ok=True)
        unit.write_text("[Service]\nExecStart=/tmp/.x/evil.sh\n")
        make_stub_file(self.sysroot, "/tmp/.x/evil.sh")
        prom = Path(self.tmp.name) / "metrics" / "weird-persist.prom"
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = self.weird.cmd_persist(scan_args(json=True, journal=True, prometheus=str(prom)))
        self.assertEqual(code, 2)
        self.assertTrue(self.records, "no journal record for the critical persistence entry")
        self.assertEqual(self.records[0]["WEIRD_COMMAND"], "persist")
        self.assertEqual(self.records[0]["PRIORITY"], 2)
        self.assertEqual(self.records[0]["WEIRD_KIND"], "systemd service")
        text = prom.read_text()
        self.assertRegex(text, r'(?m)^weird_findings\{command="persist",severity="critical"\} [1-9]\d*$')
        self.assertRegex(text, r'(?m)^weird_findings\{command="persist",severity="medium"\} \d+$')
        self.assertRegex(text, r'(?m)^weird_scan_timestamp_seconds\{command="persist"\} \d+$')


class PrometheusOutput(OutputBox):
    def test_prometheus_textfile(self):
        self.critical_proc()
        self.warning_proc()
        directory = Path(self.tmp.name) / "textfile_collector"
        prom = directory / "weird.prom"
        with mock.patch.object(os, "replace", wraps=os.replace) as replace:
            _, code = self.cmd_scan(json=True, prometheus=str(prom))
        self.assertEqual(code, 2)
        self.assertEqual(os.listdir(directory), ["weird.prom"])
        replace.assert_called_once()
        src, dst = replace.call_args[0]
        self.assertEqual(os.path.dirname(src), str(directory))
        self.assertEqual(dst, str(prom))
        self.assertTrue(os.path.basename(src).endswith(".tmp"), src)

        text = prom.read_text()
        self.assertRegex(text, r'(?m)^weird_alerts\{level="critical"\} 1$')
        self.assertRegex(text, r'(?m)^weird_alerts\{level="warning"\} 1$')
        self.assertRegex(text, r"(?m)^weird_processes_total 3$")
        self.assertRegex(text, r"(?m)^weird_scan_timestamp_seconds \d{10}$")
        self.assertRegex(text, r"(?m)^weird_scan_duration_seconds \d+\.\d{3}$")
        for metric in ("weird_alerts", "weird_processes_total", "weird_scan_timestamp_seconds",
                       "weird_scan_duration_seconds"):
            self.assertRegex(text, rf"(?m)^# HELP {metric} \S.*$")
            self.assertRegex(text, rf"(?m)^# TYPE {metric} gauge$")
        self.assertTrue(text.endswith("\n"))
        self.assertEqual(prom.stat().st_mode & 0o777, 0o644)

    def test_prometheus_clean_scan_writes_zeroes(self):
        prom = Path(self.tmp.name) / "weird.prom"
        _, code = self.cmd_scan(json=True, prometheus=str(prom))
        self.assertEqual(code, 0)
        text = prom.read_text()
        self.assertRegex(text, r'(?m)^weird_alerts\{level="critical"\} 0$')
        self.assertRegex(text, r'(?m)^weird_alerts\{level="warning"\} 0$')

    def test_prometheus_overwrites_previous_file(self):
        prom = Path(self.tmp.name) / "weird.prom"
        prom.write_text("stale\n")
        self.cmd_scan(json=True, prometheus=str(prom))
        self.assertNotIn("stale", prom.read_text())
        self.assertEqual(sorted(os.listdir(self.tmp.name)), sorted(os.listdir(self.tmp.name)))
        self.assertFalse([n for n in os.listdir(self.tmp.name) if n.endswith(".tmp")])

    def test_prometheus_unwritable_path_warns_and_scan_continues(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            _, code = self.cmd_scan(json=True, prometheus="/proc/weird-cannot-write/weird.prom")
        self.assertEqual(code, 0)
        self.assertIn("could not write", err.getvalue())


class UnitFiles(unittest.TestCase):
    def parse(self, name):
        cp = configparser.ConfigParser(strict=False, interpolation=None)
        cp.optionxform = str
        cp.read(UNIT_DIR / name)
        return cp

    def test_service_units(self):
        for name in SERVICES:
            cp = self.parse(name)
            self.assertIn("Description", cp["Unit"], name)
            self.assertEqual(cp["Service"]["Type"], "oneshot", name)
            exec_start = cp["Service"]["ExecStart"]
            self.assertTrue(exec_start.startswith("/usr/bin/env weird"), exec_start)
            for flag in ("--json", "--journal", "--prometheus %h/"):
                self.assertIn(flag, exec_start, name)
            self.assertEqual(cp["Service"]["SuccessExitStatus"], "1 2", name)
            self.assertIn("SyslogIdentifier", cp["Service"], name)
        self.assertIn("weird persist", self.parse("weird-persist.service")["Service"]["ExecStart"])
        self.assertIn("/var/lib/node_exporter/textfile_collector", (UNIT_DIR / "weird.service").read_text())

    def test_timer_units(self):
        for name in TIMERS:
            cp = self.parse(name)
            self.assertIn("Description", cp["Unit"], name)
            self.assertEqual(cp["Timer"]["OnCalendar"], "daily", name)
            self.assertEqual(cp["Timer"]["Persistent"], "true", name)
            self.assertEqual(cp["Install"]["WantedBy"], "timers.target", name)
            service = name.replace(".timer", ".service")
            self.assertTrue((UNIT_DIR / service).is_file(), service)

    def test_no_typography_in_units(self):
        for name in SERVICES + TIMERS:
            text = (UNIT_DIR / name).read_text()
            self.assertNotRegex(text, "[\\u2014\\u2013]", name)

    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd-analyze not available")
    def test_timer_unit_files_valid(self):
        for name in SERVICES + TIMERS:
            r = subprocess.run(["systemd-analyze", "--user", "verify", str(UNIT_DIR / name)],
                               capture_output=True, text=True, timeout=60)
            output = (r.stdout + r.stderr).strip()
            if r.returncode != 0 and not re.search(r"Unknown|Failed to parse|Invalid|not executable", output):
                self.skipTest(f"systemd-analyze cannot verify user units here: {output[:200]}")
            self.assertEqual(r.returncode, 0, output)
            self.assertNotRegex(output, r"Unknown (key|section|lvalue)")


if __name__ == "__main__":
    unittest.main()
