"""Baseline by default: every run records one, the changes section, the progress line and Ctrl-C."""
import contextlib
import hashlib
import io
import json
import os
import pty
import signal
import stat
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

from fixtures import make_stub_file  # noqa: E402
from test_report import ReportBox  # noqa: E402


class Tty(io.StringIO):
    def isatty(self):
        return True


def no_question(*args, **kwargs):
    raise AssertionError("weird asked a question it should not have")


class BaselineBox(ReportBox):
    def setUp(self):
        super().setUp()
        os.environ.pop("WEIRD_NO_PROMPT", None)
        self.baseline_file = self.home / ".config/weird/baseline.json"

    def quiet_report(self, *words):
        with mock.patch("builtins.input", no_question):
            return self.report(*words)

    def save_first(self):
        text, code = self.quiet_report()
        self.assertTrue(self.baseline_file.is_file())
        return text

    def baseline(self):
        return json.loads(self.baseline_file.read_text())


class FirstRun(BaselineBox):
    def test_first_run_writes_version_2_without_a_question(self):
        text = self.save_first()
        self.assertNotIn("Compared with your last run", text)
        self.assertIn("First run: weird saved what this machine looks like now", " ".join(text.split()))
        data = self.baseline()
        self.assertEqual(data["version"], 2)
        for part in ("processes", "persistence", "packages", "posture"):
            self.assertIn(part, data, part)
        self.assertEqual(data["processes"][0]["exe_realpath"], "/usr/bin/bash")
        self.assertTrue(data["processes"][0]["exe_sha256"])
        self.assertTrue(int(data["processes"][0]["exe_size"]) > 0)
        self.assertEqual(data["posture"]["module_loading"], "open")
        self.assertEqual(stat.S_IMODE(self.baseline_file.stat().st_mode), 0o600)

    def test_a_terminal_is_not_asked_about_the_baseline(self):
        out = Tty()
        argv = ["--proc-root", str(self.proc), "--sysroot", str(self.sysroot)]
        self.weird.set_config_value("online", False)
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()), \
                mock.patch.object(sys, "stdin", Tty()), mock.patch("builtins.input", no_question):
            code = self.weird.main(argv)
        self.assertEqual(code, 0, out.getvalue())
        self.assertTrue(self.baseline_file.is_file())
        self.assertNotIn("online checks not enabled", out.getvalue())

    def test_json_run_writes_the_baseline_and_never_asks(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()), \
                mock.patch.object(sys, "stdin", Tty()), mock.patch("builtins.input", no_question):
            self.weird.main(["--proc-root", str(self.proc), "--sysroot", str(self.sysroot), "--json"])
        payload = json.loads(out.getvalue())
        self.assertTrue(self.baseline_file.is_file())
        self.assertEqual(payload["online"], {"enabled": False, "note": self.weird.ONLINE_NOTE})

    def test_save_baseline_flag_says_so(self):
        self.save_first()
        text, code = self.quiet_report("--save-baseline")
        self.assertIn("Saved this machine's current state in ~/.config/weird/baseline.json.", " ".join(text.split()))
        self.assertEqual(self.baseline()["version"], 2)

    def test_no_baseline_neither_compares_nor_records(self):
        text, code = self.quiet_report("--no-baseline")
        self.assertEqual(code, 0, text)
        self.assertFalse(self.baseline_file.exists())
        self.assertNotIn("baseline", text)

    def test_dev_baseline_init_keeps_version_2(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.weird.main(["--proc-root", str(self.proc), "--sysroot", str(self.sysroot),
                             "dev", "baseline", "init"])
        data = self.baseline()
        self.assertEqual(data["version"], 2)
        self.assertIn("processes", data)
        self.assertNotIn("persistence", data)


class LaterRuns(BaselineBox):
    def test_identical_run_shows_nothing_changed(self):
        self.save_first()
        text, code = self.quiet_report()
        self.assertEqual(code, 0, text)
        flat = " ".join(text.split())
        self.assertIn("Compared with your last run on", flat)
        self.assertIn("Nothing changed since", flat)
        self.assertIn("(1 process, 0 persistence entries, 0 foreign packages, kernel posture compared).", flat)
        self.assertNotIn("--save-baseline", text)
        self.assertNotIn("Saved this machine", text)
        self.assertTrue(self.baseline_file.is_file())

    def test_new_unit_appears_once_then_becomes_the_baseline(self):
        self.save_first()
        make_stub_file(self.sysroot, "/tmp/decoy")
        self.sys_file("/etc/systemd/system/decoy.service", "[Service]\nExecStart=/tmp/decoy\n")
        text, code = self.quiet_report()
        self.assertEqual(code, 2, text)
        flat = " ".join(text.split())
        self.assertIn("New since your last run: decoy starts at boot", flat)
        self.assertIn("/etc/systemd/system/decoy.service runs /tmp/decoy. If you added it, there is nothing to do", flat)
        self.assertIn("Changes 1 change since", flat)
        self.assertIn("all listed above.", flat)
        self.assertNotIn("--save-baseline", text)
        self.assertEqual(len(self.baseline()["persistence"]), 1)

        out = io.StringIO()
        with contextlib.redirect_stdout(out), mock.patch("builtins.input", no_question):
            self.weird.main(["--proc-root", str(self.proc), "--sysroot", str(self.sysroot), "--json"])
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["changes"]["findings"], [])
        self.assertEqual(payload["summary"]["medium"], 0)
        self.assertNotIn("interrupted", payload)

    def test_replaced_executable_is_a_hash_change(self):
        self.save_first()
        exe = self.sysroot / "usr/bin/bash"
        exe.write_bytes(b"#!/bin/sh\necho replaced\n")
        os.utime(exe, ns=(exe.stat().st_atime_ns, exe.stat().st_mtime_ns + 10 ** 10))
        text, code = self.quiet_report()
        flat = " ".join(text.split())
        self.assertIn("Changed since your last run: bash", flat)
        self.assertIn("/usr/bin/bash is not the same file as at your last run", flat)

    def test_version_1_baseline_is_read(self):
        digest = hashlib.sha256((self.sysroot / "usr/bin/bash").read_bytes()).hexdigest()
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        self.baseline_file.write_text(json.dumps({
            "machine_id": "test", "timestamp": 1700000000,
            "processes": [{"process_key": "/usr/bin/bash|1000|1|bash", "exe_realpath": "/usr/bin/bash",
                           "exe_sha256": digest, "uid": "1000", "trust_level": "OFFICIAL"}],
        }))
        text, code = self.quiet_report()
        self.assertEqual(code, 0, text)
        self.assertIn("Compared with your last run on Nov 1", text)
        self.assertIn("(1 process compared).", " ".join(text.split()))
        self.assertEqual(self.baseline()["version"], 2)

    def test_no_baseline_skips_the_section(self):
        self.save_first()
        text, code = self.quiet_report("--no-baseline")
        self.assertNotIn("Changes", text)
        self.assertNotIn("Compared with", text)
        self.assertTrue(text.startswith("Nothing weird on"), text)


class ProgressLine(BaselineBox):
    def test_progress_on_a_terminal_and_a_clean_report(self):
        report_file = self.home / "report.txt"
        pid, fd = pty.fork()
        if pid == 0:
            code = 1
            try:
                with open(report_file, "w") as out, contextlib.redirect_stdout(out):
                    code = self.weird.main(["--proc-root", str(self.proc), "--sysroot", str(self.sysroot)])
            finally:
                os._exit(code)
        chunks = []
        while True:
            try:
                data = os.read(fd, 4096)
            except OSError:
                break
            if not data:
                break
            chunks.append(data)
        os.close(fd)
        _, status = os.waitpid(pid, 0)
        terminal = b"".join(chunks).decode(errors="replace")
        self.assertEqual(os.waitstatus_to_exitcode(status), 0, terminal)
        self.assertIn("checking ", terminal)
        self.assertIn("\r", terminal)
        report = report_file.read_text()
        self.assertNotIn("checking", report)
        self.assertTrue(report.startswith("Nothing weird on"), report)
        self.assertIn("Everything else", report)
        self.assertNotIn("OK? [Y/n]", terminal)

    def test_nothing_on_a_piped_stderr(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            text, code = self.quiet_report()
        self.assertNotIn("checking", err.getvalue())
        for line in err.getvalue().splitlines():
            self.assertTrue(not line.strip() or "WARNING" in line or "Warning" in line, line)


class CtrlC(BaselineBox):
    def setUp(self):
        super().setUp()
        # a suite started in the background inherits an ignored SIGINT
        previous = signal.signal(signal.SIGINT, signal.default_int_handler)
        self.addCleanup(signal.signal, signal.SIGINT, previous)

    def slow_hidden(self, *args, **kwargs):
        threading.Timer(0.5, os.kill, [os.getpid(), signal.SIGINT]).start()
        time.sleep(30)
        return []

    def test_sigint_prints_the_partial_report(self):
        with mock.patch.object(self.weird, "find_hidden_pids", self.slow_hidden):
            text, code = self.quiet_report()
        self.assertEqual(code, 130, text)
        self.assertIn("Running programs", text)
        self.assertIn("Kernel modules", text)
        self.assertNotIn("Hidden processes", text)
        self.assertIn("Stopped early during hidden processes: this report covers only the parts that finished.",
                      " ".join(text.split()))
        self.assertFalse(self.baseline_file.exists())

    def test_sigint_under_json_is_still_json(self):
        with mock.patch.object(self.weird, "find_hidden_pids", self.slow_hidden):
            text, code = self.quiet_report("--json")
        self.assertEqual(code, 130)
        payload = json.loads(text)
        self.assertEqual(payload["interrupted"], "hidden")
        self.assertIn("processes", payload)
        self.assertNotIn("hidden", payload)
        self.assertEqual(payload["summary"]["exit_code"], 130)


if __name__ == "__main__":
    unittest.main()
