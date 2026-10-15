"""Snapshots of the one-command report: a clean machine and one with findings in several sections."""
import contextlib
import io
import os
import re
import socket
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

from fixtures import _write, make_proc, make_proc_root, make_stub_file  # noqa: E402
from test_persist import PersistBox  # noqa: E402

CLEAN = """\
Nothing weird on HOST.
First run: weird saved what this machine looks like now, so the next run can
show what changed.

Everything else

  Running programs   1 checked.
  AUR packages       None installed.
  Startup programs   0 entries checked.
  Kernel modules     None loaded. The kernel is untainted.
  Hidden processes   Nothing hidden among 1 process.

Online checks are off: run weird once in a terminal and answer its one
question to turn them on.

weird -v lists everything; weird 1234 explains process 1234.
"""

DIRTY = """\
3 things on HOST need you to act now.
First run: weird saved what this machine looks like now, so the next run can
show what changed.

Act now

  Every program loads /tmp/evil.so
    /etc/ld.so.preload makes every program on this machine load /tmp/evil.so.
    It lives in a temporary folder, where programs are not installed and
    malware often hides. The library it names does not exist yet, so nothing
    is loaded. If you did not set this up, treat it as serious.

  evil starts at boot
    /etc/systemd/system/evil.service runs /tmp/evil. It lives in a temporary
    folder, where programs are not installed and malware often hides. If you
    did not set this up, treat it as serious.

  Hidden process: evil (pid 4242)
    The kernel answers for pid 4242, but it is missing from the list that ps
    and top read. Rootkits hide programs this way; treat it as serious. Run
    weird 4242 for the full picture.

Everything else

  Running programs   2 checked.
  AUR packages       None installed.
  Startup programs   3 entries checked, 1 of them your own scripts.
  Kernel modules     None loaded. The kernel is untainted.
  Hidden processes   1 process listed.

Online checks are off: run weird once in a terminal and answer its one
question to turn them on.

weird -v lists everything; weird 1234 explains process 1234.
"""


class ReportBox(PersistBox):
    def setUp(self):
        super().setUp()
        make_proc_root(self.proc)
        _write(self.proc / "sys/kernel/pid_max", "5000\n")
        _write(self.proc / "loadavg", "0.10 0.10 0.10 1/2 4300\n")
        self.add_official("bash", "/usr/bin/bash")
        make_proc(self.proc, 100, "/usr/bin/bash", comm="bash")
        self.table[("pacman", "-Qm")] = ""
        self.table[("bpftool", "prog", "list")] = None
        self.table[("ss", "-H", "-tuanp")] = None
        self.table[("ss", "-H", "-tuan")] = None

    def report(self, *words):
        out = io.StringIO()
        argv = ["--proc-root", str(self.proc), "--sysroot", str(self.sysroot), *words]
        with contextlib.redirect_stdout(out):
            code = self.weird.main(argv)
        text = re.sub(r"\x1b\[[0-9;]*m", "", out.getvalue())
        text = text.replace(str(self.home), "~").replace(str(self.sysroot), "")
        return text.replace(f" on {socket.gethostname()}", " on HOST"), code


class CleanReport(ReportBox):
    def test_clean_report_is_short(self):
        text, code = self.report()
        self.assertEqual(code, 0, text)
        self.assertLess(len(text.splitlines()), 25, text)
        self.assertEqual(text, CLEAN)

    def test_verbose_keeps_the_full_sections(self):
        text, code = self.report("-v")
        self.assertIn("secure boot:", text)
        self.assertIn("bash (pid 100): It comes from the bash package", " ".join(text.split()))
        self.assertIn("Nothing hidden among", " ".join(text.split()))


class DirtyReport(ReportBox):
    def setUp(self):
        super().setUp()
        make_stub_file(self.sysroot, "/tmp/evil")
        self.sys_file("/etc/systemd/system/evil.service", "[Service]\nExecStart=/tmp/evil\n")
        self.sys_file("/etc/ld.so.preload", "/tmp/evil.so\n")
        self.home_file("bin/mine.sh", "#!/bin/sh\n")
        self.home_file(".config/systemd/user/mine.service", "[Service]\nExecStart=%h/bin/mine.sh\n")
        make_proc(self.proc, 4242, "/usr/bin/bash", comm="evil")

    def test_dirty_report(self):
        original = self.weird.list_pids_readdir
        with mock.patch.object(self.weird, "list_pids_readdir", side_effect=lambda: original() - {4242}):
            text, code = self.report()
        self.assertEqual(code, 2, text)
        self.assertEqual(text, DIRTY)


if __name__ == "__main__":
    unittest.main()
