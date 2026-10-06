"""Snapshots of the one-command report: a clean machine and one with findings in several sections."""
import contextlib
import io
import os
import re
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

from fixtures import _write, make_proc, make_proc_root, make_stub_file  # noqa: E402
from test_persist import PersistBox  # noqa: E402

CLEAN = """\
== Processes ==

WARNING: pacman LocalFileSigLevel = Optional: locally built packages (makepkg/AUR) are installed unsigned
nothing to report (1 process examined)

== AUR packages ==

nothing to report (no foreign packages installed)

== Persistence ==

nothing to report (0 persistence entries checked, 0 your own unpackaged software, 0 info)

== Kernel ==

nothing to report (0 loaded modules, 0 owned by packages, taint clean)

== Hidden processes ==

nothing to report (1 pid listed, pids 1..5000 probed)

summary: 0 to look at (0 critical, 0 medium, 0 low), 0 entries are your own unpackaged software, 6 info (exit 0)
"""

DIRTY = """\
== Processes ==

WARNING: pacman LocalFileSigLevel = Optional: locally built packages (makepkg/AUR) are installed unsigned
nothing to report (2 processes examined)

== AUR packages ==

nothing to report (no foreign packages installed)

== Persistence ==

SOURCE           FILE                                     TARGET                               TRUST        SEVERITY
--------------------------------------------------------------------------------------------------------------------
ld.so.preload    /etc/ld.so.preload                       /tmp/evil.so                         UNKNOWN      critical
                 line 1: /tmp/evil.so
                 in a temporary directory, target does not exist [T1574.006]
systemd service  /etc/systemd/system/evil.service         /tmp/evil                            UNKNOWN      critical
                 ExecStart: /tmp/evil
                 in a temporary directory, not owned by any package [T1543.002]

3 persistence entries checked: 2 critical, 0 medium, 1 your own unpackaged software, 0 info (-v lists the info entries)

== Kernel ==

nothing to report (0 loaded modules, 0 owned by packages, taint clean)

== Hidden processes ==

KIND                     DETAIL                                                           SEVERITY
--------------------------------------------------------------------------------------------------
hidden pid               pid 4242 (evil): present in /proc but absent from the directory  critical [T1564.001]
                         listing
                         A rootkit that filters the /proc directory listing hides a
                         process from ps and top, but /proc/<pid>/stat still answers a
                         direct stat. This is what unhide does.

1 pid listed, pids 1..5000 probed: 1 critical, 0 medium, 0 low

summary: 3 to look at (3 critical, 0 medium, 0 low), 1 entry is your own unpackaged software, 6 info (exit 2)
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
        return text.replace(str(self.home), "~").replace(str(self.sysroot), ""), code


class CleanReport(ReportBox):
    def test_clean_report_is_short(self):
        text, code = self.report()
        self.assertEqual(code, 0, text)
        self.assertLess(len(text.splitlines()), 25, text)
        self.assertEqual(text, CLEAN)

    def test_verbose_keeps_the_full_sections(self):
        text, code = self.report("-v")
        self.assertIn("SECURITY NOTE", text)
        self.assertIn("Posture", text)
        self.assertIn("Every pid, thread and socket", text)


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
