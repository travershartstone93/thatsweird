import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Dict, Optional, Tuple
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

from fixtures import make_pacman_conf, make_pacman_pkg, make_proc  # noqa: E402
from helpers import fake_run_command, fake_which, load_weird, run_cli, scan_args  # noqa: E402

PACKAGES = [
    # pid, package, version, exe
    (100, "bash", "5.3.15-2", "/usr/bin/bash"),
    (200, "kwin", "6.5.0-1", "/usr/bin/kwin_wayland"),
    (300, "pipewire", "1:1.6.2-1", "/usr/bin/pipewire"),
]


class FixtureBox(unittest.TestCase):
    """A sandbox with three official pacman packages and one process each."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.home = root / "home"
        self.proc = root / "proc"
        self.sysroot = root / "sys"
        make_pacman_conf(self.sysroot)
        self.table: Dict[Tuple[str, ...], Optional[str]] = {
            ("dpkg-divert", "--list"): None,
            ("systemd-detect-virt", "--container"): None,
            ("pacman", "-Sl"): None,
        }
        for pid, pkg, ver, exe in PACKAGES:
            make_pacman_pkg(self.sysroot, pkg, ver, [exe])
            make_proc(self.proc, pid, exe)
            self.table[("pacman", "-Qo", exe)] = f"{exe} is owned by {pkg} {ver}\n"
            self.table[("pacman", "-Qi", pkg)] = f"Name            : {pkg}\nDescription     : {pkg} test package\n"
            self.table[("pacman", "-Si", pkg)] = f"Repository      : core\nName            : {pkg}\n"
        self.weird = load_weird(self.home, proc_root=self.proc, sysroot=self.sysroot)
        self.weird.run_command = fake_run_command(self.table)
        patcher = mock.patch("shutil.which", fake_which({"pacman"}))
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        self.tmp.cleanup()

    def test_fixture_clean_box(self):
        processes, alerts, code = self.weird.run_scan(scan_args(verbose=True))
        self.assertEqual(code, 0)
        self.assertEqual(alerts, [])
        by_pid = {p.pid: p for p in processes}
        self.assertEqual(set(by_pid), {100, 200, 300})
        for pid, pkg, _, _ in PACKAGES:
            self.assertEqual(by_pid[pid].trust_level, self.weird.TrustLevel.OFFICIAL_REPO, by_pid[pid].evidence)
            self.assertEqual(by_pid[pid].package, pkg)

    def test_fixture_critical_box(self):
        make_proc(self.proc, 666, "/usr/bin/evil", memfd="evil")
        processes, alerts, code = self.weird.run_scan(scan_args())
        self.assertEqual(code, 2)
        self.assertEqual([a["pid"] for a in alerts], [666])
        self.assertEqual(alerts[0]["severity"], "critical")
        self.assertTrue(next(p for p in processes if p.pid == 666).is_memfd)

    def test_proc_root_isolation(self):
        processes, _, _ = self.weird.run_scan(scan_args(verbose=True, all=True))
        pids = {p.pid for p in processes}
        self.assertEqual(pids, {100, 200, 300})
        self.assertNotIn(os.getpid(), pids)
        self.assertNotIn(os.getppid(), pids)
        # every subprocess the scan needed came from the fixture table
        self.assertTrue(all(c in self.table for c in self.weird.run_command.calls))

    def test_sandbox_config_dir(self):
        self.assertEqual(self.weird.CONFIG_DIR, self.home / ".config" / "weird")
        self.assertEqual(self.weird.PROC_ROOT, str(self.proc))
        self.assertEqual(self.weird.SYSROOT, str(self.sysroot))
        self.assertEqual(self.weird.proc_path(100, "exe"), str(self.proc / "100" / "exe"))
        self.assertEqual(self.weird.sys_path("/etc/pacman.conf"), str(self.sysroot / "etc" / "pacman.conf"))

    def test_cli_reads_fixture_tree(self):
        r = run_cli(["--json", "-v", "-a"], proc_root=self.proc, sysroot=self.sysroot, home=self.home)
        self.assertIn(r.returncode, (0, 1, 2), r.stderr[-500:])
        data = json.loads(r.stdout)
        self.assertEqual({p["pid"] for p in data["processes"]}, {100, 200, 300})


class DefaultRoots(unittest.TestCase):
    def test_defaults_are_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            weird = load_weird(Path(tmp))
        self.assertEqual(weird.PROC_ROOT, "/proc")
        self.assertEqual(weird.SYSROOT, "/")
        self.assertEqual(weird.proc_path(1, "ns", "pid"), "/proc/1/ns/pid")
        self.assertEqual(weird.sys_path("/var/lib/pacman"), "/var/lib/pacman")
        self.assertEqual(weird.sys_realpath("/etc"), os.path.realpath("/etc"))


if __name__ == "__main__":
    unittest.main()
