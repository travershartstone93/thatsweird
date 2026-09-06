import argparse
import contextlib
import gzip
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

from fixtures import make_apt_pkg, make_pacman_pkg, make_proc, make_stub_file  # noqa: E402
from helpers import load_weird, scan_args  # noqa: E402
from test_arch import ARCH, ArchBox  # noqa: E402

BASH = "/usr/bin/bash"


def append_byte(sysroot, host_path):
    with open(Path(sysroot) / host_path.lstrip("/"), "ab") as f:
        f.write(b"\n")


class IntegrityBox(ArchBox):
    def setUp(self):
        super().setUp()
        self.scores = self.weird.load_policy()["scores"]

    def official(self, name, version, exe, **kwargs):
        self.add_pkg(name, version, exe, repo="core", packager=ARCH, **kwargs)

    def scan(self, pid, **overrides):
        processes, alerts, code = self.weird.run_scan(scan_args(verbose=True, **overrides))
        return next(p for p in processes if p.pid == pid), alerts, code


class PacmanIntegrity(IntegrityBox):
    def test_intact_binary_verifies(self):
        self.official("bash", "5.3.15-2", BASH)
        status, detail = self.weird.verify_integrity(BASH, "bash", "pacman")
        self.assertEqual(status, "intact", detail)
        self.assertIn("sha256", detail)
        self.assertIn("bash", detail)

    def test_modified_binary_detected(self):
        self.official("bash", "5.3.15-2", BASH)
        append_byte(self.sysroot, BASH)
        make_proc(self.proc, 100, BASH)
        proc, alerts, code = self.scan(100, deep=True)
        self.assertEqual(proc.trust_level, self.weird.TrustLevel.OFFICIAL_REPO, proc.evidence)
        self.assertEqual(proc.integrity, "modified")
        self.assertEqual(proc.weirdness_score, self.scores["integrity_modified"])
        self.assertEqual(proc.signal_keys, ["integrity_modified"])
        reason = proc.reasons[0]
        self.assertIn("T1554", reason)
        self.assertIn("bash", reason)
        self.assertIn("sha256", reason)
        self.assertIn("T1554", proc.attack)
        self.assertEqual(self.weird.verdict_for(proc), "Likely malicious")
        self.assertEqual(self.weird.process_to_dict(proc)["integrity"], "modified")
        self.assertEqual(code, 2)
        self.assertEqual([a["pid"] for a in alerts], [100])
        self.assertEqual(alerts[0]["verdict"], "Likely malicious")

    def test_missing_mtree_is_unavailable(self):
        pkgdir = make_pacman_pkg(self.sysroot, "bash", "5.3.15-2", [BASH], packager=ARCH)
        self.table[("pacman", "-Si", "bash")] = "Repository      : core\nName            : bash\n"
        (pkgdir / "mtree").unlink()
        make_proc(self.proc, 100, BASH)
        proc, alerts, code = self.scan(100, deep=True)
        self.assertEqual(proc.integrity, "unavailable")
        self.assertEqual(proc.weirdness_score, 0)
        self.assertEqual(proc.signal_keys, [])
        line = next(e for e in proc.evidence if e.startswith("Integrity: unavailable"))
        self.assertIn("mtree", line)
        self.assertEqual(code, 0)
        self.assertEqual(alerts, [])

    def test_path_not_in_mtree_is_unavailable(self):
        self.official("bash", "5.3.15-2", BASH)
        make_stub_file(self.sysroot, "/usr/bin/other")
        status, detail = self.weird.verify_integrity("/usr/bin/other", "bash", "pacman")
        self.assertEqual(status, "unavailable")
        self.assertIn("not listed", detail)

    def test_unknown_package_is_unavailable(self):
        status, detail = self.weird.verify_integrity(BASH, "nothing", "pacman")
        self.assertEqual(status, "unavailable")
        self.assertIn("nothing", detail)

    def test_md5_only_mtree_falls_back(self):
        pkgdir = make_pacman_pkg(self.sysroot, "bash", "5.3.15-2", [BASH], packager=ARCH)
        with gzip.open(pkgdir / "mtree", "rt") as f:
            text = "".join(line for line in f if not line.startswith("#"))
        lines = []
        for line in text.splitlines():
            lines.append(" ".join(kv for kv in line.split() if not kv.startswith("sha256digest=")))
        with gzip.open(pkgdir / "mtree", "wt") as f:
            f.write("#mtree\n" + "\n".join(lines) + "\n")
        status, detail = self.weird.verify_integrity(BASH, "bash", "pacman")
        self.assertEqual(status, "intact", detail)
        self.assertIn("md5", detail)
        append_byte(self.sysroot, BASH)
        self.weird.set_roots(sysroot=str(self.sysroot))
        status, detail = self.weird.verify_integrity(BASH, "bash", "pacman")
        self.assertEqual(status, "modified")
        self.assertIn("md5", detail)

    def test_mtree_escaping(self):
        spaced = "/opt/my app/bin/my tool"
        pkgdir = make_pacman_pkg(self.sysroot, "mytool", "1.0-1", [spaced], packager=ARCH)
        with gzip.open(pkgdir / "mtree", "rt") as f:
            raw = f.read()
        self.assertIn("./opt/my\\040app/bin/my\\040tool ", raw)
        entries = self.weird.read_pacman_mtree(pkgdir)
        self.assertIn(spaced, entries)
        status, detail = self.weird.verify_integrity(spaced, "mytool", "pacman")
        self.assertEqual(status, "intact", detail)
        append_byte(self.sysroot, spaced)
        self.weird.set_roots(sysroot=str(self.sysroot))
        self.assertEqual(self.weird.verify_integrity(spaced, "mytool", "pacman")[0], "modified")

    def test_unescape_handles_utf8_and_backslash(self):
        self.assertEqual(self.weird.mtree_unescape(r"/etc/caf\303\251"), "/etc/café")
        self.assertEqual(self.weird.mtree_unescape(r"/a\134b"), "/a\\b")
        self.assertEqual(self.weird.mtree_unescape("/plain"), "/plain")

    def test_result_cached_per_run(self):
        self.official("bash", "5.3.15-2", BASH)
        with mock.patch.object(self.weird, "digest_file", wraps=self.weird.digest_file) as digest:
            self.assertEqual(self.weird.verify_integrity(BASH, "bash", "pacman")[0], "intact")
            self.assertEqual(self.weird.verify_integrity(BASH, "bash", "pacman")[0], "intact")
        self.assertEqual(digest.call_count, 1)

    def test_never_raises(self):
        self.official("bash", "5.3.15-2", BASH)
        with mock.patch.object(self.weird, "read_pacman_mtree", side_effect=RuntimeError("boom")):
            status, detail = self.weird.verify_integrity(BASH, "bash", "pacman")
        self.assertEqual(status, "unavailable")
        self.assertIn("boom", detail)


class WhenIntegrityRuns(IntegrityBox):
    def setUp(self):
        super().setUp()
        self.official("bash", "5.3.15-2", BASH)
        make_proc(self.proc, 100, BASH)
        self.spy = mock.patch.object(self.weird, "verify_integrity", wraps=self.weird.verify_integrity)
        self.calls = self.spy.start()
        self.addCleanup(self.spy.stop)

    def verified_paths(self):
        return [c.args[0] for c in self.calls.call_args_list]

    def test_clean_official_not_verified_by_default(self):
        proc, _, _ = self.scan(100)
        self.assertEqual(proc.weirdness_score, 0)
        self.assertEqual(self.verified_paths(), [])
        self.assertEqual(proc.integrity, "")
        self.assertEqual(self.weird.process_to_dict(proc)["integrity"], "")

    def test_deep_verifies_every_packaged_process(self):
        self.official("kwin", "6.5.0-1", "/usr/bin/kwin_wayland")
        make_proc(self.proc, 200, "/usr/bin/kwin_wayland")
        proc, _, _ = self.scan(100, deep=True)
        self.assertEqual(sorted(self.verified_paths()), [BASH, "/usr/bin/kwin_wayland"])
        self.calls.assert_any_call(BASH, "bash", "pacman")
        self.assertEqual(proc.integrity, "intact")
        self.assertTrue(any(e.startswith("Integrity: intact") for e in proc.evidence), proc.evidence)

    def test_flagged_process_always_verified(self):
        make_proc(self.proc, 101, BASH, environ={"HOME": "/home/user1000", "LD_PRELOAD": "/tmp/a.so"})
        proc, _, _ = self.scan(101)
        self.assertIn("ld_preload", proc.signal_keys)
        self.assertEqual(self.verified_paths(), [BASH])
        self.assertEqual(proc.integrity, "intact")

    def test_unowned_flagged_process_reports_unavailable(self):
        make_stub_file(self.sysroot, "/tmp/.x/helper")
        self.table[("pacman", "-Qo", "/tmp/.x/helper")] = None
        make_proc(self.proc, 700, "/tmp/.x/helper")
        proc, _, _ = self.scan(700)
        self.assertIn("suspicious_path", proc.signal_keys)
        self.assertEqual(proc.integrity, "unavailable")
        self.assertNotIn("integrity_modified", proc.signal_keys)


class DpkgIntegrity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.sysroot = root / "sys"
        self.weird = load_weird(root / "home", proc_root=root / "proc", sysroot=self.sysroot)
        self.weird.run_command = mock.Mock(side_effect=AssertionError("no subprocess expected"))

    def test_intact(self):
        make_apt_pkg(self.sysroot, "foo", ["/usr/bin/foo"])
        status, detail = self.weird.verify_integrity("/usr/bin/foo", "foo", "dpkg")
        self.assertEqual(status, "intact", detail)
        self.assertIn("md5", detail)
        self.assertIn("weak", detail)

    def test_modified(self):
        make_apt_pkg(self.sysroot, "foo", ["/usr/bin/foo"])
        append_byte(self.sysroot, "/usr/bin/foo")
        status, detail = self.weird.verify_integrity("/usr/bin/foo", "foo", "apt")
        self.assertEqual(status, "modified")
        self.assertIn("md5", detail)
        self.assertIn("weak", detail)

    def test_missing_md5sums_is_unavailable(self):
        make_apt_pkg(self.sysroot, "foo", ["/usr/bin/foo"], hashes=False)
        status, detail = self.weird.verify_integrity("/usr/bin/foo", "foo", "dpkg")
        self.assertEqual(status, "unavailable")
        self.assertIn("md5", detail)

    def test_arch_qualified_md5sums(self):
        info = make_apt_pkg(self.sysroot, "foo", ["/usr/bin/foo"])
        (info.parent / "foo.md5sums").rename(info.parent / "foo:amd64.md5sums")
        status, detail = self.weird.verify_integrity("/usr/bin/foo", "foo", "dpkg")
        self.assertEqual(status, "intact", detail)
        self.weird.run_command.assert_not_called()


class InspectOutput(IntegrityBox):
    def test_inspect_prints_integrity(self):
        self.official("bash", "5.3.15-2", BASH)
        make_proc(self.proc, 100, BASH)
        self.table[("pstree", "-p", "-s", "100")] = None
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = self.weird.cmd_inspect(argparse.Namespace(pid=100, enrich_net=False))
        self.assertEqual(code, 0)
        self.assertIn("Integrity: intact (sha256 matches package bash mtree)", out.getvalue())

    def test_inspect_flags_modified(self):
        self.official("bash", "5.3.15-2", BASH)
        append_byte(self.sysroot, BASH)
        make_proc(self.proc, 100, BASH)
        self.table[("pstree", "-p", "-s", "100")] = None
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.weird.cmd_inspect(argparse.Namespace(pid=100, enrich_net=False))
        text = out.getvalue()
        self.assertIn("Integrity: modified", text)
        self.assertIn("T1554", text)
        self.assertIn("Likely malicious", text)


class SubprocessEconomy(IntegrityBox):
    def calls(self, *prefix):
        return [c for c in self.weird.run_command.calls if c[:len(prefix)] == prefix]

    def test_detect_virt_runs_once_per_scan(self):
        for pid, name, exe in ((100, "bash", BASH), (200, "kwin", "/usr/bin/kwin_wayland"), (300, "pipewire", "/usr/bin/pipewire")):
            self.official(name, "1.0-1", exe)
            make_proc(self.proc, pid, exe)
        processes, _, _ = self.weird.run_scan(scan_args(verbose=True))
        self.assertEqual(len(processes), 3)
        self.assertEqual(len(self.calls("systemd-detect-virt", "--container")), 1)

    def test_unowned_path_asked_once(self):
        exe = "/opt/thing/bin/zzdaemon"
        make_stub_file(self.sysroot, exe)
        self.table[("pacman", "-Qo", exe)] = None
        make_proc(self.proc, 500, exe)
        make_proc(self.proc, 501, exe)
        processes, _, _ = self.weird.run_scan(scan_args(verbose=True))
        self.assertEqual({p.pid for p in processes}, {500, 501})
        self.assertEqual(self.calls("pacman", "-Qo"), [("pacman", "-Qo", exe)])


if __name__ == "__main__":
    unittest.main()
