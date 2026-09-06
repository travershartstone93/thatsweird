import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from fixtures import make_proc, make_proc_root  # noqa: E402
from helpers import sandbox_root  # noqa: E402
from test_arch import ARCH  # noqa: E402
from test_signals import SignalBox  # noqa: E402

T = 1_800_000_000            # package installdate
BOOT = T - 7200
BEFORE = 3600 * 100          # ticks since boot: started an hour before the upgrade

BASH = "/usr/bin/bash"
STACK = "7ffd0d3e5000-7ffd0d406000 rw-p 00000000 00:00 0                          [stack]"
VDSO = "7ffd0d5c3000-7ffd0d5c5000 r-xp 00000000 00:00 0                          [vdso]"


def exe_maps(exe):
    return [
        f"5648cf883000-5648cf885000 r--p 00000000 08:01 1725820                    {exe}",
        f"5648cf885000-5648cf890000 r-xp 00002000 08:01 1725820                    {exe}",
    ]


def lib_map(path, perms="r-xp", inode=1234):
    return f"7f3a1c000000-7f3a1c003000 {perms} 00000000 08:01 {inode}                       {path}"


class InjectionBox(SignalBox):
    sandbox_dir = sandbox_root()

    def setUp(self):
        super().setUp()
        make_proc_root(self.proc, btime=BOOT)

    def official_with_maps(self, pid, exe, extra, **kwargs):
        self.add_pkg(exe.rsplit("/", 1)[1], "1.0-1", exe, repo="core", packager=ARCH, installdate=T)
        make_proc(self.proc, pid, exe, maps=exe_maps(exe) + extra + [STACK, VDSO], **kwargs)
        proc, _, code = self.scan_pid(pid)
        return proc, code


class InjectedLibrary(InjectionBox):
    def test_injected_lib_in_official_process(self):
        proc, code = self.official_with_maps(600, BASH, [lib_map("/tmp/evil.so")])
        self.assertEqual(proc.trust_level, self.weird.TrustLevel.OFFICIAL_REPO, proc.evidence)
        self.assert_signal(proc, "lib_injection", "T1055", "/tmp/evil.so")
        self.assertEqual(proc.weirdness_score, self.scores["lib_injection"])
        self.assertEqual(self.scores["lib_injection"], 40)
        self.assertIn(code, (1, 2))

    def test_dev_shm_and_var_tmp_count_too(self):
        proc, _ = self.official_with_maps(601, BASH, [lib_map("/dev/shm/.x/inject.so"), lib_map("/var/tmp/l.so", inode=99)])
        reason = proc.reasons[proc.signal_keys.index("lib_injection")]
        self.assertIn("/dev/shm/.x/inject.so", reason)
        self.assertIn("/var/tmp/l.so", reason)
        self.assertEqual(proc.signal_keys.count("lib_injection"), 1)

    def test_readonly_mapping_is_not_injection(self):
        proc, _ = self.official_with_maps(602, BASH, [lib_map("/tmp/data.bin", perms="r--p")])
        self.assertNotIn("lib_injection", proc.signal_keys)
        self.assertEqual(proc.weirdness_score, 0)

    def test_unowned_exe_is_left_to_other_checks(self):
        self.unowned("/opt/thing/bin/zzdaemon")
        make_proc(self.proc, 603, "/opt/thing/bin/zzdaemon",
                  maps=exe_maps("/opt/thing/bin/zzdaemon") + [lib_map("/tmp/evil.so")])
        proc, _, _ = self.scan_pid(603)
        self.assertNotIn("lib_injection", proc.signal_keys)


class DeletedMapping(InjectionBox):
    def test_deleted_unowned_lib_mapping(self):
        proc, _ = self.official_with_maps(610, BASH, [lib_map("/usr/lib/libfoo.so (deleted)")])
        self.assert_signal(proc, "lib_injection", "T1055", "/usr/lib/libfoo.so (deleted")
        self.assertEqual(proc.stale_libs, [])

    def test_deleted_owned_lib_with_newer_install_is_stale(self):
        self.add_pkg("libfoo", "2.0-1", "/usr/lib/libfoo.so", repo="core", packager=ARCH, installdate=T)
        proc, code = self.official_with_maps(611, BASH, [lib_map("/usr/lib/libfoo.so (deleted)")], starttime=BEFORE)
        self.assertEqual(proc.stale_libs, ["/usr/lib/libfoo.so"])
        self.assertNotIn("lib_injection", proc.signal_keys)
        self.assertEqual(proc.weirdness_score, 0)
        self.assertEqual(code, 0)

    def test_deleted_exe_itself_is_the_deleted_exe_signal(self):
        exe = "/usr/bin/zzsvc"
        self.add_pkg("zzsvc", "1.0-1", exe, repo="core", packager=ARCH, installdate=T)
        (self.sysroot / exe.lstrip("/")).unlink()
        make_proc(self.proc, 612, exe, deleted=True, starttime=BEFORE)
        proc, _, _ = self.scan_pid(612)
        self.assertIn("deleted_exe", proc.signal_keys)
        self.assertNotIn("lib_injection", proc.signal_keys)


class KnownJit(InjectionBox):
    def test_jit_memfd_not_flagged(self):
        firefox = "/usr/bin/firefox"
        proc, code = self.official_with_maps(620, firefox, [
            lib_map("/memfd:JITCode:QtQml (deleted)", inode=77),
            lib_map("/dev/shm/wayland-shm-a1b2", inode=78),
            lib_map("/dev/shm/shm-ff29f", inode=79),
            lib_map("/memfd:mozilla-ipc (deleted)", inode=80),
        ])
        self.assertNotIn("lib_injection", proc.signal_keys)
        self.assertFalse(proc.is_memfd, proc.memfd_evidence)
        self.assertEqual(proc.weirdness_score, 0, proc.reasons)
        self.assertEqual(code, 0)

    def test_unknown_memfd_belongs_to_memfd_check(self):
        proc, _ = self.official_with_maps(621, BASH, [lib_map("/memfd:payload (deleted)", inode=81)])
        self.assertIn("memfd_exec", proc.signal_keys)
        self.assertNotIn("lib_injection", proc.signal_keys)


class UnownedRegularFile(InjectionBox):
    def test_unowned_lib_outside_prefix(self):
        proc, _ = self.official_with_maps(630, BASH, [lib_map("/usr/lib/libselinux-ng.so.1")])
        self.assert_signal(proc, "lib_injection", "T1055", "/usr/lib/libselinux-ng.so.1 not owned")

    def test_native_module_from_user_package_not_flagged(self):
        mod = self.home / ".npm/_npx/abc/node_modules/keytar/build/Release/keytar.node"
        mod.parent.mkdir(parents=True)
        mod.write_bytes(b"\x7fELF")
        (self.home / ".npm/_npx/abc/node_modules/keytar/package.json").write_text(
            json.dumps({"name": "keytar", "version": "7.9.0"}))
        proc, _ = self.official_with_maps(631, "/usr/bin/node", [lib_map(str(mod))])
        self.assertNotIn("lib_injection", proc.signal_keys)
        self.assertTrue(any("explained by user space package metadata" in e for e in proc.evidence), proc.evidence)
        self.assertTrue(any("installed by npm as keytar@7.9.0" in e for e in proc.evidence), proc.evidence)

    def test_user_pkg_loads_from_its_own_tree(self):
        exe = self.home / ".local/share/uv/tools/foo/bin/python"
        lib = self.home / ".local/share/uv/tools/foo/lib/python3.12/site-packages/x/_x.so"
        for path in (exe, lib):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"\x7fELF")
        exe.chmod(0o755)
        make_proc(self.proc, 632, str(exe), cmdline=[str(exe), "-m", "x"], maps=exe_maps(str(exe)) + [lib_map(str(lib))])
        proc, _, _ = self.scan_pid(632)
        self.assertEqual(proc.trust_level, self.weird.TrustLevel.USER_PKG, proc.evidence)
        self.assertNotIn("lib_injection", proc.signal_keys)
        self.assertEqual(proc.weirdness_score, 0, proc.reasons)


class UnreadableMaps(InjectionBox):
    @unittest.skipIf(os.geteuid() == 0, "root can read anything")
    def test_unreadable_maps(self):
        self.add_pkg("bash", "1.0-1", BASH, repo="core", packager=ARCH, installdate=T)
        d = make_proc(self.proc, 640, BASH, maps=exe_maps(BASH) + [lib_map("/tmp/evil.so")])
        (d / "maps").chmod(0)
        self.addCleanup((d / "maps").chmod, 0o644)
        proc, _, code = self.scan_pid(640)
        self.assertNotIn("lib_injection", proc.signal_keys)
        self.assertIn("maps unavailable (library injection not checked)", proc.evidence)
        self.assertEqual(proc.weirdness_score, 0)
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
