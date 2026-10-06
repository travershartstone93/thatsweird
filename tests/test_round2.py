"""Round 2 unprivileged checks: PATH shadowing, SSH footholds, restart loops, kernel helpers,
pacman.log history, language caches, /proc bind mounts, the second pid probe and anonymous executable memory."""

import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

from fixtures import make_proc, make_proc_root, make_stub_file  # noqa: E402
from helpers import sandbox_root  # noqa: E402
from test_arch import ARCH, ArchBox  # noqa: E402
from test_persist import PersistBox  # noqa: E402


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


class PathShadowTests(PersistBox):
    sandbox_dir = sandbox_root()

    def setUp(self):
        super().setUp()
        self.add_official("sudo", "/usr/bin/sudo")
        self.bin_dir = self.home / ".local/bin"
        self.bin_dir.mkdir(parents=True)
        patcher = mock.patch.dict(os.environ, {"PATH": "/usr/bin:/usr/local/bin"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def shadows(self):
        return [e for e in self.weird.persist_path_shadow_entries()]

    def test_fake_sudo_in_local_bin_is_critical(self):
        _write(self.bin_dir / "sudo", "#!/bin/sh\nexit 0\n")
        found = self.shadows()
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "critical")
        self.assertEqual(found[0].attack, "T1036.005")
        self.assertIn("/usr/bin/sudo", found[0].provenance)

    def test_symlink_to_real_binary_is_info(self):
        os.symlink(str(self.sysroot / "usr/bin/sudo"), str(self.bin_dir / "sudo"))
        found = self.shadows()
        self.assertEqual([e.severity for e in found], ["info"])

    def test_clean_bin_dir_stays_clean(self):
        _write(self.bin_dir / "myscript", "#!/bin/sh\n")
        self.assertEqual(self.shadows(), [])

    def test_shadow_reaches_persist_entries(self):
        _write(self.bin_dir / "sudo", "#!/bin/sh\n")
        entries = self.weird.collect_persistence()
        self.assertTrue(any(e.source == "path shadow" and e.severity == "critical" for e in entries))


class SshFootholdTests(PersistBox):
    sandbox_dir = sandbox_root()

    def keys(self, text):
        _write(self.home / ".ssh/authorized_keys", text)
        return [e for e in self.weird.persist_ssh_foothold_entries() if e.source == "ssh key"]

    def test_forced_command_in_tmp_is_critical(self):
        found = self.keys('command="/tmp/.x/run" ssh-ed25519 AAAAC3 bot@example\n')
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "critical")
        self.assertEqual(found[0].attack, "T1098.004")

    def test_forwarding_and_wildcard_from_are_medium(self):
        found = self.keys('from="*",agent-forwarding ssh-ed25519 AAAAC3 me@laptop\n')
        self.assertEqual([e.severity for e in found], ["medium"])
        self.assertIn("wildcard", found[0].provenance)

    def test_missing_comment_is_medium(self):
        found = self.keys("ssh-rsa AAAAB3\n")
        self.assertEqual([e.severity for e in found], ["medium"])

    def test_plain_commented_key_is_clean(self):
        self.assertEqual(self.keys("# my keys\nssh-ed25519 AAAAC3 me@laptop\n"), [])

    def test_no_ssh_dir_is_clean(self):
        self.assertEqual(self.weird.persist_ssh_foothold_entries(), [])

    def test_proxycommand_in_tmp_is_medium(self):
        _write(self.home / ".ssh/config", "Host evil\n  ProxyCommand /tmp/relay %h %p\n")
        found = [e for e in self.weird.persist_ssh_foothold_entries() if e.source == "ssh config"]
        self.assertEqual([e.severity for e in found], ["medium"])

    def test_proxycommand_with_packaged_binary_is_clean(self):
        self.add_official("openssh", "/usr/bin/ssh")
        _write(self.home / ".ssh/config", "Host jump\n  ProxyCommand /usr/bin/ssh -W %h:%p bastion\n")
        self.assertEqual([e for e in self.weird.persist_ssh_foothold_entries() if e.source == "ssh config"], [])


class RestartLoopTests(PersistBox):
    sandbox_dir = sandbox_root()

    def unit(self, text, target="/home/x/run.sh"):
        unit = _write(self.sysroot / "etc/systemd/system/loop.service", text)
        entry = self.weird.PersistEntry("systemd service", str(unit).replace(str(self.sysroot), ""), "ExecStart",
                                        target, target=target, trust="UNKNOWN", provenance="not owned",
                                        severity="medium")
        self.weird.persist_apply_restart_loops([entry])
        return entry

    def test_quick_restart_loop_raises_severity(self):
        entry = self.unit("[Service]\nExecStart=/home/x/run.sh\nRestart=always\nRestartSec=5\n")
        self.assertEqual(entry.severity, "critical")
        self.assertEqual(entry.attack, "T1543.002")
        self.assertIn("restart loop keeps it alive", entry.provenance)

    def test_slow_restart_is_untouched(self):
        entry = self.unit("[Service]\nExecStart=/home/x/run.sh\nRestart=on-failure\nRestartSec=5min\n")
        self.assertEqual(entry.severity, "medium")

    def test_no_restart_is_untouched(self):
        entry = self.unit("[Service]\nExecStart=/home/x/run.sh\n")
        self.assertEqual(entry.severity, "medium")


class KernelHelperTests(ArchBox):
    def setUp(self):
        super().setUp()
        make_proc_root(self.proc)
        self.add_pkg("systemd", "255-1", "/usr/lib/systemd/systemd-coredump", repo="core", packager=ARCH)
        self.add_pkg("kmod", "31-1", "/usr/bin/kmod", repo="core", packager=ARCH)
        self.table[("pacman", "-Qo", "/usr/bin/kmod")] = "/usr/bin/kmod is owned by kmod 31-1"

    def sysctl(self, name, value):
        _write(self.proc / "sys/kernel" / name, value + "\n")

    def test_core_pattern_to_tmp_is_critical(self):
        self.sysctl("core_pattern", "|/tmp/.h/dump %p")
        row, finding = self.weird.core_pattern_state()
        self.assertIn("temporary", row)
        self.assertEqual((finding.severity, finding.attack), ("critical", "T1546"))

    def test_systemd_coredump_is_clean(self):
        self.sysctl("core_pattern", "|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h")
        row, finding = self.weird.core_pattern_state()
        self.assertIsNone(finding)
        self.assertEqual(row, "piped to /usr/lib/systemd/systemd-coredump")

    def test_plain_core_file_is_clean(self):
        self.sysctl("core_pattern", "core")
        self.assertIsNone(self.weird.core_pattern_state()[1])

    def test_missing_modprobe_helper_is_critical(self):
        self.sysctl("modprobe", "/dev/shm/modprobe")
        row, finding = self.weird.modprobe_state()
        self.assertEqual((finding.severity, finding.attack), ("critical", "T1547.006"))

    def test_packaged_modprobe_is_clean(self):
        self.sysctl("modprobe", "/usr/bin/kmod")
        self.assertIsNone(self.weird.modprobe_state()[1])

    def test_unreadable_sysctls_are_unavailable(self):
        self.assertEqual(self.weird.core_pattern_state(), ("unavailable", None))
        self.assertEqual(self.weird.modprobe_state(), ("unavailable", None))

    def test_cmdline_flags(self):
        rows, findings = self.weird.cmdline_posture("BOOT_IMAGE=/vmlinuz root=/dev/sda1 audit=0 nokaslr init=/tmp/init")
        kinds = {(f.detail.split(":")[0], f.severity) for f in findings}
        self.assertIn(("audit=0 on the command line", "medium"), kinds)
        self.assertIn(("init=/tmp/init is not a standard init path", "medium"), kinds)
        self.assertIn(("nokaslr", "info"), kinds)
        self.assertIn("audit=0", rows["cmdline"])

    def test_cmdline_hardened_is_positive(self):
        rows, findings = self.weird.cmdline_posture("root=/dev/sda1 module.sig_enforce=1 ima_policy=tcb lockdown=integrity")
        self.assertEqual([f.severity for f in findings], ["info"])
        self.assertIn("module.sig_enforce=1", findings[0].detail)

    def test_posture_rows_present(self):
        self.sysctl("core_pattern", "core")
        self.sysctl("modprobe", "/usr/bin/kmod")
        _write(self.proc / "cmdline", "root=/dev/sda1\n")
        posture = self.weird.kernel_posture()
        self.assertEqual(posture["core_pattern"], "file core")
        self.assertEqual(posture["modprobe"], "/usr/bin/kmod")
        self.assertIn("no IMA", posture["cmdline"])


PACMAN_LOG = """[2026-01-10T10:00:00+0000] [ALPM] installed foo (1.0-1)
[2026-01-10T10:05:00+0000] [ALPM] installed bar (2.0-1)
[2026-02-01T09:00:00+0000] [ALPM] upgraded foo (1.0-1 -> 1.1-1)
[2026-02-02T09:00:00+0000] [ALPM] removed bar (2.0-1)
[2026-02-03T12:00:00+0000] [ALPM] installed foo-aur (3.0-1)
"""


class PacmanHistoryTests(ArchBox):
    sandbox_dir = sandbox_root()

    def setUp(self):
        super().setUp()
        _write(self.sysroot / "var/log/pacman.log", PACMAN_LOG)
        self.add_pkg("foo-aur", "3.0-1", "/usr/bin/foo-aur", packager="Me <me@x>")
        self.add_pkg("foo", "1.1-1", "/usr/bin/foo", repo="extra", packager=ARCH)

    def test_history_rows(self):
        rows = self.weird.pacman_history()
        self.assertEqual([(r[1], r[2], r[3]) for r in rows][:3],
                         [("installed", "foo", "1.0-1"), ("installed", "bar", "2.0-1"), ("upgraded", "foo", "1.1-1")])
        self.assertEqual(self.weird.pacman_history_install_time("foo"), rows[2][0])

    def test_installed_then_removed(self):
        self.assertEqual([r[0] for r in self.weird.installed_then_removed()], ["bar"])

    def test_foreign_installs_in_window(self):
        rows = self.weird.pacman_history()
        aur_ts = rows[-1][0]
        hits = self.weird.foreign_installs_in_windows([(aur_ts - 60, aur_ts + 60)])
        self.assertEqual([r[2] for r in hits], ["foo-aur"])
        self.assertEqual(self.weird.foreign_installs_in_windows([(0, 10)]), [])

    def test_rotated_gzip_log_is_read(self):
        import gzip
        with gzip.open(str(self.sysroot / "var/log/pacman.log.1.gz"), "wt") as f:
            f.write("[2025-12-01T08:00:00+0000] [ALPM] installed old (0.1-1)\n")
        self.assertEqual(self.weird.pacman_history()[0][2], "old")

    def test_missing_log_is_empty(self):
        os.remove(self.sysroot / "var/log/pacman.log")
        self.assertEqual(self.weird.pacman_history(), [])
        self.assertEqual(self.weird.language_cache_findings(), [])


class LanguageCacheTests(ArchBox):
    sandbox_dir = sandbox_root()

    def setUp(self):
        super().setUp()
        self.aur_ts = int(time.time()) - 86400
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S+0000", time.gmtime(self.aur_ts))
        _write(self.sysroot / "var/log/pacman.log", f"[{stamp}] [ALPM] installed node-thing (1.0-1)\n")
        self.add_pkg("node-thing", "1.0-1", "/usr/bin/node-thing", packager="Me <me@x>")
        with open(self.local_dir / "node-thing-1.0-1/desc", "a") as f:
            f.write("%MAKEDEPENDS%\nnpm\n\n")

    def cache_entry(self, when):
        path = self.home / ".bun/install/cache/evil-pkg@1.0.0"
        path.mkdir(parents=True)
        os.utime(path, (when, when))

    def test_fetch_during_build_window_is_medium(self):
        self.cache_entry(self.aur_ts - 600)
        findings = self.weird.language_cache_findings()
        self.assertEqual(len(findings), 1)
        self.assertEqual((findings[0].severity, findings[0].subject), ("medium", "node-thing"))
        self.assertIn("evil-pkg@1.0.0", findings[0].detail)

    def test_fetch_outside_window_is_clean(self):
        self.cache_entry(self.aur_ts - 7200)
        self.assertEqual(self.weird.language_cache_findings(), [])

    def test_package_without_node_deps_is_clean(self):
        self.add_pkg("c-thing", "1.0-1", "/usr/bin/c-thing", packager="Me <me@x>")
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S+0000", time.gmtime(self.aur_ts + 3600))
        with open(self.sysroot / "var/log/pacman.log", "a") as f:
            f.write(f"[{stamp}] [ALPM] installed c-thing (1.0-1)\n")
        self.cache_entry(self.aur_ts + 3000)
        self.assertEqual(self.weird.language_cache_findings(), [])


MOUNTINFO_CLEAN = """22 1 0:21 / /proc rw,nosuid - proc proc rw
23 1 0:22 / /sys rw - sysfs sysfs rw
24 22 0:23 / /proc/sys/fs/binfmt_misc rw - autofs systemd-1 rw
"""


class ProcMountTests(ArchBox):
    def setUp(self):
        super().setUp()
        make_proc_root(self.proc)

    def mounts(self, text):
        _write(self.proc / "self/mountinfo", text)
        return self.weird.proc_mount_findings()

    def test_bind_over_pid_is_critical(self):
        found = self.mounts(MOUNTINFO_CLEAN + "25 22 0:24 / /proc/4242 rw - tmpfs tmpfs rw\n")
        self.assertEqual([(f.severity, f.attack) for f in found], [("critical", "T1564")])
        self.assertIn("pid 4242", found[0].detail)

    def test_fake_proc_is_critical(self):
        found = self.mounts(MOUNTINFO_CLEAN.replace("- proc proc rw", "- fuse fake rw"))
        self.assertEqual(len(found), 1)
        self.assertIn("not proc", found[0].detail)

    def test_clean_mounts_are_clean(self):
        self.assertEqual(self.mounts(MOUNTINFO_CLEAN), [])

    def test_missing_mountinfo_is_info(self):
        self.assertEqual([f.severity for f in self.weird.proc_mount_findings()], ["info"])


class PidProbeTests(ArchBox):
    def setUp(self):
        super().setUp()
        make_proc_root(self.proc)
        _write(self.proc / "sys/kernel/pid_max", "64\n")
        make_proc(self.proc, 1, "/usr/bin/init")
        make_proc(self.proc, 7, "/usr/bin/daemon")

    def test_pid_only_in_proc_is_flagged(self):
        with mock.patch.object(self.weird, "getpgid_probe", side_effect=lambda pid: pid == 1):
            hidden = self.weird.find_hidden_pids()
        self.assertEqual([(h["pid"], h["mismatch"]) for h in hidden], [(7, "proc only")])

    def test_pid_only_in_kernel_is_flagged(self):
        with mock.patch.object(self.weird, "getpgid_probe", side_effect=lambda pid: pid in (1, 7, 9)):
            hidden = self.weird.find_hidden_pids()
        self.assertEqual([(h["pid"], h["mismatch"]) for h in hidden], [(9, "getpgid only")])

    def test_agreeing_interfaces_are_clean(self):
        with mock.patch.object(self.weird, "getpgid_probe", side_effect=lambda pid: pid in (1, 7)):
            self.assertEqual(self.weird.find_hidden_pids(), [])

    def test_replayed_tree_skips_the_probe(self):
        self.assertIsNone(self.weird.getpgid_probe(1))
        self.assertEqual(self.weird.find_hidden_pids(), [])


def big_anon_maps(exe):
    return [f"00400000-00500000 r-xp 00000000 08:01 1 {exe}",
            "7f0000000000-7f0001000000 rwxp 00000000 00:00 0",
            "7f0002000000-7f0002100000 rw-p 00000000 00:00 0",
            "7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0 [stack]"]


class AnonExecTests(ArchBox):
    def setUp(self):
        super().setUp()
        make_proc_root(self.proc)

    def proc_with_maps(self, pid, exe, comm=None):
        make_stub_file(self.sysroot, exe)
        make_proc(self.proc, pid, exe, comm=comm, maps=big_anon_maps(exe))
        return self.weird.ProcessInfo(pid=pid, name=comm or os.path.basename(exe), path=exe, cmdline=exe, uid=1000)

    def test_unknown_binary_with_16mb_anon_exec_fires(self):
        proc = self.proc_with_maps(300, "/opt/thing/agent")
        self.assertEqual(self.weird.anonymous_exec_bytes(300), (16 * 1024 * 1024, False))
        self.assertGreater(self.weird.anon_exec_signal(proc), 0)
        self.assertIn("anon_exec_region", proc.signal_keys)
        self.assertIn("16 MB", proc.evidence[-1])

    def test_node_is_allowlisted(self):
        proc = self.proc_with_maps(301, "/usr/bin/node", comm="npm exec thing")
        self.assertEqual(self.weird.anon_exec_signal(proc), 0)

    def test_jit_thread_evidence_is_allowlisted(self):
        proc = self.proc_with_maps(302, "/opt/bunapp/app")
        _write(self.proc / "302/task/303/comm", "JITWorker\n")
        self.assertEqual(self.weird.anon_exec_signal(proc), 0)

    def test_small_anon_region_is_clean(self):
        make_stub_file(self.sysroot, "/opt/small/tool")
        make_proc(self.proc, 304, "/opt/small/tool", maps=["7f0000000000-7f0000100000 rwxp 00000000 00:00 0"])
        proc = self.weird.ProcessInfo(pid=304, name="tool", path="/opt/small/tool", cmdline="tool", uid=1000)
        self.assertEqual(self.weird.anon_exec_signal(proc), 0)

    def test_unreadable_maps_is_clean(self):
        proc = self.weird.ProcessInfo(pid=305, name="ghost", path="/opt/ghost", cmdline="ghost", uid=1000)
        self.assertEqual(self.weird.anon_exec_signal(proc), 0)


if __name__ == "__main__":
    unittest.main()
