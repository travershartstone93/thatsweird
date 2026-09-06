import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from fixtures import make_proc, make_stub_file  # noqa: E402
from test_arch import ARCH, ArchBox  # noqa: E402

DAEMON = "/opt/thing/bin/zzdaemon"
CAP_SYS_ADMIN = f"{1 << 21:016x}"


class SignalBox(ArchBox):
    def setUp(self):
        super().setUp()
        self.scores = self.weird.load_policy()["scores"]

    def unowned(self, path):
        make_stub_file(self.sysroot, path)
        self.table[("pacman", "-Qo", path)] = None

    def add_official(self, name, version, path):
        self.add_pkg(name, version, path, repo="extra", packager=ARCH)

    def assert_signal(self, proc, key, technique, needle):
        self.assertIn(key, proc.signal_keys, proc.evidence)
        self.assertIn(technique, proc.attack)
        reason = proc.reasons[proc.signal_keys.index(key)]
        self.assertIn(needle, reason)
        self.assertTrue(reason.endswith(f"(+{self.scores[key]})"), reason)


class Masquerade(SignalBox):
    def test_masquerade_by_name(self):
        self.unowned("/tmp/.x/sshd")
        make_proc(self.proc, 500, "/tmp/.x/sshd", comm="sshd", cmdline=["sshd", "-D"])
        proc, alerts, code = self.scan_pid(500)
        self.assert_signal(proc, "masquerade", "T1036.005", "sshd")
        self.assertIn("suspicious_path", proc.signal_keys)
        self.assertEqual(proc.weirdness_score, self.scores["masquerade"] + self.scores["suspicious_path"])
        self.assertEqual(self.weird.verdict_for(proc), "Likely malicious")
        self.assertEqual(code, 2)
        self.assertEqual([a["pid"] for a in alerts], [500])

    def test_argv0_counts_too(self):
        self.unowned("/opt/thing/bin/zzdaemon")
        make_proc(self.proc, 502, DAEMON, comm="zzdaemon", cmdline=["/opt/thing/bin/systemd", "--user"])
        proc, _, _ = self.scan_pid(502)
        self.assert_signal(proc, "masquerade", "T1036.005", "systemd")

    def test_packaged_sshd_is_clean(self):
        self.add_official("openssh", "10.0p1-1", "/usr/bin/sshd")
        make_proc(self.proc, 501, "/usr/bin/sshd", comm="sshd", cmdline=["sshd", "-D"])
        proc, alerts, code = self.scan_pid(501)
        self.assertEqual(proc.trust_level, self.weird.TrustLevel.OFFICIAL_REPO, proc.evidence)
        self.assertEqual(proc.signal_keys, [])
        self.assertEqual(proc.weirdness_score, 0)
        self.assertEqual(code, 0)


class LdPreload(SignalBox):
    def test_ld_preload_env(self):
        self.unowned(DAEMON)
        make_proc(self.proc, 510, DAEMON, environ={"HOME": "/home/user1000", "LD_PRELOAD": "/tmp/a.so"})
        proc, _, code = self.scan_pid(510)
        self.assert_signal(proc, "ld_preload", "T1574.006", "LD_PRELOAD=/tmp/a.so")
        self.assertEqual(proc.weirdness_score, self.scores["ld_preload"])
        self.assertEqual(code, 1)

    def test_ld_library_path_in_home(self):
        self.unowned(DAEMON)
        make_proc(self.proc, 511, DAEMON, environ={"HOME": "/srv/build", "LD_LIBRARY_PATH": "/usr/lib:/srv/build/lib"})
        proc, _, _ = self.scan_pid(511)
        self.assert_signal(proc, "ld_library_path", "T1574.006", "LD_LIBRARY_PATH=/srv/build/lib")
        self.assertNotIn("ld_preload", proc.signal_keys)

    def test_ld_library_path_alone_scores_low(self):
        self.unowned(DAEMON)
        make_proc(self.proc, 514, DAEMON, environ={"HOME": "/home/u", "LD_LIBRARY_PATH": "/home/u/steam/lib"})
        proc, _, _ = self.scan_pid(514)
        self.assertEqual(proc.signal_keys, ["ld_library_path"])
        self.assertEqual(proc.weirdness_score, 10)
        self.assertEqual(self.scores["ld_library_path"], 10)

    def test_ld_preload_with_library_path_scores_full(self):
        self.unowned(DAEMON)
        make_proc(self.proc, 515, DAEMON, environ={"HOME": "/home/u", "LD_PRELOAD": "/tmp/x.so",
                                                    "LD_LIBRARY_PATH": "/home/u/steam/lib"})
        proc, _, _ = self.scan_pid(515)
        self.assert_signal(proc, "ld_preload", "T1574.006", "LD_PRELOAD=/tmp/x.so")
        self.assertEqual(proc.weirdness_score, 30)
        self.assertNotIn("ld_library_path", proc.signal_keys)

    def test_packaged_library_not_scored(self):
        self.add_official("jemalloc", "1:5.3.0-4", "/usr/lib/libjemalloc.so.2")
        self.unowned(DAEMON)
        make_proc(self.proc, 512, DAEMON, environ={"HOME": "/home/user1000", "LD_PRELOAD": "/usr/lib/libjemalloc.so.2"})
        proc, _, _ = self.scan_pid(512)
        self.assertNotIn("ld_preload", proc.signal_keys)
        self.assertEqual(proc.weirdness_score, 0)

    def test_packaged_library_in_temp_dir_is_evidence_only(self):
        self.add_official("weird-shim", "1.0-1", "/var/tmp/libshim.so")
        self.unowned(DAEMON)
        make_proc(self.proc, 513, DAEMON, environ={"HOME": "/home/user1000", "LD_PRELOAD": "/var/tmp/libshim.so"})
        proc, _, _ = self.scan_pid(513)
        self.assertNotIn("ld_preload", proc.signal_keys)
        self.assertEqual(proc.weirdness_score, 0)
        self.assertTrue(any("owned by package weird-shim" in e for e in proc.evidence), proc.evidence)


class Traced(SignalBox):
    def test_tracerpid(self):
        self.unowned(DAEMON)
        self.unowned("/opt/thing/bin/zzinjector")
        make_proc(self.proc, 520, DAEMON, status_extra={"TracerPid": "4242"})
        make_proc(self.proc, 4242, "/opt/thing/bin/zzinjector")
        proc, _, _ = self.scan_pid(520)
        self.assert_signal(proc, "traced", "T1055", "traced by pid 4242 (zzinjector)")
        self.assertEqual(proc.weirdness_score, self.scores["traced"])

    def test_not_traced(self):
        self.unowned(DAEMON)
        make_proc(self.proc, 521, DAEMON)
        proc, _, _ = self.scan_pid(521)
        self.assertNotIn("traced", proc.signal_keys)
        self.assertEqual(proc.weirdness_score, 0)

    def test_known_debugger_not_scored(self):
        self.add_official("gdb", "17.1-1", "/usr/bin/gdb")
        self.unowned(DAEMON)
        make_proc(self.proc, 522, DAEMON, status_extra={"TracerPid": "4243"})
        make_proc(self.proc, 4243, "/usr/bin/gdb", cmdline=["gdb", "-p", "522"])
        proc, _, _ = self.scan_pid(522)
        self.assertNotIn("traced", proc.signal_keys)
        self.assertEqual(proc.weirdness_score, 0)
        self.assertTrue(any("known debugger" in e for e in proc.evidence), proc.evidence)


class ElevatedCaps(SignalBox):
    def test_caps_on_nonroot(self):
        self.unowned(DAEMON)
        make_proc(self.proc, 530, DAEMON, uid=1000, status_extra={"CapEff": CAP_SYS_ADMIN})
        proc, _, _ = self.scan_pid(530)
        self.assert_signal(proc, "elevated_caps", "T1068", "CAP_SYS_ADMIN")
        self.assertEqual(proc.weirdness_score, self.scores["elevated_caps"])

    def test_caps_on_root_not_scored(self):
        self.unowned(DAEMON)
        make_proc(self.proc, 531, DAEMON, uid=0, status_extra={"CapEff": CAP_SYS_ADMIN})
        proc, _, _ = self.scan_pid(531)
        self.assertNotIn("elevated_caps", proc.signal_keys)
        self.assertEqual(proc.weirdness_score, 0)

    def test_caps_in_user_namespace_not_scored(self):
        self.unowned(DAEMON)
        d = make_proc(self.proc, 532, DAEMON, uid=1000, status_extra={"CapEff": CAP_SYS_ADMIN})
        (d / "uid_map").write_text("         0       1000          1\n")
        proc, _, _ = self.scan_pid(532)
        self.assertNotIn("elevated_caps", proc.signal_keys)
        self.assertTrue(any("user namespace" in e for e in proc.evidence), proc.evidence)


class RawIpOutbound(SignalBox):
    def test_raw_ip_outbound(self):
        self.unowned(DAEMON)
        make_proc(self.proc, 540, DAEMON, connections=[("203.0.113.5", 4444, "ESTABLISHED")])
        proc, _, _ = self.scan_pid(540)
        self.assert_signal(proc, "raw_ip_outbound", "T1071", "203.0.113.5:4444")
        self.assertEqual(proc.weirdness_score, self.scores["raw_ip_outbound"])
        self.assertEqual([(c.remote_address, c.remote_port) for c in proc.connections], [("203.0.113.5", 4444)])

    def test_official_firefox_to_https_not_scored(self):
        self.add_official("firefox", "143.0-1", "/usr/lib/firefox/firefox")
        make_proc(self.proc, 541, "/usr/lib/firefox/firefox", comm="firefox",
                  connections=[("203.0.113.5", 443, "ESTABLISHED")])
        proc, _, code = self.scan_pid(541)
        self.assertEqual(proc.trust_level, self.weird.TrustLevel.OFFICIAL_REPO, proc.evidence)
        self.assertNotIn("raw_ip_outbound", proc.signal_keys)
        self.assertEqual(proc.weirdness_score, 0)
        self.assertEqual(code, 0)

    def test_common_port_and_private_ip_not_scored(self):
        self.unowned(DAEMON)
        make_proc(self.proc, 542, DAEMON, connections=[("203.0.113.5", 443, "ESTABLISHED"),
                                                       ("192.168.1.20", 4444, "ESTABLISHED"),
                                                       ("203.0.113.9", 4444, "TIME_WAIT")])
        proc, _, _ = self.scan_pid(542)
        self.assertNotIn("raw_ip_outbound", proc.signal_keys)
        self.assertEqual(proc.weirdness_score, 0)

    def test_sockets_of_other_processes_not_attributed(self):
        self.unowned(DAEMON)
        self.unowned("/opt/thing/bin/zzother")
        make_proc(self.proc, 543, "/opt/thing/bin/zzother", connections=[("203.0.113.5", 4444, "ESTABLISHED")])
        make_proc(self.proc, 544, DAEMON)
        proc, _, _ = self.scan_pid(544)
        self.assertNotIn("raw_ip_outbound", proc.signal_keys)
        self.assertEqual(proc.connections, [])


if __name__ == "__main__":
    unittest.main()
