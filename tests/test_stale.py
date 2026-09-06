import contextlib
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from fixtures import make_proc, make_proc_root, make_stub_file  # noqa: E402
from helpers import scan_args  # noqa: E402
from test_arch import ARCH, ArchBox  # noqa: E402

T = 1_800_000_000            # package installdate
BOOT = T - 7200
BEFORE = 3600 * 100          # ticks since boot: started an hour before the upgrade
AFTER = 10800 * 100          # started an hour after the upgrade

DEALSCOUT = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/dealscout.service"
SESSION = "0::/user.slice/user-1000.slice/session-2.scope"


class StaleBox(ArchBox):
    def setUp(self):
        super().setUp()
        make_proc_root(self.proc, btime=BOOT)
        self.critical = self.weird.load_policy()["thresholds"]["critical"]

    def add_official(self, name, version, path):
        self.add_pkg(name, version, path, repo="extra", packager=ARCH, installdate=T)

    def restart_needed(self, **overrides):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = self.weird.cmd_restart_needed(scan_args(**overrides))
        return out.getvalue(), code


class StaleAfterUpgrade(StaleBox):
    def test_stale_after_upgrade_is_not_critical(self):
        self.add_official("pipewire", "1:1.6.2-1", "/usr/bin/pipewire")
        make_proc(self.proc, 300, "/usr/bin/pipewire", deleted=True, starttime=BEFORE)
        proc, alerts, code = self.scan_pid(300)
        self.assertEqual(self.weird.classify_deleted_exe(proc, proc.provenance), "stale_after_upgrade")
        self.assertTrue(proc.is_stale)
        self.assertTrue(proc.is_deleted)
        self.assertEqual(proc.trust_level, self.weird.TrustLevel.OFFICIAL_REPO, proc.evidence)
        self.assertLess(proc.weirdness_score, self.critical)
        self.assertEqual(proc.weirdness_score, self.weird.load_policy()["scores"]["stale_after_upgrade"])
        reasons = [e for e in proc.evidence if "restart" in e]
        self.assertTrue(reasons, proc.evidence)
        self.assertIn("pipewire", reasons[0])
        self.assertIn(code, (0, 1))
        self.assertFalse([a for a in alerts if a["severity"] == "critical"], alerts)

    def test_deleted_after_start_is_critical(self):
        self.add_official("pipewire", "1:1.6.2-1", "/usr/bin/pipewire")
        make_proc(self.proc, 300, "/usr/bin/pipewire", deleted=True, starttime=AFTER)
        proc, alerts, code = self.scan_pid(300)
        self.assertEqual(self.weird.classify_deleted_exe(proc, proc.provenance), "deleted")
        self.assertFalse(proc.is_stale)
        self.assertGreaterEqual(proc.weirdness_score, self.weird.load_policy()["scores"]["deleted_exe"])
        self.assertEqual(code, 2)
        self.assertEqual([(a["pid"], a["severity"]) for a in alerts], [(300, "critical")])

    def test_deleted_and_path_gone_is_critical(self):
        self.add_official("pipewire", "1:1.6.2-1", "/usr/bin/pipewire")
        (self.sysroot / "usr/bin/pipewire").unlink()
        make_proc(self.proc, 300, "/usr/bin/pipewire", deleted=True, starttime=BEFORE)
        proc, alerts, code = self.scan_pid(300)
        self.assertEqual(self.weird.classify_deleted_exe(proc, proc.provenance), "deleted")
        self.assertFalse(proc.is_stale)
        self.assertEqual(code, 2)
        self.assertEqual([a["pid"] for a in alerts], [300])

    def test_unowned_deleted_is_critical(self):
        make_stub_file(self.sysroot, "/opt/thing/bin/daemon")
        self.table[("pacman", "-Qo", "/opt/thing/bin/daemon")] = None
        make_proc(self.proc, 400, "/opt/thing/bin/daemon", deleted=True, starttime=BEFORE)
        proc, alerts, code = self.scan_pid(400)
        self.assertEqual(self.weird.classify_deleted_exe(proc, proc.provenance), "deleted")
        self.assertFalse(proc.is_stale)
        self.assertEqual(code, 2)
        self.assertEqual([a["pid"] for a in alerts], [400])

    def test_json_includes_stale_fields(self):
        self.add_official("pipewire", "1:1.6.2-1", "/usr/bin/pipewire")
        make_proc(self.proc, 300, "/usr/bin/pipewire", deleted=True, starttime=BEFORE)
        proc, _, _ = self.scan_pid(300)
        as_json = json.loads(json.dumps(self.weird.process_to_dict(proc)))
        self.assertTrue(as_json["is_stale"])
        self.assertEqual(as_json["stale_libs"], [])
        self.assertEqual(as_json["start_time"], BOOT + BEFORE / 100)


class RestartNeeded(StaleBox):
    def test_groups_by_unit(self):
        self.add_official("python", "3.13.7-1", "/usr/bin/python3")
        self.add_official("kwin", "6.5.0-1", "/usr/bin/kwin_wayland")
        make_proc(self.proc, 500, "/usr/bin/python3", deleted=True, starttime=BEFORE, cgroup=DEALSCOUT)
        make_proc(self.proc, 501, "/usr/bin/python3", deleted=True, starttime=BEFORE, cgroup=DEALSCOUT)
        make_proc(self.proc, 600, "/usr/bin/kwin_wayland", deleted=True, starttime=BEFORE, cgroup=SESSION)
        text, code = self.restart_needed()
        self.assertEqual(code, 1)
        self.assertIn("systemctl --user restart dealscout.service", text)
        self.assertIn("session-2.scope", text)

        text, code = self.restart_needed(json=True)
        self.assertEqual(code, 1)
        data = json.loads(text)
        self.assertEqual(data["stale_processes"], 3)
        self.assertEqual(len(data["groups"]), 2)
        by_unit = {g["unit"]: g for g in data["groups"]}
        self.assertEqual([p["pid"] for p in by_unit["dealscout.service"]["processes"]], [500, 501])
        self.assertEqual(by_unit["dealscout.service"]["manager"], "user")
        self.assertEqual(by_unit["session-2.scope"]["manager"], "system")
        self.assertEqual([p["pid"] for p in by_unit["session-2.scope"]["processes"]], [600])
        for group in data["groups"]:
            for p in group["processes"]:
                self.assertTrue(p["is_stale"])
                self.assertEqual(p["stale_libs"], [])

    def test_stale_lib_only(self):
        self.add_official("python", "3.13.7-1", "/usr/bin/python3")
        self.add_official("openssl", "3.5.2-1", "/usr/lib/libssl.so.3")
        maps = [
            "5648cf883000-5648cf885000 r--p 00000000 00:23 1725820                    /usr/bin/python3",
            "5648cf885000-5648cf890000 r-xp 00002000 00:23 1725820                    /usr/bin/python3",
            "7f10a0000000-7f10a0100000 r-xp 00000000 00:23 1725999                    /usr/lib/libssl.so.3 (deleted)",
            "7ffd0d3e5000-7ffd0d406000 rw-p 00000000 00:00 0                          [stack]",
        ]
        make_proc(self.proc, 500, "/usr/bin/python3", starttime=BEFORE, cgroup=DEALSCOUT, maps=maps)
        proc, alerts, code = self.scan_pid(500)
        self.assertFalse(proc.is_stale)
        self.assertEqual(proc.stale_libs, ["/usr/lib/libssl.so.3"])
        self.assertEqual(proc.weirdness_score, 0)
        self.assertEqual(code, 0)
        self.assertEqual(alerts, [])

        text, code = self.restart_needed()
        self.assertEqual(code, 1)
        self.assertIn("library libssl.so.3", text)
        self.assertIn("dealscout.service", text)
        self.assertNotIn("exe ", text)

    def test_nothing_stale(self):
        self.add_official("python", "3.13.7-1", "/usr/bin/python3")
        make_proc(self.proc, 500, "/usr/bin/python3", starttime=BEFORE, cgroup=DEALSCOUT)
        text, code = self.restart_needed()
        self.assertEqual(code, 0)
        self.assertIn("nothing to restart", text.lower())

        text, code = self.restart_needed(json=True)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(text)["groups"], [])

    def test_uses_same_logic_as_a6(self):
        self.add_official("pipewire", "1:1.6.2-1", "/usr/bin/pipewire")
        self.add_official("kwin", "6.5.0-1", "/usr/bin/kwin_wayland")
        (self.sysroot / "usr/bin/kwin_wayland").unlink()
        make_stub_file(self.sysroot, "/opt/thing/bin/daemon")
        self.table[("pacman", "-Qo", "/opt/thing/bin/daemon")] = None
        make_proc(self.proc, 300, "/usr/bin/pipewire", deleted=True, starttime=AFTER, cgroup=DEALSCOUT)
        make_proc(self.proc, 600, "/usr/bin/kwin_wayland", deleted=True, starttime=BEFORE, cgroup=SESSION)
        make_proc(self.proc, 400, "/opt/thing/bin/daemon", deleted=True, starttime=BEFORE, cgroup=DEALSCOUT)
        _, _, code = self.weird.run_scan(scan_args(verbose=True))
        self.assertEqual(code, 2)
        text, code = self.restart_needed()
        self.assertEqual(code, 0)
        self.assertIn("nothing to restart", text.lower())


if __name__ == "__main__":
    unittest.main()
