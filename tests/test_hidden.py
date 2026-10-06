import contextlib
import io
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

from fixtures import _write, make_proc  # noqa: E402
from helpers import scan_args  # noqa: E402
from test_arch import ARCH, ArchBox  # noqa: E402

SS_LINE = ('tcp ESTAB 0 0 10.0.0.2:40000 1.2.3.4:443 users:(("curl",pid=500,fd=3)) '
           'uid:1000 ino:{inode} sk:1 cgroup:/user.slice <->\n')


class HiddenBox(ArchBox):
    def setUp(self):
        super().setUp()
        _write(self.proc / "sys/kernel/pid_max", "5000\n")
        self.add_pkg("bash", "5.3.15-2", "/usr/bin/bash", repo="core", packager=ARCH)
        make_proc(self.proc, 100, "/usr/bin/bash")
        make_proc(self.proc, 4242, "/usr/bin/bash", comm="evil")

    def hidden(self, **overrides):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = self.weird.cmd_hidden(scan_args(**overrides))
        return out.getvalue(), code

    def hidden_json(self):
        out, code = self.hidden(json=True)
        return json.loads(out), code

    def hide(self, pid):
        original = self.weird.list_pids_readdir
        return mock.patch.object(self.weird, "list_pids_readdir", side_effect=lambda: original() - {pid})


class HiddenPids(HiddenBox):
    def test_hidden_pid_detected(self):
        with self.hide(4242):
            payload, code = self.hidden_json()
        self.assertEqual(code, 2)
        self.assertEqual([h["pid"] for h in payload["hidden_pids"]], [4242])
        self.assertEqual(payload["hidden_pids"][0]["name"], "evil")
        hit = [f for f in payload["findings"] if f["kind"] == "hidden pid"]
        self.assertEqual(len(hit), 1, payload["findings"])
        self.assertEqual((hit[0]["severity"], hit[0]["attack"]), ("critical", "T1564.001"))
        self.assertIn("pid 4242 (evil): present in /proc but absent from the directory listing", hit[0]["detail"])
        self.assertEqual(payload["pid_max"], 5000)
        with self.hide(4242):
            out, code = self.hidden()
        self.assertEqual(code, 2)
        self.assertIn("hidden pid", out)
        self.assertIn("absent from the directory", out)
        self.assertIn("unhide", out)

    def test_no_hidden_pids(self):
        payload, code = self.hidden_json()
        self.assertEqual(code, 0)
        self.assertEqual(payload["hidden_pids"], [])
        self.assertEqual([f for f in payload["findings"] if f["severity"] != "info"], [])
        self.assertEqual(payload["listed_pids"], 2)
        out, code = self.hidden()
        self.assertEqual(code, 0)
        self.assertIn("Every pid, thread and socket", out)
        self.assertIn("2 pids listed, pids 1..5000 probed", out)

    def test_thread_id_is_not_a_hidden_process(self):
        make_proc(self.proc, 4300, "/usr/bin/bash", status_extra={"Tgid": "100"})
        with self.hide(4300):
            payload, code = self.hidden_json()
        self.assertEqual(code, 0)
        self.assertEqual(payload["hidden_pids"], [])

    def test_pid_max_respected(self):
        original = self.weird.probe_pid
        with mock.patch.object(self.weird, "probe_pid", side_effect=original) as spy:
            hidden = self.weird.find_hidden_pids()
        self.assertEqual(hidden, [])
        probed = [call.args[0] for call in spy.call_args_list]
        self.assertEqual(max(probed), 5000)
        self.assertEqual(min(probed), 1)
        self.assertEqual(len(probed), 5000 - 2)
        self.assertNotIn(100, probed)

    def test_default_probe_stops_above_the_last_pid_assigned(self):
        _write(self.proc / "sys/kernel/pid_max", "100000\n")
        _write(self.proc / "loadavg", "0.50 0.40 0.30 1/2 3000\n")
        self.assertEqual(self.weird.hidden_probe_limit({100, 4242}), 6242)
        self.assertEqual(self.weird.hidden_probe_limit({100, 4242}, deep=True), 100000)
        _write(self.proc / "loadavg", "0.50 0.40 0.30 1/2 90000\n")
        self.assertEqual(self.weird.hidden_probe_limit({100}), 94500)
        _write(self.proc / "loadavg", "0.50 0.40 0.30 1/2 99000\n")
        self.assertEqual(self.weird.hidden_probe_limit({100}), 100000)
        os.remove(self.proc / "loadavg")
        self.assertEqual(self.weird.hidden_probe_limit({100}), 100000)
        _write(self.proc / "loadavg", "0.50 0.40 0.30 1/2 3000\n")
        original = self.weird.probe_pid
        with mock.patch.object(self.weird, "probe_pid", side_effect=original) as spy:
            out, _ = self.hidden()
        self.assertEqual(max(call.args[0] for call in spy.call_args_list), 6242)
        self.assertIn("2 pids listed, pids 1..6242 probed", out)
        payload, _ = self.hidden_json()
        self.assertEqual((payload["pid_max"], payload["probed_to"]), (100000, 6242))

    def test_pid_above_the_mark_needs_deep(self):
        _write(self.proc / "sys/kernel/pid_max", "100000\n")
        _write(self.proc / "loadavg", "0.50 0.40 0.30 1/2 1000\n")
        with self.hide(4242):
            payload, code = self.hidden_json()
            self.assertEqual((code, payload["hidden_pids"]), (0, []))
            out, code = self.hidden(json=True, deep=True)
        payload = json.loads(out)
        self.assertEqual((code, [h["pid"] for h in payload["hidden_pids"]]), (2, [4242]))
        self.assertEqual(payload["probed_to"], 100000)

    def test_pid_max_default_and_cap(self):
        os.remove(self.proc / "sys/kernel/pid_max")
        self.assertEqual(self.weird.read_pid_max(), 32768)
        _write(self.proc / "sys/kernel/pid_max", "99999999\n")
        self.assertEqual(self.weird.read_pid_max(), 4194304)


class ThreadAndLoadViews(HiddenBox):
    def test_thread_count_mismatch(self):
        make_proc(self.proc, 300, "/usr/bin/bash", status_extra={"Threads": "1"})
        for tid in (300, 301, 302):
            (self.proc / "300/task" / str(tid)).mkdir(parents=True)
        payload, code = self.hidden_json()
        self.assertEqual(code, 1)
        hit = [f for f in payload["findings"] if f["kind"] == "thread count mismatch"]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["severity"], "medium")
        self.assertIn("status says 1 threads, /proc/300/task lists 3", hit[0]["detail"])

    def test_thread_count_match_is_quiet(self):
        make_proc(self.proc, 300, "/usr/bin/bash", status_extra={"Threads": "2"})
        for tid in (300, 301):
            (self.proc / "300/task" / str(tid)).mkdir(parents=True)
        payload, code = self.hidden_json()
        self.assertEqual(code, 0)
        self.assertEqual([f for f in payload["findings"] if f["kind"] == "thread count mismatch"], [])

    def test_loadavg_mismatch_needs_margin(self):
        _write(self.proc / "loadavg", "0.50 0.40 0.30 1/2 4243\n")
        payload, _ = self.hidden_json()
        self.assertEqual([f for f in payload["findings"] if f["kind"] == "loadavg mismatch"], [])
        _write(self.proc / "loadavg", "0.50 0.40 0.30 1/400 4243\n")
        payload, code = self.hidden_json()
        self.assertEqual(code, 0)
        hit = [f for f in payload["findings"] if f["kind"] == "loadavg mismatch"]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["severity"], "low")
        self.assertIn("reports 400 tasks", hit[0]["detail"])
        self.assertIn("2 threads counted", hit[0]["detail"])


class SocketViews(HiddenBox):
    def setUp(self):
        super().setUp()
        make_proc(self.proc, 500, "/usr/bin/bash", comm="curl", connections=[("1.2.3.4", 443, "ESTABLISHED")])
        self.inode = 500 * 100 + 1

    def test_ss_reports_socket_procfs_lacks(self):
        self.table[("ss", "-tunapHe")] = SS_LINE.format(inode=self.inode) + SS_LINE.format(inode=77777)
        findings = self.weird.socket_view_findings()
        self.assertEqual(len(findings), 1, findings)
        self.assertEqual((findings[0].kind, findings[0].severity, findings[0].attack),
                         ("hidden socket", "critical", "T1014"))
        self.assertIn("inode 77777", findings[0].detail)
        self.assertIn("reported by ss over netlink but absent from /proc/net", findings[0].detail)
        self.assertIn("pid 500 (curl)", findings[0].detail)

    def test_procfs_socket_ss_lacks(self):
        self.table[("ss", "-tunapHe")] = ""
        findings = self.weird.socket_view_findings()
        self.assertEqual(len(findings), 1, findings)
        self.assertEqual(findings[0].severity, "critical")
        self.assertIn(f"inode {self.inode} (tcp 10.0.0.2:40000 -> 1.2.3.4:443 ESTABLISHED)", findings[0].detail)
        self.assertIn("not reported by ss", findings[0].detail)

    def test_matching_views_are_quiet(self):
        self.table[("ss", "-tunapHe")] = SS_LINE.format(inode=self.inode)
        self.assertEqual(self.weird.socket_view_findings(), [])

    def test_ss_unavailable_is_a_note(self):
        self.table[("ss", "-tunapHe")] = None
        findings = self.weird.socket_view_findings()
        self.assertEqual([(f.kind, f.severity) for f in findings], [("socket cross-view", "info")])
        self.assertIn("ss unavailable", findings[0].detail)

    def test_replayed_proc_tree_skips_ss(self):
        payload, code = self.hidden_json()
        notes = [f["detail"] for f in payload["findings"] if f["kind"] == "socket cross-view"]
        self.assertEqual(len(notes), 1)
        self.assertIn("replayed /proc tree", notes[0])
        self.assertNotIn(("ss", "-tunapHe"), self.weird.run_command.calls)


class SelfCheck(ArchBox):
    def setUp(self):
        super().setUp()
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("LD_PRELOAD", None)
        os.environ.pop("LD_AUDIT", None)
        self.weird.set_roots("/proc", str(self.sysroot))

    def test_ld_so_preload_warns(self):
        _write(self.sysroot / "etc/ld.so.preload", "/tmp/evil.so\n")
        warnings = self.weird.self_check()
        self.assertEqual(len(warnings), 1, warnings)
        self.assertIn("/etc/ld.so.preload is active (/tmp/evil.so)", warnings[0])

    def test_empty_preload_is_silent(self):
        _write(self.sysroot / "etc/ld.so.preload", "\n")
        self.assertEqual(self.weird.self_check(), [])

    def test_ld_preload_in_own_environment_warns(self):
        os.environ["LD_PRELOAD"] = "/tmp/x.so"
        warnings = self.weird.self_check()
        self.assertEqual(len(warnings), 1, warnings)
        self.assertIn("LD_PRELOAD=/tmp/x.so is set in weird's own environment", warnings[0])
        os.environ["LD_AUDIT"] = "/tmp/y.so"
        self.assertEqual(len(self.weird.self_check()), 2)

    def test_silent_otherwise(self):
        self.assertEqual(self.weird.self_check(), [])

    def test_skipped_on_replayed_proc(self):
        _write(self.sysroot / "etc/ld.so.preload", "/tmp/evil.so\n")
        os.environ["LD_PRELOAD"] = "/tmp/x.so"
        self.weird.set_roots(str(self.proc), str(self.sysroot))
        self.assertEqual(self.weird.self_check(), [])

    def test_warnings_precede_output_and_land_in_json(self):
        _write(self.sysroot / "etc/ld.so.preload", "/tmp/evil.so\n")
        self.weird.set_roots(str(self.proc), str(self.sysroot))
        self.add_pkg("bash", "5.3.15-2", "/usr/bin/bash", repo="core", packager=ARCH)
        make_proc(self.proc, 100, "/usr/bin/bash")
        _write(self.proc / "sys/kernel/pid_max", "5000\n")
        with mock.patch.object(self.weird, "self_check", return_value=["/etc/ld.so.preload is active"]):
            for command in (self.weird.cmd_hidden, self.weird.cmd_persist, self.weird.cmd_scan):
                self.table[("crontab", "-l")] = None
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    command(scan_args())
                self.assertTrue(out.getvalue().startswith("\033[33mWARNING (self-check): /etc/ld.so.preload"),
                                (command.__name__, out.getvalue()[:120]))
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    command(scan_args(json=True))
                self.assertEqual(json.loads(out.getvalue())["self_check"], ["/etc/ld.so.preload is active"],
                                 command.__name__)


if __name__ == "__main__":
    unittest.main()
