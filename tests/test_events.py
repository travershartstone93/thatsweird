"""weird watch --events: the sensor's NDJSON replayed through events_loop with fixture /proc trees."""
import argparse
import contextlib
import io
import json
import os
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

from fixtures import _write, make_pacman_pkg, make_proc, make_stub_file  # noqa: E402
from test_arch import ARCH, ArchBox  # noqa: E402
from test_kernel import KernelBox, RELEASE  # noqa: E402

EVENTS = Path(__file__).resolve().parent / "fixtures" / "events"
HELLO_RELEASE = "7.2.2-1-cachyos"


def fixture_lines(name):
    return (EVENTS / name).read_text().splitlines()


def event(kind, pid, comm, **extra):
    line = {"v": 1, "ts": 23389300000000, "kind": kind, "pid": pid, "tgid": pid, "ppid": 100,
            "uid": 1000, "gid": 1000, "comm": comm}
    line.update(extra)
    return json.dumps(line, separators=(",", ":"))


def exec_event(pid, path, comm, start=23389190400000):
    return event("exec", pid, comm, path=path, argv0=comm, start=start)


class EventsBox(ArchBox):
    def setUp(self):
        super().setUp()
        self.add_pkg("bash", "5.3.15-2", "/usr/bin/bash", repo="core", packager=ARCH)
        make_proc(self.proc, 100, "/usr/bin/bash")
        self.emitted = []
        self.rescans = []
        self.hello = fixture_lines("lost.ndjson")[0]

    def tmp_proc(self, pid, path="/tmp/sshd", comm=None, **kwargs):
        comm = comm or os.path.basename(path)
        make_stub_file(self.sysroot, path)
        self.table[("pacman", "-Qo", path)] = None
        make_proc(self.proc, pid, path, comm=comm, cmdline=[comm], **kwargs)

    def run_events(self, lines):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = self.weird.events_loop(lines, self.emitted.append, lambda: self.rescans.append(1))
        return code, err.getvalue()

    def alerts(self):
        return [item for item in self.emitted if "weirdness_score" in item]

    def findings(self):
        return [item for item in self.emitted if "detail" in item]


class Hello(EventsBox):
    def test_hello_v1_accepted(self):
        code, err = self.run_events(fixture_lines("lost.ndjson")[:1])
        self.assertEqual((code, self.emitted, err), (0, [], ""))

    def test_v2_refused_with_exit_3(self):
        code, err = self.run_events(fixture_lines("schema_v2.ndjson"))
        self.assertEqual(code, 3)
        self.assertIn("unsupported sensor schema v=2 (weird understands v=1)", err)
        self.assertEqual(self.emitted, [])

    def test_missing_hello_warns_and_continues(self):
        self.tmp_proc(4000123)
        code, err = self.run_events(fixture_lines("exec_tmp.ndjson")[1:])
        self.assertEqual(code, 0)
        self.assertIn("did not start with a hello", err)
        self.assertEqual([a["pid"] for a in self.alerts()], [4000123])

    def test_start_time_conversion_uses_hello_boot(self):
        hello = json.loads(self.hello)
        exec_line = json.loads(fixture_lines("exec_tmp.ndjson")[1])
        start = self.weird.event_start_time(exec_line, hello)
        self.assertEqual(start, round(hello["boot"] + exec_line["start"] / 1e9, 2))
        self.assertEqual(self.weird.event_start_time(exec_line, None), round(self.weird.boot_time() + exec_line["start"] / 1e9, 2))


class Exec(EventsBox):
    def test_masquerading_tmp_exec_alerts_in_one_iteration(self):
        self.tmp_proc(4000123)
        code, _ = self.run_events(fixture_lines("exec_tmp.ndjson"))
        self.assertEqual(code, 0)
        self.assertEqual(len(self.emitted), 1)
        item = self.emitted[0]
        self.assertEqual((item["pid"], item["path"], item["name"]), (4000123, "/tmp/sshd", "sshd"))
        self.assertIn("masquerade", item["signals"])
        self.assertIn("suspicious_path", item["signals"])
        self.assertIn("T1036.005", item["attack"])
        self.assertEqual(item["verdict"], "Likely malicious")
        for key in ("host", "timestamp", "reasons", "process_key", "start_time", "trust_level"):
            self.assertIn(key, item)
        self.assertIsNotNone(item["start_time"])

    def test_exited_pid_with_tmp_path_gets_short_lived_record(self):
        code, _ = self.run_events(fixture_lines("exec_tmp.ndjson"))
        self.assertEqual(code, 0)
        self.assertEqual(len(self.emitted), 1)
        item = self.emitted[0]
        self.assertEqual((item["pid"], item["path"], item["name"], item["cmdline"]), (4000123, "/tmp/sshd", "sshd", "sshd"))
        self.assertIn("short-lived process", item["reasons"][0])
        self.assertEqual(item["signals"], ["suspicious_path"])
        self.assertEqual(item["attack"], ["T1036.005"])
        self.assertEqual(item["weirdness_score"], self.weird.load_policy()["scores"]["suspicious_path"])
        self.assertIn("exited before /proc could be read", "\n".join(item["evidence"]))

    def test_exited_pid_with_deleted_path_gets_short_lived_record(self):
        self.run_events([self.hello, exec_event(4000130, "/opt/app/bin/x (deleted)", "x")])
        self.assertEqual([a["pid"] for a in self.alerts()], [4000130])

    def test_exited_pid_with_ordinary_path_is_silent(self):
        self.run_events([self.hello, exec_event(4000131, "/usr/bin/true", "true")])
        self.assertEqual(self.emitted, [])

    def test_clean_official_exec_is_silent(self):
        with mock.patch.object(self.weird, "classify_and_score", wraps=self.weird.classify_and_score) as spy:
            code, _ = self.run_events([self.hello, exec_event(100, "/usr/bin/bash", "bash")])
        self.assertEqual((code, self.emitted), (0, []))
        self.assertEqual([[p.pid for p in call.args[0]] for call in spy.call_args_list], [[100]])

    def test_exit_forgets_key_so_pid_reuse_is_new(self):
        self.tmp_proc(4000123)
        exec_line = fixture_lines("exec_tmp.ndjson")[1]
        exit_line = fixture_lines("exit.ndjson")[2]
        self.run_events([self.hello, exec_line, exec_line, exit_line, exec_line])
        self.assertEqual([a["pid"] for a in self.alerts()], [4000123, 4000123])

    def test_seen_set_is_bounded(self):
        consumer = self.weird.SensorConsumer(self.emitted.append, lambda: None)
        with mock.patch.object(self.weird, "SENSOR_SEEN_MAX", 3):
            for pid in range(5000, 5006):
                consumer.handle(json.loads(exec_event(pid, "/usr/bin/true", "true", start=pid)))
        self.assertEqual(len(consumer.seen), 3)
        self.assertEqual(sorted(consumer.by_pid), [5003, 5004, 5005])


class Signals(EventsBox):
    def test_memfd_adds_signal_to_live_pid(self):
        self.tmp_proc(4000124, "/tmp/.x/helper")
        self.run_events(fixture_lines("memfd.ndjson"))
        self.assertEqual(len(self.alerts()), 1)
        item = self.alerts()[0]
        self.assertEqual(item["pid"], 4000124)
        self.assertIn("memfd_exec", item["signals"])
        self.assertIn("T1620", item["attack"])
        self.assertTrue(any('memfd_create("weird-decoy")' in r for r in item["reasons"]))

    def test_memfd_exited_pid_gets_minimal_record(self):
        self.run_events(fixture_lines("memfd.ndjson"))
        item = self.alerts()[0]
        self.assertEqual((item["pid"], item["name"], item["signals"]), (4000124, "helper", ["memfd_exec"]))
        self.assertIn("short-lived process", item["reasons"][0])

    def test_memfd_legitimate_name_and_official_process_not_scored(self):
        self.run_events([self.hello, event("memfd", 4000124, "helper", name="pipewire-memfd:12", flags=1),
                         event("memfd", 100, "bash", name="something", flags=1)])
        self.assertEqual(self.emitted, [])

    def test_ptrace_adds_traced_signal_on_target(self):
        self.tmp_proc(4000126, "/tmp/victim")
        make_proc(self.proc, 4000125, "/usr/bin/bash", comm="python3")
        self.run_events(fixture_lines("ptrace.ndjson"))
        self.assertEqual(len(self.alerts()), 1)
        item = self.alerts()[0]
        self.assertEqual(item["pid"], 4000126)
        self.assertIn("traced", item["signals"])
        self.assertIn("T1055", item["attack"])
        reason = next(r for r in item["reasons"] if "traced" in r.lower())
        self.assertIn("pid 4000125 (python3)", reason)

    def test_ptrace_by_known_debugger_and_gone_target_silent(self):
        self.tmp_proc(4000126, "/tmp/victim")
        self.run_events([self.hello, event("ptrace", 4000125, "gdb", request=16, target=4000126),
                         event("ptrace", 4000125, "python3", request=16, target=4000199)])
        self.assertEqual(self.emitted, [])

    def test_module_unowned_is_critical_finding(self):
        _write(self.sysroot / f"usr/lib/modules/{HELLO_RELEASE}/extra/evil_mod.ko", b"")
        self.run_events(fixture_lines("module.ndjson"))
        self.assertEqual(len(self.findings()), 1)
        f = self.findings()[0]
        self.assertEqual((f["kind"], f["severity"], f["attack"], f["subject"]), ("module_load", "critical", "T1014", "evil_mod"))
        self.assertIn("insmod pid 4000127", f["detail"])
        self.assertIn("not owned by any package", f["detail"])
        self.assertIn("host", f)

    def test_module_missing_file_is_critical_and_owned_is_info(self):
        ko = f"/usr/lib/modules/{HELLO_RELEASE}/kernel/drivers/video/nvidia.ko.zst"
        make_pacman_pkg(self.sysroot, "nvidia-utils", "580.1-1", [ko], packager=ARCH)
        self.weird.file_package_cache.build()
        self.run_events([self.hello, event("module", 4000127, "insmod", name="ghost"),
                         event("module", 4000127, "modprobe", name="nvidia")])
        severities = {f["subject"]: f["severity"] for f in self.findings()}
        self.assertEqual(severities, {"ghost": "critical", "nvidia": "info"})
        self.assertIn(f"no ghost.ko under /usr/lib/modules/{HELLO_RELEASE}", self.findings()[0]["detail"])

    def test_module_finit_fallback_uses_fd_link(self):
        _write(self.sysroot / "opt/x/rk.ko", b"")
        make_proc(self.proc, 4000127, "/usr/bin/bash", comm="insmod")
        fd_dir = self.proc / "4000127" / "fd"
        fd_dir.mkdir(exist_ok=True)
        os.symlink("/opt/x/rk.ko", fd_dir / "3")
        self.run_events([self.hello, event("module", 4000127, "insmod", name="finit_module", fd=3)])
        f = self.findings()[0]
        self.assertEqual(f["severity"], "critical")
        self.assertIn("/opt/x/rk.ko (from fd 3)", f["detail"])

    def test_bpf_load_by_non_official_is_medium(self):
        self.tmp_proc(4000128, "/tmp/loader")
        self.run_events(fixture_lines("bpf.ndjson"))
        self.assertEqual(len(self.findings()), 1)
        f = self.findings()[0]
        self.assertEqual((f["kind"], f["severity"], f["attack"], f["subject"]), ("bpf_load", "medium", "T1014", "loader"))
        self.assertIn("BPF_PROG_LOAD prog_type 2", f["detail"])
        self.assertIn("/tmp/loader", f["detail"])

    def test_bpf_load_by_official_is_info_and_map_ops_ignored(self):
        self.run_events([self.hello, event("bpf", 100, "bash", cmd=5, prog_type=2), event("bpf", 100, "bash", cmd=1)])
        self.assertEqual([f["severity"] for f in self.findings()], ["info"])

    def test_bpf_load_by_exited_process_is_medium(self):
        self.run_events(fixture_lines("bpf.ndjson"))
        f = self.findings()[0]
        self.assertEqual(f["severity"], "medium")
        self.assertIn("exited before it could be checked", f["detail"])

    def test_connect_public_ip_unusual_port_flags_unverified_process(self):
        self.tmp_proc(4000129, "/tmp/helper")
        self.run_events(fixture_lines("connect.ndjson"))
        self.assertEqual(len(self.alerts()), 1)
        item = self.alerts()[0]
        self.assertIn("raw_ip_outbound", item["signals"])
        self.assertIn("T1071", item["attack"])
        self.assertTrue(any("203.0.113.7:4444" in r for r in item["reasons"]))

    def test_connect_official_common_port_or_private_ip_silent(self):
        self.tmp_proc(4000129, "/tmp/helper")
        self.run_events([self.hello, event("connect", 100, "bash", family=2, daddr="203.0.113.7", dport=4444),
                         event("connect", 4000129, "helper", family=2, daddr="203.0.113.7", dport=443),
                         event("connect", 4000129, "helper", family=2, daddr="10.0.0.9", dport=4444)])
        self.assertEqual(self.emitted, [])

    def test_lost_triggers_one_rescan(self):
        code, err = self.run_events(fixture_lines("lost.ndjson"))
        self.assertEqual((code, self.rescans), (0, [1]))
        self.assertIn("lost 17 event(s)", err)

    def test_unknown_kind_and_garbage_are_skipped(self):
        code, err = self.run_events([self.hello, "not json", event("future", 1, "x"), ""])
        self.assertEqual((code, self.emitted), (0, []))
        self.assertIn("unparseable", err)


class FollowFile(EventsBox):
    def path(self):
        return self.sysroot / "events.ndjson"

    def test_stops_at_eof_without_follow(self):
        _write(self.path(), "a\nb\npartial")
        self.assertEqual(list(self.weird.follow_file(str(self.path()), follow=False)), ["a\n", "b\n", "partial"])

    def test_truncation_reopens(self):
        path = self.path()
        _write(path, "one\ntwo\n")
        gen = self.weird.follow_file(str(path), follow=True, poll=0.01)
        self.assertEqual([next(gen), next(gen)], ["one\n", "two\n"])
        with open(path, "w") as f:
            f.write("three\n")
        self.assertEqual(next(gen), "three\n")
        gen.close()

    def test_rotation_reopens(self):
        path = self.path()
        _write(path, "one\n")
        gen = self.weird.follow_file(str(path), follow=True, poll=0.01)
        self.assertEqual(next(gen), "one\n")
        os.rename(path, str(path) + ".1")
        _write(path, "two\n")
        self.assertEqual(next(gen), "two\n")
        gen.close()

    def test_partial_line_waits_for_newline(self):
        path = self.path()
        _write(path, "one\ntw")
        gen = self.weird.follow_file(str(path), follow=True, poll=0.01)
        self.assertEqual(next(gen), "one\n")
        with open(path, "a") as f:
            f.write("o\n")
        self.assertEqual(next(gen), "two\n")
        gen.close()


class WatchCommand(EventsBox):
    def watch(self, **overrides):
        args = dict(falco=False, poll=None, events=None, follow=None)
        args.update(overrides)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = self.weird.cmd_watch(argparse.Namespace(**args))
        lines = [json.loads(line) for line in out.getvalue().splitlines()]
        return code, lines, err.getvalue()

    def sensor_file(self, age=0):
        path = self.sysroot / "run/weird/events.ndjson"
        _write(path, "\n".join(fixture_lines("exec_tmp.ndjson")) + "\n")
        if age:
            os.utime(path, (time.time() - age, time.time() - age))
        return path

    def test_events_file_read_to_eof(self):
        self.tmp_proc(4000123)
        code, lines, err = self.watch(events=str(EVENTS / "exec_tmp.ndjson"))
        self.assertEqual(code, 0)
        self.assertEqual([line["pid"] for line in lines], [4000123])
        self.assertIn("reading sensor events from", err)

    def test_events_schema_refusal_exit_code(self):
        code, lines, err = self.watch(events=str(EVENTS / "schema_v2.ndjson"))
        self.assertEqual((code, lines), (3, []))
        self.assertIn("unsupported sensor schema v=2", err)

    def test_events_missing_file(self):
        code, lines, err = self.watch(events=str(self.sysroot / "nope.ndjson"))
        self.assertEqual((code, lines), (1, []))
        self.assertIn("cannot read sensor events", err)

    def test_auto_selects_fresh_sensor_file(self):
        self.tmp_proc(4000123)
        path = self.sensor_file()
        with mock.patch.object(self.weird, "watch_snapshots") as snapshots:
            code, lines, err = self.watch()
        snapshots.assert_not_called()
        self.assertEqual(code, 0)
        self.assertIn(f"real-time sensor is writing {path}", err)
        self.assertEqual([line["pid"] for line in lines], [4000123])

    def test_stale_sensor_file_falls_back_to_poll(self):
        self.sensor_file(age=600)

        def snapshots(interval):
            self.assertEqual(interval, 2)
            yield self.weird.get_processes()
            raise KeyboardInterrupt

        with mock.patch.object(self.weird, "watch_snapshots", snapshots):
            code, lines, err = self.watch()
        self.assertEqual((code, lines), (0, []))
        self.assertEqual(err.strip(), f"watching {self.weird.PROC_ROOT} every 2 s")

    def test_explicit_poll_skips_auto_selection(self):
        self.sensor_file()

        def snapshots(interval):
            raise KeyboardInterrupt

        with mock.patch.object(self.weird, "watch_snapshots", snapshots):
            code, lines, err = self.watch(poll=1)
        self.assertEqual((code, lines), (0, []))
        self.assertIn("every 1 s", err)

    def test_journal_gets_alerts_and_findings(self):
        self.tmp_proc(4000123)
        _write(self.sysroot / f"usr/lib/modules/{HELLO_RELEASE}/extra/evil_mod.ko", b"")
        path = self.sysroot / "both.ndjson"
        _write(path, "\n".join(fixture_lines("exec_tmp.ndjson") + fixture_lines("module.ndjson")[1:]) + "\n")
        with mock.patch.object(self.weird, "journal_send") as journal:
            code, lines, _ = self.watch(events=str(path), journal=True)
        self.assertEqual((code, len(lines)), (0, 2))
        messages = [call.args[0]["MESSAGE"] for call in journal.call_args_list]
        self.assertEqual(len(messages), 2)
        self.assertIn("sshd pid 4000123", messages[0])
        self.assertIn("critical module_load evil_mod", messages[1])

    def test_lost_rescan_emits_scan_alerts(self):
        self.tmp_proc(4000123)
        code, lines, _ = self.watch(events=str(EVENTS / "lost.ndjson"))
        self.assertEqual(code, 0)
        self.assertEqual([line["pid"] for line in lines], [4000123])


class KernelPosture(KernelBox):
    def test_posture_shows_sensor_version_from_hello(self):
        _write(self.sysroot / "run/weird/events.ndjson", "\n".join(fixture_lines("exec_tmp.ndjson")) + "\n")
        posture = self.weird.kernel_posture()
        self.assertEqual((posture["sensor"], posture["sensor_version"], posture["sensor_schema"]), ("active", "0.1.0", "1"))
        out, _ = self.kernel()
        self.assertIn("real-time sensor             active (weird-sensor 0.1.0, schema v1)", out)
        payload, _ = self.kernel_json()
        self.assertEqual(payload["posture"]["sensor_version"], "0.1.0")

    def test_posture_without_hello_stays_plain(self):
        _write(self.sysroot / "run/weird/events.ndjson", '{"type": "exec"}\n')
        posture = self.weird.kernel_posture()
        self.assertNotIn("sensor_version", posture)
        out, _ = self.kernel()
        self.assertIn("real-time sensor             active\n", out)
        self.assertEqual(self.weird.running_kernel(), RELEASE)


if __name__ == "__main__":
    unittest.main()
