import argparse
import contextlib
import io
import json
import os
import shutil
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

from fixtures import make_proc, make_stub_file  # noqa: E402
from test_arch import ARCH, ArchBox  # noqa: E402

HELPER = "/tmp/.x/helper"
MEMFD_MAPS = [
    "5648cf883000-5648cf885000 r--p 00000000 00:23 1725820                    /tmp/.x/helper",
    "5648cf885000-5648cf890000 r-xp 00002000 00:23 1725820                    /tmp/.x/helper",
    "7f10a0000000-7f10a0100000 r-xp 00000000 00:01 4242                       /memfd:payload (deleted)",
    "7ffd0d3e5000-7ffd0d406000 rw-p 00000000 00:00 0                          [stack]",
]


class WatchBox(ArchBox):
    def setUp(self):
        super().setUp()
        self.add_pkg("bash", "5.3.15-2", "/usr/bin/bash", repo="core", packager=ARCH)
        make_proc(self.proc, 100, "/usr/bin/bash")
        make_proc(self.proc, 101, "/usr/bin/bash", cmdline=["bash", "-l"])
        self.emitted = []

    def snapshot(self):
        return self.weird.get_processes()

    def memfd_proc(self, pid, starttime=None):
        make_stub_file(self.sysroot, HELPER)
        self.table[("pacman", "-Qo", HELPER)] = None
        make_proc(self.proc, pid, HELPER, maps=MEMFD_MAPS, starttime=starttime)

    def remove_proc(self, pid):
        shutil.rmtree(self.proc / str(pid))

    def watch(self, snapshots):
        self.weird.watch_loop(snapshots, self.emitted.append)
        return self.emitted


class WatchLoop(WatchBox):
    def test_watch_emits_only_new_flagged(self):
        first = self.snapshot()
        self.memfd_proc(102)
        second = self.snapshot()
        lines = self.watch([first, second])
        self.assertEqual([line["pid"] for line in lines], [102])
        item = lines[0]
        self.assertTrue(item["is_memfd"])
        self.assertIn("memfd_exec", item["signals"])
        self.assertEqual(item["verdict"], "Likely malicious")
        self.assertGreater(item["weirdness_score"], 0)
        for key in ("host", "timestamp", "reasons", "attack", "process_key", "start_time", "trust_level"):
            self.assertIn(key, item)

    def test_watch_ignores_repeats(self):
        first = self.snapshot()
        self.memfd_proc(102)
        second = self.snapshot()
        lines = self.watch([first, second, second, self.snapshot()])
        self.assertEqual([line["pid"] for line in lines], [102])

    def test_watch_new_clean_process_silent(self):
        first = self.snapshot()
        make_proc(self.proc, 103, "/usr/bin/bash", cmdline=["bash", "-c", "true"])
        lines = self.watch([first, self.snapshot()])
        self.assertEqual(lines, [])

    def test_watch_pid_reuse(self):
        first = self.snapshot()
        self.memfd_proc(102, starttime=100)
        second = self.snapshot()
        self.remove_proc(102)
        third = self.snapshot()
        self.memfd_proc(102, starttime=5000)
        fourth = self.snapshot()
        self.remove_proc(102)
        self.memfd_proc(102, starttime=5000)
        fifth = self.snapshot()
        lines = self.watch([first, second, third, fourth, fifth])
        self.assertEqual([line["pid"] for line in lines], [102, 102])
        self.assertNotEqual(lines[0]["start_time"], lines[1]["start_time"])

    def test_watch_scores_only_new_processes(self):
        first = self.snapshot()
        self.memfd_proc(102)
        second = self.snapshot()
        make_proc(self.proc, 103, "/usr/bin/bash", cmdline=["bash", "-c", "true"])
        third = self.snapshot()
        with mock.patch.object(self.weird, "classify_and_score", wraps=self.weird.classify_and_score) as spy:
            self.watch([first, second, third])
        scored = [[p.pid for p in call.args[0]] for call in spy.call_args_list]
        self.assertEqual(scored, [[102], [103]])

    def test_first_snapshot_is_never_scored(self):
        self.memfd_proc(102)
        only = self.snapshot()
        with mock.patch.object(self.weird, "classify_and_score", wraps=self.weird.classify_and_score) as spy:
            lines = self.watch([only, only])
        self.assertEqual(lines, [])
        self.assertEqual(spy.call_count, 0)


class WatchCommand(WatchBox):
    def test_falco_flag_dispatches_to_falco(self):
        with mock.patch.object(self.weird, "watch_falco", return_value=0) as falco:
            code = self.weird.cmd_watch(argparse.Namespace(falco=True, poll=2))
        falco.assert_called_once_with()
        self.assertEqual(code, 0)

    def test_poll_mode_streams_ndjson_and_exits_zero_on_ctrl_c(self):
        first = self.snapshot()
        self.memfd_proc(102)
        second = self.snapshot()

        def snapshots(interval):
            self.assertEqual(interval, 1)
            yield first
            yield second
            raise KeyboardInterrupt

        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(self.weird, "watch_snapshots", snapshots), \
                mock.patch.object(self.weird, "watch_falco") as falco, \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = self.weird.cmd_watch(argparse.Namespace(falco=False, poll=1))
        self.assertEqual(code, 0)
        falco.assert_not_called()
        self.assertEqual(err.getvalue().strip(), f"watching {self.weird.PROC_ROOT} every 1 s")
        lines = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual([line["pid"] for line in lines], [102])


if __name__ == "__main__":
    unittest.main()
