"""The one-command shape: `weird` runs every section, verbs dispatch, dev keeps the old tree."""
import contextlib
import io
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

from fixtures import make_proc, make_proc_root  # noqa: E402
from helpers import run_cli  # noqa: E402
from test_persist import PersistBox  # noqa: E402

SECTIONS = ("processes", "aur", "persist", "kernel", "stale", "hidden")


class OneCommandTests(PersistBox):
    def setUp(self):
        super().setUp()
        make_proc_root(self.proc)
        self.add_official("bash", "/usr/bin/bash")
        make_proc(self.proc, 100, "/usr/bin/bash", comm="bash")
        (self.proc / "sys/kernel").mkdir(parents=True, exist_ok=True)
        (self.proc / "sys/kernel/pid_max").write_text("1000\n")
        self.table[("pacman", "-Qm")] = ""
        self.table[("bpftool", "prog", "list")] = None
        self.table[("ss", "-H", "-tuanp")] = None
        self.table[("ss", "-H", "-tuan")] = None

    def weird_main(self, *words):
        out = io.StringIO()
        argv = ["--proc-root", str(self.proc), "--sysroot", str(self.sysroot), *words]
        with contextlib.redirect_stdout(out):
            code = self.weird.main(argv)
        return out.getvalue(), code

    def test_plain_run_prints_every_section_and_a_summary(self):
        text, code = self.weird_main()
        for label in ("Running programs", "AUR packages", "Startup programs", "Kernel modules", "Hidden processes"):
            self.assertIn(f"\n  {label}", text)
        self.assertNotIn("Old files in use", text)
        self.assertRegex(text.splitlines()[0], r"^Nothing weird on \S+\.$")
        self.assertEqual(text.splitlines()[-1], "weird -v lists everything; weird 1234 explains process 1234.")
        self.assertEqual(code, 0, text)

    def test_exit_code_aggregates_across_sections(self):
        self.sys_file("/etc/ld.so.preload", "/tmp/evil.so\n")
        text, code = self.weird_main()
        self.assertEqual(code, 2, text)
        self.assertRegex(text.splitlines()[0], r"^1 thing on \S+ needs you to act now\.$")
        self.assertIn("Every program loads /tmp/evil.so", text)

    def test_skip_omits_a_section(self):
        text, code = self.weird_main("--skip", "hidden", "--skip", "kernel")
        self.assertNotIn("Hidden processes", text)
        self.assertNotIn("Kernel modules", text)
        self.assertIn("Startup programs", text)

    def test_json_has_a_key_per_section(self):
        text, code = self.weird_main("--json")
        data = json.loads(text)
        for name in SECTIONS + ("summary", "host", "timestamp", "self_integrity"):
            self.assertIn(name, data)
        self.assertEqual(data["summary"]["exit_code"], code)
        self.assertIn("alerts", data["processes"])
        self.assertIn("entries", data["persist"])
        self.assertIn("posture", data["kernel"])
        text, _ = self.weird_main("--json", "--skip", "aur")
        self.assertNotIn("aur", json.loads(text))

    def test_pid_and_path_dispatch_to_inspect(self):
        with mock.patch.object(self.weird, "cmd_inspect", return_value=0) as inspect:
            self.weird_main("100")
        self.assertEqual(inspect.call_args[0][0].pid, 100)
        with mock.patch.object(self.weird, "cmd_inspect", return_value=0) as inspect:
            self.weird_main("/usr/bin/bash")
        self.assertEqual(inspect.call_args[0][0].path, "/usr/bin/bash")
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                self.weird_main("no-such-thing")

    def test_trust_and_untrust_dispatch(self):
        with mock.patch.object(self.weird, "cmd_baseline_trust", return_value=0) as trust:
            self.weird_main("trust", "/usr/bin/bash")
        self.assertEqual(trust.call_args[0][0].target, "/usr/bin/bash")
        with mock.patch.object(self.weird, "cmd_baseline_untrust", return_value=0) as untrust:
            self.weird_main("--json", "untrust", "/usr/bin/bash")
        self.assertEqual(untrust.call_args[0][0].target, "/usr/bin/bash")

    def test_dev_persist_still_works(self):
        text, code = self.weird_main("dev", "persist", "--json")
        self.assertIn("entries", json.loads(text))
        text, code = self.weird_main("dev", "kernel")
        self.assertIn("Posture", text)

    def test_watch_passes_its_options(self):
        with mock.patch.object(self.weird, "cmd_watch", return_value=0) as watch:
            self.weird_main("watch", "--poll", "5")
        self.assertEqual(watch.call_args[0][0].poll, 5.0)


class HelpShapeTests(unittest.TestCase):
    def test_help_is_short_and_hides_dev_commands(self):
        r = run_cli(["--help"], timeout=60)
        self.assertEqual(r.returncode, 0)
        self.assertLess(len(r.stdout.splitlines()), 45)
        for word in ("weird trust", "weird untrust", "weird watch", "weird dev", "--skip"):
            self.assertIn(word, r.stdout)
        for word in (" persist ", " self-check", " falco-rules", " completions"):
            self.assertNotIn(word, r.stdout)

    def test_dev_help_lists_the_old_commands(self):
        r = run_cli(["dev", "--help"], timeout=60)
        self.assertEqual(r.returncode, 0)
        for word in ("persist", "hidden", "kernel", "aur", "self-check", "baseline", "completions", "scan"):
            self.assertIn(word, r.stdout)


if __name__ == "__main__":
    unittest.main()
