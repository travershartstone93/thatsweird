"""weird fixture record: a live process captured into a tree that --proc-root/--sysroot replays identically."""
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

from helpers import load_weird, run_cli, scan_args  # noqa: E402

SLEEP = shutil.which("sleep") or "/bin/sleep"


def quiet(weird):
    """Descriptions are cosmetic and cost a subprocess per name; skip them."""
    patches = [mock.patch.object(weird, "get_process_description", return_value=None),
               mock.patch.object(weird, "get_man_page_description", return_value=None)]
    for p in patches:
        p.start()
    return patches


@unittest.skipUnless(sys.platform == "linux", "needs /proc")
class FixtureRecord(unittest.TestCase):
    def setUp(self):
        self.sandbox = tempfile.TemporaryDirectory(prefix="weird-fixture-")
        self.addCleanup(self.sandbox.cleanup)
        self.home = Path(self.sandbox.name) / "home"
        self.live = load_weird(self.home)
        for p in quiet(self.live):
            self.addCleanup(p.stop)
        self.tmp = tempfile.mkdtemp(prefix="weird-fixture-", dir="/tmp")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def decoy(self, name):
        path = os.path.join(self.tmp, name)
        shutil.copy(SLEEP, path)
        os.chmod(path, 0o755)
        return path

    def start(self, argv, env):
        proc = subprocess.Popen(argv, env=env, start_new_session=True,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.stop, proc)
        return proc

    @staticmethod
    def stop(proc):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=10)

    @staticmethod
    def scan_pid(weird, pid):
        weird.file_package_cache.build()
        processes, alerts, code = weird.run_scan(scan_args(verbose=True))
        found = [p for p in processes if p.pid == pid]
        assert len(found) == 1, f"pid {pid} missing from scan output"
        return found[0], alerts, code

    def test_fixture_recorder_roundtrip(self):
        path = self.decoy("weird-fx-sleep")
        env = {"HOME": str(self.home), "PATH": "/usr/bin:/bin", "LANG": "C",
               "API_TOKEN": "hunter2", "MY_SECRET": "s3cret-value", "AWS_ACCESS_KEY_ID": "AKIA123",
               "DB_PASSWORD": "pw", "EDITOR": "vi"}
        proc = self.start([path, "300"], env)
        live_info, live_alerts, live_code = self.scan_pid(self.live, proc.pid)
        self.assertEqual(live_info.trust_level, self.live.TrustLevel.UNKNOWN)
        self.assertIn("suspicious_path", live_info.signal_keys, live_info.reasons)

        fixture = Path(self.sandbox.name) / "fixture"
        summary = self.live.record_fixture(proc.pid, str(fixture))
        pid_dir = fixture / str(proc.pid)
        for name in ("stat", "status", "comm", "cmdline", "maps", "environ", "cgroup"):
            self.assertTrue((pid_dir / name).is_file(), name)
        self.assertEqual(os.readlink(pid_dir / "exe"), path)
        self.assertTrue((fixture / "stat").read_text().find("btime ") >= 0)
        self.assertTrue((fixture / "sys/kernel/pid_max").is_file())
        self.assertTrue((fixture / "sysroot" / path.lstrip("/")).is_file())
        self.assertEqual(summary["exe"], path)
        self.assertTrue(any((pid_dir / "fd" / fd).is_symlink() for fd in os.listdir(pid_dir / "fd")))

        environ = (pid_dir / "environ").read_bytes()
        for secret in (b"hunter2", b"s3cret-value", b"AKIA123", b"pw\x00"):
            self.assertNotIn(secret, environ)
        for key in (b"API_TOKEN=redacted", b"MY_SECRET=redacted", b"AWS_ACCESS_KEY_ID=redacted",
                    b"DB_PASSWORD=redacted", b"EDITOR=vi", b"LANG=C"):
            self.assertIn(key, environ)
        self.assertEqual(summary["redacted"], 4)

        replay = load_weird(Path(self.sandbox.name) / "home2", proc_root=fixture, sysroot=fixture / "sysroot")
        for p in quiet(replay):
            self.addCleanup(p.stop)
        info, alerts, code = self.scan_pid(replay, proc.pid)
        self.assertEqual(info.trust_level.value, live_info.trust_level.value)
        self.assertEqual(info.weirdness_score, live_info.weirdness_score)
        self.assertEqual(info.reasons, live_info.reasons)
        self.assertEqual(info.signal_keys, live_info.signal_keys)
        self.assertEqual(info.attack, live_info.attack)
        self.assertEqual(info.provenance.ownership, live_info.provenance.ownership)
        self.assertEqual((info.name, info.path, info.cmdline), (live_info.name, live_info.path, live_info.cmdline))
        self.assertEqual(info.parent_chain, live_info.parent_chain)
        self.assertEqual(replay.verdict_for(info), self.live.verdict_for(live_info))
        # The scan's exit code covers every other process on the host too, so only
        # the decoy's own alert is compared
        def mine(entries):
            return [{k: a.get(k) for k in ("pid", "score", "level", "verdict")} for a in entries
                    if a["pid"] == proc.pid]
        self.assertEqual(mine(alerts), mine(live_alerts))
        self.assertGreaterEqual(live_code, code)

    def test_cli_record_prints_replay_hint(self):
        path = self.decoy("weird-fx-cli")
        proc = self.start([path, "300"], {"HOME": str(self.home), "PATH": "/usr/bin:/bin"})
        fixture = Path(self.sandbox.name) / "cli-fixture"
        r = run_cli(["fixture", "record", str(proc.pid), str(fixture)], home=self.home, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f"recorded pid {proc.pid} into {fixture}", r.stdout)
        self.assertIn(f"replay: weird --proc-root {fixture} --sysroot {fixture}/sysroot -v", r.stdout)
        self.assertTrue((fixture / str(proc.pid) / "status").is_file())
        r = run_cli(["fixture", "record", "999999999", str(fixture)], home=self.home, timeout=60)
        self.assertEqual(r.returncode, 1)
        self.assertIn("not found", r.stderr)

    def test_redact_environ_keeps_keys(self):
        data = b"PATH=/usr/bin\x00GITHUB_TOKEN=abc\x00apikey=x\x00secret_thing=y\x00PASSWORD=z\x00NOVALUE\x00"
        out, count = self.live.redact_environ(data)
        self.assertEqual(count, 4)
        self.assertEqual(out, b"PATH=/usr/bin\x00GITHUB_TOKEN=redacted\x00apikey=redacted\x00"
                              b"secret_thing=redacted\x00PASSWORD=redacted\x00NOVALUE\x00")


if __name__ == "__main__":
    unittest.main()
