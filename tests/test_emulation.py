"""Adversary emulation: harmless decoys, real /proc, real package database.

Each test starts a benign process shaped like a technique, runs the real scan
(HOME sandboxed so no user config or cache is touched) and kills the decoy in
cleanup whatever happens. Linux only, no root needed.
"""
import ctypes.util
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

from helpers import load_weird, scan_args  # noqa: E402

SLEEP = shutil.which("sleep") or "/bin/sleep"
LIB_DIRS = ("/usr/lib", "/usr/lib64", "/lib", "/lib64", "/usr/lib/x86_64-linux-gnu", "/lib/x86_64-linux-gnu")


def find_shared_library(name: str):
    soname = ctypes.util.find_library(name)
    if not soname:
        return None
    for d in LIB_DIRS:
        candidate = os.path.join(d, soname)
        if os.path.exists(candidate):
            return os.path.realpath(candidate)
    return None


def wait_for_child(parent_pid: int, comm: str, timeout: float = 10.0):
    """pid of the first /proc entry whose PPid is parent_pid and comm matches."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                with open(f"/proc/{entry}/stat") as f:
                    stat = f.read()
                end = stat.rindex(")")
                if stat[stat.index("(") + 1:end] == comm and int(stat[end + 1:].split()[1]) == parent_pid:
                    return int(entry)
            except (OSError, ValueError):
                continue
        time.sleep(0.05)
    return None


@unittest.skipUnless(sys.platform == "linux", "needs /proc")
class Emulation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sandbox = tempfile.TemporaryDirectory(prefix="weird-emu-home-")
        cls.weird = load_weird(os.path.join(cls.sandbox.name, "home"))
        # Descriptions are cosmetic: skip the man page and registry lookups, which
        # otherwise cost a subprocess per process name on every scan
        cls.patches = [
            mock.patch.object(cls.weird, "get_process_description", return_value=None),
            mock.patch.object(cls.weird, "get_man_page_description", return_value=None),
        ]
        for patch in cls.patches:
            patch.start()

    @classmethod
    def tearDownClass(cls):
        for patch in cls.patches:
            patch.stop()
        cls.sandbox.cleanup()

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="weird-emu-", dir="/tmp")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def decoy(self, name: str) -> str:
        path = os.path.join(self.tmp, name)
        shutil.copy(SLEEP, path)
        os.chmod(path, 0o755)
        return path

    def start(self, argv, env=None) -> subprocess.Popen:
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

    def scan(self, pid: int, verbose: bool = False):
        self.weird.file_package_cache.build()
        processes, alerts, code = self.weird.run_scan(scan_args(verbose=verbose))
        found = [p for p in processes if p.pid == pid]
        self.assertEqual(len(found), 1, f"pid {pid} missing from scan output")
        return found[0], alerts, code

    def test_masquerade_detected(self):
        path = self.decoy("sshd")
        proc = self.start([path, "300"])
        info, alerts, code = self.scan(proc.pid)
        self.assertIn("masquerade", info.signal_keys, info.reasons)
        self.assertIn("T1036.005", info.attack)
        self.assertEqual(self.weird.verdict_for(info), "Likely malicious")
        self.assertIn(proc.pid, [a["pid"] for a in alerts])
        self.assertEqual(code, 2)

    def test_deleted_exe_detected(self):
        path = self.decoy("x")
        proc = self.start([path, "300"])
        os.unlink(path)
        info, alerts, code = self.scan(proc.pid)
        self.assertTrue(info.is_deleted)
        self.assertFalse(info.is_stale)
        self.assertIn("deleted_exe", info.signal_keys, info.reasons)
        self.assertIn("T1070.004", info.attack)
        self.assertEqual(code, 2)

    def test_memfd_detected(self):
        fd = os.memfd_create("weird-emu")
        self.addCleanup(os.close, fd)
        with open(SLEEP, "rb") as f:
            os.write(fd, f.read())
        pid = os.fork()
        if pid == 0:
            try:
                os.execve(f"/proc/self/fd/{fd}", ["weird-emu-memfd", "300"], {})
            finally:
                os._exit(127)
        self.addCleanup(self.stop_pid, pid)
        time.sleep(0.2)
        _, status = os.waitpid(pid, os.WNOHANG)
        self.assertEqual(status, 0, "memfd child exited early")
        info, alerts, code = self.scan(pid)
        self.assertTrue(info.is_memfd, info.evidence)
        self.assertIn("T1620", info.attack)
        self.assertEqual(code, 2)

    @staticmethod
    def stop_pid(pid: int):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass

    def test_ld_preload_detected(self):
        lib = find_shared_library("m")
        if not lib:
            self.skipTest("no shared library to copy")
        decoy = os.path.join(self.tmp, "decoy.so")
        shutil.copy(lib, decoy)
        env = {"PATH": os.environ.get("PATH", "/usr/bin"), "HOME": self.sandbox.name, "LD_PRELOAD": decoy}
        proc = self.start([SLEEP, "300"], env=env)
        time.sleep(0.2)
        self.assertIsNone(proc.poll(), "sleep died under LD_PRELOAD")
        if self.weird.read_environ(proc.pid) is None:
            self.skipTest("environ of own child unreadable")
        info, alerts, code = self.scan(proc.pid)
        self.assertIn("ld_preload", info.signal_keys, info.reasons)
        self.assertIn("T1574.006", info.attack)
        self.assertTrue(any(f"LD_PRELOAD={decoy}" in r for r in info.reasons), info.reasons)
        self.assertGreaterEqual(code, 1)

    def test_parent_chain_live(self):
        proc = self.start([sys.executable, "-c",
                           "import subprocess, time\n"
                           "subprocess.Popen(['bash', '-c', 'sleep 300; true'])\n"
                           "time.sleep(300)\n"])
        bash_pid = wait_for_child(proc.pid, "bash")
        self.assertIsNotNone(bash_pid, "bash child never appeared")
        sleep_pid = wait_for_child(bash_pid, "sleep")
        self.assertIsNotNone(sleep_pid, "sleep grandchild never appeared")
        python_comm = os.path.basename(sys.executable)[:15]

        chain = self.weird.ancestors(sleep_pid)
        self.assertEqual([c for _, c in chain][:2], ["bash", python_comm])
        self.assertEqual(chain[0][0], bash_pid)
        self.assertEqual(chain[1][0], proc.pid)

        info, _, _ = self.scan(bash_pid, verbose=True)
        self.assertEqual(info.parent_chain[0], python_comm)
        self.assertIn(python_comm, info.parent_chain)
        self.assertNotIn("rule_upgrade", info.signal_keys)


if __name__ == "__main__":
    unittest.main()
