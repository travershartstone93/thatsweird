"""Self integrity: sha256 of bin/weird against the weirdIntegrity pin in package.json."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))

from fixtures import make_pacman_pkg, make_proc  # noqa: E402
from helpers import REPO, load_weird  # noqa: E402

RED = "\033[31m"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class SandboxCopy(unittest.TestCase):
    """A copy of the checkout with its own package.json, so the pin can be recomputed and altered freely."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="weird-selfcheck-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        (self.repo / "bin").mkdir(parents=True)
        (self.repo / "scripts").mkdir()
        shutil.copy2(REPO / "bin" / "weird", self.repo / "bin" / "weird")
        shutil.copy2(REPO / "scripts" / "update-pin.py", self.repo / "scripts" / "update-pin.py")
        shutil.copy2(REPO / "package.json", self.repo / "package.json")
        self.package_json = self.repo / "package.json"
        self.home = self.root / "home"
        self.home.mkdir()
        self.sysroot = self.root / "sys"
        self.proc = self.root / "proc"
        make_pacman_pkg(self.sysroot, "bash", "5.3.15-2", ["/usr/bin/bash"])
        make_proc(self.proc, 100, "/usr/bin/bash")

    def pin(self):
        subprocess.run([sys.executable, str(self.repo / "scripts" / "update-pin.py"), str(self.repo)],
                       check=True, capture_output=True, text=True)

    def read_pin(self):
        return json.loads(self.package_json.read_text()).get("weirdIntegrity")

    def write_pin(self, value):
        data = json.loads(self.package_json.read_text())
        if value is None:
            data.pop("weirdIntegrity", None)
        else:
            data["weirdIntegrity"] = value
        self.package_json.write_text(json.dumps(data, indent=2) + "\n")

    def run_weird(self, *args, timeout=120):
        env = dict(os.environ, HOME=str(self.home))
        env.pop("WEIRD_PROC_ROOT", None)
        env.pop("WEIRD_SYSROOT", None)
        return subprocess.run([sys.executable, str(self.repo / "bin" / "weird"), *args],
                              capture_output=True, text=True, timeout=timeout, env=env)

    def test_self_hash_matches_pinned(self):
        self.pin()
        pin = self.read_pin()
        self.assertEqual(pin["sha256"], sha256(self.repo / "bin" / "weird"))
        self.assertEqual(pin["version"], json.loads(self.package_json.read_text())["version"])
        r = self.run_weird("self-check")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("self integrity: match", r.stdout)
        self.assertIn(f"sha256           {pin['sha256']}", r.stdout)
        self.assertIn(f"pinned sha256    {pin['sha256']}", r.stdout)
        self.assertIn(f"pinned version   {pin['version']}", r.stdout)
        self.assertNotIn("self-integrity", r.stderr)
        self.assertNotIn(RED, r.stderr)

    def test_self_hash_mismatch_banner(self):
        self.pin()
        real = self.read_pin()["sha256"]
        self.write_pin({"sha256": "0" * 64, "version": "0.0.1"})
        r = self.run_weird("self-check")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("WARNING (self-integrity)", r.stderr)
        self.assertIn(RED, r.stderr)
        self.assertIn("self integrity: mismatch", r.stdout)
        self.assertIn(f"sha256           {real}", r.stdout)
        self.assertIn("pinned sha256    " + "0" * 64, r.stdout)
        self.assertIn("pinned version   0.0.1", r.stdout)
        # the banner comes before any other output and never changes the exit code of a run
        r = self.run_weird("--proc-root", str(self.proc), "--sysroot", str(self.sysroot), "kernel", "--json")
        self.assertIn(r.returncode, (0, 1, 2), r.stderr)
        self.assertTrue(r.stderr.startswith(RED + "WARNING (self-integrity)"), r.stderr[:200])
        self.assertEqual(json.loads(r.stdout)["self_integrity"], "mismatch")
        r = self.run_weird("--proc-root", str(self.proc), "--sysroot", str(self.sysroot), "--json")
        self.assertIn(r.returncode, (0, 1, 2), r.stderr)
        self.assertEqual(json.loads(r.stdout)["self_integrity"], "mismatch")

    def test_missing_pin_is_evidence_not_warning(self):
        self.write_pin(None)
        r = self.run_weird("self-check")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("self integrity: unpinned", r.stdout)
        self.assertIn("integrity pin not found", r.stdout)
        self.assertIn("pinned sha256    none", r.stdout)
        self.assertEqual(r.stderr, "")
        r = self.run_weird("self-check", "--json")
        payload = json.loads(r.stdout)
        self.assertEqual(payload["self_integrity"]["status"], "unpinned")
        self.assertIn("integrity pin not found", payload["self_integrity"]["detail"])
        self.assertIsInstance(payload["self_check"], list)

    def test_release_script_updates_pin(self):
        self.pin()
        before = self.read_pin()["sha256"]
        with open(self.repo / "bin" / "weird", "a") as f:
            f.write("\n# changed\n")
        self.pin()
        after = self.read_pin()
        self.assertNotEqual(after["sha256"], before)
        self.assertEqual(after["sha256"], sha256(self.repo / "bin" / "weird"))
        self.assertEqual(after["version"], json.loads(self.package_json.read_text())["version"])
        data = json.loads(self.package_json.read_text())
        self.assertEqual(data["name"], "thatsweird")
        r = self.run_weird("self-check")
        self.assertIn("self integrity: match", r.stdout)


class InProcess(unittest.TestCase):
    def test_self_integrity_reports_both_hashes(self):
        with tempfile.TemporaryDirectory() as home:
            w = load_weird(home)
        info = w.self_integrity()
        self.assertIn(info["status"], ("match", "mismatch", "unpinned"))
        self.assertEqual(info["path"], os.path.realpath(str(REPO / "bin" / "weird")))
        self.assertEqual(info["sha256"], sha256(REPO / "bin" / "weird"))
        self.assertEqual(info["pin_file"], str(REPO / "package.json"))
        self.assertEqual(w.check_self_integrity(), info["status"])
        self.assertEqual(w._self_integrity, info["status"])


if __name__ == "__main__":
    unittest.main()
