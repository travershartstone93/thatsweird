import argparse
import contextlib
import hashlib
import io
import json
import os
import shutil
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

from fixtures import make_proc, make_stub_file  # noqa: E402
from helpers import scan_args  # noqa: E402
from test_arch import ARCH, ArchBox  # noqa: E402

DAEMON = "/opt/thing/bin/zzdaemon"
V1 = b"#!/bin/sh\necho v1\n"
V2 = b"#!/bin/sh\necho v2\n"


class TrustBox(ArchBox):
    def setUp(self):
        super().setUp()
        self.add_pkg("bash", "5.3.15-2", "/usr/bin/bash", repo="core", packager=ARCH)
        make_proc(self.proc, 100, "/usr/bin/bash")
        self.exe = make_stub_file(self.sysroot, DAEMON, V1)
        self.table[("pacman", "-Qo", DAEMON)] = None
        make_proc(self.proc, 500, DAEMON, cmdline=[DAEMON, "--serve"])

    def baseline(self, cmd, target=None):
        out, err = io.StringIO(), io.StringIO()
        handler = {"trust": self.weird.cmd_baseline_trust, "untrust": self.weird.cmd_baseline_untrust}.get(cmd)
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            if handler:
                code = handler(argparse.Namespace(target=target))
            else:
                code = self.weird.cmd_scan(scan_args(baseline_cmd=cmd))
        return out.getvalue() + err.getvalue(), code

    def entries(self):
        return json.loads(self.weird.TRUSTED_FILE.read_text())["entries"]

    def modify(self):
        self.exe.write_bytes(V2)

    def scan(self, verbose=False):
        processes, alerts, code = self.weird.run_scan(scan_args(verbose=verbose))
        return {p.pid: p for p in processes}, alerts, code


class TrustRecords(TrustBox):
    def test_baseline_trust_records_hash(self):
        out, code = self.baseline("trust", "500")
        self.assertEqual(code, 0, out)
        self.assertIn(DAEMON, out)
        entries = self.entries()
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry["exe_realpath"], DAEMON)
        self.assertEqual(entry["exe_sha256"], hashlib.sha256(V1).hexdigest())
        self.assertEqual(entry["trust"], "UNKNOWN")
        self.assertEqual(entry["package"], "")
        self.assertTrue(entry["process_key"].startswith(DAEMON + "|1000|1|"), entry["process_key"])
        self.assertGreater(entry["recorded"], 0)

    def test_trust_by_path(self):
        out, code = self.baseline("trust", DAEMON)
        self.assertEqual(code, 0, out)
        entry = self.entries()[0]
        self.assertEqual(entry["exe_sha256"], hashlib.sha256(V1).hexdigest())
        self.assertEqual(entry["process_key"], "")

    def test_trust_unknown_target(self):
        out, code = self.baseline("trust", "9999")
        self.assertEqual(code, 1)
        self.assertIn("not found", out)
        out, code = self.baseline("trust", "/nope/missing")
        self.assertEqual(code, 1)
        self.assertFalse(self.weird.TRUSTED_FILE.exists())


class TrustInScan(TrustBox):
    def test_trusted_unchanged_is_quiet(self):
        procs, alerts, code = self.scan()
        self.assertIn(500, procs)
        self.assertEqual(self.weird.verdict_for(procs[500]), "Unverified")

        self.baseline("trust", "500")
        procs, alerts, code = self.scan()
        self.assertNotIn(500, procs)
        self.assertEqual(alerts, [])
        self.assertEqual(code, 0)

        procs, _, _ = self.scan(verbose=True)
        proc = procs[500]
        self.assertTrue(proc.suppressed)
        self.assertEqual(proc.tags, ["trusted"])
        self.assertEqual(proc.weirdness_score, 0)
        self.assertEqual(proc.signal_keys, [])
        self.assertTrue(any(e.startswith("Trusted: executable hash recorded ") for e in proc.evidence), proc.evidence)
        self.assertIn("[trusted]", self.weird.format_process_table([proc], verbose=True))

        out, code = self.baseline("diff")
        self.assertEqual(code, 0)
        self.assertIn("No differences found.", out)

    def test_trusted_binary_changed(self):
        self.baseline("trust", "500")
        self.modify()
        procs, alerts, code = self.scan()
        self.assertIn(500, procs)
        proc = procs[500]
        self.assertFalse(proc.suppressed)
        self.assertNotIn("trusted", proc.tags)
        self.assertIn("trusted_binary_changed", proc.signal_keys)
        self.assertIn("T1554", proc.attack)
        reason = proc.reasons[proc.signal_keys.index("trusted_binary_changed")]
        self.assertRegex(reason, r"^trusted binary changed since trust was recorded \(\d{4}-\d{2}-\d{2}\) \(\+30\)$")
        self.assertEqual(proc.weirdness_score, self.weird.load_policy()["scores"]["trusted_binary_changed"])
        self.assertEqual(self.weird.verdict_for(proc), "Suspicious")
        self.assertEqual([a["pid"] for a in alerts], [500])
        self.assertEqual(code, 1)

    def test_diff_reports_changed_hash(self):
        self.baseline("trust", "500")
        self.modify()
        diff = self.weird.diff_baseline([], {}, self.weird.load_trusted())
        self.assertEqual(len(diff["changed_hash"]), 1)
        changed = diff["changed_hash"][0]
        self.assertEqual(changed["exe_realpath"], DAEMON)
        self.assertEqual(changed["exe_sha256"], hashlib.sha256(V2).hexdigest())
        self.assertEqual(changed["trusted_sha256"], hashlib.sha256(V1).hexdigest())
        self.assertTrue(changed["trusted"])
        out, code = self.baseline("diff")
        self.assertEqual(code, 0)
        self.assertIn("changed_hash: 1", out)
        self.assertIn(f"{DAEMON}|1000|1|", out)
        self.assertIn("(trusted binary changed on disk)", out)

    def test_diff_hashes_file_not_process(self):
        self.baseline("trust", "500")
        self.modify()
        shutil.rmtree(self.proc / "500")
        diff = self.weird.diff_baseline([], {}, self.weird.load_trusted())
        self.assertEqual([c["exe_realpath"] for c in diff["changed_hash"]], [DAEMON])

    def test_same_hash_elsewhere_is_trusted_by_hash(self):
        self.baseline("trust", DAEMON)
        copy = "/opt/other/bin/zzcopy"
        make_stub_file(self.sysroot, copy, V1)
        self.table[("pacman", "-Qo", copy)] = None
        make_proc(self.proc, 501, copy)
        procs, _, _ = self.scan(verbose=True)
        self.assertTrue(procs[501].suppressed)
        self.assertEqual(procs[501].tags, ["trusted"])

    def test_untrust_removes(self):
        self.baseline("trust", "500")
        self.baseline("trust", DAEMON)
        self.assertEqual(len(self.entries()), 2)
        out, code = self.baseline("untrust", DAEMON)
        self.assertEqual(code, 0, out)
        self.assertEqual(self.entries(), [])
        procs, _, _ = self.scan()
        self.assertIn(500, procs)
        self.assertFalse(procs[500].suppressed)
        out, code = self.baseline("untrust", DAEMON)
        self.assertEqual(code, 1)
        self.assertIn("No trusted entry", out)


class TrustFilePermissions(TrustBox):
    def test_trust_file_permissions(self):
        self.baseline("trust", "500")
        path = self.weird.TRUSTED_FILE
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertFalse([n for n in os.listdir(path.parent) if n.endswith(".tmp")])
        self.assertEqual(len(self.weird.load_trusted()), 1)

        path.chmod(0o666)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.weird.load_trusted(), [])
        self.assertIn("world-writable", err.getvalue())
        with contextlib.redirect_stderr(io.StringIO()):
            procs, _, _ = self.scan()
        self.assertIn(500, procs)
        self.assertFalse(procs[500].suppressed)

        path.chmod(0o600)
        with mock.patch.object(os, "getuid", return_value=os.getuid() + 1), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.weird.load_trusted(), [])
        self.assertEqual(len(self.weird.load_trusted()), 1)

    def test_rewrite_keeps_mode(self):
        self.baseline("trust", "500")
        self.baseline("trust", DAEMON)
        self.assertEqual(self.weird.TRUSTED_FILE.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
