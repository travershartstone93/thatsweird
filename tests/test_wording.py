import contextlib
import io
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

from fixtures import make_proc, make_stub_file  # noqa: E402
from helpers import scan_args  # noqa: E402
from test_arch import ARCH, ArchBox  # noqa: E402
from test_reasons import MEMFD_MAPS  # noqa: E402


class Verdicts(ArchBox):
    def test_describe_verdict_table(self):
        T = self.weird.TrustLevel
        describe = self.weird.describe_verdict
        cases = [
            ((T.UNKNOWN, 0, False), "Unverified"),
            ((T.UNKNOWN, 1, False), "Suspicious"),
            ((T.UNKNOWN, 2, False), "Likely malicious"),
            ((T.UNKNOWN, 1, True), "Likely malicious"),
            ((T.OFFICIAL_REPO, 1, False), "Suspicious"),
            ((T.OFFICIAL_REPO, 3, True), "Suspicious"),
        ]
        for args, expected in cases:
            self.assertEqual(describe(*args), expected, args)
        self.assertEqual(describe(T.OFFICIAL_REPO, 0, False, integrity_modified=True), "Likely malicious")
        self.assertEqual(describe(T.OFFICIAL_REPO, 0, False), "")
        self.assertEqual(describe("OFFICIAL", 1, False), "Suspicious")
        for level in (T.THIRD_PARTY_REPO, T.LOCAL_BUILD):
            self.assertEqual(describe(level, 5, True), "Suspicious", level)
        self.assertEqual(describe(T.USER_LOCAL, 0, False), "Unverified")

    def test_no_process_gets_old_wording(self):
        self.add_pkg("bash", "5.3.15-2", "/usr/bin/bash", repo="core", packager=ARCH)
        make_proc(self.proc, 100, "/usr/bin/bash")
        for path in ("/opt/thing/bin/zzquiet", "/tmp/.x/helper"):
            make_stub_file(self.sysroot, path)
            self.table[("pacman", "-Qo", path)] = None
        make_proc(self.proc, 600, "/opt/thing/bin/zzquiet")
        make_proc(self.proc, 700, "/tmp/.x/helper", maps=MEMFD_MAPS)

        processes, _, _ = self.weird.run_scan(scan_args(verbose=True))
        table = self.weird.format_process_table(processes, verbose=True)
        with mock.patch.object(self.weird, "get_process_description", return_value=None):
            detail = "\n".join(self.weird.format_process_detail(p) for p in processes)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.weird.cmd_scan(scan_args(json=True, verbose=True))
        payload = json.loads(out.getvalue())

        for text in (table, detail, out.getvalue()):
            self.assertNotIn("Likely Malware", text)
            self.assertNotIn("INVESTIGATE IMMEDIATELY", text)
        rows = {int(line.split()[0]): line for line in table.splitlines() if line.split() and line.split()[0].isdigit()}
        self.assertIn("(no description)", rows[600])
        self.assertIn("Likely malicious", rows[700])
        self.assertNotIn("Unverified", rows[100])
        verdicts = {p["pid"]: p["verdict"] for p in payload["processes"]}
        self.assertEqual(verdicts, {100: "", 600: "Unverified", 700: "Likely malicious"})
        self.assertIn("no provenance: unverified, investigate if it also shows signals", detail)


if __name__ == "__main__":
    unittest.main()
