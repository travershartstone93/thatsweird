import json
import os
import subprocess
import sys
import unittest

WEIRD = os.path.join(os.path.dirname(__file__), "..", "bin", "weird")


def run(*args, timeout=300):
    return subprocess.run([sys.executable, WEIRD, *args], capture_output=True, text=True, timeout=timeout)


class CliTests(unittest.TestCase):
    def test_help_lists_subcommands(self):
        r = run("--help")
        self.assertEqual(r.returncode, 0)
        for sub in ("inspect", "rules", "baseline", "falco-rules"):
            self.assertIn(sub, r.stdout)

    def test_falco_rules_is_yaml_rule_list(self):
        r = run("falco-rules")
        self.assertEqual(r.returncode, 0)
        rules = [l for l in r.stdout.splitlines() if l.startswith("- rule:")]
        self.assertGreater(len(rules), 3)
        self.assertIn("condition:", r.stdout)

    def test_json_scan_has_expected_shape(self):
        r = run("--json")
        # 0 = clean, 1 = warnings, 2 = suspicious processes found; 3 = collector failure
        self.assertIn(r.returncode, (0, 1, 2), r.stderr[-500:])
        data = json.loads(r.stdout)
        self.assertIn("host", data)
        self.assertIn("timestamp", data)
        self.assertIsInstance(data["processes"], list)
        for p in data["processes"]:
            self.assertIn("pid", p)
            self.assertIn("name", p)


if __name__ == "__main__":
    unittest.main()
