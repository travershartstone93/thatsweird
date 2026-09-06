import contextlib
import io
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

from fixtures import make_proc, make_stub_file  # noqa: E402
from helpers import scan_args  # noqa: E402
from test_arch import ARCH, ArchBox  # noqa: E402

BUILD_EXE = "/home/u/.cache/paru/clone/foo/src/foo/cc1"


class RuleBox(ArchBox):
    def official(self, name, version, path):
        self.add_pkg(name, version, path, repo="extra", packager=ARCH)

    def unowned(self, path):
        make_stub_file(self.sysroot, path)
        self.table[("pacman", "-Qo", path)] = None

    def user_rules(self, rules):
        """Only the given rules, no built-in defaults."""
        return mock.patch.object(self.weird, "load_rules", return_value={
            "profiles": {}, "allow": [], "rules": rules, "defaults": False,
        })

    def firefox_then_bash(self):
        self.official("firefox", "143.0-1", "/usr/lib/firefox/firefox")
        self.official("bash", "5.3.15-2", "/usr/bin/bash")
        make_proc(self.proc, 200, "/usr/lib/firefox/firefox", comm="firefox")
        make_proc(self.proc, 201, "/usr/bin/bash", ppid=200, cmdline=["bash", "-c", "curl x | sh"])


class Ancestors(RuleBox):
    def test_walks_ppid_nearest_first(self):
        self.firefox_then_bash()
        make_proc(self.proc, 202, "/usr/bin/bash", comm="bash", ppid=201)
        self.assertEqual(self.weird.ancestors(202), [(201, "bash"), (200, "firefox")])
        self.assertEqual(self.weird.ancestors(202, limit=1), [(201, "bash")])
        self.assertEqual(self.weird.ancestors(200), [])

    def test_broken_chain(self):
        self.official("bash", "5.3.15-2", "/usr/bin/bash")
        make_proc(self.proc, 210, "/usr/bin/bash", ppid=999)
        self.assertEqual(self.weird.ancestors(210), [])
        self.assertEqual(self.weird.ancestors(4242), [])
        with self.user_rules([{"parent": "firefox", "action": "upgrade", "add": 30},
                              {"direct_parent": {"regex": "."}, "action": "upgrade", "add": 30}]):
            proc, _, _ = self.scan_pid(210)
        self.assertEqual(proc.parent_chain, [])
        self.assertEqual(proc.weirdness_score, 0)
        self.assertEqual(proc.signal_keys, [])

    def test_parent_chain_in_json(self):
        self.firefox_then_bash()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.weird.cmd_scan(scan_args(json=True, verbose=True))
        import json
        rows = {p["pid"]: p for p in json.loads(out.getvalue())["processes"]}
        self.assertEqual(rows[201]["parent_chain"], ["firefox"])
        self.assertEqual(rows[200]["parent_chain"], [])
        self.assertIn("tags", rows[201])


class ParentMatchers(RuleBox):
    def test_ancestor_rule_matches(self):
        self.firefox_then_bash()
        with self.user_rules([{"id": "doc-shell", "parent": {"regex": "^(firefox|evince)$"},
                               "name": "bash", "action": "upgrade", "add": 30, "attack": "T1204.002"}]):
            proc, alerts, code = self.scan_pid(201)
        self.assertEqual(proc.parent_chain, ["firefox"])
        self.assertEqual(proc.weirdness_score, 30)
        self.assertEqual(proc.reasons, ["Rule doc-shell: upgraded under firefox (+30)"])
        self.assertEqual(proc.signal_keys, ["rule_upgrade"])
        self.assertEqual(proc.attack, ["T1204.002"])
        self.assertEqual([a["pid"] for a in alerts], [201])
        self.assertEqual(code, 1)

    def test_depth_limit(self):
        self.official("bash", "5.3.15-2", "/usr/bin/bash")
        self.official("firefox", "143.0-1", "/usr/lib/firefox/firefox")
        # 300 <- 301 <- ... <- 307; 306 is depth 6, 307 depth 7
        for depth in range(1, 8):
            pid = 300 + depth
            comm = "firefox" if depth == 7 else f"bash{depth}"
            make_proc(self.proc, pid, "/usr/bin/bash", comm=comm, ppid=pid + 1 if depth < 7 else 1)
        make_proc(self.proc, 300, "/usr/bin/bash", ppid=301)
        self.assertEqual(len(self.weird.ancestors(300)), 6)
        rule = {"parent": "firefox", "action": "upgrade", "add": 30}
        with self.user_rules([rule]):
            proc, _, _ = self.scan_pid(300)
        self.assertEqual(proc.parent_chain, ["bash1", "bash2", "bash3", "bash4", "bash5", "bash6"])
        self.assertEqual(proc.weirdness_score, 0)
        with self.user_rules([{"parent": "bash5", "action": "upgrade", "add": 30}]):
            proc, _, _ = self.scan_pid(300)
        self.assertEqual(proc.weirdness_score, 30)

    def test_direct_parent_vs_ancestor(self):
        self.firefox_then_bash()
        make_proc(self.proc, 202, "/usr/bin/bash", comm="bash", ppid=201, cmdline=["bash", "-c", "true"])
        with self.user_rules([{"direct_parent": "firefox", "action": "upgrade", "add": 30}]):
            child, _, _ = self.scan_pid(201)
            grandchild, _, _ = self.scan_pid(202)
        self.assertEqual(child.weirdness_score, 30)
        self.assertEqual(grandchild.weirdness_score, 0)
        with self.user_rules([{"parent": "firefox", "action": "upgrade", "add": 30}]):
            grandchild, _, _ = self.scan_pid(202)
        self.assertEqual(grandchild.weirdness_score, 30)
        self.assertEqual(grandchild.reasons, ["Rule rule1: upgraded under firefox (+30)"])

    def test_plain_string_is_exact(self):
        self.firefox_then_bash()
        with self.user_rules([{"parent": "fire", "action": "upgrade", "add": 30}]):
            proc, _, _ = self.scan_pid(201)
        self.assertEqual(proc.weirdness_score, 0)


class DefaultRules(RuleBox):
    def build_tree(self, chain_root_is_paru=True):
        self.official("paru", "2.1.0-1", "/usr/bin/paru")
        self.official("bash", "5.3.15-2", "/usr/bin/bash")
        self.official("pacman", "7.0.0-1", "/usr/bin/makepkg")
        self.unowned(BUILD_EXE)
        if chain_root_is_paru:
            make_proc(self.proc, 100, "/usr/bin/paru", cmdline=["paru", "-S", "foo"])
            make_proc(self.proc, 101, "/usr/bin/makepkg", ppid=100, cmdline=["/bin/bash", "/usr/bin/makepkg"])
            make_proc(self.proc, 102, "/usr/bin/bash", ppid=101)
        else:
            make_proc(self.proc, 102, "/usr/bin/bash", ppid=1)
        make_proc(self.proc, 103, BUILD_EXE, ppid=102, cmdline=[BUILD_EXE, "-O2", "foo.c"])

    def test_makepkg_descendants_suppressed(self):
        self.build_tree()
        self.assertFalse(self.weird.RULES_FILE.exists())
        processes, alerts, code = self.weird.run_scan(scan_args(verbose=False))
        self.assertNotIn(103, [p.pid for p in processes])
        self.assertEqual(alerts, [])
        self.assertEqual(code, 0)

        proc, alerts, code = self.scan_pid(103)
        self.assertEqual(proc.parent_chain, ["bash", "makepkg", "paru"])
        self.assertTrue(proc.suppressed)
        self.assertEqual(proc.tags, ["build"])
        self.assertEqual(proc.weirdness_score, 0)
        self.assertEqual(proc.signal_keys, [])
        self.assertIn("Rule aur-helper-build: suppressed under makepkg", proc.evidence)
        self.assertEqual(alerts, [])
        table = self.weird.format_process_table([proc], verbose=True)
        self.assertIn("[build]", table)

    def test_same_binary_outside_a_build_is_alerted(self):
        self.build_tree(chain_root_is_paru=False)
        proc, alerts, code = self.scan_pid(103)
        self.assertEqual(proc.parent_chain, ["bash"])
        self.assertFalse(proc.suppressed)
        self.assertEqual(proc.tags, [])
        self.assertIn("suspicious_path", proc.signal_keys)
        self.assertIn(103, [a["pid"] for a in alerts])
        self.assertGreaterEqual(code, 1)

    def test_shell_from_document_app(self):
        self.firefox_then_bash()
        proc, alerts, code = self.scan_pid(201)
        self.assertEqual(proc.reasons, ["Rule shell-from-document-app: upgraded under firefox (+30)"])
        self.assertEqual(proc.attack, ["T1204.002"])
        self.assertEqual(self.weird.verdict_for(proc), "Suspicious")
        self.assertEqual([a["pid"] for a in alerts], [201])

    def test_defaults_can_be_disabled(self):
        self.firefox_then_bash()
        self.weird.RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
        self.weird.RULES_FILE.write_text("defaults = false\n")
        proc, alerts, _ = self.scan_pid(201)
        self.assertEqual(proc.weirdness_score, 0)
        self.assertEqual(alerts, [])

    def test_defaults_render_as_toml(self):
        import tomllib
        data = tomllib.loads(self.weird.format_default_rules())
        self.assertEqual([r["id"] for r in data["rules"]], ["aur-helper-build", "shell-from-document-app"])
        self.assertEqual(data["rules"][1]["attack"], "T1204.002")
        template = tomllib.loads(self.weird.RULES_TEMPLATE)
        self.assertTrue(any("parent" in r for r in template["rules"]))
        self.assertTrue(any("direct_parent" in r for r in template["rules"]))


if __name__ == "__main__":
    unittest.main()
