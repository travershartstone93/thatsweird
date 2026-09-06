"""Version, pip entry point, completions and the documents that must list every command."""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))

from helpers import REPO, WEIRD, load_weird, run_cli  # noqa: E402


def command_tree(parser):
    """{name: subparser} for every subcommand, nested ones as "parent child"."""
    found = {}
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, sub in action.choices.items():
                found[name] = sub
                for inner, deeper in command_tree(sub).items():
                    found[f"{name} {inner}"] = deeper
    return found


def long_options(parser):
    return [opt for action in parser._actions if action.help is not argparse.SUPPRESS
            for opt in action.option_strings if opt.startswith("--")]


class Versions(unittest.TestCase):
    def test_script_package_json_and_pin_agree(self):
        script_version = re.search(r'^__version__ = "([^"]+)"', WEIRD.read_text(), re.M).group(1)
        data = json.loads((REPO / "package.json").read_text())
        self.assertEqual(data["version"], script_version)
        self.assertEqual(data["weirdIntegrity"]["version"], script_version)
        self.assertIn('dynamic = ["version"]', (REPO / "pyproject.toml").read_text())
        self.assertIn(script_version, (REPO / "CHANGELOG.md").read_text())

    def test_version_flag(self):
        r = run_cli(["--version"])
        self.assertEqual(r.returncode, 0)
        self.assertRegex(r.stdout.strip(), r"^weird \d+\.\d+\.\d+$")


class EntryPoint(unittest.TestCase):
    def test_shim_runs_bin_weird(self):
        code = ("import sys; sys.path.insert(0, %r); import weird_cli; m = weird_cli.load(); "
                "print(m.SELF_PATH); weird_cli.main()" % str(REPO))
        r = subprocess.run([sys.executable, "-c", code, "--version"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = r.stdout.splitlines()
        self.assertEqual(lines[0], str(WEIRD.resolve()))
        self.assertRegex(lines[1], r"^weird \d")

    def test_installed_layout_finds_pin_and_man_page(self):
        """A wheel puts weird, package.json and weird.1 side by side; the script must find them there."""
        with tempfile.TemporaryDirectory(prefix="weird-wheel-") as tmp:
            pkg = Path(tmp) / "site" / "weird_cli"
            pkg.mkdir(parents=True)
            shutil.copy2(WEIRD, pkg / "weird")
            shutil.copy2(REPO / "package.json", pkg / "package.json")
            shutil.copy2(REPO / "man" / "weird.1", pkg / "weird.1")
            shutil.copy2(REPO / "weird_cli" / "__init__.py", pkg / "__init__.py")
            code = "import sys; sys.path.insert(0, %r); import weird_cli; weird_cli.main()" % str(pkg.parent)
            r = subprocess.run([sys.executable, "-c", code, "self-check", "--json"],
                               capture_output=True, text=True, env={**os.environ, "HOME": tmp})
            self.assertEqual(r.returncode, 0, r.stderr)
            info = json.loads(r.stdout)["self_integrity"]
            self.assertEqual(info["status"], "match", info)
            self.assertEqual(info["path"], str(pkg / "weird"))
            self.assertEqual(info["pin_file"], str(pkg / "package.json"))
            r = subprocess.run([sys.executable, "-c", code, "man"], capture_output=True, text=True,
                               env={**os.environ, "HOME": tmp, "PATH": tmp})
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn(".TH WEIRD 1", r.stdout)


class Completions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sandbox = tempfile.TemporaryDirectory(prefix="weird-completions-")
        cls.weird = load_weird(Path(cls.sandbox.name) / "home")
        cls.parser = cls.weird.build_parser()
        cls.bash = cls.weird._bash_completion(cls.parser)
        cls.fish = cls.weird._fish_completion(cls.parser)

    @classmethod
    def tearDownClass(cls):
        cls.sandbox.cleanup()

    def test_every_subcommand_and_option_is_offered(self):
        tree = command_tree(self.parser)
        for name, sub in tree.items():
            leaf = name.split()[-1]
            self.assertRegex(self.bash, rf"[ \"]{re.escape(leaf)}[ \"]", name)
            self.assertIn(f"-a {leaf} ", self.fish, name)
            for opt in long_options(sub):
                self.assertIn(opt, self.bash, f"{name} {opt}")
                self.assertIn(f"-l {opt[2:]} ", self.fish, f"{name} {opt}")
        for opt in long_options(self.parser):
            self.assertIn(opt, self.bash)
            self.assertIn(f"-l {opt[2:]} ", self.fish)

    def test_nested_options_stay_under_their_parent(self):
        self.assertIn('"rules init") words="-h --help --force"', self.bash)
        self.assertIn('__fish_seen_subcommand_from rules; and __fish_seen_subcommand_from init" -l force', self.fish)
        self.assertNotIn('__fish_seen_subcommand_from baseline; and __fish_seen_subcommand_from init', self.fish)

    def test_file_options_complete_paths(self):
        self.assertIn("--prometheus|", self.bash)
        self.assertIn("-l prometheus -r -F", self.fish)
        self.assertIn("-l poll -x", self.fish)

    def test_subcommand_prints_them(self):
        for shell, marker in (("bash", "complete -F _weird weird"), ("fish", "complete -c weird -f")):
            r = run_cli(["completions", shell])
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn(marker, r.stdout)

    @unittest.skipUnless(shutil.which("bash"), "bash not installed")
    def test_bash_script_parses(self):
        r = subprocess.run(["bash", "-n"], input=self.bash, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    @unittest.skipUnless(shutil.which("fish"), "fish not installed")
    def test_fish_script_completes(self):
        with tempfile.NamedTemporaryFile("w", suffix=".fish", delete=False) as f:
            f.write(self.fish)
        self.addCleanup(os.unlink, f.name)
        r = subprocess.run(["fish", "-c", f"source {f.name}; complete -C 'weird rules '"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("show", r.stdout)
        self.assertIn("init", r.stdout)


class Documents(unittest.TestCase):
    """--help, the man page and the README must all list every subcommand."""

    @classmethod
    def setUpClass(cls):
        cls.sandbox = tempfile.TemporaryDirectory(prefix="weird-docs-")
        cls.parser = load_weird(Path(cls.sandbox.name) / "home").build_parser()
        cls.commands = command_tree(cls.parser)
        cls.man = (REPO / "man" / "weird.1").read_text().replace("\\-", "-").replace("\\f", "")
        cls.man = re.sub(r"[BIR](?=[a-z-])", "", cls.man)
        cls.readme = (REPO / "README.md").read_text()

    @classmethod
    def tearDownClass(cls):
        cls.sandbox.cleanup()

    def test_help_lists_every_subcommand(self):
        r = run_cli(["--help"])
        self.assertEqual(r.returncode, 0)
        for name in self.commands:
            self.assertIn(name.split()[0], r.stdout, name)

    def test_man_page_lists_every_subcommand_and_option(self):
        for name, sub in self.commands.items():
            self.assertIn(name.split()[-1], self.man, name)
            for opt in long_options(sub):
                self.assertIn(opt, self.man, f"{name} {opt}")
        for opt in long_options(self.parser):
            self.assertIn(opt, self.man, opt)

    def test_readme_commands_table_lists_every_subcommand(self):
        section = self.readme.split("## Commands", 1)[1].split("\n## ", 1)[0]
        for name in self.commands:
            if name in ("rules show", "rules init", "fixture record"):
                continue
            self.assertIn(f"`weird {name}", section, name)
        self.assertLess(self.readme.count("\n"), 260, "README should stay short; long reference goes in docs/")
        self.assertNotIn("\u2014", self.readme)


if __name__ == "__main__":
    unittest.main()
