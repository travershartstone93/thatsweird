import json
import os
import shutil
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

from fixtures import STUB, make_proc  # noqa: E402
from helpers import FakeRunCommand, fake_which, sandbox_root  # noqa: E402
from test_arch import ArchBox  # noqa: E402

UV_TOOLCHAIN = "cpython-3.13.14-linux-x86_64-gnu"
RUSTUP_TOOLCHAIN = "stable-x86_64-unknown-linux-gnu"


class GoPassThrough(FakeRunCommand):
    """The fake table for everything except `go`, which really runs."""

    def __call__(self, cmd, timeout=10, check=True):
        if cmd[0] != "go":
            return super().__call__(cmd, timeout, check)
        self.calls.append(tuple(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return None if check and result.returncode else result.stdout


class UserPkgBox(ArchBox):
    sandbox_dir = sandbox_root()

    def home_file(self, rel, data: "str | bytes" = STUB, executable=False):
        target = self.home / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(data, bytes):
            target.write_bytes(data)
        else:
            target.write_text(data)
        if executable:
            target.chmod(0o755)
        return str(target)

    def user_pkg(self, exe):
        level, info = self.provenance(exe)
        self.assertEqual(level, self.weird.TrustLevel.USER_PKG, info.evidence)
        self.assertEqual(info.ownership, "owned")
        self.assertTrue(info.description, info)
        return info

    def scanned(self, pid, exe, cmdline=None):
        make_proc(self.proc, pid, exe, cmdline=cmdline)
        proc, _, code = self.scan_pid(pid)
        return proc, code


class UvPython(UserPkgBox):
    def test_uv_python(self):
        exe = self.home_file(f".local/share/uv/python/{UV_TOOLCHAIN}/bin/python3.13", executable=True)
        info = self.user_pkg(exe)
        self.assertEqual(info.evidence[0], "installed by uv as cpython@3.13.14")
        self.assertEqual(info.manager, "uv")
        self.assertEqual(info.version, "3.13.14")
        self.assertIn("uv python 3.13.14", info.description)
        proc, code = self.scanned(700, exe, cmdline=[exe, "-m", "serena"])
        self.assertEqual(proc.trust_level, self.weird.TrustLevel.USER_PKG, proc.evidence)
        self.assertEqual(proc.weirdness_score, 0, proc.reasons)
        self.assertEqual(proc.provenance.description, info.description)
        self.assertTrue(proc.cached_description)
        self.assertEqual(code, 0)
        self.assertEqual(self.pacman_calls("-Qo"), [])


class UvTool(UserPkgBox):
    def test_uv_tool_receipt_and_dist_info(self):
        exe = self.home_file(".local/share/uv/tools/aider-chat/bin/aider", executable=True)
        self.home_file(".local/share/uv/tools/aider-chat/uv-receipt.toml",
                       '[tool]\nrequirements = [{ name = "aider-chat" }]\npython = "3.12"\n')
        self.home_file(".local/share/uv/tools/aider-chat/lib/python3.12/site-packages/aider_chat-0.86.1.dist-info/METADATA",
                       "Name: aider-chat\n")
        info = self.user_pkg(exe)
        self.assertEqual(info.evidence[0], "installed by uv as aider-chat@0.86.1")
        self.assertEqual(info.description, "uv tool aider-chat")
        self.assertIn("uv tool python 3.12", info.evidence)


class Pipx(UserPkgBox):
    def test_pipx_metadata(self):
        exe = self.home_file(".local/share/pipx/venvs/foo/bin/foo", executable=True)
        self.home_file(".local/share/pipx/venvs/foo/pipx_metadata.json", json.dumps({
            "main_package": {"package_or_url": "foo", "package_version": "2.0.1", "apps": ["foo"]},
            "pipx_metadata_version": "0.5",
        }))
        info = self.user_pkg(exe)
        self.assertEqual(info.evidence[0], "installed by pipx as foo@2.0.1")
        self.assertEqual(info.description, "pipx package foo")
        self.assertEqual(info.prefix, f"{self.home}/.local/share/pipx/venvs/foo/")

    def test_legacy_pipx_home(self):
        exe = self.home_file(".local/pipx/venvs/foo/bin/foo", executable=True)
        self.home_file(".local/pipx/venvs/foo/pipx_metadata.json",
                       json.dumps({"main_package": {"package_or_url": "foo", "package_version": "1.0"}}))
        self.assertEqual(self.user_pkg(exe).evidence[0], "installed by pipx as foo@1.0")


class NpmGlobal(UserPkgBox):
    def test_npm_package_json(self):
        exe = self.home_file(".local/lib/node_modules/bar/bin/bar", executable=True)
        self.home_file(".local/lib/node_modules/bar/package.json", json.dumps({
            "name": "bar", "version": "1.4.0", "description": "Bar does things",
            "_resolved": "https://registry.npmjs.org/bar/-/bar-1.4.0.tgz",
            "_integrity": "sha512-abc",
        }))
        info = self.user_pkg(exe)
        self.assertEqual(info.evidence[0], "installed by npm as bar@1.4.0")
        self.assertEqual(info.description, "Bar does things")
        self.assertIn("_resolved https://registry.npmjs.org/bar/-/bar-1.4.0.tgz", info.evidence)
        self.assertIn("_integrity sha512-abc", info.evidence)

    def test_scoped_package_in_npx_cache(self):
        exe = self.home_file(".npm/_npx/abc123/node_modules/@scope/tool/build/Release/tool.node")
        self.home_file(".npm/_npx/abc123/node_modules/@scope/tool/package.json",
                       json.dumps({"name": "@scope/tool", "version": "0.3.2"}))
        info = self.user_pkg(exe)
        self.assertEqual(info.evidence[0], "installed by npm as @scope/tool@0.3.2")
        self.assertEqual(info.prefix, f"{self.home}/.npm/_npx/abc123/node_modules/@scope/tool/")


class Cargo(UserPkgBox):
    def test_crates_toml(self):
        exe = self.home_file(".cargo/bin/baz", executable=True)
        self.home_file(".cargo/.crates.toml",
                       '[v1]\n"baz 1.2.3 (registry+https://github.com/rust-lang/crates.io-index)" = ["baz"]\n'
                       '"other 0.1.0 (git+https://example.org/other#abcdef)" = ["other", "other-cli"]\n')
        info = self.user_pkg(exe)
        self.assertEqual(info.evidence[0], "installed by cargo as baz@1.2.3")
        self.assertIn("source registry+https://github.com/rust-lang/crates.io-index", info.evidence)
        self.assertIn("cargo install baz", info.description)

    def test_rustup_proxy_in_cargo_bin(self):
        exe = self.home_file(".cargo/bin/cargo", executable=True)
        self.home_file(".cargo/bin/rustup", executable=True)
        self.home_file(f".rustup/toolchains/{RUSTUP_TOOLCHAIN}/bin/cargo", executable=True)
        info = self.user_pkg(exe)
        self.assertEqual(info.manager, "rustup")
        self.assertEqual(info.evidence[0], "installed by rustup as cargo")


class Rustup(UserPkgBox):
    def test_toolchain_dir(self):
        exe = self.home_file(f".rustup/toolchains/{RUSTUP_TOOLCHAIN}/bin/cargo", executable=True)
        info = self.user_pkg(exe)
        self.assertEqual(info.evidence[0], f"installed by rustup as cargo@{RUSTUP_TOOLCHAIN}")
        self.assertEqual(info.description, f"rustup toolchain {RUSTUP_TOOLCHAIN}")


class Nvm(UserPkgBox):
    def test_node_version_dir(self):
        exe = self.home_file(".nvm/versions/node/v22.4.0/bin/node", executable=True)
        info = self.user_pkg(exe)
        self.assertEqual(info.evidence[0], "installed by nvm as node@v22.4.0")
        self.assertEqual(info.description, "nvm node v22.4.0")


class SitePackages(UserPkgBox):
    def test_dist_info_record(self):
        site = "proj/.venv/lib/python3.12/site-packages"
        exe = self.home_file(f"{site}/numpy/core/_multiarray.so")
        self.home_file(f"{site}/numpy-2.0.0.dist-info/RECORD",
                       "numpy/__init__.py,sha256=abc,10\nnumpy/core/_multiarray.so,sha256=def,20\n"
                       "../../../bin/f2py,sha256=ghi,5\n")
        self.home_file(f"{site}/numpy-2.0.0.dist-info/INSTALLER", "pip\n")
        info = self.user_pkg(exe)
        self.assertEqual(info.evidence[0], "installed by pip as numpy@2.0.0")
        self.assertEqual(info.prefix, f"{self.home}/{site}/")
        self.assertIsNone(self.weird.verify_user_pkg_provenance(f"{self.home}/{site}/other/x.so"))


class GoBinary(UserPkgBox):
    @unittest.skipUnless(shutil.which("go"), "go toolchain not installed")
    def test_go_binary_identified(self):
        src = self.home / "src/hello"
        src.mkdir(parents=True)
        (src / "go.mod").write_text("module example.com/hello\n\ngo 1.21\n")
        (src / "main.go").write_text('package main\n\nfunc main() { println("hi") }\n')
        out = self.home / "go/bin/hello"
        out.parent.mkdir(parents=True)
        env = dict(os.environ, HOME=str(self.home), GOPATH=str(self.home / "go"),
                   GOCACHE=str(self.home / "gocache"), GOFLAGS="-mod=mod", GOTOOLCHAIN="local")
        build = subprocess.run(["go", "build", "-o", str(out), "."], cwd=src, env=env,
                               capture_output=True, text=True, timeout=180)
        self.assertEqual(build.returncode, 0, build.stderr)

        self.weird.run_command = GoPassThrough(self.table)
        with mock.patch("shutil.which", fake_which({"pacman", "go"})):
            info = self.user_pkg(str(out))
            self.assertEqual(info.manager, "go")
            self.assertEqual(info.package, "example.com/hello")
            self.assertTrue(info.evidence[0].startswith("installed by go as example.com/hello"), info.evidence)
            self.assertIn("go module example.com/hello", info.description)
            self.assertTrue(any(e.startswith("built with go1.") for e in info.evidence), info.evidence)
            self.assertIn(("go", "version", "-m", str(out)), self.weird.run_command.calls)
            # negative result is cached: a second look at a non Go ELF costs one call
            self.assertIsNone(self.weird.verify_user_pkg_provenance(str(out) + "-missing"))
            self.assertIsNone(self.weird.go_binary_module(str(out) + "-missing"))


class BareScript(UserPkgBox):
    def test_script_in_local_bin_stays_user_local(self):
        exe = self.home_file(".local/bin/tool.sh", "#!/bin/sh\nexit 0\n", executable=True)
        proc, code = self.scanned(701, exe)
        self.assertEqual(proc.trust_level, self.weird.TrustLevel.USER_LOCAL, proc.evidence)
        self.assertEqual(proc.provenance.manager, "")
        self.assertEqual(code, 0)
        self.assertFalse([c for c in self.weird.run_command.calls if c[0] == "go"])

    def test_uv_tool_symlink_in_local_bin(self):
        target = self.home_file(".local/share/uv/tools/foo/bin/foo", executable=True)
        self.home_file(".local/share/uv/tools/foo/uv-receipt.toml", 'requirements = [{ name = "foo" }]\n')
        link = self.home / ".local/bin/foo"
        link.parent.mkdir(parents=True)
        os.symlink(target, link)
        make_proc(self.proc, 702, str(link))
        proc, _, _ = self.scan_pid(702)
        self.assertEqual(proc.trust_level, self.weird.TrustLevel.USER_PKG, proc.evidence)
        self.assertEqual(proc.provenance.evidence[0], "installed by uv as foo")


if __name__ == "__main__":
    unittest.main()
