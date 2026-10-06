"""weird offline SYSROOT: persist, executable integrity and aur against a mounted disk, no process scan."""
import contextlib
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from fixtures import make_pacman_pkg, make_stub_file  # noqa: E402
from helpers import run_cli, scan_args  # noqa: E402
from test_arch import ARCH, ArchBox  # noqa: E402
from test_integrity import append_byte  # noqa: E402
from test_persist import UnownedAwareRunCommand  # noqa: E402


class OfflineBox(ArchBox):
    def setUp(self):
        super().setUp()
        self.table[("crontab", "-l")] = None
        self.weird.run_command = UnownedAwareRunCommand(self.table)
        self.add_pkg("bash", "5.3.15-2", "/usr/bin/bash", repo="core", packager=ARCH)
        self.add_pkg("glibc", "2.40-1", "/usr/lib/libc.so.6", repo="core", packager=ARCH)

    def offline(self, sysroot=None, **overrides):
        args = dict(sysroot_dir=str(sysroot or self.sysroot), force=False, limit=0, pkgbuild_dir=None)
        args.update(overrides)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = self.weird.cmd_offline(scan_args(**args))
        return out.getvalue(), err.getvalue(), code

    def offline_json(self, **overrides):
        out, _, code = self.offline(json=True, **overrides)
        return json.loads(out), code

    def hook(self, name, exec_line):
        target = self.sysroot / "etc/pacman.d/hooks" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("[Trigger]\nOperation = Install\nType = Package\nTarget = *\n\n"
                          f"[Action]\nDescription = test\nWhen = PostTransaction\nExec = {exec_line}\n")


class Offline(OfflineBox):
    def test_clean_disk_is_exit_0(self):
        out, err, code = self.offline()
        self.assertEqual(code, 0, out + err)
        self.assertIn("Offline check of", out)
        self.assertIn("every persistence entry launches a packaged, intact executable", out)
        self.assertIn("2 executables under /usr/bin and /usr/lib: 2 checked, 2 intact, 0 modified", out)
        self.assertIn("0 critical, 0 medium, 0 low, 0 info", out)

    def test_unowned_hook_is_critical(self):
        make_stub_file(self.sysroot, "/usr/bin/evil-sync")
        self.hook("evil.hook", "/usr/bin/evil-sync")
        payload, code = self.offline_json()
        self.assertEqual(code, 2)
        persist = payload["sections"]["persist"]
        self.assertEqual(persist["counts"]["critical"], 1)
        hit = persist["findings"][0]
        self.assertEqual((hit["kind"], hit["severity"], hit["attack"]), ("pacman hook", "critical", "T1546"))
        self.assertIn("/usr/bin/evil-sync", hit["detail"])
        self.assertIn("not owned by any package", hit["detail"])
        self.assertEqual(payload["sections"]["integrity"]["counts"]["unowned"], 1)
        out, _, code = self.offline()
        self.assertEqual(code, 2)
        self.assertIn("pacman hook", out)

    def test_modified_packaged_binary_is_critical(self):
        append_byte(self.sysroot, "/usr/bin/bash")
        payload, code = self.offline_json()
        self.assertEqual(code, 2)
        integrity = payload["sections"]["integrity"]
        self.assertEqual(integrity["counts"]["modified"], 1)
        self.assertEqual(integrity["counts"]["checked"], 2)
        hit = integrity["findings"][0]
        self.assertEqual((hit["kind"], hit["severity"], hit["attack"], hit["subject"]),
                         ("integrity", "critical", "T1554", "/usr/bin/bash"))
        self.assertIn("package bash", hit["detail"])
        self.assertEqual(payload["sections"]["persist"]["counts"]["critical"], 0)
        out, _, _ = self.offline()
        self.assertIn("/usr/bin/bash differs from what package bash installed", out)

    def test_limit_caps_the_walk(self):
        payload, code = self.offline_json(limit=1)
        self.assertEqual(code, 0)
        self.assertEqual(payload["sections"]["integrity"]["counts"]["examined"], 1)
        self.assertEqual(payload["sections"]["integrity"]["limit"], 1)
        out, _, _ = self.offline(limit=1)
        self.assertIn("(first 1)", out)

    def test_symlinks_and_non_executables_are_skipped(self):
        make_stub_file(self.sysroot, "/usr/lib/data.txt").chmod(0o644)
        os.symlink("bash", self.sysroot / "usr/bin/sh")
        self.weird.file_package_cache.build()
        self.assertEqual(self.weird.offline_executables(), ["/usr/bin/bash", "/usr/lib/libc.so.6"])

    def test_json_sections(self):
        payload, code = self.offline_json()
        self.assertEqual(code, 0)
        self.assertEqual(payload["sysroot"], str(self.sysroot))
        self.assertEqual(sorted(payload["sections"]), ["aur", "integrity", "persist"])
        self.assertEqual(sorted(payload["sections"]["persist"]), ["counts", "entries", "findings"])
        self.assertEqual(payload["sections"]["integrity"]["dirs"], ["/usr/bin", "/usr/lib"])
        self.assertEqual(payload["sections"]["aur"]["packages"], [])
        self.assertEqual(payload["counts"]["total"], 0)
        self.assertIn("self_integrity", payload)
        self.assertEqual(payload["findings"], [])

    def test_aur_section_reads_the_disk_not_the_host(self):
        make_pacman_pkg(self.sysroot, "foo", "1.0-1", ["/usr/bin/foo"], validation="none",
                        packager="Unknown Packager")
        payload, code = self.offline_json()
        self.assertEqual(code, 0)
        aur = payload["sections"]["aur"]
        self.assertEqual([p["name"] for p in aur["packages"]], ["foo"])
        self.assertEqual(aur["findings"][0]["kind"], "PKGBUILD unavailable")
        self.assertNotIn(("pacman", "-Qm"), self.weird.run_command.calls)

    def test_no_pacman_db_means_no_aur_section(self):
        import shutil
        shutil.rmtree(self.sysroot / "var/lib/pacman")
        payload, code = self.offline_json()
        self.assertIsNone(payload["sections"]["aur"])
        out, _, _ = self.offline()
        self.assertIn("no pacman local database under the sysroot", out)

    def test_refuses_root_without_force(self):
        out, err, code = self.offline(sysroot="/")
        self.assertEqual(code, 3)
        self.assertEqual(out, "")
        self.assertIn("refusing / (the running system) without --force", err)
        self.assertEqual(self.weird.SYSROOT, str(self.sysroot))

    def test_missing_directory_is_refused(self):
        out, err, code = self.offline(sysroot=str(self.sysroot / "nope"))
        self.assertEqual(code, 3)
        self.assertIn("is not a directory", err)


class OfflineCli(unittest.TestCase):
    def test_cli_refuses_root(self):
        r = run_cli(["dev", "offline", "/"], timeout=60)
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertIn("--force", r.stderr)

    def test_help_mentions_live_media(self):
        r = run_cli(["dev", "offline", "--help"], timeout=60)
        self.assertEqual(r.returncode, 0)
        self.assertIn("--force", r.stdout)
        self.assertIn("--limit", r.stdout)


if __name__ == "__main__":
    unittest.main()
