import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Dict, Optional, Tuple
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

from fixtures import make_pacman_conf, make_pacman_pkg, make_proc  # noqa: E402
from helpers import fake_run_command, fake_which, load_weird, scan_args  # noqa: E402

CACHYOS = "CachyOS <admin@cachyos.org>"
ARCH = "Levente Polyak <anthraxx@archlinux.org>"
AUR = "Unknown Packager"


class ArchBox(unittest.TestCase):
    """Sandbox with a pacman local database, a pacman.conf and a fake /proc."""

    siglevel = "Required DatabaseOptional"
    localfilesiglevel = "Optional"
    write_conf = True
    # a home directory under /tmp trips the temp dir checks; tests that scan home paths move it
    sandbox_dir: Optional[str] = None

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=self.sandbox_dir)
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.home = root / "home"
        self.proc = root / "proc"
        self.sysroot = root / "sys"
        self.local_dir = self.sysroot / "var/lib/pacman/local"
        if self.write_conf:
            make_pacman_conf(self.sysroot, siglevel=self.siglevel, localfilesiglevel=self.localfilesiglevel)
        self.table: Dict[Tuple[str, ...], Optional[str]] = {
            ("dpkg-divert", "--list"): None,
            ("systemd-detect-virt", "--container"): None,
            ("pacman", "-Sl"): None,
        }
        self.weird = load_weird(self.home, proc_root=self.proc, sysroot=self.sysroot)
        self.weird.run_command = fake_run_command(self.table)
        patcher = mock.patch("shutil.which", fake_which({"pacman"}))
        patcher.start()
        self.addCleanup(patcher.stop)

    def add_pkg(self, name, version, exe, repo=None, repo_version=None, **kwargs):
        make_pacman_pkg(self.sysroot, name, version, [exe], **kwargs)
        if repo:
            self.table[("pacman", "-Si", name)] = (
                f"Repository      : {repo}\nName            : {name}\n"
                f"Version         : {repo_version or version}\n"
            )
        else:
            self.table[("pacman", "-Si", name)] = None

    def provenance(self, exe):
        self.weird.file_package_cache.build()
        return self.weird.verify_package_provenance(exe)

    def scan_pid(self, pid):
        processes, alerts, code = self.weird.run_scan(scan_args(verbose=True))
        return next(p for p in processes if p.pid == pid), alerts, code

    def pacman_calls(self, flag):
        return [c for c in self.weird.run_command.calls if c[:2] == ("pacman", flag)]


class PacmanCache(ArchBox):
    def test_pacman_cache_maps_paths(self):
        self.add_pkg("bash", "5.3.15-2", "/usr/bin/bash")
        self.add_pkg("kwin", "6.5.0-1", "/usr/bin/kwin_wayland")
        cache = self.weird.FilePackageCache()
        cache.build()
        self.assertEqual(cache.get("/usr/bin/kwin_wayland"), "kwin")
        self.assertEqual(cache.get("/usr/bin/bash"), "bash")
        self.assertEqual(cache.get_manager("/usr/bin/bash"), "pacman")
        self.assertIsNone(cache.get("/usr/bin"))
        self.assertIsNone(cache.get("/usr/bin/nothing"))

    def test_pacman_cache_no_subprocess(self):
        self.add_pkg("bash", "5.3.15-2", "/usr/bin/bash", repo="core", packager=CACHYOS)
        level, info = self.provenance("/usr/bin/bash")
        self.assertEqual(level, self.weird.TrustLevel.OFFICIAL_REPO, info.evidence)
        self.assertEqual(info.package, "bash")
        self.assertEqual(info.description, "bash test package")
        self.assertEqual(self.pacman_calls("-Qo"), [])
        self.assertEqual(self.pacman_calls("-Qi"), [])

    def test_pacman_cache_reuses_until_db_changes(self):
        self.add_pkg("bash", "5.3.15-2", "/usr/bin/bash")
        original = self.weird.FilePackageCache._build_pacman
        with mock.patch.object(self.weird.FilePackageCache, "_build_pacman",
                               autospec=True, side_effect=original) as spy:
            self.weird.FilePackageCache().build()
            self.assertEqual(spy.call_count, 1)
            second = self.weird.FilePackageCache()
            second.build()
            self.assertEqual(spy.call_count, 1)
            self.assertEqual(second.get("/usr/bin/bash"), "bash")

            st = self.local_dir.stat()
            os.utime(self.local_dir, (st.st_atime, st.st_mtime + 30))
            third = self.weird.FilePackageCache()
            third.build()
            self.assertEqual(spy.call_count, 2)
            self.assertEqual(third.get("/usr/bin/bash"), "bash")

    def test_sync_index_first_repo_wins(self):
        self.add_pkg("bash", "5.3.15-2", "/usr/bin/bash", packager=CACHYOS)
        del self.table[("pacman", "-Si", "bash")]
        self.table[("pacman", "-Sl")] = (
            "cachyos-v3 bash 5.3.15-2 [installed]\n"
            "core bash 5.3.15-1 [installed: 5.3.15-2]\n"
            "extra kwin 6.5.0-1\n"
        )
        level, info = self.provenance("/usr/bin/bash")
        self.assertEqual(level, self.weird.TrustLevel.OFFICIAL_REPO, info.evidence)
        self.assertIn("Repository: cachyos-v3", info.evidence)
        self.assertFalse(any("differs" in e for e in info.evidence), info.evidence)
        self.assertEqual(self.pacman_calls("-Si"), [])
        self.assertEqual(len(self.pacman_calls("-Sl")), 1)

    def test_pacman_cache_integrity_still_enforced(self):
        self.add_pkg("bash", "5.3.15-2", "/usr/bin/bash")
        self.weird.FilePackageCache().build()
        cache_file = self.weird.CACHE_FILE
        data = json.loads(cache_file.read_text())
        data["cache"]["/usr/bin/evil"] = "bash"
        cache_file.write_text(json.dumps(data))

        original = self.weird.FilePackageCache._build_pacman
        with mock.patch.object(self.weird.FilePackageCache, "_build_pacman",
                               autospec=True, side_effect=original) as spy:
            cache = self.weird.FilePackageCache()
            cache.build()
            self.assertEqual(spy.call_count, 1)
        self.assertIsNone(cache.get("/usr/bin/evil"))
        self.assertEqual(cache.get("/usr/bin/bash"), "bash")


class LocalBuild(ArchBox):
    def test_aur_package_is_local_build(self):
        self.add_pkg("forkstat", "0.03.02-1", "/usr/bin/forkstat", validation="none", packager=AUR)
        make_proc(self.proc, 100, "/usr/bin/forkstat")
        proc, alerts, code = self.scan_pid(100)
        self.assertEqual(proc.trust_level, self.weird.TrustLevel.LOCAL_BUILD, proc.evidence)
        self.assertTrue(any("makepkg" in e for e in proc.evidence), proc.evidence)
        self.assertEqual(proc.weirdness_score, 0)
        self.assertEqual(alerts, [])
        self.assertEqual(code, 0)
        self.assertEqual(proc.provenance.packager, AUR)
        as_json = self.weird.process_to_dict(proc)
        self.assertEqual(as_json["trust_level"], "LOCAL_BUILD")
        self.assertEqual(as_json["provenance"]["validation"], "none")
        self.assertIn("LOCAL_BUILD", self.weird.format_process_table([proc]))
        self.assertIn("makepkg", self.weird.format_process_detail(proc))

    def test_aur_package_still_scores_on_signals(self):
        self.add_pkg("forkstat", "0.03.02-1", "/usr/bin/forkstat", validation="none", packager=AUR)
        make_proc(self.proc, 100, "/usr/bin/forkstat", deleted=True)
        proc, alerts, code = self.scan_pid(100)
        critical = self.weird.load_policy()["thresholds"]["critical"]
        self.assertGreaterEqual(proc.weirdness_score, critical)
        self.assertEqual(code, 2)
        self.assertEqual([a["pid"] for a in alerts], [100])

    def test_pgp_package_is_not_local_build(self):
        self.add_pkg("bash", "5.3.15-2", "/usr/bin/bash", repo="core", packager=CACHYOS)
        level, info = self.provenance("/usr/bin/bash")
        self.assertNotEqual(level, self.weird.TrustLevel.LOCAL_BUILD)
        self.assertEqual(level, self.weird.TrustLevel.OFFICIAL_REPO)
        self.assertFalse(any("makepkg" in e for e in info.evidence))


class OfflineSignature(ArchBox):
    def test_pgp_validation_marks_verified(self):
        self.add_pkg("bash", "5.3.15-2", "/usr/bin/bash", repo="cachyos", packager=CACHYOS)
        _, info = self.provenance("/usr/bin/bash")
        self.assertEqual(info.signature, "verified")
        self.assertEqual(info.validation, "pgp")
        self.assertTrue(any(CACHYOS in e for e in info.evidence), info.evidence)

    def test_none_validation_never_verified(self):
        self.add_pkg("bash", "5.3.15-2", "/usr/bin/bash", repo="core", validation="none", packager=CACHYOS)
        level, info = self.provenance("/usr/bin/bash")
        self.assertNotEqual(info.signature, "verified")
        self.assertNotEqual(level, self.weird.TrustLevel.OFFICIAL_REPO)

    def test_missing_validation_field_is_unknown(self):
        self.add_pkg("bash", "5.3.15-2", "/usr/bin/bash", repo="core", validation=None, packager=CACHYOS)
        level, info = self.provenance("/usr/bin/bash")
        self.assertEqual(info.signature, "unknown")
        self.assertEqual(info.validation, "")
        self.assertNotEqual(level, self.weird.TrustLevel.OFFICIAL_REPO)

    def test_desc_fields_exposed(self):
        self.add_pkg("bash", "5.3.15-2", "/usr/bin/bash", repo="core", packager=ARCH, installdate=1700000000)
        _, info = self.provenance("/usr/bin/bash")
        self.assertEqual(info.packager, ARCH)
        self.assertEqual(info.installdate, 1700000000)
        self.assertEqual(info.version, "5.3.15-2")


class RepoImpersonation(ArchBox):
    def test_local_build_named_like_repo_pkg(self):
        self.add_pkg("bash", "5.3.15-2", "/usr/bin/bash", repo="core", validation="none", packager=AUR)
        make_proc(self.proc, 100, "/usr/bin/bash")
        proc, alerts, code = self.scan_pid(100)
        self.assertNotEqual(proc.trust_level, self.weird.TrustLevel.OFFICIAL_REPO)
        self.assertEqual(proc.trust_level, self.weird.TrustLevel.LOCAL_BUILD)
        reasons = [e for e in proc.evidence if "local build" in e and "core" in e]
        self.assertTrue(reasons, proc.evidence)
        expected = self.weird.load_policy()["scores"]["repo_name_impersonation"]
        self.assertTrue(any(f"(+{expected})" in e for e in reasons), reasons)
        self.assertGreaterEqual(proc.weirdness_score, expected)
        self.assertEqual([a["pid"] for a in alerts], [100])
        self.assertEqual(code, 1)

    def test_distro_signed_repo_package_is_official(self):
        self.add_pkg("bash", "5.3.15-2", "/usr/bin/bash", repo="core", packager=ARCH)
        make_proc(self.proc, 100, "/usr/bin/bash")
        proc, alerts, code = self.scan_pid(100)
        self.assertEqual(proc.trust_level, self.weird.TrustLevel.OFFICIAL_REPO, proc.evidence)
        self.assertEqual(proc.weirdness_score, 0)
        self.assertEqual(code, 0)

    def test_pgp_but_foreign_packager_is_third_party(self):
        self.add_pkg("bash", "5.3.15-2", "/usr/bin/bash", repo="core", packager="Mallory <m@example.org>")
        level, _ = self.provenance("/usr/bin/bash")
        self.assertEqual(level, self.weird.TrustLevel.THIRD_PARTY_REPO)

    def test_version_mismatch_is_evidence_only(self):
        self.add_pkg("bash", "5.3.15-2", "/usr/bin/bash", repo="core", repo_version="5.3.15-3", packager=ARCH)
        make_proc(self.proc, 100, "/usr/bin/bash")
        proc, _, _ = self.scan_pid(100)
        self.assertTrue(any("5.3.15-3" in e and "differs" in e for e in proc.evidence), proc.evidence)
        self.assertEqual(proc.weirdness_score, 0)
        self.assertEqual(proc.trust_level, self.weird.TrustLevel.OFFICIAL_REPO)


class SigLevelHonesty(ArchBox):
    def test_siglevel_database_optional_evidence(self):
        self.add_pkg("bash", "5.3.15-2", "/usr/bin/bash", repo="core", packager=CACHYOS)
        _, info = self.provenance("/usr/bin/bash")
        joined = "\n".join(info.evidence)
        self.assertIn("sync database not verified", joined)
        self.assertNotIn("signed package database", joined)

    def test_describe_siglevel_wording(self):
        describe = self.weird.describe_pacman_siglevel
        self.assertEqual(describe(None), "SigLevel unknown")
        self.assertEqual(describe("Required DatabaseOptional"), "packages signature checked, sync database not verified")
        self.assertEqual(describe("Required DatabaseNever"), "packages signature checked, sync database not verified")
        self.assertEqual(describe("Required DatabaseRequired"), "packages and sync database signature checked")
        self.assertEqual(describe("Required"), "packages and sync database signature checked")
        self.assertIn("not required", describe("Never"))

    def test_localfilesiglevel_optional_warns(self):
        self.add_pkg("bash", "5.3.15-2", "/usr/bin/bash", repo="core", packager=CACHYOS)
        self.add_pkg("kwin", "6.5.0-1", "/usr/bin/kwin_wayland", repo="extra", packager=CACHYOS)
        make_proc(self.proc, 100, "/usr/bin/bash")
        make_proc(self.proc, 200, "/usr/bin/kwin_wayland")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.weird.cmd_scan(scan_args(verbose=True))
        text = out.getvalue()
        self.assertEqual(text.count("LocalFileSigLevel"), 1, text)
        self.assertIn("installed unsigned", text)


class SigLevelDatabaseRequired(ArchBox):
    siglevel = "Required DatabaseRequired"
    localfilesiglevel = "Required"

    def test_siglevel_database_required(self):
        self.add_pkg("bash", "5.3.15-2", "/usr/bin/bash", repo="core", packager=CACHYOS)
        _, info = self.provenance("/usr/bin/bash")
        joined = "\n".join(info.evidence)
        self.assertIn("packages and sync database signature checked", joined)
        self.assertNotIn("not verified", joined)

    def test_localfilesiglevel_required_does_not_warn(self):
        self.add_pkg("bash", "5.3.15-2", "/usr/bin/bash", repo="core", packager=CACHYOS)
        make_proc(self.proc, 100, "/usr/bin/bash")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.weird.cmd_scan(scan_args(verbose=True))
        self.assertNotIn("LocalFileSigLevel", out.getvalue())


class MissingPacmanConf(ArchBox):
    write_conf = False

    def test_missing_pacman_conf(self):
        self.assertIsNone(self.weird.get_pacman_siglevel())
        self.assertIsNone(self.weird.get_pacman_local_file_siglevel())
        self.assertFalse(self.weird.pacman_local_files_unsigned())
        self.add_pkg("bash", "5.3.15-2", "/usr/bin/bash", repo="core", packager=CACHYOS)
        level, info = self.provenance("/usr/bin/bash")
        self.assertEqual(level, self.weird.TrustLevel.OFFICIAL_REPO, info.evidence)
        self.assertTrue(any("SigLevel unknown" in e for e in info.evidence), info.evidence)


if __name__ == "__main__":
    unittest.main()
