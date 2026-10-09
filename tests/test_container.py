"""Container-aware provenance: a container process is checked against the package database inside its own root."""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

from fixtures import _write, make_apt_pkg, make_proc, make_stub_file  # noqa: E402
from helpers import scan_args  # noqa: E402
from test_arch import ARCH, ArchBox  # noqa: E402

DOCKER_CGROUP = "0::/system.slice/docker-0123456789abcdef.scope"


class ContainerBox(ArchBox):
    def setUp(self):
        super().setUp()
        self.table[("dpkg-query", "-W", "-f", "${Description}", "nginx")] = None
        self.table[("apt-cache", "policy", "nginx")] = None
        self.add_pkg("bash", "5.3.15-2", "/usr/bin/bash", repo="core", packager=ARCH)
        make_proc(self.proc, 100, "/usr/bin/bash")

    def container(self, pid, exe, marker=True, cgroup=DOCKER_CGROUP, **kwargs):
        """A container process whose /proc/<pid>/root is a directory holding the image."""
        make_proc(self.proc, pid, exe, cgroup=cgroup, **kwargs)
        root = self.proc / str(pid) / "root"
        root.mkdir(parents=True, exist_ok=True)
        if marker:
            _write(root / ".dockerenv", "")
        return root

    def scan(self):
        processes, alerts, code = self.weird.run_scan(scan_args(verbose=True, all=True))
        return {p.pid: p for p in processes}, code


class ImageProvenance(ContainerBox):
    def test_container_provenance_from_image_db(self):
        root = self.container(500, "/usr/sbin/nginx")
        make_apt_pkg(root, "nginx", ["/usr/sbin/nginx"])
        procs, _ = self.scan()
        nginx = procs[500]
        self.assertTrue(nginx.is_container)
        self.assertEqual(nginx.trust_level, self.weird.TrustLevel.CONTAINER)
        self.assertEqual((nginx.provenance.ownership, nginx.provenance.package), ("owned", "nginx"))
        self.assertIn("container image package nginx", "\n".join(nginx.evidence))
        self.assertEqual(nginx.weirdness_score, 0)
        self.assertFalse(nginx.container_unowned)

    def test_container_unowned_binary(self):
        root = self.container(501, "/app/miner", comm="miner")
        make_apt_pkg(root, "nginx", ["/usr/sbin/nginx"])
        make_stub_file(root, "/app/miner")
        procs, code = self.scan()
        miner = procs[501]
        self.assertTrue(miner.is_container)
        self.assertEqual(miner.trust_level, self.weird.TrustLevel.UNKNOWN)
        self.assertEqual(miner.provenance.ownership, "unowned")
        self.assertIn("container_unowned", miner.signal_keys, miner.reasons)
        reason = next(r for r in miner.reasons if "container" in r.lower())
        self.assertIn("not part of container image", reason.lower())
        self.assertIn("(+20)", reason)
        self.assertIn("T1036", miner.attack)
        self.assertGreaterEqual(miner.weirdness_score, 20)
        self.assertEqual(code, 1)

    def test_unowned_score_is_policy_driven(self):
        self.assertEqual(self.weird.load_policy()["scores"]["container_unowned"], 20)
        self.assertEqual(self.weird.SIGNAL_ATTACK["container_unowned"], "T1036")

    def test_binary_missing_from_root_is_unavailable(self):
        self.container(503, "/usr/sbin/nginx")
        procs, _ = self.scan()
        p = procs[503]
        self.assertEqual(p.trust_level, self.weird.TrustLevel.CONTAINER)
        self.assertIn("container provenance unavailable", "\n".join(p.evidence))
        self.assertEqual(p.weirdness_score, 0)


class LanguagePackages(ContainerBox):
    """pip and npm leave their own metadata in the image; that is provenance, not a dropped binary."""

    def pip_console_script(self, root, name="chroma", shebang="#!/usr/local/bin/python3.11\n"):
        site = root / "usr/local/lib/python3.11/site-packages"
        _write(site / "chromadb-0.5.0.dist-info/RECORD",
               "chromadb/__init__.py,sha256=abc,10\n"
               f"../../../bin/{name},sha256=def,200\n"
               "chromadb-0.5.0.dist-info/INSTALLER,,\n")
        _write(site / "chromadb/__init__.py", "")
        make_stub_file(root, "/usr/local/bin/python3.11")
        make_stub_file(root, f"/usr/local/bin/{name}", (shebang + "import chromadb\n").encode())

    def test_pip_console_script_is_container_with_pip_evidence(self):
        root = self.container(504, "/usr/local/bin/chroma", comm="chroma")
        make_apt_pkg(root, "nginx", ["/usr/sbin/nginx"])
        self.pip_console_script(root)
        procs, code = self.scan()
        chroma = procs[504]
        self.assertTrue(chroma.is_container)
        self.assertEqual(chroma.trust_level, self.weird.TrustLevel.CONTAINER)
        self.assertIn("/usr/local/bin/chroma installed in image by pip (chromadb 0.5.0)", chroma.evidence)
        self.assertEqual((chroma.provenance.ownership, chroma.provenance.manager, chroma.provenance.package),
                         ("owned", "pip", "chromadb"))
        self.assertFalse(chroma.container_unowned)
        self.assertNotIn("container_unowned", chroma.signal_keys)
        self.assertEqual(chroma.weirdness_score, 0)
        self.assertEqual(code, 0)

    def test_pip_module_file_is_container(self):
        root = self.container(505, "/usr/local/lib/python3.11/site-packages/chromadb/__init__.py", comm="python3")
        self.pip_console_script(root)
        procs, _ = self.scan()
        self.assertEqual(procs[505].trust_level, self.weird.TrustLevel.CONTAINER)
        self.assertIn("installed in image by pip", "\n".join(procs[505].evidence))

    def test_record_hit_without_python_shebang_stays_unowned(self):
        root = self.container(506, "/usr/local/bin/chroma", comm="chroma")
        self.pip_console_script(root, shebang="#!/bin/sh\n")
        procs, _ = self.scan()
        self.assertTrue(procs[506].container_unowned)
        self.assertIn("container_unowned", procs[506].signal_keys)

    def test_npm_global_package_and_its_bin_symlink(self):
        root = self.container(507, "/usr/local/lib/node_modules/svc/bin/cli.js", comm="node")
        pkg = root / "usr/local/lib/node_modules/svc"
        _write(pkg / "package.json", '{"name": "svc", "version": "2.1.0", "bin": {"svc": "bin/cli.js"}}')
        _write(pkg / "bin/cli.js", "#!/usr/bin/env node\n")
        (root / "usr/local/bin").mkdir(parents=True, exist_ok=True)
        os.symlink("../lib/node_modules/svc/bin/cli.js", root / "usr/local/bin/svc")
        make_proc(self.proc, 508, "/usr/local/bin/svc", comm="node", cgroup=DOCKER_CGROUP)
        os.symlink(root, self.proc / "508" / "root")
        procs, _ = self.scan()
        for pid in (507, 508):
            self.assertEqual(procs[pid].trust_level, self.weird.TrustLevel.CONTAINER, procs[pid].evidence)
            self.assertIn("installed in image by npm (svc 2.1.0)", "\n".join(procs[pid].evidence))
            self.assertEqual(procs[pid].weirdness_score, 0)

    def test_index_is_cached_per_root(self):
        root = self.container(509, "/usr/local/bin/chroma", comm="chroma")
        self.pip_console_script(root)
        with mock.patch.object(self.weird.glob, "glob", wraps=self.weird.glob.glob) as spy:
            first = self.weird.image_language_index(str(root))
            second = self.weird.image_language_index(str(root))
        self.assertIs(first, second)
        self.assertEqual(spy.call_count, len(self.weird.IMAGE_SITE_PACKAGES_GLOBS) + 1 + len(self.weird.IMAGE_NODE_MODULES_GLOBS))


@unittest.skipIf(os.geteuid() == 0, "root can read every directory")
class UnreadableRoot(ContainerBox):
    def test_container_root_unreadable(self):
        root = self.container(502, "/usr/sbin/nginx", marker=False)
        make_apt_pkg(root, "nginx", ["/usr/sbin/nginx"])
        # second container signal that does not need the root: a pid namespace that differs from pid 1
        for pid, ns in ((1, "pid:[4026531836]"), (502, "pid:[4026532999]")):
            link = self.proc / str(pid) / "ns" / "pid"
            link.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(ns, link)
        root.chmod(0o000)
        self.addCleanup(root.chmod, 0o755)
        procs, _ = self.scan()
        p = procs[502]
        self.assertTrue(p.is_container)
        self.assertEqual(p.trust_level, self.weird.TrustLevel.CONTAINER)
        self.assertIn("container provenance unavailable", "\n".join(p.evidence))
        self.assertNotIn("container_unowned", p.signal_keys)
        self.assertEqual(p.weirdness_score, 0)
        self.assertEqual(p.provenance.ownership, "unknown")


class HostAfterContainer(ContainerBox):
    def test_host_process_resolves_after_container_scan(self):
        root = self.container(500, "/usr/sbin/nginx")
        make_apt_pkg(root, "nginx", ["/usr/sbin/nginx"])
        root2 = self.container(501, "/app/miner", comm="miner")
        make_stub_file(root2, "/app/miner")
        procs, _ = self.scan()
        bash = procs[100]
        self.assertEqual(bash.trust_level, self.weird.TrustLevel.OFFICIAL_REPO)
        self.assertEqual(bash.package, "bash")
        self.assertEqual(self.weird.SYSROOT, str(self.sysroot))
        self.assertTrue(self.weird.file_package_cache.persist)
        self.assertEqual(self.weird.file_package_cache.get("/usr/bin/bash"), "bash")
        self.assertIsNone(self.weird.file_package_cache.get("/usr/sbin/nginx"))
        level, info = self.weird.verify_package_provenance("/usr/bin/bash")
        self.assertEqual((level, info.package), (self.weird.TrustLevel.OFFICIAL_REPO, "bash"))
        level, info = self.weird.verify_package_provenance("/usr/sbin/nginx")
        self.assertNotEqual(info.ownership, "owned")
        self.assertEqual(level, self.weird.TrustLevel.UNKNOWN)

    def test_override_restores_on_error_and_shares_cache_per_root(self):
        w = self.weird
        root = self.container(500, "/usr/sbin/nginx")
        make_apt_pkg(root, "nginx", ["/usr/sbin/nginx"])
        host_cache = w.file_package_cache
        with self.assertRaises(RuntimeError):
            with w.sysroot_override(str(root)):
                w.file_package_cache.build()
                self.assertFalse(w.file_package_cache.persist)
                self.assertEqual(w.SYSROOT, str(root))
                self.assertEqual(w.file_package_cache.get("/usr/sbin/nginx"), "nginx")
                first = w.file_package_cache
                raise RuntimeError("boom")
        self.assertEqual(w.SYSROOT, str(self.sysroot))
        self.assertIs(w.file_package_cache, host_cache)
        with w.sysroot_override(str(root)):
            self.assertIs(w.file_package_cache, first)


if __name__ == "__main__":
    unittest.main()



PODMAN_CGROUP = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/db.service/libpod-payload-c4a47815ff5e86d02b552adb5760b64a5c7d07b47221cc2e146d1b06523e4214"
CID = "c4a47815ff5e86d02b552adb5760b64a5c7d07b47221cc2e146d1b06523e4214"


class ImageLayerAttribution(ContainerBox):
    """An unowned container binary is judged by whether the image build or the running container put it there."""

    def podman(self, image_diff, container_diff):
        self.table[("podman", "inspect", "--format", "{{.Image}}", CID)] = "a221f3391b5e\n"
        self.table[("podman", "image", "diff", "a221f3391b5e")] = image_diff
        self.table[("podman", "diff", CID)] = container_diff

    def chroma(self, which):
        root = self.container(700, "/usr/local/bin/chroma", comm="chroma", cgroup=PODMAN_CGROUP)
        make_apt_pkg(root, "dumb-init", ["/usr/bin/dumb-init"])
        make_stub_file(root, "/usr/local/bin/chroma")
        with mock.patch.object(self.weird.shutil, "which", which):
            procs, code = self.scan()
        return procs[700], code

    def test_binary_placed_by_image_build_is_container(self):
        self.podman("A /usr/local/bin/chroma\nA /config.yaml\n", "A /data\nC /etc\n")
        proc, code = self.chroma(lambda name: "/usr/bin/podman" if name == "podman" else None)
        self.assertEqual(proc.trust_level, self.weird.TrustLevel.CONTAINER)
        self.assertFalse(proc.container_unowned)
        self.assertNotIn("container_unowned", proc.signal_keys)
        self.assertTrue(any("put there by the image build" in e for e in proc.evidence), proc.evidence)
        self.assertEqual(code, 0)

    def test_binary_added_at_runtime_stays_unowned(self):
        self.podman("A /config.yaml\n", "A /usr/local/bin/chroma\nA /data\n")
        proc, code = self.chroma(lambda name: "/usr/bin/podman" if name == "podman" else None)
        self.assertTrue(proc.container_unowned)
        self.assertIn("container_unowned", proc.signal_keys)
        self.assertTrue(any("added after the container started" in e for e in proc.evidence), proc.evidence)
        self.assertEqual(code, 1)

    def test_no_runtime_tool_keeps_old_verdict(self):
        proc, code = self.chroma(lambda name: None)
        self.assertTrue(proc.container_unowned)
        self.assertTrue(any("no package in the image owns it" in e for e in proc.evidence), proc.evidence)
        self.assertEqual(code, 1)
