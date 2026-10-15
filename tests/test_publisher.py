"""Publisher verification: discovery, the signed and hosted tiers, mismatch, caching, inheritance, the online switch."""
import hashlib
import http.server
import io
import json
import os
import re
import shutil
import ssl
import stat
import subprocess
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

from fixtures import make_proc, make_stub_file  # noqa: E402
from helpers import FakeRunCommand, fake_which, load_weird, sandbox_root, scan_args  # noqa: E402
from test_arch import ArchBox  # noqa: E402

GPG = shutil.which("gpg")
NAME = "demo"
PRODUCT = "demo-tool"
VERSION = "1.4.2"
MANIFEST = f"{PRODUCT}-releases/{VERSION}/manifest.json"
SUMS = f"{PRODUCT}-releases/{VERSION}/SHA256SUMS"


class Tty(io.StringIO):
    def isatty(self):
        return True


def plain(text):
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


class ToolPassThrough(FakeRunCommand):
    """gpg really runs; everything else answers from the table."""

    def __call__(self, cmd, timeout=10, check=True):
        if cmd[0] != "gpg":
            return super().__call__(cmd, timeout, check)
        self.calls.append(tuple(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return None if check and result.returncode else result.stdout


def gpg(home, *words):
    return subprocess.run(["gpg", "--homedir", str(home), "--batch", "--no-tty", "--pinentry-mode", "loopback",
                           "--passphrase", "", *words], check=True, capture_output=True).stdout


class FakePublisher:
    """An HTTPS server on localhost with a throwaway certificate and throwaway signing keys; counts requests."""

    def __init__(self, root: Path):
        self.root = root
        self.docroot = root / "www"
        self.docroot.mkdir(parents=True)
        self.requests = []
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(root / "key.pem"),
                        "-out", str(root / "cert.pem"), "-days", "1", "-subj", "/CN=localhost",
                        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], check=True, capture_output=True)
        publisher = self

        class Handler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                publisher.requests.append(self.path)
                super().do_GET()

        self.server = http.server.HTTPServer(("127.0.0.1", 0),
                                             lambda *a, **k: Handler(*a, directory=str(self.docroot), **k))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(root / "cert.pem"), str(root / "key.pem"))
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.client_context = ssl.create_default_context(cafile=str(root / "cert.pem"))
        self.gnupg = root / "gnupg"
        self.gnupg.mkdir()
        self.gnupg.chmod(0o700)
        self.keys = {}

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        subprocess.run(["gpgconf", "--homedir", str(self.gnupg), "--kill", "gpg-agent"], capture_output=True)

    @property
    def base(self):
        return f"https://localhost:{self.port}/{PRODUCT}-releases"

    def write(self, rel, data):
        target = self.docroot / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data if isinstance(data, bytes) else data.encode())
        return target

    def new_key(self, name):
        gpg(self.gnupg, "--quick-gen-key", f"{name} <{name}@example.org>", "default", "default", "never")
        listing = gpg(self.gnupg, "--with-colons", "--list-keys", f"{name}@example.org").decode()
        fingerprint = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
        self.keys[name] = fingerprint
        return fingerprint

    def publish_key(self, name, rel=f"keys/{PRODUCT}.asc"):
        self.write(rel, gpg(self.gnupg, "--armor", "--export", self.keys[name]))

    def sign(self, rel, name):
        target = self.docroot / rel
        gpg(self.gnupg, "--yes", "--local-user", self.keys[name], "--output", str(target) + ".sig",
            "--detach-sign", str(target))

    def manifest(self, sha256):
        self.write(MANIFEST, json.dumps({"version": VERSION,
                                         "platforms": {"linux-x64": {"checksum": sha256, "size": 1}}}))


class PublisherBox(ArchBox):
    """A fake publisher, and a fixture binary under the sandbox home that names it."""

    sandbox_dir = sandbox_root()

    def setUp(self):
        super().setUp()
        self.weird.run_command = ToolPassThrough(self.table)
        for patcher in (mock.patch("shutil.which", fake_which({"pacman", "gpg"} if GPG else {"pacman"})),
                        mock.patch.object(self.weird, "get_process_description", return_value=None)):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.publisher = FakePublisher(Path(self.tmp.name) / "publisher")
        self.addCleanup(self.publisher.close)
        self.weird.CAMPAIGNS_SSL_CONTEXT = self.publisher.client_context
        os.environ.pop("WEIRD_NO_PROMPT", None)
        self.exe = self.home / f".local/share/{NAME}/versions/{VERSION}"
        self.exe.parent.mkdir(parents=True)
        self.exe.write_text(f"#!/bin/sh\n# {self.publisher.base}\nexit 0\n")
        self.exe.chmod(0o755)
        make_proc(self.proc, 500, str(self.exe), comm=NAME)
        self.config = self.home / ".config/weird/config.toml"
        self.publishers = self.home / ".config/weird/publishers/localhost"

    def go_online(self):
        self.weird.set_config_value("online", True)

    def sha256(self):
        return hashlib.sha256(self.exe.read_bytes()).hexdigest()

    def scan(self, pid=500, **overrides):
        self.weird._online_state = {"decided": None, "note": ""}
        processes, alerts, code = self.weird.run_scan(scan_args(verbose=True, **overrides))
        return next(p for p in processes if p.pid == pid), alerts, code

    def change_bytes(self):
        with open(self.exe, "ab") as f:
            f.write(b"\n")
        st = self.exe.stat()
        os.utime(self.exe, ns=(st.st_atime_ns, st.st_mtime_ns + 10 ** 9))


class Discovery(PublisherBox):
    def test_path_and_strings_give_product_version_host(self):
        claim = self.weird.discover_publisher(str(self.exe))
        self.assertEqual(claim.product, PRODUCT)
        self.assertEqual(claim.products, [PRODUCT, NAME])
        self.assertEqual(claim.version, VERSION)
        self.assertEqual(claim.release_bases, [self.publisher.base])
        self.assertEqual(claim.hosts[0], "localhost")
        self.assertEqual(claim.repo, "")
        self.assertEqual(claim.install_root, str(self.exe.parent))
        self.assertEqual(claim.source, ["install path", "strings scan"])
        cached = json.loads((self.home / ".config/weird/claims.json").read_text())[str(self.exe)]
        self.assertEqual(cached["sha256"], "", "discovery alone never hashes")
        self.assertEqual(cached["claim"]["product"], PRODUCT)
        with mock.patch.object(self.weird, "scan_release_urls", side_effect=AssertionError("scanned again")):
            self.assertEqual(self.weird.discover_publisher(str(self.exe)), claim)

    def test_manifest_candidates_follow_the_conventions(self):
        urls = self.weird.manifest_candidates("https://dl.example/tool-releases", "2.0")
        self.assertEqual(urls[:2], ["https://dl.example/tool-releases/2.0/manifest.json",
                                    "https://dl.example/tool-releases/2.0/SHA256SUMS"])
        self.assertEqual(urls[-2:], ["https://dl.example/tool-releases/manifest.json",
                                     "https://dl.example/tool-releases/latest/manifest.json"])
        github = self.weird.github_candidates("owner/tool", "2.0", ["tool"])
        self.assertIn("https://github.com/owner/tool/releases/download/v2.0/SHA256SUMS", github)
        self.assertIn("https://github.com/owner/tool/releases/download/2.0/tool-2.0.sha256", github)
        self.assertEqual(self.weird.github_candidates("owner/tool", "", ["tool"]), [])
        keys = self.weird.key_candidates("https://dl.example/tool-releases/2.0/manifest.json",
                                         "https://dl.example/tool-releases", ["tool", "t"])
        self.assertEqual(keys[:2], ["https://dl.example/keys/tool.asc", "https://dl.example/keys/t.asc"])
        self.assertIn("https://dl.example/KEYS", keys)
        self.assertIn("https://dl.example/tool-releases/KEYS", keys)

    def test_release_bases_and_products_from_addresses(self):
        base = self.weird.release_base_of("https://downloads.claude.ai/claude-code-releases/2.1.296/manifest.json")
        self.assertEqual(base, "https://downloads.claude.ai/claude-code-releases")
        self.assertEqual(self.weird.products_from_base(base), ["claude-code"])
        self.assertEqual(self.weird.release_base_of("https://claude.com/downloadANTHROPIC_AUTH_TOKEN"),
                         "https://claude.com/download")
        self.assertEqual(self.weird.release_base_of("https://releases.astral.sh"), "https://releases.astral.sh")
        self.assertEqual(self.weird.path_claim(f"{self.home}/.local/share/claude/versions/2.1.296"),
                         (["claude"], "2.1.296", f"{self.home}/.local/share/claude/versions"))
        self.assertEqual(self.weird.path_claim("/opt/thing/3.2.1/bin/thing"), (["thing"], "3.2.1", "/opt/thing/3.2.1"))
        self.assertEqual(self.weird.path_claim("/usr/bin/python3.13"), ([], "", ""))
        self.assertFalse(self.weird.hostname_ok("s3."))
        self.assertFalse(self.weird.hostname_ok("registry.npmjs.orgdarwinaarch64-musl-baselinev1.v0."))
        self.assertTrue(self.weird.hostname_ok("downloads.claude.ai"))


@unittest.skipUnless(GPG, "gpg not installed")
class SignedTier(PublisherBox):
    def setUp(self):
        super().setUp()
        self.fingerprint = self.publisher.new_key("release")
        self.publisher.publish_key("release")
        self.publisher.manifest(self.sha256())
        self.publisher.sign(MANIFEST, "release")
        self.go_online()

    def test_signed_manifest_with_matching_hash(self):
        proc, alerts, code = self.scan()
        self.assertEqual(proc.trust_level, self.weird.TrustLevel.PUBLISHER_SIGNED, proc.evidence)
        short = self.fingerprint[-8:]
        self.assertIn(f"verified: localhost, {PRODUCT} {VERSION}, signature by key {short}", proc.evidence)
        self.assertEqual((proc.weirdness_score, alerts, code), (0, [], 0))
        self.assertEqual(self.weird.verdict_for(proc), "")
        self.assertEqual((proc.publisher.tier, proc.publisher.key_fingerprint), ("signed", self.fingerprint))
        self.assertEqual(self.weird.verified_sentence(),
                         f"Verified with their publishers: {PRODUCT} {VERSION} (signed release list at localhost).")
        trust = json.loads((self.publishers / "trust.json").read_text())
        self.assertEqual((trust["fingerprints"], trust["products"]), ([self.fingerprint], [PRODUCT]))
        self.assertEqual(stat.S_IMODE((self.publishers / "gnupg").stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.publishers / "trust.json").stat().st_mode), 0o600)
        self.assertEqual(json.loads((self.publishers / "verified.json").read_text())[self.sha256()]["tier"], "signed")
        for path in (f"/{MANIFEST}", f"/{MANIFEST}.sig", f"/keys/{PRODUCT}.asc"):
            self.assertIn(path, self.publisher.requests)
        self.assertIn("checks out: it matches its publisher's signed release list", " ".join(plain(self.weird.format_process_detail(proc)).split()))
        self.assertIn(f"That list is signed by the key ending {short}", " ".join(plain(self.weird.format_process_detail(proc)).split()))
        self.assertIn("trust PUBLISHER_SIGNED", self.weird.process_details(proc))
        self.assertEqual(self.weird.process_to_dict(proc)["publisher"]["tier"], "signed")
        self.assertNotIn(str(self.home), self.weird.process_to_dict(proc)["publisher"]["manifest_url"])

    def test_same_bytes_are_never_verified_twice(self):
        self.scan()
        self.publisher.requests.clear()
        with mock.patch.object(self.weird, "download_url", side_effect=AssertionError("network used")):
            proc, _, code = self.scan()
        self.assertEqual(proc.trust_level, self.weird.TrustLevel.PUBLISHER_SIGNED)
        self.assertEqual((self.publisher.requests, code), ([], 0))

    def test_tampered_file_is_a_mismatch(self):
        self.change_bytes()
        proc, alerts, code = self.scan()
        self.assertIn("publisher_mismatch", proc.signal_keys)
        self.assertGreaterEqual(proc.weirdness_score, 60)
        self.assertEqual(self.weird.verdict_for(proc), "Likely malicious")
        self.assertIn("T1554", proc.attack)
        self.assertEqual((code, alerts[0]["severity"]), (2, "critical"))
        self.assertIn("sha256 is not in the publisher's list", " ".join(proc.reasons))
        self.assertEqual(proc.trust_level, self.weird.TrustLevel.UNKNOWN)
        detail = plain(self.weird.format_process_detail(proc))
        flat = " ".join(detail.split())
        self.assertIn("It does not match its publisher's release list", flat)
        self.assertIn(f"The list is at {self.publisher.base}/{VERSION}/manifest.json.", flat)
        self.assertEqual(self.weird.verified_sentence(), "")

    def test_a_rewrite_keeping_size_and_mtime_is_hashed_again(self):
        self.scan()
        self.assertTrue(json.loads((self.home / ".config/weird/claims.json").read_text())[str(self.exe)]["sha256"])
        st = self.exe.stat()
        self.exe.write_bytes(self.exe.read_bytes().replace(b"exit 0", b"exit 1"))
        os.utime(self.exe, ns=(st.st_atime_ns, st.st_mtime_ns))
        self.assertEqual((self.exe.stat().st_size, self.exe.stat().st_mtime_ns), (st.st_size, st.st_mtime_ns))
        proc, alerts, code = self.scan()
        self.assertIn("publisher_mismatch", proc.signal_keys)
        self.assertEqual(code, 2)

    def test_new_key_from_the_same_host_is_accepted_with_one_medium(self):
        self.scan()
        rotated = self.publisher.new_key("rotated")
        self.publisher.publish_key("rotated")
        self.change_bytes()
        self.publisher.manifest(self.sha256())
        self.publisher.sign(MANIFEST, "rotated")
        proc, alerts, code = self.scan()
        self.assertEqual(proc.trust_level, self.weird.TrustLevel.PUBLISHER_SIGNED, proc.evidence)
        self.assertIn("publisher_key_changed", proc.signal_keys)
        self.assertIn(f"publisher key changed for localhost: now {rotated[-8:]}", " ".join(proc.reasons))
        self.assertEqual((proc.weirdness_score, code, alerts[0]["severity"]), (20, 1, "warning"))
        trust = json.loads((self.publishers / "trust.json").read_text())
        self.assertEqual(trust["fingerprints"], [self.fingerprint, rotated])
        proc, alerts, code = self.scan()
        self.assertNotIn("publisher_key_changed", proc.signal_keys)
        self.assertEqual((proc.trust_level, code), (self.weird.TrustLevel.PUBLISHER_SIGNED, 0))

    def test_garbage_signature_is_a_mismatch(self):
        self.publisher.write(MANIFEST + ".sig", b"not a signature")
        proc, _, code = self.scan()
        self.assertIn("publisher_mismatch", proc.signal_keys)
        self.assertIn("does not verify under the keys published at localhost", " ".join(proc.reasons))
        self.assertEqual(code, 2)

    def test_key_only_on_the_keyserver_still_verifies(self):
        self.publisher.publish_key("release", rel="vks/v1/by-keyid/" + self.fingerprint[-16:])
        (self.publisher.docroot / f"keys/{PRODUCT}.asc").unlink()
        real = self.weird.download_url

        def via_fake_keyserver(url, max_bytes, timeout, host=None):
            if host == "keys.openpgp.org":
                url = url.replace("https://keys.openpgp.org", f"https://localhost:{self.publisher.port}")
                host = "localhost"
            return real(url, max_bytes, timeout, host)

        with mock.patch.object(self.weird, "download_url", via_fake_keyserver):
            proc, _, code = self.scan()
        self.assertEqual(proc.trust_level, self.weird.TrustLevel.PUBLISHER_SIGNED, proc.evidence)
        self.assertIn("key fetched from keys.openpgp.org", proc.publisher.detail)
        self.assertIn(f"/vks/v1/by-keyid/{self.fingerprint[-16:]}", self.publisher.requests)


class HostedTier(PublisherBox):
    def test_unsigned_checksum_list_over_tls(self):
        self.go_online()
        self.publisher.write(SUMS, f"{self.sha256()}  {PRODUCT}-linux-x64\n")
        proc, alerts, code = self.scan()
        self.assertEqual(proc.trust_level, self.weird.TrustLevel.PUBLISHER_HOSTED, proc.evidence)
        self.assertIn("verified over TLS from localhost (unsigned checksum)", proc.evidence)
        self.assertEqual(self.weird.verified_sentence(),
                         f"Verified with their publishers: {PRODUCT} {VERSION} (checksum list at localhost).")
        self.assertEqual((proc.weirdness_score, alerts, code), (0, [], 0))
        self.assertIn("checks out: it matches its publisher's checksum list", " ".join(plain(self.weird.format_process_detail(proc)).split()))
        self.assertIn("Nobody signed that list", " ".join(plain(self.weird.format_process_detail(proc)).split()))

    def test_archive_only_checksums_leave_the_file_unverifiable(self):
        self.go_online()
        self.publisher.write(SUMS, f"{'0' * 64}  {PRODUCT}-{VERSION}-linux-x64.tar.gz\n"
                                   f"{'1' * 64}  {PRODUCT}-{VERSION}-darwin-arm64.zip\n")
        proc, _, code = self.scan()
        self.assertEqual((proc.trust_level, proc.weirdness_score, code), (self.weird.TrustLevel.UNKNOWN, 0, 0))
        self.assertEqual(proc.publisher.tier, "unverifiable")
        self.assertIn("cover release archives, not the installed file", " ".join(proc.evidence))

    def test_versioned_list_without_the_hash_is_a_mismatch(self):
        self.go_online()
        self.publisher.write(SUMS, f"{'0' * 64}  {PRODUCT}-linux-x64\n")
        proc, _, code = self.scan()
        self.assertIn("publisher_mismatch", proc.signal_keys)
        self.assertEqual(code, 2)

    def test_nothing_published_is_unverifiable_and_the_misses_are_remembered(self):
        self.go_online()
        proc, alerts, code = self.scan()
        self.assertEqual((proc.trust_level, proc.weirdness_score, alerts, code), (self.weird.TrustLevel.UNKNOWN, 0, [], 0))
        self.assertEqual(proc.publisher.tier, "unverifiable")
        self.assertIn("no publisher proof found (tried 6 locations at localhost)", proc.evidence)
        self.assertIn("Its publisher posts no checksum for it: weird tried 6 addresses at localhost.", " ".join(plain(self.weird.format_process_detail(proc)).split()))
        self.assertEqual(len(json.loads((self.publishers / "misses.json").read_text())), 6)
        self.assertEqual(len(self.publisher.requests), 6)
        self.publisher.requests.clear()
        proc, _, _ = self.scan()
        self.assertEqual(self.publisher.requests, [])
        self.assertIn("tried 6 locations", " ".join(proc.evidence))

    def test_offline_never_touches_the_network(self):
        self.publisher.manifest(self.sha256())
        with mock.patch.object(self.weird, "download_url", side_effect=AssertionError("network used")):
            for offline in ("", "/mnt/root", None):
                proc, _, code = self.scan(offline=offline) if offline is not None else self.scan()
                self.assertEqual((proc.publisher.tier, proc.trust_level, code),
                                 ("unverifiable", self.weird.TrustLevel.UNKNOWN, 0), offline)
                self.assertIn("offline", proc.publisher.detail)
            self.go_online()
            proc, _, _ = self.scan(offline="")
            self.assertEqual(proc.publisher.tier, "unverifiable")
            self.weird.set_config_value("online", False)
            proc, _, _ = self.scan()
            self.assertEqual(proc.publisher.tier, "unverifiable")
        self.assertEqual(self.publisher.requests, [])
        self.assertEqual(self.weird.online_note(), "")

    def test_network_budget_leaves_the_rest_pending(self):
        self.go_online()
        self.publisher.manifest(self.sha256())
        with mock.patch.object(self.weird, "PUBLISHER_BUDGET_SECONDS", 0):
            proc, _, code = self.scan()
        self.assertEqual((proc.publisher.tier, code), ("pending", 0))
        self.assertIn("verification pending", " ".join(proc.evidence))
        self.assertIn("Checking it against its publisher ran out of time this run", " ".join(plain(self.weird.format_process_detail(proc)).split()))
        self.assertEqual(self.publisher.requests, [])


class Inheritance(PublisherBox):
    @unittest.skipUnless(GPG, "gpg not installed")
    def test_a_verified_tier_is_never_inherited(self):
        self.publisher.new_key("release")
        self.publisher.publish_key("release")
        self.publisher.manifest(self.sha256())
        self.publisher.sign(MANIFEST, "release")
        self.go_online()
        helper = self.exe.parent / "helper"
        helper.write_text("#!/bin/sh\nexit 0\n")
        sibling = self.exe.parent / "1.4.3"
        sibling.write_text(f"#!/bin/sh\n# {self.publisher.base}\nexit 1\n")
        for pid, path in ((501, helper), (502, sibling)):
            path.chmod(0o755)
            make_proc(self.proc, pid, str(path), comm=path.name)
        self.weird._online_state = {"decided": None, "note": ""}
        processes, _, code = self.weird.run_scan(scan_args(verbose=True))
        by_pid = {p.pid: p for p in processes}
        self.assertEqual(by_pid[500].trust_level, self.weird.TrustLevel.PUBLISHER_SIGNED, by_pid[500].evidence)
        for pid in (501, 502):
            proc = by_pid[pid]
            self.assertEqual(proc.trust_level, self.weird.TrustLevel.UNKNOWN, proc.evidence)
            self.assertEqual((proc.publisher.tier, proc.publisher.inherited_from), ("unverifiable", ""))
        self.assertEqual(code, 0)

    def test_child_under_an_identified_root_inherits_the_claim(self):
        make_stub_file(self.sysroot, "/usr/local/bin/ollama")
        make_stub_file(self.sysroot, "/usr/local/lib/ollama/llama-server")
        self.table[("pacman", "-Qo", "/usr/local/lib/ollama/llama-server")] = None
        make_proc(self.proc, 600, "/usr/local/bin/ollama", comm="ollama")
        make_proc(self.proc, 601, "/usr/local/lib/ollama/llama-server", comm="llama-server")

        def buildinfo(path):
            return ("github.com/ollama/ollama", "v0.9.0", "go1.26.0") if path.endswith("/ollama") else None

        with mock.patch.object(self.weird, "go_binary_module", side_effect=buildinfo):
            processes, _, code = self.weird.run_scan(scan_args(verbose=True))
        lead = next(p for p in processes if p.pid == 600)
        child = next(p for p in processes if p.pid == 601)
        self.assertEqual(lead.trust_level, self.weird.TrustLevel.USER_PKG, lead.evidence)
        self.assertEqual(child.trust_level, self.weird.TrustLevel.USER_PKG, child.evidence)
        self.assertIn("inherits identified from /usr/local/lib/ollama", child.evidence)
        self.assertEqual(child.publisher.tier, "identified")
        self.assertEqual(child.provenance.package, "github.com/ollama/ollama")
        self.assertIn("go module github.com/ollama/ollama", child.cached_description)
        self.assertEqual(code, 0)
        self.assertEqual(self.weird.install_roots("/usr/local/bin/ollama", self.weird.discover_publisher(
            "/usr/local/bin/ollama", str(self.sysroot / "usr/local/bin/ollama")), lead.provenance),
            ["/usr/local/lib/ollama"])


class PersistenceTier(PublisherBox):
    """A unit's severity follows its target: verified is info, identified is low, the rest unchanged."""

    def setUp(self):
        super().setUp()
        self.table[("crontab", "-l")] = None

    def unit(self, name, target, text="#!/bin/sh\nexit 0\n", service=""):
        exe = self.sysroot / target.lstrip("/")
        exe.parent.mkdir(parents=True, exist_ok=True)
        exe.write_text(text)
        exe.chmod(0o755)
        self.table[("pacman", "-Qo", target)] = None
        unit = self.sysroot / f"etc/systemd/system/{name}.service"
        unit.parent.mkdir(parents=True, exist_ok=True)
        unit.write_text(f"[Service]\nExecStart={target}\n{service}")
        return exe

    def entry(self, name):
        found = [e for e in self.weird.collect_persistence() if e.file.endswith(f"/{name}.service")]
        self.assertEqual(len(found), 1, found)
        return found[0]

    @unittest.skipUnless(GPG, "gpg not installed")
    def test_unit_running_a_signed_binary_is_info(self):
        exe = self.unit(NAME, f"/opt/{NAME}/{VERSION}/bin/{NAME}", f"#!/bin/sh\n# {self.publisher.base}\nexit 0\n")
        self.publisher.new_key("release")
        self.publisher.publish_key("release")
        self.publisher.manifest(hashlib.sha256(exe.read_bytes()).hexdigest())
        self.publisher.sign(MANIFEST, "release")
        self.go_online()
        self.weird.online_allowed(scan_args())
        e = self.entry(NAME)
        self.assertEqual((e.trust, e.severity), ("PUBLISHER_SIGNED", "info"), e.provenance)
        self.assertIn(f"verified: {PRODUCT} {VERSION} from localhost", e.provenance)

    def test_unit_running_an_identified_binary_is_low(self):
        self.unit("ollama", "/usr/local/bin/ollama", service="Restart=always\nRestartSec=3\n")
        module = ("github.com/ollama/ollama", "v0.9.0", "go1.26.0")
        with mock.patch.object(self.weird, "go_binary_module", return_value=module):
            e = self.entry("ollama")
        self.assertEqual((e.trust, e.severity), ("USER_PKG", "low"), e.provenance)
        self.assertIn("identified by its package manager, no publisher proof", e.provenance)

    def test_unit_running_an_unverifiable_script_stays_medium(self):
        self.unit("fan-control", "/usr/local/sbin/fan-control.sh", service="Restart=always\nRestartSec=5\n")
        e = self.entry("fan-control")
        self.assertEqual((e.trust, e.severity), ("USER_LOCAL", "medium"), e.provenance)
        self.assertIn("restart loop keeps it alive", e.provenance)
        self.assertIn("system-wide persistence of unpackaged code", e.provenance)


class OnlineSwitch(PublisherBox):
    def ask(self, answer):
        asked = []

        def fake_input(question):
            asked.append(question)
            if answer is None:
                raise EOFError
            return answer

        self.weird._online_state = {"decided": None, "note": ""}
        with mock.patch.object(sys, "stdin", Tty()), mock.patch.object(sys, "stdout", Tty()), \
                mock.patch("builtins.input", fake_input):
            result = self.weird.online_allowed(scan_args())
        return result, asked

    def test_asked_once_enter_means_yes_and_the_answer_is_stored(self):
        result, asked = self.ask("")
        self.assertTrue(result)
        self.assertEqual(asked, ["weird can go online to check your software against publishers' signed lists "
                                 "and the known-bad AUR list. OK? [Y/n] "])
        self.assertEqual(self.config.read_text(), "online = true\n")
        self.assertEqual(self.weird.online_note(), "")
        again = load_weird(self.home, self.proc, self.sysroot)
        with mock.patch.object(sys, "stdin", Tty()), mock.patch.object(sys, "stdout", Tty()), \
                mock.patch("builtins.input", side_effect=AssertionError("asked twice")):
            self.assertTrue(again.online_allowed(scan_args()))
            self.assertTrue(again.online_allowed(scan_args(no_prompt=True)))

    def test_n_is_stored_as_no(self):
        result, asked = self.ask("n")
        self.assertFalse(result)
        self.assertEqual(len(asked), 1)
        self.assertEqual(self.config.read_text(), "online = false\n")
        self.assertEqual(self.weird.online_note(), "")
        self.assertIs(self.weird.config_value("online"), False)

    def test_eof_means_no_for_this_run_only(self):
        result, asked = self.ask(None)
        self.assertFalse(result)
        self.assertEqual(len(asked), 1)
        self.assertFalse(self.config.exists())
        self.assertEqual(self.weird.online_note(), self.weird.ONLINE_NOTE)

    def test_nobody_to_answer_means_offline_with_a_note(self):
        with mock.patch("builtins.input", side_effect=AssertionError("asked without a terminal")):
            self.assertFalse(self.weird.online_allowed(scan_args()))
        self.assertEqual(self.weird.online_note(), self.weird.ONLINE_NOTE)
        self.assertTrue(self.weird.ONLINE_NOTE.startswith("Online checks are off"))
        for overrides in ({"json": True}, {"ndjson": True}, {"no_prompt": True}, {"command": "watch"}):
            self.weird._online_state = {"decided": None, "note": ""}
            with mock.patch.object(sys, "stdin", Tty()), mock.patch.object(sys, "stdout", Tty()), \
                    mock.patch("builtins.input", side_effect=AssertionError("asked")):
                self.assertFalse(self.weird.online_allowed(scan_args(**overrides)), overrides)
        os.environ["WEIRD_NO_PROMPT"] = "1"
        try:
            self.weird._online_state = {"decided": None, "note": ""}
            with mock.patch.object(sys, "stdin", Tty()), mock.patch.object(sys, "stdout", Tty()), \
                    mock.patch("builtins.input", side_effect=AssertionError("asked")):
                self.assertFalse(self.weird.online_allowed(scan_args()))
        finally:
            del os.environ["WEIRD_NO_PROMPT"]
        self.assertFalse(self.config.exists())

    def test_offline_flag_beats_a_stored_yes(self):
        self.go_online()
        self.assertFalse(self.weird.online_allowed(scan_args(offline="")))
        self.assertFalse(self.weird.online_allowed(scan_args(offline="/mnt/root")))
        self.assertTrue(self.weird.online_allowed(scan_args()))
        self.assertEqual(self.weird.online_note(), "")

    def test_offline_flag_parses_alone_or_with_a_sysroot(self):
        parser = self.weird.build_parser()
        self.assertIsNone(parser.parse_args([]).offline)
        self.assertEqual(parser.parse_args(["--offline"]).offline, "")
        self.assertEqual(parser.parse_args(["--offline", "--skip", "hidden"]).offline, "")
        self.assertEqual(parser.parse_args(["--offline", "/mnt/root"]).offline, "/mnt/root")
        self.assertEqual(self.weird.split_argv(["--offline", "trust", "/usr/bin/bash"]),
                         (["--offline"], "trust", ["/usr/bin/bash"]))
        self.assertEqual(self.weird.split_argv(["--offline", "/mnt/root"]), (["--offline", "/mnt/root"], None, []))
        self.assertEqual(self.weird.split_argv(["--offline", "--skip", "hidden"]), (["--offline", "--skip", "hidden"], None, []))
        dev = self.weird.dev_args(parser.parse_args(["--offline"]), ["scan"], self.weird.build_dev_parser())
        self.assertEqual(dev.offline, "")

    def test_config_keys_survive_the_stored_answer(self):
        self.config.parent.mkdir(parents=True, exist_ok=True)
        self.config.write_text("# mine\n[policy]\n[policy.scores]\nmasquerade = 45\n")
        self.weird.set_config_value("online", True)
        text = self.config.read_text()
        self.assertTrue(text.startswith("online = true\n"), text)
        self.assertIn("masquerade = 45", text)
        self.assertIs(self.weird.config_value("online"), True)
        self.assertEqual(self.weird.load_policy()["scores"]["masquerade"], 45)
        self.weird.set_config_value("online", False)
        self.assertEqual(self.config.read_text().count("online ="), 1)
        self.assertIs(self.weird.config_value("online"), False)


if __name__ == "__main__":
    unittest.main()
