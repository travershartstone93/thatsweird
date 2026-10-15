import contextlib
import hashlib
import io
import json
import os
import stat
import sys
import time
import unittest
from unittest import mock
import urllib.request
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from fixtures import make_pacman_pkg  # noqa: E402
from helpers import FakeRunCommand, scan_args  # noqa: E402
from test_arch import ArchBox  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "campaigns" / "campaigns.json"
INSTALLED = int(time.time()) - 100000


class CampaignBox(ArchBox):
    def setUp(self):
        super().setUp()
        self.table[("pacman", "-Qm")] = None
        self.weird.run_command = FakeRunCommand(self.table)
        os.environ.pop("WEIRD_NO_PROMPT", None)

    def foreign(self, name, installdate=INSTALLED):
        return make_pacman_pkg(self.sysroot, name, "1.0-1", [f"/usr/bin/{name}"], validation="none",
                               packager="Unknown Packager", installdate=installdate)

    def aur_json(self, **overrides):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = self.weird.cmd_aur(scan_args(json=True, **overrides))
        return json.loads(out.getvalue()), code

    def aur_text(self, **overrides):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = self.weird.cmd_aur(scan_args(**overrides))
        return out.getvalue(), code


class ParserTests(CampaignBox):
    def test_real_schema(self):
        campaigns, skipped = self.weird.parse_campaigns(FIXTURE)
        self.assertEqual(skipped, 0)
        by_id = {c.id: c for c in campaigns}
        self.assertEqual(sorted(by_id), ["aur-infected", "chaos-rat", "russian-spam"])
        infected = by_id["aur-infected"]
        self.assertEqual(infected.label, "AUR malware packages (June 2026)")
        self.assertEqual((infected.start, infected.end), ("2026-06-09", "2026-06-14"))
        self.assertIn("123pan-bin", infected.packages)
        self.assertIn("rakudo-star", infected.packages)  # from the second list file
        self.assertEqual(len(by_id["chaos-rat"].packages), 7)
        self.assertEqual((by_id["russian-spam"].start, by_id["russian-spam"].end), ("", ""))
        self.assertFalse(any(n.startswith("#") or " " in n for c in campaigns for n in c.packages))
        self.assertEqual(set(vars(infected)), {"id", "label", "start", "end", "packages"})
        self.assertEqual(self.weird.load_campaigns(FIXTURE), campaigns)

    def test_malformed_entries_skipped(self):
        path = self.home / "campaigns.json"
        (self.home / "lists").mkdir(parents=True)
        (self.home / "lists" / "good.txt").write_text("alpha\nbeta # note\n\n# comment\n")
        path.write_text(json.dumps({"campaigns": [
            {"id": "good", "display": "Good", "lists": ["lists/good.txt"], "date_window": {"start": "2026-01-01", "end": "x"},
             "ioc_files": [{"path": "~/.local/bin/sudo"}], "refresh_url": "https://example.org"},
            {"display": "no id", "lists": ["lists/good.txt"]},
            {"id": "escape", "lists": ["../outside.txt"]},
            {"id": "missing", "lists": ["lists/none.txt"]},
            {"id": "inline", "packages": ["gamma", "bad name", 7, "delta"]},
            "not a dict",
        ]}))
        campaigns, skipped = self.weird.parse_campaigns(path)
        self.assertEqual([c.id for c in campaigns], ["good", "inline"])
        self.assertEqual(campaigns[0].packages, {"alpha", "beta"})
        self.assertEqual((campaigns[0].start, campaigns[0].end), ("2026-01-01", ""))
        self.assertEqual(campaigns[1].packages, {"gamma", "delta"})
        self.assertEqual(skipped, 4)

    def test_unreadable_file(self):
        self.assertEqual(self.weird.parse_campaigns(self.home / "nope.json"), ([], 1))
        bad = self.home / "bad.json"
        bad.write_text("{not json")
        self.assertEqual(self.weird.parse_campaigns(bad), ([], 1))


class MatchTests(CampaignBox):
    def test_installed_package_flagged(self):
        self.foreign("123pan-bin")
        payload, code = self.aur_json(campaigns=str(FIXTURE))
        hits = [f for f in payload["findings"] if f["kind"] == "known-bad package"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "critical")
        self.assertEqual(hits[0]["attack"], "T1195.002")
        self.assertEqual(hits[0]["subject"], "123pan-bin")
        self.assertIn("installed package 123pan-bin is on the AUR malware packages (June 2026) compromised list",
                      hits[0]["detail"])
        self.assertIn("window 2026-06-09 to 2026-06-14", hits[0]["detail"])
        self.assertIn("installed " + time.strftime("%Y-%m-%d", time.localtime(INSTALLED)), hits[0]["detail"])
        self.assertEqual(code, self.weird.findings_exit_code([self.weird.Finding("x", "y", "critical")]))
        self.assertTrue(payload["known_bad_list"].startswith("3 campaigns, "))
        self.assertIn(hits[0], payload["packages"][0]["findings"])

    def test_helper_cache_only_is_info(self):
        self.foreign("harmless")
        (self.home / ".cache" / "paru" / "clone" / "minecraft-cracked").mkdir(parents=True)
        (self.home / ".cache" / "yay" / "123pan-bin").mkdir(parents=True)
        payload, code = self.aur_json(campaigns=str(FIXTURE))
        built = {f["subject"]: f for f in payload["findings"] if f["kind"] == "known-bad package built"}
        self.assertEqual(sorted(built), ["123pan-bin", "minecraft-cracked"])
        self.assertEqual(built["minecraft-cracked"]["severity"], "info")
        self.assertIn("campaign package minecraft-cracked was built on this machine but is not installed",
                      built["minecraft-cracked"]["detail"])
        self.assertFalse([f for f in payload["findings"] if f["kind"] == "known-bad package"])
        self.assertEqual(code, 0)
        text, _ = self.aur_text(campaigns=str(FIXTURE))
        self.assertIn("1 installed, none on the known-bad list.", " ".join(text.split()))

    def test_no_list_available(self):
        self.foreign("harmless")
        payload, code = self.aur_json()
        self.assertEqual(payload["known_bad_list"],
                         "not available (fetched when online checks are enabled, or pass --campaigns PATH)")
        self.assertFalse([f for f in payload["findings"] if f["kind"].startswith("known-bad")])
        self.assertEqual(code, 0)
        text, _ = self.aur_text()
        self.assertIn("The known-bad list is not available, so their names were not checked against it.", " ".join(text.split()))


class OnlinePolicyTests(CampaignBox):
    """The list is refreshed without a question when weird may go online, and never otherwise."""

    def refresh(self, online, **overrides):
        fetched = []

        def fetch():
            fetched.append(True)
            return self.weird.CAMPAIGNS_FILE

        with mock.patch.object(self.weird, "online_allowed", return_value=online), \
                mock.patch("builtins.input", side_effect=AssertionError("a question was asked")):
            result = self.weird.maybe_offer_campaign_update(scan_args(**overrides), fetch=fetch)
        return result, fetched

    def cache(self, age_days):
        self.weird.CAMPAIGNS_DIR.mkdir(parents=True)
        self.weird.CAMPAIGNS_FILE.write_text(FIXTURE.read_text())
        self.weird.write_private_json(self.weird.CAMPAIGNS_META, {"fetched_at": int(time.time()) - age_days * 86400})

    def test_missing_list_is_fetched_when_online(self):
        self.assertEqual(self.refresh(True), (self.weird.CAMPAIGNS_FILE, [True]))

    def test_stale_list_is_refreshed_when_online(self):
        self.cache(age_days=9)
        self.assertEqual(self.refresh(True), (self.weird.CAMPAIGNS_FILE, [True]))

    def test_fresh_list_is_kept(self):
        self.cache(age_days=2)
        self.assertEqual(self.refresh(True), (self.weird.CAMPAIGNS_FILE, []))

    def test_offline_never_fetches(self):
        self.assertEqual(self.refresh(False), (None, []))
        self.cache(age_days=30)
        self.assertEqual(self.refresh(False), (self.weird.CAMPAIGNS_FILE, []))

    def test_campaigns_path_used_as_it_is(self):
        self.assertEqual(self.refresh(True, campaigns=str(FIXTURE)), (FIXTURE, []))

    def test_fetch_campaigns_flag_fetches_even_offline(self):
        self.assertEqual(self.refresh(False, fetch_campaigns=True), (self.weird.CAMPAIGNS_FILE, [True]))

    def test_no_terminal_means_offline_with_a_note(self):
        fetched = []
        with mock.patch.object(sys, "stdin", io.StringIO()), \
                mock.patch("builtins.input", side_effect=AssertionError("asked without a terminal")):
            result = self.weird.maybe_offer_campaign_update(scan_args(), fetch=lambda: fetched.append(True))
        self.assertEqual((result, fetched), (None, []))
        self.assertEqual(self.weird.online_note(), self.weird.ONLINE_NOTE)

    def test_fetch_failure_warns_and_continues(self):
        self.foreign("harmless")

        def failing(*a, **k):
            raise self.weird.CampaignFetchError("no route to host")

        with mock.patch.object(self.weird, "fetch_campaigns", failing):
            text, code = self.aur_text(fetch_campaigns=True)
        self.assertIn("known-bad list not fetched: no route to host", text)
        self.assertIn("The known-bad list is not available", " ".join(text.split()))
        self.assertEqual(code, 0)
        self.assertFalse(self.weird.CAMPAIGNS_FILE.exists())


class FetchTests(CampaignBox):
    def downloader(self, sizes=None):
        calls = []

        def download(url):
            calls.append(url)
            base = "https://raw.githubusercontent.com/lenucksi/aur-malware-check/master/"
            self.assertTrue(url.startswith(base), url)
            rel = url[len(base):]
            if rel == "data/campaigns.json":
                return FIXTURE.read_bytes()
            if sizes and rel in sizes:
                return b"x" * sizes[rel]
            return (FIXTURE.parent / rel).read_bytes()
        return download, calls

    def test_saves_private_files_and_meta(self):
        download, calls = self.downloader()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            path = self.weird.fetch_campaigns(download=download)
        self.assertEqual(path, self.weird.CAMPAIGNS_FILE)
        self.assertEqual(calls[0], self.weird.CAMPAIGNS_URL)
        self.assertEqual(len(calls), 5)
        for saved in (path, self.weird.CAMPAIGNS_META,
                      self.weird.CAMPAIGNS_DIR / "data/campaigns/aur-infected/packages.txt"):
            self.assertEqual(stat.S_IMODE(saved.stat().st_mode), 0o600, saved)
        meta = json.loads(self.weird.CAMPAIGNS_META.read_text())
        raw = FIXTURE.read_bytes()
        self.assertEqual(meta["sha256"], hashlib.sha256(raw).hexdigest())
        expected = len(raw) + sum((FIXTURE.parent / f).stat().st_size for f in meta["files"])
        self.assertEqual(meta["size"], expected)
        self.assertEqual(meta["newest_campaign_date"], "2026-06-14")
        self.assertEqual(meta["url"], self.weird.CAMPAIGNS_URL)
        self.assertGreater(meta["package_count"], 30)
        self.assertAlmostEqual(meta["fetched_at"], time.time(), delta=60)
        line = out.getvalue().strip()
        self.assertIn(f"{expected} bytes", line)
        self.assertIn(meta["sha256"], line)
        self.assertIn("newest campaign 2026-06-14", line)
        campaigns, meta_read = self.weird.campaigns_for_scan(path)
        self.assertRegex(self.weird.campaigns_status(campaigns, meta_read), r"^3 campaigns, \d+ packages, fetched \d{4}-\d{2}-\d{2}$")

    def test_size_cap(self):
        download, _ = self.downloader(sizes={"data/campaigns/aur-infected/packages.txt": 5 * 1024 * 1024})
        with self.assertRaises(self.weird.CampaignFetchError):
            self.weird.fetch_campaigns(download=download)
        self.assertFalse(self.weird.CAMPAIGNS_FILE.exists())
        with self.assertRaises(self.weird.CampaignFetchError):
            self.weird.fetch_campaigns(download=lambda url: b"x" * (5 * 1024 * 1024 + 1))

    def test_redirect_off_domain_refused(self):
        handler = self.weird.same_domain_redirect_handler()()
        req = urllib.request.Request(self.weird.CAMPAIGNS_URL)
        with self.assertRaises(self.weird.CampaignFetchError):
            handler.redirect_request(req, None, 302, "Found", {}, "https://evil.example/campaigns.json")
        with self.assertRaises(self.weird.CampaignFetchError):
            handler.redirect_request(req, None, 302, "Found", {}, "http://github.com/campaigns.json")
        moved = handler.redirect_request(req, None, 302, "Found", {}, "https://objects.githubusercontent.com/x")
        self.assertEqual(moved.full_url, "https://objects.githubusercontent.com/x")
        self.assertFalse(self.weird.campaigns_host_ok("https://github.com.evil.example/x"))
        with self.assertRaises(self.weird.CampaignFetchError):
            self.weird.download_url("https://example.org/campaigns.json")


if __name__ == "__main__":
    unittest.main()


class WholeRunFetchTests(CampaignBox):
    """The main command with --fetch-campaigns: a failed fetch must not turn into a question."""

    def test_failed_explicit_fetch_never_prompts(self):
        self.foreign("harmless")
        self.weird.set_config_value("online", True)
        asked = []

        def failing(*a, **k):
            raise self.weird.CampaignFetchError("network is unreachable")

        def fake_ask(question):
            asked.append(question)
            return "y"

        args = self.weird.build_parser().parse_args(
            ["--fetch-campaigns", "--no-baseline", "--skip", "hidden", "--skip", "processes",
             "--skip", "persist", "--skip", "kernel", "--skip", "stale"])
        out = io.StringIO()
        with mock.patch.object(self.weird, "fetch_campaigns", failing), \
                mock.patch.object(self.weird, "prompt_allowed", lambda a: True), \
                mock.patch("builtins.input", fake_ask), \
                contextlib.redirect_stdout(out):
            code = self.weird.cmd_all(args)
        text = out.getvalue()
        self.assertEqual(asked, [], text)
        self.assertEqual(text.count("known-bad list not fetched"), 1, text)
        self.assertIn("The known-bad list is not available", " ".join(text.split()))
        self.assertIn(code, (0, 1))


class AddressFallbackTests(unittest.TestCase):
    """A dead IPv6 route must not stop the fetch when IPv4 works (errno 101 on the author's laptop)."""

    def test_download_falls_through_dead_ipv6(self):
        import http.server
        import socket
        import ssl
        import subprocess
        import tempfile
        import threading
        sys.path.insert(0, os.path.dirname(__file__))
        from helpers import load_weird
        tmp = Path(tempfile.mkdtemp(prefix="weird-tls-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(tmp / "k.pem"),
                        "-out", str(tmp / "c.pem"), "-days", "1", "-subj", "/CN=localhost"],
                       check=True, capture_output=True)
        (tmp / "campaigns.json").write_text('{"campaigns": []}')

        class Quiet(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *a):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), lambda *a, **k: Quiet(*a, directory=str(tmp), **k))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(tmp / "c.pem"), str(tmp / "k.pem"))
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)

        weird = load_weird(tmp / "home")
        real = socket.getaddrinfo

        def dead_v6_first(host, *a, **k):
            if host == "github.com":
                return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:50c0:8000::154", port, 0, 0)),
                        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
            return real(host, *a, **k)

        client = ssl.create_default_context()
        client.check_hostname = False
        client.verify_mode = ssl.CERT_NONE
        with mock.patch.object(socket, "getaddrinfo", dead_v6_first), \
                mock.patch.object(weird, "CAMPAIGNS_SSL_CONTEXT", client):
            data = weird.download_url(f"https://github.com:{port}/campaigns.json")
        self.assertEqual(json.loads(data), {"campaigns": []})
