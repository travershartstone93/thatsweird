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


class Tty(io.StringIO):
    def isatty(self):
        return True


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
        self.assertIn("none of the 1 foreign packages is on any list", text)

    def test_no_list_available(self):
        self.foreign("harmless")
        payload, code = self.aur_json()
        self.assertEqual(payload["known_bad_list"], "not available (run interactively to fetch, or pass --campaigns PATH)")
        self.assertFalse([f for f in payload["findings"] if f["kind"].startswith("known-bad")])
        self.assertEqual(code, 0)
        text, _ = self.aur_text()
        self.assertIn("known-bad list: not available (run interactively to fetch, or pass --campaigns PATH)", text)


class PromptPolicyTests(CampaignBox):
    def offer(self, tty, answer=None, **overrides):
        asked, fetched = [], []

        def ask(question):
            asked.append(question)
            if answer is None:
                raise EOFError
            return answer

        def fetch():
            fetched.append(True)
            return self.weird.CAMPAIGNS_FILE

        stdin = Tty() if tty else io.StringIO()
        stdout = Tty() if tty else io.StringIO()
        with mock.patch.object(sys, "stdin", stdin), mock.patch.object(sys, "stdout", stdout):
            result = self.weird.maybe_offer_campaign_update(scan_args(**overrides), ask=ask, fetch=fetch)
        return result, asked, fetched, stdout.getvalue()

    def cache(self, age_days):
        self.weird.CAMPAIGNS_DIR.mkdir(parents=True)
        self.weird.CAMPAIGNS_FILE.write_text(FIXTURE.read_text())
        self.weird.write_private_json(self.weird.CAMPAIGNS_META, {"fetched_at": int(time.time()) - age_days * 86400})

    def test_no_tty_no_prompt(self):
        result, asked, fetched, _ = self.offer(tty=False)
        self.assertEqual((result, asked, fetched), (None, [], []))

    def test_json_no_prompt(self):
        for flag in ("json", "ndjson", "no_prompt", "watch"):
            result, asked, fetched, _ = self.offer(tty=True, **{flag: True})
            self.assertEqual((result, asked, fetched), (None, [], []), flag)
        result, asked, fetched, _ = self.offer(tty=True, command="watch")
        self.assertEqual((asked, fetched), ([], []))

    def test_env_no_prompt(self):
        os.environ["WEIRD_NO_PROMPT"] = "1"
        try:
            result, asked, fetched, _ = self.offer(tty=True)
        finally:
            del os.environ["WEIRD_NO_PROMPT"]
        self.assertEqual((result, asked, fetched), (None, [], []))

    def test_tty_missing_list_answer_no(self):
        for answer in ("n", "", None):
            result, asked, fetched, _ = self.offer(tty=True, answer=answer)
            self.assertEqual(len(asked), 1, answer)
            self.assertEqual(asked[0], "Known-bad AUR package list: not downloaded. Fetch it from "
                                       "github.com/lenucksi/aur-malware-check? [y/N] ")
            self.assertEqual((result, fetched), (None, []), answer)

    def test_tty_stale_list_answer_yes(self):
        self.cache(age_days=9)
        result, asked, fetched, _ = self.offer(tty=True, answer="y")
        self.assertEqual(asked, ["Known-bad AUR package list: last updated 9 days ago. Update it? [y/N] "])
        self.assertEqual(fetched, [True])
        self.assertEqual(result, self.weird.CAMPAIGNS_FILE)

    def test_tty_fresh_list_no_prompt(self):
        self.cache(age_days=2)
        result, asked, fetched, _ = self.offer(tty=True, answer="y")
        self.assertEqual((result, asked, fetched), (self.weird.CAMPAIGNS_FILE, [], []))

    def test_campaigns_path_used_without_prompt(self):
        result, asked, fetched, _ = self.offer(tty=True, answer="y", campaigns=str(FIXTURE))
        self.assertEqual((result, asked, fetched), (FIXTURE, [], []))

    def test_fetch_campaigns_flag(self):
        result, asked, fetched, _ = self.offer(tty=False, fetch_campaigns=True)
        self.assertEqual((result, asked, fetched), (self.weird.CAMPAIGNS_FILE, [], [True]))

    def test_fetch_failure_warns_and_continues(self):
        self.foreign("harmless")

        def failing(*a, **k):
            raise self.weird.CampaignFetchError("no route to host")

        with mock.patch.object(self.weird, "fetch_campaigns", failing):
            text, code = self.aur_text(fetch_campaigns=True)
        self.assertIn("known-bad list not fetched: no route to host", text)
        self.assertIn("known-bad list: not available", text)
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
        self.assertIn("known-bad list: not available", text)
        self.assertIn(code, (0, 1))
