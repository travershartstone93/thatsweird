import contextlib
import io
import json
import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

from fixtures import _write, make_pacman_pkg, make_stub_file  # noqa: E402
from helpers import scan_args  # noqa: E402
from test_arch import ARCH, ArchBox  # noqa: E402

RELEASE = "6.1.0-x"
NVIDIA_KO = f"/usr/lib/modules/{RELEASE}/kernel/drivers/video/nvidia.ko.zst"


class KernelBox(ArchBox):
    def setUp(self):
        super().setUp()
        self.table[("bpftool", "prog", "list")] = None
        patcher = mock.patch.object(self.weird, "running_kernel", return_value=RELEASE)
        patcher.start()
        self.addCleanup(patcher.stop)
        make_pacman_pkg(self.sysroot, "linux", "6.1.0-1",
                        [f"/usr/lib/modules/{RELEASE}/vmlinuz", f"/usr/lib/modules/{RELEASE}/pkgbase", NVIDIA_KO],
                        packager=ARCH)
        self.loaded(["nvidia"])
        self.taint(0)

    def loaded(self, names, sys_names=None, kallsyms_names=None):
        _write(self.proc / "modules", "".join(f"{n} 4096 0 - Live 0x0000000000000000\n" for n in names))
        for n in (names if sys_names is None else sys_names):
            _write(self.sysroot / "sys/module" / n / "coresize", "4096\n")
        _write(self.sysroot / "sys/module/printk/parameters/time", "N\n")
        lines = [f"0000000000000000 t {n}_init\t[{n}]\n" for n in (names if kallsyms_names is None else kallsyms_names)]
        lines.append("0000000000000000 t bpf_prog_1234\t[bpf]\n0000000000000000 T _stext\n")
        _write(self.proc / "kallsyms", "".join(lines))

    def taint(self, value):
        _write(self.proc / "sys/kernel/tainted", f"{value}\n")

    def kernel(self, **overrides):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = self.weird.cmd_kernel(scan_args(**overrides))
        return out.getvalue(), code

    def kernel_json(self):
        out, code = self.kernel(json=True)
        return json.loads(out), code

    def by_kind(self, payload, kind):
        return [f for f in payload["findings"] if f["kind"] == kind]


class Modules(KernelBox):
    def test_unowned_module_flagged(self):
        make_stub_file(self.sysroot, f"/usr/lib/modules/{RELEASE}/extra/evil_mod.ko")
        self.loaded(["nvidia", "evil_mod"])
        self.taint(4096)
        payload, code = self.kernel_json()
        self.assertEqual(code, 2)
        hit = self.by_kind(payload, "unowned module")
        self.assertEqual(len(hit), 1, payload["findings"])
        self.assertEqual((hit[0]["severity"], hit[0]["attack"], hit[0]["subject"]), ("critical", "T1014", "evil_mod"))
        self.assertIn(f"/usr/lib/modules/{RELEASE}/extra/evil_mod.ko is not owned by any package", hit[0]["detail"])
        self.assertEqual(payload["modules"]["unowned"], ["evil_mod"])
        self.assertEqual(payload["modules"]["owned"], 1)
        self.assertEqual(self.by_kind(payload, "module view mismatch"), [])
        taint = self.by_kind(payload, "out-of-tree module")
        self.assertEqual(taint[0]["severity"], "medium")
        self.assertIn("out-of-tree module loaded (bit 12), and an unowned module is loaded", taint[0]["detail"])

    def test_module_without_file_flagged(self):
        self.loaded(["nvidia", "evil_mod"])
        payload, code = self.kernel_json()
        self.assertEqual(code, 2)
        hit = self.by_kind(payload, "unowned module")
        self.assertEqual(len(hit), 1)
        self.assertIn("no evil_mod.ko exists under", hit[0]["detail"])

    def test_module_missing_from_sys_module(self):
        self.loaded(["nvidia", "evil_mod"], sys_names=["nvidia"], kallsyms_names=["nvidia", "evil_mod"])
        make_stub_file(self.sysroot, f"/usr/lib/modules/{RELEASE}/extra/evil_mod.ko")
        payload, code = self.kernel_json()
        self.assertEqual(code, 2)
        hit = self.by_kind(payload, "module view mismatch")
        self.assertEqual(len(hit), 1, payload["findings"])
        self.assertEqual((hit[0]["severity"], hit[0]["attack"]), ("critical", "T1014"))
        self.assertEqual(hit[0]["detail"], "evil_mod: in /proc/modules, kallsyms but not in /sys/module")

    def test_module_only_in_kallsyms(self):
        self.loaded(["nvidia"], kallsyms_names=["nvidia", "ghost"])
        payload, code = self.kernel_json()
        self.assertEqual(code, 2)
        hit = self.by_kind(payload, "module view mismatch")
        self.assertEqual(hit[0]["detail"], "ghost: in kallsyms but not in /proc/modules, /sys/module")

    def test_builtin_and_bpf_pseudo_module_ignored(self):
        payload, code = self.kernel_json()
        self.assertEqual(code, 0)
        self.assertEqual(self.by_kind(payload, "module view mismatch"), [])
        self.assertEqual(payload["modules"]["sys_module"], 1)
        self.assertEqual(payload["modules"]["kallsyms"], 1)

    def test_kallsyms_unreadable_is_noted(self):
        os.remove(self.proc / "kallsyms")
        payload, code = self.kernel_json()
        self.assertEqual(code, 0)
        self.assertIsNone(payload["modules"]["kallsyms"])
        note = self.by_kind(payload, "module cross-view")
        self.assertIn("kallsyms unreadable or empty", note[0]["detail"])
        self.assertEqual(note[0]["severity"], "info")

    def test_dashed_filename_matches_underscored_module(self):
        make_pacman_pkg(self.sysroot, "snd", "1-1", [f"/usr/lib/modules/{RELEASE}/kernel/sound/snd-hda-intel.ko.xz"],
                        packager=ARCH)
        self.loaded(["nvidia", "snd_hda_intel"])
        payload, code = self.kernel_json()
        self.assertEqual(code, 0)
        self.assertEqual(payload["modules"]["owned"], 2)

    def test_dkms_module_is_info(self):
        make_stub_file(self.sysroot, f"/usr/lib/modules/{RELEASE}/updates/dkms/msi-ec.ko.zst")
        make_pacman_pkg(self.sysroot, "msi-ec-dkms", "1.0-1", ["/usr/src/msi-ec-1.0/dkms.conf"],
                        validation="none", packager="Unknown Packager")
        self.loaded(["nvidia", "msi_ec"])
        self.taint(12288)
        payload, code = self.kernel_json()
        self.assertEqual(code, 1)
        self.assertEqual(self.by_kind(payload, "unowned module"), [])
        hit = self.by_kind(payload, "dkms module")
        self.assertEqual(hit[0]["severity"], "info")
        self.assertIn("built by dkms from /usr/src/msi-ec-1.0 (package msi-ec-dkms)", hit[0]["detail"])
        self.assertEqual(payload["modules"]["dkms"], 1)
        self.assertEqual(self.by_kind(payload, "out-of-tree module")[0]["severity"], "low")

    def test_taint_items_name_their_modules_and_where_they_came_from(self):
        make_stub_file(self.sysroot, f"/usr/lib/modules/{RELEASE}/updates/dkms/msi-ec.ko.zst")
        make_pacman_pkg(self.sysroot, "msi-ec-dkms", "1.0-1", ["/usr/src/msi-ec-1.0/dkms.conf"],
                        validation="none", packager="Unknown Packager")
        self.loaded(["nvidia", "msi_ec"])
        _write(self.sysroot / "sys/module/nvidia/taint", "O\n")
        _write(self.sysroot / "sys/module/msi_ec/taint", "OE\n")
        self.taint(12288)
        payload, code = self.kernel_json()
        self.assertEqual(code, 0, payload["findings"])
        unsigned = self.by_kind(payload, "unsigned module")[0]
        self.assertEqual((unsigned["severity"], unsigned["title"]), ("low", "Unsigned driver loaded: msi_ec"))
        self.assertIn("msi-ec-dkms, a package from the AUR rather than a signed repository", unsigned["text"])
        out_of_tree = self.by_kind(payload, "out-of-tree module")[0]
        self.assertEqual(out_of_tree["severity"], "info")
        self.assertIn("nvidia comes from the linux package, signed by your distribution", out_of_tree["text"])
        out, _ = self.kernel()
        self.assertNotIn("built outside the kernel", out)


class Taint(KernelBox):
    def test_taint_bits_decoded(self):
        self.taint(4096)
        payload, code = self.kernel_json()
        self.assertEqual(code, 0)
        hit = self.by_kind(payload, "out-of-tree module")
        self.assertEqual((hit[0]["detail"], hit[0]["severity"]), ("out-of-tree module loaded (bit 12)", "low"))
        self.assertEqual(payload["modules"]["taint_flags"], ["out-of-tree module loaded"])
        out, _ = self.kernel()
        self.assertIn("taint                        4096 (out-of-tree module loaded)", out)

    def test_unsigned_module_is_medium(self):
        self.taint(8192 + 1 + (1 << 15))
        payload, code = self.kernel_json()
        self.assertEqual(code, 1)
        hit = self.by_kind(payload, "unsigned module")
        self.assertEqual((hit[0]["detail"], hit[0]["severity"], hit[0]["attack"]),
                         ("unsigned module loaded (bit 13)", "medium", "T1014"))
        info = sorted(f["detail"] for f in self.by_kind(payload, "kernel taint"))
        self.assertEqual(info, ["kernel live patched (bit 15)", "proprietary module loaded (bit 0)"])

    def test_decode_table_covers_required_bits(self):
        decoded = dict(self.weird.decode_taint((1 << 0) | (1 << 1) | (1 << 12) | (1 << 13) | (1 << 14) | (1 << 15)))
        self.assertEqual(sorted(decoded), [0, 1, 12, 13, 14, 15])
        self.assertEqual(decoded[14], "soft lockup occurred")


class UpgradePending(KernelBox):
    def test_kernel_upgrade_pending_not_compromise(self):
        with mock.patch.object(self.weird, "running_kernel", return_value="6.0.9-x"):
            payload, code = self.kernel_json()
        self.assertEqual(code, 0)
        self.assertEqual([f for f in payload["findings"] if f["severity"] == "critical"], [])
        hit = self.by_kind(payload, "reboot pending")
        self.assertEqual(len(hit), 1, payload["findings"])
        self.assertEqual(hit[0]["severity"], "info")
        self.assertIn("running 6.0.9-x, installed 6.1.0-x (linux)", hit[0]["detail"])
        self.assertTrue(payload["modules"]["reboot_pending"])
        with mock.patch.object(self.weird, "running_kernel", return_value="6.0.9-x"):
            out, code = self.kernel()
        self.assertIn("A reboot is pending", " ".join(out.split()))
        self.assertIn("running kernel               6.0.9-x", out)
        self.assertIn("so they are checked after the reboot", " ".join(out.split()))

    def test_upgrade_pending_with_unsigned_taint_is_exit_1(self):
        self.taint(8192)
        with mock.patch.object(self.weird, "running_kernel", return_value="6.0.9-x"):
            payload, code = self.kernel_json()
        self.assertEqual(code, 1)
        self.assertEqual([f for f in payload["findings"] if f["severity"] == "critical"], [])


class Quiet(KernelBox):
    def test_all_owned_and_untainted(self):
        payload, code = self.kernel_json()
        self.assertEqual(code, 0)
        self.assertEqual([f["kind"] for f in payload["findings"]], ["ebpf", "hardening"])
        self.assertIn("bpftool unavailable or not root", payload["findings"][0]["detail"])
        out, code = self.kernel()
        self.assertEqual(code, 0)
        self.assertIn("1 loaded: 1 from packages. The kernel is untainted.", " ".join(out.split()))
        self.assertIn("taint                        0 (clean)", out)
        self.assertIn("1 in /proc/modules, 1 in /sys/module, 1 in kallsyms; 1 owned by packages, 0 dkms, 0 unowned", out)

    def test_ebpf_programs_listed_when_bpftool_works(self):
        self.table[("bpftool", "prog", "list")] = (
            "3: cgroup_skb  name sd_fw_egress  tag 6deef7357e7b4530  gpl\n"
            "12: kprobe  name hide_getdents64  tag 0123456789abcdef  gpl\n"
            "13: tracepoint  name sys_enter  tag 0123456789abcdef  gpl\n")
        payload, code = self.kernel_json()
        self.assertEqual(code, 0)
        details = [f["detail"] for f in self.by_kind(payload, "ebpf")]
        self.assertEqual(details[0], "3 eBPF program(s) loaded")
        self.assertEqual(len(details), 2)
        self.assertIn("kprobe program hide_getdents64", details[1])


class Posture(KernelBox):
    def write_posture(self, secure_boot_byte=1, lockdown="none [integrity] confidentiality"):
        _write(self.sysroot / "sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
               bytes([6, 0, 0, 0, secure_boot_byte]))
        _write(self.sysroot / "sys/kernel/security/lockdown", lockdown + "\n")
        _write(self.sysroot / "sys/module/module/parameters/sig_enforce", "N\n")
        _write(self.proc / "sys/kernel/modules_disabled", "0\n")
        _write(self.proc / "sys/kernel/kptr_restrict", "1\n")
        _write(self.proc / "sys/kernel/unprivileged_bpf_disabled", "2\n")
        _write(self.proc / "sys/kernel/yama/ptrace_scope", "1\n")

    def test_posture_parses_lockdown_and_secure_boot(self):
        self.write_posture()
        posture = self.weird.kernel_posture()
        self.assertEqual(posture["lockdown"], "integrity")
        self.assertEqual(posture["secure_boot"], "enabled")
        self.assertEqual(posture["module_loading"], "signed only")
        self.assertEqual((posture["modules_disabled"], posture["kptr_restrict"], posture["unprivileged_bpf_disabled"],
                          posture["ptrace_scope"], posture["sig_enforce"]), ("0", "1", "2", "1", "N"))
        out, _ = self.kernel()
        self.assertIn("Posture\n", out)
        self.assertIn("secure boot                  enabled", out)
        self.assertIn("lockdown                     integrity", out)
        self.assertIn("kernel module loading        signed only", out)
        payload, _ = self.kernel_json()
        self.assertEqual(payload["posture"], posture)

    def test_posture_open_and_disabled(self):
        self.write_posture(secure_boot_byte=0, lockdown="[none] integrity confidentiality")
        posture = self.weird.kernel_posture()
        self.assertEqual((posture["secure_boot"], posture["lockdown"], posture["module_loading"]),
                         ("disabled", "none", "open"))
        _write(self.proc / "sys/kernel/modules_disabled", "1\n")
        self.assertEqual(self.weird.kernel_posture()["module_loading"], "disabled")
        _write(self.proc / "sys/kernel/modules_disabled", "0\n")
        _write(self.sysroot / "sys/module/module/parameters/sig_enforce", "Y\n")
        self.assertEqual(self.weird.kernel_posture()["module_loading"], "signed only")

    def test_posture_without_efi_or_lockdown(self):
        posture = self.weird.kernel_posture()
        self.assertEqual(posture["secure_boot"], "unknown (not EFI)")
        self.assertEqual(posture["lockdown"], "unavailable")
        self.assertEqual(posture["sig_enforce"], "unavailable")
        self.assertEqual(posture["module_loading"], "open")


class Lkrg(KernelBox):
    def test_lkrg_absent_with_open_loading_is_recommended(self):
        posture = self.weird.kernel_posture()
        self.assertEqual((posture["module_loading"], posture["lkrg"]), ("open", "not present"))
        payload, code = self.kernel_json()
        self.assertEqual(code, 0)
        hit = self.by_kind(payload, "hardening")
        self.assertEqual(len(hit), 1, payload["findings"])
        self.assertEqual(hit[0]["severity"], "info")
        self.assertIn("LKRG is not present", hit[0]["detail"])
        self.assertIn("sig_enforce", hit[0]["detail"])
        out, _ = self.kernel()
        self.assertIn("LKRG                         not present", out)
        self.assertIn("weird -v lists everything", out)
        out, _ = self.kernel(all=True)
        self.assertIn("Root can load new kernel code at any time", " ".join(out.split()))

    def test_lkrg_in_sys_module_is_active(self):
        _write(self.sysroot / "sys/module/lkrg/parameters/log_level", "3\n")
        posture = self.weird.kernel_posture()
        self.assertEqual(posture["lkrg"], "active")
        payload, _ = self.kernel_json()
        self.assertEqual(self.by_kind(payload, "hardening"), [])
        out, _ = self.kernel()
        self.assertIn("LKRG                         active", out)

    def test_lkrg_in_proc_modules_is_active(self):
        self.loaded(["nvidia", "lkrg"], sys_names=["nvidia"], kallsyms_names=["nvidia"])
        self.assertEqual(self.weird.kernel_posture()["lkrg"], "active")

    def test_signed_only_loading_needs_no_recommendation(self):
        _write(self.sysroot / "sys/module/module/parameters/sig_enforce", "Y\n")
        payload, _ = self.kernel_json()
        self.assertEqual(self.weird.kernel_posture()["module_loading"], "signed only")
        self.assertEqual(self.by_kind(payload, "hardening"), [])


class Sensor(KernelBox):
    def test_sensor_fresh_events_file_is_active(self):
        _write(self.sysroot / "run/weird/events.ndjson", '{"type": "exec"}\n')
        self.assertEqual(self.weird.kernel_posture()["sensor"], "active")
        out, _ = self.kernel()
        self.assertIn("real-time sensor             active", out)

    def test_sensor_stale_or_missing_is_not_running(self):
        self.assertEqual(self.weird.kernel_posture()["sensor"], "not running")
        events = self.sysroot / "run/weird/events.ndjson"
        _write(events, '{"type": "exec"}\n')
        old = time.time() - 600
        os.utime(events, (old, old))
        self.assertEqual(self.weird.kernel_posture()["sensor"], "not running")
        out, _ = self.kernel()
        self.assertIn("real-time sensor             not running", out)
        payload, _ = self.kernel_json()
        self.assertEqual(payload["posture"]["sensor"], "not running")
        self.assertEqual(payload["posture"]["lkrg"], "not present")


if __name__ == "__main__":
    unittest.main()
