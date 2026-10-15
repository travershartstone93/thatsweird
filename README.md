# thatsweird

`weird` is a single-command host check for Linux. One run says what is
running, what is installed, what persists across reboots, what the kernel
allows, and whether any of it can be trusted, judged from the distribution's
own signed-package data rather than a signature list. It is one Python file
with no dependencies outside the standard library, and it never asks for
root.

## Why it never asks for root

A security tool that needs root asks you to trust its whole supply chain
with your machine: the author, the build, the packaging, and every future
maintainer who inherits the project. "Community reviewed" describes the
past. Root is a grant for the future. A detection tool should have less
power than the thing it hunts, so that running it is never itself the
compromise. weird is one readable file, runs as your user, and can prove it
has not changed (`weird dev self-check` compares its own sha256 with the pin
in package.json).

This became the design rule after Atomic Arch in June 2026, when about 1,500
AUR packages were taken over through the normal adoption process and
delivered an infostealer and an eBPF rootkit to the people who rebuilt them.
Every step of that chain was the process working as designed. Kernel-level checks that genuinely need root live in a separate,
opt-in sensor ([weird-sensor](https://github.com/travershartstone93/weird-sensor))
and are otherwise a recommendation, never a dependency: when weird sees that
module loading is open it tells you to run a privileged scanner, it does not
become one.

weird asks one question, ever: may it go online. Enter means yes, the answer is
kept in `~/.config/weird/config.toml`, and what it cannot verify stays listed as such.

## Install

```bash
sudo npm install -g thatsweird                                   # npm
pipx install git+https://github.com/travershartstone93/thatsweird.git   # pipx (or pipx install . in a checkout)
git clone https://github.com/travershartstone93/thatsweird && python3 thatsweird/bin/weird   # from source
```

Python 3.8 or newer. Both packages run the same file, `bin/weird` (pip wraps
it in a `weird_cli` shim); `weird dev completions bash|fish` prints completions.

## Usage

```bash
weird                  # one report: processes, AUR packages, persistence, kernel, stale binaries, hidden processes
weird -v               # every process, info rows and the notes behind each finding
weird --json           # the same as one JSON object, a key per section plus "summary"
weird 1234             # one process in depth: provenance, integrity, publisher, mappings, environment, sockets, tree
weird /usr/bin/foo     # one file: owner package, integrity, which processes run it
weird trust 1234       # pin that executable's hash; scans stay quiet until the file changes
weird watch            # one NDJSON line per new flagged process
weird --skip hidden    # leave a section out (repeatable); --deep probes every pid up to pid_max
weird --offline        # no network this run; --offline /mnt/root is live-media mode (a mounted disk)
```

The report opens with one sentence ("Nothing weird on whisper."), lists each
item under "Act now", "Worth a look" or "Minor" in plain words, and ends with
one line per section. Exit status: 0 clean, 1 worth a look, 2 act now, 3 a
collector failed.

Every completed run records its state in `~/.config/weird/baseline.json`; the
next lists what changed: new programs, executables whose hash moved, startup
entries and foreign packages added or removed, kernel settings. `--no-baseline`
skips both; Ctrl-C prints what finished (exit 130).

## Commands

| Command | What it does |
| --- | --- |
| `weird` | The whole report; `--skip SECTION` leaves one out, `--offline` keeps a run off the network (`--offline SYSROOT` checks a mounted disk), `--no-prompt` skips the online question (unanswered means offline), `--no-baseline` skips the comparison, `--fetch-campaigns` downloads the known-bad AUR list now, `--campaigns PATH` uses your own copy |
| `weird PID` or `weird PATH` | Everything weird knows about one process or one file |
| `weird trust PID\|PATH` | Pin an executable's hash so scans stay quiet until the file changes; `weird untrust PATH` removes it |
| `weird watch` | One NDJSON line per new flagged process; `--events PATH` reads weird-sensor, `--falco` runs Falco |
| `weird dev ...` | Single sections (`scan`, `persist`, `hidden`, `kernel`, `aur`, `restart-needed`, `self-check`), `baseline`, `rules`, `cache`, `fixture record`, `completions`, `man`, `falco-rules`; `weird dev --help` lists them |

## What one run checks

**Processes.** Every pid in /proc: who owns the executable, whether its hash
still matches what the package recorded at install, and whether it is doing
something a normal copy would not (memfd, deleted file, injected library,
loader variables, odd parent, raw public IP connections, large anonymous
executable memory in a process with no JIT).

**AUR packages.** Each package not from a repository is traced to its
PKGBUILD in the paru or yay cache: sources without https or on paste hosts,
missing or SKIP checksums, install scripts, a PKGBUILD changed after the
install date, and language-manager caches that fetched packages during the
build. Package names are also matched against the known-bad campaign lists
from aur-malware-check; a listed package that is installed is critical. The
list is fetched, and refreshed after seven days, only when weird may go online.

**Persistence.** systemd units, cron, autostart, shell rc files,
ld.so.preload, udev, pacman hooks and makepkg.conf, each target checked for
provenance; a binary in a user-writable PATH directory shadowing sudo, ssh,
git or pacman; authorized_keys entries with forced commands or options;
units that restart an unowned target in a tight loop. Your own scripts under
your home, run by your own units and rc files, are "your own unpackaged
software" (info) until a second signal appears. A target its publisher
verifies is info, and one only a package manager names is low.

**Kernel posture.** Modules compared across /proc/modules, /sys/module and
kallsyms, module file ownership, taint flags, Secure Boot, lockdown, module
signing, the sysctls that matter, kernel.core_pattern and kernel.modprobe
pointing at packaged handlers, and kernel command line flags that switch
audit, lockdown or IMA off.

**Stale binaries.** Processes still running a file an upgrade replaced,
grouped by systemd unit with the restart line to run.

**Hidden processes.** The /proc listing against two independent pid probes
(stat and getpgid on every pid up to the last one assigned, or to pid_max with
`--deep`), /proc/net against ss over netlink, thread counts against task
directories, and bind mounts placed over /proc/PID directories to hide them.

## How it works

**Provenance** has two axes. The first is who owns the file: the package
database (pacman's local database or dpkg's info lists, read in-process) and
the metadata of uv, pipx, npm, cargo, rustup, go and nvm. The second is
whether that package can be believed: repository signing, the SigLevel in
pacman.conf, and the install-time hash (pacman mtree sha256, dpkg md5sums)
compared with the file that is running. A packaged binary whose hash differs
is `integrity_modified` (T1554) and the verdict is "Likely malicious"
whatever the trust level.

**Publisher verification** covers files no package owns. The file says where it
came from (install path, ELF package note, Go build info, https addresses in its
bytes); weird looks there for a signed `manifest.json` or SHA256SUMS naming the
file's hash, with keys from the same host. No address is hardcoded, the binary is
never executed. A signature that verifies is `PUBLISHER_SIGNED`, an unsigned list
over TLS `PUBLISHER_HOSTED`, a list without the hash `publisher_mismatch` (T1554),
and nothing found stays "unverifiable" on every run.

**Trust levels** say where a file came from, not whether it is safe: `OFFICIAL`
(signed distribution repository), `PUBLISHER_SIGNED` and `PUBLISHER_HOSTED`
(above), `THIRD_PARTY` (apt package signed by another key), `LOCAL_BUILD` (built
with makepkg, so the PKGBUILD is the whole chain of trust), `USER_PKG` (a
language package manager's own metadata; named, unsigned), `USER_LOCAL`
(/usr/local or ~/.local, no metadata), `CONTAINER`, `UNKNOWN`, plus `APPIMAGE`,
`FLATPAK`, `SNAP`, `KERNEL` and `USER_TRUSTED`. The xz backdoor shipped as OFFICIAL.

**Signals** are behaviours read from /proc, each with a score and an ATT&CK
id: masquerade (T1036.005), temp-directory executable (T1036.005), deleted
executable (T1070.004), memfd execution (T1620), LD_PRELOAD or LD_AUDIT into
an unowned library (T1574.006), unowned executable mappings or a tracer
attached (T1055), anonymous executable region without JIT (T1055.009),
history disabled (T1070.003), PYTHONPATH or NODE_OPTIONS into a temp or home
path (T1574), unknown PROMPT_COMMAND (T1546.004), raw public IP connections
(T1071) and unusual ports (T1571), raised capabilities (T1068), a shell spawned
by a document viewer (T1204.002), a container file its image does not own (T1036).

**Verdicts**: "Unverified" is no provenance and no signals; "Suspicious" is one
signal, or any signal with known provenance; "Likely malicious" is two or more,
or memfd, deleted or masquerade on an unverified process; every point is a reason.

**Rules** in `~/.config/weird/rules.toml` suppress, downgrade, upgrade or tag
processes by name, path, cmdline, uid, package, trust level or parent (`weird
dev rules init` writes the template; syntax in [docs/rules.md](docs/rules.md)).
**Baseline trust** (`weird trust`) records an executable's hash and keeps the
scan quiet until that file changes, a small file integrity monitor for the
things you chose to run. The long form is in [docs/reference.md](docs/reference.md).

## Arch notes

After `pacman -Syu` long-running processes keep executing the old, deleted
file; weird marks them stale rather than critical and the stale section lists
them by systemd unit (needrestart is not in the official repositories).
Packages from outside the repositories (`pacman -Qm`) are LOCAL_BUILD. Trust
is the %VALIDATION% pacman recorded (pgp from a distribution packager is
OFFICIAL, anything else LOCAL_BUILD), the SigLevel from pacman.conf is quoted
in each package's evidence, and `-v` notes a LocalFileSigLevel that installs
local builds unsigned. /var/log/pacman.log
and its rotated copies give the install history used for the "PKGBUILD changed
after install" check and for packages installed and later removed.

## Real-time

`weird watch` polls /proc every 2 seconds (`--poll SECONDS`) and prints one
NDJSON line per new process that scores. With weird-sensor, a small eBPF
program that writes exec, exit, memfd, ptrace, module, bpf and connect events
to `/run/weird/events.ndjson` as root, `weird watch --events PATH` judges a
process within its first second and turns module and bpf loads into findings.
`weird watch --falco` runs Falco with the rules from `weird dev falco-rules`;
the event schema is in [docs/events.md](docs/events.md).

## Scheduled runs and outputs

`--journal` writes each finding to journald as `SYSLOG_IDENTIFIER=weird` with
`WEIRD_*` fields (`journalctl -t weird`). `--prometheus PATH` writes a
node_exporter textfile with `weird_alerts`, `weird_processes_total` and the
run timestamp and duration. `systemd/` ships one user timer for a daily full
run that logs what changed and follows the online answer you gave in a terminal:

```bash
systemctl --user link "$PWD/systemd/weird.service" "$PWD/systemd/weird.timer"
systemctl --user enable --now weird.timer
```

## Offline mode

Boot live media, mount the suspect disk, and let a kernel the attacker does
not control read it: `weird --offline /mnt/root` runs persistence, the
integrity of every packaged executable and the AUR checks against the mounted
disk. No process or hidden sections; `/` is refused without `--force`.

## Testing

```bash
python3 -m unittest discover -s tests      # about 460 tests, a minute or two
```

Most tests build a fake /proc and a fake package database (Arch and Debian
shaped) under `tests/.sandbox` and run the real code against them with
`--proc-root` and `--sysroot`, so they pass anywhere without root (the
publisher tests use a throwaway HTTPS publisher and GPG key on localhost).
`tests/test_emulation.py` starts harmless decoys on the host (a copy of sleep
named sshd under /tmp, a deleted executable, a memfd exec, an LD_PRELOAD, a
ptrace attach) and proves the live scan catches each with its ATT&CK id. CI
runs the suite on Ubuntu (Python 3.12 and 3.13) and in an Arch container.

## How it compares

[ghostscan](https://github.com/aidlx/ghostscan) runs as root with 52
kernel-level scanners (syscall table, ftrace, kprobe and BPF checks), so it is
better than weird at finding a kernel rootkit already in place. weird recommends
it when module loading is open and borrowed its unprivileged ideas: core_pattern
and modprobe tampering, kernel cmdline flags, proc bind mounts, a second pid probe.

[aur-malware-check](https://github.com/lenucksi/aur-malware-check) keeps the
lists of packages named in known campaigns; weird downloads them once allowed
online and adds the structural PKGBUILD check, which needs no list at all.

Falco and Tetragon watch syscalls in real time through eBPF, need root and
know nothing about packages; weird is a user-space snapshot and provenance
tool that exports Falco rules and consumes the weird-sensor stream. rkhunter
and chkrootkit match known rootkit signatures; weird has no signature list
and asks where each file came from. unhide finds hidden pids by the same
readdir versus stat walk and stops there. osquery answers any question you
can write as SQL; weird ships the questions. AIDE, debsums and `pacman -Qkk`
check files on disk; weird applies the package hashes to what is running and
to what is set to run. Lynis audits hardening; only the posture rows overlap.

weird is a user-space tool, and a kernel rootkit that controls what /proc says
can lie to it. The mitigations are the cross-view checks that compare sources a
rootkit must hook separately, the sensor, the posture report that says whether
the kernel is hookable at all, and offline mode for when you need certainty.

## Files

`~/.config/weird/` holds `config.toml` (with the `online` answer), `rules.toml`,
`user_trusted.txt`, `baseline.json`, `trusted.json`, `claims.json`, `campaigns/`,
`publishers/<host>/` and the file to package cache. `package.json` carries the
sha256 pin of `bin/weird` for `weird dev self-check`; `scripts/update-pin.py` renews it.

## License

MIT
