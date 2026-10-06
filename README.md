# thatsweird

`weird` looks at every process on a Linux machine and answers two questions
about each one: where did this executable come from, and is it doing anything
a normal copy of that program would not do. Provenance comes from the package
database (pacman or dpkg), the signature policy and the hash the package
recorded at install time. Behaviour comes from /proc: memfd executables,
deleted binaries, injected libraries, loader variables, odd parents, raw IP
connections. The two combine into a score, a verdict and a list of reasons
with MITRE ATT&CK ids, readable by a person or piped into the journal, a
metrics file or a real-time consumer. It is one Python file with no
dependencies outside the standard library, and it runs without root.

## Install

```bash
sudo npm install -g thatsweird                                   # npm
pipx install git+https://github.com/travershartstone93/thatsweird.git   # pipx (or pipx install . in a checkout)
git clone https://github.com/travershartstone93/thatsweird && python3 thatsweird/bin/weird   # from source
```

Python 3.8 or newer. Both packages run the same file, `bin/weird`; the pip
package wraps it in a `weird_cli` shim so `pip install .` gives a `weird`
console script. Shell completions are generated from the command tree:

```bash
weird dev completions bash > ~/.local/share/bash-completion/completions/weird
weird dev completions fish > ~/.config/fish/completions/weird.fish
```

## Quick start

```bash
weird                # one report: processes, AUR packages, persistence, kernel, stale binaries, hidden processes
weird -v             # every process, info rows and the notes behind each finding
weird --json         # the same as one JSON object, a key per section plus "summary"
weird --skip hidden  # leave out a section (repeatable); hidden is the slow pid probe
weird 1234           # one process in depth: provenance, integrity, mappings, environment, sockets, tree
weird /usr/bin/foo   # one file: owner package, integrity, which processes run it
```

The report ends with a summary line (counts by severity across every
section) and the exit status is 2 when anything is critical, 1 for medium or
warning findings, 0 when clean, 3 when a collector failed. Make the terminal
wide enough for the table.

## Commands

| Command | What it does |
| --- | --- |
| `weird` | The whole report; `--skip SECTION` leaves one out, `--offline SYSROOT` checks a mounted disk from live media |
| `weird PID` or `weird PATH` | Everything weird knows about one process or one file |
| `weird trust PID\|PATH` | Pin an executable's hash so scans stay quiet until the file changes; `weird untrust PATH` removes it |
| `weird watch` | One NDJSON line per new flagged process; `--events PATH` reads weird-sensor, `--falco` runs Falco |
| `weird dev ...` | Everything else: single sections (`scan`, `persist`, `hidden`, `kernel`, `aur`, `restart-needed`, `self-check`), `baseline init\|show\|diff`, `rules show\|init`, `cache`, `fixture record`, `completions`, `man`, `falco-rules`; `weird dev --help` lists them |

weird reads `~/.config/weird/rules.toml` for allow, suppress, upgrade,
downgrade and tag rules (`weird dev rules init` writes the template; see
`docs/rules.md`). The trusted list and baseline live next to it and work the
same whichever way the sections are run.

## How it works

**Provenance** is two axes. The first is who owns the file: the package
database says which package installed this path (pacman's local database or
dpkg's info lists, read in-process, no root), and metadata from uv, pipx,
npm, cargo, rustup, go and nvm covers the tools those install. The second is
whether that package can be believed: repository signing, the SigLevel in
pacman.conf, and the hash the package recorded at install time (pacman mtree
sha256, dpkg md5sums) compared with the file that is running. A packaged
binary whose hash differs is `integrity_modified` (T1554) and the verdict is
"Likely malicious" whatever the trust level.

**Signals** are the behaviours read from /proc, each with a score and an
ATT&CK id: masquerade, an unpackaged binary using a system daemon's name
(T1036.005); suspicious path under /tmp, /dev/shm or /var/tmp (T1036.005);
deleted executable (T1070.004); memfd execution (T1620); LD_PRELOAD,
LD_AUDIT or LD_LIBRARY_PATH into an unowned library (T1574.006); executable
mappings from a temp directory or from a library no package owns (T1055);
a tracer attached (T1055); HISTFILE=/dev/null or HISTSIZE=0 (T1070.003);
PYTHONPATH or NODE_OPTIONS pointing at a temp or home path (T1574);
PROMPT_COMMAND that is not a known shell integration (T1546.004); raw IP
connections to public addresses (T1071) and unusual ports (T1571);
elevated capabilities (T1068); a shell or downloader whose ancestor is a
document viewer (T1204.002); a file in a container that its image does not
own (T1036). A process running a file an upgrade replaced is stale, not
deleted, and scores 5.

**Verdicts**: "Unverified" is no provenance and no signals; "Suspicious" is
one signal, or any signal on a process with known provenance; "Likely
malicious" is two or more signals, or memfd, deleted or masquerade on an
unverified process. Every point is listed under the row as a reason.

**Rules** in `~/.config/weird/rules.toml` suppress, downgrade, upgrade or
tag processes by name, path, cmdline, uid, package, trust level, parent or
direct parent. Built-in rules cover package builds and shells spawned by
document viewers. Syntax in [docs/rules.md](docs/rules.md).

**Trust levels** say where a file came from, not whether it is safe:
`OFFICIAL` (signed distro repository), `THIRD_PARTY` (apt package signed by
another key), `LOCAL_BUILD` (built with makepkg, so the PKGBUILD is the whole
chain of trust), `USER_PKG` (installed by uv, pipx, npm, cargo, rustup, go or
nvm; named, but unsigned), `USER_LOCAL` (/usr/local or ~/.local, no
metadata), `APPIMAGE`, `FLATPAK`, `SNAP`, `CONTAINER`, `KERNEL`,
`USER_TRUSTED` and `UNKNOWN`. The xz backdoor shipped as OFFICIAL.

## Arch notes

After `pacman -Syu` long running processes keep executing the old, deleted
file; weird marks them stale rather than critical, and `weird restart-needed`
lists them by systemd unit with the `systemctl restart` line to run
(needrestart is not in the official repositories). Packages that did not
come from a repository (`pacman -Qm`) are LOCAL_BUILD, and `weird aur` reads
the PKGBUILD behind each one from the paru or yay cache or `--pkgbuild-dir`:
sources without https or on paste hosts, missing or SKIP checksums, install
scripts, and a PKGBUILD commit newer than the install date. Trust on Arch is
the %VALIDATION% pacman recorded (pgp from a distro packager is OFFICIAL,
anything else LOCAL_BUILD), the SigLevel from pacman.conf is quoted in each
package's evidence, and a LocalFileSigLevel that lets unsigned packages
install prints a warning at the top of every scan. Pacman hooks and
makepkg.conf are persistence sources for `weird persist`.

## Real-time

`weird watch` polls /proc every 2 seconds (`--poll SECONDS`) and prints one
NDJSON line per new process that scores, keyed by pid and start time. No
root, no Falco. With [weird-sensor](https://github.com/travershartstone93/weird-sensor),
a small eBPF program that writes exec, exit, memfd, ptrace, module, bpf and
connect events to `/run/weird/events.ndjson` as root, `weird watch --events
PATH` judges a process within its first second and turns module and bpf
loads into findings; when the file is fresh `weird watch` picks it by
itself. `weird watch --falco` runs Falco with the rules from
`weird falco-rules`. Event schema in [docs/events.md](docs/events.md).

```bash
weird watch | jq -r '"\(.verdict) \(.name) pid \(.pid): \(.reasons[0])"'
```

## Scheduled scans and outputs

`--journal` writes each alert to journald as `SYSLOG_IDENTIFIER=weird` with
`WEIRD_PID`, `WEIRD_NAME`, `WEIRD_SCORE`, `WEIRD_TRUST`, `WEIRD_ATTACK` and
`WEIRD_VERDICT` fields (`journalctl -t weird`). `--prometheus PATH` writes a
node_exporter textfile with `weird_alerts`, `weird_processes_total` and the
scan timestamp and duration, renamed into place atomically. `systemd/`
ships a user timer unit for one daily `weird --json --journal` run (every section):

```bash
systemctl --user link "$PWD/systemd/weird.service" "$PWD/systemd/weird.timer"
systemctl --user enable --now weird.timer
```

## Offline mode

Boot live media, mount the suspect disk, and let a kernel the attacker does
not control read it:

```bash
weird --offline /mnt/root        # persistence, integrity of every packaged executable, aur
weird --offline /mnt/root --json # {sysroot, sections: {persist, integrity, aur}, findings, counts}
```

No process scan, `/` refused without `--force`, exit 2/1/0 as usual.

## Testing

```bash
python3 -m unittest discover -s tests      # about 340 tests, around 90 seconds
```

Most tests build a fake /proc and a fake package database (Arch and Debian
shaped) under `tests/.sandbox` and run the real code against them with
`--proc-root` and `--sysroot`, so they pass on any distribution without
root. The emulation tests in `tests/test_emulation.py` are different: they
start harmless decoys on the host (a copy of sleep named sshd under /tmp,
a deleted executable, a memfd exec, an LD_PRELOAD of a real library, a
ptrace attach) and prove the live scan catches each one with the expected
reason and ATT&CK id. `weird dev fixture record PID DIR` captures a real
process into a tree the suite can replay, so a scenario seen once can
become a test without shipping anything dangerous. CI runs the suite on
Ubuntu (Python 3.12 and 3.13) and in an Arch Linux container.

## How it compares

Falco and Tetragon watch syscalls in real time through eBPF, need root and a
kernel module or BPF programs, and know nothing about packages; weird is a
user-space snapshot and provenance tool that exports Falco rules and
consumes the weird-sensor stream when real-time matters. rkhunter and
chkrootkit match known rootkit signatures and file names; weird has no
signature list and asks where each file came from instead. unhide finds
hidden pids by the same readdir versus stat walk that `weird hidden` does,
and stops there. needrestart tells you what to restart after an upgrade
and is not in the official Arch repositories; `weird restart-needed` is
the equivalent, built from the same stale-file detection the scanner uses.
osquery answers any question you can write as SQL; weird ships the
questions. AIDE, debsums and `pacman -Qkk` check files on disk against a
database; weird applies the package hashes to what is running and to what
is set to run. Lynis audits hardening settings; the posture block of
`weird kernel` overlaps with its kernel section and nothing else.

No user-space tool defeats a kernel rootkit. weird detects the userspace
class via the static probe and cross-views, catches sloppy kernel rootkits
through module and eBPF cross-views, reports whether the kernel is hookable
at all, and has an offline mode for when you need certainty.

## Files

`~/.config/weird/` holds `config.toml`, `rules.toml`, `user_trusted.txt`,
`baseline.json`, `trusted.json` and the file to package cache. `package.json`
carries the sha256 pin of `bin/weird` that `weird self-check` verifies;
`scripts/update-pin.py` records a new one after an intended change.

## License

MIT
