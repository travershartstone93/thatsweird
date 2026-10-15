# Reference

The long form of what each subcommand reads, how it scores and what its JSON
carries. The [README](../README.md) has the short version; [rules.md](rules.md)
covers rules.toml and [events.md](events.md) the weird-sensor event stream.
The sections below are the sections of one plain `weird` run; each is also a
`weird dev` command on its own, which is what the examples show.

## One run

Plain `weird` prints, in order: the self-check lines (only when something is
wrong), the changes since the baseline (once one is saved, see "Baseline"
below), the process scan, AUR packages (foreign package list, known-bad
cross-check, PKGBUILD analysis), persistence entries, kernel posture and
findings, stale binaries (only when a process still runs a replaced file) and
the hidden-process cross-views (the pid probe, last). The AUR, persistence and
kernel sections run in threads while the process scan runs, so the whole report
takes a few seconds; the output order never changes. While a section runs and
stderr is a terminal, one line on stderr names the sections still running
("checking hidden processes... 3s"); it is cleared before the report prints and
never written under `--json` or to a pipe.

The report prints in one piece once every section has run. It opens with one
sentence about the machine ("Nothing weird on whisper.", "2 things on whisper are
worth a look, and 4 are minor. Nothing needs you to act now."), then a line
naming the run it compares with, then the items grouped as "Act now" (critical),
"Worth a look" (medium) and "Minor" (low). Each item is a title that names the
real thing (a program by what it runs, a unit by the file it starts, a package,
a kernel module) and a few plain sentences: what it is, why it is listed, what to
do. "Everything else" closes the report with one line per section: how much was
checked and, for running programs, which were verified with their publishers.
Text wraps at 78 columns without splitting a path; colour is used only on a
terminal. Info items appear only with `-v`, which also adds a dim details line
under each item (the check, the trust level, the ATT&CK id), the kernel posture
rows, and one line per process and startup entry. A single `weird dev` section
prints the same layout for itself.

Exit status: 2 with any critical item, 1 with any medium one, 0 otherwise, and 3
when a collector failed (that section is reported as failed and the rest still
prints); minor items never change it. "Your own scripts" counts the startup
entries in the yours tier (below), which never change the exit status either.
`--json` carries the counts under "summary", with "yours" as its own key.

`--skip SECTION` leaves a section out (processes, aur, persist, kernel, stale,
hidden; repeatable). `-v` shows every process, the info items and the details
behind each item. `--json` prints one object with a key per section plus
"summary"; `--ndjson` is one line per process and covers the scan section only.
`--deep` hashes every packaged executable (below) and makes the hidden section
sweep every pid up to pid_max instead of stopping at the last pid assigned.
`--journal` and `--prometheus PATH` apply to every section. `--offline SYSROOT`
runs the live-media checks instead (below). `--save-baseline` records this run
as the baseline without asking; `--no-baseline` skips the comparison and the
question. `--no-prompt`, or WEIRD_NO_PROMPT in the environment, means weird
never asks a question; its two questions are whether to download the known-bad
AUR list and whether to save the first run as the baseline. `--proc-root DIR`
and `--sysroot DIR` (or WEIRD_PROC_ROOT and WEIRD_SYSROOT) point every section
at a recorded tree. `weird PID` and `weird PATH` inspect one process or file,
`weird trust` and `weird untrust` manage the trusted hashes, `weird watch`
streams.

Ctrl-C during a run prints the sections that had finished, one line
"interrupted during <section>", the summary line marked "(partial)", and exits
130. Under `--json` the document is still valid JSON with an "interrupted" key
naming the section and only the finished sections present. The sections that
run in threads are daemon threads, so an interrupted run never waits for them.

### The dev commands

Everything else is under `weird dev`, which keeps the single-section flags
(`--all`, `--net`, `--include-listen`, `--enrich-net`, `--log-file`,
`--raw-cmdline`, `--debug-log`):

- `weird dev scan`: the process section alone, with the network flags.
- `weird dev inspect PID`: what `weird PID` runs.
- `weird dev trust NAME`: add a name to `user_trusted.txt` (the older
  name-based list; `weird trust` pins a hash instead).
- `weird dev rules show|init`: print the active rules or write the template.
- `weird dev cache show|clear`: the file to package cache.
- `weird dev watch`, `restart-needed`, `persist`, `hidden`, `kernel`, `aur`,
  `self-check`, `offline SYSROOT`, `fixture record PID DIR` and
  `baseline init|show|diff|trust|untrust`: the sections and tools described
  below, run one at a time with their own flags.
- `weird dev falco-rules`: print the Falco rules `weird watch --falco` loads.
- `weird dev man`: show the manual page. `weird dev completions bash|fish`:
  print a completion script generated from the command tree.

## Binary integrity

A running executable is compared with the hash its package recorded at
install time: the sha256 in `/var/lib/pacman/local/<pkg>/mtree` on Arch,
the md5 in `/var/lib/dpkg/info/<pkg>.md5sums` on Debian (a weak hash, but
it is what dpkg keeps), `rpm -V` on RPM systems. The mtree and md5sums files
are read in-process, so no root and no package manager call is needed.

By default only flagged processes (any score, deleted or memfd executable)
are hashed. `--deep` also hashes every OFFICIAL and THIRD_PARTY process,
which costs well under a second per hundred binaries (about 0.3 s for 88 on this machine). `weird dev inspect PID` always
verifies the inspected process and prints an `Integrity:` line.

A mismatch is `integrity_modified` (+60, ATT&CK T1554) and the verdict is
"Likely malicious" regardless of trust level. A binary that cannot be
checked (no mtree, path not listed, unreadable) is reported as
`unavailable` in the evidence and does not score. JSON output carries the
result in the `integrity` field.

## Publisher verification (a file no package owns)

An executable with trust UNKNOWN, USER_LOCAL or USER_PKG (not a container
process) is asked about its publisher. Discovery (`discover_publisher`) reads,
in order: the install path (`~/.local/share/<name>/versions/<ver>`,
`<root>/<name>/<ver>/bin/<x>`, `/opt/<name>/<ver>`, any version-like directory
under the home, /usr/local or /opt: the version, and the product from the
component before it), the ELF `.note.package` JSON (name, version), Go build
information through `go version -m`, and a bounded scan of the file's bytes for
https addresses (1 MB chunks, at most 1 GB and 15 s). Hosts, release bases
(addresses whose path mentions releases, downloads, manifests, checksums or
updates) and GitHub repositories are kept; product candidates come from the
release path (`claude-code` from `claude-code-releases`), the install directory
name, the note, the Go module and the file name. The claim, and the file's
sha256 and sha512 once verification has hashed it, are cached per path, inode,
size, mtime and ctime in `~/.config/weird/claims.json`, so a later run costs one
stat; a file replaced, or rewritten with its mtime set back, gets a new ctime,
which a user cannot forge. Hashing a large binary takes about a second, so an
offline run hashes only when a result for that host is cached: the same bytes
verified on an earlier run keep their tier offline. Nothing is ever executed,
and no publisher address is written into weird.

Verification (`verify_publisher`) tries, for each release base B and version V:
`B/V/manifest.json`, `B/V/SHA256SUMS`, `B/V/checksums.txt`, `B/V/sha256sum.txt`,
`B/manifest.json`, `B/latest/manifest.json`; for a GitHub repository
`releases/download/v<V>/` (and without the v) `SHA256SUMS`, `checksums.txt`,
`sha256sum.txt`, `<product>-<V>.sha256`, `SHA256SUMS.txt`. Each is one small
GET through the same code as the known-bad list (TLS verified against the
system store, redirects only to the same host, every resolved address tried,
5 MB for lists and 64 KB for keys and signatures, 20 s). Next to a found list
weird looks for `.sig` and `.asc` (and `.minisig` when minisign is installed);
keys are tried at `/keys/<product>.asc` for every product candidate,
`/<product>.asc`, `/keys/release.asc`, `/release-key.asc`, `/pgp-key.asc`,
`/KEYS` and `B/KEYS` on the same host, then the key the signature names on
keys.openpgp.org. Keys live in a private keyring per host,
`~/.config/weird/publishers/<host>/gnupg` (0700), and gpg must report VALIDSIG.
The file's hash is matched as hex text anywhere in the list, so manifest.json
files and SHA256SUMS lines both work.

The tiers: **signed** (PUBLISHER_SIGNED, a signature verifies under a key from
the host and the hash is present), **hosted** (PUBLISHER_HOSTED, an unsigned
list fetched over TLS from the publisher's host names the hash), **mismatch**
(a list that should name the file does not, or a signature fails under the
host's keys: `publisher_mismatch`, +60, T1554, verdict "Likely malicious"),
**unverifiable** (nothing published, no network, offline, or a list that
cannot contain the file: release archives only, an unknown format, the latest
list of another version; info, never scored, and `weird PID` says why under
"Where it came from") and **pending**
(the run's eight seconds of network time for new probes are used up; checked
next run). A verified tier is never inherited: every file, each Claude Code
version included, is checked against its own published hash, so a file dropped
next to a verified binary gains nothing from it. Only a manager's claim is handed
down: a process whose executable lies under the install root of a binary a
manager identified (USER_PKG; the versioned directory, a `lib/<name>` sibling
under the same prefix, never a bare bin directory or the home) and that does not
name its own version inherits that claim with evidence "inherits identified from
<root>" (llama-server under /usr/local/lib/ollama follows ollama's Go build
information).

Per host, `~/.config/weird/publishers/<host>/` keeps `trust.json` (the pinned
fingerprints, first seen, products; a new key from the same host is accepted
and reported once as medium `publisher_key_changed`), `verified.json` (results
by file sha256, so the same bytes are never verified twice; a mismatch is
rechecked after a day) and `misses.json` (404s, kept a day). Every run names the
programs verified with their publishers in its line for running programs, for
example "Verified with their publishers: claude-code 2.1.291 and 2.1.296 (signed
release list at downloads.claude.ai)."
`weird PID` shows the result under "Publisher", `--json` under `publisher`
(tier, host, product, version, manifest_url, key_fingerprint, detail,
inherited_from).

Whether any of this may use the network is the one question weird ever asks:
"weird can go online to check your software against publishers' signed lists
and the known-bad AUR list. OK? [Y/n]", on the first run with a terminal (Enter
means yes, EOF means no for this run only), stored as `online = true|false` at
the top of `~/.config/weird/config.toml`. Without a terminal, under `--json`,
`--ndjson`, `watch`, `--no-prompt` or WEIRD_NO_PROMPT it is not asked, the run
stays offline and the report (or the JSON `online` key) says "online checks not
enabled: run weird once in a terminal to answer". `--offline` forces a run
offline whatever is stored. The same switch gates the known-bad list download
(fetched or refreshed silently when missing or older than
campaigns_max_age_days) and the GitHub and npm description lookups. Since 1.5.0
no other question exists: the baseline is recorded by every completed run and
"Changes since <date>" means since the previous run.

## Restart needed (needrestart is not in the official Arch repositories)

After `pacman -Syu` (or `apt upgrade`) long running processes keep executing
the old, now deleted, file. weird tells those apart from a real deleted
binary: if the path exists again, a package owns it, and that package was
installed after the process started, the process is marked stale (score 5,
not critical) instead of critical. Mapped libraries in `/proc/<pid>/maps`
get the same treatment.

```bash
weird dev restart-needed          # stale processes grouped by systemd unit
weird dev restart-needed --json   # same, machine readable
```

Exit code is 1 when something should be restarted and 0 otherwise. Each group
comes with the matching `systemctl restart` or `systemctl --user restart` line.

## Persistence (what runs without you starting it)

`weird dev persist` walks the places a Linux box starts programs on its own and
checks the provenance of what each one launches, with the same package
database, signature and hash checks the scanner uses on running processes:

- systemd units in /etc/systemd, /usr/lib/systemd and ~/.config/systemd/user
  (ExecStart, ExecStartPre, ExecStartPost, ExecReload; timers are followed to
  their service)
- cron: /etc/crontab, /etc/cron.d, /etc/cron.{hourly,daily,weekly,monthly},
  readable spool files and `crontab -l`
- XDG autostart .desktop files (system and user)
- shell rc files (~/.bashrc, ~/.zshrc, ~/.profile, ~/.bash_profile,
  config.fish, /etc/profile, /etc/profile.d, /etc/bash.bashrc): lines that run
  an absolute path or source a file no package owns
- /etc/ld.so.preload
- udev RUN rules in /etc/udev/rules.d
- Arch: pacman hooks in /etc/pacman.d/hooks and /usr/share/libalpm/hooks (they
  run as root on every upgrade), plus CC, CXX, LD, STRIP, BUILDENV and PACKAGER
  in /etc/makepkg.conf and ~/.makepkg.conf pointing at unowned paths

Exec lines are parsed the way the launcher reads them: systemd prefixes
(`-`, `@`, `+`, `!`), `env VAR=x /path`, .desktop field codes, `%h` and friends.
`sh -c "..."` and other inline scripts are flagged as such, and an interpreter
given a script (`python3 /home/me/job.py`) reports the script as the target.

Severity: **critical** when the target is not owned by any package, its hash no
longer matches the package, or the entry lives under /tmp, /dev/shm or /var/tmp;
**medium** for inline scripts, USER_LOCAL or LOCAL_BUILD targets and shell rc
hits; **info** otherwise. An inline script in a unit or hook file that a package
shipped and that still matches its install hash is the distro's script, so it
stays info.

The yours tier: a USER_LOCAL target under the current user's home (~/.local,
~/.cargo, ~/.config, a project directory, a venv) launched from a file that is
also under the home (a user unit, ~/.bashrc, ~/.ssh/config) is what a
developer machine looks like, so it is **info** with the provenance note "your
own unpackaged software" and the entry carries `"yours": true` in the JSON. It
becomes **medium** with a second signal: the launching file lives under /etc or
/usr ("a system file runs code under your home"), a restart loop keeps it alive
through an interpreter no package owns (a venv python, say), or any temp-dir or
integrity hit (critical, as above). A target that changed after the file that
runs it is noted but stays info, because scripts are edited more often than
units. A unit under /etc/systemd/system that points at an unpackaged file under
/usr/local stays medium and says so: "system-wide persistence of unpackaged
code". A target outside the home is also checked against its publisher (see
the publisher verification section): verified is **info** with trust
PUBLISHER_SIGNED or PUBLISHER_HOSTED, a target only a package manager names
(Go build information, say) is **low**, a publisher mismatch is **critical**,
and anything else keeps its severity, so a hand-written script in /usr/local
stays medium. The section's summary line says how many entries were checked and how many
are your own scripts. Each source carries its MITRE ATT&CK id in the JSON (T1543.002
services, T1053.006 timers, T1053.003 cron, T1547.013 autostart, T1546.004 shell
rc, T1574.006 ld.so.preload, T1546 udev and pacman hooks, T1195.001 makepkg.conf).

```bash
weird dev persist          # the entries worth a look, then one summary line
weird dev persist --all    # also list the entries that check out
weird dev persist --json   # {host, timestamp, entries, counts}
```

Exit code is 2 with any critical entry, 1 with any medium one, 0 otherwise.

Three further sources, read without root:

- PATH shadowing: a file in a user-writable PATH directory (also ~/.local/bin
  and ~/bin) named like a watched system binary (sudo, su, ssh, git, pacman,
  curl, bash ...) is critical [T1036.005]; a symlink to the real binary is info.
- SSH footholds: ~/.ssh/authorized_keys entries with a forced command,
  forwarding options, a wildcard from= or no comment are medium, critical when
  the command lives in a temp dir or an unowned path outside the home
  [T1098.004]; ssh config ProxyCommand/LocalCommand from such paths is medium,
  and from the user's own script under the home it is a yours-tier info entry.
- Restart loops: a systemd unit with Restart=always or on-failure and a
  RestartSec under 60 whose target is unowned or user-local is raised one
  severity step ("restart loop keeps it alive") [T1543.002]; a yours-tier
  entry only when the interpreter is unpackaged too.

## Hidden processes, threads and sockets

A rootkit that filters the /proc directory listing hides a process from ps,
top and from weird's own scan. `weird dev hidden` reads the same facts through
two paths each and reports every disagreement:

- pids: the directory listing of /proc against a direct `stat` of
  `/proc/<pid>/stat` and a `getpgid()` call for every pid from 1 up to the
  probe limit (what unhide does). A pid that answers but is not listed is
  **critical** (T1564.001). Thread ids also answer without being listed, so a
  hit whose Tgid is another pid is skipped, and every hit is confirmed a
  second time so a process that started or exited during the walk is not
  reported. The limit is the high-water mark plus a margin: the last pid the
  kernel assigned (the last field of /proc/loadavg) or the highest listed
  pid, whichever is larger, plus 2000 or five percent. A hidden process is
  already running, so its pid is at or below that mark; probing further only
  costs time. `--deep` sweeps every pid up to `pid_max` (the counter can
  wrap on a long-running system, and that is the one case the mark misses).
- sockets: inodes in /proc/net/{tcp,tcp6,udp,udp6} against `ss -tunapHe`,
  which asks the kernel over netlink. A socket only one side knows about is
  **critical** (T1014). /proc/net is read before and after ss so churn is
  not a hit; sockets without an inode (TIME_WAIT) are ignored.
- threads: the Threads: line in /proc/<pid>/status against the entries of
  /proc/<pid>/task, re-read to rule out a race: **medium**.
- totals: the task count in the fourth field of /proc/loadavg against the
  threads counted over the listing, with a margin for normal churn: **low**.

The default probe takes under a second; the `--deep` sweep is about fifteen
seconds on a 4194304 pid_max system, most of it inside the kernel.

```bash
weird dev hidden           # findings table with an explanation under each row
weird dev hidden --deep    # every pid up to pid_max
weird dev hidden --json    # {host, timestamp, self_check, pid_max, probed_to, listed_pids, hidden_pids, findings, counts}
```

Exit code is 2 with any critical finding, 1 with any medium one, 0 otherwise.

### Self-check

`weird`, `weird dev hidden` and `weird dev persist` start by looking at their own
process: a non-empty /etc/ld.so.preload, LD_PRELOAD or LD_AUDIT in the
environment, or an executable mapping in /proc/self/maps that no package owns
(outside the interpreter's own prefix) prints a yellow warning before any
other output and lands in the JSON as `self_check`. It never stops the run;
it tells you the results may have been tampered with.

### Self integrity

At startup weird hashes its own script (`bin/weird`, sha256) and compares it
with the pin shipped in `package.json` next to `bin/` under `weirdIntegrity`
(`{"sha256": ..., "version": ...}`). A mismatch prints one red warning line
on stderr before any other output and sets `"self_integrity": "mismatch"` in
every JSON payload; it never changes an exit code, because a tampered copy
that refused to run would hide the tampering. No pin at all is reported as
"integrity pin not found" without a warning.

```bash
weird dev self-check                # self-check items, integrity result, both hashes
python3 scripts/update-pin.py   # after an intended change: record the new hash
```

Two more views. /proc/self/mountinfo is checked for mounts placed over
/proc/<pid> (the way old rootkits hid pids) and for a /proc that is not of
type proc [T1564]; every pid is also asked for through getpgid(), and a pid
that one kernel interface knows and the other does not is reported after a
second check [T1564.001]. The getpgid probe is skipped on replayed trees.

## Kernel and modules

`weird dev kernel` looks at the running kernel from the side a rootkit has to
hide from:

- loaded modules across three views: /proc/modules, /sys/module (entries with
  a coresize or initstate file, so builtins are left out) and the `[name]`
  suffixes in /proc/kallsyms. A module missing from one view is **critical**
  (T1014). kallsyms that is unreadable or empty for a non-root user is noted
  and left out of the comparison.
- ownership: every loaded module must exist as a .ko, .ko.zst, .ko.xz or
  .ko.gz under /usr/lib/modules/`uname -r` and that file must belong to a
  package; a missing or unowned file is **critical** ("unowned module"). A
  module built by dkms from a packaged source tree in /usr/src is reported as
  info instead. When the directory for the running kernel is gone and a
  different kernel version is installed, that is "reboot pending" (info),
  because pacman removes the old module tree on a kernel upgrade.
- taint: /proc/sys/kernel/tainted decoded bit by bit, each item naming the
  modules behind it (read from /sys/module/NAME/taint) and where they came
  from. Unsigned module (bit 13) is low when every unsigned module is a DKMS
  build from a package (the text says when that package comes from the AUR)
  and **medium** when one is not explained. Out-of-tree module (bit 12) is
  info when every such module comes from a package your distribution signed,
  low otherwise, and medium when an unowned module is loaded as well; the
  rest are info.
- eBPF: with root and bpftool, the loaded programs are counted and any kprobe
  or tracepoint whose name points at getdents or the tcp/udp seq_show
  functions is noted, since that is where an eBPF rootkit hooks.

Before the findings it prints a posture block, report only, no score: Secure
Boot (the last byte of the SecureBoot efivar), lockdown mode, modules_disabled,
sig_enforce, kptr_restrict, unprivileged_bpf_disabled, yama ptrace_scope,
LKRG (`active` when /sys/module/lkrg exists or lkrg is in /proc/modules,
else `not present`), the real-time sensor (`active` while
/run/weird/events.ndjson was written in the last 120 s, else `not running`),
the taint value and the module counts per view, plus one verdict line:
`kernel module loading: open / signed only / disabled`. When module loading
is open and LKRG is not present, an info finding recommends signed-module
enforcement (module.sig_enforce=1 or lockdown=integrity) or LKRG.

```bash
weird dev kernel           # posture block, then findings
weird dev kernel --json    # {host, timestamp, modules, posture, findings, counts}
```

Exit code is 2 with any critical finding, 1 with any medium one, 0 otherwise.

The posture report also has the rows "core dumps" (kernel.core_pattern; a pipe to a handler
in a temp dir, missing, user writable or unowned is critical [T1546]),
"modprobe helper" (kernel.modprobe must be a packaged path, otherwise critical
[T1547.006]) and "kernel cmdline" (audit=0 and a non-standard init= are
medium, missing ima_policy= and nokaslr are info, module.sig_enforce=1 is a
positive note).

## AUR supply chain

Packages that did not come from an enabled repository were built locally from
a PKGBUILD, and that PKGBUILD is the whole chain of trust. `weird dev aur` lists
them (`pacman -Qm`, or the local database when pacman is not available:
validation other than pgp or an unknown packager) and finds the PKGBUILD in
~/.cache/paru/clone/<name>, ~/.cache/yay/<name> or the directory given with
`--pkgbuild-dir`. For each one it reads `source=()` (and the per-arch
variants, `name::url` entries, multi-line arrays, `$url` style variables),
the checksum arrays and the `install=` line:

- a source fetched without https (http, git, ftp) is **medium** "insecure
  source"; a source on a paste host (pastebin, hastebin, ghostbin,
  transfer.sh, anonfiles and friends) is **critical**
- no checksum array, or a `SKIP` entry for a plain download, is **low**; SKIP
  on a git source is the normal way to build a VCS package and stays info,
  noting whether the checkout is pinned to a commit or tag
- `install=` is info: that script runs as root on install
- when the clone is a git repository, the last commit touching PKGBUILD is
  compared with the package's %INSTALLDATE%. A newer commit is **medium**
  "PKGBUILD modified after install" with the `git diff --stat` summary and
  whether pkgver changed; uncommitted edits count too, except a lone pkgver=
  bump, which is what makepkg writes for a VCS package. The same package with
  an insecure source as well is **critical**.
- a foreign package that still carries a pgp signature (a repository since
  removed) or has no clone is listed as info

```bash
weird dev aur                      # critical, medium and low findings
weird dev aur --all                # also the info entries
weird dev aur --pkgbuild-dir DIR   # DIR/<name>/PKGBUILD checked first
weird dev aur --json               # {host, timestamp, packages, findings, counts}
```

Exit code is 2 with any critical finding, 1 with any medium one, 0 otherwise.

/var/log/pacman.log (plus rotated .gz/.xz copies) gives a
per-run install history (`pacman_history()`), used for the install time of
the "PKGBUILD modified after install" check, for packages installed and later
removed, and for foreign installs inside given time windows. Language manager
caches (~/.npm, ~/.bun, ~/.cache/pnpm, yarn, global node_modules) are scanned
for packages fetched in the 30 minutes before an AUR package whose build uses
npm, yarn, pnpm or bun was installed: "package fetched during an AUR build"
(medium, T1195.001). Absent or unreadable caches are skipped.

### Known-bad list

Foreign package names are also matched against the campaign lists kept by
[aur-malware-check](https://github.com/lenucksi/aur-malware-check)
(campaigns.json plus the list files it names). Only ids, labels, date windows
and package names are read; nothing in the file is executed. An installed
package on a list is **critical** "known malicious AUR package" [T1195.002]
with the campaign window and the install date from pacman.log; a name that is
only present in the paru or yay cache is info. The list lives under
`~/.config/weird/campaigns/` (0600) with a meta.json recording sha256, size and
the newest campaign date, and the aur header shows its status.

weird never downloads the list on its own. On a terminal, when no list is
cached or it is older than `campaigns_max_age_days` (config.toml, default 7),
it asks one [y/N] question and prints what it would fetch; Enter or EOF means
no. It never asks without a terminal, under `--json` or `--ndjson`, in watch
mode, on the timer (the shipped unit sets WEIRD_NO_PROMPT=1), or with
`--no-prompt`. `weird dev aur --campaigns PATH` uses a file you supply and
never fetches; `--fetch-campaigns` downloads without asking (https only, 20 s,
5 MB, redirects away from github.com refused; every address DNS returns is tried in turn, so a host with a dead IPv6 route still reaches GitHub over IPv4). A failed download prints one
line and the run continues.

### Network inspection (what it actually does)

weird does **not** sniff packet contents. It builds a process-to-socket view using:

- `ss` (preferred) or `/proc/net` as a fallback
- Outbound connections by default

## Offline mode (live media)

No user space tool defeats a kernel rootkit on the machine it owns. The one
mode whose answer is trustworthy by construction is to boot live media, mount
the suspect disk and read it from a kernel the attacker does not control:

```bash
weird dev offline /mnt/root              # persist + executable integrity + aur, no process scan
weird dev offline /mnt/root --limit 500  # hash only the first 500 executables
weird dev offline /mnt/root --json       # {sysroot, sections: {persist, integrity, aur}, findings, counts}
```

`offline SYSROOT` sets the sysroot and runs three parts against the mounted
disk: the persistence sweep (`weird dev persist` with every path under SYSROOT),
integrity of every package-owned executable under SYSROOT/usr/bin and
SYSROOT/usr/lib (pacman mtree or dpkg md5sums, a differing hash is
**critical**, T1554; symlinks and unowned files are counted, not hashed) and
the AUR PKGBUILD checks when a pacman local database exists there (foreign
packages come from that database, never from the running system's
`pacman -Qm`). Findings print per section; the exit code is the usual
2/1/0 over all of them. `/` is refused without `--force`, since the running
system is exactly what this mode is meant to avoid.

## Container-aware provenance

A process in a container (cgroup, marker file, pid namespace, root) used to
stop at CONTAINER. When /proc/PID/root is readable (own user for rootless
containers, root otherwise) weird now runs package provenance against the
package database inside that root: dpkg or pacman of the image, cached once
per container. An executable the image's packages own gets its trust from
that database (evidence `container image package NAME`); one that no package
in the image owns is UNKNOWN with `container_unowned` (+20, T1036,
"not part of container image"), which is what a cryptominer dropped into a
running container looks like. Software installed into the image by pip or npm
is recognised from the metadata those tools leave behind (every file in a
`*.dist-info/RECORD` under the image's site-packages, console scripts under
/usr/local/bin included when their shebang points at a python in the image,
and every file under /usr/local/lib/node_modules) and stays CONTAINER with
evidence `installed in image by pip (NAME VERSION)`. A binary no package or
language manager owns is then checked against the image itself: when podman or
docker is available, `image diff` says whether one of the image's own layers
put the file there (a multi-stage build that compiles a program and copies it
in, as the official chromadb image does) and `diff CONTAINER` says whether it
appeared after the container started. Placed by the image build: CONTAINER, no
score, evidence `put there by the image build`. Added at runtime: still
`container_unowned`, evidence `added after the container started`. No runtime
tool: the old verdict. An unreadable root leaves the
process at CONTAINER with "container provenance unavailable" and no score.
Host processes are unaffected: the sysroot and caches are restored after
each container lookup.

## Fixtures (replaying a live process)

```bash
weird dev fixture record 1234 /tmp/case          # capture PID 1234
weird --proc-root /tmp/case --sysroot /tmp/case/sysroot -v   # replay it anywhere
```

`fixture record` copies the /proc files weird reads for one process (stat,
status, comm, cmdline, maps, environ, cgroup, the exe link target, the fd
listing as symlink targets, the ancestors' stat and comm), the top-level
/proc/stat and pid_max, the /proc/net lines for that process's sockets, a
copy of the executable and the local database entry of every package that
owns the executable or one of its mapped libraries (pacman desc/files/mtree
or dpkg list/md5sums) into DIR. Environment values whose key contains KEY,
TOKEN, SECRET, PASSWORD or API are written as `redacted`. Replaying the tree
reproduces the same trust level, score and reasons, so a captured scenario
can live in CI without shipping anything dangerous.

## Watch mode (no root, no Falco)

`weird watch` polls `/proc` every 2 seconds (`--poll SECONDS` changes that),
keeps the set of processes it has seen keyed by pid and start time, and
scores only the new ones. Every new process with a score above zero or a
memfd/deleted executable is printed as one NDJSON line in the same shape as
`--ndjson`; clean new processes are silent and no process is printed twice.
A reused pid with a different start time counts as new. One line,
`watching /proc every 2 s`, goes to stderr at startup so stdout stays a pure
NDJSON stream for a consumer such as btop. Ctrl-C exits 0.

```bash
weird watch | jq -r '"\(.verdict) \(.name) pid \(.pid): \(.reasons[0])"'
```

`weird watch --falco` keeps the old behaviour and runs Falco in the
foreground with the weird dev rules (needs `/usr/bin/falco` and sudo).

### Real-time events from weird-sensor

The event schema is documented in [events.md](events.md).

[weird-sensor](https://github.com/travershartstone93/weird-sensor) is a small
eBPF program that writes one NDJSON line per exec, exit, memfd_create, ptrace
attach, module load, bpf() call and outbound TCP connect, as root, to
`/run/weird/events.ndjson`. `weird watch --events PATH` tails that file
instead of polling, still unprivileged. When the file was written in the
last two minutes and neither `--poll` nor `--events` is given, `weird watch`
picks it by itself and says so on stderr.

Each exec event is read from `/proc` at once and put through the same
classification and scoring as a scan, so a process is judged before it has
finished its first second, and the alert line has the same shape as poll
mode. A process that exited before `/proc` could be read is dropped unless
the exec path itself was under /tmp, /dev/shm, /var/tmp or deleted; then a
minimal record with reason "short-lived process" (T1036.005, the
suspicious_path score) is printed from the event alone. The other kinds map
to the existing signals on that pid: memfd_create to `memfd_exec` (names
the desktop stack uses, and packaged programs, are not scored), ptrace to
`traced` on the target with the tracer's comm (known debuggers are noted
only), a TCP connect to `raw_ip_outbound` (public IP, non-standard port,
unverified process). Module loads become a `module_load` finding, critical
unless the .ko is owned by a package or built by dkms; BPF program loads
become a `bpf_load` finding, info for a packaged loader, medium otherwise
(both T1014). A `lost` event (ring buffer overflow) runs a full scan and
prints its alerts. Findings carry `kind`, `detail`, `severity`, `attack`;
`--journal` sends alerts and findings to the journal.

Processes are keyed by pid and start time as in poll mode. The sensor sends
the task start as monotonic nanoseconds and its hello line carries the boot
time in epoch seconds, so `boot + start / 1e9` is the same number
`/proc/stat btime + starttime / CLK_TCK` gives a scan (they part only across
a suspend). Keys are forgotten on the exit event and capped at 100k. The
first line must be the hello; a schema other than v1 is refused with exit 3
and a clear message, a missing hello is a warning. A path under /run is
followed like `tail -F` (rotation and truncation reopen the file); any other
path is read to end of file and then weird exits, which is what a recorded
file wants. `--follow` and `--no-follow` override that.

```bash
sudo weird-sensor > /tmp/events.ndjson      # terminal 1
weird watch --events /tmp/events.ndjson     # terminal 2 (add --follow: /tmp is not /run)
cp /usr/bin/sleep /tmp/sshd && /tmp/sshd 30 # terminal 3: the alert appears within the second
```

`weird dev kernel` shows `real-time sensor: active (weird-sensor 0.1.0, schema
v1)` while the file is fresh, reading the version from the hello line.

## Journal and Prometheus output

`--journal` sends each alert to the systemd journal with
`SYSLOG_IDENTIFIER=weird`, `PRIORITY` 2 for critical and 4 for warning, and
the fields `WEIRD_PID`, `WEIRD_NAME`, `WEIRD_SCORE`, `WEIRD_TRUST`,
`WEIRD_ATTACK` (comma separated technique ids) and `WEIRD_VERDICT`. The
`persist`, `hidden`, `kernel` and `aur` subcommands accept it too and log
their non-info findings with `WEIRD_KIND`, `WEIRD_COMMAND`, `WEIRD_SEVERITY`
(medium is priority 4, low is 5). The record is written with the
`systemd.journal` module when it is installed, otherwise straight to the
journald socket, with `systemd-cat` and `logger` as the last fallbacks.

```bash
journalctl -t weird -p warning -o verbose -n 1
```

`--prometheus PATH` writes a node_exporter textfile with `weird_alerts`
by level, `weird_processes_total`, `weird_scan_timestamp_seconds` and
`weird_scan_duration_seconds`; the subcommands write
`weird_findings{command="persist",severity="critical"}` and friends. The
file is written next to PATH and renamed into place, so node_exporter never
reads a half-written file.

## Scheduled scans

The `systemd/` directory ships `weird.service` + `weird.timer` (daily scan
with `--json --journal --prometheus`, every section in one run). They are user units, so
the metrics file lives under `%h/.local/share/node_exporter/` (point
node_exporter at that directory, or edit the path for the system instance
as the comments explain). Install with either

```bash
systemctl --user link "$PWD/systemd/weird.service" "$PWD/systemd/weird.timer"
systemctl --user enable --now weird.timer
```

or

```bash
cp systemd/weird.service systemd/weird.timer ~/.config/systemd/user/
systemctl --user daemon-reload && systemctl --user enable --now weird.timer
```

Exit codes 1 and 2 are listed as `SuccessExitStatus` so a scan that finds
something does not show up as a failed unit. The timer run compares with the
saved baseline and logs the changes to the journal (`WEIRD_COMMAND=changes`)
but never saves one, since a timer that accepted every state would defeat the
comparison; accept a new state by running `weird --save-baseline` yourself. For a desktop notification
after each run:

```bash
weird --journal; notify-send weird "$(journalctl -t weird -p warning -n 1 -o cat)"
```

## Baseline (what changed since last time)

The first interactive run asks once, after the report, "Save this run as the
baseline so future runs show what changed? [Y/n]"; Enter means yes. The
question follows the same rule as the known-bad list question: stdin and
stdout must be a terminal, and it is never asked under `--json`, `--ndjson`,
`watch`, `--no-prompt` or WEIRD_NO_PROMPT. A run without a terminal never
writes a baseline on its own. `weird --save-baseline` writes one without
asking (also when one exists: that is how a new state is accepted);
`--no-baseline` neither compares nor asks. The file is
`~/.config/weird/baseline.json`, 0600, written atomically and ignored with a
warning when world-writable or owned by someone else.

Format, `"version": 2` (a version 1 file, processes only, is still read and
its missing parts are simply not compared):

- `processes`: one entry per process examined (the display filters do not
  apply): `process_key`, `exe_realpath`, `exe_sha256`, `exe_size`,
  `exe_mtime_ns`, `uid`, sanitized `cmdline`, `package`, `manager`,
  `ownership`, `signature`, `trust_level`, an `evidence` snippet.
- `persistence`: one entry per persistence entry: `source`, `file`, `key`,
  `target`, `severity`, `target_sha256`, `target_size`, `target_mtime_ns`.
- `packages`: the foreign (`pacman -Qm`) packages as name to version.
- `posture`: the kernel posture rows (secure boot, lockdown, module loading,
  modules_disabled, sig_enforce, kptr_restrict, unprivileged_bpf_disabled,
  ptrace_scope, core dumps, modprobe helper, kernel cmdline, LKRG).
- `machine_id`, `timestamp`.

With a baseline present the report says which run it compares with ("Compared
with your last run on Oct 6 at 19:57."), lists each change with the other items
under its urgency ("New since your last run: ...", "Changed since your last
run: ..."; info ones with `-v`), and its "Changes" line under "Everything else"
counts them, or reads "Nothing changed since ... (N processes, M persistence
entries, K foreign packages, kernel posture compared)." The changes:

- `new process` (a program not running at the previous run, matched
  by executable path and user, so a second copy of a known program is not
  new): medium for USER_LOCAL, UNKNOWN and container processes, low for a
  LOCAL_BUILD, USER_PKG, Flatpak, Snap or AppImage program, info when
  OFFICIAL, THIRD_PARTY, kernel or trusted.
- `process hash changed` (medium, T1554): the executable on disk is not the
  file the baseline recorded. A file is only re-read when its size or mtime
  moved since the baseline (every file with `--deep`), so a run with a
  baseline costs no more than one without.
- `new persistence entry` (medium) and `persistence entry removed` (info),
  matched by file, key and target; `persistence target changed` (medium,
  T1554) when the launched file's hash moved.
- `new foreign package` (low), `foreign package version` (info) and `foreign
  package removed` (info).
- `posture changed` (medium): a posture row has another value, for example
  kernel module loading went from signed only to open.

The medium and low rows count toward "to look at" in the summary and set the
exit status like any other finding; info rows do not. The baseline is never
updated by a run: after a run with changes the report ends with "baseline from
<date>; run `weird --save-baseline` to accept the current state". `--json`
carries the same rows under `"changes"` (`baseline_timestamp`,
`baseline_date`, `findings`, `counts`); `--journal` logs them with
`WEIRD_COMMAND=changes`. `weird dev baseline init|show|diff` still exist: init
writes the process part (keeping the other parts of an existing file), diff is
the older process-only comparison.

## Baseline trust (a file integrity monitor for what you run)

`weird dev baseline trust <pid|path>` records the executable's realpath,
sha256, package and trust level in `~/.config/weird/trusted.json` (0600,
written atomically, ignored if world-writable or owned by someone else,
like the cache). From then on:

- a process whose executable hash matches an entry is suppressed and tagged
  `trusted` (visible with `-v`);
- a process matching an entry by process key or path whose hash no longer
  matches is not suppressed and gets `trusted_binary_changed` (+30,
  ATT&CK T1554, "trusted binary changed since trust was recorded (date)");
- `weird dev baseline diff` re-hashes every trusted file on disk and lists the
  changed ones under `changed_hash`, whether or not they are running.

`weird dev baseline untrust <path>` removes the entry.

## Weirdness labels (untrusted classes)

For UNKNOWN / UNTRACKED_KEY / USER_LOCAL / USER_PKG / LOCAL_BUILD / APPIMAGE:

- **0**: UNKNOWN (green)
- **1-19**: UNKNOWN (A little weird)
- **20-39**: UNKNOWN (Weird)
- **40-59**: UNKNOWN (Very weird)
- **60+**: UNKNOWN (CRITICAL WEIRDNESS)

Trusted processes that trip suspicious signals (e.g., unusual network activity,
deleted binaries, memfd execution) display "(Maybe Weird)".

The signal `anon_exec_region` (20 points, T1055.009) fires on more than
8 MB of anonymous executable memory in a process that shows no JIT evidence
(browser, node, java, QML, Bun, wasm or JIT thread names, JIT libraries in its
maps, or a JIT engine embedded in its executable).

## Files

- `~/.config/weird/config.toml`: Policy configuration
  (`signals.memfd_allow`: fnmatch patterns for memfd names your own tools
  create, so a known sandbox or telemetry collector stays quiet, for
  example `memfd_allow = ["my-collector*"]`)
- `~/.config/weird/rules.toml`: User rules
- `~/.config/weird/user_trusted.txt`: User trusted list
- `~/.config/weird/cache/file_package_map.json`: File -> package cache
- `~/.config/weird/baseline.json`: the baseline (version 2: processes, persistence entries, foreign packages, posture), 0600
- `~/.config/weird/trusted.json`: Trusted executable hashes (`weird trust`)
- `~/.config/weird/campaigns/`: known-bad AUR list (campaigns.json, the list files it names, meta.json), 0600
- `~/.config/weird/claims.json`: what each unpackaged executable says about its publisher, with its hashes, per path, inode, size, mtime and ctime
- `~/.config/weird/publishers/<host>/`: `gnupg/` keyring (0700), `trust.json` pinned keys, `verified.json` results by file hash, `misses.json` 404s (a day)
- `~/.config/weird/config.toml` also holds `online = true|false`, the stored answer to the one question
- `package.json` (`weirdIntegrity`): sha256 pin of `bin/weird`, refreshed by `scripts/update-pin.py`
- `systemd/weird.service`, `weird.timer`: scheduled daily run
