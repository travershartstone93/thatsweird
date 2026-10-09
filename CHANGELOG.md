# Changelog

## 1.4.0

Later in 1.4.0: the known-bad list is fetched once, up front, and tries every
address DNS returns so a dead IPv6 route falls through to IPv4; `--fetch-campaigns`
and `--campaigns` work on the main command. A container binary that no package
owns is now attributed through the image's own layers (podman or docker image
diff), so a program compiled and copied in by the image build counts as part of
the image and only a file added after the container started is scored.

A baseline by default. On a terminal the first run asks once, after the
report, whether to save it as the baseline (Enter means yes; the file is
~/.config/weird/baseline.json, 0600, and nothing leaves the machine). Every
later run opens with a "Changes since <date>" section: programs that were not
running when the baseline was saved (matched by executable path and user;
medium when unpackaged or unknown, low for a locally built or language-manager
package, info when OFFICIAL), executables whose hash moved (re-read only when
size or mtime changed, every file with `--deep`), persistence entries added
(medium) or removed (info) and targets whose hash moved, foreign packages
added (low), removed or rebuilt (info), and kernel posture rows that changed
(medium). Medium and low rows count toward "to look at" and the exit status.
The baseline is never updated on its own: `--save-baseline` records the
current state without asking and `--no-baseline` skips the comparison. A run
without a terminal, or under `--json`, `--ndjson`, `--no-prompt` or
WEIRD_NO_PROMPT, never asks and never writes one; the shipped timer keeps
comparing and logs the changes to the journal. The file is version 2
(processes with size and mtime, persistence entries with target hashes,
foreign packages with versions, posture rows); a version 1 file is still read.
`--json` carries the rows under "changes". `weird dev baseline init` writes
the process part only.

A progress line on stderr ("checking hidden processes... 3s", naming every
section still running) while the report is being built, only when stderr is a
terminal and never under `--json`. Ctrl-C prints the sections that finished,
"interrupted during <section>" and a summary marked "(partial)", and exits
130; under `--json` the partial document is still valid JSON with an
"interrupted" key. The section threads are daemon threads, so an interrupted
run does not wait for them.

## 1.3.0

Faster and quieter. The default hidden-process probe stops a margin above the
last pid the kernel assigned (the last field of /proc/loadavg, or the highest
listed pid), since a hidden process is already running and so already has a
pid at or below that mark; `--deep` keeps the exhaustive sweep up to pid_max.
The AUR, persistence and kernel sections run in threads while the process
scan runs, with the report printed in the same fixed order, so a full run on a
laptop went from about 23 s to about 5 s and `--skip hidden` to about 4 s.

The persistence section has a "yours" tier: a target under your own home
launched by your own unit, rc file or ssh config is your own unpackaged
software and is info, listed with `-v`, until a second signal appears (a unit
under /etc or /usr pointing into your home, a restart loop through an
unpackaged interpreter, a temp directory, a changed packaged file). A unit
under /etc/systemd/system that points at an unpackaged file under /usr/local
stays medium and says "system-wide persistence of unpackaged code". The
summary line now reads "N to look at (c critical, m medium, l low), M entries
are your own unpackaged software, I info (exit E)"; only "to look at" sets the
exit status, and the JSON summary has a "yours" key. The persistence count
line and counts split the same way, and each entry carries "yours" in JSON.

The one-command report starts at the first section header: the security
banner and the "Scanning processes..." line print with `-v` and in `weird dev
scan`, a section with nothing to show prints one "nothing to report" line, the
kernel posture rows and info notes appear with `-v`, and a clean report fits
on one screen. A GitHub name match no longer says "possible match" twice, and
an unpackaged binary with no description is described by where it lives and
when it was installed ("unpackaged, ~/.local/share/claude (2026-10-05)").

## 1.2.0

One command. Plain `weird` now runs the process scan, the AUR package checks,
the persistence entries, the kernel posture report, the stale binaries and
the hidden-process cross-views in one report with one summary line and one
exit code (0 clean, 1 medium or warning, 2 critical, 3 a collector failed).
`--skip SECTION` leaves a section out and `--json` prints one object with a
key per section. The verbs that stay at the top level are `weird PID`,
`weird PATH`, `weird trust`, `weird untrust` and `weird watch`; the single
sections and the developer commands (`scan`, `persist`, `hidden`, `kernel`,
`aur`, `restart-needed`, `self-check`, `offline`, `baseline`, `rules`,
`cache`, `fixture`, `completions`, `man`, `falco-rules`) moved under
`weird dev`, and `--help` fits on one screen. `systemd/` ships one daily
timer for the full run.

New checks, all without root. Persistence now reports a file in a
user-writable PATH directory that shadows a system binary, authorized_keys
entries with forced commands or options, and restart loops (a unit with
Restart=always and a short RestartSec keeping an unpackaged file alive). The
kernel posture report gained rows for kernel.core_pattern piped to a handler,
the kernel.modprobe helper path and kernel cmdline flags that turn audit,
lockdown or IMA off, and when module loading is open it names ghostscan as
the root-level check to run. The hidden section asks for every pid a second
way, through getpgid(), and reads /proc/self/mountinfo for bind mounts placed
over /proc/<pid>. The process scan flags large anonymous executable regions
in a program with no JIT. The AUR section reads /var/log/pacman.log (and its
rotated copies) for install history and scans the npm, bun, pnpm and yarn
caches for packages fetched during an AUR build.

Known-bad list. Foreign package names are matched against the campaign lists
from aur-malware-check; an installed package on a list is critical. weird
never fetches the list on its own: on a terminal, when the list is missing or
older than seven days, it asks one [y/N] question, and it never asks without
a terminal, under `--json` or `--ndjson`, in watch mode, on the timer or with
`--no-prompt` or WEIRD_NO_PROMPT. `weird dev aur --campaigns PATH` takes a
file you supply.

The principle behind the release is written up in the README: weird never
asks for root, because a detection tool must have less power than what it
hunts, so running it is never itself the compromise. Root-level checks stay a
recommendation or the separate opt-in weird-sensor. Credit where the ideas
came from: the PATH shadowing, authorized_keys, core_pattern, modprobe,
cmdline, second pid probe and /proc bind mount checks are the unprivileged
ideas from ghostscan (github.com/aidlx/ghostscan), carried over
without the root-only kernel scanners; the campaign lists and the idea of
checking installed packages against them come from aur-malware-check
(github.com/lenucksi/aur-malware-check).

## 1.1.0

The scanner now applies the package's own install-time hash to every flagged
executable (and to every packaged one with `--deep`), reads /proc/PID/maps
for injected or unowned executable mappings, and reads the environment for
anti-forensics and interpreter hooks. Verdicts (Unverified, Suspicious,
Likely malicious) replace the bare score in the table, and every reason
carries its MITRE ATT&CK id in text and JSON. Software installed by uv,
pipx, npm, cargo, rustup, go or nvm is recognised from its own metadata
(USER_PKG) and packages built with makepkg are LOCAL_BUILD, so a developer
desktop no longer fills the table with UNKNOWN rows. Processes still running
a file that an upgrade replaced are marked stale instead of deleted.

New subcommands: `restart-needed` (stale processes grouped by systemd unit),
`persist` (units, cron, autostart, shell rc, ld.so.preload, udev, pacman
hooks and makepkg.conf, each target checked for provenance), `hidden`
(processes, threads and sockets compared across two views), `kernel`
(module cross-view, module ownership, taint and a hardening posture block),
`aur` (PKGBUILD supply chain checks behind locally built packages),
`offline` (persistence, executable integrity and aur against a mounted
disk from live media), `self-check` (own-process checks and the script's
sha256 against the pin in package.json), `fixture record` (capture a live
process for replay with `--proc-root` and `--sysroot`) and `completions`
(bash and fish scripts generated from the command tree).

`weird watch` polls /proc without root and prints one NDJSON line per new
flagged process; `--events PATH` consumes the weird-sensor eBPF stream
instead and judges a process within its first second. `--journal` and
`--prometheus PATH` send alerts to journald and node_exporter, and the
`systemd/` directory ships timer units for scheduled scans. `baseline trust`
records an executable's hash so scans stay quiet until the file changes.
Processes inside containers get provenance from the image's own package
database. Rules gain `parent`, `direct_parent`, `id` and `attack`, plus
built-in rules for package builds and shells spawned by document viewers.

Packaging: `pip install .` and `pipx install` give a `weird` console script
through a small `weird_cli` shim that runs the same `bin/weird` the npm
package ships; `--version` prints the version; the test suite (emulation
with real decoys, Arch and Debian shaped fixtures) runs in CI on Ubuntu with
Python 3.12 and 3.13 and in an Arch Linux container.

## 1.0.4

The npm release: scan with the provenance and trust model, `inspect`,
`trust`, `rules`, `cache`, `baseline`, `watch --falco`, `falco-rules` and
`man`, with `--json` and `--ndjson` output.
