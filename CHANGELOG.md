# Changelog

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
