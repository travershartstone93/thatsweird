# Changelog

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
