# thatsweird

Process anomaly detector for Linux. It scans running processes, checks provenance, and scores suspicious behavior so you can focus on what actually looks risky.

## Install
```bash
sudo npm install -g thatsweird
```

## Requires
Python 3.8+ on the target system.

## Quick start
```bash
weird              # Scan for suspicious processes
```

**Make sure terminal window is big enough to see full table**

## Options

weird -v           # Verbose output (show all processes)
weird --net        # Show networked processes
weird --json       # JSON output for scripting
weird inspect 1234 # Deep dive on a PID
weird man          # Manual page

## What it does

- Verifies process provenance (package manager ownership + signature evidence)
- Detects suspicious behaviors (memfd execution, deleted binaries, odd paths, network exposure, etc.)
- Computes a weirdness score so high‑risk items bubble up
- Labels trust levels (OFFICIAL, UNKNOWN, USER_TRUSTED, etc.)
- Tries to identify UNKNOWN processes via man pages and registry lookups

## How descriptions are generated (flow + fallbacks)

When a process is UNKNOWN, weird tries to add a human‑readable description using this chain:

1) **Man page lookup (local, fast)**  
   If a man page exists for the process name, the tool extracts the NAME or DESCRIPTION section.

2) **Registry lookup (best effort, network)**  
   If there is no man page result, it infers the ecosystem from the process path/parent/cmdline:
   - Node → npm registry  
   - Python → PyPI  
   - Rust/Go/other → GitHub search  
   This yields a package name, short description, and URL (when available).

3) **Final fallback**  
   If nothing can be identified, the table shows **“Likely Malware”** for UNKNOWN processes.

### Network inspection (what it actually does)

weird does **not** sniff packet contents. It builds a process‑to‑socket view using:

- `ss` (preferred) or `/proc/net` as a fallback
- Outbound connections by default

## Trust levels (provenance, not security)

- **OFFICIAL** — Signed distro repository
- **THIRD_PARTY** — APT package signed by a non‑distro key
- **UNTRACKED_KEY** — Trusted key of unclear origin
- **USER_LOCAL** — User‑installed binary (e.g., `/usr/local` or `~/.local`)
- **APPIMAGE** — Portable app without sandboxing
- **FLATPAK / SNAP / CONTAINER / KERNEL / USER_TRUSTED / UNKNOWN** — Other provenance classes

Even OFFICIAL packages can be compromised. Treat trust as provenance only.

## Weirdness labels (untrusted classes)

For UNKNOWN / UNTRACKED_KEY / USER_LOCAL / APPIMAGE:

- **0** — UNKNOWN (green)
- **1–19** — UNKNOWN (A little weird)
- **20–39** — UNKNOWN (Weird)
- **40–59** — UNKNOWN (Very weird)
- **60+** — UNKNOWN (CRITICAL WEIRDNESS)

Trusted processes that trip suspicious signals (e.g., unusual network activity,
deleted binaries, memfd execution) display “(Maybe Weird)”.

## Example output

```
    PID    SCORE  TRUST LEVEL                                 NAME                DESCRIPTION
--------------------------------------------------------------------------------------------------------------
  12345   75/100  UNKNOWN (CRITICAL WEIRDNESS)                suspicious          Likely Malware
   5432   20/100  USER_LOCAL (Weird)                          mytool              (no description)
    847   10/100  OFFICIAL (Maybe Weird)                      avahi-daemon        avahi-daemon - The Avahi mDNS/DNS-SD daemon
```

## Commands

```text
weird [-v] [-a] [--net] [--net-outbound-only]
      [--include-listen] [--enrich-net]
      [--json | --ndjson]
      [--log-file FILE]
      [--raw-cmdline]
      [--debug-log FILE]
weird inspect PID
weird trust NAME_OR_PATH
weird rules [show | init [--force]]
weird cache [--rebuild]
weird baseline init | show | diff
weird watch
weird falco-rules
weird man
```

## Files

- `~/.config/weird/config.toml` — Policy configuration
- `~/.config/weird/rules.toml` — User rules
- `~/.config/weird/user_trusted.txt` — User trusted list
- `~/.config/weird/cache/file_package_map.json` — File → package cache
- `~/.config/weird/baseline.json` — Baseline data

## Help

```bash
weird --help
weird man
```

## License

MIT
