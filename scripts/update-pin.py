#!/usr/bin/env python3
"""Record the sha256 of bin/weird as the weirdIntegrity pin in package.json.

Run after every intended change to bin/weird, before a release:

    python3 scripts/update-pin.py [REPO_DIR]

REPO_DIR defaults to the checkout this script lives in. The pin carries the
package.json version so a stale pin can be told apart from a tampered script.
The pip package reads its version from __version__ in bin/weird, so the two
must agree; this script refuses to pin while they differ.
"""
import hashlib
import json
import re
import sys
from pathlib import Path


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def script_version(script: Path) -> str:
    m = re.search(r'^__version__ = "([^"]+)"', script.read_text(), re.M)
    return m.group(1) if m else ""


def update_pin(repo: Path) -> dict:
    package_json = repo / "package.json"
    script = repo / "bin" / "weird"
    data = json.loads(package_json.read_text())
    version = script_version(script)
    if version and version != str(data.get("version", "")):
        raise SystemExit(f"version mismatch: bin/weird says {version}, package.json says {data.get('version')}")
    pin = {"sha256": sha256_of(script), "version": str(data.get("version", ""))}
    data["weirdIntegrity"] = pin
    package_json.write_text(json.dumps(data, indent=2) + "\n")
    return pin


def main() -> int:
    repo = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
    if not (repo / "bin" / "weird").is_file() or not (repo / "package.json").is_file():
        print(f"{repo} does not contain bin/weird and package.json", file=sys.stderr)
        return 1
    pin = update_pin(repo)
    print(f"pinned bin/weird sha256 {pin['sha256']} (version {pin['version']}) in {repo / 'package.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
