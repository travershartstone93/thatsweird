"""Console script entry for pip and pipx installs.

The program is the single file bin/weird. A wheel carries a copy of it (and of
package.json and man/weird.1) inside this package; a source checkout or an
editable install finds it one directory up. Either way the file that runs is
the one the self-integrity pin describes.
"""
import importlib.machinery
import importlib.util
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
CANDIDATES = (_HERE / "weird", _HERE.parent / "bin" / "weird")


def load():
    for path in CANDIDATES:
        if path.is_file():
            loader = importlib.machinery.SourceFileLoader("weird", str(path))
            spec = importlib.util.spec_from_file_location("weird", path, loader=loader)
            module = importlib.util.module_from_spec(spec)
            sys.modules["weird"] = module
            loader.exec_module(module)
            return module
    raise SystemExit("weird: bin/weird not found next to weird_cli")


def main():
    sys.exit(load().main())
