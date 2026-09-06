import argparse
import importlib.machinery
import importlib.util
import itertools
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, List, Mapping, Optional, Tuple

REPO = Path(__file__).resolve().parent.parent
WEIRD = REPO / "bin" / "weird"

_counter = itertools.count()


def sandbox_root() -> str:
    """A scratch directory that is not under /tmp, for sandboxes whose home paths get scanned."""
    root = REPO / "tests" / ".sandbox"
    root.mkdir(exist_ok=True)
    return str(root)


def load_weird(home: Path, proc_root: Optional[Path] = None, sysroot: Optional[Path] = None) -> Any:
    """Import bin/weird as a fresh module with HOME pointing at a sandbox."""
    home = Path(home)
    home.mkdir(parents=True, exist_ok=True)
    os.environ["HOME"] = str(home)
    os.environ.pop("WEIRD_PROC_ROOT", None)
    os.environ.pop("WEIRD_SYSROOT", None)
    name = f"weird_under_test_{next(_counter)}"
    loader = importlib.machinery.SourceFileLoader(name, str(WEIRD))
    spec = importlib.util.spec_from_file_location(name, WEIRD, loader=loader)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    module.set_roots(str(proc_root) if proc_root else None, str(sysroot) if sysroot else None)
    return module


def scan_args(**overrides) -> argparse.Namespace:
    """Namespace matching what argparse hands to run_scan for a plain `weird`."""
    args = dict(
        verbose=False, all=False, net=False, net_outbound_only=False,
        include_listen=False, enrich_net=False, deep=False, json=False, ndjson=False,
        log_file=None, raw_cmdline=False, debug_log=None,
        proc_root=None, sysroot=None, command=None, baseline_cmd=None,
    )
    args.update(overrides)
    return argparse.Namespace(**args)


def run_cli(args, proc_root=None, sysroot=None, home=None, timeout=300) -> subprocess.CompletedProcess:
    """Run bin/weird as a subprocess for black-box tests."""
    env = dict(os.environ)
    if home is not None:
        env["HOME"] = str(home)
    cmd = [sys.executable, str(WEIRD)]
    if proc_root is not None:
        cmd += ["--proc-root", str(proc_root)]
    if sysroot is not None:
        cmd += ["--sysroot", str(sysroot)]
    cmd += list(args)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)


class FakeRunCommand:
    """Stand-in for weird.run_command that answers only from `table`.

    Keys are the full argv as a tuple, values are stdout (None means the
    command failed). Anything else raises so a test proves no other
    subprocess was needed. `calls` records every argv seen.
    """

    def __init__(self, table: Mapping[Tuple[str, ...], Optional[str]]):
        self.table = table
        self.calls: List[Tuple[str, ...]] = []

    def __call__(self, cmd, timeout=10, check=True) -> Optional[str]:
        key = tuple(cmd)
        self.calls.append(key)
        if key not in self.table:
            raise AssertionError(f"unexpected command: {' '.join(cmd)}")
        return self.table[key]


def fake_run_command(table: Mapping[Tuple[str, ...], Optional[str]]) -> FakeRunCommand:
    return FakeRunCommand(table)


def fake_which(available):
    """Replacement for shutil.which that only knows the given tool names."""
    def which(name, *a, **k):
        return f"/usr/bin/{name}" if name in available else None
    return which
