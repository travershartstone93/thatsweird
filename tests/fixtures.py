"""Builders for fake /proc trees and package databases used by the tests."""
import gzip
import hashlib
import os
import time
from pathlib import Path
from typing import Dict, Iterable, Optional, Sequence, Tuple

CLK_TCK = 100
TCP_STATES = {"ESTABLISHED": "01", "SYN_SENT": "02", "LISTEN": "0A", "TIME_WAIT": "06"}
STUB = b"#!/bin/sh\nexit 0\n"


def _write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data)


def mtree_escape(name: str) -> str:
    """Spaces the way libarchive writes them in pacman mtree files (\\040)."""
    return name.replace("\\", "\\134").replace(" ", "\\040")


def make_stub_file(sysroot: Path, host_path: str, content: bytes = STUB) -> Path:
    """Create an executable stub at sysroot/<host_path> and return it."""
    target = Path(sysroot) / host_path.lstrip("/")
    _write(target, content)
    target.chmod(0o755)
    return target


def make_pacman_pkg(sysroot, name: str, version: str, files: Sequence[str],
                    validation: Optional[str] = "pgp",
                    packager: str = "Arch Linux <arch@example.org>",
                    installdate: Optional[int] = None, desc: str = "",
                    hashes: bool = True, builddate: Optional[int] = None,
                    contents: Optional[Dict[str, bytes]] = None) -> Path:
    """Write var/lib/pacman/local/<name>-<version>/{desc,files,mtree} and the files themselves.

    `files` are absolute host paths. validation=None leaves %VALIDATION% out,
    which is what older databases look like. `contents` maps a path to the
    bytes to write there instead of the default stub.
    """
    sysroot = Path(sysroot)
    if installdate is None:
        installdate = int(time.time()) - 86400
    if builddate is None:
        builddate = installdate - 3600
    pkgdir = sysroot / "var/lib/pacman/local" / f"{name}-{version}"
    pkgdir.mkdir(parents=True, exist_ok=True)

    sections = [
        ("NAME", name), ("VERSION", version), ("BASE", name),
        ("DESC", desc or f"{name} test package"), ("URL", f"https://example.org/{name}"),
        ("ARCH", "x86_64"), ("BUILDDATE", str(builddate)), ("INSTALLDATE", str(installdate)),
        ("PACKAGER", packager), ("SIZE", "4096"), ("REASON", "1"), ("LICENSE", "GPL-3.0-or-later"),
    ]
    if validation is not None:
        sections.append(("VALIDATION", validation))
    sections.append(("XDATA", "pkgtype=pkg"))
    _write(pkgdir / "desc", "".join(f"%{k}%\n{v}\n\n" for k, v in sections))

    rel_files = [f.lstrip("/") for f in files]
    dirs = set()
    for rel in rel_files:
        parent = os.path.dirname(rel)
        while parent:
            dirs.add(parent + "/")
            parent = os.path.dirname(parent)
    entries = sorted(dirs | set(rel_files))
    _write(pkgdir / "files", "%FILES%\n" + "".join(e + "\n" for e in entries) + "\n")

    lines = ["#mtree", "/set type=file uid=0 gid=0 mode=644"]
    for entry in entries:
        if entry.endswith("/"):
            lines.append(f"./{mtree_escape(entry[:-1])} time={builddate}.0 mode=755 type=dir")
            continue
        stub = make_stub_file(sysroot, "/" + entry, (contents or {}).get("/" + entry, STUB))
        data = stub.read_bytes()
        line = f"./{mtree_escape(entry)} time={builddate}.0 mode=755 size={len(data)}"
        if hashes:
            line += f" md5digest={hashlib.md5(data).hexdigest()}"
            line += f" sha256digest={hashlib.sha256(data).hexdigest()}"
        lines.append(line)
    with gzip.open(pkgdir / "mtree", "wt") as f:
        f.write("\n".join(lines) + "\n")
    return pkgdir


def make_pacman_conf(sysroot, siglevel: str = "Required DatabaseOptional",
                     localfilesiglevel: str = "Optional",
                     repos: Iterable[str] = ("core", "extra")) -> Path:
    conf = Path(sysroot) / "etc/pacman.conf"
    text = "[options]\nHoldPkg = pacman glibc\nArchitecture = auto\n"
    text += f"SigLevel = {siglevel}\nLocalFileSigLevel = {localfilesiglevel}\n\n"
    for repo in repos:
        text += f"[{repo}]\nInclude = /etc/pacman.d/mirrorlist\n\n"
    _write(conf, text)
    return conf


def make_apt_pkg(sysroot, name: str, files: Sequence[str], version: str = "1.0-1",
                 desc: str = "", hashes: bool = True) -> Path:
    """Minimal dpkg equivalent: a status stanza plus info/<name>.{list,md5sums}."""
    sysroot = Path(sysroot)
    status = sysroot / "var/lib/dpkg/status"
    status.parent.mkdir(parents=True, exist_ok=True)
    stanza = (
        f"Package: {name}\nStatus: install ok installed\nPriority: optional\n"
        f"Section: utils\nInstalled-Size: 100\nMaintainer: Test <test@example.org>\n"
        f"Architecture: amd64\nVersion: {version}\nDescription: {desc or name + ' test package'}\n\n"
    )
    with open(status, "a") as f:
        f.write(stanza)
    listed = ["/."]
    for path in files:
        parent = os.path.dirname(path)
        parts = []
        while parent and parent != "/":
            parts.append(parent)
            parent = os.path.dirname(parent)
        for p in reversed(parts):
            if p not in listed:
                listed.append(p)
        listed.append(path)
        make_stub_file(sysroot, path)
    info = sysroot / "var/lib/dpkg/info" / f"{name}.list"
    _write(info, "".join(p + "\n" for p in listed))
    if hashes:
        sums = ""
        for path in files:
            data = (sysroot / path.lstrip("/")).read_bytes()
            sums += f"{hashlib.md5(data).hexdigest()}  {path.lstrip('/')}\n"
        _write(info.with_suffix(".md5sums"), sums)
    return info


def make_proc_root(proc_root, btime: Optional[int] = None) -> Path:
    """Write the top-level /proc files the scanner needs (stat with btime, pid_max)."""
    proc_root = Path(proc_root)
    if btime is None:
        btime = int(time.time()) - 86400
    if not (proc_root / "stat").exists():
        _write(proc_root / "stat",
               "cpu  1000 0 500 100000 10 0 5 0 0 0\n"
               "intr 0\nctxt 0\n"
               f"btime {btime}\n"
               "processes 100\nprocs_running 1\nprocs_blocked 0\n")
    if not (proc_root / "sys/kernel/pid_max").exists():
        _write(proc_root / "sys/kernel/pid_max", "4194304\n")
    return proc_root


def _hex_addr(addr: str, port: int) -> str:
    """IPv4 address:port the way /proc/net/tcp prints it (host byte order hex)."""
    octets = [int(o) for o in addr.split(".")]
    return "".join(f"{o:02X}" for o in reversed(octets)) + f":{port:04X}"


def make_connections(proc_root: Path, pid: int, uid: int,
                     connections: Sequence[Tuple[str, int, str]]) -> None:
    """Append (remote_ip, remote_port, state) sockets to net/tcp and link them from <pid>/fd."""
    net_tcp = proc_root / "net/tcp"
    if not net_tcp.exists():
        _write(net_tcp, "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt"
                        "   uid  timeout inode\n")
    fd_dir = proc_root / str(pid) / "fd"
    fd_dir.mkdir(parents=True, exist_ok=True)
    with open(net_tcp, "a") as f:
        for i, (addr, port, state) in enumerate(connections):
            inode = pid * 100 + i + 1
            f.write(f"{i:4d}: {_hex_addr('10.0.0.2', 40000 + i)} {_hex_addr(addr, port)} {TCP_STATES[state]} "
                    f"00000000:00000000 00:00000000 00000000 {uid:8d}        0 {inode} 1 0000000000000000 "
                    f"100 0 0 10 0\n")
            os.symlink(f"socket:[{inode}]", fd_dir / str(3 + i))


def make_proc(proc_root, pid: int, exe: str, comm: Optional[str] = None,
              cmdline: Optional[Sequence[str]] = None, ppid: int = 1, uid: int = 1000,
              deleted: bool = False, memfd: Optional[str] = None,
              maps: Sequence[str] = (), status_extra: Optional[Dict[str, str]] = None,
              environ: Optional[Dict[str, str]] = None,
              cgroup: str = "0::/user.slice/user-1000.slice/session-2.scope",
              starttime: Optional[int] = None, rss_kb: int = 4096, tty_nr: int = 0,
              connections: Sequence[Tuple[str, int, str]] = ()) -> Path:
    """Write /proc/<pid>/{stat,status,comm,cmdline,maps,environ,cgroup,exe}.

    `starttime` is in clock ticks since boot (field 22 of stat). `status_extra`
    overrides or adds status fields (TracerPid, CapEff, ...). `connections` are
    (remote_ip, remote_port, state) TCP sockets written to net/tcp and <pid>/fd.
    """
    proc_root = make_proc_root(proc_root)
    d = proc_root / str(pid)
    d.mkdir(parents=True, exist_ok=True)

    if comm is None:
        comm = os.path.basename(exe)[:15]
    if cmdline is None:
        cmdline = [exe]
    if starttime is None:
        starttime = CLK_TCK
    if memfd is not None:
        target = f"/memfd:{memfd} (deleted)"
    elif deleted:
        target = f"{exe} (deleted)"
    else:
        target = exe

    fields = [str(pid), f"({comm})", "S", str(ppid), str(pid), str(pid), str(tty_nr), "-1",
              "4194304", "0", "0", "0", "0", "0", "0", "0", "0", "20", "0", "1", "0",
              str(starttime), str(rss_kb * 1024 * 4), str(rss_kb // 4)]
    fields += ["0"] * (52 - len(fields))
    _write(d / "stat", " ".join(fields) + "\n")

    status = {
        "Name": comm, "Umask": "0022", "State": "S (sleeping)", "Tgid": str(pid), "Ngid": "0",
        "Pid": str(pid), "PPid": str(ppid), "TracerPid": "0",
        "Uid": f"{uid}\t{uid}\t{uid}\t{uid}", "Gid": f"{uid}\t{uid}\t{uid}\t{uid}",
        "FDSize": "64", "Groups": "", "VmRSS": f"{rss_kb} kB", "Threads": "1",
    }
    status.update(status_extra or {})
    _write(d / "status", "".join(f"{k}:\t{v}\n" for k, v in status.items()))

    _write(d / "comm", comm + "\n")
    _write(d / "cmdline", b"\x00".join(a.encode() for a in cmdline) + b"\x00")
    if not maps:
        maps = [
            f"5648cf883000-5648cf885000 r--p 00000000 00:23 1725820                    {target}",
            f"5648cf885000-5648cf890000 r-xp 00002000 00:23 1725820                    {target}",
            "7ffd0d3e5000-7ffd0d406000 rw-p 00000000 00:00 0                          [stack]",
            "7ffd0d5c3000-7ffd0d5c5000 r-xp 00000000 00:00 0                          [vdso]",
        ]
    _write(d / "maps", "\n".join(maps) + "\n")
    env = environ if environ is not None else {"HOME": f"/home/user{uid}", "PATH": "/usr/bin"}
    _write(d / "environ", b"".join(f"{k}={v}".encode() + b"\x00" for k, v in env.items()))
    _write(d / "cgroup", cgroup + "\n")

    link = d / "exe"
    if link.is_symlink():
        link.unlink()
    os.symlink(target, link)
    if connections:
        make_connections(proc_root, pid, uid, connections)
    return d
