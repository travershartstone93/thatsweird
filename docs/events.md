# weird-sensor event stream

[weird-sensor](https://github.com/travershartstone93/weird-sensor) is a
small eBPF program (C, libbpf, CO-RE) that runs as root and writes one JSON
object per line to `/run/weird/events.ndjson`. It emits and never reads.
`weird watch --events PATH` consumes the file without privileges and turns
each event into the same alert shape a scan produces.

## Common fields

Every line carries these keys.

| Field | Meaning |
| --- | --- |
| `v` | schema version; weird understands `1` and exits 3 on anything else |
| `ts` | monotonic nanoseconds when the event was recorded |
| `kind` | one of `hello`, `exec`, `exit`, `memfd`, `ptrace`, `module`, `bpf`, `connect`, `lost` |
| `pid`, `tgid`, `ppid` | task id, thread group (process) id, parent process id |
| `uid`, `gid` | credentials of the task |
| `comm` | the 16 byte task name |

## Per kind

| Kind | Extra fields | What weird does with it |
| --- | --- | --- |
| `hello` | `wall` and `boot` (epoch seconds), `release` (uname -r), `sensor` (sensor version) | must be the first line; `boot` converts every `start` into the same key a scan computes from /proc/stat btime |
| `exec` | `path`, `argv0`, `start` (task start, monotonic ns) | the process is read from /proc at once and classified and scored like a scan; a process already gone is printed only when `path` was under /tmp, /dev/shm, /var/tmp or deleted ("short-lived process", T1036.005) |
| `exit` | `code` | the pid and start key is forgotten so a reused pid counts as new |
| `memfd` | `name`, `flags` | adds `memfd_exec` to that pid; names the desktop stack uses, and packaged programs, are not scored |
| `ptrace` | `request`, `target` | adds `traced` to the target with the tracer's comm; known debuggers are noted only |
| `module` | `name` | prints a `module_load` finding: critical unless the .ko is owned by a package or built by dkms (T1014) |
| `bpf` | `cmd`, `prog_type` | prints a `bpf_load` finding: info for a packaged loader, medium otherwise (T1014) |
| `connect` | `family`, `daddr`, `dport` | adds `raw_ip_outbound` when the address is public, the port non-standard and the process unverified |
| `lost` | `count` (events dropped by the ring buffer) | runs a full scan and prints its alerts |

Findings (module and bpf) carry `kind`, `detail`, `severity` and `attack`;
alerts carry the `--ndjson` fields (`pid`, `name`, `score`, `trust_level`,
`verdict`, `reasons`, `attack`). `--journal` sends both to the systemd
journal.

## Keys and timing

Processes are keyed by pid and start time. The sensor reports the task start
as monotonic nanoseconds and its hello carries the boot time in epoch
seconds, so `boot + start / 1e9` equals `btime + starttime / CLK_TCK` from
/proc; the two only drift across a suspend. Keys are dropped on `exit` and
capped at 100k entries.

## Following the file

A path under /run is followed like `tail -F` (rotation and truncation reopen
the file). Any other path is read to end of file and then weird exits, which
is what a recorded file wants. `--follow` and `--no-follow` override that.
When `/run/weird/events.ndjson` was written in the last 120 seconds and
neither `--poll` nor `--events` is given, `weird watch` picks it by itself.

## Recorded samples

`tests/fixtures/events/` holds one file per kind. Each starts with a hello
line and can be replayed with `weird watch --events tests/fixtures/events/memfd.ndjson`.
