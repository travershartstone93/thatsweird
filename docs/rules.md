# Rules

`~/.config/weird/rules.toml` adjusts what the scanner reports without
touching the code. `weird rules init` writes a commented template there,
`weird rules show` prints it, and `weird rules show --defaults` prints the
built-in rules that run before your file.

## Shape

```toml
defaults = true          # false switches the built-in rules off

[[allow]]
name = { equals = "bash" }

[[rules]]
id = "shell-from-pdf-viewer"
name = { regex = "^(bash|sh|curl|wget)$" }
parent = { regex = "^(evince|okular|zathura)$" }
action = "upgrade"
add = 30
attack = "T1204.002"
```

Every `[[rules]]` table is one rule. All matchers present in a rule must
match for the action to apply; rules are applied in file order.

## Matchers

| Matcher | Matches against | Form |
| --- | --- | --- |
| `name` | the process comm | string, or a table with `equals`, `contains` or `regex` |
| `path` | the executable path | same |
| `cmdline` | the sanitised command line | same |
| `uid` | the owning uid | exact integer |
| `manager` | the package manager that owns the executable (`pacman`, `dpkg`, `uv`, `npm` and so on) | exact string |
| `package` | the owning package | exact string |
| `trust_level` | `OFFICIAL`, `USER_LOCAL`, `USER_PKG`, `LOCAL_BUILD`, `UNKNOWN` and the rest | exact string |
| `parent` | any ancestor comm, up to six levels up the ppid chain read from /proc/PID/stat | string or table as for `name` |
| `direct_parent` | the comm of the immediate parent only | string or table |

A ppid chain that ends early (an ancestor exited, or its stat is unreadable)
simply does not match.

## Actions

| Action | Effect |
| --- | --- |
| `suppress` | hide the process unless `-v` is given; `tag = "label"` shows why under `-v` |
| `downgrade` | drop the score to zero |
| `upgrade` | add `add = N` points; `attack = "T1234"` records a technique on the reason |
| `tag` | label the row with `tag = "label"` and change nothing else |

`id = "label"` names the rule in the reasons list so a hit reads
`rule shell-from-pdf-viewer (+30) [T1204.002]` instead of an anonymous line.

## Built-in rules

Printed by `weird rules show --defaults`. They cover two cases that every
Arch desktop hits: a build running under makepkg, paru, yay, pikaur or
aurutils is suppressed and tagged `build`, and a shell, interpreter, curl or
wget whose ancestor is a browser, PDF viewer, office suite or mail client
gains 30 points (T1204.002, user execution). `defaults = false` in
rules.toml turns them off.

## Profiles

`[profiles.NAME]` tables hold their own `allow` and `rules` lists. The
`default` profile is used unless the config selects another one.
