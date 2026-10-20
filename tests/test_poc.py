import base64
import importlib.util
import json
import os
import pathlib
import pty
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("normalize", ROOT / "src/normalize.py")
normalizer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(normalizer)


class NormalizerTests(unittest.TestCase):
    def test_all_sources_have_canonical_fields(self):
        for line in (ROOT / "examples/events.jsonl").read_text().splitlines():
            item = json.loads(line)
            e = normalizer.normalize(item["source"], item["event"])
            self.assertEqual(e["schema_version"], "1.0")
            self.assertTrue(e["action"])
            self.assertTrue(e["event_id"])
            self.assertIn("correlation_id", e)
            again = normalizer.normalize(item["source"], item["event"])
            self.assertEqual(e["event_id"], again["event_id"])
            self.assertEqual(e["action"], again["action"])

    def test_k8s_exec_identity(self):
        item = json.loads((ROOT / "examples/events.jsonl").read_text().splitlines()[3])
        e = normalizer.normalize(item["source"], item["event"])
        self.assertEqual((e["actor"]["user"], e["pod"], e["namespace"], e["correlation_id"]),
                         ("alice", "web", "default", "audit-uuid"))

    def test_unset_audit_login_id_is_unknown(self):
        e = normalizer.normalize("auditd", {"auid": "4294967295", "uid": "0", "syscall": "execve"})
        self.assertIsNone(e["actor"]["user"])
        self.assertIsNone(e["time"])


class BashProfileTests(unittest.TestCase):
    def test_interactive_shell_records_and_noninteractive_does_not(self):
        with tempfile.TemporaryDirectory() as d:
            log = pathlib.Path(d) / "events.jsonl"
            log.touch()
            rc = pathlib.Path(d) / "bashrc"
            rc.write_text(f"source {ROOT / 'scripts/bash_audit.sh'}\n")
            env = os.environ.copy()
            env.update(INFRA_AUDIT_SINK_FILE=str(log), INFRA_AUDIT_POD="pod-a",
                       INFRA_AUDIT_NAMESPACE="ns-a", PS1="AUDIT> ")
            master, slave = pty.openpty()
            try:
                proc = subprocess.Popen(["bash", "--noprofile", "--rcfile", str(rc), "-i"],
                                        stdin=slave, stdout=slave, stderr=slave, env=env)
                os.close(slave)
                time.sleep(0.2)
                os.write(master, b"echo audit-poc-marker\nexit\n")
                proc.wait(timeout=5)
            finally:
                os.close(master)
            events = [json.loads(x)["event"] for x in log.read_text().splitlines()]
            commands = [base64.b64decode(e["command_b64"]).decode() for e in events]
            self.assertIn("echo audit-poc-marker", commands)
            self.assertEqual(events[0]["pod"], "pod-a")
            self.assertEqual(events[0]["namespace"], "ns-a")
            self.assertTrue(events[0]["time"].endswith("Z"))
            self.assertTrue(events[0]["session_id"])
            log.write_text("")
            env["BASH_ENV"] = str(ROOT / "scripts/bash_audit.sh")
            subprocess.run(["bash", "-c", "echo noninteractive"], env=env,
                           check=True, stdout=subprocess.DEVNULL)
            self.assertEqual(log.read_text(), "")

    def test_noprofile_norc_bypasses_script(self):
        with tempfile.TemporaryDirectory() as d:
            log = pathlib.Path(d) / "events.jsonl"
            log.touch()
            env = os.environ.copy()
            env["INFRA_AUDIT_SINK_FILE"] = str(log)
            subprocess.run(["bash", "--noprofile", "--norc", "-c", "echo bypass"],
                           env=env, check=True, stdout=subprocess.DEVNULL)
            self.assertEqual(log.read_text(), "")

    def test_explicit_syslog_mode_uses_logger(self):
        with tempfile.TemporaryDirectory() as d:
            rc = pathlib.Path(d) / "bashrc"
            rc.write_text(f"source {ROOT / 'scripts/bash_audit.sh'}\n")
            fake = pathlib.Path(d) / "logger"
            captured = pathlib.Path(d) / "logger-args"
            fake.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$TEST_LOGGER_ARGS"\n')
            fake.chmod(0o755)
            env = os.environ.copy()
            env.pop("INFRA_AUDIT_SINK_FILE", None)
            env.update(INFRA_AUDIT_ENABLE="1", TEST_LOGGER_ARGS=str(captured),
                       PATH=d + os.pathsep + env["PATH"], PS1="AUDIT> ")
            master, slave = pty.openpty()
            try:
                proc = subprocess.Popen(["bash", "--noprofile", "--rcfile", str(rc), "-i"],
                                        stdin=slave, stdout=slave, stderr=slave, env=env)
                os.close(slave)
                time.sleep(0.2)
                os.write(master, b"echo syslog-marker\nexit\n")
                proc.wait(timeout=5)
            finally:
                os.close(master)
            self.assertIn("infra-audit-shell", captured.read_text())
            self.assertIn('"source":"shell"', captured.read_text())


class DeploymentTests(unittest.TestCase):
    def test_stage_and_rollback(self):
        with tempfile.TemporaryDirectory() as d:
            cmd = [sys.executable, str(ROOT / "scripts/manage.py")]
            subprocess.run(cmd + ["deploy", "--root", d, "--remote", "logs.example", "--host-input", "debian", "--apply"],
                           check=True, stdout=subprocess.DEVNULL)
            self.assertTrue((pathlib.Path(d) / "etc/profile.d/99-infra-audit.sh").exists())
            self.assertIn('StreamDriver="gtls"', (pathlib.Path(d) / "etc/rsyslog.d/70-infra-audit.conf").read_text())
            self.assertIn('/var/log/auth.log', (pathlib.Path(d) / "etc/rsyslog.d/71-infra-audit-host-inputs.conf").read_text())
            subprocess.run(cmd + ["rollback", "--root", d, "--apply"],
                           check=True, stdout=subprocess.DEVNULL)
            self.assertFalse((pathlib.Path(d) / "etc/profile.d/99-infra-audit.sh").exists())
            self.assertFalse((pathlib.Path(d) / "etc/rsyslog.d/71-infra-audit-host-inputs.conf").exists())

    def test_rhel_host_inputs_and_lab_ruleset(self):
        with tempfile.TemporaryDirectory() as d:
            cmd = [sys.executable, str(ROOT / "scripts/manage.py"), "deploy", "--root", d,
                   "--remote", "logs.example", "--host-input", "rhel", "--transport", "tcp-lab", "--apply"]
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)
            text = (pathlib.Path(d) / "etc/rsyslog.d/71-infra-audit-host-inputs.conf").read_text()
            self.assertIn('/var/log/secure', text)
            self.assertIn('ruleset="infra_audit_forward"', text)
            self.assertNotIn("__RULESET__", text)

    def test_rejects_unsafe_custom_log_path(self):
        with tempfile.TemporaryDirectory() as d:
            cmd = [sys.executable, str(ROOT / "scripts/manage.py"), "deploy", "--root", d,
                   "--remote", "logs.example", "--host-input", "custom", "--auth-log", '/var/log/auth.log"\\nstop']
            result = subprocess.run(cmd, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)


class FileCollectorTests(unittest.TestCase):
    def test_incremental_conversion_and_restart(self):
        with tempfile.TemporaryDirectory() as d:
            source = pathlib.Path(d) / "raw.jsonl"
            output = pathlib.Path(d) / "normalized.jsonl"
            state = pathlib.Path(d) / "state.json"
            rejects = pathlib.Path(d) / "rejects.jsonl"
            rows = (ROOT / "examples/events.jsonl").read_text().splitlines()
            source.write_text(rows[0] + "\n" + rows[1][:30])
            cmd = [sys.executable, str(ROOT / "src/collect_file.py"), "--input", str(source),
                   "--output", str(output), "--state", str(state), "--rejects", str(rejects)]
            subprocess.run(cmd, check=True)
            self.assertEqual(len(output.read_text().splitlines()), 1)
            with source.open("a") as f:
                f.write(rows[1][30:] + "\n")
            subprocess.run(cmd, check=True)
            subprocess.run(cmd, check=True)
            events = [json.loads(x) for x in output.read_text().splitlines()]
            self.assertEqual([e["source"] for e in events], ["auditd", "rootsh"])
            self.assertFalse(rejects.exists())


if __name__ == "__main__":
    unittest.main()
