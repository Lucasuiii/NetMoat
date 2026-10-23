import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import netmoat


def completed(stdout="", code=0):
    return subprocess.CompletedProcess([], code, stdout, "")


class PolicyTests(unittest.TestCase):
    def policy(self, **changes):
        data = {"interfaces": ["en0"], "targets": ["192.0.2.0/24", "2001:db8::/32"]}
        data.update(changes)
        return netmoat.Policy.parse(data)

    def test_rule_injection_is_rejected(self):
        for value in ["en0\npass out all", "en0;id", "utun0", "lo0", "en0 all"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.policy(interfaces=[value])
        for target in ["example.com", "192.0.2.1\npass out all", "0.0.0.0/0", "::/0"]:
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.policy(targets=[target])

    def test_ambiguous_schema_is_rejected(self):
        for data in [None, [], {}, {"interfaces": [], "targets": []},
                     {"interfaces": ["en0"], "targets": [False]},
                     {"interfaces": ["en0"], "targets": ["192.0.2.1"], "extra": True}]:
            with self.subTest(data=data), self.assertRaises((ValueError, TypeError)):
                netmoat.Policy.parse(data)

    def test_cidrs_are_normalized_and_deduplicated(self):
        p = self.policy(interfaces=["en0", "en0"], targets=["192.0.2.3/24", "192.0.2.0/24"])
        self.assertEqual(p.interfaces, ("en0",))
        self.assertEqual(p.targets, ("192.0.2.0/24",))

    def test_render_does_not_expand_to_other_interfaces(self):
        text = netmoat.render(self.policy(interfaces=["en0", "en4"]))
        self.assertEqual(text.count("block drop out quick"), 4)
        self.assertIn("on en0 inet6", text)
        self.assertIn("on en4 inet", text)
        self.assertNotIn("utun", text)
        self.assertNotIn("pass ", text)

    def test_decoys_cannot_probe_protected_targets(self):
        args = argparse.Namespace(ipv4="192.0.2.7", ipv6=None, interface="en0")
        with mock.patch.object(netmoat, "probe_socket") as probe:
            with self.assertRaisesRegex(ValueError, "outside protected"):
                netmoat.verify(args, self.policy())
            probe.assert_not_called()

    def test_decoy_address_families_are_checked(self):
        args = argparse.Namespace(ipv4="2001:db8::1", ipv6=None, interface="en0")
        with self.assertRaisesRegex(ValueError, "family"):
            netmoat.verify(args, self.policy())

    def test_ipv6_scope_ids_cannot_inject_pf_rules(self):
        for target in ["fe80::1%en0/128", "fe80::1%en0\npass out all/128"]:
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.policy(targets=[target])

    def test_decoy_scope_ids_are_rejected_before_connections(self):
        args = argparse.Namespace(ipv4=None, ipv6="fe80::1%en0", interface="en0")
        with mock.patch.object(netmoat, "probe_socket") as probe:
            with self.assertRaisesRegex(ValueError, "unscoped"):
                netmoat.verify(args, self.policy())
            probe.assert_not_called()
        with self.assertRaises(ValueError):
            self.policy().with_decoys(["fe80::1%en0\npass out all/128"])


class ParserTests(unittest.TestCase):
    def test_token_must_be_a_complete_numeric_line(self):
        self.assertEqual(netmoat.parse_token("warning\nToken : 12345\n"), "12345")
        for value in ["Token : 123x", "Token : ;id", "no token", "Token : "]:
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                netmoat.parse_token(value)

    def test_counter_errors_are_not_treated_as_zero(self):
        with self.assertRaises(RuntimeError):
            netmoat.packet_count("", "eg_v4")
        text = ('block label "eg_v4"\n [ Packets: 3 Bytes: 20 ]\n'
                'block label "eg_v4"\n [ Packets: 5 Bytes: 30 ]\n')
        self.assertEqual(netmoat.packet_count(text, "eg_v4"), 8)

    def test_cleanup_script_is_valid_shell_and_scoped(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "cleanup.sh"
            text = netmoat.cleanup_script("com.apple/netmoat_0123456789abcdef", Path(tmp))
            script.write_text(text)
            subprocess.run(["/bin/sh", "-n", str(script)], check=True)
            for line in text.splitlines():
                if " -F " in line:
                    self.assertIn("-a com.apple/netmoat_0123456789abcdef", line)
            self.assertNotIn(" -d", text)
            self.assertNotIn("-F all", text)
            self.assertIn('-X "$token"', text)

    def test_recovery_refuses_arbitrary_paths(self):
        with self.assertRaises(ValueError):
            netmoat.inspect_state(Path("/tmp/arbitrary"))


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.config = self.base / "pf.conf"
        self.config.write_text("unchanged")
        self.policy = netmoat.Policy.parse({"interfaces": ["en0"], "targets": ["192.0.2.0/24"]})
        self.calls = []
        self.active = False
        self.readback_error = False
        self.parent = 'anchor "com.apple/*" all\n'
        self.patches = [mock.patch.object(netmoat, "RUNTIME", self.base),
                        mock.patch.object(netmoat, "PF_CONFIG", self.config),
                        mock.patch.object(netmoat, "require_admin"),
                        mock.patch.object(netmoat.socket, "if_nametoindex", return_value=1),
                        mock.patch.object(netmoat, "command", side_effect=self.command),
                        mock.patch.object(netmoat, "enabled", side_effect=lambda: self.active),
                        mock.patch.object(netmoat.subprocess, "Popen"),
                        mock.patch.object(netmoat.subprocess, "run", side_effect=self.enable),
                        mock.patch.object(netmoat.os, "killpg")]
        self.started = [patch.start() for patch in self.patches]
        self.started[-3].return_value.pid = 999999

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self.tmp.cleanup()

    def enable(self, args, **kwargs):
        self.calls.append(args)
        self.active = True
        kwargs["stdout"].write("Token : 777\n")
        return completed()

    def command(self, args, **kwargs):
        self.calls.append(args)
        if args == [netmoat.PF, "-sr"]:
            return completed(self.parent)
        if args[0] == "/bin/sh":
            self.active = False
            Path(args[1]).with_name("enable.log").unlink(missing_ok=True)
            return completed()
        if "show" in args:
            return completed("192.0.2.0/24\n")
        if "-vvsr" in args:
            return completed('block label "eg_v4"\n Packets: 0\nblock label "eg_v6"\n Packets: 0\n')
        if "-sr" in args or "Tables" in args:
            return completed(code=1 if self.readback_error else 0)
        return completed()

    def test_session_releases_its_own_reference_and_removes_runtime(self):
        session = netmoat.Session(self.policy, 60).start()
        folder = session.folder
        self.assertTrue(folder.exists())
        self.assertTrue(self.active)
        session.close()
        self.assertTrue(session.cleanup_result["removed"])
        self.assertTrue(session.cleanup_result["enable_status_restored"])
        self.assertFalse(folder.exists())
        self.assertFalse(self.active)
        self.assertFalse(any(args[:2] == [netmoat.PF, "-f"] for args in self.calls))
        session.close()  # Idempotent after success.

    def test_missing_parent_refuses_mutation(self):
        self.parent = ""
        with self.assertRaisesRegex(RuntimeError, "parent anchor"):
            netmoat.Session(self.policy, 60).start()
        self.assertNotIn([netmoat.PF, "-E"], self.calls)
        self.assertEqual(list(self.base.glob(netmoat.PREFIX + "*")), [])

    def test_failed_readback_retains_recovery_state(self):
        session = netmoat.Session(self.policy, 60).start()
        self.readback_error = True
        session.close()
        self.assertFalse(session.cleanup_result["removed"])
        self.assertTrue(session.folder.exists())
        self.assertIn("recovery_directory", session.cleanup_result)
        self.started[-1].assert_not_called()

    def test_wrong_target_readback_rolls_back_startup(self):
        self.policy = netmoat.Policy.parse({"interfaces": ["en0"], "targets": ["198.51.100.0/24"]})
        session = netmoat.Session(self.policy, 60)
        with self.assertRaisesRegex(RuntimeError, "target table"):
            session.start()
        self.assertFalse(self.active)
        self.assertTrue(session.cleanup_result["removed"])


if __name__ == "__main__":
    unittest.main()
