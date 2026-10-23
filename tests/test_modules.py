from contextlib import nullcontext
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import netmoat
import netmoat_service as service


def module(**updates):
    result = {"id": "work-service", "name": "工作服务", "enabled": True,
              "targets": ["192.0.2.0/24"], "hosts": []}
    result.update(updates)
    return result


def document(modules=None, **updates):
    result = {"interfaces": ["en0"], "targets": [], "modules": modules if modules is not None else [module()]}
    result.update(updates)
    return result


class ModuleTests(unittest.TestCase):
    def test_disabled_module_removes_only_its_unique_targets(self):
        config = service.Config(document([module(enabled=False), module(id="other", targets=["198.51.100.0/24"])]))
        self.assertFalse(config.policy.includes("192.0.2.1"))
        self.assertTrue(config.policy.includes("198.51.100.1"))

    def test_all_disabled_modules_produce_an_empty_destination_table(self):
        config = service.Config(document([module(enabled=False)]))
        self.assertEqual(config.policy.targets, ())
        self.assertIn("table <eg_targets> {  }", netmoat.render(config.policy))
        with self.assertRaises(ValueError):
            netmoat.Policy.parse({"interfaces": ["en0"], "targets": []})

    def test_enabled_modules_merge_and_deduplicate_targets(self):
        config = service.Config(document([module(), module(id="other")]))
        self.assertEqual(config.policy.targets, ("192.0.2.0/24",))

    def test_disabled_host_module_does_not_resolve_or_contribute_cached_ips(self):
        config = service.Config(document([module(enabled=False, hosts=["service.example.com"], targets=[])],
            dns={"hosts": [], "proxy": "http://127.0.0.1:8080", "refresh_seconds": 300}))
        self.assertIsNone(config.dns)
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(service, "HOME", Path(temp)), \
                mock.patch.object(service, "dns_lookup") as query:
            policy, _ = service.DNSCache(config).policy()
        query.assert_not_called()
        self.assertEqual(policy.targets, ())

    def test_hostname_module_requires_explicit_proxy_settings(self):
        with self.assertRaisesRegex(ValueError, "proxy"):
            service.Config(document([module(hosts=["service.example.com"], targets=[])]))

    def test_module_schema_and_identifiers_are_strict(self):
        for candidate in [module(id="bad\nid"), module(name=""), module(name="bad\nname"),
                          module(enabled=1), module(targets=[]), module(hosts=["*.example.com"]),
                          module(targets=["192.0.2.1\npass out all"])]:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                service.Config(document([candidate]))
        with self.assertRaisesRegex(ValueError, "unique"):
            service.Config(document([module(), module()]))

    def test_legacy_conversion_preserves_effective_targets_and_hosts(self):
        original = {"interfaces": ["en0"], "targets": ["192.0.2.0/24"],
                    "dns": {"hosts": ["service.example.com"], "proxy": "http://127.0.0.1:8080", "refresh_seconds": 300}}
        before = service.Config(original)
        edited = before.editable()
        after = service.Config(edited)
        self.assertEqual(before.policy, after.policy)
        self.assertEqual(before.dns, after.dns)
        self.assertEqual(len(edited["modules"]), 1)
        self.assertEqual(original["targets"], ["192.0.2.0/24"])

    def test_disabling_one_module_keeps_shared_target_if_another_needs_it(self):
        config = service.Config(document([module(enabled=False), module(id="other")]))
        self.assertTrue(config.policy.includes("192.0.2.1"))


class ReloadTests(unittest.TestCase):
    def test_live_reload_applies_new_policy_without_cleanup_between_edits(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp); runtime = folder / "runtime"; runtime.mkdir()
            path = folder / "policy.json"
            path.write_text(json.dumps(document()))
            changed = document([module(targets=["198.51.100.0/24"])])
            sleeps = 0
            def sleep(_):
                nonlocal sleeps
                sleeps += 1
                if sleeps == 1:
                    path.write_text(json.dumps(changed))
                else:
                    raise KeyboardInterrupt()
            with mock.patch.object(service, "HOME", folder), mock.patch.object(service, "RUN", runtime), \
                    mock.patch.object(service, "installed"), mock.patch.object(service, "secure"), \
                    mock.patch.object(service, "lock", return_value=nullcontext()), \
                    mock.patch.object(service.time, "sleep", side_effect=sleep), \
                    mock.patch.object(service, "Guard") as guard:
                guard.return_value.ensure.return_value = {"4": 0, "6": 0}
                with self.assertRaises(KeyboardInterrupt):
                    service.run()
                policies = [call.args[0] for call in guard.return_value.ensure.call_args_list]
                self.assertEqual(len(policies), 2)
                self.assertTrue(policies[0].includes("192.0.2.1"))
                self.assertFalse(policies[1].includes("192.0.2.1"))
                self.assertTrue(policies[1].includes("198.51.100.1"))
                guard.return_value.cleanup.assert_called_once()

    def test_invalid_edit_does_not_replace_working_config(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp); old = folder / "policy.json"; old.write_text(json.dumps(document()))
            candidate = folder / "candidate.json"
            candidate.write_text(json.dumps(document([module(targets=["0.0.0.0/0"])])))
            original = old.read_bytes()
            with mock.patch.object(service, "HOME", folder), mock.patch.object(service, "installed"):
                with self.assertRaises(ValueError):
                    service.configure(candidate)
            self.assertEqual(old.read_bytes(), original)
            self.assertFalse((folder / "policy.previous.json").exists())

    def test_valid_edit_waits_for_matching_policy_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp); path = folder / "policy.json"; path.write_text(json.dumps(document()))
            candidate = folder / "candidate.json"; candidate.write_text(json.dumps(document([module(enabled=False)])))
            original = path.read_bytes()
            def status():
                return {"rules_verified": True, "state": {"config_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}}
            with mock.patch.object(service, "HOME", folder), mock.patch.object(service, "installed"), \
                    mock.patch.object(netmoat, "command", return_value=subprocess.CompletedProcess([], 0, "", "")), \
                    mock.patch.object(service, "status", side_effect=status):
                service.configure(candidate)
            self.assertEqual((folder / "policy.previous.json").read_bytes(), original)
            self.assertEqual(json.loads(path.read_text()), json.loads(candidate.read_text()))


if __name__ == "__main__":
    unittest.main()
