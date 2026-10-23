import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import netmoat
import netmoat_service as service


def completed(stdout="", code=0):
    return subprocess.CompletedProcess([], code, stdout, "")


class ConfigTests(unittest.TestCase):
    def config(self, **changes):
        data = {"interfaces": ["en0"], "targets": ["192.0.2.0/24"]}
        data.update(changes)
        return service.Config(data)

    def test_service_reuses_strict_policy_validation(self):
        for value in ["en0\npass all", "utun0"]:
            with self.assertRaises(ValueError):
                self.config(interfaces=[value])
        with self.assertRaises(ValueError):
            self.config(unexpected=True)

    def test_dns_has_no_direct_or_remote_proxy_fallback(self):
        for proxy in ["", "http://example.com:8080", "https://127.0.0.1:8080",
                      "http://user:password@127.0.0.1:8080", "http://127.0.0.1:8080/path"]:
            with self.subTest(proxy=proxy), self.assertRaises(ValueError):
                self.config(dns={"hosts": ["example.com"], "proxy": proxy, "refresh_seconds": 300})

    def test_dns_rejects_shell_text_wildcards_and_bad_intervals(self):
        for host in ["*.example.com", "example.com\npass all", "-x.example.com", "localhost"]:
            with self.assertRaises(ValueError):
                self.config(dns={"hosts": [host], "proxy": "http://127.0.0.1:8080", "refresh_seconds": 300})
        with self.assertRaises(ValueError):
            self.config(dns={"hosts": ["example.com"], "proxy": "http://127.0.0.1:8080", "refresh_seconds": True})

    def test_launchd_runs_isolated_copied_code_and_keeps_it_alive(self):
        job = service.job()
        self.assertTrue(job["RunAtLoad"])
        self.assertTrue(job["KeepAlive"])
        self.assertEqual(job["ProgramArguments"][:3], ["/usr/bin/python3", "-I", "-B"])
        self.assertEqual(job["ProgramArguments"][3], str(service.HOME / "netmoat.py"))
        self.assertNotIn("PYTHONPATH", job.get("EnvironmentVariables", {}))

    def test_install_refuses_existing_paths_before_any_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            config = folder / "policy.json"
            config.write_text(json.dumps({"interfaces": ["en0"], "targets": ["192.0.2.0/24"]}))
            with mock.patch.object(service, "HOME", folder), mock.patch.object(service, "write") as write:
                with self.assertRaisesRegex(ValueError, "conflicting path"):
                    service.install(config)
                write.assert_not_called()

    def test_root_service_paths_reject_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            (folder / "target").write_text("data")
            (folder / "link").symlink_to(folder / "target")
            with self.assertRaisesRegex(ValueError, "Unsafe service path"):
                service.secure(folder / "link")

    def test_runtime_lock_refuses_another_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(service, "RUN", Path(tmp)), mock.patch.object(service, "secure"):
                with service.lock():
                    with self.assertRaisesRegex(RuntimeError, "still running"):
                        with service.lock():
                            self.fail("Concurrent lock was granted")

    def test_stop_lock_waits_for_asynchronous_daemon_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(service, "RUN", Path(tmp)), mock.patch.object(service, "secure"), \
                    mock.patch.object(service.fcntl, "flock", side_effect=[BlockingIOError(), None]) as acquire, \
                    mock.patch.object(service.time, "sleep") as sleep:
                with service.lock(wait=30):
                    self.assertEqual(acquire.call_count, 2)
                sleep.assert_called_once_with(0.1)


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.patch = mock.patch.object(service, "HOME", self.home)
        self.patch.start()
        self.secure = mock.patch.object(service, "secure")
        self.secure.start()
        self.config = service.Config({"interfaces": ["en0"], "targets": ["192.0.2.0/24"],
            "dns": {"hosts": ["example.com"], "proxy": "http://127.0.0.1:8080", "refresh_seconds": 300}})

    def tearDown(self):
        self.secure.stop()
        self.patch.stop()
        self.temp.cleanup()

    def test_dns_failure_retains_last_good_addresses_and_reports_staleness(self):
        (self.home / "dns-cache.json").write_text(json.dumps({"example.com": {
            "addresses": ["8.8.8.8"], "resolved_at": 1}}))
        cache = service.DNSCache(self.config)
        with mock.patch.object(service, "dns_lookup", side_effect=RuntimeError("Proxy unavailable")):
            policy, state = cache.policy()
        self.assertTrue(policy.includes("8.8.8.8"))
        self.assertEqual(state["stale_hosts"], ["example.com"])

    def test_partial_family_failure_does_not_replace_last_good_addresses(self):
        cache = service.DNSCache(self.config)
        cache.records = {"example.com": {"addresses": ["8.8.8.8"], "resolved_at": 1}}
        with mock.patch.object(service, "dns_lookup", side_effect=[["1.1.1.1"], RuntimeError("IPv6 lookup failed")]):
            policy, _ = cache.policy()
        self.assertTrue(policy.includes("8.8.8.8"))
        self.assertFalse(policy.includes("1.1.1.1"))

    def test_status_cache_read_does_not_connect(self):
        cache = service.DNSCache(self.config)
        cache.next_refresh = float("inf")
        with mock.patch.object(service, "dns_lookup") as query:
            _, state = cache.policy()
        query.assert_not_called()
        self.assertEqual(state["stale_hosts"], ["example.com"])

    def test_cached_syntax_is_validated_before_rules(self):
        cache = service.DNSCache(self.config)
        cache.next_refresh = float("inf")
        cache.records = {"example.com": {"addresses": ["8.8.8.8\npass all"], "resolved_at": 1}}
        with self.assertRaises(ValueError):
            cache.policy()

    def test_dns_query_is_proxy_only_and_rejects_fake_ip(self):
        with mock.patch.object(netmoat, "command", return_value=completed(json.dumps({
                "Status": 0, "Answer": [{"type": 1, "data": "198.18.0.1"}]}))) as command:
            with self.assertRaises(ValueError):
                service.dns_lookup(("example.com", "A", "http://127.0.0.1:8080"))
        argv = command.call_args.args[0]
        self.assertIn("--proxy", argv)
        self.assertEqual(argv[argv.index("--noproxy") + 1], "")
        self.assertNotIn("--retry", argv)


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.patch = mock.patch.object(service, "RUN", self.folder)
        self.patch.start()
        self.safe = mock.patch.object(service, "secure")
        self.safe.start()
        self.policy = netmoat.Policy.parse({"interfaces": ["en0"], "targets": ["192.0.2.0/24"]})
        self.guard = service.Guard()
        self.guard.log.write_text("Token : 777\n")
        self.canonical = 'block drop out quick on en0 inet all label "eg_v4"\nblock drop out quick on en0 inet6 all label "eg_v6"\n'
        (self.folder / "canonical.txt").write_text(self.canonical)
        (self.folder / "rules.pf").write_text(netmoat.render(self.policy))
        self.loaded = self.canonical
        self.parent = 'anchor "com.apple/*" all\n'
        self.table = "192.0.2.0/24\n"
        self.calls = []
        self.command = mock.patch.object(netmoat, "command", side_effect=self.execute)
        self.command.start()
        self.enabled = mock.patch.object(netmoat, "enabled", return_value=True)
        self.enabled.start()

    def tearDown(self):
        self.enabled.stop()
        self.command.stop()
        self.safe.stop()
        self.patch.stop()
        self.temp.cleanup()

    def execute(self, args, **kwargs):
        self.calls.append(args)
        if args == [netmoat.PF, "-sr"]:
            return completed(self.parent)
        if "show" in args:
            return completed(self.table)
        if "-vvsr" in args:
            return completed('block label "eg_v4"\n Packets: 3\nblock label "eg_v6"\n Packets: 4\n')
        if "-f" in args and "-n" not in args:
            self.loaded = self.canonical
        if "-sr" in args:
            return completed(self.loaded)
        return completed()

    def test_restart_adopts_reference_without_enabling_again(self):
        with mock.patch.object(service.subprocess, "run") as enable:
            counts = service.Guard().ensure(self.policy)
        enable.assert_not_called()
        self.assertEqual(counts, {"4": 3, "6": 4})
        self.assertEqual(self.guard.log.read_text(), "Token : 777\n")

    def test_missing_parent_refuses_all_mutations(self):
        self.parent = ""
        with self.assertRaisesRegex(RuntimeError, "parent anchor"):
            self.guard.ensure(self.policy)
        self.assertEqual(self.calls, [[netmoat.PF, "-sr"]])

    def test_missing_child_rules_are_restored_without_root_reload(self):
        self.loaded = ""
        self.guard.ensure(self.policy)
        loads = [args for args in self.calls if "-f" in args]
        self.assertEqual(len(loads), 2)
        self.assertTrue(all("-a" in args and service.ANCHOR in args for args in loads))

    def test_wrong_target_readback_is_a_failure(self):
        self.table = "198.51.100.0/24\n"
        with self.assertRaisesRegex(RuntimeError, "Target table"):
            self.guard.ensure(self.policy)

    def test_cleanup_never_releases_reference_when_rules_remain(self):
        with self.assertRaisesRegex(RuntimeError, "Cleanup readback"):
            self.guard.cleanup()
        self.assertTrue(self.guard.log.exists())
        self.assertFalse(any("-X" in args for args in self.calls))

    def test_cleanup_releases_only_owned_token_after_empty_readback(self):
        self.loaded = ""
        self.guard.cleanup()
        self.assertIn([netmoat.PF, "-X", "777"], self.calls)
        self.assertFalse(self.guard.log.exists())
        self.assertFalse(any("-d" in args or args[-2:] == ["-F", "all"] for args in self.calls))

    def test_invalid_token_does_not_acquire_another_reference(self):
        self.guard.log.write_text("unexpected output")
        with mock.patch.object(service.subprocess, "run") as enable:
            with self.assertRaisesRegex(RuntimeError, "token"):
                self.guard.ensure(self.policy)
        enable.assert_not_called()


if __name__ == "__main__":
    unittest.main()
