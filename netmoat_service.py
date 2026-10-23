"""Optional launchd service. No destinations or machine-specific policy shipped."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlencode, urlsplit

import netmoat as core

LABEL = "io.github.lucasuiii.netmoat"
HOME = Path("/Library/Application Support/NetMoat")
PLIST = Path("/Library/LaunchDaemons") / (LABEL + ".plist")
LAUNCHER = Path("/usr/local/bin/netmoat")
RUN = core.RUNTIME / "netmoat-service"
ANCHOR = core.ANCHOR_PREFIX + "0000000000000000"
LAUNCHCTL = "/bin/launchctl"
SYSTEM_PYTHON = "/usr/bin/python3"
MARKER = "netmoat-service-v1"


def secure(path, directory=False):
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("Unsafe service path: " + str(path))


def mkdir(path):
    path.mkdir(mode=0o700, exist_ok=True)
    secure(path, directory=True)


def write(path, value, mode=0o600):
    """Atomic replacement inside a previously checked administrator-owned directory."""
    fd, tmp = tempfile.mkstemp(prefix=".netmoat-", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(value if isinstance(value, bytes) else value.encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def write_json(path, value):
    write(path, json.dumps(value, indent=2) + "\n")


@contextmanager
def lock(wait=0):
    mkdir(RUN)
    fd = os.open(str(RUN / "lock"), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        secure(RUN / "lock")
        deadline = time.monotonic() + wait
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("The service is still running; refusing concurrent changes")
                time.sleep(0.1)
        yield
    finally:
        os.close(fd)


class Config:
    def __init__(self, data):
        if not isinstance(data, dict) or set(data) - {"interfaces", "targets", "dns"}:
            raise ValueError("Service config accepts interfaces, targets, and optional dns")
        self.policy = core.Policy.parse({k: data.get(k) for k in ["interfaces", "targets"]})
        self.dns = data.get("dns")
        if self.dns is not None:
            if not isinstance(self.dns, dict) or set(self.dns) != {"hosts", "proxy", "refresh_seconds"}:
                raise ValueError("dns requires hosts, proxy, and refresh_seconds")
            hosts = self.dns["hosts"]
            if not isinstance(hosts, list) or not 1 <= len(hosts) <= 32:
                raise ValueError("Supply 1 to 32 exact DNS hostnames")
            for host in hosts:
                if (not isinstance(host, str) or len(host) > 253 or "." not in host
                        or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
                               for part in host.split("."))):
                    raise ValueError("DNS hosts must be exact ASCII hostnames")
            if not isinstance(self.dns["proxy"], str):
                raise ValueError("DNS proxy must be an HTTP URL")
            proxy = urlsplit(self.dns["proxy"])
            if (proxy.scheme != "http" or proxy.hostname not in ["127.0.0.1", "::1"]
                    or proxy.username or proxy.password or proxy.path not in ["", "/"]
                    or proxy.query or proxy.fragment or not proxy.port):
                raise ValueError("DNS refresh requires an explicit loopback HTTP proxy without credentials")
            interval = self.dns["refresh_seconds"]
            if type(interval) is not int or not 60 <= interval <= 86400:
                raise ValueError("DNS refresh interval must be 60..86400 seconds")

    @classmethod
    def load(cls, path):
        return cls(json.loads(path.read_text()))


def dns_lookup(item):
    host, qtype, proxy = item
    url = "https://cloudflare-dns.com/dns-query?" + urlencode({"name": host, "type": qtype})
    result = core.command(["/usr/bin/curl", "--silent", "--show-error", "--fail",
                           "--proto", "=https", "--proxy", proxy, "--noproxy", "",
                           "--connect-timeout", "3", "--max-time", "5", "--max-filesize", "65536",
                           "--header", "accept: application/dns-json", url], timeout=7)
    data = json.loads(result.stdout)
    if data.get("Status") != 0:
        raise RuntimeError("Resolver did not return a successful DNS response")
    addresses = []
    version = 4 if qtype == "A" else 6
    for answer in data.get("Answer", []):
        if answer.get("type") == (1 if version == 4 else 28):
            ip = ipaddress.ip_address(answer["data"])
            if ip.version != version or not ip.is_global:
                raise ValueError("Resolver returned a non-global or mismatched address")
            addresses.append(str(ip))
    return addresses


class DNSCache:
    def __init__(self, config):
        self.config = config
        self.records = {}
        self.next_refresh = 0
        self.path = HOME / "dns-cache.json"
        if self.path.exists():
            secure(self.path)
            self.records = json.loads(self.path.read_text())

    def policy(self):
        dns = self.config.dns
        if dns is None:
            return self.config.policy, {"enabled": False, "stale_hosts": []}
        now = time.time()
        if now >= self.next_refresh:
            def resolve(host):
                try:
                    addresses = dns_lookup((host, "A", dns["proxy"])) + dns_lookup((host, "AAAA", dns["proxy"]))
                    if not addresses:
                        raise ValueError("No usable DNS addresses")
                    return host, {"addresses": sorted(set(addresses)), "resolved_at": now}
                except (ValueError, RuntimeError, OSError, subprocess.SubprocessError):
                    return host, None
            with ThreadPoolExecutor(max_workers=4) as pool:
                for host, result in pool.map(resolve, dns["hosts"]):
                    if result is not None:
                        self.records[host] = result
            write_json(self.path, self.records)
            self.next_refresh = now + dns["refresh_seconds"]
        addresses, stale = [], []
        for host in dns["hosts"]:
            record = self.records.get(host, {})
            # Revalidate cached addresses; never expand a cached string into PF syntax.
            values = record.get("addresses", [])
            for address in values:
                if not ipaddress.ip_address(address).is_global:
                    raise ValueError("Unsafe cached DNS address")
            addresses.extend(values)
            if not values or now - record.get("resolved_at", 0) > 3 * dns["refresh_seconds"]:
                stale.append(host)
        return self.config.policy.with_decoys(addresses), {"enabled": True, "stale_hosts": stale}


class Guard:
    """Keep one reference across crashes; restart adopts it rather than accumulating tokens."""
    def __init__(self):
        self.log = RUN / "enable.log"

    def release(self):
        if self.log.exists():
            secure(self.log)
            token = core.parse_token(self.log.read_text())
            core.command([core.PF, "-X", token])
            self.log.unlink()

    def ensure(self, policy):
        main = core.command([core.PF, "-sr"]).stdout
        if not re.search(r'^anchor "com\.apple/\*"', main, re.M):
            raise RuntimeError("Waiting for the system PF parent anchor; root rules were not reloaded")
        if not core.enabled() and self.log.exists():
            self.release()
        if not self.log.exists():
            # Persist the kernel-issued token directly, including across a crash.
            fd = os.open(str(self.log), os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as stream:
                result = subprocess.run([core.PF, "-E"], stdout=stream, stderr=subprocess.STDOUT, timeout=10)
            if result.returncode:
                raise RuntimeError("Failed to acquire a PF enable reference")
        core.parse_token(self.log.read_text())
        expected = core.render(policy)
        rulefile, canonical = RUN / "rules.pf", RUN / "canonical.txt"
        loaded = core.command([core.PF, "-a", ANCHOR, "-sr"]).stdout
        table = core.command([core.PF, "-a", ANCHOR, "-t", "eg_targets", "-T", "show"], check=False)
        try:
            actual = {ipaddress.ip_network(s.strip(), strict=False) for s in table.stdout.splitlines() if s.strip()}
        except ValueError:
            actual = set()
        targets = set(map(ipaddress.ip_network, policy.targets))
        healthy = (table.returncode == 0 and actual == targets and canonical.exists()
                   and loaded == canonical.read_text() and rulefile.exists() and rulefile.read_text() == expected)
        if not healthy:
            write(rulefile, expected)
            core.command([core.PF, "-n", "-a", ANCHOR, "-f", str(rulefile)])
            core.command([core.PF, "-a", ANCHOR, "-f", str(rulefile)])
            loaded = core.command([core.PF, "-a", ANCHOR, "-sr"]).stdout
            if len(loaded.splitlines()) != len(policy.interfaces) * 2:
                raise RuntimeError("Rule count readback failed")
            write(canonical, loaded)
            table = core.command([core.PF, "-a", ANCHOR, "-t", "eg_targets", "-T", "show"])
            actual = {ipaddress.ip_network(s.strip(), strict=False) for s in table.stdout.splitlines() if s.strip()}
            if actual != targets:
                raise RuntimeError("Target table readback failed")
        counters = core.command([core.PF, "-a", ANCHOR, "-vvsr"]).stdout
        return {str(family): core.packet_count(counters, label)
                for family, label in [(4, "eg_v4"), (6, "eg_v6")]}

    def cleanup(self):
        core.command([core.PF, "-a", ANCHOR, "-F", "rules"])
        core.command([core.PF, "-a", ANCHOR, "-F", "Tables"])
        if (core.command([core.PF, "-a", ANCHOR, "-sr"]).stdout.strip()
                or core.command([core.PF, "-a", ANCHOR, "-s", "Tables"]).stdout.strip()):
            raise RuntimeError("Cleanup readback failed; reference retained")
        self.release()


def job():
    return {"Label": LABEL, "ProgramArguments": [SYSTEM_PYTHON, "-I", "-B", str(HOME / "netmoat.py"),
                                               "service", "run"],
            "RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 10,
            "ExitTimeOut": 30, "ProcessType": "Background", "Umask": 0o077,
            "WorkingDirectory": str(HOME)}


def installed():
    secure(HOME, directory=True)
    secure(HOME / "installed.json")
    if json.loads((HOME / "installed.json").read_text()).get("format") != MARKER:
        raise ValueError("Unrecognized installation; refusing modification")


def status():
    loaded = core.command([LAUNCHCTL, "print", "system/" + LABEL], check=False).returncode == 0
    overrides = core.command([LAUNCHCTL, "print-disabled", "system"], check=False)
    match = re.search(r'"' + re.escape(LABEL) + r'"\s*=>\s*(true|false)', overrides.stdout)
    disabled = (match.group(1) == "true") if match else False
    state = {}
    if RUN.exists():
        secure(RUN, directory=True)
        if (RUN / "state.json").exists():
            secure(RUN / "state.json")
            state = json.loads((RUN / "state.json").read_text())
    counters, readback = {}, False
    if HOME.exists() and state.get("state") == "rules_loaded" and loaded:
        installed()
        config = Config.load(HOME / "policy.json")
        cache = DNSCache(config)
        cache.next_refresh = float("inf")  # Status must never make DNS or service connections.
        policy, dns = cache.policy()
        table = core.command([core.PF, "-a", ANCHOR, "-t", "eg_targets", "-T", "show"], check=False)
        try:
            actual = {ipaddress.ip_network(s.strip(), strict=False) for s in table.stdout.splitlines() if s.strip()}
            canonical = RUN / "canonical.txt"
            rules = core.command([core.PF, "-a", ANCHOR, "-sr"])
            readback = (core.enabled() and table.returncode == 0
                        and actual == set(map(ipaddress.ip_network, policy.targets))
                        and canonical.exists() and rules.stdout == canonical.read_text())
            text = core.command([core.PF, "-a", ANCHOR, "-vvsr"]).stdout
            counters = {str(f): core.packet_count(text, label) for f, label in [(4, "eg_v4"), (6, "eg_v6")]}
            state["dns"] = dns
        except (ValueError, RuntimeError, OSError, subprocess.SubprocessError):
            readback = False
    return {"installed": HOME.exists(), "loaded": loaded,
            "autostart_enabled": (PLIST.exists() and overrides.returncode == 0
                                  and not disabled and not (HOME / "disabled").exists()),
            "rules_verified": readback, "state": state, "counters": counters}


def stop():
    installed()
    write(HOME / "disabled", "stopped\n")
    core.command([LAUNCHCTL, "disable", "system/" + LABEL])
    if core.command([LAUNCHCTL, "print", "system/" + LABEL], check=False).returncode == 0:
        core.command([LAUNCHCTL, "bootout", "system/" + LABEL], timeout=40)
    # bootout may return while SIGTERM cleanup is still running. Wait for the
    # exclusive lock before doing fallback cleanup or deleting runtime state.
    with lock(wait=30):
        Guard().cleanup()
        write_json(RUN / "state.json", {"anchor": ANCHOR, "state": "stopped", "updated_at": time.time()})


def start():
    installed()
    (HOME / "disabled").unlink(missing_ok=True)
    core.command([LAUNCHCTL, "enable", "system/" + LABEL])
    if core.command([LAUNCHCTL, "print", "system/" + LABEL], check=False).returncode != 0:
        core.command([LAUNCHCTL, "bootstrap", "system", str(PLIST)])
    core.command([LAUNCHCTL, "kickstart", "system/" + LABEL])
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if status()["rules_verified"]:
            return
        time.sleep(1)
    raise RuntimeError("Service installed but rules not verified; inspect service status before relying on it")


def install(path):
    config = Config.load(path)
    if HOME.exists() or PLIST.exists() or LAUNCHER.exists() or LAUNCHER.is_symlink():
        raise ValueError("An installation or conflicting path exists; uninstall it before reinstalling")
    for parent in [HOME.parent, PLIST.parent, LAUNCHER.parent]:
        secure(parent, directory=True)
    # A system-owned interpreter is required; a user-editable venv is never run as root.
    secure(Path(SYSTEM_PYTHON).resolve())
    mkdir(HOME)
    for module in ["netmoat.py", "netmoat_service.py"]:
        write(HOME / module, Path(__file__).with_name(module).read_bytes())
    write_json(HOME / "policy.json", json.loads(path.read_text()))
    write_json(HOME / "installed.json", {"format": MARKER, "installed_at": time.time()})
    write(PLIST, plistlib.dumps(job()), mode=0o644)
    launcher = '#!/bin/sh\nexec /usr/bin/python3 -I -B "/Library/Application Support/NetMoat/netmoat.py" "$@"\n'
    write(LAUNCHER, launcher, mode=0o755)
    start()


def run():
    installed()
    secure(HOME / "policy.json")
    config = Config.load(HOME / "policy.json")
    cache = DNSCache(config)
    with lock():
        guard = Guard()
        state = {"anchor": ANCHOR, "pid": os.getpid()}
        try:
            while not (HOME / "disabled").exists():
                try:
                    policy, dns = cache.policy()
                    counts = guard.ensure(policy)
                    state.update({"state": "rules_loaded", "interfaces": policy.interfaces,
                                  "target_count": len(policy.targets), "dns": dns, "counters": counts})
                    state.pop("error", None)
                except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
                    state.update({"state": "degraded", "error": str(error)[:1000]})
                state["updated_at"] = time.time()
                write_json(RUN / "state.json", state)
                time.sleep(10)
        finally:
            guard.cleanup()
            state.update({"state": "stopped", "updated_at": time.time()})
            write_json(RUN / "state.json", state)


def main(args):
    action = args.service_action
    if action == "install":
        install(Path(args.config))
    elif action == "run":
        run()
        return 0
    elif action == "start":
        start()
    elif action == "stop":
        stop()
    elif action == "uninstall":
        stop()
        secure(PLIST)
        secure(LAUNCHER)
        if plistlib.loads(PLIST.read_bytes()).get("Label") != LABEL:
            raise ValueError("Refusing to remove a different launchd job")
        if '"/Library/Application Support/NetMoat/netmoat.py"' not in LAUNCHER.read_text():
            raise ValueError("Refusing to remove a different launcher")
        PLIST.unlink()
        LAUNCHER.unlink()
        shutil.rmtree(HOME)
        shutil.rmtree(RUN)
    print(json.dumps(status(), indent=2))
    return 0
