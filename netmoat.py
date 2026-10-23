"""macOS PF policies, decoy verification, and an opt-in startup service."""
import argparse
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

PF = "/sbin/pfctl"
PF_CONFIG = Path("/etc/pf.conf")
RUNTIME = Path("/private/var/run")
PREFIX = "netmoat-"
ANCHOR_PREFIX = "com.apple/netmoat_"


def command(args, check=True, timeout=15):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError("Command failed: %s: %s" % (args[0], result.stderr.strip()))
    return result


@dataclass(frozen=True)
class Policy:
    interfaces: tuple
    targets: tuple

    @classmethod
    def load(cls, filename):
        return cls.parse(json.loads(Path(filename).read_text()))

    @classmethod
    def parse(cls, data):
        if not isinstance(data, dict) or set(data) != {"interfaces", "targets"}:
            raise ValueError("Policy must contain only interfaces and targets")
        interfaces, targets = data["interfaces"], data["targets"]
        if not isinstance(interfaces, list) or not 1 <= len(interfaces) <= 32:
            raise ValueError("Provide 1 to 32 physical en interfaces")
        if any(not isinstance(i, str) or not re.fullmatch(r"en\d{1,4}", i) for i in interfaces):
            raise ValueError("Interfaces must be explicit physical en names; tunnels are excluded")
        if not isinstance(targets, list) or not 1 <= len(targets) <= 4096:
            raise ValueError("Provide 1 to 4096 literal IP addresses or CIDRs")
        networks = []
        for target in targets:
            if not isinstance(target, str) or not re.fullmatch(r"[0-9A-Fa-f:.]+(?:/\d{1,3})?", target):
                # ipaddress accepts arbitrary IPv6 scope IDs, including whitespace.
                # Scope IDs have no place in an address table or generated PF text.
                raise ValueError("Targets must be unscoped numeric IP/CIDR strings")
            network = ipaddress.ip_network(target, strict=False)
            if network.prefixlen == 0:
                raise ValueError("Default-route targets are deliberately unsupported")
            networks.append(str(network))
        return cls(tuple(dict.fromkeys(interfaces)), tuple(dict.fromkeys(networks)))

    def includes(self, address):
        ip = ipaddress.ip_address(address)
        return any(ip.version == n.version and ip in n for n in map(ipaddress.ip_network, self.targets))

    def with_decoys(self, addresses):
        return Policy.parse({"interfaces": list(self.interfaces),
                             "targets": list(self.targets) + list(addresses)})


def render(policy):
    lines = ["table <eg_targets> { " + ", ".join(policy.targets) + " }"]
    for interface in policy.interfaces:
        for family, label in [("inet", "eg_v4"), ("inet6", "eg_v6")]:
            lines.append('block drop out quick on %s %s from any to <eg_targets> label "%s"'
                         % (interface, family, label))
    return "\n".join(lines) + "\n"


def require_admin():
    if sys.platform != "darwin" or os.geteuid() != 0:
        raise RuntimeError("This operation requires macOS and administrator privileges")


def enabled():
    result = re.search(r"Status:\s*(Enabled|Disabled)", command([PF, "-s", "info"]).stdout)
    if not result:
        raise RuntimeError("PF enable status is unavailable")
    return result.group(1) == "Enabled"


def parse_token(output):
    match = re.search(r"^Token\s*:\s*(\d+)\s*$", output, re.M)
    if not match:
        raise RuntimeError("PF did not return an enable reference token")
    return match.group(1)


def packet_count(text, label):
    lines, total, found = text.splitlines(), 0, False
    for i, line in enumerate(lines):
        if 'label "%s"' % label in line:
            match = re.search(r"Packets:\s*(\d+)", "\n".join(lines[i + 1:i + 5]))
            if match:
                total += int(match.group(1))
                found = True
    if not found:
        raise RuntimeError("Missing PF counters for " + label)
    return total


def cleanup_script(anchor, folder):
    # Every interpolated path is generated locally, quoted, and root-owned.
    token_log = shlex.quote(str(folder / "enable.log"))
    return ("#!/bin/sh\nset -eu\n"
            + PF + " -a " + shlex.quote(anchor) + " -F rules >/dev/null 2>&1\n"
            + PF + " -a " + shlex.quote(anchor) + " -F Tables >/dev/null 2>&1\n"
            + "if [ -s " + token_log + " ]; then\n"
            + " token=$(/usr/bin/awk '/Token[[:space:]]*:/ { print $NF }' " + token_log + ")\n"
            + ' case "$token" in ""|*[!0-9]*) exit 1;; esac\n'
            + PF + ' -X "$token" >/dev/null 2>&1\n'
            + " /bin/rm -f " + token_log + "\nfi\n")


class Session:
    """Own one unique anchor and one PF enable reference; never reload root rules."""

    def __init__(self, policy, lifetime):
        self.policy, self.lifetime = policy, lifetime
        self.anchor = ANCHOR_PREFIX + secrets.token_hex(8)
        self.folder = None
        self.watchdog = None
        self.cleanup_result = None
        self.before_main = None
        self.before_enabled = None
        self.before_hash = None

    def start(self):
        require_admin()
        for interface in self.policy.interfaces:
            socket.if_nametoindex(interface)
        self.before_main = command([PF, "-sr"]).stdout
        if not re.search(r'^anchor "com\.apple/\*"', self.before_main, re.M):
            raise RuntimeError("No active com.apple/* parent anchor; refusing to reload root rules")
        self.before_enabled = enabled()
        self.before_hash = hashlib.sha256(PF_CONFIG.read_bytes()).hexdigest()
        self.folder = Path(tempfile.mkdtemp(prefix=PREFIX, dir=str(RUNTIME)))
        self.folder.chmod(0o700)
        try:
            state = {"anchor": self.anchor, "interfaces": self.policy.interfaces,
                     "targets": self.policy.targets, "created_at": time.time()}
            (self.folder / "state.json").write_text(json.dumps(state))
            (self.folder / "state.json").chmod(0o600)
            rule_file = self.folder / "rules.pf"
            rule_file.write_text(render(self.policy))
            rollback = self.folder / "cleanup.sh"
            rollback.write_text(cleanup_script(self.anchor, self.folder))
            rollback.chmod(0o700)
            command([PF, "-n", "-a", self.anchor, "-f", str(rule_file)])
            # Armed before any PF mutation. The timeout also protects a killed parent.
            self.watchdog = subprocess.Popen(
                ["/bin/sh", "-c", 'sleep "$1"; exec /bin/sh "$2"', "netmoat-watchdog",
                 str(self.lifetime), str(rollback)], stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            # The kernel's token is written directly to an on-disk log, closing the
            # gap between acquiring a reference and persisting a parsed token.
            with (self.folder / "enable.log").open("w") as log:
                result = subprocess.run([PF, "-E"], stdout=log, stderr=subprocess.STDOUT, timeout=10)
            if result.returncode:
                raise RuntimeError("Could not acquire a PF enable reference")
            parse_token((self.folder / "enable.log").read_text())
            command([PF, "-a", self.anchor, "-f", str(rule_file)])
            table = command([PF, "-a", self.anchor, "-t", "eg_targets", "-T", "show"]).stdout
            actual = {ipaddress.ip_network(s.strip(), strict=False) for s in table.splitlines() if s.strip()}
            expected = set(map(ipaddress.ip_network, self.policy.targets))
            if actual != expected:
                raise RuntimeError("Loaded target table did not match the requested policy")
            for label in ["eg_v4", "eg_v6"]:
                packet_count(command([PF, "-a", self.anchor, "-vvsr"]).stdout, label)
            return self
        except BaseException:
            self.close()
            raise

    def count(self, family):
        return packet_count(command([PF, "-a", self.anchor, "-vvsr"]).stdout,
                            "eg_v6" if family == 6 else "eg_v4")

    def close(self):
        if self.folder is None:
            return
        if self.cleanup_result is not None and self.cleanup_result.get("removed"):
            return
        rollback = self.folder / "cleanup.sh"
        if not rollback.exists():
            # No mutation is attempted before this script has been prepared.
            shutil.rmtree(self.folder)
            self.cleanup_result = {"removed": True, "started": False}
            return
        cleanup = command(["/bin/sh", str(rollback)], check=False)
        remaining = command([PF, "-a", self.anchor, "-sr"], check=False)
        tables = command([PF, "-a", self.anchor, "-s", "Tables"], check=False)
        # Nonzero pfctl readback is ambiguous: do not equate an error with empty rules.
        removed = (cleanup.returncode == 0 and remaining.returncode == 0
                   and tables.returncode == 0 and not remaining.stdout.strip()
                   and not tables.stdout.strip() and not (self.folder / "enable.log").exists())
        self.cleanup_result = {
            "removed": removed, "main_rules_unchanged": command([PF, "-sr"]).stdout == self.before_main,
            "pf_conf_unchanged": hashlib.sha256(PF_CONFIG.read_bytes()).hexdigest() == self.before_hash,
            "enable_status_restored": enabled() == self.before_enabled,
        }
        if removed:
            if self.watchdog is not None:
                try:
                    # Some launch paths inherit blocked SIGTERM; SIGKILL is used
                    # only for the private watchdog process group we created.
                    os.killpg(self.watchdog.pid, signal.SIGKILL)
                    self.watchdog.wait(timeout=3)
                except ProcessLookupError:
                    pass
                except subprocess.TimeoutExpired:
                    self.cleanup_result["watchdog_exit_observed"] = False
            shutil.rmtree(self.folder)
        else:
            self.cleanup_result["recovery_directory"] = str(self.folder)


def probe_socket(interface, address, protocol, port, timeout, used_ports):
    ip = ipaddress.ip_address(address)
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM if protocol == "TCP" else socket.SOCK_DGRAM)
    s.settimeout(timeout)
    start = time.monotonic()
    result = {"address": address, "family": ip.version, "protocol": protocol,
              "interface": interface, "connected": False}
    try:
        s.setsockopt(socket.IPPROTO_IPV6 if ip.version == 6 else socket.IPPROTO_IP,
                     125 if ip.version == 6 else 25, socket.if_nametoindex(interface))
        for _ in range(64):
            source_port = 40000 + secrets.randbelow(20000)
            if source_port in used_ports:
                continue
            try:
                s.bind(("::" if ip.version == 6 else "0.0.0.0", source_port))
                used_ports.add(source_port)
                break
            except OSError:
                continue
        else:
            raise RuntimeError("No fresh source port is available")
        s.connect((address, port))
        if protocol == "TCP":
            result["connected"] = True
        else:
            ident = secrets.randbelow(65536)
            query = (struct.pack("!HHHHHH", ident, 0x100, 1, 0, 0, 0)
                     + b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1))
            s.send(query)
            response = s.recv(4096)
            result["connected"] = (len(response) >= 12 and response[:2] == query[:2]
                                    and bool(struct.unpack("!H", response[2:4])[0] & 0x8000))
    except OSError as error:
        result["error"] = type(error).__name__
    finally:
        s.close()
    result["seconds"] = round(time.monotonic() - start, 3)
    return result


def verify(args, policy):
    addresses = [s for s in [args.ipv4, args.ipv6] if s]
    if not addresses:
        raise ValueError("Supply an IPv4 and/or IPv6 decoy you are allowed to test")
    for value, version in [(args.ipv4, 4), (args.ipv6, 6)]:
        if value and not re.fullmatch(r"[0-9A-Fa-f:.]+", value):
            raise ValueError("Decoys must be unscoped numeric IP addresses")
        if value and ipaddress.ip_address(value).version != version:
            raise ValueError("Decoy address family does not match its option")
    if args.interface not in policy.interfaces:
        raise ValueError("The probe interface must be included in the policy")
    if any(policy.includes(s) for s in addresses):
        raise ValueError("Decoys must be outside protected targets: baseline probes connect directly")
    require_admin()
    ports, baselines = set(), []
    for address in addresses:
        for proto, port in [("TCP", args.tcp_port), ("UDP", args.dns_port)]:
            baselines.append(probe_socket(args.interface, address, proto, port, args.timeout, ports))
    report = {"baselines": baselines, "checks": [], "families_requested": sorted(
        {ipaddress.ip_address(a).version for a in addresses}), "protected_targets_probed": False}
    if not all(s["connected"] for s in baselines):
        report.update({"passed": False, "reason": "Baseline unavailable; no rules applied"})
        return report
    session = Session(policy.with_decoys(addresses), args.rollback_after)
    try:
        session.start()
        for baseline in baselines:
            before = session.count(baseline["family"])
            outcome = probe_socket(args.interface, baseline["address"], baseline["protocol"],
                                   args.tcp_port if baseline["protocol"] == "TCP" else args.dns_port,
                                   args.timeout, ports)
            after = session.count(baseline["family"])
            report["checks"].append({"probe": outcome, "counter_delta": after - before,
                                     "passed": not outcome["connected"] and after > before})
    finally:
        session.close()
        report["cleanup"] = session.cleanup_result
    if session.cleanup_result and session.cleanup_result.get("removed"):
        report["recovery"] = [probe_socket(args.interface, b["address"], b["protocol"],
            args.tcp_port if b["protocol"] == "TCP" else args.dns_port, args.timeout, ports) for b in baselines]
    report["passed"] = (all(s["passed"] for s in report["checks"])
                        and len(report["checks"]) == len(baselines)
                        and bool(report.get("recovery")) and all(s["connected"] for s in report["recovery"])
                        and bool(report.get("cleanup")) and all(v is True for v in report["cleanup"].values()))
    return report


def inspect_state(folder):
    if folder.is_symlink() or folder.parent != RUNTIME or not folder.name.startswith(PREFIX):
        raise ValueError("State directory must be a framework-owned runtime directory")
    if folder.stat().st_uid != 0 or folder.stat().st_mode & 0o077:
        raise ValueError("Unsafe state directory ownership or permissions")
    path = folder / "state.json"
    if path.is_symlink() or path.stat().st_uid != 0:
        raise ValueError("Unsafe state file")
    state = json.loads(path.read_text())
    if not re.fullmatch(re.escape(ANCHOR_PREFIX) + r"[0-9a-f]{16}", state.get("anchor", "")):
        raise ValueError("State references an unsupported anchor")
    return state


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    for name in ["render", "guard", "probe"]:
        p = sub.add_parser(name)
        p.add_argument("--config", required=True)
        if name == "guard":
            p.add_argument("--seconds", type=int, default=60)
        if name == "probe":
            p.add_argument("--interface", required=True)
            p.add_argument("--ipv4")
            p.add_argument("--ipv6")
            p.add_argument("--tcp-port", type=int, default=443)
            p.add_argument("--dns-port", type=int, default=53)
            p.add_argument("--timeout", type=float, default=2)
            p.add_argument("--rollback-after", type=int, default=180)
    sub.add_parser("status")
    sub.add_parser("cleanup").add_argument("--state-dir", required=True)
    service = sub.add_parser("service", help="Install and manage the optional startup service")
    actions = service.add_subparsers(dest="service_action", required=True)
    actions.add_parser("install").add_argument("--config", required=True)
    for action in ["start", "stop", "status", "uninstall", "run"]:
        actions.add_parser(action)
    args = parser.parse_args(argv)
    try:
        if args.action == "render":
            print(render(Policy.load(args.config)), end="")
            return 0
        require_admin()
        if hasattr(signal, "pthread_sigmask"):
            signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGINT, signal.SIGTERM})
        def interrupted(signum, frame):
            raise KeyboardInterrupt()
        signal.signal(signal.SIGTERM, interrupted)
        if args.action == "service":
            # The installed launcher uses isolated Python; only add its own
            # administrator-owned source directory, never the working directory.
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            import netmoat_service
            return netmoat_service.main(args)
        if args.action == "status":
            states = []
            for folder in sorted(RUNTIME.glob(PREFIX + "*")):
                try:
                    state = inspect_state(folder)
                    result = command([PF, "-a", state["anchor"], "-vvsr"], check=False)
                    state.update({"directory": str(folder), "rules": result.stdout,
                                  "readback_ok": result.returncode == 0})
                    states.append(state)
                except (ValueError, OSError) as error:
                    states.append({"directory": str(folder), "error": str(error)})
            print(json.dumps({"pf_enabled": enabled(), "sessions": states}, indent=2))
            return 0
        if args.action == "cleanup":
            folder = Path(args.state_dir)
            state = inspect_state(folder)
            rollback = folder / "cleanup.sh"
            if rollback.is_symlink() or rollback.stat().st_uid != 0:
                raise ValueError("Unsafe cleanup script")
            command(["/bin/sh", str(rollback)])
            remaining = command([PF, "-a", state["anchor"], "-sr"])
            tables = command([PF, "-a", state["anchor"], "-s", "Tables"])
            if remaining.stdout.strip() or tables.stdout.strip() or (folder / "enable.log").exists():
                raise RuntimeError("Cleanup readback is incomplete; runtime state retained")
            # Leave the directory for the owning process to remove if it is alive.
            print(json.dumps({"removed": True, "directory": str(folder)}))
            return 0
        policy = Policy.load(args.config)
        if args.action == "probe":
            if not 0.1 <= args.timeout <= 5 or not 60 <= args.rollback_after <= 600:
                raise ValueError("Use timeout 0.1..5 seconds and rollback-after 60..600 seconds")
            if not all(1 <= port <= 65535 for port in [args.tcp_port, args.dns_port]):
                raise ValueError("Ports must be 1..65535")
            report = verify(args, policy)
            print(json.dumps(report, indent=2))
            return 0 if report["passed"] else 2
        if not 1 <= args.seconds <= 3600:
            raise ValueError("Session duration must be 1..3600 seconds")
        session = Session(policy, args.seconds + 15)
        try:
            session.start()
            print(json.dumps({"state": "loaded_not_verified", "anchor": session.anchor,
                              "directory": str(session.folder), "seconds": args.seconds}), flush=True)
            time.sleep(args.seconds)
        finally:
            session.close()
            print(json.dumps({"state": "finished", "cleanup": session.cleanup_result}), flush=True)
        return 0 if session.cleanup_result and session.cleanup_result.get("removed") else 2
    except KeyboardInterrupt:
        return 130
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
