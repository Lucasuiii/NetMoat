# Security and operational scope

Privileged operations are limited to a unique child of an already-loaded
`com.apple/*` PF anchor and one enable-reference token acquired by that session.
The framework never reloads the root ruleset, disables PF globally, or flushes
global connection states. If the parent anchor is absent, startup stops.

The optional startup service reserves the child anchor ending in
`0000000000000000`, holds an exclusive runtime lock, and retains its enable
reference across process crashes within one boot. launchd restarts it; normal
stop/uninstall flushes only that anchor and releases only its own reference.
Code/configuration are copied into an administrator-owned directory and run by
the system Python in isolated mode. Do not replace the system interpreter with
a user-editable environment. Service installation is an explicit privileged action.

Configuration is administrator-controlled input. Interface names and literal
IP/CIDR targets are validated before rule generation. Runtime state lives in a
root-owned private directory. Do not execute an unreviewed checkout as root.

A successful rule load is not proof of protection. Use controlled decoys and
review all requested address families, PF counters, and cleanup results. A
failed baseline, an unreadable counter, or an ambiguous cleanup readback is a
failure rather than a pass. The framework does not promise per-application,
hostname, earliest-startup, reboot-transition, or established-connection isolation.
Startup and periodic repair can have gaps. Optional exact-host DNS refresh is
forced through a configured loopback HTTP proxy to Cloudflare DoH; failures
retain last-good addresses and eventually report stale hosts. Shared IPs can
affect unrelated direct connections. DNS refresh is not a domain-filter backend.

Issue reports should use documentation-only targets and omit private policies,
real network identifiers, credentials, and raw local reports. For a sensitive
security issue, use the repository's private vulnerability reporting feature
when available; otherwise avoid publishing exploit details or secrets in a
public issue.
