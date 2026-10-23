# Security and operational scope

Privileged operations are limited to a unique child of an already-loaded
`com.apple/*` PF anchor and one enable-reference token acquired by that session.
The framework never reloads the root ruleset, disables PF globally, or flushes
global connection states. If the parent anchor is absent, startup stops.

Configuration is administrator-controlled input. Interface names and literal
IP/CIDR targets are validated before rule generation. Runtime state lives in a
root-owned private directory. Do not execute an unreviewed checkout as root.

A successful rule load is not proof of protection. Use controlled decoys and
review all requested address families, PF counters, and cleanup results. A
failed baseline, an unreadable counter, or an ambiguous cleanup readback is a
failure rather than a pass. The framework does not promise per-application,
hostname, startup, reboot, or established-connection isolation.

Issue reports should use documentation-only targets and omit private policies,
real network identifiers, credentials, and raw local reports. For a sensitive
security issue, use the repository's private vulnerability reporting feature
when available; otherwise avoid publishing exploit details or secrets in a
public issue.
