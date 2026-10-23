# Security and operational scope

Permanent backend and service CLI are Rust. Privileged operations are limited to
one fixed owned child of an existing `com.apple/*` PF anchor and its enable token.
The framework never reloads root rules, globally disables PF or flushes global
connection states. Missing parent causes application failure without root reload.

The anchor ends in `0000000000000000`. Lifetime and management locks protect
process ownership and serialized changes. No Drop handler clears rules. Explicit
stop/uninstall unloads the job, waits for its lock, flushes only its anchor and
releases only its token after empty readback. Unexpected exit is not a stop.

Binary/configuration are administrator owned. Path checks reject symlinks,
unexpected owners and group/world-writable files. JSON is size-limited and typed;
interfaces, targets, exact hostnames and loopback proxies are validated. Saves
require an expected configuration version; rollback must still own its candidate.
Do not run an unreviewed checkout/binary as administrator. See
[backend design](docs/BACKEND.md).

DNS is forced through explicit loopback HTTP proxy to Cloudflare DoH, with no
direct fallback. Reply/cache errors retain last-good records; missing records
prevent installing an incomplete policy. Old records cannot ensure new real-world
addresses are blocked. Shared IPs may affect unrelated connections. This is not
a hostname-filter backend.

Private state stays in administrator-owned private directories. A sanitized
public heartbeat exposes only aggregate counts, configuration digest and status,
not targets, interfaces, proxy settings, module names or errors. Old observations
are marked unknown. A green heartbeat is a recent check, not continuous proof.

Readback is not an end-to-end test. Validate intended paths and address families.
There is no promise of per-app, domain, earliest-boot, reboot-transition,
other-interface or established-connection isolation. External PF changes and
periodic repair can have gaps. Old Python cleans rules on exit, so 0.3-to-0.4
migration can have a gap too. Enabling PF may activate other already-loaded rules.
No full security audit, zero-bug or uninterrupted-protection claim is made.

Optional Python tools provide temporary sessions and decoy tests only. Their
watchdog intentionally revokes temporary rules at expiry; permanent Rust daemon
has different retained-rule semantics. They are not installed as a backend.

Reports should use documentation targets and omit personal policies, network
identifiers, credentials and raw local reports. Use private vulnerability
reporting when available; avoid exploit details or secrets in public issues.
