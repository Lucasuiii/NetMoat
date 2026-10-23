# Backend failure semantics

The Rust service manages policy. Packet filtering remains in the macOS PF
kernel; no packet stream is copied through Rust and no network extension is
installed. The controller remains SwiftUI.

## Ownership and exit

One system job owns a fixed child of the existing `com.apple/*` parent, a private
runtime directory and one enable token. A lifetime flock prevents two daemons.
An independent management flock serializes configure/start/stop/upgrade/uninstall
without blocking ticks.

The PF guard has **no cleanup destructor**. Signals, returned errors, panics,
status-write failures and launchd replacement retain rules and the enable log.
Explicit stop/uninstall records intent, disables/unloads the job, waits for its
lifetime lock, then flushes only its own anchor. Its token is released only after
empty rule/table readback. Ambiguous cleanup preserves recovery state. The real
runner connects token output directly to the log descriptor.

Last-known rules cannot ensure protection if another administrator clears PF,
removes the parent anchor or changes interfaces. Repair runs about every ten
seconds plus execution time. Startup is not an earliest-boot barrier.

## Configuration transaction

1. Parse size-limited typed input before mutation.
2. Acquire management lock, compare expected SHA-256 with current bytes. Stale
   writers return a conflict without policy changes.
3. Persist previous bytes, atomically replace and synchronize new file and parent.
   Compute the transaction digest from intended bytes, not a later file read.
4. Daemon constructs the complete effective policy, checks parent/enabled status,
   repairs only its anchor as needed, reads rules/table back, then publishes the
   configuration and effective-policy fingerprints.
5. Writer waits for its version and live PF readback. Timeout rollback only owns
   the candidate while its digest still matches; restoration is checked and
   ambiguous verification returns an error.

A killed writer may leave a valid candidate committed, not half-written JSON.
That candidate can be applied on the next tick. Success is not a connection test.
Controller snapshots also take the management lock, so the editable document and
its check cannot accidentally be paired from two concurrent transactions.

## DNS and retained policy

Queries use fixed `/usr/bin/curl` arguments and explicit loopback HTTP proxy.
Environment proxy variables are cleared; there is no direct retry. JSON shapes,
size, response family and cache addresses are checked. Only conservative global
unicast DNS addresses are accepted, excluding special-purpose ranges as well as
private/documentation addresses; explicit static CIDRs keep general IP syntax.

A host requires successful A and AAAA replies and at least one address before
replacing its record. Partial failure retains its entire previous record.
Malformed replies are Result errors. Missing usable records prevent installing
an incomplete target set. Valid stale records remain usable with a warning.
Successful proxy queries can recover a corrupt cache; existing PF rules remain
until a complete effective policy is available.

Scheduling uses monotonic time and relevant DNS settings. Renaming modules does
not trigger queries. Display timestamps depend on wall-clock time; clock jumps
can conservatively invalidate status until a successful update.

## Status and energy

Ordinary ticks check parent, enable status, child rules and targets. Counters are
only requested for user status. Heartbeats are atomically replaced on change or
every thirty seconds without fsync. Policy, reference, installation, rules and
cache updates still use durable synchronization.

The public heartbeat contains format/backend/version, last check, state, config
digest and counts. It contains no domains, addresses, interfaces, module names,
proxy settings or errors. GUI checks ownership, permissions, type, size, age and
config digest. It reads every fifteen seconds while active and on activation.
It expires observations after seventy-five seconds; privileged status uses
ninety seconds and live PF readback. A heartbeat is a bounded recent observation,
not continuous instantaneous kernel attestation.
The GUI also respects a newer privileged check: an older green heartbeat cannot
override a failed manual check. A later successful heartbeat can show recovery.

## Installation and migration

Installed binary, policy and private state are administrator owned. Privileged
CLI accepts no executable-path or environment overrides. Child commands use
absolute paths, clean environments, bounded output and deadlines. Service CLI
requires macOS and euid 0. Never execute an unreviewed checkout as administrator.

Upgrade validates existing policy and saves job/launcher/manifest/previous native
binary. It unloads the old job, waits for its lifetime lock, stages the new
installation, and requires fresh native readback before removing backup and old
installed Python files. Policy is preserved. Old Python may clear rules on exit,
so migration can have a gap. Failure restores launch configuration and attempts
restart; retained backup or restoration errors require inspection. Paused
installations remain paused.

## Tests and boundaries

Rust tests use temporary directories and simulated PF/launchd. Separate fixture
processes exercise SIGTERM and an injected panic; restart checks token adoption.
Other cases cover proxy-only queries, malformed DNS/cache, missing-parent repair,
stale writers, conditional rollback, management locking, live acknowledgement,
upgrade rollback, explicit cleanup and uninstall. Real command runner tests cover
timeout termination and output bounds.

These tests require no root or protected-destination access. They do not prove
actual routing, real launchd restart timing, sleep/wake behavior or battery
savings. Releases should separately record installed-service tests, keeping
private policies and raw local evidence outside the public repository.
