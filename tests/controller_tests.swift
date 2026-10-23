import Foundation

@main struct ControllerTests {
    @MainActor static func main() {
        let model = Model()
        let version = String(repeating: "a", count: 64)
        let module = ProtectionModule(id: "work-service", name: "Work", enabled: true, targets: ["192.0.2.0/24"], hosts: [])
        model.snapshot = Snapshot(configuration: PolicyDocument(interfaces: ["en0"], targets: [], dns: nil, modules: [module]),
            configuration_sha256: version, status: GuardStatus(installed: true, loaded: true, autostart_enabled: true,
                rules_verified: true, state: ServiceState(state: "rules_loaded", target_count: 1)))
        let now = Date()
        let good = PublicStatus(format: "netmoat-status-v1", state: "rules_loaded", updated_at: now.timeIntervalSince1970,
            backend: "rust", version: "0.4.0", configuration_sha256: version, rules_verified: true,
            target_count: 1, active_modules: 1, stale_host_count: 0)
        model.observedAt = now
        model.heartbeat = good
        precondition(model.protected && !model.needsCheck)
        model.observedAt = now.addingTimeInterval(76)
        precondition(!model.protected && model.needsCheck && model.statusTitle == "保护待核对")
        model.observedAt = now
        model.heartbeat?.configuration_sha256 = String(repeating: "b", count: 64)
        precondition(!model.protected && model.statusDetail.contains("其他入口"))
        model.heartbeat = good
        model.heartbeat?.updated_at = now.addingTimeInterval(6).timeIntervalSince1970
        precondition(!model.protected)
        model.heartbeat = good
        model.heartbeat?.rules_verified = false
        model.heartbeat?.state = "degraded"
        precondition(!model.protected && model.needsCheck)
        model.heartbeat = nil
        precondition(!model.protected && model.needsCheck)
        model.heartbeat = good
        model.snapshot?.status.checked_at = now.addingTimeInterval(1).timeIntervalSince1970
        model.snapshot?.status.rules_verified = false
        precondition(!model.protected, "A newer failed live check must override an older green heartbeat")
        model.heartbeat?.updated_at = now.addingTimeInterval(2).timeIntervalSince1970
        precondition(model.protected, "A newer successful daemon check can recover the status")
        model.heartbeat?.state = "stopped"
        model.heartbeat?.rules_verified = false
        precondition(!model.protected && !model.serviceLoaded && !model.needsCheck)
        model.snapshot?.status.checked_at = nil
        model.heartbeat = good
        model.snapshot?.configuration.modules[0].enabled = false
        precondition(!model.protected && !model.needsCheck)
        precondition(Runner.quote("a'b") == "'a'\"'\"'b'")
        precondition(split("en0，en1\nen0") == ["en0", "en1"])
        print("Controller checks passed: fresh/stale/future/degraded/missing status, version conflict, disabled module, quoting, input split")
    }
}
