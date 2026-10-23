import AppKit
import SwiftUI

struct ProtectionModule: Codable, Identifiable, Equatable, Sendable {
    var id: String
    var name: String
    var enabled: Bool
    var targets: [String]
    var hosts: [String]
    static var empty: Self { .init(id: UUID().uuidString.lowercased(), name: "", enabled: true, targets: [], hosts: []) }
}
struct DNSSettings: Codable, Sendable {
    var hosts: [String]
    var proxy: String
    var refresh_seconds: Int
}
struct PolicyDocument: Codable, Sendable {
    var interfaces: [String]
    var targets: [String]
    var dns: DNSSettings?
    var modules: [ProtectionModule]
}
struct DNSState: Codable, Sendable { var enabled: Bool?; var stale_hosts: [String]? }
struct ServiceState: Codable, Sendable {
    var state: String?
    var target_count: Int?
    var dns: DNSState?
    var error: String?
}
struct GuardStatus: Codable, Sendable {
    var installed: Bool
    var loaded: Bool
    var autostart_enabled: Bool
    var rules_verified: Bool
    var state: ServiceState?
    var checked_at: Double?
    var error: String?
}
struct Snapshot: Codable, Sendable { var configuration: PolicyDocument; var configuration_sha256: String?; var status: GuardStatus }
struct PublicStatus: Decodable, Sendable {
    var format: String
    var state: String
    var updated_at: Double
    var backend: String
    var version: String
    var configuration_sha256: String
    var rules_verified: Bool
    var target_count: Int
    var active_modules: Int
    var stale_host_count: Int
}

enum Runner {
    static func quote(_ value: String) -> String { "'" + value.replacingOccurrences(of: "'", with: "'\"'\"'") + "'" }
    static func run(_ command: String) throws -> String {
        let escaped = command.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        let source = "with timeout of 180 seconds\nreturn do shell script \"\(escaped)\" with administrator privileges with prompt \"管理 NetMoat 网络保护\"\nend timeout"
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", source]
        let out = Pipe(), err = Pipe()
        process.standardOutput = out; process.standardError = err
        try process.run()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        let errors = err.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            let message = String(decoding: errors, as: UTF8.self)
            let explanation = message.contains("-128") ? "操作已取消，保护配置保持原状。" : message.contains("Configuration conflict") ? "配置已由其他入口更新，请重新读取后再保存。" : message.contains("Another NetMoat operation") ? "另一个管理操作尚未结束，请稍后重新读取状态。" : message
            throw NSError(domain: "NetMoat", code: Int(process.terminationStatus), userInfo: [NSLocalizedDescriptionKey: explanation])
        }
        return String(decoding: data, as: UTF8.self)
    }
}

@MainActor final class Model: ObservableObject {
    @Published var snapshot: Snapshot?
    @Published var busy = false
    @Published var message: String?
    @Published var error: String?
    @Published var heartbeat: PublicStatus?
    @Published var observedAt = Date()
    let preview = CommandLine.arguments.contains("--preview")
    var modules: [ProtectionModule] { snapshot?.configuration.modules ?? [] }
    var activeCount: Int { modules.filter(\.enabled).count }
    var stale: [String] { snapshot?.status.state?.dns?.stale_hosts ?? [] }
    var heartbeatFresh: Bool {
        guard let heartbeat else { return false }
        let age = observedAt.timeIntervalSince1970 - heartbeat.updated_at
        return (-5...75).contains(age)
    }
    var configurationMatches: Bool { heartbeat?.configuration_sha256 == snapshot?.configuration_sha256 }
    var protected: Bool {
        if preview { return snapshot?.status.rules_verified == true && activeCount > 0 }
        guard activeCount > 0 else { return false }
        let checked = snapshot?.status.checked_at ?? 0
        if let heartbeat, heartbeatFresh, heartbeat.updated_at >= checked {
            return configurationMatches && heartbeat.rules_verified && heartbeat.target_count > 0
        }
        let age = observedAt.timeIntervalSince1970 - checked
        return checked > 0 && (-5...75).contains(age) && snapshot?.status.rules_verified == true && (snapshot?.status.state?.target_count ?? 0) > 0
    }
    var serviceLoaded: Bool {
        if let heartbeat, heartbeatFresh, heartbeat.updated_at >= (snapshot?.status.checked_at ?? 0) { return heartbeat.state != "stopped" }
        return snapshot?.status.loaded == true
    }
    var needsCheck: Bool { !preview && snapshot != nil && serviceLoaded && !protected && activeCount > 0 }
    var statusTitle: String { protected ? "保护已开启" : needsCheck ? "保护待核对" : "保护未开启" }
    var statusDetail: String {
        if protected { return "已启用的目标正在按配置限制直连。" }
        if needsCheck {
            if !heartbeatFresh { return "后台状态已过期，请重新读取核对。" }
            if !configurationMatches { return "配置已从其他入口更新，请重新读取。" }
            return "后台报告异常，请重新读取查看详情；已有规则可能仍在。"
        }
        return activeCount == 0 ? "添加或开启一个模块，选择要保护的目标。" : "开启服务，让已配置的模块生效。"
    }

    func observeStatus() {
        observedAt = Date()
        guard !preview else { return }
        let path = "/private/var/run/netmoat-public/status.json"
        do {
            let attributes = try FileManager.default.attributesOfItem(atPath: path)
            guard attributes[.type] as? FileAttributeType == .typeRegular,
                  (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == 0,
                  let permissions = attributes[.posixPermissions] as? NSNumber, permissions.intValue & 0o022 == 0,
                  let size = attributes[.size] as? NSNumber, size.intValue <= 16384 else { heartbeat = nil; return }
            let value = try JSONDecoder().decode(PublicStatus.self, from: Data(contentsOf: URL(fileURLWithPath: path)))
            heartbeat = value.format == "netmoat-status-v1" && value.backend == "rust" ? value : nil
        } catch { heartbeat = nil }
    }

    init() {
        if preview {
            snapshot = Snapshot(configuration: PolicyDocument(interfaces: ["en0"], targets: [],
                dns: DNSSettings(hosts: [], proxy: "http://127.0.0.1:8080", refresh_seconds: 300),
                modules: [.init(id: "example-service", name: "示例工作服务", enabled: true,
                                targets: ["192.0.2.0/24", "2001:db8::/32"], hosts: ["service.example.com"])]),
                status: GuardStatus(installed: true, loaded: true, autostart_enabled: true, rules_verified: true,
                                    state: ServiceState(state: "rules_loaded", target_count: 3,
                                                        dns: DNSState(enabled: true, stale_hosts: []))))
        }
        observeStatus()
    }

    func execute(_ action: String, document: PolicyDocument? = nil) {
        guard !busy else { return }
        error = nil; message = nil
        if preview {
            if let document { snapshot?.configuration = document }
            if action == "stop" { snapshot?.status.rules_verified = false; snapshot?.status.autostart_enabled = false }
            if action == "start" { snapshot?.status.rules_verified = true; snapshot?.status.autostart_enabled = true }
            message = "预览已更新，未修改系统。"; return
        }
        busy = true
        Task {
            var file: URL?
            defer { busy = false; if let file { try? FileManager.default.removeItem(at: file) } }
            do {
                var command = "/usr/local/bin/netmoat service " + action
                if let document {
                    guard let version = snapshot?.configuration_sha256, version.count == 64 else {
                        throw NSError(domain: "NetMoat", code: 1, userInfo: [NSLocalizedDescriptionKey: "请先重新读取状态，再保存配置。"])
                    }
                    let path = FileManager.default.temporaryDirectory.appendingPathComponent("NetMoat-policy-\(UUID().uuidString).json")
                    file = path
                    try JSONEncoder().encode(document).write(to: path, options: .atomic)
                    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
                    command += " --config " + Runner.quote(path.path) + " --expected-sha " + Runner.quote(version)
                }
                if action != "snapshot" && action != "uninstall" { command += " >/dev/null && /usr/local/bin/netmoat service snapshot" }
                let shellCommand = command
                let text = try await Task.detached { try Runner.run(shellCommand) }.value
                if action == "uninstall" { snapshot = nil; message = "后台服务已卸载。"; return }
                let result = try JSONDecoder().decode(Snapshot.self, from: Data(text.utf8))
                snapshot = result
                observeStatus()
                if let backendError = result.status.error ?? result.status.state?.error { self.error = backendError }
                if action == "configure" {
                    message = !stale.isEmpty ? "配置已保存，部分主机地址尚未更新。" : result.status.rules_verified ? "模块配置已保存并核对。" : "配置已保存，将在开启保护后生效。"
                }
                if action == "stop" { message = "保护已暂停，开机启动已关闭。" }
                if action == "start" { message = "保护已开启，开机启动已开启。" }
            } catch { self.error = error.localizedDescription }
        }
    }
    func save(_ module: ProtectionModule) {
        guard var document = snapshot?.configuration else { return }
        if let index = document.modules.firstIndex(where: { $0.id == module.id }) { document.modules[index] = module }
        else { document.modules.append(module) }
        execute("configure", document: document)
    }
    func remove(_ module: ProtectionModule) {
        guard var document = snapshot?.configuration else { return }
        document.modules.removeAll { $0.id == module.id }
        execute("configure", document: document)
    }
}

enum Section: String, CaseIterable, Identifiable {
    case overview = "概览", modules = "保护模块", settings = "设置"
    var id: String { rawValue }
    var icon: String { switch self { case .overview: "square.grid.2x2"; case .modules: "square.stack.3d.up"; case .settings: "slider.horizontal.3" } }
}

struct ContentView: View {
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var model = Model()
    @State private var section: Section = .overview
    @State private var editing: ProtectionModule?
    @State private var deleting: ProtectionModule?
    @State private var uninstall = false
    @State private var proxy = ""
    @State private var interfaces = ""
    @State private var refresh = 300
    private let accent = Color(red: 0.23, green: 0.48, blue: 0.51)
    var body: some View {
        HStack(spacing: 0) {
            sidebar
            Divider()
            VStack(alignment: .leading, spacing: 22) {
                header
                if let error = model.error { notice(error, icon: "exclamationmark.circle", color: .orange) }
                if let message = model.message { notice(message, icon: "checkmark.circle", color: accent) }
                if model.snapshot == nil { welcome }
                else {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 22) {
                            switch section {
                            case .overview: overview
                            case .modules: moduleList
                            case .settings: settings
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading).padding(.bottom, 8)
                    }
                }
                footer
            }.padding(30).frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(minWidth: 870, minHeight: 620)
        .background(Color(nsColor: .windowBackgroundColor))
        .tint(accent)
        .sheet(item: $editing) { module in ModuleEditor(module: module) { model.save($0) } }
        .confirmationDialog("移除这个模块？", isPresented: Binding(get: { deleting != nil }, set: { if !$0 { deleting = nil } }), titleVisibility: .visible) {
            Button("移除模块", role: .destructive) { if let module = deleting { model.remove(module) }; deleting = nil }
            Button("取消", role: .cancel) { deleting = nil }
        } message: { Text("其他模块保持原状；移除后，这个模块的目标将不再拦截。") }
        .confirmationDialog("卸载 NetMoat 后台服务？", isPresented: $uninstall, titleVisibility: .visible) {
            Button("卸载服务", role: .destructive) { model.execute("uninstall") }
        } message: { Text("撤销保护规则、关闭开机启动，并移除本机服务配置。") }
        .onChange(of: section) { _, next in if next == .settings { loadSettings() } }
        .onChange(of: model.snapshot?.configuration.dns?.proxy) { _, _ in if section == .settings { loadSettings() } }
        .task(id: scenePhase) {
            guard scenePhase == .active else { return }
            while !Task.isCancelled {
                model.observeStatus()
                do { try await Task.sleep(for: .seconds(15)) } catch { break }
            }
        }
    }

    var sidebar: some View {
        VStack(alignment: .leading, spacing: 32) {
            HStack(spacing: 10) {
                Image(nsImage: NSApplication.shared.applicationIconImage).resizable().frame(width: 43, height: 43)
                VStack(alignment: .leading, spacing: 3) {
                    Text("NetMoat").font(.system(size: 19, weight: .semibold, design: .rounded))
                    Text("网络护城河").font(.system(size: 11)).foregroundStyle(.secondary)
                }
            }.padding(.top, 14)
            VStack(spacing: 7) {
                ForEach(Section.allCases) { item in
                    Button { section = item } label: {
                        HStack(spacing: 12) { Image(systemName: item.icon).frame(width: 18); Text(item.rawValue); Spacer() }
                            .font(.system(size: 13, weight: section == item ? .semibold : .regular))
                            .padding(.horizontal, 13).padding(.vertical, 12)
                            .background(section == item ? Color.primary.opacity(0.065) : .clear, in: RoundedRectangle(cornerRadius: 10))
                    }.buttonStyle(.plain).accessibilityLabel(item.rawValue)
                }
            }
            Spacer()
            VStack(alignment: .leading, spacing: 7) {
                HStack(spacing: 7) { Circle().fill(model.protected ? accent : Color.secondary).frame(width: 6, height: 6); Text(model.protected ? "保护运行中" : "本机网络控制").font(.system(size: 11, weight: .medium)) }
                Text(model.preview ? "预览模式 · 不修改系统" : "配置留在你的 Mac 上")
                    .font(.system(size: 10)).foregroundStyle(.tertiary)
            }.padding(.bottom, 12)
        }.padding(.horizontal, 20).frame(width: 190).background(Color.primary.opacity(0.018))
    }

    var header: some View {
        HStack(alignment: .center) {
            VStack(alignment: .leading, spacing: 7) {
                Text(section.rawValue).font(.system(size: 27, weight: .semibold))
                Text(section == .modules ? "为不同服务组合独立的保护规则" : section == .settings ? "连接方式与本机服务" : "掌握保护状态，管理自己的网络边界")
                    .font(.system(size: 12)).foregroundStyle(.secondary)
            }
            Spacer()
            if model.busy { ProgressView().controlSize(.small); Text("处理中").font(.caption).foregroundStyle(.secondary) }
            else if model.snapshot != nil { Button { model.execute("snapshot") } label: { Image(systemName: "arrow.clockwise") }.help("重新读取状态").buttonStyle(.borderless) }
        }
    }
    var welcome: some View {
        VStack(alignment: .leading, spacing: 18) {
            Image(systemName: "circle.dotted.circle").font(.system(size: 44, weight: .ultraLight)).foregroundStyle(accent)
            Text("连接你的本机服务").font(.title2.weight(.medium))
            Text("读取当前配置后，即可管理现有保护并添加更多服务。首次读取可能需要系统管理员认证。")
                .font(.system(size: 13)).foregroundStyle(.secondary).lineSpacing(5)
            Button("读取保护状态") { model.execute("snapshot") }.buttonStyle(.borderedProminent).disabled(model.busy)
        }.padding(28).frame(maxWidth: .infinity, alignment: .leading).card()
        .frame(maxHeight: .infinity, alignment: .top)
    }
    var overview: some View {
        VStack(alignment: .leading, spacing: 22) {
            HStack(alignment: .top, spacing: 20) {
                Image(systemName: model.protected ? "checkmark.circle" : "pause.circle")
                    .font(.system(size: 38, weight: .ultraLight)).foregroundStyle(model.protected ? accent : .secondary)
                VStack(alignment: .leading, spacing: 9) {
                    Text(model.statusTitle).font(.system(size: 22, weight: .semibold))
                    Text(model.statusDetail)
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                    HStack(spacing: 8) {
                        chip(model.snapshot?.status.autostart_enabled == true ? "开机启动已开" : "开机启动已关")
                        chip("\(model.activeCount) 个启用模块")
                    }.padding(.top, 4)
                    if let heartbeat = model.heartbeat, !model.preview {
                        Text("最近核对 \(Date(timeIntervalSince1970: heartbeat.updated_at).formatted(date: .omitted, time: .standard))")
                            .font(.system(size: 10)).foregroundStyle(.tertiary)
                    }
                }
                Spacer(minLength: 0)
                Button(model.serviceLoaded ? "暂停保护" : "开启保护") {
                    model.execute(model.serviceLoaded ? "stop" : "start")
                }.buttonStyle(.bordered).disabled(model.busy)
            }.padding(26).card()
            if !model.stale.isEmpty || (model.heartbeat?.stale_host_count ?? 0) > 0 {
                notice("\(max(model.stale.count, model.heartbeat?.stale_host_count ?? 0)) 个主机的地址尚未更新，当前保留可用缓存。", icon: "clock", color: .orange)
            }
            HStack(spacing: 14) {
                metric("保护模块", value: "\(model.modules.count)", detail: "各自编辑与启停")
                metric("已加载地址", value: "\(model.snapshot?.status.state?.target_count ?? 0)", detail: "IP 地址与范围")
                metric("网络接口", value: model.snapshot?.configuration.interfaces.joined(separator: ", ") ?? "—", detail: "随该网卡切换 Wi-Fi 生效")
            }
            HStack { Text("你的模块").font(.system(size: 15, weight: .semibold)); Spacer(); Button("管理模块") { section = .modules }.buttonStyle(.borderless) }
            ForEach(model.modules.prefix(3)) { module in moduleRow(module, controls: false) }
            if model.modules.isEmpty { emptyModules }
        }
    }
    var moduleList: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack { Text("\(model.modules.count) 个模块 · \(model.activeCount) 个启用").font(.system(size: 12)).foregroundStyle(.secondary); Spacer(); Button { editing = .empty } label: { Label("添加模块", systemImage: "plus") }.buttonStyle(.borderedProminent).disabled(model.busy).keyboardShortcut("n") }
            ForEach(model.modules) { module in moduleRow(module, controls: true) }
            if model.modules.isEmpty { emptyModules }
            Text("主机名会转换为当前 IP 地址进行拦截。共享同一 IP 的其他直连服务也可能受影响。")
                .font(.system(size: 11)).foregroundStyle(.secondary).lineSpacing(4).padding(.top, 8)
        }
    }
    var emptyModules: some View { Text("还没有模块。添加一个网站或服务，为它设置独立的保护规则。").font(.system(size: 13)).foregroundStyle(.secondary).padding(25).frame(maxWidth: .infinity, alignment: .leading).card() }
    func moduleRow(_ module: ProtectionModule, controls: Bool) -> some View {
        HStack(spacing: 14) {
            Image(systemName: "square.stack.3d.up").font(.system(size: 17, weight: .light)).foregroundStyle(module.enabled ? accent : .secondary)
                .frame(width: 40, height: 40).background(accent.opacity(0.07), in: RoundedRectangle(cornerRadius: 11))
            VStack(alignment: .leading, spacing: 6) {
                Text(module.name).font(.system(size: 14, weight: .medium))
                Text("\(module.hosts.count) 个主机 · \(module.targets.count) 个 IP 范围").font(.system(size: 11)).foregroundStyle(.secondary)
                if module.enabled && module.hosts.contains(where: { model.stale.contains($0) }) {
                    Text("部分地址待更新").font(.system(size: 10)).foregroundStyle(.orange)
                }
            }
            Spacer()
            if controls {
                Button { editing = module } label: { Image(systemName: "pencil") }.buttonStyle(.borderless).help("编辑 \(module.name)").accessibilityLabel("编辑 \(module.name)")
                Button { deleting = module } label: { Image(systemName: "trash") }.buttonStyle(.borderless).foregroundStyle(.secondary).help("移除 \(module.name)").accessibilityLabel("移除 \(module.name)")
                Toggle("启用", isOn: Binding(get: { module.enabled }, set: { value in var edited = module; edited.enabled = value; model.save(edited) }))
                    .toggleStyle(.switch).controlSize(.small).labelsHidden().accessibilityLabel("\(module.name) 保护开关")
            } else { Text(module.enabled ? "已启用" : "已关闭").font(.system(size: 11)).foregroundStyle(module.enabled ? accent : .secondary) }
        }.padding(18).card().disabled(model.busy)
    }
    var settings: some View {
        VStack(alignment: .leading, spacing: 22) {
            VStack(alignment: .leading, spacing: 18) {
                Text("地址更新").font(.system(size: 16, weight: .semibold))
                settingField("本机 HTTP 代理", text: $proxy, placeholder: "http://127.0.0.1:8080")
                Text("只用于查询主机地址，不会替你选择代理节点。代理不可用时保留已有缓存。")
                    .font(.system(size: 11)).foregroundStyle(.secondary).lineSpacing(4)
                Picker("更新间隔", selection: $refresh) { Text("1 分钟").tag(60); Text("5 分钟").tag(300); Text("15 分钟").tag(900) }.frame(maxWidth: 280)
                Divider()
                settingField("保护的网络接口", text: $interfaces, placeholder: "en0")
                Text("规则跟随网卡，不绑定 Wi-Fi 名称。多个接口用逗号分隔。")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
                Button("保存设置") {
                    guard var document = model.snapshot?.configuration else { return }
                    document.interfaces = split(interfaces)
                    let old = document.dns
                    document.dns = DNSSettings(hosts: old?.hosts ?? [], proxy: proxy.trimmingCharacters(in: .whitespacesAndNewlines), refresh_seconds: refresh)
                    model.execute("configure", document: document)
                }.buttonStyle(.borderedProminent).disabled(model.busy)
            }.padding(24).card()
            VStack(alignment: .leading, spacing: 12) {
                Text("本机服务").font(.system(size: 16, weight: .semibold))
                Text("开启保护会同时启用开机启动；暂停保护会同时关闭开机启动。保护只覆盖所列接口和配置中的目标，不能保证所有动态入口零遗漏。")
                    .font(.system(size: 12)).foregroundStyle(.secondary).lineSpacing(5)
                Button("卸载后台服务", role: .destructive) { uninstall = true }.disabled(model.busy)
            }.padding(24).card()
        }
    }
    func loadSettings() {
        proxy = model.snapshot?.configuration.dns?.proxy ?? "http://127.0.0.1:8080"
        refresh = model.snapshot?.configuration.dns?.refresh_seconds ?? 300
        interfaces = model.snapshot?.configuration.interfaces.joined(separator: ", ") ?? "en0"
    }
    func settingField(_ title: String, text: Binding<String>, placeholder: String) -> some View {
        VStack(alignment: .leading, spacing: 8) { Text(title).font(.system(size: 12, weight: .medium)); TextField(placeholder, text: text).textFieldStyle(.roundedBorder) }
    }
    func metric(_ title: String, value: String, detail: String) -> some View {
        VStack(alignment: .leading, spacing: 9) { Text(title).font(.system(size: 11)).foregroundStyle(.secondary); Text(value).font(.system(size: 23, weight: .medium, design: .rounded)).lineLimit(1).minimumScaleFactor(0.7); Text(detail).font(.system(size: 10)).foregroundStyle(.tertiary) }.padding(18).frame(maxWidth: .infinity, alignment: .leading).card()
    }
    func chip(_ text: String) -> some View { Text(text).font(.system(size: 10, weight: .medium)).padding(.horizontal, 9).padding(.vertical, 5).background(Color.primary.opacity(0.045), in: Capsule()) }
    func notice(_ text: String, icon: String, color: Color) -> some View { HStack(alignment: .top, spacing: 8) { Image(systemName: icon); Text(text).textSelection(.enabled); Spacer(minLength: 0) }.font(.system(size: 12)).foregroundStyle(color).padding(12).background(color.opacity(0.07), in: RoundedRectangle(cornerRadius: 10)) }
    var footer: some View { HStack { Text("NetMoat · Rust 后台").font(.system(size: 10, weight: .medium)); Spacer(); Text("本地配置 · 无遥测").font(.system(size: 10)) }.foregroundStyle(.tertiary) }
}

func split(_ value: String) -> [String] {
    Array(NSOrderedSet(array: value.components(separatedBy: CharacterSet(charactersIn: ",，\n\r\t ")).map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty })) as? [String] ?? []
}

struct ModuleEditor: View {
    @Environment(\.dismiss) private var dismiss
    var module: ProtectionModule
    var save: (ProtectionModule) -> Void
    @State private var name = ""
    @State private var hosts = ""
    @State private var targets = ""
    var valid: Bool { !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && (!split(hosts).isEmpty || !split(targets).isEmpty) }
    var body: some View {
        VStack(alignment: .leading, spacing: 19) {
            Text(module.name.isEmpty ? "添加保护模块" : "编辑保护模块").font(.system(size: 22, weight: .semibold))
            Text("将一个网站或服务的目标放在一起，独立管理。" ).font(.system(size: 12)).foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 8) { Text("模块名称").font(.system(size: 12, weight: .medium)); TextField("例如：工作服务", text: $name).textFieldStyle(.roundedBorder).accessibilityLabel("模块名称") }
            VStack(alignment: .leading, spacing: 8) { Text("主机名").font(.system(size: 12, weight: .medium)); TextEditor(text: $hosts).font(.system(size: 12, design: .monospaced)).frame(height: 85).padding(6).background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8)).overlay(RoundedRectangle(cornerRadius: 8).stroke(.quaternary).allowsHitTesting(false)).accessibilityLabel("主机名"); Text("每行一个完整主机名，例如 service.example.com。不支持通配符。") .font(.system(size: 10)).foregroundStyle(.secondary) }
            VStack(alignment: .leading, spacing: 8) { Text("IP 地址或网段（可选）").font(.system(size: 12, weight: .medium)); TextEditor(text: $targets).font(.system(size: 12, design: .monospaced)).frame(height: 70).padding(6).background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8)).overlay(RoundedRectangle(cornerRadius: 8).stroke(.quaternary).allowsHitTesting(false)).accessibilityLabel("IP 地址或网段") }
            Text("主机名会通过设置中的本机代理更新 IP。IP 可能被多个服务共享，请只加入你确认的目标。")
                .font(.system(size: 11)).foregroundStyle(.secondary).lineSpacing(4)
            HStack { Spacer(); Button("取消") { dismiss() }.keyboardShortcut(.cancelAction); Button("保存模块") { var edited = module; edited.name = name.trimmingCharacters(in: .whitespacesAndNewlines); edited.hosts = split(hosts).map { $0.lowercased() }; edited.targets = split(targets); save(edited); dismiss() }.buttonStyle(.borderedProminent).disabled(!valid).keyboardShortcut(.defaultAction) }
        }.padding(28).frame(width: 480).onAppear { name = module.name; hosts = module.hosts.joined(separator: "\n"); targets = module.targets.joined(separator: "\n") }
    }
}

extension View {
    func card() -> some View { self.background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 15)).overlay(RoundedRectangle(cornerRadius: 15).stroke(Color.primary.opacity(0.055)).allowsHitTesting(false)) }
}

#if !NETMOAT_TESTS
@main struct NetMoatApp: App {
    var body: some Scene {
        WindowGroup("NetMoat") { ContentView() }
            .defaultSize(width: 1000, height: 710)
            .windowResizability(.contentMinSize)
            .commands { CommandGroup(replacing: .newItem) {} }
    }
}
#endif
