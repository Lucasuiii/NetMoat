# NetMoat

给出站连接筑一道护城河。

NetMoat 是 macOS PF 出站策略框架：**Rust 后台 + 原生 SwiftUI 控制台**。通过明确的物理网卡、IP/CIDR 和可选的精确主机地址更新，管理独立保护模块。不附带任何真实服务的域名或地址清单。

**实验性项目。** 它不是按域名或应用识别的通用防火墙，也不承诺零遗漏或开机最早阶段的保护。请先阅读覆盖限制。

## 0.4 后台变更

- 常驻后台与服务管理全部改为 Rust，运行时无需 Python 或 Xcode。
- 信号、异常和意外退出保留最后已加载规则；明确停止或卸载才撤销。
- 配置修改使用独立管理锁和预期版本；旧快照不能覆盖新配置，回滚也检查版本。
- 验证 DNS 回复与缓存结构；地址缺失时不以不完整集合替换已有规则。
- 保留 10 秒规则核对，计数按需读取；状态变化或每 30 秒写心跳，不强制同步临时状态。
- 界面显示核对时间、过期状态与配置变化；心跳不含目标网站信息。
- 成功升级后删除已安装的旧 Python 后台，控制台仍只有一个应用入口。

这些措施减少已知故障路径，不构成无漏洞或零中断保证。详见[后台设计](docs/BACKEND.md)。

## 构建

需要 macOS、Rust 工具链及系统链接工具。构建界面另需 Xcode 命令行工具、Python 3、macOS 14+；这些是构建依赖，不是后台运行依赖。

```sh
git clone https://github.com/Lucasuiii/NetMoat.git
cd NetMoat
cargo build --release --locked
./target/release/netmoat --version
./target/release/netmoat validate --config examples/policy.json
./target/release/netmoat render --config examples/policy.json
```

`validate`、`render` 无需管理员权限，不联网、不加载规则；`render` 仅显示静态目标，不查询 DNS。

## 保护模块

```json
{
  "interfaces": ["en0"],
  "targets": [],
  "dns": {"hosts": [], "proxy": "http://127.0.0.1:8080", "refresh_seconds": 300},
  "modules": [
    {"id": "work-service", "name": "示例工作服务", "enabled": true,
     "targets": ["192.0.2.0/24", "2001:db8::/32"], "hosts": ["service.example.com"]}
  ]
}
```

以上仅为格式示例。首次实验建议使用 `examples/policy.json` 中的静态文档地址。

- `interfaces`：1–32 个明确的物理 `en` 网卡，不能假设 Wi-Fi 都叫 `en0`。同一网卡更换 Wi-Fi 后仍适用，其他网卡需明确添加。
- `targets`：最多 4096 个数字 IP/CIDR，不接受通配符、作用域 ID、默认路由 `/0`。
- `modules`：最多 64 个独立模块；启用模块目标取并集，共享目标不会因其中一个模块关闭而移除。
- `hosts`：启用主机去重后最多 32 个精确 ASCII 主机名，不支持通配域名。A/AAAA 均成功后才更新该主机缓存。
- `dns`：仅需更新主机地址时提供。只允许明确的回环 HTTP 代理，无凭据、远程代理或直连回退；间隔 60–86400 秒。

旧平面配置与混合基础目标在控制台显示为“现有保护”模块，防止隐藏规则；混合格式需留一个迁移模块槽位。模块全部关闭时目标可为空，不能视为保护任何服务。

## 安装与管理

首次安装立即尝试开启保护，并启用开机启动。只使用已有 `com.apple/*` 父锚点；父锚点不存在时返回失败，不重载系统主规则。

```sh
sudo ./target/release/netmoat service install --config examples/policy.json
sudo /usr/local/bin/netmoat service snapshot
sudo /usr/local/bin/netmoat service status
sudo /usr/local/bin/netmoat service stop
sudo /usr/local/bin/netmoat service start
sudo /usr/local/bin/netmoat service uninstall
```

`stop` 同时关闭开机启动；`start` 同时开启开机启动；`uninstall` 撤销自己的规则、引用和本机服务文件。退出控制台不停止后台。意外终止也不被解释为关闭保护；launchd 会尝试重启。停止失败时规则可能仍保留，应核对状态。

| 用途 | 路径 |
| --- | --- |
| 原生后台、私有配置及缓存 | `/Library/Application Support/NetMoat/` |
| 开机任务 | `/Library/LaunchDaemons/io.github.lucasuiii.netmoat.plist` |
| 命令入口 | `/usr/local/bin/netmoat` |
| 私有规则、状态及引用 | `/private/var/run/netmoat-service/` |
| 无目标信息的只读心跳 | `/private/var/run/netmoat-status.json` |

`rules_verified` 表示配置、近期心跳与当前 PF 读回一致，不是实际网络探测证明。仅有进程或陈旧绿色提示不代表保护有效。`status`、`snapshot` 不查询 DNS 或连接目标。

### 从旧版升级

```sh
cargo build --release --locked
sudo ./target/release/netmoat service upgrade
```

升级保留配置，替换后台、启动任务和命令入口。**0.3 → 0.4 可能有保护空窗**：旧 Python 后台正常退出会清理规则，应暂停受保护应用的敏感活动。Rust 后台之间升级保留旧规则，但仍不保证全程不中断。

升级暂存旧启动配置；新后台核对通过后才删除备份和旧 Python 文件。失败则恢复旧启动配置、尝试重启、保留回退材料并返回失败。原本暂停的服务升级后保持暂停。未完成的升级备份阻止再次盲目升级。

### 原生控制台

```sh
python3 scripts/build_controller.py
# 更新已经安装的同标识控制台
python3 scripts/build_controller.py --replace
```

默认安装到个人 `Applications/NetMoat.app`，支持模块增删改、启停、设置及卸载。修改配置需要管理员认证；活动界面定期读取心跳无需认证。状态过期或配置从其他入口变化时提示重新核对。

### 命令行修改配置

读取 `service snapshot` 的 `configuration_sha256`，编辑 `configuration` 文档，再用刚读取的版本保存：

```sh
sudo /usr/local/bin/netmoat service configure \
  --config policy.json --expected-sha "$CONFIGURATION_SHA256"
```

运行中等待后台确认该版本并现场核对规则；超时只回滚仍属于本操作的配置，并报告恢复是否核对成功。暂停时只保存，开启后核对。版本冲突时重新读取、合并修改，不能用旧快照覆盖。

## 可选临时会话与诱饵验证

Python 仅保留不常驻的临时会话、对照探测和清理工具，不再实现后台，也不安装到后台目录。可直接运行 `python3 netmoat.py`，或安装可选工具：

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
sudo .venv/bin/netmoat-tools guard --config examples/policy.json --seconds 60
sudo .venv/bin/netmoat-tools probe --config examples/policy.json \
  --interface en0 --ipv4 "$DECOY_V4" --ipv6 "$DECOY_V6"
```

诱饵必须是你有权测试、且不在受保护目标集合内的地址；TCP 端口可直连，UDP DNS 端口能回答 `example.com` 查询。验证包括基线成功、临时加入诱饵、连接失败且计数增加、撤销后恢复。基线失败不加载规则，可只请求一种地址族。聚合规则计数不能逐连接归因。

临时会话有独立超时看守，期满撤销；永久 Rust 后台意外退出保留规则，两者生命周期不同。

## 覆盖限制

- 按网卡和目的 IP 工作，不能识别应用、账户或所有域名入口。
- 地址来自经本机代理访问的 Cloudflare DoH，可能与客户端 DNS 答案不同；共享 CDN 地址可能误伤其他直连服务。
- 查询失败保留旧地址，超过三个刷新周期标记过期；旧地址不能保证拦住新地址。缺少有效记录时保留已有 PF 规则并报告降级。
- 不清空系统连接状态，不保证阻断已建立连接。
- 不重载 `/etc/pf.conf`、主规则、路由或 DNS，不全局禁用 PF；父锚点缺失、外部清规则、开机和恢复阶段仍可能有空窗。
- 启用 PF 引用也可能激活系统里已加载但原先未启用的其他规则。
- 不是完整代理断线保护或全网断网开关。应按预期路径对照验证，不能把单次超时当作拦截证明。

## 验证与贡献

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
python3 -m unittest discover -s tests -v
# macOS：不启动界面的状态逻辑测试
python3 scripts/test_controller.py
```

测试使用模拟 PF、临时目录与文档地址，覆盖规则恢复、异常/信号退出、DNS/缓存错误、配置冲突、并发、原子写入、升级成功/失败及卸载。不会操作真实防火墙或连接目标网站，也不替代真实安装、睡眠唤醒及续航测试。

请勿提交个人策略、凭据、真实网段、网络标识或本机原始报告。详见 [SECURITY.md](SECURITY.md)。MIT License。

English: NetMoat is an experimental macOS PF egress policy framework with a Rust launchd service and native SwiftUI controller. It provides retained rules on unexpected exits, versioned configuration transactions, proxy-only exact-host DNS refresh, and independent modules. Optional Python tools handle temporary sessions and decoy verification only. It ships no service-specific policy and does not promise complete domain, application, or uninterrupted isolation.
