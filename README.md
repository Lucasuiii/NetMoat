# GFW

一个轻量的 macOS PF 出站策略与验证框架。

通过 JSON 配置选择物理网卡和目标 IP / CIDR，生成 IPv4、IPv6 拦截规则；用临时会话加载规则，再通过可控的诱饵连接和实际命中计数验证效果。

**实验性项目，当前版本只提供临时会话，不安装开机服务。** 不附带任何真实服务的域名或地址清单。

## 能做什么

- 只在明确指定的 `en` 网卡上拦截指定目的地址。
- 生成可检查的 PF 规则，默认示例使用文档专用地址。
- 基于已经存在的 `com.apple/*` 父锚点加载独立、随机命名的子锚点。
- 同时验证 IPv4 / IPv6 的 TCP 与 UDP DNS 连接。
- 对照加规则前、规则生效时、撤销后的连接结果。
- 读取 PF 命中计数，避免把原本就不通的网络当作拦截成功。
- 使用正常清理及独立超时看守进程，撤销自己的规则和 PF 启用引用。
- 检查状态，并提供失败后的手动清理入口。

不重载 PF 主规则，不修改 `/etc/pf.conf`、DNS、路由或代理配置，也不清空系统连接状态。启用一个会话会启用 PF，因此系统原本加载但尚未启用的其他 PF 规则也可能开始生效。

## 安装

需要 macOS 和 Python 3.9+。运行时仅使用 Python 标准库。

```sh
git clone https://github.com/Lucasuiii/GFW.git
cd GFW
python3 -m venv .venv
.venv/bin/python -m pip install .
```

也可以直接用 `python3 gfw.py` 代替安装后的 `gfw` 命令。

## 先看规则

```sh
.venv/bin/gfw render --config examples/policy.json
```

此命令不需要管理员权限，不连接网络，也不加载规则。

```json
{
  "interfaces": ["en0"],
  "targets": ["192.0.2.0/24", "2001:db8::/32"]
}
```

`interfaces` 是你明确选择的网卡，不能假设每台 Mac 的 Wi-Fi 都叫 `en0`。`targets` 仅接受数字 IP / CIDR；不解析域名，不接受默认路由 `/0`。示例地址用于文档，不能用来证明真实服务的可达性。

## 临时加载

先审查自己的配置，再运行一个 60 秒会话：

```sh
sudo .venv/bin/gfw guard --config examples/policy.json --seconds 60
```

命令会输出锚点和恢复目录。时间到或按 Ctrl-C 时清理，另有一个独立看守进程兜底撤销。`loaded_not_verified` 只表示规则已加载、表内容已读回，不表示已经证明流量被阻止。

查看会话：

```sh
sudo .venv/bin/gfw status
```

如正常清理失败，状态会保留恢复目录。可使用命令输出的目录手动清理：

```sh
sudo .venv/bin/gfw cleanup --state-dir /private/var/run/gfw-REPLACE_WITH_SESSION_ID
```

清理只操作该会话自己的锚点和启用引用，不能用来管理其他软件的规则。手动清理后的目录会保留给仍在运行的原会话处理；进程意外终止时可能留下小型恢复目录供检查。

## 验证实际拦截

选择你有权测试的无关诱饵地址。诱饵必须：

1. 不在配置中的受保护目标内。
2. 在指定网卡上可以直连 TCP 测试端口。
3. 在 UDP 测试端口提供 DNS 服务，能回答 `example.com` 查询。

```sh
# 先把 DECOY_V4、DECOY_V6 设置为合适的测试地址。
sudo .venv/bin/gfw probe \
  --config examples/policy.json \
  --interface en0 \
  --ipv4 "$DECOY_V4" \
  --ipv6 "$DECOY_V6"
```

默认端口是 TCP 443 和 UDP 53，可用 `--tcp-port`、`--dns-port` 修改。可以只给一种地址族；报告会明确列出实际请求验证的地址族。

流程：

```text
诱饵直连成功 → 临时加入同一目标表 → 连接失败且 PF 计数增加
                                    ↓
                              撤销后连接恢复
```

基线失败时不会加载规则。探测不会主动访问配置中的受保护目标。规则计数是观察窗口内的聚合计数，不是逐包归因。

## 边界

- 这是目的 IP 和接口级框架，**不提供域名识别、按应用过滤或全局 kill switch**。
- 只覆盖配置中的网卡和地址；网卡、地址或路由变化需要重新评估配置。
- 不管理代理或隧道。隧道接口不在规则中，并不能独立证明代理实际采用了哪个出口。
- 云托管 IP 可能变化或被多个服务共享；增加地址范围会扩大误伤风险。
- 不主动终止既有 PF 状态，已有长连接不属于这套新连接验证的保证范围。
- 其他 PF 规则、系统服务、系统升级和网络扩展可能改变实际行为；应在目标环境运行诱饵验证。
- 超时清理不是跨重启保证。强制断电、重启、内核问题或清理失败都需要状态检查。
- 不上传配置或测试报告，不读取凭据，没有账户、遥测或后台更新服务。

## 开发

```sh
python3 -m unittest discover -s tests -v
```

单元测试覆盖配置注入、目标表核验、受保护地址探测拒绝、缺失父锚点、清理失败和 PF 引用恢复。CI 不执行特权网络操作；真实网络验证需要在一台 Mac 上显式运行 `probe`。

English: GFW is a small, session-scoped macOS PF policy and verification framework. It accepts explicit interfaces and literal IP/CIDR targets, renders rules, runs temporary sessions, and checks blocking with user-selected decoys. It ships no service-specific rules and no startup daemon. See the configuration and commands above; all CLI help is available through `--help`.

## 许可证

[MIT](LICENSE)。
