# WireGuard 专版

基于 [WireGuard for Windows](https://github.com/WireGuard/wireguard-windows) 1.1.1 修改，
解决一个问题：服务端使用 DDNS 域名、公网 IP 变化后，官方客户端不会重新解析，
隧道一直连着旧地址，只能手动重连。本版本会自动检测并恢复。

原有功能不变，新增：

- 隧道运行期间自动检测连通性，失败后重新解析对端域名并恢复连接
- 解析依次使用系统 DNS、DoH（dns.alidns.com）、ip-api.com，取与当前不同的结果
- 第一次恢复只重新下发配置，仍不通则整体重建 peer；重试间隔 15/30/60 秒，不放弃
- 可选企业微信 Webhook 告警
- 主界面左下角新增「隧道检测状态」「参数编辑」两个按钮，界面已中文化

此构建没有代码签名，首次运行会有 SmartScreen 提示，也不接收官方自动更新。

详细设计见 [docs/autoreconnect.md](docs/autoreconnect.md)。

## 下载

从 [Releases](https://github.com/leimu520/wireguard-windows-update/releases) 下载
`wireguard-zhuanban-amd64.zip`，由 GitHub Actions 自动构建，
内含 wireguard.exe、wg.exe 和 MSI 安装包。

## 安装

### MSI

解压 zip 后双击 `wireguard-amd64-1.1.1.msi`。不要在压缩包里直接双击，
那样只会弹出 msiexec 的帮助窗口。

- 全新机器可以直接装
- 已装官方版的机器会直接覆盖升级，隧道配置不受影响
- 安装过程会重启 WireGuard，隧道断几秒后自动恢复
- 卸载会删除隧道配置（官方安装包本来的行为），卸载前先在 GUI 里导出
- 版本号沿用上游的 1.1.1。如果官方发布了更高版本并且已经装上，
  这个 MSI 会被拒绝，此时改用下面的 install.bat

### 替换 exe

已经装了官方版、不想产生安装记录的机器：解压后双击 `install.bat`（需要管理员）。
只替换 `wireguard.exe` 一个文件，回滚执行 `deploy-zhuanban.ps1 -Restore`。

## 配置

参数写在隧道配置的 `[Interface]` 段里，也可以在主界面的「参数编辑」里改：

| 键 | 默认 | 说明 |
| --- | --- | --- |
| AutoReconnect | on | 总开关 |
| ReconnectProbe | 空 | 隧道内探测地址，如 `10.122.10.1:80` |
| ReconnectMethod | http | `http`（收到任何响应都算通）或 `tcp` |
| ReconnectInterval | 5 | 探测间隔（秒） |
| ReconnectTimeout | 3 | 单次探测超时（秒） |
| ReconnectThreshold | 3 | 连续失败多少次才动作 |
| ReconnectWebhook | 空 | 可选，状态变化时推送企业微信消息 |

一般只设 `ReconnectProbe` 就够了。不设探针时按握手时间判断，
要求对端配置了 `PersistentKeepalive`。

参数会随隧道配置一起导出/导入。带这些键的配置文件官方版不认
（官方对未知键是报错而不是忽略）。

## 构建

```bash
./build-amd64.sh                  # amd64/wireguard.exe + amd64/wg.exe
./installer/build-msi.sh          # MSI 安装包
```

在 Git Bash 里运行，需要联网下载工具链（Go、llvm-mingw 等，均带 sha256 校验）。
推送到 master 后 GitHub Actions 会自动构建并更新 Release。

## 文档

`docs/autoreconnect.md`：设计说明、配置参考、部署与回滚、测试情况、已知限制。

---

# [WireGuard](https://www.wireguard.com/) for Windows

This is a fully-featured WireGuard client for Windows that uses [WireGuardNT](https://git.zx2c4.com/wireguard-nt/about/). It is the only official and recommended way of using WireGuard on Windows.

*This fork adds automatic endpoint re-resolution and tunnel recovery on top of the official client,
for servers reached by a DDNS hostname on a dynamic public address. If the address changes, the
official client keeps using the IP it resolved at startup and the tunnel stays down until somebody
intervenes. This fork watches the tunnel, re-resolves the name through three independent resolvers,
prefers an answer that differs from the address already in use, pushes it into the driver, and
escalates to rebuilding the peer when a plain re-apply does not help. Nothing about the WireGuard
protocol or the driver changes. See [`docs/autoreconnect.md`](docs/autoreconnect.md) for the full
write-up (in Chinese).*

## Download &amp; Install

If you've come here looking to simply run WireGuard for Windows, [the main download page has links](https://www.wireguard.com/install/). There you will find two things:

- [The WireGuard Installer](https://download.wireguard.com/windows-client/wireguard-installer.exe) &ndash; This selects the most recent version for your architecture, downloads it, checks signatures and hashes, and installs it.
- [Standalone MSIs](https://download.wireguard.com/windows-client/) &ndash; These are for system admins who wish to deploy the MSIs directly. For most end users, the ordinary installer takes care of downloading these automatically.

## Documentation

In addition to this [`README.md`](README.md), the following documents are also available:

- [`adminregistry.md`](docs/adminregistry.md) &ndash; A list of registry keys settable by the system administrator for changing the behavior of the application.
- [`attacksurface.md`](docs/attacksurface.md) &ndash; A discussion of the various components from a security perspective, so that future auditors of this code have a head start in assessing its security design.
- [`buildrun.md`](docs/buildrun.md) &ndash; Instructions on building, localizing, running, and developing for this repository.
- [`enterprise.md`](docs/enterprise.md) &ndash; A summary of various features and tips for making the application usable in enterprise settings.
- [`netquirk.md`](docs/netquirk.md) &ndash; A description of various networking quirks and "kill-switch" semantics.

## License

This repository is MIT-licensed.

```text
Copyright (C) 2018-2026 WireGuard LLC. All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
```
