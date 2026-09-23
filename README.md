# WireGuard for Windows（增强版）

> **本仓库是 [WireGuard for Windows](https://github.com/WireGuard/wireguard-windows) 官方客户端的修改版**，
> 在官方版之上增加了**对端地址变化时的自动检测与隧道自动恢复**能力。

## 为什么需要这个改动

官方客户端在隧道启动时把 `Endpoint` 里的**域名解析成 IP，之后就再也不过问 DNS**。
这个 IP 会被直接写进 WireGuardNT 驱动，此后没有任何代码会再看一眼 DNS。

于是当服务端使用的是 **DDNS 域名 + 动态公网 IP** 时就会出现这样的情况：

1. 服务端的公网 IP 变了，DDNS 把新地址写进了域名解析记录；
2. 客户端手里仍然攥着启动时解析到的旧 IP，只能不停往那个已经没人听的地址发握手；
3. 隧道一直不恢复，**必须有人手动干预**（重新激活隧道 / 重启服务）才能恢复。

这不是配置错误，而是"地址只解析一次"这个设计在动态地址场景下的必然结果。

## 本版本做了什么

给隧道加了一个**随它一起运行的看门狗**，把上面第 2、3 步自动化掉：

- **检测**：按固定间隔检查隧道是否还在通。可以配置一个隧道内的探针地址（如路由器管理页
  `10.122.10.1:80`）用 HTTP 或 TCP 探测；不配探针时改用"上次握手距今多久"来判断。
  连续失败达到阈值才动手，避免单次丢包就改配置。
- **重新解析**：依次向**三个互相独立的解析器**询问对端域名——系统解析器（先刷新本地 DNS 缓存）、
  DNS over HTTPS（`dns.alidns.com`）、`ip-api.com`，并且**优先采纳与当前地址不同的答案**。
  三个解析器各自维护独立的缓存，谁先过期谁先给出新地址。
  只问一个解析器是不够的：缓存里那条旧记录**不会报错**，它是一次成功但过期的查询。
- **恢复**：把解析结果下发给驱动，让会话重新握手。第一轮只做普通的重新下发；如果下一次检查
  仍然不通，就升级为**把 peer 整体重建**（一次驱动调用内先删光再按新配置建好，不留"接口里
  一个 peer 都没有"的窗口）。
- **重试**：15 秒 → 30 秒 → 60 秒，之后每 60 秒一次，不放弃。同时按需推送告警
  （企业微信机器人格式：DOWN / RECOVERY ATTEMPTED / RECOVERED / FAILED）。

设计上的两条边界：

- **不碰 WireGuard 协议，不碰驱动**。所有动作都是通过 WireGuardNT 本来就提供的接口完成的
  （重新下发配置、替换 peer），与其他 WireGuard 实现对端完全互通。
- **参数写在隧道配置文件里**，只对该隧道生效，跟着导出/导入走。
  详见下面的配置说明。

> ⚠️ 因为不是官方构建，客户端**收不到自动更新**（更新器拒绝替换它无法验证签名的可执行文件——
> 这是对的，换成官方版会把本功能一起丢掉）。

## 安装

有两种方式，**按需选**：

### 方式一：MSI 安装包

双击 `wireguard-amd64-1.1.1.msi` 即可（会弹 UAC）。它用的是与官方相同的产品标识，
所以能直接覆盖/升级官方版，装完在「应用」列表里能看到 **WireGuard 1.1.1**，也能正常卸载。

| ✅ 好处 | ⚠️ 代价 |
| --- | --- |
| 双击安装、有卸载项、正规安装流程 | **不含 `wg.exe`**，覆盖安装官方版时官方 MSI 会把它的 `wg.exe` 一并带走 |
| 会创建开始菜单快捷方式 | **卸载时会一并删除隧道配置**（`Data` 目录，官方安装包本来的行为） |

`wg.exe` 是命令行工具，上游的源码目录不在本仓库里，所以没东西可以构建它。核心功能不受影响——
GUI 里的「隧道检测状态」显示的就是 `wg show` 会打印的那些（握手时间、收发流量）。
想要 `wg.exe` 的话用方式二，或者从官方 MSI 里取回来：

```powershell
msiexec /a wireguard-amd64-1.1.1.msi /qn TARGETDIR=$env:TEMP\wg
copy $env:TEMP\wg\WireGuard\wg.exe "$env:ProgramFiles\WireGuard\"
```

**卸载前请先在 GUI 里导出隧道配置**，否则卸载会把配置目录一起清掉。

### 方式二：替换可执行文件（保留 `wg.exe` 和配置）

适合：只想换掉程序本体、不想动安装记录，或者在意 `wg.exe`。

**双击 `install.bat` 即可**，它会自己请求管理员权限，然后完成剩下的步骤。

> **为什么不能双击 `wireguard.exe` 安装？** 因为它不是安装程序，而是程序本体。
> 双击它是**启动客户端**，不会注册服务、也不会复制任何文件到别处。
> 而"安装"在这里的含义是**替换掉已经存在的那个可执行文件**（由官方 MSI 装好的那个），
> 并且替换前必须先停服务 —— 否则旧代码还留在内存里跑着，看起来像换了其实没换
> （Windows 允许覆盖正在运行的 exe，这个坑很隐蔽，所以脚本会核对进程和落盘哈希）。

**前置条件**：机器上已经装过官方 WireGuard（用它自己的 MSI）。这种方式只替换程序本体，
不含驱动与服务的安装逻辑 —— 那部分是官方安装包负责的。

想自己控制的话，也可以用命令行：

```powershell
# 管理员 PowerShell
.\deploy-zhuanban.ps1            # 安装（先备份，让你确认一次）
.\deploy-zhuanban.ps1 -Force     # 不确认，直接装
.\deploy-zhuanban.ps1 -Restore   # 回滚到备份的官方 exe
```

脚本会停服务、备份原文件、替换后**核对落盘哈希**、再把服务按原状态起回来。
手工替换的步骤、以及"为什么必须停服务再复制"见文档。

## 配置

在隧道的 `[Interface]` 段里加（全部可省略，省略即用默认值）：

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `AutoReconnect` | `on` | 是否启用自动重连，`off` 关闭 |
| `ReconnectProbe` | 空 | 隧道内探测地址 `host:port`，HTTP 方式可带 `/path` |
| `ReconnectMethod` | `http` | `http`（收到任何响应都算通）或 `tcp`（连接成功即算通） |
| `ReconnectInterval` | `5` | 探测间隔（秒） |
| `ReconnectTimeout` | `3` | 单次探测超时（秒），会被限制在不超过探测间隔 |
| `ReconnectThreshold` | `3` | 连续失败多少次才动作 |
| `ReconnectWebhook` | 空 | 可选，状态变化时 POST 企业微信格式文本 |

没配 `ReconnectProbe` 时改用握手时间判断，**这要求对端设置了 `PersistentKeepalive`**
（否则空闲隧道和断掉的隧道无法区分；看门狗不会误判，而是在日志里告诉你需要设置它）。

界面上也可以直接改：隧道列表页左下角的「**隧道检测状态**」与「**参数编辑**」两个按钮。

导出隧道时这些参数会写进 `.conf`，导入到另一台装了本版本的机器就直接生效。
（只写与默认值不同的项——与官方对 `ListenPort`、`Table` 的处理一致。）
反向不成立：带这些键的配置交给官方版会被拒绝加载，因为官方版对未知键是报错而不是忽略。

## 开发与构建

```bash
./build-amd64.sh                 # 产出 amd64/wireguard.exe
./build-amd64.sh --deps-only     # 只拉工具链、预热模块缓存
./build-amd64.sh --no-resources  # 快速构建（无托盘图标，需把 wireguard.dll 放到 exe 旁边）
```

需要 Python 3 和网络（下载工具链，全部带 sha256 校验）。构建细节与注意事项见文档。

## 文档

- [`docs/autoreconnect.md`](docs/autoreconnect.md) —— 本功能的完整技术说明：
  问题分析、设计与实现、配置参考、界面、构建、部署与回滚、测试与验证、已知限制。

以下是官方原版 README。

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
