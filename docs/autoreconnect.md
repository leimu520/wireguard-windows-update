# 端点地址变化后自动重连

## 上游为什么做不到

配置文件里 `Endpoint` 写的是主机名时，WireGuard 只在**隧道启动那一刻**解析一次
（`conf.Config.ResolveEndpoints()`，见 `conf/dnsresolver_windows.go`），把结果**就地覆盖**
掉主机名，然后这个 IP 就被写进驱动，一直用到隧道停止。

中心端是动态公网地址时，变化的是 DNS 里的 A 记录，不是我们的配置，所以本机侧没有任何东西会
察觉：会话继续往旧地址打握手，隧道一直不通，直到有人手动重启隧道。这就是路由器上要靠
`checkwgv4.sh` 轮询解决的那个问题，现在把它做进 Windows 客户端本身。

功能是**客户端自身的能力，每个配置文件独立开关**：一切参数存在该隧道的 `.conf` 里，只对
它自己生效。

## 设计原则

实现的样子基本是被这四条约束推出来的，先说清楚它们，后面的细节才好读：

1. **只做客户端自己的事。** 不新增协议字段、不要求服务端配合、不碰 WireGuardNT 驱动。
   所有动作都走驱动本来就提供的能力（重新下发配置、替换 peer），所以对端跑原版 WireGuard 照样工作。
2. **参数属于隧道，不属于程序。** 隧道服务是**每条隧道一个进程**，它只读自己那一份配置文件。
   做成全局开关就得额外发明一套存储和同步机制，所以七个参数全部写在 `[Interface]` 段里，
   跟着隧道导出/导入走。
3. **只在有证据时动手。** 判定要求连续 N 次失败；恢复动作发出后，还要等下一次检查确认"隧道确实
   回来了"才算数。误判的代价是非对称的：把一条健在的隧道反复重建，比晚恢复一分钟糟糕得多。
4. **不放弃，但不假装知道。** 恢复动作永不停止（退避到 60 秒一次），可是**做不到的事情不做表态**：
   既没配探针、又没设 `PersistentKeepalive` 时，看门狗不去猜，而是在日志里说明缺什么。

### 数据流

```text
隧道服务进程（wireguard.exe /tunnelservice HOME.conf.dpapi）
  │
  ├─ 启动
  │    读配置 → 快照端点主机名（reconnectHosts）
  │            → ResolveEndpoints 就地把域名覆盖成 IP → 下发驱动
  │    （快照必须发生在覆盖之前：域名一旦被 IP 顶掉就再也找不回来了）
  │
  ├─ 看门狗 goroutine（每 ReconnectInterval）
  │    探测 ── 配了探针就 reconnect.Probe(探针)
  │         └ 没配就用驱动里 peer 的 LastHandshake 陈旧度
  │    连续 N 次不健康 → 判定断开
  │    恢复 ── resolveEndpointHost（三级解析，优先采纳与当前不同的地址）
  │         → config.Peers[i].Endpoint.Host = 新地址
  │         → adapter.SetConfiguration(config.ToDriverConfiguration())
  │         → 下一次检查确认是否真的恢复
  │
  └─ interfaceWatcher goroutine（网络变化时同样重下发配置）
       └─ 与看门狗共用同一个 conf.Config，靠同一把 configMutationLock 串行化

GUI 进程
  └─ 状态框：自己发探测 + 经 IPC 读驱动状态（RuntimeConfig），按同一套规则给结论
```

有一点是刻意如此、也值得使用者知道：**看门狗和界面之间没有状态通道**。状态框显示的是它自己
现场测出来的结果，不是服务端看门狗的内部计数。要打通就得让服务落状态文件再加一条 IPC，
那是另一件事；现在这样至少不会出现"界面显示的和实际发生的不一致"。

## 做了什么

| 层 | 位置 | 作用 |
| --- | --- | --- |
| 探测 | `reconnect/probe.go`（新包） | HTTP/TCP 探测、延迟测量、默认值、握手阈值。隧道服务与 UI 共用同一份，两边测的东西和判定规则不会跑偏 |
| 配置 | `conf/parser.go`、`conf/writer.go` | 认 7 个新键并原样回写，保证在 GUI 编辑器里改完保存不丢键 |
| 解析 | `conf/dnsresolver_windows.go` | 导出 `ResolveHostnameOnce`（单次、不重试）与 `FlushResolverCache`（`dnsapi.dll!DnsFlushResolverCache`） |
| 看门狗 | `tunnel/reconnect.go` | 健康判定、多级重解析、端点重下发、退避、告警 |
| 接入 | `tunnel/service.go` | 隧道 Up 之后启动看门狗，服务停止时优雅退出；解析前先快照原始主机名 |
| 并发 | `tunnel/interfacewatcher.go` | 网络变化回调也会重下发同一份 `conf.Config`，与看门狗共用一把锁 |
| 界面 | `ui/tunnelspage.go`、`ui/reconnectdialog.go` | 隧道页左下角两个按钮 + 状态框 + 参数框 |
| 高亮 | `ui/syntax/highlighter.go` | 登记 7 个新键，否则编辑器会把它们标红 |

## 界面

隧道列表页底部左侧（「编辑」按钮那一条的最左边）多两个按钮，选中某条隧道后可用：

**Reconnect status** —— 只读状态框，每 5 秒自动刷新一次，另有「Probe now」立即探一次：

| 行 | 含义 |
| --- | --- |
| Tunnel / Automatic reconnect / Probe method / Probe target / Probe interval / Probe timeout / Failures tolerated | 该隧道当前的探测配置（来自存储的配置，不是运行中的服务） |
| Current endpoint | 驱动里此刻实际在用的对端地址 |
| Last handshake | 上次完成握手距今多久（同样来自驱动） |
| Traffic | 收发字节 |
| Probe result | 本次探测结果，HTTP 时含状态码 |
| Latency | 本次探测往返毫秒数 |
| Failures in a row | **本框打开期间**连续失败次数 |
| Assessment | 按与看门狗相同的规则推算出的结论 |

两点必须说清：

- 判定结果是在 **UI 进程里实测**出来的。隧道服务和 UI 之间没有状态通道，UI 拿到的是驱动里的
  实时状态（经管理服务 IPC）+ 自己发出的探测。好处是数字是现场测的；代价是
  「Failures in a row」是**这个框自己的计数**，不是服务端看门狗的内部计数。
- 状态框只读，不改任何东西。真正动手重连的是隧道服务里的看门狗。

**Reconnect parameters** —— 该隧道的功能总开关与全部探测参数：启用/停用、探测方式、探测地址、
探测间隔、探测超时、连续失败阈值、告警 Webhook。数值留空表示用默认值（体现在输入框的灰色提示
里）。保存前会校验，探测地址的校验直接调用配置解析器的那一份规则（`conf.ValidateProbeTarget`），
不另抄一套。

**改完会重启该隧道** —— 隧道服务是启动时读一次配置，所以任何参数变更都必须重启隧道才生效。
这一步走的是与「编辑」按钮完全相同的保存流程。

原始配置文件里手写这些键也可以，编辑器接受它们并且不会丢。

状态框底部有一行说明加一个**最近检查时间戳**。说明写的是这个框的作用
（`显示隧道检测的结果。实际的检测与重连由隧道服务执行。`），**不写具体间隔**——5 秒只是默认值，
写进说明会让人以为它固定不变。时间戳则让"它在自己刷新"变成可以核对的事实，而不是要你相信的承诺。

### 标题与版本信息

窗口标题、托盘悬停提示、文件属性里的产品名统一是 **`WireGuard 专版`**（`ui/managewindow.go` 的
`ProductName`，一处定义）。它是写死的而不是走翻译表的：名字不是句子，切语言时不该跟着变。

**上游那个「未签名」提示已经去掉。** 官方构建会检查 exe 的代码签名证书，没有官方证书就判定为
非官方构建，于是把窗口标题改成 `WireGuard (unsigned build, no updates)`
（`ui/ui.go`，由 `manager/updatestate.go` 的 `IsRunningOfficialVersion()` 触发）。本专版必然未签名，
所以这个后缀必然出现；而它给出的信息（"你不会收到自动更新"）对使用者没有任何可操作的意义——
更新器本来就拒绝替换无法验证的 exe，这恰恰是应该的：换成原版会把自动重连功能一起丢掉。
现在那个分支只留注释，不再改标题。文件属性（`resources.rc`）里的 `ProductName` 也一并改成了
`WireGuard 专版`，简体中文块的描述是 `WireGuard 专版：端点自动重连`。

界面文案已随项目一起中文化（`locales/zh-CN`），新增的词条都有中文；非中文界面回落到英文原文。

## 本地化

新增字符串走的是上游那套 `gotext` 流程，但**只往 `locales/zh-CN` 里加**：

```bash
# 1. 提取新字符串（会顺带往所有语言包塞未翻译条目，见下面的注意事项）
go run -tags generate gotext.go
# 2. 在 locales/zh-CN/messages.gotext.json 里补 translation
# 3. 再次运行上面的命令，把翻译编进 zgotext.go
```

注意事项：

- 第 1 步会给**全部 40 个语言包**各加数百行未翻译条目（实测约 26000 行，还夹着一批 Go 标准库
  字符串如 `http2: Framer …`）。为保持改动可读，本仓库只保留 `zh-CN` 的变更，其余语言包已回退。
  将来若要重新生成，这部分噪声会再次出现。
- 词条在网表里是按**源码里的格式串**索引的（`"%s must be between 1 and 65535"`），不是
  `locales` 里 `{What}` 那种占位形式。`zgotext_autoreconnect_test.go` 会验证这一点。
- 字典注册的标签来自目录名 `zh-CN`，因此只有 UI 语言精确等于 `zh-CN` 才会命中；
  `zh-Hans`、`zh-Hans-CN` 都会回落到英文（`l18n.Sprintf` 的真实路径在本机是命中的，
  因为首选 UI 语言就是 `zh-CN`）。

## 与路由器脚本的对应关系

| `checkwgv4.sh` 里的东西 | Windows 版里的位置 |
| --- | --- |
| `CHECK_TARGET` + 3 次 `curl -LI`（200/403 判通） | `reconnect.Probe`（http / tcp 两种方式，可配） |
| `resolve_ip()`（getent） | `conf.ResolveHostnameOnce`（先 `DnsFlushResolverCache`） |
| `HTTP_API` / `HTTP_API_ALI` 两级回退 | `resolveViaIPAPI` / `resolveViaDoH`（`dns.alidns.com`） |
| `cli set … endpoint ${NEW_IP}:${PORT}` | `SetConfiguration`（light 档） |
| force 档：delete peer → 重新 set | `INTERFACE_REPLACE_PEERS`（force 档，一次调用完成） |
| `FAIL_COUNT` / `LAST_RECOVERY` 状态文件 | 进程内计数 + 日志（`Auto-reconnect: …`） |
| `send_wechat()` 企业微信告警 | `ReconnectWebhook`（改成配置项，不再写死在脚本里） |
| cron 周期 | `ReconnectInterval`（默认 5s，进程内定时器） |

有意与脚本不同的三处，都是刻意的：

1. **HTTP 探测接受任何状态码**。脚本只认 200/403，会把躲在 404 后面的健康隧道判成故障；
   隧道内能收到对方任何响应，就已经证明包过去了。
2. **探测地址、间隔、超时、失败阈值、告警地址全部可配**，不再写死在脚本里。
3. **没有单独的状态文件**。服务端看门狗的内部计数写在日志里，UI 状态框走实时实测
   （见下面「界面」）。

## 配置键（写在 `[Interface]` 段）

```ini
[Interface]
PrivateKey = ...
Address = 10.122.20.2/24

AutoReconnect      = on                  # 总开关，默认 on；只有要关掉时才需要写
ReconnectMethod    = http                # http（默认）| tcp
ReconnectProbe     = 10.122.10.1:80      # 探测地址；http 方式可带路径，如 .../healthz
ReconnectInterval  = 5                   # 探测间隔（秒），默认 5
ReconnectTimeout   = 3                   # 单次探测超时（秒），默认 3，且被夹到不超过间隔
ReconnectThreshold = 3                   # 连续失败多少次才动作，默认 3
ReconnectWebhook   = https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx   # 可选

[Peer]
PublicKey = ...
Endpoint = wishing9ie.com.cn:51829
PersistentKeepalive = 25
AllowedIPs = 10.122.10.0/24, 192.168.11.0/24
```

- `AutoReconnect` 接受 `on/off`（也认 `true/false`、`yes/no`、`1/0`）。键不存在 = 开启。
- 数值键留空/不写 = 用默认值。范围 1..65535。
- 只有 `Endpoint` 是**主机名**的 peer 会被监视；写字面 IP 的 peer 跳过。

## 判定与恢复

按 `ReconnectInterval` 周期检查；**连续 `ReconnectThreshold` 次**不健康才动手，
避免单次丢包就改端点。

健康判据二选一：

1. **配了 `ReconnectProbe`** —— 按 `ReconnectMethod` 探测：
   - `http`（默认，跟路由器脚本同一路子）：GET `http://<地址><路径>`，不跟随跳转，
     任何 HTTP 状态码都算"通"，只有收不到响应才算失败。
     **这里与脚本有意不同**：脚本只认 200/403，那会把一个躲在 404 后面的健康隧道判成故障。
     隧道内能收到对方任何响应，就已经证明包过去了。
   - `tcp`：完成一次 TCP 连接即算通。
2. **没配探针** —— 用驱动里 peer 的 `LastHandshake` 陈旧度，阈值
   `max(180s, 3 × PersistentKeepalive)`（`reconnect.HandshakeThreshold`）。180 秒来自 WireGuard
   的 REJECT_AFTER_TIME。**这条判据要求 peer 上有 `PersistentKeepalive`**，否则空闲隧道和断掉
   的隧道无法区分；看门狗不会误判，而是在日志里明确告诉你需要设置它。

### 为什么探测方式只有 http 和 tcp

它们回答的是同一个问题——“隧道内那个地址现在还答不答”——只是问法不同：

| 方式 | 适合 | 例子 |
| --- | --- | --- |
| `http`（默认） | 目标上有 Web 服务；默认打 80 端口，可以带路径 | 路由器管理页 `10.122.10.1:80` |
| `tcp` | 目标只开放某个 TCP 端口 | SSH `:22`、DNS `:53`、RDP `:3389`、数据库端口 |

加上第三种判据（握手时效，不需要任何目标，代价是需要 `PersistentKeepalive`），
日常能遇到的隧道内目标基本都覆盖了。

**什么情况下不够**：目标主机既不跑 HTTP，也不开放任何愿意拿来探测的 TCP 端口——那时只剩 ping，
而 ping 需要 ICMP raw socket（得额外用 `IcmpSendEcho` 实现一套）。实际上不需要：只要隧道里
*存在* 一个会应答的地址（网关、路由器、任何一台机器上的任何服务）就够了，探针要证明的是
"包还能过去"，不是"某台特定主机活着"。本机 HOME 隧道用 `10.122.10.1:80`，属 `http` 那条。

恢复动作（按顺序，与路由器脚本的 light → force 一致）：

1. 依次询问三个解析器：系统解析器（先刷 DNS 客户端缓存）→ DoH `dns.alidns.com` → `ip-api.com`。
   **三个都会被问到**，并且**优先采纳与当前地址不同的答案**；只有当三者都给出同一个地址时才用它。
   这样做的原因是"缓存里的旧记录不是错误，而是一次成功但过期的查询"——如果第一级没报错就停下，
   正好停在了需要被绕开的那个缓存上。三个解析器各自维护独立的缓存，谁先过期谁就能拿到新地址。
   仅在某级查询**报错**时才轮到下一级、以及"三级一致"时的兜底，见第 3 条。
2. 把解析结果写回配置并下发给驱动（**light 档**）。
3. 结果与驱动里的旧地址不同就记录 `moved from X to Y`；三级都给同一个地址则记录
   `no resolver has a different address … the DNS record has probably not been updated yet`，
   然后**仍然重下发那个地址**——用来修复"地址没变、是会话坏了"的情况。
4. 下一次检查如果仍然不通，升级到 **force 档**：同一次调用里带上
   `WIREGUARD_INTERFACE_REPLACE_PEERS`，让驱动**先删掉所有 peer 再按新配置重建**，
   会话与握手状态一并作废。用一次调用完成"删除+重建"，就不会出现"接口里一个 peer 都没有"的窗口。
5. 还没修好就退避重试：15 秒 → 30 秒 → 60 秒，之后每 60 秒一次，永不放弃；期间保持 force 档。
   **退避依据的是"隧道有没有回来"，不是"写操作有没有报错"**：重下发成功只说明写进去了，
   真正的判据是下一次检查。所以退避在"上一次尝试之后仍然不健康"时才增长。
   上限刻意压到 60 秒——等的东西是一条还没被放开的 DNS 记录，记录通常几分钟内就更新，
   每分钟试一次意味着新地址出现后一分钟内就被抓到，而不是最多等五分钟。
   隧道断着的时候重试密集没有代价：写入是幂等的，重下发的就是配置里已有的地址。
6. 配了 `ReconnectWebhook` 就往企业微信机器人地址推一条文本。**DOWN 只在状态变化时发一次**
   （`streak` 每轮尝试后都会重置，所以"连续失败达阈值"这条分支在一次断线里会被反复走到，
   不去重就会既重复告警、又把上报的 Duration 一直重置）；`RECOVERY ATTEMPTED` / `RECOVERED` /
   `FAILED` 按进度发，格式与路由器脚本一致。

实测证据（2026-09-23，把探针临时指向隧道内的死地址来触发，隧道本身保持健康）：
三个解析器按上面的顺序各被调用一次，日志依次为
`the system resolver still returns the address the tunnel is already using, so asking the next resolver`
→ 同一句的 `DNS over HTTPS` 版本 → 同一句的 `ip-api.com` 版本。调用之间的时间差
（系统解析器 → DoH 135 ms → ip-api 768 ms）本身就说明后两级确实发出了网络请求。

### 三档"重建"的边界（问过的那个问题）

| 档 | 做什么 | 会话 | 接口（LUID/路由） | 服务 |
| --- | --- | --- | --- | --- |
| light（第 1 次） | 刷 DNS、重解析、重下发 `SetConfiguration` | 重建（重新握手） | 不动 | 不动 |
| force（第 2 次起） | 同上 + `INTERFACE_REPLACE_PEERS`，peer 整体重建 | 彻底重建 | **不动**（LUID 不变，路由不闪断） | 不动 |
| 重启隧道服务 | 停 `WireGuardTunnel$X` 再启 | 重建 | 会重建（地址/路由重新下发） | 重建 |

前两档都由隧道服务自己做主。第三档**隧道服务做不到**——它就是那个服务，没法重启自己；
只有管理器/UI 能通过 `Tunnel.Stop()` / `Tunnel.Start()`（IPC）做到，「参数编辑」保存时走的就是这条路。
force 档在语义上已经等价于脚本的 force 分支（删 peer 再设），而"接口会不会在 down/up 后丢掉
Win32 地址与路由"这一点没有实测过，所以没有把第三档做成自动升级。

依据来自本地 WireGuardNT 头文件（`wireguard-nt-1.1`）：

```
WIREGUARD_INTERFACE_REPLACE_PEERS = 1 << 3   /**< Remove all peers before adding new ones */
WIREGUARD_PEER_REMOVE             = 1 << 6   /**< Remove specified peer */
WIREGUARD_ADAPTER_STATE_DOWN / UP            /**< Sets the specified adapter up or down */
```

日志前缀统一是 `Auto-reconnect: `，用 `wireguard.exe /dumplog /tail` 或 GUI 的日志页看。

## 构建

```bash
./build-amd64.sh                  # 出 amd64/wireguard.exe（带资源段，可直接替换安装目录里的 exe）
./build-amd64.sh --no-resources   # 快速构建，无 manifest / 无托盘图标，需把 wireguard.dll 放旁边
./build-amd64.sh --deps-only      # 只拉工具链
```

工具链落在 `.deps/`（已 gitignore），第一次跑要下约 300 MB：Go 1.27.1、llvm-mingw（windres）、
ImageMagick（SVG→ICO）、WireGuardNT（要嵌入的 dll/sys）。全部带 sha256 校验。

两点与上游 `build.bat` 不同，都是刻意的：

- **不加 `-overlay`**。本仓库里那份 overlay 把 `crypto/internal/fips140deps/cpu/cpu.go` 换成了
  只导出 `HasSHA512AVX2`/`HasSHA512ARM64` 的垫片，而 `crypto/internal/fips140/{aes,bigmod,sha256,sha3}`
  需要全套 `cpu.X86Has*` 再导出，对固定的 Go 1.27.1 必然编译失败（`undefined: cpu.X86HasADX`）。
- **不走 `build.bat`**。它在本机环境下 GNU tar 顶掉了 System32 的 bsdtar，zip 解不开。

资源段不能省：manifest 决定 GUI 用的是版本 6 的通用控件（否则界面退化成 Win95 观感），而
`ui/iconprovider.go` 的托盘图标是从**资源 id 7** 读的，没有资源就没有托盘图标。带资源构建的 exe
还把 `wireguard.dll` 嵌进了 RCDATA，所以不需要往安装目录丢 DLL。

## 部署与回滚

有两种方式，按需要选一种。

### 方式一：MSI 安装包

`installer/` 里有完整的 WiX 定义，`./installer/build-msi.sh` 产出
`installer/dist/wireguard-amd64-<版本>.msi`（CI 也会一并构建并发布）。它沿用官方的 UpgradeCode，
所以能**正常覆盖/升级官方版本**，装完出现在「应用」列表里，可以正常卸载。

实测（2026-09-23，在本机做了两轮覆盖安装：官方版 → 本版本，以及**重建出来的同版本 MSI 再装一次**，
两次都读了 `msiexec` 的完整日志）：

- **隧道配置完好**。`Data` 目录（含 `HOME.conf.dpapi`）两次都没被动、字节数不变；
  适配器也没被删，仍在 `Up`；开始菜单快捷方式已创建。
- **安装过程会重启三个进程，隧道断几秒**。`customactions.c` 的 `KillWireGuardProcesses`
  在安装事务里必然被设置（`WireGuardExecutable` 组件"将被安装"那一支），实测管理器 / 隧道服务 /
  托盘进程的创建时间都变成了安装那一刻；看门狗日志里 `stopping watchdog` 到 `watching …`
  相隔约 **2 秒**，隧道由服务控制器的故障恢复自己拉回来。**升级前知道这一点是必要的。**
- **每次重建出来的 MSI 都算"新产品"**。`<Product Id="*">` 意味着 ProductCode 每次自动生成，
  所以装一个新构建就是一次完整的升级事务（旧产品注销、新产品注册）。实测「应用」列表里
  始终只有 **1 条**，ProductCode 从 `{42A442DA…}` 变成 `{BFA67D05…}`。
- **升级为什么不删配置**（机制，从日志读出，不是猜）：新旧包用的是**同一批组件 GUID**，
  安装事务里新包执行 `RegisterSharedComponentProvider` 认领了 `WireGuardExecutable`，
  旧包卸载时只是 `UnregisterSharedComponentProvider` 交回份额，组件本身不会被移除。
  于是旧产品那一侧的组件动作既不是"将被安装"也不是"将被卸载"，
  `RemoveConfigFolder` / `RemoveAdapters` 虽按计划被调度，但 `CustomActionData` 是空的，
  等于什么都没做 —— 日志里可以直接看到这三种调度参数的差别。
- **不含 `wg.exe`**。上游 Windows 仓库的根目录里没有 `wg/`（命令行工具的源码不在其中），
  所以没有东西可以构建它，也不适合把官方签名过的那个打包进来。用这个 MSI 覆盖官方版时，
  官方 MSI 的卸载流程会把它的 `wg.exe` 一并带走 —— 这是**唯一的功能损失**，
  命令行能看的信息在 GUI 的「隧道检测状态」里都有。想保留 `wg.exe` 就用方式二，
  或从官方 MSI 里取回来：`msiexec /a wireguard-amd64-1.1.1.msi /qn TARGETDIR=%TEMP%\wg`
  然后复制 `%TEMP%\wg\WireGuard\wg.exe`。
- **卸载会删配置**。`RemoveConfigFolder` 会递归删除 `<安装目录>\Data`，并删掉
  `HKLM\Software\WireGuard`（`customactions.c`，官方行为）。**这一条一定会执行**：
  卸载时组件状态是 `INSTALLSTATE_ABSENT`(2) 或 `INSTALLSTATE_REMOVED`(1)，
  两者都落在 `component_action >= INSTALLSTATE_REMOVED` 那一支里。卸载前先在 GUI 里导出隧道。
- **版本号固定为 1.1.1，而包上写着 `AllowDowngrades="no"`**。所以哪天官方出了 1.1.2 并装上了，
  这份 1.1.1 的 MSI 会被拒绝（`A newer version of WireGuard is already installed`）：
  要么把 `version/version.go` 的号往上抬，要么改用方式二（文件替换不受版本号约束）。

### 方式二：替换可执行文件

**已装官方版的机器，直接覆盖这个 exe 就行**，不需要卸载、不需要重装、配置文件与 WireGuardNT
驱动都不动：换掉的只有 `wireguard.exe` 一个文件，它跟驱动之间的接口和官方版完全一样。
这种方式**不会碰 `wg.exe`**。

**最省事的做法是双击 `install.bat`**（它自己请求管理员权限）。有个常见误解值得先澄清：
`wireguard.exe` **不是安装程序**，双击它是"启动客户端"，不会注册服务、不会往别处复制文件。
"安装"在这里指的是**替换掉官方 MSI 已经装好的那个可执行文件**，而替换前必须停服务——
否则旧代码还在内存里跑着，看起来像换了其实没换（Windows 允许覆盖运行中的 exe）。
所以**前置条件是机器上已经装过官方 WireGuard**；本项目的产物不含驱动和服务的安装逻辑。

下面的脚本比手敲命令可靠（它会等进程真正退出、校验落地哈希、按原状态恢复服务）：

```powershell
# 在管理员权限的 PowerShell 里
.\deploy-zhuanban.ps1            # 安装（会先备份，并让你确认一次）
.\deploy-zhuanban.ps1 -Force     # 不确认，直接装
.\deploy-zhuanban.ps1 -Restore   # 回滚到备份的官方 exe
```

它做的事：检查管理员权限 → 检查已安装 → 备份原始 exe 为 `wireguard.exe.orig-<版本>`
（**已有备份就绝不覆盖**，所以 `-Restore` 永远回到同一个文件）→ 停服务并确认进程全部退出 →
替换 → **核对落盘哈希与源一致** → 按原状态起服务 → 打印服务与进程状态。

手工做的话：

```cmd
:: 0. 备份
copy "C:\Program Files\WireGuard\wireguard.exe" "C:\Program Files\WireGuard\wireguard.exe.orig-1.1.1"

:: 1. 停服务（管理器服务和隧道服务跑的是同一个 exe，不停会锁住文件）
net stop "WireGuardTunnel$HOME"
net stop WireGuardManager
taskkill /im wireguard.exe /f

:: 2. 替换
copy /y <仓库>\amd64\wireguard.exe "C:\Program Files\WireGuard\wireguard.exe"

:: 3. 起服务，然后在 GUI 里激活 HOME 隧道
net start WireGuardManager
```

回滚就是把第 2 步换成 `copy /y "...\wireguard.exe.orig-1.1.1" "...\wireguard.exe"`，再走一遍 1 和 3。
建议留一份官方 1.1.1 的 MSI/安装包，MSI 修复也能恢复原文件。

**为什么必须停服务再复制**：Windows 允许覆盖正在运行的 exe，所以复制会"成功"，但那个进程仍然跑着
旧代码，要等下一次服务重启才换成新的。这一步不核对进程启动时间，就会误判"新版本没效果"。
脚本里 `-Force` 之外的所有检查都是为了这个。

**注意**：官方 MSI 的"修复"或版本更新会把这个 exe 覆盖回官方版本，那之后重跑一次部署脚本即可。

### 配置的导入导出与版本间兼容

检测参数放在 `[Interface]` 段里，**跟着隧道配置文件走**，所以「导出隧道」出来的 `.conf`
自带这些参数，「导入」到另一台装了这个专版的机器就直接生效，不用重新配。实测（用真实的 HOME 隧道）：

- **导出带参数**。只写出**与默认值不同**的项：只改了探针，文件里就只有
  `ReconnectProbe = 10.122.10.1:80` 一行；把自动重连关掉才写 `AutoReconnect = off`。
  没写出来的项导入后取默认值，行为与导出前完全一致。
- **往返一致**。导出的文件再导入，七个参数原样回来。
- **兼容原版导出的配置**。官方版导出的 `.conf`（没有这些键）导入本专版：解析成功、
  重连功能**默认开着**、且**再次导出不会多出任何一行**——不会把文件改脏。
  导入后如果这个隧道没有 `PersistentKeepalive`，看门狗会用握手时效判定并在日志里提示；
  想要更快的判定就补一个 `ReconnectProbe`。
- **反向不成立**：把带这些键的配置交给**官方版**，官方版会拒绝加载整份配置
  （`conf/parser.go` 对未知键是报错而不是忽略）。这是可以接受的——专版之间互通即可。

### 回滚时的一个坑（务必先看）

**官方版不是"忽略"这 7 个键，而是直接拒绝整份配置。** `conf/parser.go` 对 `[Interface]` 里不认识的
键返回 `Invalid key for [Interface] section`，`LoadFromPath` 因此失败：官方版既起不了这条隧道，
GUI 也打不开它。而 GUI 保存配置时写的是 **DPAPI 加密**的 `.conf.dpapi`（`conf/store.go`），
所以**不能用记事本改**——删掉那 7 行需要先解密。

因此回滚前先做这一步：

1. 在 GUI 里**导出该隧道**（得到明文 `.conf`）。
2. 用记事本删掉这 7 行：`AutoReconnect` / `ReconnectMethod` / `ReconnectProbe` /
   `ReconnectInterval` / `ReconnectTimeout` / `ReconnectThreshold` / `ReconnectWebhook`，
   存成一份干净副本备用。
3. 之后任何时候回滚：GUI 里删除该隧道（删除只动文件，不依赖解析）→ 导入那份干净 `.conf`。

配置目录同时支持明文 `.conf` 和加密 `.conf.dpapi`（`conf/NameFromPath`），但 GUI 只会写加密的那种，
所以别在同一目录下同时放 `HOME.conf` 和 `HOME.conf.dpapi`——会出现同名的两条隧道。

## 测试与验证

```bash
./.deps/go/bin/go.exe test -count=1 ./conf/ ./reconnect/ .
```

### 自动化测试覆盖了什么

| 包 | 覆盖内容 |
| --- | --- |
| `reconnect` | 探测的 11 项：任何 HTTP 状态码都算通、**每次探测都必须新开一条连接**、带路径、不跟随跳转、TCP 成功与失败、超时被遵守、目标切分、方式解析、握手阈值、默认值回退 |
| `conf` | 解析、`ToWgQuick` 往返、非法值拒绝、`on` 的多种拼写、探针带路径、方式大小写不敏感、**不写新键的配置序列化后不会多出任何一行** |
| `main` | 中文字典查表 17 项，防止改了界面字符串却忘了同步词条 |

`reconnect` 里"每次探测都必须新开一条连接"那条测试是有来历的，它对应的 bug 是实测抓到的：
探针原来用带连接池的 `http.DefaultTransport`，于是隧道断了之后探针还骑着断线之前建立的
keep-alive 连接，把一条已经死掉的隧道报成健康（`Get-NetTCPConnection` 能看到隧道服务进程持有
一条到探针地址的 Established 连接）。

### 怎么在不弄断隧道的前提下测恢复

把探针临时指向隧道里的一个**死地址**（如 `10.122.10.99:9`），同时把阈值设为 1、间隔设为 2 秒。
看门狗会判定"隧道已断"并走完整条恢复链，但因为解析出来的仍然是真实地址，重下发是无害的
——**隧道全程保持连通**。这是验证判定、三级查询顺序、light→force 升级、退避节奏和日志格式最快的办法。

要测"解析结果真的变化"那条分支，只能靠下面验证清单的第 4 条（改 `hosts`），代价是隧道真的会断。

### 已经真机验证过的

- 从资源段加载内嵌 `wireguard.dll`（先验这条，因为它坏了隧道根本起不来）；
- 完整状态机：判定断开 → 三级解析 → light 重下发 → force 重建 → 之后 `wg show` 正常、握手持续刷新；
- 三级解析链全部执行（时间差 135 ms / 768 ms 证明后两级确实发了网络请求）；
- 退避节奏实测：31s → 61s → 61s → 60s → 61s，稳定在 60 秒；
- 反复重连后 `allowed ips` 不累积（`SetConfiguration` 是全量语义，写入幂等）；
- 配置导出带参数、导入回来一致、原版配置导入不产生多余行；
- 窗口标题、托盘提示、文件属性显示为「WireGuard 专版」。

### 还没验证的

只有一条：**`moved from X to Y`**——也就是"解析结果真的换成另一个地址、并且新地址握手成功"。
触发它必须让系统解析器返回一个不同的地址，唯一办法是改 `hosts` 指向假 IP，代价是隧道真的会断
约 20 秒，暂时没有执行。除它之外的每个分支都已在真机上跑过。

## 验证清单

1. **看门狗起来了**：隧道激活后日志里应有一行
   `Auto-reconnect: watching wishing9ie.com.cn, probing 10.122.10.1:80 over http every 5s (timeout 3s, 3 failures in a row before acting)`。
   没配探针时则是 `judging by handshake age every 5s`。
2. **状态框对得上**：打开 Reconnect status，`Current endpoint` 应与 `wg show` 的 endpoint 一致，
   `Latency` 是个合理的小数字，`Assessment` 与日志里看门狗的说法一致。
3. **判据可用**：`wg show` 里 `latest handshake` 是否在持续刷新。不刷新说明 peer 没设
   `PersistentKeepalive`，需要设上或改用探针。
4. **主动验证（不改中心端也能测）**：往
   `C:\Windows\System32\drivers\etc\hosts` 加一行把端点域名指到一个不存在的 IP：

   ```
   203.0.113.9   wishing9ie.com.cn
   ```

   隧道会断。观察日志依次出现 `tunnel looks unhealthy (1/3)` → `tunnel is down` →
   `moved from <真IP> to 203.0.113.9`，随后 light 档重下发、再升级 force 档。
   **这是唯一能实测 `moved from X to Y` 这条分支的办法**：系统解析器读 hosts 优先于 DNS，
   于是"解析结果 ≠ 当前地址"的条件成立，而其余分支（三级查询顺序、重下发、两级升级）都可以用
   下面第 6 条那种"探针指向死地址"的方式触发，且全程不弄断隧道。
   代价是隧道真的要断——**删掉 hosts 那行之后约 20 秒恢复**：下一次探测发现地址变回真值，
   走 `moved from 203.0.113.9 to <真IP>` 并重新握手。所以验完记得把那行删掉，
   然后确认 `latest handshake` 恢复刷新、状态框回到"carrying traffic"。
6. **不用弄断隧道的触发方式**：把探针临时指向隧道内的死地址（如 `10.122.10.99:9`）并把
   `ReconnectThreshold` 设为 1、`ReconnectInterval` 设为 2。看门狗会判定"隧道已断"并走完全部恢复逻辑，
   但因为解析出来仍是真实地址，重下发是无害的，**隧道全程保持连通**。
   这是验证三级查询顺序、light/force 升级、退避、日志格式最快的办法。
   本仓库 2026-09-23 就是这么验证的。
7. **无副作用**：反复触发几次后，`wg show` 的 `allowed ips` 不应重复累积。**已确认**，
   依据是数据流而不是猜测：`WireGuardSetConfiguration` 接收的是**一份完整配置**（没有"追加 peer"
   这种语义），而 `conf.Config.ToDriverConfiguration()` 每次都按 `len(AllowedIPs)` 重新预分配、
   从 `conf.Config` 重新构建 peer 列表，恢复动作只改 `Endpoint.Host`，从不碰 `AllowedIPs`。
   force 档用的 `INTERFACE_REPLACE_PEERS` 更是"先删掉所有 peer 再按传入的重建"，所以这个写入是
   幂等的。实测侧证：`HOME` 的 `allowed ips` 始终是 `10.122.0.0/16, 192.168.11.0/24` 两项，
   经死地址注入触发两轮 force 之后仍未出现重复条目。

## 真实 IP 变更时的验证（装机后待测）

上面第 4 条是**离线**模拟（改 hosts，故意让解析结果跳到一个错地址）。真正的场景是中心端换了公网
IP、DDNS 把新地址写进 DNS，此时要做的是"判断它多久恢复、有没有恢复"。

### 先看日志（正确的读法）

```bash
cd "C:\Program Files\WireGuard"
MSYS_NO_PATHCONV=1 ./wireguard.exe /dumplog > dump.txt   # 不带 /tail：导出全部历史后退出，带时间戳
grep "Auto-reconnect" dump.txt | tail -20
```

- 不带 `/tail` 才是**一次性导出**（2048 行、带毫秒时间戳、跑完自己退出）；`/dumplog /tail` 是
  **持续跟随**，不会退出，要用 `timeout` 包起来。
- **不要直接 grep `Data\log.bin`**：那里面**没有时间戳**（条目形如 `[TUN] [HOME] …`），而且环形
  日志是循环覆盖的，文件物理顺序 ≠ 时间顺序，`sort -u` 会把先后关系彻底丢掉。要看时间线就用
  `dumplog`。
- 从 Git Bash 调这两个参数必须带 `MSYS_NO_PATHCONV=1`，否则 `/dumplog` 会被当成路径转换。

### 预期时间线

已知 `wishing9ie.com.cn` 的权威 SOA `default TTL = 600`（10 分钟），所以**别指望十几秒恢复**。

| 时刻 | 发生什么 | 日志 |
| --- | --- | --- |
| t+15s | 连续 3 次探测失败（5s 一次） | `tunnel looks unhealthy (1/3)` → `(2/3)` → `tunnel is down: probe …` |
| t+15s | 第 1 次恢复，light 档 | DNS 还是旧值时会看到 `still resolves to <旧IP> … re-applying the endpoint to force a new handshake` |
| t+30s | 第 2 次，升 force 档 | `rebuilding the peer from scratch` → `endpoint re-applied and the peer rebuilt …` |
| 之后 | 退避重试：15s → 30s → 60s，之后每 60s 一次，永不放弃 | 每轮一条 `no resolver has a different address …`，随后仍重下发（light / force） |
| DNS 更新后的某一轮 | 拿到新地址 | `moved from <旧IP> to <新IP> (via system resolver / DoH / ip-api)` |
| 紧跟 | 重下发，会话重新握手 | `endpoint re-applied, waiting for a handshake`，之后**静默**（静默 = 健康） |

### 成功判据

```bash
./wg.exe show | grep -E "endpoint|latest handshake"
```

`endpoint` 变成新地址，且 `latest handshake` 是刚刚（探针模式下判定不依赖握手，但握手刷新说明
数据面确实通了）。

### 恢复慢是正常的，而且不是客户端的锅

从 IP 变化到恢复，**几分钟到十几分钟都属正常**：先是路由器上的 DDNS 客户端要把新 IP 推到阿里云，
再等各级 DNS 缓存按 TTL（最长 600s）过期。三级查询（系统解析器 / DoH / `ip-api.com`）问的是
**同一条 DNS 记录**，记录没更新谁都拿不到新地址——路由器上那个脚本受同样的限制。所以看不到
"几分钟内恢复"，先去看 DNS 记录本身更新了没有（手机开热点查一次最准），而不是怀疑客户端。

那三级查询有什么用？它们维护的是**互相独立的三份缓存**（本机解析器、阿里云 DoH、ip-api 自己的
解析器），所以新记录一旦上线，**谁先过期谁先给出新地址**，客户端就在那一轮拿到它，
而不必再等本机那份额外的等待时间。

### 三种日志分别对应什么

- 每轮都是 `no resolver has a different address for <域名> … the DNS record has probably not been
  updated yet` → DNS 记录还没更新，继续等，属预期。
- `every resolution method failed for <域名>` → 三种查询全部失败（通常意味着完全没网），
  后面会跟具体错误原因。
- 出现 `moved from X to Y` 之后仍然 `tunnel is down` → 新地址拿到了但连不上：问题在中心端
  （端口未放通 / 服务没起 / 密钥变更），不是重连逻辑。

### 重试节奏，以及为什么是这个值

退避是 15s → 30s → 60s，之后每 60 秒一次（`tunnel/reconnect.go` 的 `reconnectMinBackoff` /
`reconnectMaxBackoff`）。上限选 60 秒是有意的：**等的东西是一条还没被放开的 DNS 记录**，
所以"多久试一次"直接决定了"记录更新后多久能恢复"。60 秒意味着最多一分钟。

配合判定侧的 5 秒探测、3 次确认（阈值在界面上可改），端到端的最坏情况是
"记录更新后约 75 秒恢复"。路由器上那个脚本按 cron 跑，一轮就是几分钟，
所以这个节奏只会更快，不会更慢。

如果觉得一分钟一次太密（长时间断网时日志会多），把 `reconnectMaxBackoff` 调大即可；
反方向就调小。改的是常量，需要重新构建部署。

### 关于权限：刷新 DNS 不需要管理员

`DnsFlushResolverCache` 刷的是**调用者的** DNS 客户端缓存，是用户级 API，不需要提权——
实测当前用户身份和 `LocalSystem` 身份都返回成功，现场日志里
`unable to flush the DNS resolver cache` 从未出现过（服务以 `LocalSystem` 运行，权限本身也最高）。

而且**这一步失败也不影响恢复**：真正兜底的是后两级查询（DoH 与 `ip-api.com`），
它们是自己发 HTTP 请求去问的，**完全不经过本机解析器**，所以本机缓存是不是旧的都无所谓。
这也是为什么三级都要问、而不是第一级成功就停。

顺带说明：**第三级之后的墙是记录本身的 TTL**（本域是 600 秒）。任何查询方式——系统解析器、
DoH、`ip-api.com`，甚至路由器脚本——问的都是同一条记录，记录没更新谁都拿不到新地址。
三个独立缓存的价值在于"谁先过期谁先给出新值"，而不是绕过 TTL 本身。

## 已知限制

- **界面已中文化，但只做了 `zh-CN`**。其余语言包保持原样（上游那套生成器会给所有语言包塞进
  大量未翻译条目，实测约 26000 行噪声，已剔除）。另外目录名决定了字典标签，只有 UI 语言恰好是
  `zh-CN` 才命中翻译。界面确实显示中文，已用 `zgotext_autoreconnect_test.go` 验证。
- **状态框的判定是即时推算，不是服务端内部状态**。它读驱动状态 + 自己探测，按同一套规则给结论；
  服务端看门狗的内部计数器（连续失败次数、上次恢复时间）没有跨进程通道，看不到。
- **改参数会重启隧道**（服务启动时读一次配置），正在传的数据会断。
- **全隧道配置下 DoH 回退会失效**。若某些 peer 的 AllowedIPs 含 `0.0.0.0/0`，到
  `dns.alidns.com` 的请求会被路由进已经断掉的隧道。系统解析器仍可用，但它可能命中缓存。
  本机是分隧道（`10.122.x` + `192.168.11.0/24`），不受影响。
- **`ip-api.com` 回退走明文 HTTP**，沿用路由器脚本的做法；它只是最后一道兜底。
- 看门狗活在隧道服务进程里。隧道没激活（服务停止）时它不工作——那时也不需要它工作。
- 构建产物**没有代码签名**，官方 MSI 的修复/更新会把这个 exe 覆盖掉（重跑一次部署脚本即可）。
  另外，**Windows 在首次运行未签名程序时的 SmartScreen/UAC 提示是操作系统行为，程序内部去不掉**，
  只能靠购买代码签名证书；界面标题里那个"unsigned build"后缀是另一回事，那个已经去掉了。
