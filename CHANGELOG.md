# Changelog

## 2026-09-29

修复：endpoint 解析正确、配置未变，隧道仍单向不通（有发送无接收），
重建 peer 与重启隧道服务均无效，仅整机重启可恢复。

原因：出口防火墙/NAT 为该五元组保留的 UDP 会话映射失效，看门狗每 5 秒
的重试流量使其永不过期。

tunnel/reconnect.go 新增两档恢复：

- force 重建连续失败后（第 4 次尝试起），运行时 ListenPort 换为随机值
  并重绑 socket，以新五元组绕开失效映射。对端 roaming 自适应，存储配置
  不变，手动重连后恢复原端口。
- 换端口仍无效时（第 7 次尝试起），摘除全部 peer 并静默 120 秒，待路径
  上 UDP 状态过期后以新端口重建，效果等同整机重启。
- 进入静默窗时执行一次 w32tm /resync，规避时钟回拨导致握手被对端丢弃。
- 探针失败但握手新鲜时，日志与 webhook 标明故障在隧道之外。

## 2026-09-23

基于 wireguard-windows 1.1.1：

- 中心端动态 IP 变化后的自动重连：HTTP/TCP 探针与握手年龄判定、
  刷 DNS 缓存后三级解析、退避重试、企业微信 webhook 通知。
- 新增配置键 AutoReconnect、ReconnectMethod、ReconnectProbe、
  ReconnectInterval、ReconnectTimeout、ReconnectThreshold、
  ReconnectWebhook；导出仅写非默认值，与官方版配置文件兼容。
- GUI 新增「隧道检测状态」「参数编辑」。
