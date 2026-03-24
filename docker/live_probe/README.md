# MirageTCP Live Probe

这个子目录放的是 Docker 内实测程序。它不做真实转发，而是用 Linux `TUN` 设备把发往指定测试地址的系统 `IPv4/TCP` 流量截进用户态，然后直接交给 `MirageTcp` 本地终结。

## 目录内容

- `main.cpp`：实测程序本体，创建并配置 `TUN` 设备，读取 `TUN` 出站包，调用 `handle_incoming_ip_packet(...)`，再把 `MirageTcp` 回调生成的下行包写回 `TUN`。

## 行为

- 只处理 `IPv4/TCP`。
- 客户端发起握手后，`MirageTcp` 在本地完成被动握手。
- 收到首个上行 payload 后，程序返回一个固定 `HTTP 200` 文本响应，然后调用 `close_flow(...)` 主动关闭连接。

## 容器内最小用法

先构建：

```bash
cmake -S . -B build
cmake --build build --target mirage_tcp_live_probe
```

启动探针：

```bash
./build/mirage_tcp_live_probe
```

程序启动后会自动执行：

- `ip addr replace ${MIRAGE_TCP_LIVE_PROBE_LOCAL_IP:-10.200.0.1/24} dev ${MIRAGE_TCP_LIVE_PROBE_TUN:-mtcp0}`
- `ip link set ${MIRAGE_TCP_LIVE_PROBE_TUN:-mtcp0} up`
- `ip route replace ${MIRAGE_TCP_LIVE_PROBE_TARGET_IP:-10.200.0.2/32} dev ${MIRAGE_TCP_LIVE_PROBE_TUN:-mtcp0}`

然后直接访问被拦截的测试地址：

```bash
curl --max-time 3 http://10.200.0.2/
```

如果需要自定义：

- `MIRAGE_TCP_LIVE_PROBE_TUN`：默认 `mtcp0`
- `MIRAGE_TCP_LIVE_PROBE_LOCAL_IP`：默认 `10.200.0.1/24`
- `MIRAGE_TCP_LIVE_PROBE_TARGET_IP`：默认 `10.200.0.2/32`
- `MIRAGE_TCP_LIVE_PROBE_BODY`：默认响应正文
