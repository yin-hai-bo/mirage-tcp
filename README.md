# MirageTCP

`MirageTCP` 是一个使用 `C++11` 编写的微型 `TCP` 库，目标是配合虚拟网卡/抓包库，在本地终结一部分 `TCP` 连接并伪造对端响应。

## 范围

- 不负责拦截 `IP packet`；抓包、注包由外部库负责，例如 `WinTun`。
- 处理完整 `IPv4/TCP packet`，输入接口使用 `const void* + size_t`。
- 通过回调把 `MirageTCP` 伪造出的下行 `IPv4 packet` 通知给调用方。
- 基于 `ConnectionInfo` 维护多个被接管的 `TCP flow`。

## v1 已支持

- 本机 outbound `SYN` 被接管后，库内生成 downstream `SYN+ACK`。
- 本机第三次握手 `ACK` 到达后，触发 `on_tcp_handshake_completed`。
- 已建立连接上的顺序 payload 接收与立即 `ACK`。
- 调用方可通过 `send_downstream_tcp_payload(...)` 主动向本机程序注入下行 `TCP payload`。
- 调用方可通过 `close_flow(...)` 主动向本机程序发起下行 `FIN+ACK` 关闭。
- 本机 `FIN` 主动关闭时，库内生成 downstream `FIN+ACK`，并在最终 `ACK` 后触发关闭事件。
- 未知 flow、非法序号、非法握手确认时，库会生成 downstream `RST` 并清理 flow。
- 收到本机程序发来的 `RST` 时，库会清理 flow 并触发 reset 事件。
- `IPv4` 头解析与序列化。
- `TCP` 头解析与序列化，固定 `data offset = 5`，不支持 `options`。
- 出站伪造包会计算 `TCP checksum` 与 `IPv4 header checksum`。

## v1 明确不支持

- 真正的外网转发
- 拥塞控制
- 超时重传
- 乱序重组
- 滑动窗口扩展
- `IPv4 fragment`
- `TCP option`

当前实现面向“本地截获并本地终结”的最小场景，重点是握手接管与连接事件，不是完整协议栈。

## 构建

```powershell
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

## 最小用法

```cpp
#include <mirage_tcp/mirage_tcp.h>

mirage_tcp::MirageTcpCallbacks callbacks;
callbacks.on_downstream_ip_packet_generated = my_packet_callback;
callbacks.on_tcp_handshake_completed = my_handshake_callback;
callbacks.on_tcp_connection_reset = my_reset_callback;

mirage_tcp::MirageTcp mirage_tcp(callbacks);
mirage_tcp.handle_incoming_ip_packet(ip_packet, ip_packet_size);
mirage_tcp::ConnectionInfo connection_info;
mirage_tcp.send_downstream_tcp_payload(connection_info, payload, payload_size);
mirage_tcp.close_flow(connection_info);
```

完整示例见 `examples/basic_client.cpp`。
