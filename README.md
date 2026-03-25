# MirageTCP

`MirageTCP` 是一个使用 `C++11` 实现的微型 `TCP` 库，目标是配合虚拟网卡或抓包库，在本地终结一部分 `TCP` 连接并伪造对端响应。

## 范围

- 不负责拦截 `IP packet`；抓包、注包由宿主负责，例如 `WinTun`。
- 处理完整 `IPv4/TCP packet`，输入接口使用 `const void* + size_t`。
- 通过回调把 `MirageTCP` 生成的下行 `IPv4 packet` 交回宿主。
- 基于 `mirage_tcp_connection_info_t` 跟踪多个被接管的 `TCP flow`。

## Public API

- `mirage_tcp/connection_info.h`
  纯 C 兼容的连接标识结构与初始化函数。
- `mirage_tcp/error_code.h`
  公共错误码常量，调用方可直接使用 `MTE_*` 判断结果。
- `mirage_tcp/mirage_tcp.h`
  纯 C API，包含 handle、callbacks 和主操作入口。
- `mirage_tcp/mirage_tcp.hpp`
  对纯 C API 的 C++ 包装类 `mirage_tcp::MirageTcp`。

`mirage_tcp_connection_info_t` 同时承载 `IPv4` 和 `IPv6` 地址：
- `client_ip` / `server_ip` 使用 `mirage_tcp_address_t`
- `ip_ver` 使用 `4` 或 `6` 标识地址族

当前实现仍然聚焦 `IPv4/TCP`，但公共连接标识已经按双栈形式预留。

## 错误处理

- 所有对外返回值统一使用 `mirage_tcp_error_code_t`。
- `MTE_Ok` 表示成功。
- 失败时，调用方应按 `MTE_*` 常量处理，而不是依赖字符串。
- `mirage_tcp_create()` 使用 `error code + out handle` 形式返回结果。

## C API 约定

- `mirage_tcp_create()` 要求 `callbacks` 和 `result` 非空。
- `mirage_tcp_destroy(NULL)` 是安全的。
- `mirage_tcp_handle_incoming_ip_packet()`、`mirage_tcp_send_downstream_tcp_payload()`、`mirage_tcp_close_flow()` 要求 `instance` 来自 `mirage_tcp_create()`。
- `mirage_tcp_send_downstream_tcp_payload()` 和 `mirage_tcp_close_flow()` 要求 `connection_info` 非空。
- `mirage_tcp_set_connection_info_v4()` / `mirage_tcp_set_connection_info_v6()` 用于填充 flow 标识。

## C++ API 约定

- `mirage_tcp::MirageTcp` 定义在 `mirage_tcp/mirage_tcp.hpp`。
- C++ 包装层直接复用同一套 callbacks、error code 和 `mirage_tcp_connection_info_t`。

## 已支持

- 本机 outbound `SYN` 被接管后，生成 downstream `SYN+ACK`
- 本机第三次握手 `ACK` 到达后，触发 `on_tcp_handshake_completed`
- 已建立连接上的顺序 payload 接收与立即 `ACK`
- 通过 `mirage_tcp_send_downstream_tcp_payload()` 或 C++ 包装方法主动注入下行 `TCP payload`
- 通过 `mirage_tcp_close_flow()` 或 C++ 包装方法主动发起下行 `FIN+ACK`
- 本机 `FIN` 主动关闭时，生成 downstream `FIN+ACK`，并在最终 `ACK` 后触发关闭事件
- 未知 flow、非法序号、非法握手确认时，生成 downstream `RST` 并清理 flow
- 收到本机程序发来的 `RST` 时，清理 flow 并触发 reset 事件
- `IPv4` 头解析与序列化
- `TCP` 头解析与序列化，固定 `data offset = 5`，不支持 `options`
- 出站伪造包会计算 `TCP checksum` 与 `IPv4 header checksum`

## 明确不支持

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
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

## 最小用法（C）

```c
#include <string.h>
#include <mirage_tcp/mirage_tcp.h>
#include <mirage_tcp/error_code.h>

static void on_packet(void * user_data, const void * ip_packet, size_t ip_packet_size) {
    (void)user_data;
    (void)ip_packet;
    (void)ip_packet_size;
}

int main(void) {
    mirage_tcp_callbacks_t callbacks;
    mirage_tcp_object tcp;
    mirage_tcp_connection_info_t flow;

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.on_downstream_ip_packet_generated = on_packet;

    if (mirage_tcp_create(&callbacks, &tcp) != MTE_Ok) {
        return 1;
    }

    mirage_tcp_set_connection_info_v4(
        &client_ipv4,
        &server_ipv4,
        client_port,
        server_port,
        &flow);

    if (mirage_tcp_send_downstream_tcp_payload(tcp, &flow, payload, payload_size) != MTE_Ok) {
        mirage_tcp_destroy(tcp);
        return 1;
    }

    mirage_tcp_destroy(tcp);
    return 0;
}
```

## 最小用法（C++）

```cpp
#include <mirage_tcp/mirage_tcp.hpp>
#include <mirage_tcp/error_code.h>

mirage_tcp_callbacks_t callbacks = {};
callbacks.on_downstream_ip_packet_generated = my_packet_callback;
callbacks.on_tcp_handshake_completed = my_handshake_callback;
callbacks.on_tcp_connection_reset = my_reset_callback;

mirage_tcp::MirageTcp mirage_tcp(callbacks);
mirage_tcp_error_code_t result = mirage_tcp.handle_incoming_ip_packet(ip_packet, ip_packet_size);

if (result != MTE_Ok) {
    // 按 MTE_* 处理错误。
}
```

完整示例见 [`examples/basic_client.cpp`](C:/dev/MirageTCP/examples/basic_client.cpp)。

## Docker 实测

- Docker 开发镜像定义在 [`docker/Dockerfile`](C:/dev/MirageTCP/docker/Dockerfile)
- 基于 `TUN` 的实测程序位于 [`docker/live_probe/README.md`](C:/dev/MirageTCP/docker/live_probe/README.md)
- 该程序在容器内拦截发往测试地址的系统 `IPv4/TCP` 流量，并把抓到的完整 `IP packet` 直接交给 `MirageTCP` 本地终结

## 设计文档

- 依赖关系图见 [`docs/dependency-graph.md`](C:/dev/MirageTCP/docs/dependency-graph.md)
