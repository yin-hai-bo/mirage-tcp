# Header And Source Include Graph

- 每张图只覆盖一个关注点
- 仍然使用 `graph BT`
- 被引用文件在上面，引用者在下面，箭头向上

## 1. Public Header 分层

只看 `include/mirage_tcp/` 下公开头之间的依赖关系。

```mermaid
graph BT
    defines["defines.h"]
    connection_info["connection_info.h"]
    mirage_tcp_h["mirage_tcp.h"]
    mirage_tcp_hpp["mirage_tcp.hpp"]

    mirage_tcp_h --> defines
    mirage_tcp_h --> connection_info
    mirage_tcp_hpp --> mirage_tcp_h
    mirage_tcp_hpp --> connection_info
```

## 2. Core Source 依赖

只看 `src/*.cpp` 到 `src/*.h` / public 头的依赖，排除测试。
图中节点只显示文件名，不重复写 `src/` 前缀。

```mermaid
graph BT
    checksum["checksum.h"]
    connection_info_hpp["connection_info.hpp"]
    ip6_head["ip6_head.h"]
    ipv4_packet["ipv4_packet.h"]
    mirage_tcp["mirage_tcp.h"]
    mirage_tcp_hpp["mirage_tcp.hpp"]
    tcp_head["tcp_head.h"]
    tcp_segment["tcp_segment.h"]
    packet_buffer_pool_h["packet_buffer_pool.h"]

    checksum_cpp["checksum.cpp"]
    connection_info_cpp["connection_info.cpp"]
    ipv4_packet_cpp["ipv4_packet.cpp"]
    mirage_tcp_cpp["mirage_tcp.cpp"]
    packet_buffer_pool_cpp["packet_buffer_pool.cpp"]
    tcp_segment_cpp["tcp_segment.cpp"]

    checksum_cpp --> checksum
    connection_info_cpp --> connection_info_hpp
    ipv4_packet_cpp --> ipv4_packet
    packet_buffer_pool_cpp --> packet_buffer_pool_h
    tcp_segment_cpp --> tcp_segment
    tcp_segment_cpp --> tcp_head

    mirage_tcp_cpp --> checksum
    mirage_tcp_cpp --> connection_info_hpp
    mirage_tcp_cpp --> ip6_head
    mirage_tcp_cpp --> mirage_tcp_hpp
    mirage_tcp_cpp --> ipv4_packet
    mirage_tcp_cpp --> tcp_head
    mirage_tcp_cpp --> tcp_segment
    mirage_tcp_cpp --> packet_buffer_pool_h
```

## 3. Test 依赖

只看测试入口依赖哪些 public 头、内部头和测试辅助头。

```mermaid
graph BT
    connection_info_h["connection_info.h"]
    connection_info_hpp["connection_info.hpp"]
    checksum["checksum.h"]
    ipv4_packet["ipv4_packet.h"]
    mirage_tcp_hpp["mirage_tcp.hpp"]
    error_code["error_code.h"]
    tcp_segment["tcp_segment.h"]
    test_harness["test_harness.h"]

    test_checksum_cpp["test_checksum.cpp"]
    test_main_cpp["test_main.cpp"]

    test_checksum_cpp --> checksum
    test_checksum_cpp --> test_harness

    test_main_cpp --> connection_info_h
    test_main_cpp --> connection_info_hpp
    test_main_cpp --> error_code
    test_main_cpp --> ipv4_packet
    test_main_cpp --> mirage_tcp_hpp
    test_main_cpp --> tcp_segment
    test_main_cpp --> test_harness
```

## 4. 最小主路径

如果只想快速理解主实现链路，看这一张就够了。

```mermaid
graph BT
    defines["defines.h"]
    connection_info["connection_info.h"]
    connection_info_hpp["connection_info.hpp"]
    error_code["error_code.h"]
    ip4_head["ip4_head.h"]
    ipv4_packet["ipv4_packet.h"]
    tcp_segment["tcp_segment.h"]
    mirage_tcp["mirage_tcp.h"]
    mirage_tcp_hpp["mirage_tcp.hpp"]
    mirage_tcp_cpp["mirage_tcp.cpp"]

    mirage_tcp --> defines
    mirage_tcp --> connection_info
    mirage_tcp_hpp --> mirage_tcp
    mirage_tcp_hpp --> connection_info
    connection_info_hpp --> mirage_tcp
    ipv4_packet --> error_code
    ipv4_packet --> defines
    ipv4_packet --> ip4_head
    tcp_segment --> defines
    tcp_segment --> error_code

    mirage_tcp_cpp --> mirage_tcp_hpp
    mirage_tcp_cpp --> connection_info_hpp
    mirage_tcp_cpp --> ipv4_packet
    mirage_tcp_cpp --> tcp_segment
```
