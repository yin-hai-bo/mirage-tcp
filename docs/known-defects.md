# MirageTCP Known Defects

本文档记录当前代码审查中识别出的明确缺陷，便于后续按优先级修复与补测试。

范围说明：

- 结论基于当前分支代码状态
- 只记录已经能从代码直接推出的问题
- 不把 README 已明确声明“不支持”的能力缺失，误记为缺陷

## 状态概览

| ID | 优先级 | 状态 | 摘要 |
| --- | --- | --- | --- |
| KD-001 | P1 | Resolved | 第三次握手 `ACK` 携带 `payload` 时，数据被静默丢弃 |
| KD-002 | P1 | Resolved | 已建立连接收到 `payload + FIN` 组合段时，`FIN` 被忽略 |
| KD-003 | P1 | Open | `LastAck` 状态未校验对端 `sequence_number` |
| KD-004 | P2 | Open | `IPv4 fragment` 只检查了 fragment offset，未检查 `MF` 标志 |
| KD-005 | P2 | Open | Debug 下对入站包地址对齐做 `assert`，可能中止合法调用 |
| KD-006 | P3 | Resolved | `mirage_tcp_set_connection_info_v4/v6()` 之前会解引用空指针 |

## KD-001 第三次握手 `ACK` 携带 `payload` 时数据被静默丢弃

优先级：`P1`

状态：`Resolved`

位置：

- [`src/mirage_tcp.cpp:276`](C:/dev/MirageTCP/src/mirage_tcp.cpp#L276)

问题描述：

- `SynReceived` 分支只校验 `ACK` 和 `sequence_number`
- 校验通过后直接把 flow 切到 `Established` 并返回
- 同一个包里如果还带了 `payload`，当前代码不会上报 `on_tcp_payload_received`
- `client_next_sequence` 也不会按 payload 长度推进

影响：

- 对端把首个应用数据与第三次握手合并发送时，库原先会静默丢数据
- 原实现还会导致后续同一连接上的序列号继续失步

当前分支处理结果：

- `SynReceived` 分支在完成握手回调后，如果同包还带有 `payload` 或 `FIN`，会继续复用 `handle_established_packet()`
- “最终 `ACK + payload`”现在会正常上报 `on_tcp_payload_received`，并推进 `client_next_sequence`

测试覆盖：

- 已补“最终 `ACK + payload`”的 packet-level 测试

## KD-002 已建立连接收到 `payload + FIN` 组合段时，`FIN` 被忽略

优先级：`P1`

状态：`Resolved`

位置：

- [`src/mirage_tcp.cpp:353`](C:/dev/MirageTCP/src/mirage_tcp.cpp#L353)
- [`src/mirage_tcp.cpp:384`](C:/dev/MirageTCP/src/mirage_tcp.cpp#L384)
- [`src/mirage_tcp.cpp:401`](C:/dev/MirageTCP/src/mirage_tcp.cpp#L401)

问题描述：

- `handle_established_packet()` 先判断 `payload`
- 只要 `payload` 非空，就立即上报 payload 并发送 `ACK`
- 这样同一个 segment 上的 `FIN` 分支永远不会执行到

影响：

- 对端已经发起关闭，但本地 flow 仍停留在 `Established`
- 宿主看到的连接生命周期与真实 TCP 行为不一致
- 后续报文可能被按错误状态处理

建议修复方向：

- 在同一个 segment 内同时处理 payload 长度与 `FIN`
- `ACK` 号需要同时覆盖 payload 长度和 `FIN` 占用的一个序号

当前分支处理结果：

- `handle_established_packet()` 现在先处理同包 `payload`，再继续处理同包 `FIN`
- 返回给对端的单个响应包会同时带 `ACK + FIN`
- `acknowledgment_number` 会同时覆盖 payload 长度和 `FIN` 消耗的一个序号

测试覆盖：

- 已补“`payload + FIN`”组合段的 packet-level 测试

## KD-003 `LastAck` 状态未校验对端 `sequence_number`

优先级：`P1`

位置：

- [`src/mirage_tcp.cpp:419`](C:/dev/MirageTCP/src/mirage_tcp.cpp#L419)

问题描述：

- `handle_last_ack_packet()` 只要求包上带 `ACK`
- 然后只校验 `acknowledgment_number == flow.server_next_sequence`
- 没有校验 `sequence_number == flow.client_next_sequence`

影响：

- 只要有人发来一个确认号正确的包，即使序列号不对，flow 也会被直接关闭
- 关闭阶段的状态机比建立态和传输态宽松，存在错误接受非法包的问题

建议修复方向：

- 按 established 阶段相同的规则校验 `sequence_number`
- 不匹配时走现有 reset/cleanup 路径

测试缺口：

- 当前测试只覆盖了“正确的最终关闭 `ACK`”
- 没有覆盖“确认号正确但 `sequence_number` 错误”的关闭阶段非法报文

## KD-004 `IPv4 fragment` 只检查了 fragment offset，未检查 `MF` 标志

优先级：`P2`

位置：

- [`src/ipv4_packet.cpp:77`](C:/dev/MirageTCP/src/ipv4_packet.cpp#L77)
- [`README.md:70`](C:/dev/MirageTCP/README.md#L70)

问题描述：

- 当前实现只检查 `flags_fragment_offset` 的低 13 位是否非零
- 这只能拦住“非首片”
- 如果是“首片且 `MF=1`”，offset 仍然为 0，代码会把它当成完整 TCP 报文继续处理

影响：

- 实际行为与 README 中“`IPv4 fragment` 不支持”的声明不一致
- 有机会把未完整重组的数据错误交给 TCP 解析路径

建议修复方向：

- 同时检查 fragment offset 和 `MF` 标志
- 任何分片报文都统一返回 `MTE_Ipv4FragmentUnsupported`

测试缺口：

- 当前没有覆盖“offset=0 但 `MF=1`”的首片场景

## KD-005 Debug 下对入站包地址对齐做 `assert`，可能中止合法调用

优先级：`P2`

位置：

- [`src/mirage_tcp.cpp:128`](C:/dev/MirageTCP/src/mirage_tcp.cpp#L128)
- [`src/mirage_tcp.cpp:132`](C:/dev/MirageTCP/src/mirage_tcp.cpp#L132)

问题描述：

- `handle_incoming_ip_packet()` 在 Debug 下要求 `ip_packet` 按 `alignof(Ip6Head)` 对齐
- 但 public API 是 `const void* + size_t`
- 很多抓包、环形缓冲区、隧道驱动接口并不保证传入地址满足这个对齐要求

影响：

- Release 构建通常能工作
- Debug 构建下可能直接触发 `assert` 并终止进程
- 这会让调用方误以为库要求额外 ABI 契约，但这个契约并没有体现在 public API 上

建议修复方向：

- 去掉这个 `assert`
- 继续使用 `memcpy` 解析固定头，避免依赖调用方提供对齐内存

测试缺口：

- 当前没有专门覆盖“未对齐 buffer 输入”的场景

## KD-006 `mirage_tcp_set_connection_info_v4/v6()` 之前会解引用空指针

优先级：`P3`

状态：`Resolved`

位置：

- [`src/connection_info.cpp:15`](C:/dev/MirageTCP/src/connection_info.cpp#L15)
- [`tests/test_main.cpp:340`](C:/dev/MirageTCP/tests/test_main.cpp#L340)
- [`tests/test_main.cpp:372`](C:/dev/MirageTCP/tests/test_main.cpp#L372)

问题描述：

- 之前实现会直接解引用 `client/server/target`
- 任一参数为 `NULL`/`nullptr` 时会触发未定义行为

当前分支处理结果：

- 现在任一指针参数为空时直接返回，不改写 `target`
- 已补正常填充与空指针忽略的测试

## 建议修复顺序

1. 先修 `KD-003`
2. 然后修 `KD-004` 与 `KD-005`
3. 每修一项同时补一个最小 packet-level 测试
