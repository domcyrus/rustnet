# QUIC 检查

[English](QUIC.md) | [简体中文](QUIC.zh-CN.md) | [日本語](QUIC.ja.md)

**自 v1.7.0 起可用：** RustNet 组装客户端 Initial CRYPTO 流，提取 ClientHello 中的 SNI、ALPN
和 TLS 版本。找到 SNI 后仍继续组装，因为后续分片可能携带 ALPN。

检查窗口覆盖偏移 0 至 65,535，最多保留 256 个不连续区间。相邻区间会合并，
也支持逆序到达。重叠重传补充缺失字节，重叠位置保留首次观察到的值。
空分片和窗口外偏移会被忽略或拒绝。超大或过度稀疏的握手可能只能提取部分元数据。

完整 ClientHello 检查完成、64 KiB 窗口填满或合并连接关闭状态后，释放握手字节。
其余不完整握手在活动连接过期前保持有界缓冲。UI 和历史快照仅保留提取的元数据，
不复制 CRYPTO 缓冲。STREAM 应用字节会跳过。原始抓包导出仍包含报文数据。

库调用方需要注意：`CryptoFrameReassembler::get_fragments()` 现在返回
`(u64, &[u8])` 迭代器，替代借用的 `BTreeMap`。环绕的双端队列可能返回两个
相邻切片，各自带实际流偏移。`add_fragment()` 和 `get_contiguous_data()` 签名不变。

QUIC 线上长度使用检查转换和偏移运算。SNMP BER 外层及嵌套长度也限制在声明的容器中。
回归测试覆盖重叠、逆序、后续 ALPN、缓冲释放，以及 debug 和 release CI 中的
32 位长度边界。
