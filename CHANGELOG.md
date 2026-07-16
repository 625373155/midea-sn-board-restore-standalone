# Changelog

## [Unreleased]

- 暂无。

## [1.0.0] - 2026-07-16

- 首次独立源代码版，不依赖 Codex 或第三方 Python 包。
- 提供 `wizard`、`generate`、`validate`、`self-test` 和掩码 `history` 命令。
- 生成与校验两端都将兼容型号 allowlist 固定为 `KFR-26G/WXAA2@`。
- 保留单设备、单事件、写前原子保留、只读/写入结构分离和精确模板校验。
- 附带 Windows 启动器、中文教程、安全策略、GitHub Actions 和离线自动测试。
- 公开源码、测试和文档仅使用合成身份；不包含客户 SN、SSID、BSSID 或维修记录。
- 严格解码完整性通过的 SN 载荷；不可解码时建立包内/全局 `READ-INVALID-DO-NOT-WRITE` 永久停止标记。
- 写锁后的全部预发送异常归类为 `WRITE_NOT_SENT_BUT_LOCKED`，锁保持有效且禁止自动重试。
- 新板证据改用版本化 NFKC、casefold、空白折叠哈希，拒绝仅大小写/兼容字符/空白变化的伪新事件。
- `decode_sn` 的长度、边界和替换域错误统一为 `ValueError`。
- 新增覆盖工作树、文件名、NUL、符号链接、全部 Git refs/提交/标签消息的公开发布扫描器。
- 同步静态 validator、结果分类、使用说明和离线回归测试。

[Unreleased]: https://github.com/625373155/midea-sn-board-restore-standalone/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/625373155/midea-sn-board-restore-standalone/releases/tag/v1.0.0
