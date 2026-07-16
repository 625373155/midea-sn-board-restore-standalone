# 贡献指南

感谢改进这个项目。所有变更必须保留安全边界，并且不得使用真实设备进行自动测试。

目标公开仓库：[625373155/midea-sn-board-restore-standalone](https://github.com/625373155/midea-sn-board-restore-standalone)。

## 开始前

1. 不要在 Issue、分支、提交信息或测试夹具中放入真实 SN、SSID、BSSID、截图、日志或维修证据。
2. 不接受批量模式、任意目标地址、写入重试、云账号绕过、弱化确认或删除历史锁的变更。
3. 协议和模板变更必须有独立可审计依据，不能通过修改预期值来掩盖失败。

## 本地检查

```powershell
py -3 -m compileall -q .
py -3 .\midea_sn_restore_cli.py self-test
py -3 -m unittest discover -s tests -v
py -3 .\public_release_check.py
```

测试只能使用仓库允许的合成身份和临时目录。不得加入服务热点、创建到空调的 socket、调用生成包写入模式或触碰真实本机历史。

## Pull Request 清单

- 说明安全不变量是否受影响。
- 更新对应测试和中文文档。
- 确认没有真实身份、事件、路径或密钥。
- 确认生成器仍无网络导入，写路径仍只有一个静态 `0x41` 发送点。
- 确认严格 SN 解码、`READ-INVALID-DO-NOT-WRITE`、`WRITE_NOT_SENT_BUT_LOCKED` 和版本化凭据哈希的静态断言仍通过。
- 确认公开发布扫描已检查全部 refs 可达历史、提交/标签消息、路径、NUL 和符号链接，而不只是当前工作树。
- 确认完整 CI 通过。
