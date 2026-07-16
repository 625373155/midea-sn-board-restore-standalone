# 美的空调替换主板 SN 恢复工具（独立源代码版）

公开仓库：[625373155/midea-sn-board-restore-standalone](https://github.com/625373155/midea-sn-board-restore-standalone)

首个公开源代码版本为 `v1.0.0`。生成包清单中的生成器组件版本是 `1.3.0`；它是包格式/校验器的内部兼容版本，不是 GitHub 发布标签。

这是一个可直接从源代码运行的 Windows 工具，不需要 Codex，也不需要售后账号。它面向一个很窄的维修场景：设备所有者或获授权维修人给兼容型号 `KFR-26G/WXAA2@` 的美的空调更换了实体主板，新板缺少原机身的 22 位 body SN，需要为这一台空调生成一个单设备、一次写入的恢复包。

工具本身是离线生成器和校验器：它不会连接空调、不会加入 Wi-Fi、不会运行生成包，也不会发送查询或写入。只有你之后明确双击生成包内的启动器时，包内 PowerShell 才可能连接当前服务热点，并且固定只访问 `192.168.1.1:6444`。

> 这不是美的官方工具，也不代表美的授权或认可。请优先联系官方售后。涉及拆机、强电或制冷系统时，必须交给合格维修人员。

## 能做什么

- 交互向导检查所有权、产品类别、原 SN 来源、准确型号、实时服务热点和实体换板凭据。
- 生成身份硬编码、目录和 ZIP 哈希固定、带本机追加式历史的恢复包。
- 将只读诊断与唯一写入路径结构化分离。
- 在建立写入保留标记后，最多发送一次写请求；不会因为无响应而重试。
- 离线校验生成文件、ZIP、模板一致性、静态安全约束和 PowerShell SelfTest。
- 以掩码形式查看本机生成历史。
- 用版本化的 `NFKC + casefold + 折叠空白` 哈希比较换板凭据；只改大小写、兼容字符或空白不能冒充一次新换板。

## 明确不支持

- 只提供一个 SN、猜测 SN、截取 App 的 32 位显示值，或使用另一台设备的标签。
- 批量写入、复制身份到多块板、翻新/转售准备或隐藏重试。
- 绕过账号绑定、云端注册、区域限制、所有权校验或售后凭据。
- 其他家电品类、其他主机/端口、其他协议操作码。
- `KFR-26G/WXAA2@` 之外的空调型号。能看到相同格式的热点不证明协议兼容。
- 对同一次事件重复写入。即使写后没有任何返回，也不能重跑写入。

## 运行条件

- Windows 10 或 Windows 11。
- Python 3.10 或更高版本；建议从 [python.org](https://www.python.org/) 安装，并保留 Windows 的 `py` 启动器。
- Windows PowerShell 5.1 或更高版本。
- 生成阶段不需要联网，不需要安装第三方 Python 包。
- 真正操作设备前，必须能在 Windows WLAN 列表中实时看到该新主板的完整 `midea_test_<12 个十六进制字符>` 热点。

## 下载与首次自检

1. 在 GitHub 页面选择 **Code → Download ZIP**，解压到普通文件夹；不要直接在压缩包内运行。
2. 双击 `run_self_test.cmd`。
3. 看到 `"result": "SELF_TEST_OK"` 才继续。
4. 发布源码或提交 Pull Request 前，再运行 `py -3 .\public_release_check.py`；它会检查当前文件、路径、NUL/二进制、符号链接以及所有 Git refs 可达的提交和标签元数据。

也可以打开 PowerShell，在项目根目录执行：

```powershell
py -3 .\midea_sn_restore_cli.py self-test
```

该自检只运行合成测试向量和静态检查，`networkActionsPerformed` 必须为 `false`。

## 准备材料

开始向导前准备好：

1. 你拥有这台空调或得到明确维修授权。
2. 目标确实是美的空调，并且本次真实更换了一块实体主板。
3. 完整的原机身 SN：必须恰好是 22 个 ASCII 数字。
4. SN 的可信来源：客服记录、原机标签、官方 App 旧记录或旧主板可靠读取之一。
5. 铭牌或可信服务记录上的准确型号必须是 `KFR-26G/WXAA2@`，并准备本次换板凭据说明。
6. 当前新板实时广播的完整服务热点；空格、缺字、猜测字符都不接受。
7. 如果可查到 BSSID，建议同时记录。

App 显示的 32 位值不能直接作为输入，也不能默认删除前后数字来“换算”。某个型号曾出现的展示形式不是通用规则。

## 推荐流程：交互向导

双击 `run_wizard.cmd`，或执行：

```powershell
py -3 .\midea_sn_restore_cli.py wizard
```

按提示逐项输入。确认短语必须完全一致；按提示输入的真实 SN、SSID 和凭据只会写入本机生成包与本机历史，不会上传到 GitHub。

输出目录必须位于本项目目录之外，例如：

```text
D:\MideaRestorePackages
```

成功后会得到：

```text
midea-sn-<sn后4位>-<ssid后4位>-<事件前8位>\
midea-sn-<sn后4位>-<ssid后4位>-<事件前8位>.zip
midea-sn-<sn后4位>-<ssid后4位>-<事件前8位>.zip.sha256
```

生成并不代表已经操作设备；输出中的 `PACKAGE_GENERATED_NOT_EXECUTED` 正是这个含义。

## 高级流程：命令行生成

向导是首选。需要自动化单次生成时，可查看完整参数：

```powershell
py -3 .\midea_sn_restore_cli.py generate --help
```

命令结构如下；尖括号内容必须替换为本次设备的真实且已核验信息：

```powershell
py -3 .\midea_sn_restore_cli.py generate `
  --sn <原机身22位SN> `
  --ssid <当前新板完整服务热点> `
  --model KFR-26G/WXAA2@ `
  --sn-source customer-service `
  --sn-source-reference <一行来源凭据说明> `
  --new-board-evidence <一行本次实体换板凭据说明> `
  --ownership-confirmed `
  --trusted-source-confirmed `
  --new-physical-board-confirmed `
  --output <项目目录之外的输出父目录>
```

可选 `--bssid <当前BSSID>`。只有在历史事件之后又真实换了另一块实体主板时，才可按错误信息要求提供 `--previous-incident-id` 和 `--later-physical-board-event-confirmed`；这两个参数不是重试开关。

## 校验生成包

生成后、连接设备前，先运行：

```powershell
py -3 .\midea_sn_restore_cli.py validate <生成包目录> --require-archive
```

或：

```powershell
.\validate_package.cmd "<生成包目录>" --require-archive
```

只有看到 `PACKAGE_VALID` 才能继续。校验会执行离线 PowerShell SelfTest，但不会加入热点或连接设备。

## 生成包内的实际执行顺序

先打开生成包内的 `TARGET.json` 和中文说明，逐字核对本机型号、完整 22 位 SN、完整热点、SN 来源和事件 ID。确认无误后按顺序：

1. `00_self_test.cmd`：离线自检。
2. 加入已经核验的服务热点。
3. `01_query_only.cmd`：普通只读查询。完整性通过的身份载荷必须先严格解码为 22 位 ASCII 数字；若无法解码，程序会建立包内和全局 `READ-INVALID-DO-NOT-WRITE.jsonl` 永久标记并停止。
4. 必要时 `03_raw_read_only_diagnostic.cmd`：只读原始诊断。
5. 如果完整性校验后的只读结果已经是目标 SN，立即停止，不要写。
6. 如果诊断收到 0 字节，只能说明“没有收到字节”，不能证明主板为空；资格证据仍全部成立时，才考虑下一步。
7. `02_restore_once_and_verify.cmd`：唯一写入入口。认真阅读屏幕说明，并输入事件专属确认短语。写入保留标记会在联网发送前建立。
8. 只要建立过写入保留或出现过发送尝试，绝对不要再次运行第 7 步，包括“没有 ACK”“验证仍是 0 字节”“程序报错”等情况。
9. 空调整机彻底断电后冷启动。
10. `04_post_write_read_only_check.cmd` 只能只读检查；随后用官方 App 和正常控制功能核验。

## 如何理解常见结果

完整状态定义与证据层级见 [docs/OUTCOME_CLASSIFICATION.md](docs/OUTCOME_CLASSIFICATION.md)。

- `Connected ...`：只证明 TCP 曾连接，不证明 SN 已写入。
- `RAW_RECEIVED_BYTES=0`：只证明观察窗口内没有收到字节，不证明新板为空，也不证明写入失败。
- `ONE_WRITE_REQUEST_SENT`：写路径已经开始一次发送；从此该事件必须视为已消耗。
- `READ-INVALID-DO-NOT-WRITE`：收到了完整性通过但无法严格解码的 SN 载荷；这不是“空码”或普通不匹配，必须永久禁止本事件写入并交由授权维修复核。
- `WRITE_NOT_SENT_BUT_LOCKED`：写入保留已经持久化，但本进程在 `NetworkStream.Write` 开始前失败。保留锁仍然永久有效；不要删除标记或重跑写入，需要人工代码/审计复核。
- `WRITE_RESULT_UNKNOWN`：结果未知，不能重试。只能冷启动、只读检查、官方 App 核验或联系授权售后。
- `PACKAGE_INVALID`：不要运行包内任何启动器；保留完整输出用于排查。

## 查看本机历史

```powershell
py -3 .\midea_sn_restore_cli.py history
py -3 .\midea_sn_restore_cli.py history --json
```

身份默认掩码。历史保存在当前 Windows 用户的 LocalAppData 已知文件夹中，生成器不信任可临时改写的 `LOCALAPPDATA` 环境变量。不要删除或修改历史来解锁一次事件。

软件锁是尽力而为的本机保护，不是硬件 DRM。复制文件到其他电脑、修改公开源代码或删除本地状态可能绕过它，因此所有权和真实换板凭据仍是核心前提。

## 隐私与公开仓库

本仓库只包含合成 SN、合成 SSID 和合成 App 展示示例，不包含任何客户设备身份、BSSID、维修日期、截图或执行日志。

不要把以下内容提交到公开 Issue、Pull Request 或仓库：

- 真实完整 SN、SSID、BSSID、`TARGET.json` 或生成 ZIP；
- 真实换板凭据、客服记录、App 截图；
- 未脱敏的命令输出、诊断日志和本机路径。

报告问题时请先复制到离线文本，再用明显的占位符逐项替换身份信息。详见 [SECURITY.md](SECURITY.md)。

## 故障排查

### `py` 不是内部或外部命令

重新安装 Python 3.10+ 并启用 Windows Python Launcher，或将命令中的 `py -3` 替换成已确认指向 Python 3.10+ 的 `python`。

### 拒绝 22 位 SN

工具只接受 ASCII `0` 到 `9`，不自动去空格、不接受连字符、全角数字、标签文字或换行，也拒绝 32 位 App 值。

### 拒绝服务热点

必须精确匹配 `midea_test_` 加 12 个十六进制字符。请从 Windows 当前 WLAN 列表重新核对，不要根据手写文本补字符。

### 拒绝型号

当前发布版只允许 `KFR-26G/WXAA2@`。服务热点格式相同不代表其他型号的主板、固件和协议安全兼容；不要修改 allowlist 强行运行。

### 提示存在历史

同一 SN 或热点已有本机历史。对同一主板事件不能重试。只有后来又真实更换另一块实体板时，才能以最新事件 ID、新的换板凭据和额外确认建立新事件。

换板凭据的历史比较使用版本化规范化哈希：先做 Unicode NFKC、大小写折叠，再把连续空白折叠为一个空格。改变大小写、全角/兼容字符或空格数量不会形成“新凭据”；是否真的换板仍需独立人工核验。

### 校验找不到 PowerShell

确认 `powershell.exe` 可用。Windows 10/11 默认包含 Windows PowerShell 5.1；被企业策略禁用时请联系管理员，不要跳过校验。

## 源代码结构

```text
midea_sn_restore_cli.py       从源码直接运行的入口
midea_sn_restore/cli.py       向导、generate、validate、self-test、history
midea_sn_restore/generator.py 离线一次性包生成器与追加式历史
midea_sn_restore/validator.py 精确模板、哈希、ZIP 和静态约束校验器
midea_sn_restore/protocol.py  编码、帧、加密和合成回归向量
midea_sn_restore/templates/   经过校验的 Windows 运行模板
tests/                        不连接设备的自动测试
public_release_check.py       公开发布隐私、文件系统与完整 Git refs 扫描
```

开发者验证：

```powershell
py -3 -m compileall -q .
py -3 .\midea_sn_restore_cli.py self-test
py -3 -m unittest discover -s tests -v
py -3 .\public_release_check.py
```

自动测试不得连接服务热点、不得创建 TCP 连接、不得运行写入模式。

## 许可证状态

当前仓库没有 `LICENSE` 文件，也暂未附加任何许可证。公开可见不等于授予复制、修改或再发布权；待仓库所有者明确选择许可证后再按对应条款使用或分发。

版本发布页：[v1.0.0](https://github.com/625373155/midea-sn-board-restore-standalone/releases/tag/v1.0.0)
