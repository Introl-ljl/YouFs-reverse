# YouFs 2 连接排查：2026-09-29

## 当前结论

**observed：Windows 已连上目标车，取得完整 GATT 树，成功订阅通知，并在 20 秒观察期内保持连接。**
应用层 cmd0/cmd1 仍未发送，本次不能宣称 pairing-ready、遥测或车辆控制已完成。

**inferred：本次前半段的主要阻断与车辆的广播可用状态有关。** 手机蓝牙关闭、用户确认车辆
开机且距离很近时，两个扫描窗口均未发现目标；车辆断电重开后，目标开始持续发送可连接广播，
随后四次连接全部成功。无法仅凭这些数据区分自动关机、旧连接未释放、固件广播状态或其他原因。
过去 30 秒超时没有底层状态记录，不能倒推其唯一根因。

## 实验记录（本地时间 UTC+8）

| 实验 | observed 结果 | 工作区证据 |
|---|---|---|
| 10:05:52 被动扫描 30 秒 | 收到 166 条周边广播，目标 0 条，没有连接 | `work/ble_native_attempt1.jsonl` |
| 10:06:55 主动扫描 30 秒 | 收到 294 条周边广播，目标 0 条，没有连接 | `work/ble_native_attempt2.jsonl` |
| 10:08:47 启动记录，用户重新开机 | 10:09:03 起发现目标；60 秒中收到目标 57 个事件，含普通广播和扫描响应 | `work/ble_native_power_cycle.jsonl` |
| 10:09:45 原生 WinRT，采用观测地址类型 | 连接后约 2.5 秒取得 3 个服务；CONNECTED / ACTIVE / MTU 247 | `work/ble_native_random_connect1.jsonl` |
| 10:10:15 原生 WinRT，自动地址类型对照 | 自动选择同样的 RANDOM，约 3.1 秒取得服务；有一次短暂断开重连事件 | `work/ble_native_auto_control.jsonl` |
| 现有 CLI `gatt`，扫描 5 秒 / 连接上限 30 秒 | 同样取得完整服务、特征和描述符；自动地址类型，无应用帧 | `work/ble_cli_gatt_control.txt` |
| 项目 `YouFsTransport`，使用实测 UUID | 通知订阅成功，随后每 5 秒检查，4 次均在线，最后主动断开 | `work/ble_notify_check.txt`；复现脚本 `work/ble_notify_check.py` |

每次连接前都告知用户；没有自动重试或连接其他设备。原生对照实验中的短暂重连是 Windows 会话行为，
不是脚本另发连接尝试。最终所有诊断连接均已关闭。原始广告和地址仅保留在忽略跟踪的 `work/` 中。

## 广播和 GATT 的实测结果

- **observed**：目标仍为用户确认的尾号 `00:01` 地址，WinRT 报告类型为 `RANDOM`。
- **observed**：普通广播为 `CONNECTABLE_UNDIRECTED`，`is_connectable=True`；包含 FD50
  Service UUID 和 12 字节 FD50 service data，没有 manufacturer data。
- **observed**：主动扫描响应包含名称 `demo` 和 company ID `0x07D0` 的 manufacturer data。
  因此应修正“车辆没有厂商数据”：普通广播没有，扫描响应有。未收到响应的窗口仍需按精确地址识别。
- **observed**：GATT 服务为 `1800`、`1801`、`FD50`，MTU 为 247，未要求 Windows 系统配对。

| FD50 特征 UUID | 实测属性 | Value handle |
|---|---|---|
| `00000001-0000-1001-8001-00805f9b07d0` | write, write-without-response | 15 |
| `00000002-0000-1001-8001-00805f9b07d0` | notify，含 CCCD 2902 | 17 |
| `00000003-0000-1001-8001-00805f9b07d0` | read | 20 |

通知订阅只写标准 CCCD 开关，没有向应用写特征发送 cmd0、cmd1、DP 或控制帧。
用户听到提示音但没有看到仪表蓝牙图标。这不能否定已记录的 GATT 连接。
**unverified**：仪表是否要求应用认证成功后才亮图标；提示音具体由哪个阶段触发。

## 已排除与尚未确认的原因

- **observed，排除本轮的绝对性判断**：本机不能扫描或不能连接此车、广告不可连接、必须先 Windows
  系统配对才能读 GATT。以上都与成功实测矛盾。
- **unverified**：自动地址类型是历史超时原因。显式 RANDOM 成功，但自动对照同样选 RANDOM 并成功；
  没有证据证明旧轮次错选 PUBLIC，也没有因此强制修改正式客户端的地址类型。
- **observed**：安装的 Bleak 3.0.2 WinRT `connect()` 内含服务发现及 GATT 会话就绪等待；
  外层 30 秒超时不能区分无线建链和服务发现。Microsoft 也说明了创建 device 对象、维持会话和
  服务发现的不同语义：[BluetoothLEDevice.FromBluetoothAddressAsync](https://learn.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.bluetoothledevice.frombluetoothaddressasync)。
- **unverified**：本车的原版 factory selector / security mode / cmd0/cmd1 应答。FD50 布局和
  07D0 厂商数据本身不能替代这些证据，也未将它们转成已认证 P4 配置。

## 代码改动与复现

`tools/ble_link_probe.py` 提供原生 WinRT JSONL 诊断，分别记录广播可连接标志、地址类型、连接事件、
会话事件及服务发现状态。默认只扫描；`--connect` 才允许在精确地址的可连接广播后尝试一次连接。
`--address-type auto` 可复现 Bleak 默认地址解析，默认 `observed` 使用事件中实际类型。
输出必须在工作区中，已有文件不会覆盖；`--candidates` 可额外记录 FD50 候选，仍不会连接候选地址。

```powershell
# 每次执行 --connect 前，先通知车主给车开机并保持 iPhone 蓝牙关闭。
python tools/ble_link_probe.py <已确认的目标MAC> --active --connect `
  --scan-seconds 30 --connect-seconds 30 --output work/<新的诊断文件名>.jsonl

# 现有 CLI 也已成功；不传 --probe-cmd0 或 --pair 即不发送应用协议帧。
python cli.py gatt <已确认的目标MAC> --scan-timeout 5 --timeout 30
```

CLI 另修补了 connect 异常/取消后的限时 disconnect 清理，保留原始异常；将错误阶段改称
`BLE/GATT setup`，不再把组合操作的超时直接归因于无线链路。离线回归 **144 passed**；
真实验证依据是上表日志，而非这些测试。

## 下一步及边界

当前 BLE/GATT 阻断已跨过。下一步应利用本次原始扫描响应追踪目标的实际 parser 分支，并取得
原版连接配置或首批通信的证据，确认 cmd0 密钥分支后再做协议级验证。不要通过猜测 selector/
security mode 把 FD50 连接成功升级成认证成功。用户使用 iPhone，adb 不能提取它的蓝牙记录；
本轮没有安装 adb、修改手机、原始 APK 或任何全局配置。
