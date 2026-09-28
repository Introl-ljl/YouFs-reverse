# capture_analysis.md — 动态 BLE 验证(阶段 14/15)

> 状态:**PENDING — 需要 Android 真机 + 车辆**。静态部分已完成,本文档给出完整实验方案与记录模板,
> 数据到位后按模板填充。原始抓包保存于 `captures/original/`(不覆盖)。

## 环境准备

1. Android 真机,开发者选项 → 开启「蓝牙 HCI 信息收集日志」(Bluetooth HCI snoop log)。
2. 安装 YouFs-A 1.0.3,登录、绑定车辆(账号归用户所有)。
3. 关闭其它 BLE 设备干扰;车支架上,驱动轮悬空(安全约束)。

## 实验序列(单变量,间隔 5s)

```
连接 → 等 5s(记录自动下发的初始化包)
读状态(等待被动上报 10s)
开灯 → 等 5s → 关灯 → 等 5s
档位 1 → 档位 2 → 档位 3(各等 5s)
巡航 ON → 巡航 OFF(各等 5s)
锁车 → 解锁(各等 5s)
```

每步只改变一个变量。结束时导出 `/data/misc/bluetooth/logs/btsnoop_hci.log`。

## Wireshark 过滤

```
btatt.opcode.method == 0x52 || btatt.opcode.method == 0x42   # Write Request/Command
btatt.opcode.method == 0x1b                                  # Handle Value Notification
```

按 handle 区分(char 00000001 = TX,00000002 = RX)。导出 `btatt` 为 CSV 存入 `capture_analysis` 表。

## 记录模板(每个操作一行)

| Timestamp | Operation | Handle | UUID | TX bytes (hex) | RX bytes (hex) | Notification bytes |
|---|---|---|---|---|---|---|
| — | — | — | — | — | — | — |

## 分析步骤(填充方法)

1. **定 protocolType**:连接后首个下行 trsmitr 帧:首字节 `00`,随后 varint 总长,再 `(type<<4)` 字节。
   上层首字节 flag≠0 → P4/P2;若是 `[len][type][data]` 经典包 → P1。记入 models.md。
2. **验证校验**(对照 checksum.md):对 v2 明文体尾部 2B 跑 crc16_modbus;对信道末帧跑 crc16_arc;对经典包尾 1B 跑 crc8。
3. **验证 key 派生**(若已从账号取到 localKey):flag≠0 帧用 `auth.md` §3 公式派生密钥解密,能还原 sn/code 即 CONFIRMED。
4. **DP 差分**:两次抓包(开灯前/后)TLV 中唯一变化的 `[dpId type len value]` 即灯 DP → 填 telemetry.md / commands.md。
5. 每确认一条:commands.md 状态改 **【A】**(代码+抓包同证)或 **【C】**(仅抓包差分)。

## 判定标准

- CONFIRMED:APK 代码路径 + 抓包字节双向吻合(【A】)
- LIKELY:仅一方吻合(【B】/【C】)
- UNKNOWN:双方都无法定位(【E】)

## 交叉验证三件套

| 来源 | 文件/位置 |
|---|---|
| APK 代码 | work/jadx3/sources(本文档引用的 file:line) |
| HCI 抓包 | captures/original/btsnoop_hci.log(待提供) |
| nRF Connect GATT | 手动连接后截图,确认 service/characteristic 与 gatt.md 一致 |
