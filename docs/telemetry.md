# telemetry.md — 遥测协议(阶段 10)

> 数据通路【B】已还原;面板资源中已找到部分**语义代码名**,但**数字 DP ID、倍率和真实 BLE 值仍 UNKNOWN**。表结构已就绪,抓包后填空。

## 数据通路(代码确认)

```
BluetoothGatt onCharacteristicChanged (char 00000002)
  → trsmitr 重组(parseDataRecived / Packer 对偶)
  → Ret.parse: [flag][iv] AES-CBC → [sn][sn_ack][code][len][data][crc16-MODBUS]
  → bqdpddd.dealWithResponse(Ret)                        (bqdpddd.java:1519)
  → 0x8001: replayDpsReportAck + superUploadBleDps       (:1610-1616, pbpdbqp.java:8814-8818)
  → OnBleDpsReceiveListener.onDpsUpload(BleDps) → 面板/RN
  0x8004/0x8005/0x8006 状态 DP 同链路
```

## 上报帧解析(代码确认【B】)

### 0x8001 DP 上报(pv=4 新固件,DpsReportRep.parseRep)

```
[ver 1B][sn 4B BE][b_type 1B][flag 1B]   ← 7B 头(ver==4 时;bit7=0 → needAck)
[dpId 1B][type 1B][len 2B BE][value lenB] × N   ← pv4 用 2 字节长度
```

旧固件(pv3):无头,`[dpId][type][len 1B][value] × N`。

### 0x8004 状态 DP 上报(StatusDpsReportRep.java:20-50)

```
[rsnh 1B][rshl 1B][flag 1B] + TLV × N
```

### TLV 值解码(与下发一致)

| type | Python 解码 |
|---|---|
| 0 raw | bytes |
| 1 bool | v[0] != 0 |
| 2 value | int.from_bytes(v, 'little')(4B,有符号性由面板 schema 决定) |
| 3 string | v.decode('utf-8') |
| 4 enum | v[0] |
| 5 bitmap | int.from_bytes(v, 'little') |

## 字段映射表(待抓包填充)

| 车辆状态 | 预期 DP 类型 | dpId | 倍率 | 状态 |
|---|---|---|---|---|
| speed | value (4B) | UNKNOWN | UNKNOWN(常见 /10 km/h) | UNKNOWN |
| battery percent | value | UNKNOWN | UNKNOWN | UNKNOWN |
| battery voltage | value | UNKNOWN | UNKNOWN(常见 /10 V) | UNKNOWN |
| battery current | value | UNKNOWN | UNKNOWN | UNKNOWN |
| controller temp | value | UNKNOWN | UNKNOWN | UNKNOWN |
| motor temp | value | UNKNOWN | UNKNOWN | UNKNOWN |
| odometer(总里程) | value | UNKNOWN | UNKNOWN(常见 m 或 /10 km) | UNKNOWN |
| trip(单次里程) | value | UNKNOWN | UNKNOWN | UNKNOWN |
| light | bool | UNKNOWN | — | UNKNOWN |
| locked | bool/enum | UNKNOWN | — | UNKNOWN |
| cruise | bool | UNKNOWN | — | UNKNOWN |
| start mode(零启动) | bool/enum | UNKNOWN | — | UNKNOWN |
| regen(能量回收) | enum | UNKNOWN | — | UNKNOWN |
| error/fault code | raw/string/value | UNKNOWN | — | UNKNOWN |
| firmware version | string/raw | UNKNOWN | — | UNKNOWN |

> 填表方法(阶段 14/15):连接车后等待被动上报 + 逐项面板操作,对每个 TLV 记录
> (时间, 操作, dpId, type, 原始值);两帧间值变化与操作唯一对应的 dpId 即为该功能 ID。
> 涂鸦出行类设备有惯用 DP 布局,但**本仓库不采用未经验证的惯用值**,一律以抓包为准。

### MuMu 面板资源给出的代码名（非数字 DP ID）

2026-09-28 在原版 App 下载的 RN 面板资源中观察到 `dpState.speed`、
`dpState.battery_percentage`、`getDpSchema('mileage_once')`、`dpState.cruise_switch`、
`dpState.blelock_switch`。这些代码名缩小了待抓包字段范围,但还没有建立
`代码名 → 数字 dpId → BLE 原始值` 的对应关系。证据和限制见
[`emulator_validation.md`](emulator_validation.md)。【observed】

## 客户端实现状态

`src/youfs/telemetry.py` 已实现:0x8001/0x8004/0x8003 全解析(含 pv4 头、TLV 循环、六种类型解码),
输出 `DpReport{dp_id, type, raw, value}` 列表。语义层提供 `ScooterState`,通过 `dp_map.json` 配置
(dpId → 字段名 + 缩放),未配置字段原样保留 raw。
