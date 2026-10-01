# gatt.md — GATT Profile(UUID)

> 证据等级:【B】= APK 代码确认。2026-09-29 目标 GATT 经 Windows 实车验证（observed）；应用协议 HCI 仍待抓包。

## YouFs 2 当前状态与实车操作顺序【observed / unverified】

2026-09-29，App 中名称为 **YouFs 2**、地址尾号 `00:01` 的车辆已实测成功：RANDOM 地址类型，
CONNECTABLE_UNDIRECTED 广播，GATT 为下方 FD50 组，MTU 247；通知订阅后保持观察 20 秒。
普通广播没有 manufacturer data，但主动扫描响应含 0x07D0 厂商数据和名称 demo。
`protocolType`、安全 flag 和应用认证仍未验证。证据与边界见 [本轮报告](ble_diagnosis_20260929.md)。

实车确认顺序：

1. `python cli.py scan --all`：查看全部广播设备；从名称、地址尾号和 RSSI 核对目标是 YouFs 2。
   若扫描未出现目标，停在扫描阶段，不能把“未发现”解释成 GATT 或配对失败。
2. `python cli.py gatt <目标当前地址>`：只建立 BLE 链路并枚举服务/特征，不发送应用层命令。
   记录同一 service 下具备 write 与 notify/indicate 属性的特征 UUID。
3. 取得可信设备配置后运行 `python cli.py connect <地址> --profile-file work/<profile>.json --service-uuid <service> --write-uuid <write> --notify-uuid <notify>`。
   profile 的 `protocolType` 值在 CLI 中作为显式 factory selector；必须通过 YouFs 2 原版连接记录或
   目标专属元数据核实。APK 实际 selector 名为 `ControllerBean.deviceType`，不能假定等于云端
   `DeviceBean.protocolType`。`connectType`、`securityMode`、UUID、devId、localKey 也必须有目标专属
   依据。若有已核验 beaconKey 会使用原版 marker `0x10` 分支；缺失时照 APK normal path 使用 marker
   `0x00` fallback。connect 会重新扫描并以该次扫描取得的 BLEDevice 对象建立连接，再验证 GATT 和订阅
   通知，然后按 selector 发送已支持的 P4 legacy cmd 0 与 cmd 1。
4. 仅当 cmd 0 返回可解析设备信息、cmd 1 PairRep 的 bindStatus 为 0 或 2 时，app-layer 才进入 READY。cmd 0 应答不等于 pairing-ready。P1、P2、P4 新安全/证书及其他未支持组合均 fail closed。

BLE link ready 表示底层已连接；GATT ready 表示已选择并订阅通道；cmd 0 response received 表示
收到设备信息响应；**pairing-ready 需要 cmd 1 配对成功才能成立**。这些状态不可互相替代。cmd 0
超时只能说明此请求没有得到可解析响应，可能原因包括目标/协议族不匹配、请求加密要求或丢包，不能
单凭超时断定车辆需要重新配对。

截至 2026-09-28，YouFs 2 尚未在当前扫描中出现；此前准确地址的两次 BLE 连接均超时，之后广播消失。
该车的连接、GATT、cmd 0、cmd 1 和 READY 均未实车验证。当前流程仅有离线测试证据。

## Service(主通信服务)【B】

```
0000fd50-0000-1000-8000-00805f9b34fb
```

- 涂鸦蓝牙 SIG 分配的 16-bit service UUID 0xFD50。
- 定义处(混淆类,原名 ThingUUIDs):`work/jadx3/sources/com/thingclips/sdk/bluetooth/pqbqbdb.java:18`(`pqdbppq`)、`qpqqdbp.java:24`(`pbpqqdp`);另见 `sdk/ble/core/manager/bppdpdq.java:759`(连接校验使用)。

## Characteristics【B】

基座:`xxxxxxxx-0000-1001-8001-00805F9B07D0`(涂鸦自定义 128-bit 基座)

| UUID(16-bit 段) | 属性 | 用途 | 证据 |
|---|---|---|---|
| `00000001-0000-1001-8001-00805F9B07D0` | Write / Write-NoRsp | **TX(App→车)** 所有下行分片都写到这里 | 定义 `qpqqdbp.java:25`;写入路径 `dpqbbpd.java:6073` `addCommunicationService(FD50, 00000001)`;`ddbpdpq.java:1880-1886` |
| `00000002-0000-1001-8001-00805F9B07D0` | Notify | **RX(车→App)** 所有上行分片从这里来(需写 CCCD 0x2902) | 定义 `qpqqdbp.java:26`;`dpqbbpd.java:6073` `addNotificationService(FD50, 00000002)`;notify 注册 `bddqdbq.java:1062-1098` |
| `00000003-0000-1001-8001-00805F9B07D0` | Read | 配网/绑定信息读取(系统已绑定设备扫描用),常规通信用不到 | `bppdpdq.java:760` + `:1930` `read(address, FD50, 00000003, ...)` |

**TX 与 RX 是两个不同的 characteristic**(不是同一个)。Notify 通过标准 CCCD `00002902-0000-1000-8000-00805F9B34FB` 开启(`blelib/Constants.java:165-166`;设备缺 2902 时 SDK 回退 2901,`BleConnectWorker.java:2786-2787`)。

## 旧协议(P2 delegate)使用的 Telink 系 UUID【B,备用】

P2(SecurityProtocolDelegate,protocolType 非 413/400-405/100-102 时)使用:

```
Service : 00001910-0000-1000-8000-00805f9b34fb
Write   : 00002b11-0000-1000-8000-00805f9b34fb   (qpqqdbp.java:21-23; bqdpddd.java:3169-3172)
Notify  : 00002b10-0000-1000-8000-00805f9b34fb
```

即 Telink OTA/透传 UUID 组。哪个 delegate 生效由 APK factory selector 决定；selector 的入口和扫描覆盖规则见 models.md。**本次目标车实测为 FD50 组；这不单独确认 factory selector。**

> **两组常量都已由 APK 源码证实存在**(FD50 组 `pqbqbdb.java:18-20` + `bppdpdq.java:759`;
> 1910 组 `pqbqbdb.java:8-11` + `qpqqdbp.java:21-24`)。2026-09-29 已确认目标车使用 FD50 GATT 布局。
>
> **实机首次连接先跑 `python cli.py gatt <BLE_Mac>`**:连上后枚举完整 GATT 树、列出所有
> writable+notifiable 配对,并直接判断属于哪一组,不需要猜。(该探针曾对一台非 YouFs 的真实
> Tuya 系设备枚举成功；这不能证明 YouFs 2 可连接。注意 GATT service UUID 不等于广播 UUID——某台实测设备广播在
> `0xFE95`、数据通道在 `0xFE95/0x0010`,两者都不在下面两组里,所以**必须实测而不能假定**。)

## MTU【B】

- P4 ConnectBuilder 默认 `requestMtu(246)`(`dpqbbpd.java:61` `MAX_MTU=246`;仅机型 M2004J7BC 强制 23,`:6062-6070`)。
- 有效载荷按 `mtu - 3` 计算(`AbsProtocolDelegate`/pbpdbqp.java:2003);分帧下限 20 字节(`blelib/packet/Packer.java`)。

## 广播【observed/B】

涂鸦广播有**两种载体**,两种都必须解析(`src/youfs/scanner.py`):

### Service Data (0xFE95)【observed】

**重要:有真实设备把广播数据放在 service data `0000fe95-...` 里,且完全没有
manufacturer data。** 只按 company id 过滤会**一个都扫不到**。

本机实测两台真实设备(2026-09-28,`cli.py scan`)。这是**观测,不是型号规律**——
只能说明这种广播确实存在于现实中,不能说某代模块一定用它。下表向量已做匿名化替换
(MAC 与 service data 同步改写,字节布局与真实抓包一致):

| 设备名 | service data (hex) | 其中 MAC |
|---|---|---|
| `iot.switch.tdq3` | `b0543d450001eeddccbbaa080e00` | `AA:BB:CC:DD:EE:01` |
| `philips.light.lite` | `b054501301665544332211080e00` | `11:22:33:44:55:66` |

**已证实**:设备 MAC 位于 `data[5:11]`,**小端**(逆序即得)。两台的解析结果与其自身
BLE 地址逐字节相同,这是偏移正确的独立证据(回归向量见 `tests/test_protocol.py`)。

`data[:2] == b'\xb0\x54'` 时前缀一致,但其余字节含义**未证实**,代码只保留在
`TuyaAdv.raw` 中,不对其做任何解释。

> 识别仍然**不看设备名前缀**(全树无 "TY"/"YFS" 校验)——但 carrier 有两种,
> manufacturer data 和 service data 都要解析(`src/youfs/scanner.py`)。

### Manufacturer Specific Data(company id)【B】

识别条件**只看厂商数据 company id,不看设备名前缀**(全树无 "TY"/"YFS" 名字校验,`grep startsWith("TY")` = 0):

| mfd[0..1] (LE) | 含义 | 分支 |
|---|---|---|
| 0x5904 / 0x5984 | 涂鸦单 BLE 广播;首字节 bit7=1(0x5984)表示**已绑定** | 标准 20 字节格式 |
| 0x5902 / 0x5982, 0x6902 / 0x6982 | beacon 变体,要求 AD 中含 16-bit UUID 0x01A2 | beacon |
| 0x07D0(2000) | 涂鸦标准配网/能力广播 | 标准 |
| 0x0259 | 旧式 28 字节广播 | legacy |

标准格式字段(`ThingBeaconParser`/pbbqdqp.java:66-92):

```
mfd[0..1]  company id (LE, [0] 的 bit7 = 已绑定标志)
mfd[2..7]  设备 MAC(6 字节)
mfd[8]     类型字节(==1 → 纯 BLE deviceType 200;否则双模 300)
mfd[9..]   设备 UUID(ASCII,可读字符串;前缀 "key" 表示带 key 激活)
```

product id 不在明文广播中(加密型广播才有,密钥来自 product secret)。
