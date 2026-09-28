# ble.md — BLE 入口类清单(阶段 2)

> 全部来自 classes3.dex 反编译(`work/jadx3/sources/`),混淆类名后括号为 jadx 保留的原名
> (`/* compiled from: */` 注释)。反分析噪声 `Tz.a()/Tz.b(0)`(com.ai.ct.Tz)在所有方法体内大量插入,阅读时忽略。

## 分层结构

```
App/RN 面板(云端下发)
   ↓ publishDps / queryDps (IThingBleFlow)
com.thingclips.sdk.ble.core            — 协议业务层(bean/manager/business/protocol)
com.thingclips.sdk.bluetooth            — 协议 delegate 层(P1/P2/P4, 帧编解码, 广播解析)
com.thingclips.sdk.blelib               — GATT 连接库(channel 分帧, connect 请求队列)
com.thingclips.ble.jni.BLEJniLib        — JNI → libBleLib.so(经典协议编解码)
android.bluetooth                       — BluetoothGatt/LeScanner
```

## 关键类

### GATT 传输层(sdk/blelib)

| Class | Method | Purpose | Called by | Calls | Relevant constants |
|---|---|---|---|---|---|
| `connect/BleConnectWorker` | `openGatt()` :1701 | `connectGatt(ctx, autoConnect, cb, TRANSPORT_LE)` | BleConnectDispatcher | BluetoothGatt | transport=2 |
| `connect/BleConnectWorker` | `onConnectionStateChange` :1353 | 连接/断开回调;status 133 → `refreshDeviceCache` | BT 栈 | discoverServices | — |
| `connect/BleConnectWorker` | `setCharacteristicNotification` :2699 | 注册 notify + 写 CCCD 0x2902(缺则回退 0x2901) | BleNotifyRequest | writeDescriptor | `CLIENT_CHARACTERISTIC_CONFIG` |
| `connect/BleConnectWorker` | `requestMtu` :2221 | MTU 请求 | BleConfigMtuRequest | gatt.requestMtu | 上层默认 246 |
| `channel/Channel` | `send()/onRead()` :3357/:3323 | 20 字节分帧状态机(CTR/ACK/数据帧,CRC16-ARC) | OTA 大数据通道 | CRC16.get | `SN_CTR=0`, 超时 5000ms |
| `channel/packet/Packet` | `getPacket()/parse()` :222/:367 | 帧解析:sn(2B BE)==0 → 控制帧,否则数据帧 | Channel | ByteBuffer | `TYPE_ACK=1, TYPE_CMD=0` |
| `channel/packet/DataPacket` | `toBytes()/setLastFrame()` | `[seq 2B BE][payload]`;末帧裁掉尾部 2B CRC | Channel | ByteUtils | 帧容量 20B(载荷 18B) |
| `channel/packet/ACKPacket` | `toBytes()` :393 | `[0x0000][type=1][cmd=0][status 2B][seq 2B]` | Channel | ByteBuffer | status: 0 SUCCESS /1 READY /2 BUSY /3 TIMEOUT /4 CANCEL /5 SYNC |
| `channel/packet/CTRPacket` | `toBytes()` | `[0x0000][type=0][cmd=0][frameCount 2B]` | Channel | ByteBuffer | — |
| `channel/CRC16` | `get()` | CRC-16/ARC(查表,init 0),输出 LE 2B | Channel | ByteUtils.fromShort | TABLE poly 0xA001 |

### 连接编排层(sdk/bluetooth,混淆)

| Class(原名) | Method | Purpose | 证据 |
|---|---|---|---|
| `dpqbbpd` (P4SecurityProtocolDelegate) | `assembleConnectBuilder` :6062 | setMtu(246) + addCommunicationService(FD50,char1) + addNotificationService(FD50,char2) | dpqbbpd.java:6073 |
| `dpqbbpd` | `fetchDeviceInfoRet` :6100 | 连接后自动发 **cmd 0 设备信息请求**(选密钥 idx 14/11/4/1) | dpqbbpd.java:6100-6131 |
| `dpqbbpd` | `pairDevice` :6665 | 发 **cmd 1 配对**(密钥 idx 15/12/5/2) | dpqbbpd.java:6742-6850 |
| `dpqbbpd` | `queryDps` :6999 | DP 查询 = **code 3**(FUN_SENDER_DEVICE_STATUS) | dpqbbpd.java:6999-7010 |
| `dpqbbpd` | `onBusinessResult` :6547 | 应答设备时间请求(32785/32786/32787/32788) | dpqbbpd.java:6547-6575 |
| `bqdbbqq` (ThingProtocolFlowFactory) | 工厂 :49-85 | protocolType → delegate:413/400-405→P4,102→P1Sec,101→P1WiFi,100→P1Normal,**其余→P2** | bqdbbqq.java |
| `pbpdbqp` (AbsProtocolDelegate) | `connectDeviceAction` :2424 | 连接状态机("startConnectAction()") | pbpdbqp.java:2424-2451 |
| `pbpdbqp` | `superFetchDeviceInfoRetSuccess` :7471 | 保存 srand/authKey → 触发 pairDevice | pbpdbqp.java:7474-7508 |
| `pbpdbqp` | `deviceConnectSuccess` :2729 | 协议就绪("CONNECTED") | pbpdbqp.java:2729-2740 |
| `ppbdppp` (BleConnectAction) | 连接参数 :1301-1331 | retry=3, connectTimeout=10s, discoverRetry=1, discoverTimeout=3s | ppbdppp.java:1324 |
| `pbbqdqp` (ThingBeaconParser) | `bdpdqbp(name,mac,rssi,raw)` :429 | 广播解析/设备识别(company id 分发) | pbbqdqp.java:429-940 |
| `pbqbqbq` (Packer) | `bdpdqbp(type,data,len,mtu)` :47 | v2 GATT 分帧:[pkgIdx varint][totalLen varint][type<<4][payload] | pbqbqbq.java:47-70 |
| `ppqbqbb` (X2Request) | `pack()` | 组 v2 应用帧(sn/ack/code/len/crc16 → AES-CBC → Packer) | ppqbqbb.java:1378-1388 |
| `ppbpqqq` (ThingDataPacket) | `bdpdqbp(key,flag,iv,data)` :535 | 加密封帧:flag + iv(16B) + AES-128-CBC NoPadding(零填充) | ppbpqqq.java:535-562 |
| `bpdpppq` (SecurityUtil) | AES | `AES/CBC/NoPadding`,key 16B + iv 16B | bpdpppq.java:21,173 |
| `qdqbdbd` (CRCUtils) | `bdpdqbp(byte[])` | CRC-16/MODBUS(init 0xFFFF,反射 0xA001),BE 输出 → v2 帧 CRC | qdqbdbd.java |
| `bddqqbp` (Code) | 命令码表 | cmd 名称映射 | bddqqbp.java:317-414 |
| `pqdppqd` (Business) | 云接口 | `m.thing.device.auth.key.get`、`thing.m.device.active` | pqdppqd.java:33,1035 |

### JNI 桥(sdk/ble 经 BLEJniLib,classes.dex)

| Class | Method | Purpose |
|---|---|---|
| `com.thingclips.ble.jni.BLEJniLib` | `getNormalRequestData(cmd,data,len,out)` | 构造经典协议请求包(cmd: 1=pair,2=DP,3=ACK,4=query,5=loginKey pair,6=unbind,10=ext,11-15=OTA) |
| 同上 | `getCommandRequestData(...)` | 构造 DP TLV 明文([dpId][type][len][value]) |
| 同上 | `madeSessionKey(in,len,out)` | 16B 会话密钥 = CRC8(poly 0x07)表 S-box 逐字节替换(libBleLib.so) |
| 同上 | `parseDataRecived/parseKLVData/crc4otaPackage` | 接收重组/DP 解析/OTA CRC-16-MODBUS |

### 回答(阶段 2 问题清单)

1. **如何扫描?** `BleSingleScanner` → 系统扫描回调 → `ThingBeaconParser` 解析厂商数据。
2. **如何识别涂鸦设备?** 仅 mfd company id(0x5904/0x5984/0x5902/0x6982/0x07D0/0x0259)【B】;**无设备名/MAC 白名单校验**。
3. 是否检查 name/MAC/厂商数据/Service UUID?→ 只检查**厂商数据**(beacon 分支额外检查 0x01A2 service UUID)【B】。
4. **如何连接?** `connectGatt(autoConnect=false, TRANSPORT_LE)`,retry 3,超时 8-16s,发现服务后注册 notify 再 requestMtu(246)【B】。
5. 自动重连?→ 上层有 reconnect 逻辑(字符串 "Waiting to reconnect"),blelib 层 connectRetry=3【B】。
6. requestMtu?→ 是,246(P4)【B】。
7. notify?→ 是,char 00000002 + CCCD 2902【B】。
8. 使用哪些 characteristic?→ 见 gatt.md。
