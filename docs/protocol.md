# protocol.md — 数据帧格式(阶段 5/6)

> 证据等级:除特别标注外均【B】(APK 代码确认)。整个协议为涂鸦 BLE 通用协议,非 YouFs 私有。
> 三层结构:GATT 分帧层(trsmitr) → 应用帧层(AES/sn/cmd) → DP 载荷层(TLV)。

## 0. 总览

```
BluetoothGatt write/notify (≤MTU 字节)
  └─ [trsmitr 分帧层]  [pkgIdx varint][totalLen varint 首包][type<<4 首包][payload…]
       └─ [应用帧层]   [flag 1B][iv 16B 非零 flag][AES-CBC 密文]
            └─ 明文体  [sn 4B][sn_ack 4B][code 2B][len 2B][data lenB][crc16 2B]
                 └─ [DP 载荷层]  [dpId 1B][type 1B][len 1B][value…] ×N
```

## 1. trsmitr GATT 分帧层【B】

两处独立实现,线格式一致:
- Java:`bluetooth/pbqbqbq.java`(Packer) `bdpdqbp(type,data,len,mtu)` :47-70(P4/P2 路径)
- Native:`libBleLib.so` `trsmitr_send_pkg_encode`(P1 经典路径)

```
每个 BLE 写入包(≤ chunkSize,默认 20,最大 mtu-3):
┌──────────────┬─────────────────────────┬───────────┬────────────┐
│ pkgIdx       │ totalLen(仅首包)        │ hdr(仅首包)│ payload    │
│ LEB128 1-4B  │ LEB128 1-4B             │ 1B        │ 0..19B     │
└──────────────┴─────────────────────────┴───────────┴────────────┘
pkgIdx : 包序号,0 起,LEB128(7bit 变长,bit7=后续字节)
totalLen: 帧总长(纯载荷字节数),LEB128
hdr    : (type<<4) | seq;type=2 表示普通请求(Packer 固定 0x20);
         经典路径 cmd=高 4 位,seq=低 4 位(0-15 循环,libBleLib.so 全局计数)
chunk  : min(剩余载荷, chunkSize - 头长);首包头 3+字节
```

接收重组(`parseDataRecived`/libBleLib.so):pkgIdx 不连续→丢包(状态 4);重复→3;收满 totalLen→完整(状态 0),上抛 `[cmd 1B][总长低8位 1B][payload]`。

## 2. 应用帧层【B】

发送:`X2Request.pack`(ppqbqbb.java:1378-1388)+ `ThingDataPacket`(ppbpqqq.java:197-211, 535-562)
接收:`Ret.parse`(ble/core/packet/bean/Ret.java:432-480,529-535)

```
空中应用帧:
┌──────┬──────────┬──────────────────────────────────┐
│ flag │ iv       │ AES-128-CBC ciphertext            │
│ 1B   │ 16B*     │                                   │
└──────┴──────────┴──────────────────────────────────┘
flag = 0 → 明文(无 iv 字段,直接跟明文体)
flag ≠ 0 → securityFlag,同时是密钥选择码(见 auth.md)
* 仅 flag≠0 时存在;iv = 16 字节 SecureRandom(ppbpqqq.java:52-58)

AES: "AES/CBC/NoPadding"(SecurityUtil/bpdpppq.java:21,173)
明文体先零填充至 16 倍数(ppbpqqq.java:535-548)——非 PKCS#7

明文体(解密后):
┌──────┬─────────┬────────┬────────┬──────────┬──────────┐
│ sn   │ sn_ack  │ code   │ len    │ data     │ crc16    │
│ 4B BE│ 4B BE   │ 2B BE  │ 2B BE  │ len B    │ 2B BE    │
└──────┴─────────┴────────┴────────┴──────────┴──────────┘
crc16 = CRC-16/MODBUS(sn+sn_ack+code+len+data)   (qdqbdbd.bdpdqbp(byte[]))
```

- sn:4 字节序号(BE),应答包 sn_ack 回填请求 sn(Ret.java:529-535)
- code:命令号,2 字节 BE;设备→App 的上报命令置高位(0x8001 等)
- 发送构造:`pdqppqb(code 2B)/qddqppb(sn 4B)` 均为大端(bddqpdp.java:1387-1389)

## 3. DP 载荷层【B】

构造:`getCommandRequestData`(libBleLib.so KLV)/ `DpsParseHelper.java`;解析:`BLEDpBean`/`DpsReportRep.java:106-116`

```
[dpId 1B][dpType 1B][dpLen 1B][dpValue dpLen B] × N
```

| dpType | 语义 | 长度 | 值编码 |
|---|---|---|---|
| 0 | raw | 任意 | 原始字节 |
| 1 | bool | 1 | 0x00/0x01 |
| 2 | value(整数) | 4 | 发送前整体字节反转 = 小端(Java 侧先组大端再 `reversalByteArray()`,bbpqqpq.java:2160-2163)→ **线上小端** |
| 3 | string | 任意 | UTF-8 |
| 4 | enum | 1 | 1 字节 |
| 5 | bitmap | ≤4 | 小端 |

DP 上报帧(设备→App)存在两种头部(DpsReportRep.java:106-116):
- pv=4(新固件):`[ver 1B][sn 4B][b_type 1B(bit7=needAck 取反,低4位=type)][flag 1B]` + TLV 循环
- 旧格式:直接 TLV 循环
- 状态 DP 上报(cmd 0x8004):前 3B `rsnh/rshl/flag` + TLV(StatusDpsReportRep.java:20-50)

## 4. OTA 大数据通道(仅 OTA/文件传输使用)【B】

`blelib/channel`(CTR/ACK/DataPacket,见 ble.md)——常规 DP 请求**不经过**此层,只有
`ThingOtaDataPacket/bqqppbp` 和 `ThingOtaDataReceiver/pdqqdpq`(OTA 数据,CRC32 断点续传)使用。

```
CTR 帧  : [0x0000][type=0][cmd=0][frameCount 2B BE]
ACK 帧  : [0x0000][type=1][cmd=0][status 2B BE][seq 2B BE]
数据帧  : [seq 2B BE][payload ≤18B];整帧流末尾附 CRC-16/ARC(payload 全体,LE 2B)
```

## 5. 端序/编码规则汇总【B】

| 字段 | 端序 | 证据 |
|---|---|---|
| trsmitr varint 头 | LEB128(小端变长) | libBleLib.so / Packer.java |
| v2 帧 sn/sn_ack/code/len | **大端** | Ret.java:529-535 ByteBuffer + bddqpdp BE 助手 |
| v2 帧 crc16 | **大端**字节输出 | bddqpdp.pdqppqb(int) = {hi,lo}(bddqpdp.java:1387) |
| 信道层帧 sn/frameCount | 大端 | Packet.java ByteBuffer 默认 BE |
| 信道层 CRC16 | **小端**输出 | ByteUtils.fromShort = {lo,hi}(ByteUtils.java:821-825) |
| DP value(type 2) | **小端** | bbpqqpq.java:2160-2163 反转 |
| 命令号(code) | 大端 2B | 同上 Ret |

## 6. 协议选择(哪套线格式实际在用)

| APK factory selector (来源见 models.md) | delegate | GATT UUID 组 | 分帧 | 应用帧 |
|---|---|---|---|---|
| 413 / 400-405 | P4Security | FD50/0001/0002 | Packer trsmitr | flag/iv + AES-CBC(本文档) |
| 其余 | P2Security | 1910/2b11/2b10 | 同构 | 同构 |
| 100/101/102 | P1 Normal/WiFi/Sec | Telink 组 | libBleLib trsmitr | 经典包([len][type][data],会话密钥 madeSessionKey) |

YouFs 滑板车实际值:UNKNOWN(云端 DeviceBean 下发,静态不可见;2023+ 涂鸦模块默认 P4)。
