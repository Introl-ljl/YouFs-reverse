# checksum.md — 校验算法(阶段 7)

> 全部【B】:算法从代码/反汇编逐字节还原,并给出可执行 Python 实现。抓包验证【A】待做。
> 独立验证脚本:`tests/test_checksum.py`(安装 youfs 包后可运行)。

App 中共发现 **4 种**校验,分属不同层:

## 1. CRC-8(poly 0x07)— 经典协议帧尾 / 会话密钥 S-box【B】

来源:`libBleLib.so` `init_crc8`(NEON 向量化,经指令级模拟还原全表,poly=0x07、init=0x00、MSB-first、无反射无终异或 = CRC-8/SMBUS 参数)。已知答案 `"123456789" → 0xF4` 验证通过。

```python
def crc8(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc
```

用途:① 经典(P1)协议包尾 CRC(与 0x55/UART 协议同参);② `madeSessionKey` 的 S-box(见 auth.md)。

## 2. CRC-16/ARC — v2 信道层(CTR/ACK/Data)末帧校验【B】

来源:`blelib/channel/CRC16.java:11-17`(查表,init=0)+ `ByteUtils.fromShort`(LE 输出)。等价逐位实现:

```python
def crc16_arc(data: bytes) -> int:      # 输出 2 字节小端: [lo, hi]
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc & 0xFFFF                 # 写入: bytes([crc & 0xFF, crc >> 8])
```

用途:OTA 大数据通道(blelib/channel)整帧流尾部,`Channel.checkCRC`(:1744-1748)。

## 3. CRC-16/MODBUS — v2 应用帧校验【B】

来源:`bluetooth/qdqbdbd.java`(CRCUtils)`bdpdqbp(byte[])`:逐位反射 0xA001、init=**0xFFFF**、输出经 `bddqpdp.pdqppqb(int)` = `{hi, lo}` **大端**。native 侧 `crc4otaPackage`/`Thing_OTACRC` 相同参数(.rodata 半字表 {0x0000,0xA001}),已知答案 `"123456789" → 0x4B37`。

```python
def crc16_modbus(data: bytes) -> int:   # 输出 2 字节大端: [hi, lo]
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc & 0xFFFF                 # 写入: bytes([crc >> 8, crc & 0xFF])
```

用途:v2 应用帧明文体尾部(Ret.parse CRC 校验,Ret.java:537-541)+ OTA 包(`BLEJniLib.u()`)。

## 4. CRC-16/MODBUS 逐位 MSB 变体(qdqbdbd 2 参重载)【B,用途待查】

`qdqbdbd.bdpdqbp(byte[], int)`:MSB-first、init=0、XOR-before-shift 常量 0x8380、返回**单字节** `(s>>8)`。调用方未在反编译树中定位(可能为遗留代码)。**不用于** v2 帧校验(v2 用第 3 种,Ret.java:537 直接证据)。

## 5. CRC-32 — OTA 文件断点续传【B】

`blelib/channel/CRC32.java`:标准 zlib CRC-32。`ThingOtaDataReceiver` 用它校验已传文件前缀(`getFileAccessIndex`,pdqqdpq.java)。

## 6. 累加和 — P1 WiFi 配网帧【B,仅 0x55AA 配网】

`P1WiFiProtocol`(qqbppqp.java:649-661):帧 `{0x55,0xAA}[ver][cmd][len][data]` 尾部 1 字节 = 前 N 字节和 mod 256。仅用于 WiFi 配网通道(协议 101),BLE 车控不走。

## 未发现

- HMAC / SHA 系列用于 BLE 帧校验:未发现(密钥派生用 MD5,见 auth.md)
- 补码/反码校验:未发现

## 快速核对表(Phase 14 抓包用)

| 抓到位置 | 期望校验 |
|---|---|
| DP 请求/应答(v2,P4)最后 2 字节(大端) | crc16_modbus |
| OTA 数据流末尾 2 字节(小端) | crc16_arc |
| 经典协议包最后 1 字节 | crc8(poly 0x07) |
| 0x55AA 配网帧最后 1 字节 | sum mod 256 |
