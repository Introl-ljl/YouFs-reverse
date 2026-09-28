# ota.md — OTA 静态分析(阶段 13)

> ⚠️ **DO NOT EXECUTE — 本文档仅为静态分析记录。禁止对车辆执行任何 OTA 操作。**
> 用户安全约束:不刷固件、不执行 OTA、不动 MCU Flash。本仓库客户端不实现任何 OTA 命令发送。

## 通道结构(静态确认【B】)

两条 BLE OTA 路径并存:

### A. 经典协议 OTA(BLEJniLib,cmd 11-15)

| cmd | 函数 | 用途 | 证据 |
|---|---|---|---|
| 11 | `BLEJniLib.n(data)` | OTA 请求/索引(data 补零至 12B 对齐) | BLEJniLib.java:761-764 |
| 12 | `BLEJniLib.t()` | OTA 传输块请求 | BLEJniLib.java:988-999 |
| 13 | `BLEJniLib.m(buf,len)` | OTA 数据块 | BLEJniLib.java:726 |
| 14 | `BLEJniLib.k(buf)` | ? | BLEJniLib.java:684 |
| 15 | `BLEJniLib.l()` | OTA 结束 | BLEJniLib.java:690 |
| — | `crc4otaPackage(data,len)` | OTA 包 CRC = CRC-16/MODBUS | libBleLib.so Thing_OTACRC |
| — | `BLEJniLib.u(i1,i2,i3)` | 构造 `{0xAA,0x55,0xFF,0x00}+3×4B` + CRC16-MODBUS 的 OTA 包头 | BLEJniLib.java:1001-1037 |

### B. v2 OTA(ThingOtaDataPacket/Receiver + blelib channel)

- 走 blelib/channel 的 CTR/ACK/数据帧大数据通道(protocol.md §4),带 CRC16-ARC 末帧校验 + ACK 状态机(SYNC 重传)。
- 文件断点续传:设备回 `OTAFileRep{alreadyLength, alreadyCRC32}`,App 用 CRC-32 校验已传前缀(pdqqdpq.java)。
- cmd 112-115 / 128-132:FileTransferInfo/Offset/Data(v2 文件传输,可承载固件)。

## 云侧流程(静态可见)

- 云 API 提供固件信息(版本检查/下载 URL 在云端返回,APK 内无硬编码 OTA URL——assets/代码均未检出)。
- 升级入口:`com.thingclips.smart.ota.api.BleOtaService → BleOtaServiceImpl`(assets/module_app.json serviceMap)。
- 面板触发(设备详情页"检查固件更新"单元格,assets/configList.json)。
- 升级 characteristic:与控制共用(FD50/0001/0002 或 Telink 组),无独立 DFU service(无 Nordic DFU UUID)。
- 固件文件扩展名/格式:APK 内未检出(云端下发)。

## 结论

- OTA 协议本身完全可静态还原(表如上),但**本任务明确不实现、不执行**。
- 客户端 `youfs` 库不包含任何 cmd 11-15 / 112-115 构造函数;`commands.py` 显式排除。
