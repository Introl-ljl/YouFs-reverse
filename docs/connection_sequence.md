# connection_sequence.md — 连接时序还原(阶段 4)

> 证据等级:全部【B】(APK 代码确认,file:line 见文内)。整条时序的动态验证【A】待 HCI 抓包。
> 以 **P4 delegate**(protocolType 413/400-405,现代涂鸦单 BLE 设备的默认)为主线。

## 与本仓库 CLI 的边界及 YouFs 2 状态

CLI 已实现一个有明确边界的离线 P4 legacy 状态机；这不表示 YouFs 2 实车已经验证。推荐操作顺序：

```powershell
python cli.py scan --all
python cli.py gatt <已确认的 YouFs 2 当前 BLE 地址>
python cli.py connect <地址> --profile-file work/<已核验配置>.json `
  --service-uuid <实测 service UUID> --write-uuid <实测 write UUID> --notify-uuid <实测 notify UUID>
```

profile 文件必须位于工作区 `work/` 下，至少提供目标 `mac`、CLI 接受的显式 factory selector
（当前 JSON 键为 `protocolType`）、`connectType`、
`securityMode`、`uuid`、`devId` 和 `localKey`；有效 `beaconKey` 可来自与设备身份匹配的可信 profile。
`protocolType` 键的值是传入 APK factory 对应值的第三方配置，不代表已证实的云端字段名；APK 实际
selector 为 `ControllerBean.deviceType`，来源可能是广播解析或 UUID 对应的 MMKV 缓存。当前没有
YouFs 2 的原版 selector 记录，P4 状态机不能先验套用到目标车。只有确认 factory selector 落在
400–405/413 后，才可按下列 P4 legacy 实现范围继续。若 DeviceInfoRep 标记 `needBeaconKey` 且配置了可解码 beaconKey时，使用 APK 的 marker `0x10` 分支；
缺失时严格复现 APK normal path 的 marker `0x00` fallback，cmd 1 仍加密为 flag5/key5。这是原版
行为边界，不表示 beaconKey 已验证或实车必然可配对。这些字段只能来自原版 App/云端设备元数据或目标车抓包，不得根据型号名或协议默认值
填造。`connect` 会扫描并保留匹配的 BLEDevice 对象，在同一进程中完成 GATT 连接、服务/特征校验、
notify 订阅后才发应用帧。`gatt` 是单独的只读诊断连接，不会复用其 BLEDevice 对象，也不发应用帧。

当前 app-layer 仅支持 `protocolType` 400–405/413 中明确配置的 P4 legacy 普通连接
（`connectType=0`、`securityMode=legacy`）：cmd 0 加密请求为 flag4/key4；解析设备信息后 cmd 1
为 flag5/key5。PairRep 的 bindStatus 0 或 2 才判定 READY。需要 beaconKey 时按 APK 布局附加
`0x10 + hexDecode(beaconKey) + 零填充至至少16字节 + 0x01`；如果没有可解码 key，原版 normal path 使用 `0x00 + 0x01`。
P1、P2、P4 新安全/证书或其他未覆盖分支均在协议帧发送前拒绝。`info` 只做 cmd 0 探针，cmd 0
成功不代表 pairing-ready；`status` 不发送 DP 查询，DP 控制也仍 fail closed。

2026-09-29，YouFs 2（地址尾号 `00:01`）重新开机后，已观察到 RANDOM 可连接广播，原生 WinRT
和 CLI 均取得完整 FD50 GATT 树，通知订阅也实车通过。此前 Bleak connect 超时的唯一原因仍不明确，
该 API 的超时范围包含服务发现，不能直接称为无线建链失败。
实际 `protocolType`、安全 flag、密钥路径与 cmd 0/cmd 1 应答仍为 **unverified**，本轮未发送应用帧。
参见 [实车连接排查报告](ble_diagnosis_20260929.md)。

## 时序图

```
UI/RN 面板
  │ ThingBleManager.connectBleDevice()          (ThingBleManager.java:715)
  ▼
01  AbsProtocolDelegate.connectDeviceAction     日志 "startConnectAction()"   (pbpdbqp.java:2424)
02  BleConnectAction: BleConnectOptions{retry=3, connectTimeout=10s,
    serviceDiscoverRetry=1, serviceDiscoverTimeout=3s}                       (ppbdppp.java:1324)
03  BleConnectWorker.openGatt: connectGatt(ctx, autoConnect=false, cb, TRANSPORT_LE)  (:1701-1713)
04  onConnectionStateChange(STATE_CONNECTED)     (:1353) ─ 300ms 后 ─▶ discoverServices (:1132)
05  onServicesDiscovered → setConnectStatus(19)  (:1641-1666)
06  BleNotifyAction: 对 char 00000002 setCharacteristicNotification(true)
    → writeDescriptor(0x2902, ENABLE_NOTIFICATION_VALUE)                     (BleNotifyRequest.java:39-52)
07  BleSetMtuAction: requestMtu(246)             (bpbpqdd.java:933-950)
08  onMtuChanged → mGattMTU = mtu-3              (pbpdbqp.java:2002-2003)
    日志 "onConnectSuccess() called with: mac=…, mtu=…" (:2002)
09  ★ 自动发送第一条包:cmd 0x0000 设备信息请求(fetchDeviceInfoRet)        (dpqbbpd.java:6100-6131)
      · 本仓库仅实现已确认的 P4 legacy:sn=0, code=0x0000, flag4/key4(AES-CBC)
      · → Packer 分帧 → write char 00000001
10  收到设备信息应答(cmd 0, DeviceInfoRep)                                 (Ret.dataParse case 0)
    → 保存 srand / authKey / needBeaconKey                                   (pbpdbqp.java:7474-7478)
    日志 "superFetchDeviceInfoRetSuccess: security match" (:7501)
11  pairDevice(): 发 cmd 0x0001 配对请求                                      (dpqbbpd.java:6665-6850)
      · payload: uuid + loginKey + devId + [encryptedAuthKey] + …
      · 本仓库仅实现已确认的 P4 legacy:flag5/key5(AES-CBC);其他密钥分支拒绝发送
12  收到 PairRep(cmd 1 应答);App 判断成功/bindStatus 并进入 deviceConnectSuccess (pbpdbqp.java:2729)
    CLI 只接受解析出的 bindStatus 0 或 2 为 READY;其他状态保持失败
13  ── 协议就绪 ──  此后:DP 查询(code 3)、DP 下发(code 2)由面板按需触发
    连接流程本身不自动发 DP 查询(仅在设备页打开时上层调用)
14  设备可随时主动请求:时间同步(dr_code 0/1/9 → App 回 32785/32786/32788)  (dpqbbpd.java:6547-6575)
```

## 自动发送的初始化包(必须记录)

| # | 包 | 时机 | 内容 |
|---|---|---|---|
| 1 | cmd 0x0000 设备信息请求 | MTU 成功回调内,自动 | 按安全等级构建;CLI 仅支持 flag4/key4 的 P4 legacy 请求 |
| 2 | cmd 0x0001 配对请求 | 收到设备信息后自动 | uuid + loginKey(云端取) + devId + encryptedAuthKey |
| 3 | 时间同步应答(32785/32786) | 设备主动请求时自动 | 13 位毫秒时间戳 / 年月日时分秒星期 |

## 密钥派生与选择(详见 auth.md)

- securityFlag:`0`=明文,`2/5`=legacy,`12/15`=new security(pbpdbqp.java:3447-3462);CLI 不自动探测 flag
- fetchDeviceInfo 密钥索引:connectType==0 → **14**(new security)/11(需升级)/4(普通);否则 11/1(dpqbbpd.java:6100-6131)
- pair 密钥索引:**15/12/5/2**(dpqbbpd.java:6742-6765)

## P2(旧 delegate)差异

- GATT UUID 用 Telink 组:1910 / 2b11(write) / 2b10(notify)(bqdpddd.java:3169-3172)
- 分帧头同构(LEB128 varint + type<<4),cmd 同表(0x00 起步,bqdpddd.java:3261)
- P1 家族(100/101/102)走 BLEJniLib native 编解码,连接后第一包为设备信息请求(cmd 0,BLEJniLib.f() → getNormalRequestData(0))

## 失败/重试锚点(抓包时可对照的日志 tag)

- `thingble_AbsProtocolDelegate` / `thingble_P4SecurityProtocolDelegate` / `thingble_BleConnectAction` / `thingble_ConnectImpl` / `thingble_ConnectManager`("matchScanResultAndTask()")
- GattCode:201=发现服务失败,203=notify 失败,210=连接/MTU 超时,212=设备信息错误,213=版本不支持(errors.md)
