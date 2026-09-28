# models.md — 型号/协议分支判断(阶段 12)

> 全部【B】(代码确认)。Delegate factory 按 `ControllerBean.deviceType` 的整数选分支；**它不能
> 简化成已证实的“云端 DeviceBean.protocolType”**。该整数的来源随连接入口和广播解析分支变化。

## 分支机制

App 内没有任何 `if model == Z1/M1...` 式的车辆型号分支(`scooter/滑板/YouFs` 全树 0 命中,
无 pid 白名单)。静态 DEX 可确认 factory 对传入整数的映射；`dddqqdd(int)` 接收该整数并调用
`bqdbbqq.bdpdqbp(int)`。创建 delegate 的调用点为 `pbddddb.java:4765`，传入
`ControllerBean.deviceType`。不同来源的整数可能不是同一个云端字段：

| selector 值 | delegate(原名) | GATT UUID 组 | 会话密钥 | 证据 |
|---|---|---|---|---|
| 413, 400-405 | P4SecurityProtocolDelegate | FD50/0001/0002 | key12/14/15(new security) | bqdbbqq.java:49-85; dpqbbpd.java |
| 其余 | P2SecurityProtocolDelegate | 1910/2b11/2b10 | 同 P4 体系 | bqdpddd.java:3169 |
| 102 | P1SecurityProtocolDelegate | Telink 组 | native madeSessionKey | bbqpbqd |
| 101 | P1WiFiProtocolDelegate | Telink 组 | 0x55AA 配网专用 | qqbppqp.java:232 |
| 100 | P1NormalProtocolDelegate | Telink 组 | native madeSessionKey | bbpqqpq.java:1570-1572 |

**来源证据与边界**:

- `bdpdqpb.java:2889+` 云设备匹配扫描结果时,用 `BLEScanDevBean.deviceType` 填充
  `TargetDeviceBean.deviceType`;随后 `ControllerBean` 接收该字段(`bdpdqpb.java:5766`),并在
  `pbddddb.java:4765` 作为 factory selector。
- 直接连接分支 `dbddpbp.java:485-502` 从 `DataKV` 读取 UUID 对应的记录,格式为
  `<integer>#<address>#<flag>`;`DataKV.java` 使用 MMKV 命名空间 `ble_business_data`。记录中的整数
  成为 `TargetDeviceBean.deviceType`。该本地值可能与 scan 分类不同。
- `dbddpbp.java:36-48` 把 SDK `DeviceBean` 的 uuid/devId/localKey/secKey/productId/mac 映射到
  `TargetDeviceBean`,没有在此处复制一个名为 `protocolType` 的字段。当前工作区的设备列表与解密云
  响应只确认 devId/name/productId/localKey/mac/uuid/secKey 等字段;没有目标车的 protocolType、
  connectType、安全模式值。
- 扫描解析分支也会产生不同 selector。标准 parser `pbbqdqp.java:21-108` 计算广播类别 200/300,
  但写入的 `deviceType` 是 101,因此 factory 选 P1 WiFi。另一个 parser 分支
  `pbbqdqp.java:1441-1461` 写入 `deviceType=200`,按 factory 规则落到默认 P2。其余 parser 分支可写入
  100/102 等。故只看到设备名或“Tuya BLE”不足以选协议。

YouFs 2 在本轮没有可复现的目标广播字节或原版连接日志,不能判定它走哪条 parser/连接入口,也不能
断言它是 P4。`connect --protocol-type`/profile 中的整数必须被看作**显式提供给第三方客户端的
factory selector 假设值**,不是已验证的云字段映射。只有从该目标原版 App 连接记录或目标专属云/本地
元数据确认了选择器值后,才可使用当前 P4-only 状态机;否则保持 fail closed。

## 是否按固件版本分支?

是——只在**能力协商**层面:设备信息应答(cmd 0)携带 p_ver/t_ver 与安全等级,决定密钥索引
(14/11/4/1)与是否走证书认证(cmd 21-23)(dpqbbpd.java:6100-6131, pbpdbqp.java:7501
"security match")。DP 语义不分叉。

## 是否按 BLE device name 分支?

**否**【B】:全树无名字前缀校验(仅 "key" UUID 前缀特判,pbbqdqp.java:84-90)。

## 对 YouFs 滑板车的含义

- 单一产品线无需型号分支;Z1/M1/M2 若同用涂鸦模块,协议栈相同,**差异只在 DP 表(云端)**。
- 跨车型兼容的第三方客户端应把 DP 映射表做成 per-product 配置(dp_map.json)。
- 实际 protocolType:UNKNOWN → 抓包时以"连接后第一包是否带 AES flag"即可判定 P4/P2/P1 家族
  (P4: flag/iv 帧;P1: trsmitr 包 [len][type][data] + native 编解码)。
