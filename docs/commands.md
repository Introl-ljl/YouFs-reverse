# commands.md — 命令表(阶段 9)

> 命令号本身【B】(APK 代码确认)。**滑板车业务数字 DP ID 全部 UNKNOWN**——面板由涂鸦云端
> 下发,不在原始 APK 内(`scooter/滑板` 在 dex+assets 全树 0 命中)。MuMu 下载的面板资源给出部分语义代码名,
> 但抓包差分(阶段 14)后才能把它们对应到数字 ID,见 `emulator_validation.md`。
> 安全约束:电机相关命令永不发送;未知命令只分析。

## 命令帧格式

app→device:`[sn 4B][sn_ack 4B][code 2B BE][len 2B BE][data][crc16-MODBUS 2B BE]`(外层 AES-CBC,见 protocol.md)

## 命令号总表(涂鸦通用,classes3 确认)

主证据:`Ret.dataParse()` 分发(Ret.java:29-460)+ `BLEJniLib`(经典路径)+ 命令名映射 `bddqqbp.java`(Coder):317-414。

### App → 设备

| Code | 名称 | Payload | 应答 | 证据 |
|---|---|---|---|---|
| 0x0000 | DEVICE_INFO 请求(连接后自动) | (安全等级相关) | cmd 0 DeviceInfoRep(srand/authKey/能力) | dpqbbpd.java:6100;BLEJniLib.f() |
| 0x0001 | PAIR 配对 | uuid+loginKey+devId+encryptedAuthKey | cmd 1 PairRep(绑定态) | dpqbbpd.java:6665-6850 |
| 0x0002 | **DP 下发**(控制) | DP TLV 序列 | 0x8001 上报/应答 | bbpqqpq.java:2145-2160;BLEJniLib.i() |
| 0x0003 | **DP/状态查询**(P4 queryDps) | dpId 字节数组(空=全查) | 0x8004 StatusDpsReport | dpqbbpd.java:6999-7010 |
| 0x0004 | DP 查询(P1 经典路径) | 无 | DP 应答 | BLEJniLib.g() → getNormalRequestData(4) |
| 0x0005 | PAIR(loginKey,经典) | loginKey | NormalResponseBean | BLEJniLib.r() |
| 0x0006 | UNBIND/RESET 解绑 | 无 | NormalResponse | BLEJniLib.s();Ret case 5/6 |
| 0x000A | 扩展传输(时间同步等) | [subType][data] | ExtTypeResponseBean | BLEJniLib.d();subType 130/133 |
| 21/22/23 | SecurityAuth 1/2/3(证书认证) | 证书/密文/随机数 | SecurityAuth*Rep | dpqbbpd.java:5586/5720/5816 |
| 0x0B-0x0F | OTA v2 | 分片 | OTA2*Bean | BLEJniLib.k/l/m/n |
| 32785/32786/32787/32788 | 时间同步应答 | 毫秒时间戳/年月日时分秒星期 | — | dpqbbpd.java:5265-5280 |

### 设备 → App(上报)

| Code | 名称 | Payload 头 | 证据 |
|---|---|---|---|
| 0x8001 (32769) | **DP 上报**(FUN_RECEIVE_DP) | pv4: [ver][sn 4B][b_type][flag] + TLV | Ret.java:170;DpsReportRep.java:106 |
| 0x8004 (32772) | **状态 DP 上报** | [rsnh][rshl][flag] + TLV | Ret.java:202;StatusDpsReportRep.java:20 |
| 0x8003 / 0x8005 / 0x8006 | 带时间 DP 上报 | 时间戳 + TLV | Ret.java:1759-1762 |
| 0x001E (30) | 设备网络状态 | DeviceNetStatusRep | Ret.java:408 |

App 收到 0x8001 后自动回 ACK(32769, sn, success)(bqdpddd.java:1610-1616)。

## 滑板车业务命令 → DP 映射(阶段 9 要求逐项)

**数字 DP ID 状态:UNKNOWN × 全部。** 以下为捕获计划(每次只改一个变量,间隔 ≥5s):

| 功能 | 计划动作 | 预期证据 | 当前 |
|---|---|---|---|
| GET STATUS | 连接后等 0x8004 / 发 code 3 空查询 | 0x8004 TLV 差分 | UNKNOWN |
| GET VERSION | cmd 0 应答 DeviceInfoRep(mcuVersion 字段) | 静态已知结构 | 【B】格式 / 【E】内容 |
| LIGHT ON/OFF | 面板开关灯 → 0x0002 单 DP | bool DP id=X 值 1/0 | UNKNOWN(X 待定) |
| LOCK/UNLOCK | 同上 | bool 或 enum | UNKNOWN |
| GEAR 1/2/3 | 同上 | enum DP | UNKNOWN |
| CRUISE ON/OFF | 同上 | bool | UNKNOWN |
| ZERO START | 同上 | bool | UNKNOWN |
| REGEN LOW/MID/HIGH | 同上 | enum | UNKNOWN |
| SPEED LIMIT GET | code 3 查询对应 value DP | 4B value | UNKNOWN |
| SPEED LIMIT SET | 0x0002 value DP | 0x8001 确认 | UNKNOWN |

DP TLV 编码(已确认【B】):`[dpId][type][len][value]`;bool/enum=1B,value=4B 小端,string=UTF-8。

## 发送约束(合规)

1. 仅发送:code 0(设备信息)、code 3(查询)、**灯光 DP**(id 经抓包确认后)。
2. 不发送:0x0001 配对/0x0006 解绑(影响账号绑定)、全部电机相关 DP、0x0B-0x0F OTA、未知 code。
3. 每次发送只改变一个变量,间隔 ≥5s,全程记录。
