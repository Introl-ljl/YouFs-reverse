# auth.md — 鉴权与加密(阶段 8)

> 结论:**BLE 链路存在应用层鉴权与加密**(涂鸦通用机制)【B】。但**没有静态可提取的固定 key**——
> 会话密钥由设备随机数 + 云端下发的账号密钥派生,见下文。

## 1. 是否有鉴权?——有,两级

1. **连接级**:每次 BLE 连接后,App 自动交换 `cmd 0 设备信息`(取设备随机数 srand、能力)→ `cmd 1 配对`(提交身份)。
   配对成功前,协议不就绪(`deviceConnectSuccess`,pbpdbqp.java:2729)。
2. **帧级**:flag=0 明文帧之外,所有帧用 AES-128-CBC 加密,密钥按 securityFlag 从 16 个密钥槽选择(pbpdbqp.java:3447-3462)。

## 2. 密钥来源【B】

| 材料 | 来源 | 说明 |
|---|---|---|
| `srand`(设备随机数) | 设备,cmd 0 应答携带(DeviceInfoRep.java:29-33) | 每次连接刷新 → **会话密钥每次连接都变** |
| `loginKey` / `localKey` | **云端**(激活/绑定时下发) | DeviceBean 字段;等价载体 `TargetDeviceBean.localKey`(TargetDeviceBean.java:17) |
| `secretKey` / `loginKeyComplete` | 云端(new security) | 同上 |
| `encryptedAuthKey` | 云端 API `m.thing.device.auth.key.get` v3.0(pqdppqd.java:1035) | hex 解码后参与派生(bddqpdp.bdpdqbp=hexDecode) |

**与 MAC/SN 无关**,与账号-设备绑定关系绑定。**无法从 APK 静态提取**——这是设计使然。

## 3. 密钥派生公式(P4 delegate,纯 Java 可还原)【B】

全部基于 MD5(`ppbpqqq.pdqppqb` = MessageDigest MD5,ppbpqqq.java:120;`bddqpdp` = bytes/hex 工具):

```
key2  = MD5( MD5(secret)      + srand )          (dpqbbpd.java:4210-4224)
key5  = MD5( loginKey.bytes   + srand )          (dpqbbpd.java:4283-4322)  ← legacy 会话密钥
key12 = MD5( hexDecode(encryptedAuthKey) + srand )  (dpqbbpd.java:3980-3993)
key14 = MD5( loginKeyComplete + secretKey 的 ASCII ) (dpqbbpd.java:4042-4100)
key15 = MD5( MD5(输入)        + srand )          (dpqbbpd.java:4102-4112)  ← new security 会话密钥
```

securityFlag → 密钥槽映射(pbpdbqp.java:3447-3462):

| flag | 含义 | 使用密钥 |
|---|---|---|
| 0 | 明文 | 无 |
| 2 / 5 | legacy | key5 系(loginKey 派生) |
| 12 / 15 | new security | key14/key15 系(云端签发材料) |

命令级选择:设备信息请求按 connectType 用 idx **14/11/4/1**(dpqbbpd.java:6100-6131);配对用 **15/12/5/2**(dpqbbpd.java:6742-6765)。

## 4. 经典协议(P1 家族)的会话密钥【B】

`BLEJniLib.madeSessionKey(in, len, out)`(native,libBleLib.so 已反汇编):

```
out[i] = crc8_table[in[i]]              (i = 0..15;len<16 时尾部 out[i] = crc8_table[(in[i-len]+in[i-len+1])&0xff])
```

即 16 字节密钥 = 输入逐字节过 CRC-8(poly 0x07)表的 S-box 替换。输入由 Java 侧组装(P1Normal bbpqqpq.java:774 调用,传 12 字节)。**P1 配对包**(cmd 1/5)payload 经 AES-ECB 用该密钥加密(`qqddbpb` = AESUtil,BLEJniLib.i()/c())。

## 5. new security 的证书双向认证【B】

P4 支持三步证书认证(可选,`connectType` 相关):
- cmd 21 SecurityAuth1:发服务器证书,设备回 6B deviceRandom(SecurityAuth1Rep.java:15-19)
- cmd 22 SecurityAuth2:发服务端加密数据(dpqbbpd.java:5720)
- cmd 23 SecurityAuth3:发服务器随机数(dpqbbpd.java:5816)

## 6. packet 是否加密?——默认是

- 明文(flag=0)仅出现在:**配对前的设备信息请求**(部分安全等级)与调试路径。
- 配对完成后,DP 下发/查询/上报全部走 flag≠0 的 AES-CBC 帧。
- 上层帧加密/securityFlag 依 P4 delegate 的安全状态与设备应答决定；delegate factory selector 在原版连接入口中为 `ControllerBean.deviceType`，不能预设来自云端同名字段。

## 7. 第三方客户端的实现含义(重要)

| 场景 | 可行性 |
|---|---|
| 扫描/识别 | ✔ 无需密钥 |
| 连接 + notify | ✔ 无需密钥；GATT profile 仍需按设备实测 |
| 收设备信息应答(cmd 0) | P4 legacy 仅支持 flag4/key4 加密路径；需经证据确认配置。其他组合未实现并拒绝发送 |
| cmd 1 pairing-ready | ✔ 离线状态机仅支持显式 P4 legacy flag5/key5，并验证 PairRep bindStatus 0/2 |
| **DP 控制(灯光等)** | 当前仍 fail closed；READY 不代表 DP query/write 已实现 |
| 解析上报 DP | 被动接收已实现；加密 DP 仍需已验证的会话 key/flag 与 DP schema |

获取 localKey 的合规途径(车已在用户涂鸦账号下):涂鸦 IoT 平台设备详情 / `tuya-cli` / 面板数据导出。
当前 `connect` 状态机只允许显式确认的 P4 legacy 普通连接（`protocolType` 400–405/413、
`connectType=0`、`securityMode=legacy`）。它从 profile 中的 localKey 取 APK 使用的前六个字符作为
loginKey，按 flag4/key4 完成 cmd 0，再以设备 `srand` 派生 flag5/key5 发送 cmd 1。若 DeviceInfoRep
要求 beaconKey 且 profile 提供了可解码值，则按 APK marker `0x10` 分支附加；缺失时复现 APK normal
path 的 marker `0x00` fallback。该缺省行为仍加密 cmd 1，但不保证设备接受配对。P1、P2、新安全/证书
和未知分支均拒绝发送应用帧。Profile 文件只允许存放在工作区 `work/` 下；不要把密钥复制到文档、
日志或版本控制。

## 8. 未决项

- key14 中 `loginKeyComplete` 的确切字节序列化(loginKeyComplete+secretKey 是否加 null 分隔):代码可读但未逐行复核 → 复用前用抓包验证。
- 设备端证书认证(cmd 21-23)在 YouFs 滑板车固件上是否启用:UNKNOWN(抓包确认)。
- P2 delegate 的派生是否与 P4 完全一致(bqdpddd.java 对应段未逐行核对):推断一致。
