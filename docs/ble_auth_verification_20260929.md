# YouFs 2 BLE 应用认证与控制验证报告 — 2026-09-29(第二轮)

> 交付形态:分析报告 + 已实车验证的第三方客户端(非补丁)。
> 全部"observed"结论均来自本轮实车日志(`work/ble_control_test*.log`、`work/ble_ready_observe*.log`、
> `work/ble_cmd0_raw_probe.log`),静态结论来自反编译树(file:line)。
> 密钥值不入库;profile 在 `work/youfs2_profile.json`(git 忽略的 work/ 内)。

## 0. 一句话结论

**GATT → 应用认证(cmd0/cmd1)→ 保活 → 实时状态流 → DP 控制(大灯/模式)→ 断开重连**
全链路已在实车 `C0:DE:00:00:00:01`(devId `devid-redacted-00001`)打通。
用户实测:仪表蓝牙图标在应用认证成功后亮起;大灯命令被车辆状态流回显 dp8=01;
模式切换被接受且跨会话持久化(dp15=01 ECO)。

## 1. 已确认的基础条件(沿用上轮 + 本轮)

| 项 | 结果 | 证据 |
|---|---|---|
| 目标车 | C0:DE:00:00:00:01(RANDOM),FD50/0001/0002/0003,MTU 247 | 上轮报告 + 本轮全部连接日志 |
| 凭据 | devId `devid-redacted-00001`、uuid `0123456789abcdef`(16 字符)、localKey 16 字符 ASCII、secKey 16 字符 ASCII | `work/youfs_devices.json` + 解密抓包 `work/decrypted_m_life_my_group_device_list.json`(同一绑定关系) |
| cmd0 应答内含 devId | 应答帧(AES-加密+CRC 通过)内 devId 与云端一致,bleMac 反序一致 | `work/ble_cmd0_raw_probe.log` 手工解密 |

## 2. 协议分支(observed,实车+代码)

**该车的广播走 Android SDK 主解析器 `pbbqdqp`(ThingBeaconParser)3 参 `pdqppqb` 分支:**

1. 合并扫描记录含厂商数据(AD 0xFF),前 2 字节 LE = **0x07D0(2000)** → company 2000 分支
   (`pbbqdqp.java:194-238`,jadx badcode 版)。
2. `bppdpdq(record)` 检查 16 位 UUID 列表 AD 的 BigInteger 值 == 418;本车为 `50 fd`(0x50FD
   = 20733)→ false → 走 3 参 `pdqppqb(bean, mfg, record)`(`pbbqdqp.java:1031+`,badcode)。
3. 实车字节 `d007 00 00 01 00 5e49…37`(22B)+ 服务数据 `50fd 49 0c 00 08 0b10bb70c00a47fb`:
   - mfg[2]=0x00(类型 0)→ z=false;mfg[3..4]=[0x00,0x01],bit0=1 → **deviceType=400、category=100**;
   - 剩余 16B → devUuId 源;服务数据首字节 0x49 高半字节 → **protocolVersion=4**;bit3 → isBind=true。
4. factory `bqdbbqq.bdpdqbp(int)`(smali 级):**400 → dpqbbpd = P4SecurityProtocolDelegate**,
   GATT = FD50 + char 0001(write)/0002(notify),与本车实测 GATT 树完全一致
   (`dpqbbpd.java` assembleConnectBuilder / addXRequest)。

**安全等级**:服务数据 byte1=0x0c → 置位 SUPPORT_SECURITY_SUPPORT(512)+ENABLE(1024)
(`SupportType.java`),`BleDeviceController.pppbppp(devId)`(pqppqpd.java)→ **ConnectOpt securityLevel=2 = 新安全**。
实车 cmd0 应答 flag2=0x06(support+enable)与 level=2 匹配(`checkSecurityUpdateMatch`)。

> 交接单原假设"P4 legacy flag4/key4"对这辆车**不成立**:legacy cmd0(flag4)实车发送后无应答
> (对照实验),新安全 cmd0(flag14)立即应答。

## 3. 凭据对应关系(observed)

| 材料 | 值/来源 | 用途 |
|---|---|---|
| loginKey | localKey 前 6 字符(`ConnectParam.setLocalKey`: substring(0,6)) | cmd1 字段、key4/key5 派生 |
| loginKeyComplete | 完整 localKey | **key14/key15 派生**、cmd1 尾部字段 |
| secretKey | 云端 secKey | key14/key15 派生、cmd1 尾部字段 |
| beaconKey | 不需要(DeviceInfoRep flag bit4=0) | cmd1 beacon marker=0x00 |
| encryptedAuthKey/authKey | 未使用(仅 key11/12 need-update 路径) | — |
| 绑定状态 | cmd0 应答 isBind=1;PairRep bindStatus=true | 只建会话,未改绑定 |

**派生公式(实测验证)**:
- `key14 = MD5(UTF-8(localKey + secKey))` — 字符串拼接后取 UTF-8,无分隔符、无内层哈希
  (`dpqbbpd.getSecretKey14`);**auth.md §3 的 key15 公式有误,以本行为准**。
- `key15 = MD5(UTF-8(localKey + secKey) || srand)` — srand 为 cmd0 应答 6 字节
  (`getSecretKey15`,无内层 MD5)。
- legacy 分支(本车不适用):key4 = MD5(loginKey6)、key5 = MD5(loginKey6 || srand)。

## 4. 认证前 GATT 初始化时序(observed + 代码)

APK 时序(`connection_sequence.md` 主线,本轮逐条核对):
connect → 发现服务 → 订阅 char0002(CCCD)→ requestMtu(246)→ **mGattMTU = ATT_MTU-3**
(`pbpdbqp.connectSuccess`:477)→ 立即发 cmd0。
- char 000003 只在 `ThingBLESystemBondedScanner`(系统绑定/HID 路径)使用,**认证流程不读它**。
- 写特征:**带响应写**(XRequest.writeNoRsp 默认 false;仅 OTA 数据帧 setWriteNoRsp(true))
  (`BleConnectDispatcher`/`XRequest.java:41,51`)。本客户端 transport.send_frame 已改为 response=True。
- Windows 无 request_mtu 时直接用协商值 247-3=244,与 Android 等效(cmd0 data=244 BE)。

## 5. cmd0(observed,实车多次成功)

- 帧:sn=1(不是 0!`SnAckHolder` 每次 connectSuccess 重置后 incrementAndGet)、ack_sn=0、
  code=0x0000、data=**mGattMTU 2 字节 BE**、**flag=14、key14**。
- 实车应答 ~110ms:flag14 回显、sn=1、ack=1、**CRC-16/MODBUS(init 0xFFFF)2B BE 校验通过**。
- DeviceInfoRep 96 字节:devVer 4.7、**proto 4.7**、flag=0x05(v4NeedAuth=0、needBeaconKey=0)、
  **isBind=1**、srand 6B、authKey 前 16B 非 ASCII(proto≥33 → newAuthKey)、
  **flag2=0x06(support+enable)**、devId=devid-redacted-00001、mcu 0.0.0、
  after85: capability=000000、adrType=0、bleMac=01000000dec0。
- 帧尾填充:设备加密帧按**填充长度补尾**(观测 `02 02`),**非零填充**;APK parse 不拒收,
  我们的 parse_ret 已同步放宽(以 CRC 为完整性依据)。
- legacy flag4/key4 cmd0:发送成功但无应答(单变量对照)→ 该车不走 legacy。

## 6. cmd1(observed,实车 4+ 次成功,READY 达成)

- 帧序列:cmd0=sn1,cmd1=**sn2**(`SnAckHolder` 连续计数;不要复用!),ack_sn=0、code=0x0001、
  **flag=15、key15**(由**本次** cmd0 的 srand 派生)。
- 载荷(connectType=0, new security):uuid16(utf8,16 字符无需压缩)+ loginKey6 +
  devId22(NUL 补齐)+ beacon marker 0x00 + pair marker 0x01 + **loginKeyComplete16 +
  secretKey16 + verifyKey 位 4 字节 0**(flag15 路径恒为零,`dpqbbpd.pairDevice`)。
- 应答 PairRep(status 0/2 → bindStatus);实车返回 bind=true。
- **绑定安全**:cmd1 是 APK 每次连接已绑定设备的常规路径(`superFetchDeviceInfoRetSuccess` →
  `pairDevice`),仅证明既有绑定身份并建立会话;未解绑/未重绑(解绑是 cmd 5/20,未发送)。

## 7. 不需要补的分支

- P1/P2(native/Telink 组)、P4 need-update(key11/12)、证书认证(cmd 21-23,v4NeedAuth=0)、
  beaconKey 分支(needBeaconKey=0)——该车均不适用,已明确排除。
- cmd 5(`recoverDeviceStatus`):APK 有此接口但语义与 UnbindRep 相邻,**本客户端不发送**。

## 8. 承载层核对(observed + 代码,全部一致)

- trsmitr:varint(LEB128) idx + 首包 totalLen + `(type<<4)`;**app→device type 半字节=2**,
  **device→app 实测=4**(接收侧 APK 不检查,我们已放宽为仅记录)。
- 分片上限 = mGattMTU(244),非 20(`Packer.bdpdqbp`);接收侧要求 idx 严格递增(允许跳号)。
- 应用帧:[flag][iv16][AES-128-CBC/零填充];明文体 sn4+ack4+code2+len2 全 BE +
  CRC-16/MODBUS 2B BE(`qdqbdbd`,init=pqqdqpq.pbpdbqp=65535)。
- 应答密钥 = `getSecretKey(应答flag)`(PackReceiver→delegate 表 {1,2,4,5,11,12,14,15})。
- sn 规则:app 计数器跨 cmd0/cmd1/后续帧连续;**重复 sn 会被设备当重放丢弃**(实测教训);
  ack_sn:app 主动请求=0,应答设备请求=设备 sn。
- 离线测试向量:`work/protocol_selfcheck_20260929.py`(密钥掩码输出)+ `tests/`(149 通过)。

## 9. READY 之后(observed,实车)

- **PairRep 后 ~16ms 设备立即发 32785 时间同步请求(空载荷),必须立即应答**;
  应答 = 同 code 32785、ack_sn=设备 sn、data = 13 位 ASCII 毫秒 + 时区(0.01h 单位)2B BE。
  **不答 → 设备秒级断链**(上一轮所有"掉线"的根因)。
- 随后设备持续推送 **32774 pv4 状态流**(9~147 帧/会话,含 dp1/2/3/8/11/13/15/16/24/101-104),
  b_type bit7=1(needAck=false)→ 无需 ACK;这就是面板数据源,**无需 DP 查询**。
- cmd3(queryDps,空载荷与 dpId 列表两种)实车**均不应答**(设备不实现查询,靠主动推送)。
- 无应用层心跳/保活帧;链路靠时间同步应答+状态流维持(实测保持 29s+ 直至主动断开)。
- **仪表蓝牙图标 = 应用认证成功的标志**(用户实测:仅 GATT 时图标不亮,cmd0/cmd1 成功后亮起)。
- 断开后重新广播有 30~90s 暂停窗口;重连后重新认证(cmd0/cmd1)实测多次成功。
- 车辆自动关机后需重新开机才恢复广播(dp104 自动关机时间默认 10 分钟)。

## 10. DP 控制(observed,实车成功)

- **P4 的 DP 控制命令是 code 0x0027(39),不是 0x0002**!载荷 =
  `[0x00][dpsSn 4B BE] + 每DP [dpId][type][len 2B BE][value]`
  (`ppbpqqq.bdpdqbp(true, dpsSn, ...)`;dpsSn 独立计数器,PairRep 后清零)。
- 应答 DpsSendRep(4):`[sn 2B][flag 1B][status 1B]`,status=0 成功;设备繁忙时应答可延迟
  13~24s(等待超时需 ≥30s 或按 dpsSn 匹配)。
- **大灯 dp8(headlight_switch,bool)**:发送 → status=0 → 状态流回显 **dp8=01** ✓。
- **模式 dp15(mode,enum walk/eco/normal/sport)**:发送 01 → status=0 →
  **跨会话回读 dp15=01(ECO)持久化** ✓。
- 锁车状态(dp1=01)下命令仍被接受;电机/OTA/解绑类 DP 未触碰。

## 实现状态(src/youfs)

| 文件 | 状态 |
|---|---|
| protocol.py | ✅ key14/15、parse_ret 尾部放宽、trsmitr 递增接收、(其余原实现与实车一致) |
| commands.py | ✅ device_info_request_new(flag14)、CMD_DP_SEND_PV4=0x27 |
| connection.py | ✅ security_mode legacy/new 双路径、sn=1/2、新安全 cmd1 尾部、模式化校验 |
| scooter.py | ✅ 时间同步/上报 ACK 自动应答、send_dp(pv4)、sn/dpsSn 计数器、get_state 放行 |
| transport.py | ✅ 带响应写、chunk=mGattMTU |
| cli.py | ✅ --security-mode new、--sec-key、profile secKey |
| tests/ | 149 passed(含新安全专项 5 例) |

## 剩余阻断 / 已知缺口

1. **telemetry.parse_report 不识别 pv4/32774 头**(宽长度 TLV),`state.raw_dps` 仍空;
   状态解码目前靠逐帧手工解析。待修(格式已完全掌握)。
2. DpsSendRep 应答延迟可达 24s,send_dp 等待超时默认 8s → 显示"无应答";
   建议等待 30s 或按 dpsSn 匹配。命令本身已成功(status=0)。
3. cmd3 查询、cmd5、cmd21-23:设备不适用/不实现,已排除(见 §7)。
4. iPhone 原版行为仅能通过仪表/提示音间接佐证;未做 iOS 侧抓包(用户用 iPhone,无 adb 途径)。

## 工作约束执行情况

- 每次连接前均已在对话中提前告知 ✓
- 未发送解绑(5/20)、OTA(12-16)、电机/锁相关 DP ✓;仅用户授权的 dp8/dp15 ✓
- 原始 APK 未改动;全部产物在 work/;密钥只入 work/youfs2_profile.json,报告不含密钥值 ✓
- 全程未宣称"未验证 = 已验证";本报告所有"成功"均指上表实测项 ✓
