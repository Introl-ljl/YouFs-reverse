# cloud_api.md — YouFs 云端 App-API 还原(路径 B)

> 证据等级:除标注外均【B】(APK 静态分析)。服务端联调状态:签名未通过(见 §7)。

## 1. 常量(SmartApplication.e(),classes.dex)【B】

```
appKey    = vrx3vx5nan54x8w9sx44
appSecret = vtk5vjye4vss4shmwahxxngectfe8uqg
ttid      = comyongfengshun      (资源 app_scheme @0x7f130144)
channel   = oem                  (ThingSdk.init 5参版固定映射)
package   = com.yongfengshun
```

## 2. API 域名(assets/thing_domains_v1/regions,AES-256-CTR 解密)【B】

配置文件 = base64 → 前 32 字节为 AES-256 key → 其余 base64 → 前 16 字节 IV →
AES-256-CTR(Java: DomainHelper.parseDomainsConfig + AESCTRUtil)。解出:

| region | mobileApiUrl | 默认 |
|---|---|---|
| AZ | https://a1-us.gdyoufs.com | |
| EU | https://a1-eu.gdyoufs.com | ✔ |
| IN | https://a1-in.gdyoufs.com | |

完整解密产物:`work/domains_decrypted.json`(含 MQTT/网关/fusion 域名)。

## 3. 请求形状(ThingApiParams / OKHttpBusinessRequest)【B】

`POST {mobileApiUrl}/api.json`,全部参数 form-urlencode 于 body:

```
a          = API 名;checkAPIName() 把 thing.m.* 重写为 smartlife.m.*
v          = API 版本(如 2.0 / 4.0)
clientId   = appKey
os         = Android      channel = oem
appVersion = 1.0.3        lang    = en/zh
ttid       = comyongfengshun
sdkVersion = (SDK 常量)    deviceCoreVersion = (常量)
osSystem   = Android 版本  platform = 机型
requestId  = UUID         timeZoneId = 时区
et         = 3;cp = gzip(et=3 时)
deviceId   = 设备 ID(base.ApiParams.getRequestBody 追加)
time       = unix 秒(TimeStampManager)
postData   = 见 §4        sign = 见 §5
sid        = 会话(仅登录后且 sessionRequire)
bizData    = {"customDomainSupport":"1","neutralDomains":"1"}
```

## 4. postData 加密(et=3)【B】

明文 JSON → `AesGcmUtil.encryptBytes2BytesAppendNonce`:
`output = nonce(12B, random) || AES-128-GCM(ciphertext||tag16)`,再 base64。
key = `getEncryptoKey(requestId, ecode)`,native(libthing_security.so 0x6970):

```
getEncryptoKey(requestId, ecode=null) = HMAC-SHA256(key4, requestId).digest()[:16]
ecode != null 时: HMAC-SHA256(key4 + "_" + ecode, requestId)[:16]
```

响应同样加密:`{"success":true,"sign":..,"result":"<b64>"}` → b64 解码 → nonce 前 12B
GCM 解密 → gzip 解压 → 最终 JSON(Business.decryptResponse,et=3 分支)。
抓包模式(et=0.0.1)走明文,仅调试网关可用。

## 5. 签名(ThingApiSignManager + libthing_security.so)【B】

```
msg  = 按 key 排序、仅取白名单字段、非空者,拼 "k=v",以 "||" 连接
白名单 = a,v,lat,lon,lang,deviceId,appVersion,ttid,isH5,h5Token,os,
         clientId,postData,time,requestId,et,n4h5,sid,chKey,sp
postData 的值 = swapSignString(md5hex(原文)):
   h = md5(原文) 小写 hex(32 字符)
   swap = h[8:16] + h[0:8] + h[24:32] + h[16:24]
sign = HMAC-SHA256(key4, msg) 小写 hex(64 字符,native cmd 1 @0x599c-0x5fc8)
```

`key4`(native cmd 0 @0x6168-0x630c 组装,证据地址逐一核对):

```
key4 = com.yongfengshun
     + "_" + SHA256(签名证书 DER) 大写冒号 hex   ← 0x79c4:getPackageInfo.signatures[0]
     + "_" + keys[0]                            ← assets/t_s.bmp 隐写(libthing_security_algorithm.so 0x306c,appId 做
                                                  ×31 哈希索引;本包提取 = yvu7g9mgnjphc5sqv7hc9eh9ryraxmfv)
     + "_" + appSecret
```

本包签名证书(META-INF/BNDLTOOL.RSA,CN=www.tuya.com):
SHA256 = `A3:55:F5:F8:...:CF:29:E2:D4`(大写冒号)。

## 6. 登录流(LoginBusiness,classes8)【B】

```
1) thing.m.user.username.token.get  v2.0  {countryCode, username, isUid:false}
   → TokenBean{token, publicKey(每次登录新发 RSA 公钥), exponent}
2) passwd = base64( RSA/ECB/PKCS1( base64( MD5(密码) ) ) )
3) thing.m.user.mobile.passwd.login v4.0
   {countryCode, mobile, passwd, options:"{\"group\":1,\"mfaCode\":\"\"}", token, ifencrypt:1}
   (邮箱登录: thing.m.user.email.password.login v3.0)
   → User(含 session);后续请求以 sid 携带
4) 设备:thing.m.device.relation.entity.list / m.life.app.home.data.list(候选)
   设备详情:thing.m.device.get {devId} → 含 localKey
```

实现:`src/youfs/cloud.py` + `cli.py cloud`(凭据走本地 `work/secrets.env`,模板
`work/secrets.env.example`)。

## 7. 联调现状(2026-09-28)【observed】

用上述全部静态参数向 `a1-{eu,us,in}.gdyoufs.com/api.json` 发无凭据探测:

- 合法 API+版本(v=2.0)→ `ILLEGAL_CLIENT_ID "Invalid client;No access"`
- v=`*` → `API_OR_API_VERSION_WRONG`(说明网关先解析 API 再做 client 校验,
  API 名改写 smartlife.m.* 正确)
- 错误签名与正确签名错误一致;et=0.0.1 / et=3、query/body、加 deviceId 均同错
- 7 种 key 候选变体(解码/hex 文本/无冒号/换序/纯 secret)全部同错

结论:静态推导的第三方请求未通过服务端校验。错误签名与正确签名返回相同错误,
所以目前**不能从 `ILLEGAL_CLIENT_ID` 唯一定位到 HMAC key**;服务端可能先检查客户端登记、
证书或其它字段。以下都是待验证假设,不是已确认的根因:
1. t_s.bmp 密钥提取的 join 环节(Unicorn 黑盒模拟)有偏差
2. 服务端注册的证书指纹与本 APKPure 包证书不同
3. t_cdc.tcfg(App 内不存在,疑运行时下发)改变 securityOpen → 生产走另一算法

**裁决手段**:在可附加的 ARM64 环境里观察原版 App 的 `doCommandNative`
(`tools/capture_sign.md`, `tools/frida_sign_capture.js`),将真实 `(msg, sign)` 与静态实现逐字段对照。
MuMu 的 x86_64 原生库转译环境在本轮两次附加目标进程时使其退出,无法由该环境取得此证据;
详见 [`emulator_validation.md`](emulator_validation.md)。

## 8. 联调裁决(2026-09-28 第二轮)【observed】

通过 MuMu root + 系统证书 MITM(work/mumu/captures/,tools/mitm_youfs.py)取得 57 组
原版 App 真实请求/响应,据此完成全部动态核验:

1. **请求参数表(真实值,来自抓包)**:
   `ttid = sdk_thing@{appKey}`、`channel = oem`、`sdkVersion = 5.8.0`、
   `deviceCoreVersion = 5.5.0`、`appRnVersion = 5.79`、`nd = 1`、
   `chKey = 3fc2a062`(native getChKey 产物,随请求发送)、
   `platform = <机型>`、`deviceId = <安装指纹>`。
   此前静态推导的 ttid=comyongfengshun / channel=sdk / sdkVersion=3.23.0 全部有偏差,
   这是 `ILLEGAL_CLIENT_ID` 的直接原因之一。
2. **签名构造 §3-§5 全部正确**:27/27 组 et=3 真实请求的 sign 被如下 key4 复现:
   `key4 = com.yongfengshun_A3:55:..:E2:D4(大写冒号)_yvu7g9mgnjphc5sqv7hc9eh9ryraxmfv_vtk5vjye4vss4shmwahxxngectfe8uqg`
   (bmp_key0 提取、证书指纹格式、拼装顺序均动态证实;t_s.bmp 为唯一资产,无 daily 变体;
   appId 索引 = appKey,向量 count=1)。
   注意:et=0.0.1 的日志类请求(m.hades.*)用另一套签名路径,不与本公式匹配,已排除。
3. **payload 密钥派生(native getEncryptoKey @0x6970 逐行解读)**:
   `enc_key = HMAC-SHA256(key=requestId, msg=key4[+"_"+ecode]).hexdigest()[:16]`
   —— **requestId 是 HMAC 的 key,key4 是被签名消息**(与 cmd1 签名的参数顺序相反!),
   且取的是 hex 字符串前 16 个 ASCII 字符(非原始字节)作为 AES-128 key。
   会话请求的 ecode 来自登录 User 对象(不上线)。
   9/9 组无会话响应按此公式解密成功(含响应 sign 校验:
   `md5("result=<result>||t=<t>||<enc_key字符串>")` 与响应 sign 一致)。
4. **响应包装**:外层只有 `{"t","sign","result"}`,`success` 在解密后的内层 JSON。
5. **网关接受实测**:修正参数表后,`thing.m.user.username.token.get v2.0` 返回真实
   RSA 登录令牌(pbKey/exponent/token),不再 ILLEGAL_CLIENT_ID。
6. **登录管线(LoginRepository/LoginBusiness 反编译)**:
   - RSA 公钥 = `RSAPublicNumbers(exponent, publicKey十进制模数)`(不用 pbKey DER);
   - 明文 = `md5(password)` 小写 hex(非 base64;MD5Util.md5AsBase64 名不符实,实为 hex);
   - `passwd = RSAUtil.encrypt(...)` 输出为 **HEX 字符串**(非 base64);
   - `thing.m.user.mobile.passwd.login v4.0`
     `{countryCode, mobile(裸号), passwd, options:'{"group": 1,"mfaCode": ""}', token, ifencrypt:1}`;
   - 邮箱:`thing.m.user.email.password.login v3.0`。
7. **工具**:work/so/emulate_docmd.py(Unicorn 模拟 doCommandNative,假 JNIEnv)、
   work/so/emu_cert.py(0x79c4 证书指纹窄路径模拟)、work/decrypt_captures.py、
   work/verify_key4*.py(判别脚本);MITM CA 已装 MuMu 系统
   证书目录(tmpfs,重启失效),模拟器全局代理 10.0.2.2:8888。

## 9. 设备列表 / DP schema / 会话复用(2026-09-28 第三轮)【observed】

上一轮卡在设备列表 `REMOTE_API_PARAM_ALL_INPUT_LOSS`:`cloud.py` 按静态分析调用
`m.life.app.smart.local.device.list v1.1 {homeId, groupType}`。本轮用"抓包对拍"定位,
结论是**这个 API 对本账号返回空**,真正的设备列表走 `m.life.my.group.device.list v2.2`。

### 9.1 定位方法:解密 App 自己的请求,而不是猜参数

会话请求的 postData/response 用 `enc_key` 加密,而 `enc_key` 需要该会话的 `ecode`。
ecode 形如 `sess0000X0000000`(前缀 `sess0000` + 1 位 + `0000000`,共 10 个候选),
对抓包逐候选试解即可恢复(脚本 `work/dec_all.py`、`work/dec_req.py`)。
恢复后 103 组响应全部解密,证据落在 `work/mumu/decrypted/`。

**关键**:解密 App 自己的 `smartlife.m.api.batch.invoke` 请求,里面直接列出了它调用的
子 API 及其参数(见 `work/dec_batch_params.py`)。这比读混淆后的 SDK 源码可靠得多。

### 9.2 设备列表

| API | 版本 | postData | 结果 |
|---|---|---|---|
| `m.life.app.smart.local.device.list` | 1.1 | `{homeId, groupType}` | **空** `{"result":{}}`(App 自己也拿到空) |
| `m.life.my.group.device.list` | **2.2** | `{"gid": <数字>}` | **2 台车 + localKey/mac/productId** ✔ |

`gid` 在 batch 子调用里是 JSON **数字**(`{"gid":123456789}`);顶层 form 里的 `gid`
(如 batch.invoke / scene.homepage.rule.list)是**字符串**。`gid` 不在 SIGN_FIELDS,
所以顶层 `gid` 不参与签名。

返回字段包含:`devId`、`name`、`productId`、`localKey`(16 字节**可打印 ASCII**,
非 hex)、`mac`、`uuid`、`secKey`。

### 9.3 batch.invoke 子调用签名(逐字节复现)

`ApiBean.initSign()`(network/bean/ApiBean.java:27)把**公共 url 参数 + 子请求体 +
`time`** 合并后,用与顶层请求**同一个** `generateSignature()` 签名;子调用加密块以
`postData` 为键参与签名,输出字段名是 `params`。
`work/verify_subsign.py` 对抓包逐字节命中(`m.life.my.group.device.list` MATCH)。

> 踩坑:子调用只签它自己那几个字段会返回 `SING_VALIDATE_FALED`(服务端拼写如此);
> 必须带上 `deviceId`/`sid`/`chKey`/`clientId` 等公共字段。

### 9.4 DP schema(数字 dpId ↔ 代码名)

| API | 版本 | 说明 |
|---|---|---|
| `thing.m.device.get` | 1.0 | 设备详情,内嵌 `schema`(JSON 字符串):**每个 DP 的 id/code/中文名/mode/valueRange**,最完整 |
| `m.life.product.ext.prop.list` | 1.1 | 家庭级产品 schema:`functionSchemaList`(可写) + `statusSchemaList`(只读),含 `relationDpIdMaps {code: dpId}` |

本账号两台车 productId 均为 `ivybh960`(category `hbc`),共 41 项 DP。
`work/youfs_dp_map.json`、`work/youfs_product_schema.json` 为完整产物。

关键 DP(**已由服务端 schema 证实,非推测**):

| dpId | code | 中文名 | 模式 |
|---|---|---|---|
| 1 | `blelock_switch` | 锁车开关 | rw |
| 2 | `speed` | 速度 (km/h) | ro |
| 3 | `battery_percentage` | 电池电量 (%) | ro |
| 8 | `headlight_switch` | **前大灯开关** | rw |
| 12 | `mileage_total` | 总里程 | ro |
| 13 | `cruise_switch` | 定速巡航 | rw |
| 15 | `mode` | 模式 (walk/eco/normal/sport) | rw |
| 17 | `energy_recovery_level` | 能量回收强度 | rw |
| 20 | `voltage_current` | 当前电压 (scale 2) | ro |
| 37 | `battery_lock` | 电池仓锁 | rw |
| 101-103 | `speed_limit_1/2/3` | 1/2/3 档限速 | rw |
| 104 | `autopowerofftime` | 自动关机时间 (MIN) | rw |

对照:上一轮从 RN bundle 猜出的 `taillight_switch` / `speed_limit_e` **不在此设备
schema 中**,应以本表为准。

### 9.5 会话复用(避免风控)

每次调用 `login_password` 都会在服务端**新建一个会话**。逐条命令都登录一次是明显的
风控信号。正确做法(`src/youfs/cloud.py::ensure_session`):

1. 读 `work/youfs_cloud.json` 的 `sid`;
2. 用 `thing.m.user.info.get`(只读、无副作用)**探活**该 sid;
3. 通过就复用,失败才登录一次,并回写 `homeId` / `loginTime` / `lastUsed`。

CLI 的所有 cloud 子命令都走这条路;`--relogin` 是唯一的强制重登入口。

此外登录 `mobile` 字段必须是**裸号**(`13800000000`),带 `+86` 会返回
`USER_PASSWD_WRONG`。`cloud.py` 现在会自动剥离。

### 9.6 CLI

```
python cli.py cloud login                      # 复用会话(不重新登录)
python cli.py cloud homes                      # 列家庭,缓存 homeId
python cli.py cloud devices                    # devId/localKey/mac/productId
python cli.py cloud meshes                     # BLE mesh 的 networkKey/appKey/srand
python cli.py cloud schema "YouFs"             # 设备详情 + 完整 DP 表 + 当前 dps
python cli.py cloud raw <api> <ver> '<json>'   # 任意签名调用(排障用)
python cli.py info   <BLE Mac> --cloud-device "YouFs"   # 自动取 localKey 派生 key5
```

`--local-key` 同时接受 32 位 hex 和云端返回的 16 字符 ASCII 两种形式。
