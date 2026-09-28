# capture_sign.md — 用 Frida 抓一次真实签名(路径 B 的最后一块拼图)

## 目的

静态侧已经完整还原了 App 云端 API 的签名算法(docs/cloud_api.md),但服务端返回
`ILLEGAL_CLIENT_ID`,说明真实运行的 App 所用的 HMAC key 与我们从 APK 推导的值存在
差异(最可能在 t_s.bmp 密钥或证书分量)。**抓一次真机的 doCommandNative 调用即可
终裁**:拿到真实 (msg, sign) 对后离线比对,确定 key 的真实构成。

## 需要什么

- 一台 **root 过的 Android 手机**,或 **PC 上的 Android 模拟器**(Android Studio AVD,
  Google APIs 镜像自带 root)
- 装 frida-server(与 PC 端 frida 版本一致,`pip install frida-tools`)
- YouFs-A 1.0.3 APK(本仓库根目录就有)

## 步骤

```powershell
pip install frida-tools
# 设备侧(手机需 root;AVD 直接 adb root):
adb push frida-server-android-arm64 /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &"
# 安装并启动 App,注入:
adb install YouFs-A_1.0.3_APKPure.apk
frida -U -f com.yongfengshun -l tools/frida_sign_capture.js --no-pause
```

然后正常操作 App(登录进首页即可),脚本会打印:

- `doCommandNative cmd=0`(初始化:appSecret / appId / 证书处理)
- `doCommandNative cmd=1`(每次云端请求的签名:输入 msg、输出 sign)
- `getEncryptoKey`(et=3 请求加密密钥:输入 requestId)

把这些输出保存为 `work/so/frida_capture.log` 交回。

## 拿到后能确认什么

1. 真实 key 的构成(用已知 msg+sign 离线验证候选 key)→ 修正 `youfs/cloud.py`
2. 若 key 一致 → 说明服务端校验还依赖其它字段,从 msg 里逐字段 diff
3. 顺带抓到 `et=3` 加密的真实样例,校验我们的 AES-GCM 封装

## 无 root 备选

无 root 手机无法注入 Frida。备选:PC 上跑 Android Studio 模拟器(AVD 免 root,
`adb root` 即可),把 APK 装进 AVD 完成登录。
