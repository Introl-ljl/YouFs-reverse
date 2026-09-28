# app_info.md — YouFs-A 1.0.3 基本信息与结构清单

> 样本:`YouFs-A_1.0.3_APKPure.apk`(原始保留于工作区根目录,未改动)
> 分析日期:2026-09-27 · 全部结论为 APK 静态分析(observed),无动态验证

## 基本信息

| 项 | 值 | 证据 |
|---|---|---|
| App 名称 | YouFs-A | AndroidManifest application label |
| Package | `com.yongfengshun` | AndroidManifest package |
| Version Name | 1.0.3 | manifest versionName |
| Version Code | 5 | manifest versionCode |
| minSdk | 23 | manifest |
| targetSdk | 34 | manifest |
| SHA-256 | `b7fb2437c7c85056eb7f12b16157259159a1dc8d62bc2d819431e9bc63877602` | 实测 |
| Main Activity | `com.smart.ThingSplashActivity` | manifest |
| 入口容器 | 涂鸦 ThingSmart SDK 全家桶 | services: `com.thingclips.smart.*` |

## DEX 结构

15 个 dex,合计约 180 MB:

```
classes.dex   21.8 MB   涂鸦 smart 主框架(含 com.thingclips.ble.jni.BLEJniLib 声明)
classes2.dex  22.3 MB
classes3.dex  14.4 MB   ★ BLE 协议栈(com.thingclips.sdk.blelib / sdk.ble / sdk.bluetooth)
classes4-15.dex         其余 SDK(RN、面板、相机、推送、sigmesh 等)
```

## Native 库(lib/arm64-v8a,armeabi-v7a 同构)

与 BLE 协议直接相关:

| 库 | 职责 |
|---|---|
| `libBleLib.so` (16 KB) | ★ 涂鸦经典 BLE 协议编解码(trsmitr 分帧/KLV DP/会话密钥派生/OTA CRC),JNI: `com.thingclips.ble.jni.BLEJniLib` |
| `libthingsmart.so`, `libthing_security.so`, `libthing_security_algorithm.so` | 涂鸦安全/杂项 |
| `libmbedtls.so` 等 | 通用 TLS |

其余为涂鸦 IoT 生态(IPC 相机 `libThing*`、RN `libreactnativejni`/`libv8android`、V8、OpenCV、条码识别等),与本任务无关。

## 框架识别

| 项 | 结论 | 证据 |
|---|---|---|
| 原生 Android 壳 | Java/Kotlin,涂鸦 ThingSmart | 1047 个 activity(多为混淆的 RN 容器 `zqyhk*/hajec*`) |
| React Native | ✔(`libreactnativejni.so`, `libv8android.so`, `assets/x_platform_config.json` RN package 注册表) | 文件清单 |
| Flutter / UniApp / Cordova | ✘ 未发现 | — |
| Tuya IoT SDK | ✔ 核心(com.thingclips.* = 涂鸦 "ThingClips" 改名空间) | dex 包名 |
| 涂鸦 BLE SDK | ✔ `com.thingclips.sdk.blelib`(连接/channel)+ `com.thingclips.sdk.ble`(协议/业务)+ `libBleLib.so` | classes3 |
| Nordic BLE / RxAndroidBle / FastBle | ✘ 未发现 | — |
| protobuf | 未见 BLE 用;网络层另有封装 | — |
| assets | 305 个条目:涂鸦 panel/miniapp 配置 JSON、lottie、uni 插件桥(TUNI*Manager.json) | 文件清单 |
| 面板(业务 UI) | **不在 APK 内**。滑板车面板为云端下发(RN/miniApp);`scooter/滑板/YouFs` 在全部 dex 与 assets 中 0 命中 | 全树检索 |

## 关键结论

1. **本 App 是涂鸦(Tuya)方案的 OEM 出行类 App**:蓝牙链路 100% 走涂鸦 BLE SDK,不存在厂商自研私有 BLE 协议类。
2. 滑板车业务命令(DP 数据点)由云端面板驱动,APK 内无 DP 语义表 → 具体 DP ID 需动态抓包或云端面板反查(标记 UNKNOWN)。
3. BLE 传输协议本身(连接、配对、DP 封装、校验、加密)完整存在于 classes3 + libBleLib.so,可静态还原,见 protocol.md。
