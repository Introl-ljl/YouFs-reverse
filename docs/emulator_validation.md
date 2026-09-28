# MuMu 原版 App 动态核对（2026-09-28）

## 范围与环境

- 目标是**原版** `YouFs-A_1.0.3_APKPure.apk`；MuMu 内安装包的 SHA-256 与工作区原件一致：`b7fb2437c7c85056eb7f12b16157259159a1dc8d62bc2d819431e9bc63877602`。【observed】
- MuMu Player 12，Android 12，设备 ABI 为 `x86_64`，App 安装 ABI 为 `arm64-v8a`；`libnb.so` 承担原生库转译。设备有 root，项目使用 MuMu 自带 ADB。【observed】
- 本轮没有修改 APK、发送车辆控制命令或取得 BLE HCI 抓包。

## 原版 App 可见行为

- 首次启动出现用户协议和隐私政策确认，用户自行同意；随后出现 root 安全提醒，用户选择继续使用。【observed】
- 首页显示两个设备，均为离线。打开其中一个设备的面板后，能看到“未连接”、电量、里程以及定速巡航、前大灯、启动模式等入口。设备信息页将其列为“网关/手机”连接能力和“未连接”在线状态。【observed】
- 面板显示的数值可能来自缓存或云端，本轮没有同时连接实车，**不能**把这些数值当作实时 BLE 遥测，也不能由画面推定数字 DP ID。【inferred】

## 从运行时下载的面板资源得到的线索

MuMu App 数据中出现 `files/deletable/rn/000000stqa_5.9_1.8.2/main.jsbundle`。只复制了该资源至 `work/mumu/youfs_panel_inspect.jsbundle`，SHA-256 为 `b0022943906a9f5fa419272b856903ff602f96864f1acebf0375dfb870e06e4c`。【observed】

该资源的 `dpState`、`getDpSchema`、`checkDpExist` 调用中可直接找到以下**代码名**，与面板显示的功能相符：【observed】

| 代码名 | 可支持的语义判断 | 证据位置 |
|---|---|---|
| `speed` | 速度状态 | bundle:1247 的 `dpState.speed`、`getDpSchema('speed')` |
| `battery_percentage` | 电量百分比 | bundle:1247 的 `dpState.battery_percentage` |
| `mileage_once` | 单次里程 | bundle:1229-1230、1247 的 schema/状态调用 |
| `cruise_switch` | 定速巡航开关 | bundle:1225 的状态与提示逻辑 |
| `blelock_switch` | 蓝牙锁状态 | bundle:1225、1247 的状态/存在性调用 |
| `taillight_switch`、`speed_limit_e`、`energy_recoery_level` | 尾灯、限速、能量回收的面板代码候选 | bundle:1244；是否存在于此设备的 schema 尚未验证 |

这些是面板侧的**字符串代码**，不是 BLE TLV 的数字 `dpId`。资源中还出现通用灯光代码 `switch_led`，但本轮没有证据把它等同于屏幕上的“前大灯开关”。【inferred】

## 本轮未能完成的验证

- Frida 17.19.0 服务能运行，且成功附加到系统设置进程；两次附加 YouFs-A 主进程时均报 `unable to write to process memory: No such process`，目标进程随后退出。已按 skill 的两次失败停手规则停止此路径。原因尚未区分原生库转译、App 自检或其他进程状态。【observed / unverified cause】
- 先前 `work/mumu/mitm.log` 的 HTTPS 握手记录显示 App 不信任代理证书；该日志没有 `api.json` 明文，不能用来对照签名输入。【observed】
- 没有取得 `doCommandNative` 的真实输入/输出，因此 `src/youfs/cloud.py` 的签名和加密实现仍未完成动态核验。MuMu 面板能显示离线设备，不足以证明第三方客户端的 API 请求有效。【observed / inferred】
- MuMu 中没有实体滑板车 BLE 链路，本轮不能确认 GATT、握手、会话密钥、数字 DP ID 或灯光控制。继续执行 `capture_analysis.md` 仍需要真机和车辆。【observed】

## 下一步需要的输入

1. **BLE MVP：** Android 真机和已绑定的滑板车；按 `capture_analysis.md` 开启 HCI 日志，并记录连接、被动状态和灯光开关各一步。无需 root。
2. **云端签名路径：** 能正常运行这份 APK 的 ARM64 设备或无转译的 ARM64 Android 环境，并允许观察原版 App 的签名调用。若 App 要求重新登录，由账号所有者自行输入凭据和验证码。先复现原版 App 的请求，再判断第三方请求在哪个字段被拒绝。
