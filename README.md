# YouFs-reverse — 永锋顺/YouFs 电动滑板车 BLE 协议逆向

对 `YouFs-A_1.0.3_APKPure.apk`(com.yongfengshun)的静态逆向结论 + 第三方 Python/Bleak 客户端。

**核心发现**:YouFs-A 是**涂鸦(Tuya)ThingSmart 方案**的 OEM App——蓝牙链路 100% 走涂鸦通用
BLE 协议(`com.thingclips.sdk.blelib` + `libBleLib.so`),不存在厂商自研协议。因此本仓库还原的
本质是「涂鸦单 BLE 协议栈」+「滑板车 DP(数据点)映射」。

## 文档(docs/,含 file:line 证据与【A-E】证据等级)

| 文档 | 内容 |
|---|---|
| [app_info.md](docs/app_info.md) | APK 结构、SDK 清单、框架识别 |
| [ble.md](docs/ble.md) | BLE 入口类清单(阶段 2) |
| [gatt.md](docs/gatt.md) | GATT UUID:service `FD50`,TX char `0001`,RX char `0002`(已实车验证) |
| [connection_sequence.md](docs/connection_sequence.md) | 连接→MTU 246→notify→cmd 0→cmd 1 配对→就绪 |
| [protocol.md](docs/protocol.md) | 三层帧格式:trsmitr 分帧 / AES-CBC 应用帧 / DP TLV |
| [checksum.md](docs/checksum.md) | CRC-8(poly07)、CRC-16/ARC、CRC-16/MODBUS |
| [auth.md](docs/auth.md) | 鉴权与密钥派生(MD5 系;key14/key15 公式已按实车修正) |
| [commands.md](docs/commands.md) | 命令号总表;业务 DP 由云端 schema 补齐 |
| [telemetry.md](docs/telemetry.md) | 0x8001/0x8004 上报解析;字段映射表 |
| [models.md](docs/models.md) | APK delegate factory selector 来源与分支映射；不能仅凭车型判断 |
| [errors.md](docs/errors.md) | GattCode/blelib/BondCode 全量错误码 |
| [ota.md](docs/ota.md) | OTA 仅静态分析,**DO NOT EXECUTE** |
| [capture_analysis.md](docs/capture_analysis.md) | 动态抓包方案与记录模板 |
| [emulator_validation.md](docs/emulator_validation.md) | MuMu 原版 App 验证、面板代码线索与未解决项 |
| [cloud_api.md](docs/cloud_api.md) | 云端 API：签名/加密配方与设备/DP schema 还原 |
| [ble_diagnosis_20260929.md](docs/ble_diagnosis_20260929.md) | 2026-09-29 实车连接排查(广播/GATT/通知订阅) |
| [ble_auth_verification_20260929.md](docs/ble_auth_verification_20260929.md) | 2026-09-29 实车认证与控制验证(cmd0/cmd1、保活、dp8/dp15) |

## 快速开始

```powershell
pip install -e .[ble,dev]      # bleak 仅蓝牙功能需要
python cli.py scan --all
python cli.py gatt <目标当前地址> --scan-timeout 60 --timeout 30  # 扫描60秒、连接最多30秒，不发应用帧
python cli.py connect <目标当前地址> --profile-file work/<已核验配置>.json `
  --service-uuid <实测service> --write-uuid <实测write> --notify-uuid <实测notify>
```

连接步骤和阶段判读见 [connection_sequence.md](docs/connection_sequence.md)。先用 `scan --all`
确认目标身份与当前地址，再用 `gatt` 诊断服务和通道。`connect` 会在自身扫描中保留匹配到的
BLEDevice 并连接该对象、验证/订阅 GATT 通道，然后按 profile 执行应用层握手。profile JSON 必须
存于 `work/` 下并绑定目标 MAC；profile 中的 `protocolType` 当前作为第三方客户端的显式
factory selector 输入，必须由该目标原版 App 的连接记录/目标专属元数据证实。静态 DEX 的实际
factory 入参名为 `ControllerBean.deviceType`，其来源受扫描分支或本地缓存影响，不能直接假定它等于
云端 `DeviceBean.protocolType`。`connectType`、`securityMode`、UUID、devId 与密钥材料也必须有
目标专属依据。不要用设备名或默认 UUID 推断协议。

当前离线状态机覆盖 APK 证据支持的 P4 factory selector（400–405、413），并要求显式指定安全模式：
`legacy`（`connectType=0`，cmd 0 用 flag 4/key4，cmd 1 用 flag 5/key5）或 `new`（cmd 0 用
flag 14/key14，cmd 1 用 flag 15/key15，key14 = MD5(UTF-8(localKey + secKey))、
key15 = MD5(UTF-8(localKey + secKey) ‖ srand)）。若设备信息要求 beaconKey，配置中提供有效
beaconKey 时使用 marker `0x10` 分支；缺失时遵循原版 normal path 的 marker `0x00` fallback。
只有 cmd 1 PairRep 的 bindStatus 为 0 或 2 才进入 READY。P1、P2、证书认证及其他未实现分支会
fail closed。`info` 是单独的 cmd 0 诊断探针；cmd 0 应答不等于 READY。

`gatt` 的 `--scan-timeout` 控制发现目标的扫描窗口（默认 60 秒），`--timeout` 单独控制扫描命中后
BLE/GATT 建立过程的超时（默认 20 秒；Windows 上包含服务发现和会话就绪）。扫描命中后会将同一进程捕获的 BLEDevice 直接交给连接器；未命中时
不会尝试连接地址字符串或触发隐式重扫。

2026-09-29 已实测 YouFs 2（地址尾号 `00:01`，报告中一律使用匿名化占位值）：车辆重新开机后恢复
可连接广播，GATT 树（FD50、MTU 247）与通知订阅通过；随后 cmd 0/cmd 1 应用层握手、保活应答、
状态流与 DP 控制（大灯 dp8、模式 dp15）在同一台车上打通。完整实验见
[连接排查报告](docs/ble_diagnosis_20260929.md) 与 [认证与控制验证报告](docs/ble_auth_verification_20260929.md)。
该车的 security 分支为**新安全**（cmd 0 flag14/key14、cmd 1 flag15/key15）；legacy flag4/key4
在同一台车上实车无应答，仍属候选路径而非已验证结论。密钥值不入库，profile 存放在 git 忽略的
`work/` 内。

> **状态/控制边界**：`status` 不发送 DP 查询。`connect` 会发 cmd 0 和 cmd 1，因此仅在配置字段
> 与密钥已由可信来源核验后使用。`send_dp()` 只应发送车主明确授权的 DP（当前仅 dp8/dp15）；
> 电机、OTA、解绑类命令不实现。不要猜 DP ID、密钥或安全 flag。

Python API:

```python
from youfs import YouFSScooter

async with YouFSScooter(address, login_key=..., protocol_type=..., security_mode=...) as scooter:
    info = await scooter.fetch_device_info()      # cmd 0x0000；应答不等于 pairing-ready
    state = await scooter.wait_for_report()       # 被动等待车辆上报
    print(state.raw_dps)                          # [(dp_id, type, value), ...]
    await scooter.send_dp(8, 1, True)             # 仅限车主授权的 dpId（READY 之后）
```

低层 `fetch_device_info()` 单独调用不代表 pairing-ready；只有 `YouFsConnection` 状态机收到并验证
成功 PairRep 才会进入 READY，`send_dp()` 也只在 READY 之后才放行。DP 写入应按
[认证与控制验证报告](docs/ble_auth_verification_20260929.md) 的授权范围使用。

## 测试

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'  # 避开本机全局 xonsh 插件初始化异常
python -m pytest tests/ -q
```

## 验收状态(对照任务书)

| 验收项 | 状态 |
|---|---|
| 1 发现 YouFs 2 | **实车通过**：重启车辆后观察到 RANDOM 类型可连接广播；间歇消失的原因未定 |
| 2 建立到 YouFs 2 的 BLE 连接 | **实车通过**：原生 WinRT、现有 CLI 与通知探针成功 |
| 3 发现 YouFs 2 的 GATT | **实车通过**：FD50 通道、MTU 247；通知订阅成功 |
| 4 确认 YouFs 2 的 cmd 0 响应 | **实车通过**：新安全 flag14/key14 发送，~110ms 收到 DeviceInfoRep，CRC 通过 |
| 5 pairing-ready / 解析遥测 | **部分通过**：cmd 1 PairRep(bindStatus) 已达成 READY，状态流 32774 已实车收到；`telemetry.parse_report` 尚未识别 pv4 宽长度头 |
| 6 控制灯 ON/OFF | **实车通过(DP 层)**：`send_dp` 经 cmd 39 发送 dp8，车辆状态流回显 dp8=01；CLI `light` 子命令仍指向旧的配对门控提示 |

**实车链路已打通**(2026-09-29，单台车)：GATT → cmd0/cmd1 认证 → 保活 → 状态流 → DP 控制。
已知缺口：`telemetry.parse_report` 未识别 pv4/32774 宽长度 TLV（`state.raw_dps` 仍空，需逐帧手工解析，
格式已完全掌握）；`send_dp` 默认等待超时 8s，小于设备繁忙时的应答延迟（可达 24s）。云端第三方
请求的签名已验证，会话/设备/DP schema 已还原，见 `docs/cloud_api.md`。

## 安全约束执行情况

- ✅ 不刷固件 / 不 OTA / 不动 Flash / 不绕硬件保护
- ✅ 不实现电机相关命令；不提供解绑/OTA 业务命令，也不发送 cmd 5/21-23
- ✅ DP 写入只经由显式授权的 `send_dp()`(READY 之后)，实车仅发送过车主授权的 dp8/dp15
- ✅ 原始 APK 未改动(SHA-256 记录于 app_info.md)
- ✅ 密钥、profile、抓包与真机地址只存于 git 忽略的 `work/`、`captures/`；仓库内设备标识已匿名化

## 目录

```
docs/                  17 份分析文档(含 2 份 2026-09-29 实车报告)
src/youfs/             protocol / transport / scanner / commands / telemetry / connection / scooter / cloud
cli.py  examples/  tests/                  149 个离线测试
tools/                 抓包/诊断脚本(frida、mitmproxy、WinRT BLE 探针)与本地工具链落地目录
work/                  反编译树(jadx)、抓包解密产物、profile 与密钥(git 忽略)
captures/original/     HCI 抓包目录(待硬件提供，git 忽略)
```

仓库根另有 `AGENTS.md`(工作区 agent 指令)与 `.agents/skills/apk-reverse/`、`apk-reverse/`、
`skills-lock.json`(项目级 skill 与上游维护克隆)；这些属于本地工作区配置，前者随仓库分发，
后两者中的 skill 目录与上游克隆不入库。

---

# 工作区 / apk-reverse skill 安装说明(原始内容)

## 安装结果

| 路径 | 内容 | 作用域 |
|---|---|---|
| `.agents/skills/apk-reverse/` | 已安装的 skill(`SKILL.md` + `references/` + `scripts/` + `evals/` + `evidence/`)；**git 忽略，克隆后需按下节命令重装** | 项目 |
| [`skills-lock.json`](skills-lock.json) | `skills` CLI 的锁文件,记录来源与内容哈希,供后续更新/还原 | 项目 |
| `apk-reverse/` | 上游 git 检出(`newliver666/apk-reverse`),仓库根是跨 skill 的维护工具,不属于已安装 skill；**git 忽略** | 项目 |
| [`tools/`](tools) | 项目本地工具链落地区 + [`env.ps1`](tools/env.ps1)；jadx 等大体积工具装在 `tools/` 下且不入库 | 项目 |
| [`AGENTS.md`](AGENTS.md) | 工作区级 agent 指令(每次会话自动加载) | 项目 |

> 从 GitHub 克隆后，`.agents/skills/` 与 `apk-reverse/` 不存在(已被 `.gitignore` 排除)，
> 需要按下面两条命令重新安装才能使用 apk-reverse skill。

安装方式(仓库 README 记载的官方路径,未使用 `-g`):

```powershell
npx skills add newliver666/apk-reverse --skill apk-reverse -a universal --copy -y
```

- `universal` → `.agents/skills/`,正是 DSH 的项目级 skill 根(`<projectRoot>/.agents/skills`),因此无需任何全局配置即可被发现。
- `--copy` 生成独立副本而非符号链接,规避 Windows 上创建符号链接的权限问题。
- 未传 `-g`:**没有写入** `~/.agents/skills`、`~/.claude/skills`、`~/.codex/skills`、`~/.dsh`。

## 开始使用

```powershell
. .\tools\env.ps1                                             # 接上项目本地工具目录
python .\.agents\skills\apk-reverse\scripts\doctor.py --json   # 环境自检
```

## 更新与卸载

```powershell
npx skills update -p        # 仅更新项目级 skill(按 skills-lock.json)
npx skills list -p          # 查看项目级已安装 skill
git -C apk-reverse pull     # 更新上游检出(维护工具,非已安装 skill)

npx skills remove apk-reverse -p    # 卸载:移除项目级 skill
```

## 全局隔离

- skill 只存在于本工作区,其他项目不可见。
- `tools/env.ps1` 只改当前 shell 环境变量,不写任何全局配置文件。
- 未修改 `~/.dsh/settings.yaml`、`~/.dsh/cordis.yml` 或任何 `~/.agents`、`~/.claude`、`~/.codex` 内容。

## 克隆后重建(本地私有部分)

仓库只包含可公开的分析结论、协议实现与测试；以下内容按设计不入库，克隆后都是空的：

| 不入库内容 | 重建方式 |
|---|---|
| `.agents/skills/apk-reverse/` | `npx skills add newliver666/apk-reverse --skill apk-reverse -a universal --copy -y` |
| `apk-reverse/`(上游维护克隆) | `git clone https://github.com/newliver666/apk-reverse` |
| `tools/jadx*`、`tools/pydeps/`、`tools/jars/` | `. .\tools\env.ps1` 后按 `tools/README.md` 放入解包目录 |
| 样本 APK `YouFs-A_1.0.3_APKPure.apk` | 自行获取；SHA-256 见 `docs/app_info.md` |
| `work/`(反编译树、云端会话、profile 与密钥) | 由 `cli.py cloud …` 与各文档脚本重新生成 |
| `work/mumu/ecodes.json`(抓包复现用的会话候选值) | 本地留存；缺失时 `tests/test_cloud.py` 的相关用例自动 skip |

测试在没有这些本地产物时仍可运行：依赖抓包语料的用例会 skip，其余用例覆盖协议编解码、
状态机与 CLI 行为。

## 数据与隐私说明

仓库内的设备标识(车机 MAC、devId、uuid、账号 gid、会话 ecode、手机号)以及两台家用 BLE 设备的
广播向量均已替换为合成占位值，字节布局与真实抓包一致，因此回归测试仍然有效。真实值只保留在
本地 git 忽略的 `work/`、`captures/` 中。
