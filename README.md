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
| [gatt.md](docs/gatt.md) | GATT UUID:service `FD50`,TX char `0001`,RX char `0002` |
| [connection_sequence.md](docs/connection_sequence.md) | 连接→MTU 246→notify→cmd 0→cmd 1 配对→就绪 |
| [protocol.md](docs/protocol.md) | 三层帧格式:trsmitr 分帧 / AES-CBC 应用帧 / DP TLV |
| [checksum.md](docs/checksum.md) | CRC-8(poly07)、CRC-16/ARC、CRC-16/MODBUS |
| [auth.md](docs/auth.md) | 鉴权与密钥派生(MD5 系;无静态固定 key) |
| [commands.md](docs/commands.md) | 命令号总表;滑板车业务 DP 全部 UNKNOWN 待抓包 |
| [telemetry.md](docs/telemetry.md) | 0x8001/0x8004 上报解析;字段映射表待填 |
| [models.md](docs/models.md) | APK delegate factory selector 来源与分支映射；不能仅凭车型判断 |
| [errors.md](docs/errors.md) | GattCode/blelib/BondCode 全量错误码 |
| [ota.md](docs/ota.md) | OTA 仅静态分析,**DO NOT EXECUTE** |
| [capture_analysis.md](docs/capture_analysis.md) | 动态抓包方案与记录模板(待硬件) |
| [emulator_validation.md](docs/emulator_validation.md) | MuMu 原版 App 验证、面板代码线索与未解决项 |
| [cloud_api.md](docs/cloud_api.md) | 云端 API 静态还原;签名联调待动态核验 |

## 快速开始

```powershell
pip install -e .[ble,dev]      # bleak 仅蓝牙功能需要
python cli.py scan --all
python cli.py gatt <目标当前地址>                 # 诊断 GATT，不发应用帧
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

当前离线状态机只允许 APK 证据支持的 P4 factory selector（400–405、413）普通旧安全候选路径
（`connectType=0`、`securityMode=legacy`）：加密 cmd 0 使用 flag 4/key4，cmd 1 使用
flag 5/key5。若设备信息要求 beaconKey，配置中提供有效 beaconKey 时使用 marker `0x10` 分支；
缺失时遵循原版 normal path 的 marker `0x00` fallback，cmd 1 仍为 key5/flag5 加密。只有 cmd 1
PairRep 的 bindStatus 为 0 或 2 才进入 READY。P1、P2、证书/新安全及其他
未实现分支会 fail closed。该 P4 候选路径尚未确认适用于 YouFs 2。`info` 是单独的 cmd 0 诊断探针；
cmd 0 应答不等于 READY。

截至 2026-09-28，YouFs 2（App 地址尾号 `00:01`）未出现在本轮扫描结果中；此前捕获到的准确地址
曾两次连接超时，随后广播消失。因此它的可复现连接、GATT 树、cmd 0/cmd 1 应答均未确认。
YouFs 车辆的 protocolType、安全 flag、密钥路径和 DP 表仍未由真车验证；通用 Tuya 设备观察不能
替代 YouFs 实车证据。

> **状态/控制边界**：`status` 不发送 DP 查询；当前 DP 查询/控制仍 fail closed。`connect` 会发 cmd 0
> 和 cmd 1，因此仅在配置字段与密钥已由可信来源核验后使用。不要猜 DP ID、密钥或安全 flag。

Python API:

```python
from youfs import YouFSScooter

async with YouFSScooter(address, session_key=None) as scooter:
    info = await scooter.fetch_device_info()      # 尝试 cmd 0x0000；应答不等于 pairing-ready
    state = await scooter.wait_for_report()       # 被动等待车辆上报
    print(state.raw_dps)                          # [(dp_id, type, value), ...]
```

该低层 API 不代表 pairing-ready；只有 `YouFsConnection` 的 P4 legacy 状态机收到并验证成功 PairRep
才会进入 READY。DP API 目前仍拒绝发送，直至业务帧路径另行实现并验证。

## 测试

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'  # 避开本机全局 xonsh 插件初始化异常
python -m pytest tests/ -q
```

## 验收状态(对照任务书)

| 验收项 | 状态 |
|---|---|
| 1 发现 YouFs 2 | **未完成**：当前扫描未见尾号 `00:01` 的车辆广播 |
| 2 建立到 YouFs 2 的 BLE 连接 | **未验证**：尚无目标广告地址和实车连接结果 |
| 3 发现 YouFs 2 的 GATT | **未验证**：必须连接后读取服务与特征 UUID |
| 4 确认 YouFs 2 的 cmd 0 响应 | **未验证**：目标车 GATT 与 cmd 0 应答尚无可复现记录 |
| 5 pairing-ready / 解析遥测 | **未验证**：离线实现仅覆盖 P4 legacy；未拿到目标车配置或 PairRep；DP 映射待抓包 |
| 6 控制灯 ON/OFF | **不可用/未完成**：DP 查询/写入仍 fail closed，且灯光 DP、应答均待实车确认 |

**MVP 尚未达成。** 当前缺少 YouFs 2 广播识别、GATT 发现、cmd 0 与配对/业务协议的实车证据；完成这些步骤需要车辆保持 BLE 广播，并在需要时进行真车验证。原版 App 已在 MuMu 启动并显示离线设备面板；面板代码名已部分确认，数字 DP ID 和 BLE 行为仍待真车抓包。云端 API 第三方请求也尚未通过联调，见 `docs/emulator_validation.md`。

## 安全约束执行情况

- ✅ 不刷固件 / 不 OTA / 不动 Flash / 不绕硬件保护
- ✅ 不实现电机相关命令；除显式 P4 legacy 连接握手外，不提供配对/解绑/OTA 业务命令
- ✅ DP 查询/控制当前 fail closed;未知命令只分析
- ✅ 原始 APK 未改动(SHA-256 记录于 app_info.md),抓包原样存 `captures/original/`

## 目录

```
docs/                  13 份分析文档
src/youfs/             protocol / transport / scanner / commands / telemetry / scooter
cli.py  examples/  tests/
work/                  反编译树(jadx)与提取物(分析过程产物,可删)
captures/original/     HCI 抓包(待提供)
```

---

# 工作区 / apk-reverse skill 安装说明(原始内容)

## 安装结果

| 路径 | 内容 | 作用域 |
|---|---|---|
| [`.agents/skills/apk-reverse/`](.agents/skills/apk-reverse) | 已安装的 skill(`SKILL.md` + `references/` + `scripts/` + `evals/` + `evidence/`) | 项目 |
| [`skills-lock.json`](skills-lock.json) | `skills` CLI 的锁文件,记录来源与内容哈希,供后续更新/还原 | 项目 |
| [`apk-reverse/`](apk-reverse) | 上游 git 检出(`newliver666/apk-reverse`),仓库根是跨 skill 的维护工具,不属于已安装 skill | 项目 |
| [`tools/`](tools) | 项目本地工具链落地区(jadx 1.5.2 已装入 `tools/jadx/`)+ [`env.ps1`](tools/env.ps1) | 项目 |
| [`AGENTS.md`](AGENTS.md) | 工作区级 agent 指令(每次会话自动加载) | 项目 |

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
