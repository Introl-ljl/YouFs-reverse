# YouFs-reverse — 工作区说明

Android APK 逆向 / 补丁 / 重打包工作区。样本：`YouFs-A_1.0.3_APKPure.apk`。

## apk-reverse skill（项目本地安装）

- 已安装路径：`.agents/skills/apk-reverse/`，**仅本项目作用域**（全局 `~/.agents/skills` 未被改动）。
  该目录是 DSH 的项目级 skill 根之一，会被自动发现并按需加载。
- **动手做任何 APK / dex / .so / Frida / 重打包 / 补丁分析之前，先加载 `apk-reverse` skill**，
  它是一份带 gate 的流程（先分类 → 过四道 gate → 再动手），不是背景阅读材料。
- `apk-reverse/`（仓库根）是 **上游 git 检出**，不是已安装的 skill：只放跨 skill 的维护工具
  （`check_*.py`、`tests/`、`docs/`），用于 `git pull` 更新与仓库自检。
- 加载的是 `.agents/skills/apk-reverse/`（独立副本）。改了上游克隆不等于改了已安装副本。

## 环境

运行 skill 脚本前，先把项目本地工具目录接上：

```powershell
. .\tools\env.ps1
```

它只影响当前 shell，设置 `APKREV_TOOLS` / `APKREV_JARS` / `APK_REVERSE_SMALI_CP`，
并把 `tools\` 加入 `PATH`。工具装到 `tools\`，不要装全局（见 `tools\README.md`）。

自检命令（先跑这个再判断某个工具"不可用"）：

```powershell
python .\.agents\skills\apk-reverse\scripts\doctor.py --json
```

## 约定

- 只改本工作区内的文件；不要写 `~/.dsh`、`~/.agents`、`~/.claude`、`~/.codex` 等全局位置。
- 在副本上作业，保留原始 APK；补丁产物必须按 skill 的 R3 验证过才能宣称完成。

## 更新

```powershell
npx skills update -p          # 只更新项目级 skill
git -C apk-reverse pull       # 更新上游克隆（维护工具）
```
