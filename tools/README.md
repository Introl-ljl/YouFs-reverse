# tools/ — 项目本地工具链目录

这个目录是 **项目本地** 的工具落地区，目的是让逆向工具链不必装到全局。

| 路径 | 用途 |
|---|---|
| `env.ps1` | 为当前 shell 设置 `APKREV_TOOLS` / `APKREV_JARS` / `APK_REVERSE_SMALI_CP`，并把本目录加入 `PATH` |
| `jars/` | `APKREV_JARS` 指向的目录，放可直接运行的 `.jar`（apksigner、uber-apk-signer、baksmali/smali/dexlib2 等） |

## 用法

```powershell
. .\tools\env.ps1
python .\.agents\skills\apk-reverse\scripts\doctor.py
```

环境变量含义（由 skill 的脚本读取，见 `scripts/capabilities.py`、`scripts/smtool.py`）：

- `APKREV_TOOLS`：以 `;` 分隔的目录列表，脚本会在 `PATH` 之外再到这些目录里找可执行文件（adb、apktool、jadx、frida、rizin、readelf…）。
- `APKREV_JARS`：`doctor.py` 搜索可运行 Java 工具的目录（签名器、smali 三件套等）。
- `APK_REVERSE_SMALI_CP`：`smtool.py` 读取的 smali/baksmali/dexlib2 classpath；未设置时回退到 `scripts/smali_cp.txt`。

## 建议的目录布局（按需创建，不装全局）

```
tools\
├─ platform-tools\        # adb / fastboot
├─ build-tools\           # zipalign / apksigner
├─ cmdline-tools\latest\bin\
├─ jars\                  # APKREV_JARS
└─ <其它解包后的工具目录>
```

把解包后的目录直接放进 `tools\`，`env.ps1` 会自动把它们加到 `PATH` 与 `APKREV_TOOLS`。
