# 银逝 — 本机 Agent 终端

纯本机运行的 AI Agent 终端，Python 单文件实现，工具全部本地执行，不依赖任何分布式组件。

> **⚠️ 内核级保护需要你自己准备驱动** —— 仓库**不包含**任何内核驱动或二进制。
> 详见下文 [内核级保护（PPL）](#内核级保护ppl)。不使用内核级保护时程序功能完整，
> 只是防护强度从「内核级」降级为「服务级 + 守护环」。

## 目录结构

```
银逝Mesh/
├── 启动银逝.bat          双击启动（UAC 提权 → Windows Terminal → 主程序）
├── README.md
└── src/
    ├── 银逝.py           主程序（Agent 内核 + 工具调度 + 插件系统 + 守护环 + PPL + 集成平台层）
    ├── plugins/          外挂工具插件（合并为单个 官方插件集.txt，[SCHEMA]/[CODE]/[MAP] 分段文本）
    ├── ppl/              内核驱动组件目录（**驱动本体不在仓库内**，需自行放入）
    ├── .aliases.json     命令别名配置
    └── 管家拦截.vbs      静默启动脚本
```

## 启动

双击 `启动银逝.bat`。它会请求管理员权限（保护层需要），然后在 Windows Terminal
中启动主程序。若未安装 Windows Terminal，会回落到普通 cmd 窗口。

也可以直接运行：

```powershell
python src\银逝.py            # 正常运行（会自行请求提权）
python src\银逝.py --no-admin # 不提权（防护降级，功能不受影响）
```

启动序列（乱码风暴 + 自检动画）经过统一延时压缩（`BOOT_DELAY_SCALE = 1/6`），约 2~3 秒进入交互。清屏使用 ANSI 转义（零子进程）。

## 核心架构

| 模块 | 说明 |
|---|---|
| `ToolCallingAgent` | Agent 内核：对话循环、工具调用、记忆 |
| `ToolScheduler` | 注册-索引-路由三段式统一调度 |
| 动态调度 | 目录层（全量名单）+ 可见层（核心+激活 schema）+ 激活层（tool_search / tool_catalog / tool_activate） |
| 插件系统 | `plugins/` 目录热加载，支持 `self_write_plugin` 运行时自写插件 |
| 守护环 | A/B/C 三个守护子进程 + 心跳判活，异常时自动复活 |
| PPL 层 | 内核级进程保护（需驱动，见下文） |
| 集成平台层 | `MeshPlatform` 能力网络、DAG 编排、有界收敛自愈、版本化扩展、目标驱动自治 |

## 防护层级

程序启动后自动开启防护，共三层，各自独立实测、任一层失效不影响其余层：

| 层 | 机制 | 失效后果 |
|---|---|---|
| 服务级 | Windows 服务常驻（`--service-managed`） | 需管理员令牌；无服务时回落进程级 |
| 守护环 | A/B/C 三个守护子进程，5s 心跳，40s 判失效 | 主进程被杀后可被复活 |
| 内核级 PPL | 驱动给进程打 Protected Process Light 标记 | 需驱动；不可用时前两层仍然生效 |

面板上三行分别显示，由 `_tui_guard_layers()` 逐层实测，不做任何硬编码。

**退出保护**：创建文件 `C:\NeuralMemory\auto_guard_off.signal` 后再启动，可跳过自动开启。

## 内核级保护（PPL）

### 为什么需要驱动

「内核级 PPL」这一层依赖一个**能读写任意内核内存**的驱动。Windows 从 Win10 1607 起
引入了 Protected Process Light 机制，普通进程即便提权也无法被调试或注入——除非它自己
就是 PPL 进程。**给进程打上 PPL 标记的唯一用户态途径，就是通过这类内核驱动。**

没有驱动时，前两层（服务级 + 守护环）依然工作：主进程仍会被守护环复活，
但保护级别停留在普通提权进程，面对内核级工具或强制终止手段时更容易被剥离。

### 仓库为什么不带驱动

`src/ppl/` 需要的 `RTCore64.sys` 是 **MSI Afterburner 附带的第三方驱动，公开利用编号
CVE-2019-16098**（任意内核内存读写）。**分发它有法律风险与滥用风险**，因此：

- 仓库只保留**调用代码**（`银逝.py` 的 `ppl_*` 系列函数）与**安装说明**（本节）；
- `src/ppl/` 下只有 `加白RTCore64.ps1`（杀软白名单脚本）入库，
  驱动与 `PPLcontrol.exe` 被 `.gitignore` 排除；
- 克隆仓库后 `src/ppl/` 是空的，**必须自行放入驱动**，否则 PPL 层自动跳过。

### 已知限制

| 限制 | 表现 |
|---|---|
| **Windows 版本** | Win10 1607 及以后默认启用 **HVCI / 内核代码完整性** 与 **易受攻击驱动阻止列表**，该驱动**无法加载**。`ppl_driver_install()` 会返回「驱动启动失败（新版 Windows 可能已封锁此漏洞驱动）」 |
| **签名要求** | 驱动须签名。Win10 1607 之前的版本任何签名均可；之后需受信任的签名，或关闭 Secure Boot |
| **内存完整性** | 若 BIOS/UEFI 中开启 Intel Memory Integrity（内存完整性 / HVCI），加载即失败 |
| **杀毒软件** | Defender / 360 / 火绒等会把该驱动判为危险并隔离或拦截加载 |
| **PPL 生效需重启** | 保护标记在进程创建时判定。对已运行进程补打标记需重启目标进程 |
| **仅 64 位 / 特定版本** | 驱动为 x64，且 EPROCESS 结构偏移随Windows 版本变化 |
| **内核级灭杀（L3）需额外校准** | 内核终结通道需驱动可加载 + EPROCESS 偏移通过运行时自测，否则自动禁用并降级回用户态 |

### 安装步骤

**1. 取得驱动**

从 [CVE-2019-16098 的公开资料](https://nvd.nist.gov/vuln/detail/CVE-2019-16098)
或其原始出处（MSI Afterburner 安装包内的 `RTCore64.sys`）获取。
本项目不提供下载，也不校验其完整性 —— 请自行确认来源可信。

**2. 放入目录**

```
src/ppl/
├── RTCore64.sys        ← 你自己放入
├── PPLcontrol.exe      ← 你自己放入（PPL 标记工具）
└── 加白RTCore64.ps1    ← 已在仓库中
```

> 程序运行时会自动把这两个文件从 `src/ppl/` 同步到 `C:\pplwork\`（ASCII 安全路径，
> 避免中文路径导致的驱动加载问题），无需手动复制。

**3. 关闭阻碍项**（按需，取决于你的系统）

```
# 关闭内存完整性（HVCI）——必须重启生效
#   设置 → 隐私和安全性 → 安全性 → 设备安全性 → 内核隔离 → 关闭「内存完整性」
```

若要使用「内核级灭杀（L3）」通道，还需确认 EPROCESS 偏移能通过运行时自测。

**4. 杀软加白**

右键 `src/ppl/加白RTCore64.ps1` →「使用 PowerShell 运行」（需管理员）。

脚本会处理 Defender 的目录/文件排除项，并对 360、火绒给出手动操作路径。
注意脚本内的目标目录是 `C:\pplwork`（程序实际使用的同步目录）。

**5. 安装并启动**

程序启动时会自动执行；也可在对话里让 Agent 调用，或直接命令行：

```powershell
sc.exe create RTCore64 type= kernel start= demand binPath= C:\pplwork\RTCore64.sys DisplayName= "Micro - Star MSI Afterburner"
net start RTCore64
sc.exe query RTCore64      # 应显示 STATE : 4  RUNNING
```

驱动以 **demand（按需）** 模式安装，**不设开机自启**，退出即失效。

**6. 清除**

```powershell
net stop RTCore64
sc.exe delete RTCore64
```

或在对话里让 Agent 调用清除动作。守护环停止时会自动清除。

### 安全边界（代码层强制）

内核通道被刻意窄化为**两条防御性通路**，其余攻击面从源头阉割：

- **只封装**：`read_mem`（只读取证）、`write_mem`（写 EPROCESS 强制终止）
- **刻意不实现**：MSR 改写、IO 端口、Token 窃取、内核回调清零、IA32_LSTAR 劫持
  —— 这些是反 EDR / 提权 / rootkit 的攻击面，不提供
- **强制黑名单**：所有 EDR/AV 进程与系统关键进程（`csrss` `wininit` `lsass` `smss`
  `services` `system` `winlogon` 等）永不终结，触碰即拒并写审计
- **有界降级**：驱动不可用或偏移未校准时自动禁用内核通道，逐级回落到 PPL → 普通提权，
  绝不盲写内核
- **全程审计**：所有调用落 `src/plugins/kernel_kill_audit.jsonl`（仅追加）

## 工具执行轻量化

- **单行日志**：`_ToolCallLog` 只显示调用了什么工具（不带参数），始终占一行，新的把旧的挤出
- **并行执行**：同一轮多个 tool_calls 并发执行（`_execute_tool_round`，上限 4 并发），保持返回顺序
- **快工具直连**：`FAST_DIRECT_TOOLS` 白名单内的元工具零包装直接同步执行
- **慢工具转后台**：执行超过 `BG_OFFLOAD_THRESHOLD_S`（0.25s）立即转后台任务，绝不阻塞对话输出，完成后自动注入结果

## 本机能力工具

| 工具 | 说明 |
|---|---|
| `local_monitor_snapshot` | 本机实时快照：CPU/内存/磁盘/网络/进程TOP（psutil，纯本地） |
| `local_index` | 本地文件索引：`build` 建索引 / `search` 关键词检索（含命中片段）/ `stats` 状态 |

两者均有独立配置块（`LOCAL_MONITOR_CONFIG` / `LOCAL_INDEX_CONFIG`），可开关与调参。

## 插件格式

```text
[SCHEMA]
{"type":"function","function":{"name":"工具名","description":"...","parameters":{...}}}

[CODE]
def _工具名(self, arg: str) -> str:
    ...
    return result

[MAP]
工具名: _工具名
```

- 全部插件合并在单一文件 `plugins/官方插件集.txt`（加载器同样支持 `.plugin/.pyplg/.tool/.ext`
  扩展名）。加载器按 `[SCHEMA]` 用 `raw_decode` 循环解析、按 `[CODE]` 整体编译执行、按 `[MAP]`
  绑定方法，等价于原多文件加载。工具名取自 `function.name`，与文件名无关
- 如需新增/修改工具，直接编辑该文件对应分段，或让 Agent 用 `self_write_plugin` 自写
  （长期=写入 `plugins/` 新文件，短期=仅内存）
- 加载失败的插件会在启动时明确列出（`[PLUGIN][WARN]`），不再静默跳过

## 配置

主配置在 `src/银逝.py` 顶部：`CONFIG`（API/模型）、`AUTONOMOUS_CONFIG`（自主模式）、
`MULTIAGENT_CONFIG`（子 Agent 编排）、`DYNAMIC_SCHED_CONFIG`（动态调度）。

### 凭据配置（必读）

**API key 不在源码里，也不应提交到版本库。** 首次使用请任选一种方式配置：

**方式一：本机配置文件（推荐，GUI 里也能改）**

程序启动时自动加载 `C:\NeuralMemory\config_settings.json`（文件不存在则跳过，留空凭据）。
手动创建该文件并写入：

```json
{
  "api_key": "sk-你的密钥",
  "model": "deepseek-v4-flash",
  "base_url": "https://xh.v1api.cc/v1",
  "temperature": 0.7,
  "max_tokens": 4000,
  "stream": true
}
```

也可以在程序里输入 `api key <值>`、`api model <值>`、`api url <值>` 热更新，
程序会**自动创建**该文件并落盘。


**方式二：环境变量**

```powershell
setx YINSHI_API_KEY "sk-你的密钥"
```

优先级：环境变量作为源码默认值 → 配置文件覆盖（配置文件中没有`api_key` 字段时不覆盖）。

> `src/银逝.py` 中的默认值读自环境变量，未设置时为空。**若启动后提示未配置凭据，
> 说明配置文件与环境变量都没有提供 key** —— 这比启动时才带着一个别人的 key 去连API
> 要好得多。


## 离线自检

全部自检短路在 `main()` 之前，不联网、不触碰真实系统状态：

```powershell
python src\银逝.py --recon-self-test          # 插件/工具目录
python src\银逝.py --mesh-self-test            # 集成平台层
python src\银逝.py --ecology-self-test         # 生态层 + 生理层 + 递进链
python src\银逝.py --entity-self-test          # 存在层自我模型
python src\银逝.py --kernel-self-test          # 内核通道封装
python src\银逝.py --kernel-kill-self-test     # 内核灭杀红线
```

## 环境要求

- Windows（用到服务、`sc.exe`、PPL 等 Windows 专属机制）
- Python 3.10+
- 可选依赖：`psutil`（本机监控/索引，缺失时相关工具自动禁用）、`requests`、`pywin32`

## 安全声明

本项目用于**本机防护与自主运维**。它会请求管理员权限、注册 Windows 服务、
并可选加载一个存在已知漏洞的内核驱动。请仅在你信任的机器上使用，并理解：

- 授予管理员权限意味着 Agent 可执行任意系统操作
- 内核驱动一旦加载，即具备读写任意内核内存的能力
- 分发本仓库**不包含**任何驱动二进制；使用者需自行评估法律与合规风险
