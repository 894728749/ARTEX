# ARTEX runtime integrations 交接手册

**交接包：** `ARTEX-runtime-handoff-v0.4.0`  
**核心版本：** ARTEX v0.4.0，commit `bcfced88b666c69e8dbdce60ca986ea601d35b94`（`bcfced8`）  
**目标环境：** WSL Ubuntu/Linux 运行 MCP 与隔离浏览器；Windows 仅用于独立、临时的隐私探测辅助程序。

## 1. 交接状态与适用范围

来源机安装的 ARTEX 核心二进制与已核对的 GitHub Release v0.4.0 一致，未发现额外 core runtime 本地补丁。本交接包不附核心二进制。集成脚本是单独参数化的本地副本，清单和哈希见 `SOURCE-MANIFEST.json`、`PORTABILITY.patch`、`MANIFEST.json` 与 `SHA256SUMS`。源版本证据见 `SOURCE-VERSION.json`。

当前脱敏配置快照记录 16 个已启用 Agent 和 11 个 MCP 项，其中 8 个 MCP 启用。它只用于了解来源机配置和做差异核对。协作者已有的 9 个 Agent 已导入：不要重录，也不要自动全量覆盖。只有在逐项审阅后才选择性导入/调整；不要把来源机的历史提示词、触发器、工具绑定或用户授权视为协作者的新授权。

来源机在导出时没有启动 ARTEX 服务或任务；PG 通过只读事务读取后回滚，原数据库状态已恢复。`routing-state.sanitized.json` 是配置快照，不是连通性或出口测试：来源机记录 Tor marker 关闭、浏览器代理不是 Tor。新环境应独立检查自己的运行状态。

本包不包含虚拟环境、`node_modules`、浏览器二进制、任务日志、数据库、密钥、Cookie、Tor 状态或种子。不要从别处复制这些数据到协作者环境。

## 2. 获取与核对核心源码

在 WSL 中克隆固定仓库并检出记录的 commit：

```bash
git clone https://github.com/cyy081021/ARTEX.git
cd ARTEX
git checkout bcfced88b666c69e8dbdce60ca986ea601d35b94
git status --short --branch
git rev-parse HEAD
```

本包不提供 ARTEX 核心二进制。协作者从上述固定 commit 构建或取得对应 Release 二进制后，应依据 `SOURCE-VERSION.json` 中记录的 SHA-256 与实际文件计算值比对；不要以版本字符串代替哈希核对。没有 core patch 需要套用；集成目录中的 `PORTABILITY.patch` 只供审阅集成脚本的可移植性修改，不能当作 ARTEX 核心补丁。

## 3. WSL 环境与本机配置

MCP 主环境使用 WSL Ubuntu/Linux。先从模板建立本机私有环境文件，并按模板中的注释填写；不要提交或共享填写后的文件：

```bash
cp integrations/runtime.env.example integrations/runtime.env
$EDITOR integrations/runtime.env
```

按需填写变量（具体默认值和是否必填以模板为准）：

- `ARTEX_RUNTIME_ROOT`：本机实际 ARTEX runtime 根目录，必须指向协作者自己的实例。
- `ARTEX_SOURCE_ROOT`：检出的 ARTEX 源码目录。
- `ARTEX_INTEGRATIONS_ROOT`：默认由脚本推导；只有安装位置不同时才覆盖。
- `ARTEX_API_BASE`：本机 API 地址，默认 `http://localhost:8787`。
- `ARTEX_NODE`、`ARTEX_JAVA`：本机 Node.js 与 Java 命令。
- `ARTEX_POWERSHELL`、`ARTEX_WINDOWS_CURL`、`ARTEX_WINDOWS_NODE`：WSL 调用 Windows 工具时的可执行文件路径。
- `ARTEX_WINDOWS_INTEGRATIONS_ROOT`、`ARTEX_PRIVACY_COLLECTOR`：Windows 可访问的 integrations 和 collector 路径。
- `ARTEX_PRIVACY_CHROMIUM`：隔离探测浏览器路径；脚本支持自动发现锁定版本的浏览器。
- `ARTEX_WINDOWS_EDGE`：Windows Edge 可执行文件，默认使用标准安装位置。
- `ARTEX_WSL_DISTRO`：WSL 发行版名，默认 `Ubuntu`。
- `ARTEX_WINDOWS_PROXY_PORT`：WSL 可达的 Windows 代理端口，默认 `7897`；`ARTEX_PROXY_WAIT_SECONDS` 默认 `90`。
- `ARTEX_BURP_PROXY_JAR`：可选 Burp 组件路径；默认位置是 `integrations/vendor/burp/mcp-proxy-all.jar`。本包不带该 jar。

`ARTEX_MCP_*` 命令行值及远端服务凭据须由协作者按模板和目标部署单独提供。模型 API 凭据也由协作者自行设置。本包不携带任何凭据。API helper 会读取目标 runtime 的本机 `jwt.key`；该 key 应在本机生成或由本机安装流程管理，绝不共享。不要让 API helper 读取不可信 runtime、配置或脚本。

## 4. 安装依赖与启动 MCP

在 WSL 仓库/交接包目录中按需安装系统前置依赖，然后安装脚本列出的 Python/Node 依赖：

```bash
bash integrations/setup-dependencies.sh
```

脚本应在 WSL/Linux 运行。`python-requirements.lock.txt` 是实际完整 Python 锁文件；`requirements-core.txt` 是依赖摘要，不作为完整安装锁。Node 依赖按包锁文件使用 `npm ci`；Playwright 浏览器使用锁定版本安装。Linux 系统库需由本机包管理器另行安装。当前本机隔离验证复用了已有依赖，没有做全新安装。合作方需要准备依赖时，运行上述安装脚本会建立 Python venv、按完整锁安装 Python/Node 依赖并安装锁定 Chromium；脚本不导入 profile，也不启用或启动 Agent/MCP/任务。33 项合成单测通过；6 个本地 MCP 握手通过，browser MCP 握手及本地合成页导航也通过，MCP 握手共 7 项。未运行 Windows Edge 隐私探测；未调用真实模型，也未做对外出口探测。依赖下载、合作方实机启动与真实联网验收尚未完成；不要把本机合成验收扩展成合作方运行结论。

各本地 stdio MCP 由统一 launcher 按 mode 启动。launcher 会读取 `integrations/runtime.env`，随后加载 `integrations/bin/runtime-env.sh`：

```bash
bash integrations/bin/mcp-launch.sh planning
bash integrations/bin/mcp-launch.sh files-readonly
bash integrations/bin/mcp-launch.sh files-workspace
bash integrations/bin/mcp-launch.sh git-readonly
bash integrations/bin/mcp-launch.sh privacy
bash integrations/bin/mcp-launch.sh semgrep
bash integrations/bin/mcp-launch.sh browser --proxy-server "http://<WSL可达Windows代理地址>:7897" --proxy-bypass "localhost,127.0.0.1,::1"
```

launcher 还提供 `fetch`、`memory`、`burp` mode；这些模式存在不代表它们已启用或具备本机依赖。按需运行前，先配置并评估参数和权限。Burp 需本机另备可用 jar；不会由依赖脚本自动下载或启动 Burp。

`ScopeSentry` 是远端 HTTP MCP，不属于本地 launcher mode。脱敏快照显示该项 `enabled=true`，但 `url` 为空，因此不能认为来源机已配置可用服务。协作者需自行配置可用远端 URL 和凭据，并确认其数据处理和授权范围；脱敏快照不含可复用的远端凭据。不得把来源机的外部服务访问权限视作协作者的访问授权。

### 配置快照中的 MCP 启用状态

| MCP | 来源机状态 | 协作者侧说明 |
| --- | --- | --- |
| `ScopeSentry` | 启用，HTTP | 来源机虽标为 enabled，但脱敏快照的 URL 为空；协作者需自备远端服务、URL 与凭据，本包不能复用来源机访问权。 |
| `artex-burp` | 禁用，stdio | 不自动启用；若确需使用，需自备组件并独立评估权限。 |
| `artex-fetch` | 禁用，stdio | 保持禁用，除非协作者明确需要并自行审阅网络访问范围。 |
| `artex-files-readonly` | 启用，stdio | 仍受本机账户、挂载目录和配置约束。 |
| `artex-files-workspace` | 启用，stdio | 工作区工具可能写入；限定其工作目录并由协作者确认。 |
| `artex-git-readonly` | 启用，stdio | 名称/应用策略不替代操作系统隔离。 |
| `artex-memory` | 禁用，stdio | 不自动启用。 |
| `artex-planning` | 启用，stdio | 使用本机安装的依赖。 |
| `artex-privacy-local` | 启用，stdio | 隐私探测仍须按当前任务授权范围使用。 |
| `artex-semgrep-local` | 启用，stdio | 离线规则扫描工具；只向它提供获准的代码材料。 |
| `browser` | 启用，stdio | 代理需在目标 MCP 配置 args 显式传入；先确认访问范围。 |

上表反映 `profile.current.sanitized.json` 中的来源机声明状态，不代表协作者目标实例已导入、启用、启动或通过连接测试。导入前逐个比较已有配置、工具名和协作者需要；先做备份，采用最小变更。

## 5. 代理与流量路径

来源配置记录 Windows 网关代理端口 `7897`。来源机的 Tor 标记为关闭，浏览器代理不是 Tor；这是来源快照，不应解释成新环境已完成联网探测。Tor 是可选的独立 HTTP 代理端口 `18118`，当前未启用。普通非 Tor 出口符合当前配置预期，不自动视作隐私故障。

`integrations/bin/proxy-env.sh` 仅为调用它的 shell/子进程准备代理环境，不修改 ARTEX 全局配置。需要对授权目标流量设代理时，使用 `integrations/bin/target-proxy-env.sh`，并在启动前核对目标代理地址、绕过列表和任务允许范围。不要把 shell 环境变量当作代理已生效的运行证据；分别验证实际进程、协议和目标范围。不要为了验证而擅自修改系统代理、VPN、路由或现有浏览器状态。

Browser MCP 的代理需像上面的示例一样放在该 MCP 的 args 中；仅 source 代理环境脚本不会替代 MCP 的显式浏览器参数。Windows Edge 隐私探测使用隔离临时 profile，是独立 probe，不是 Browser MCP 会话；该探测需本机 Windows Node.js 和 Edge。来源机导出没有做出口探测，因此这里没有任何关于新环境实际出口的结论。

## 6. Agent、触发器与工具范围

本包的 `mcp_gate.py` 会过滤上游 MCP 的 `tools/list`，并在 `tools/call` 时再次拒绝未列入白名单的工具。launcher 中实际白名单如下：

| Mode | 允许的工具 | 范围补充 |
| --- | --- | --- |
| `files-readonly` | `read_file`、`read_text_file`、`read_multiple_files`、`list_directory`、`list_directory_with_sizes`、`directory_tree`、`search_files`、`get_file_info`、`list_allowed_directories` | 上游收到 `ARTEX_SOURCE_ROOT`、`integrations/workspace/evidence`、`integrations/workspace/reports` 三个允许目录；仍受 OS 权限约束。 |
| `files-workspace` | 上述只读文件工具，加 `write_file`、`edit_file`、`create_directory` | 范围限定在 integrations/workspace。 |
| `git-readonly` | `git_status`、`git_diff_unstaged`、`git_diff_staged`、`git_diff`、`git_log`、`git_show` | 额外检查 repo path 必须位于 integrations/workspace。 |
| `semgrep` | `semgrep_scan_with_custom_rule` | 本地扫描；脚本描述限制输入代码/规则，不接受路径、URL、registry/account/API key/cloud scan。 |

`planning`、`privacy`、`browser` 等 mode 不经过这份文件工具白名单；各自工具能力以 MCP 自身实现与参数为准。`fetch`、`memory`、`burp`虽有 launcher mode，但在来源机快照中禁用。白名单属于应用层参数/工具过滤，不等于操作系统沙箱。

脱敏快照包含这些 16 个已启用 Agent：`auto`、`finding_reviewer`、`goals`、`information_checker`、`mainagent`、`pentest`、`planner`、`reporter`、`retester`、`worker`，以及 `reverse_dynamic`、`reverse_goals`、`reverse_main`、`reverse_planner`、`reverse_reviewer`、`reverse_static`。这只是来源机配置清单。协作者现有 9 个 Agent 不因本包存在就自动增加或覆盖。

快照中两条启用的 Agent 触发配置为：

- `information_checker`：任务创建事件触发一次隐私检查（`on_task_create=true`；未声明工具调用触发）。
- `reporter`：仅由 `report_finding` 工具调用触发（`on_tool_call=true`，工具列表为 `report_finding`；未声明任务创建触发）。
- 其余 Agent 在该快照中没有启用的触发配置。

这些是来源机的配置事实，不表示协作者环境已导入或授权同样的自动执行。协作者可按自身任务范围决定是否显式配置相应触发器；不要将来源机的测试范围或授权迁移为新目标的授权。

Agent 提示词、可见工具/MCP 绑定和工具启用位是应用层配置与约束；提示词表达的限制不是强制访问控制。工具的 `read_only`、名字或 Agent 角色也不是操作系统沙箱。MCP 进程和本地命令以运行它的 WSL/Windows 用户身份工作；实际可读写范围取决于该账户、文件权限、挂载点、容器/沙箱及进程参数。MCP gate 白名单只约束列出的本地上游调用，不为其他 MCP 添加门控。

团队协作代码要求显式派发，并检查任务权限、角色和设备能力；审核与执行由不同成员承担。运行时实际权限还受协作者本机系统账户与部署设置影响。

## 全局工具拦截与审批配置

来源机实际策略见 `approval-policy.sanitized.json`。该只读导出包含全局配置，不含 `intercept_pending` 审批历史/工具输入，也不含任务级目标规则或对应授权。`settings` 列表为空，故按 v0.4.0 代码默认：`intercept_enabled_tools` 默认只包含 Bash、WebFetch、web_search、shell_open、shell_send、Write、Edit、MultiEdit；LLM fallback judge 默认关闭（`llm_judge_enabled=false`），无自定义裁判设置。规则快照共 20 条，19 条启用，均为 `deny`；唯一禁用项是 `[内置] 数据外泄管道`。没有 `ask` 规则，也没有启用的自定义 LLM 审批配置。因此这份快照没有配置对这些工具调用一律人工审批的规则。

快照中的 pattern 已脱敏且标记需复核，不要把 `approval-policy.sanitized.json` 直接导入目标库。需要恢复默认规则时，应在固定 commit 的目标版本上由 ARTEX 内置默认规则生成，再对照 enabled 状态；不要从脱敏 pattern 重建规则。协作者环境仍应以本地数据库配置为准。

代码路径是：名单外工具跳过此 intercept；名单内工具先按优先级检查已启用规则，规则动作可以是 allow、deny 或 ask；无规则命中时才可能调用启用且已接入的 LLM fallback。fallback 未启用或未接入时保持该调用的原有行为（allow）。只有规则或裁判动作是 ask 时才建立待审批项并等待用户决策；超时按相应设置处理。

`mcp_gate.py` 的上游工具白名单、Agent/profile 中的提示词/约束、ARTEX 数据库的 intercept 规则是不同机制：前者筛选特定本地 MCP 工具名并限制部分路径/参数；提示词不构成访问控制；实际拦截是否发生及采用什么动作需读取该目标实例的数据库配置。协作者配置应以本机实际值为准。

## 7. 本机 secrets 与数据保护

- 在目标 ARTEX 实例本机生成/管理 `jwt.key`。不得复制来源机 key 或把 key 放入此交接目录。
- 模型 API key、ScopeSentry 凭据、代理凭据、MCP 环境变量由协作者独立配置在本机 secret store 或受限环境文件中；不要写入 Git、profile 或共享日志。
- 不复制数据库、任务数据、运行日志、浏览器配置、Cookie、Tor 状态或用户目录。
- 只将明确授权、必要的合成或脱敏材料提供给本地 MCP。特别是 browser、fetch、Burp 和隐私工具均应按其真实副作用与本机账户权限审阅。

## 8. 验收状态与待办

交接材料提供参数化脚本、完整依赖锁文件、源清单及哈希，供协作者本机安装和核对。`VALIDATION.json` 记录了本机隔离验证结果：33 项合成测试、6 项本地 MCP 握手，以及 browser MCP 握手与本地合成页导航通过（共 7 项 MCP 握手）；使用既有依赖，没有声称干净安装。测试没有调用生产 API、真实模型或外部探测。Windows Edge 隐私探测未运行。合作方实机启动、依赖下载及远端 ScopeSentry 可达性仍未验收。

协作者完成本机配置后，应分别记录：检出的 commit/二进制哈希、依赖安装结果、需要启用的 MCP 及其握手结果、browser 实际代理参数、最小合成调用结果、失败项及其环境边界。不要把配置快照、launcher 存在、进程启动成功或单次 HTTP 可达性描述成完整运行验收。

## 参考

- [本地配置 profile 同步](https://github.com/cyy081021/ARTEX/blob/bcfced88b666c69e8dbdce60ca986ea601d35b94/docs/%E6%9C%AC%E5%9C%B0%E9%85%8D%E7%BD%AE%E5%90%8C%E6%AD%A5.md)：profile 导入、占位变量与部署边界。
- [Agent 与 MCP 执行和权限说明](https://github.com/cyy081021/ARTEX/blob/bcfced88b666c69e8dbdce60ca986ea601d35b94/docs/team-execution.md)：显式派发、成员权限和 OS 隔离限制。
- [逆向角色与跨流程协助](https://github.com/cyy081021/ARTEX/blob/bcfced88b666c69e8dbdce60ca986ea601d35b94/docs/%E9%80%86%E5%90%91%E8%A7%92%E8%89%B2%E4%B8%8E%E8%B7%A8%E6%B5%81%E7%A8%8B%E5%8D%8F%E5%8A%A9.md)：逆向六角色与跨流程边界。






