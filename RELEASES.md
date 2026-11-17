# 发布说明

本文记录本仓库版本标签及开发期间的 `main` 更新，按版本演进倒序记录新增功能、修复、验证结果和兼容边界。最新版本为 **v0.7.0**；下方 `main` 条目保留本次发布前的开发和本机验收记录，其中“未发布”指各条记录当时的状态。`artex-*` 是历史源码里程碑，未发布独立二进制下载包，不参与在线更新。下载以 [ARTEX Releases](https://github.com/cyy081021/ARTEX/releases) 的实际资产为准。

日期和时间均按北京时间（UTC+8）记录，区分源码快照、标签建立和 Release 发布时点。本文于 2026-11-10 补齐历史说明，保留原标签指向；下面的测试结果属于各版原验收记录，不表示本次重新运行了历史测试。上游 0.3.15 及更早的继承记录保留在 [CHANGELOG.md](CHANGELOG.md)，不代表本仓库另有对应正式 Release。研发过程中的“v2”是内部迭代名称，首个公开协作标签为 `artex-collaboration-v1`。

<a id="v070"></a>

## `v0.7.0`

日期：2026-11-17。本版加入自动任务分流、Linux x86-64 原生分析与本地重放，以及默认关闭的 AFL++ 最小闭环；修复 GDB 正常退出与 EOF 并发时的误判。新建附注标签，原有版本标签不变。

### 实现功能

- **自动任务分流**：创建任务时可以不预选具体方向；`kind:auto` 由已配置模型按描述、目标和材料元数据判定主工作流及能力，实际任务种类仍兼容 `pentest` / `reverse`。分类失败明确报错；新逆向任务暂停等待材料和运行授权。分类不能替代执行授权。
- **Linux x86-64 原生分析**：ELF 架构和保护信息、符号与依赖静态检查；Docker 隔离的二进制 stdin/stdout 多步会话；类型化 GDB/MI 的运行、断点、单步、继续、中断、寄存器、栈、内存、模块和有界 core 读取。GDB 队列和 EOF 采用原子快照，正常终止记录优先于连接关闭判断。
- **案例、重放与独立复核**：不可变 NativeCase、NativeReplayPlan v1/v2、stdin/文件输入、任务内依赖/loader/Python harness；绑定样本和附件哈希、固定镜像、策略修订。支持 n/N 重复验证及限定目标输出断言的有界最小化。独立审核者重放后进入 Finding，支持证据快照、导出、归档和恢复；harness 输出不冒充目标影响。
- **AFL++ 最小闭环**：`native_fuzz` 提供 `run`、`list`、`import_candidate`、`replay_candidate`，仅动态分析角色可调用。支持已插桩 ELF 的 stdin 或精确文件占位输入，单 worker 同步执行；按时间、执行数、内存、输出盘和候选数量限制运行，确认取消、超时与 owned 容器清理。结果保存为候选，显式独立重放后才能进入后续审核，不自动创建 Finding。
- **兼容与证据修复**：数据库运行模式兼容扩展 `fuzz`，保留原 exec/debug/replay 记录；旧 `native_inspect` 角色权限保留；session 与 fuzz 证据大小上限分离，超限请求与响应生成一致的失败证据。修复工具探测阶段取消被误记为失败的问题。
- **交付材料**：ZIP 包含 native runner、默认关闭的 profile 示例、实验环境材料及原生/Fuzzing/验收说明。已有模型凭据、配对和运行配置处理方式不变。

### 验证结果

- 最终隔离候选 16 文件哈希核对后合入。合入后 Linux Python 132/132 通过；Windows 122 通过、10 项平台跳过。GDB 确定性交错 200 次回归证据沿用已验收候选，组合单测包含对应回归。
- 合入后 Go/独立 PostgreSQL 定向回归 87 个顶层测试通过（含子测试 257 通过、5 个 opt-in 跳过）。AFL 和原 native/GDB 两条真实链路另行启用，2 个顶层及合计 6 个测试/子测试通过，0 跳过。另三项逆向引擎/Hermes/浏览器条件测试本轮未执行，未计作通过。
- 合入后真实 AFL 容器测试 5/5 通过，包括 stdin/file campaign、crash 独立重放、未插桩拒绝和取消清理；已有 8/8 启动取消及最终组合材料保留。测试仅使用本地合成样本，没有运行真实产品目标或调用真实模型。
- Linux 与 Windows amd64 构建、自动更新包测试、发布脚本语法检查通过。前端源码沿用此前已通过的静态构建，标签流水线重新构建前端和五平台程序包。交叉编译及 ZIP 校验不等于所有平台完整运行验收。

### 配置和保留限制

- Native 与 Fuzzing 均需管理员准备实验环境、固定 image ID/digest 并授权任务材料和时长；`enabled` / `fuzz_enabled` 示例默认 false。AFL 只验证本地 Debian AFL++ 4.04c，普通 native 镜像不保证含 AFL++。本版不自动安装、拉取、启用或发布该实验镜像；主程序 GHCR 镜像与实验镜像不同。
- 暂无持久后台 campaign 恢复/队列、多 worker、QEMU/Frida binary-only、网络服务 tube、完整交互 GDB TTY、自动 ROP/堆利用或自动 Finding。AFL stats/map、崩溃和 sanitizer 观察都不直接证明覆盖率、真实产品漏洞或可利用性。
- 本地镜像运行通过不代表仓库 native Dockerfile 的在线 apt 重建已通过；传递依赖未全部锁定。此次也不是原设计 N01–N15 全矩阵或 ARTEX 全功能验收；额外场景与跳过项见验收说明。
- 本次发布不自动升级或重启已有业务实例。已有部署需同步其 profile 实际引用的 Python runner；保留已有配置，不用示例覆盖当前环境。

说明：[原生分析与重放](docs/native-linux-workflow.md)、[AFL++ 最小闭环](docs/native-fuzzing.md)、[验收范围](docs/native-release-validation.md)。下载：[v0.7.0 Release](https://github.com/cyy081021/ARTEX/releases/tag/v0.7.0)。主程序镜像：`ghcr.io/cyy081021/artex:v0.7.0`。

<a id="v060"></a>

## `v0.6.0`

日期：2026-11-11。本版汇总 `v0.5.0` 之后的团队接入、自动协作、成员原生任务界面和逆向连续交互更新。新建附注标签，旧版本标签保持不变。

### 新增与修复

- **接入与配置自动化**：主端准备、成员接入包、设备状态组成接入向导；刷新网络检测时更新本机地址并废弃过期访问计划。协作配置自动读取主任务目标、资产与成员设备能力，核对确认后即可启用，不再手填工具能力键。
- **自动分工与复核**：协调器按已确认范围、设备能力和空闲状态安排工作；独立核验后自动接收证据充分的结果，疑点进入人工复审。启用协作后保持暂停，显式开始才执行；旧手动项目保留原配置。
- **成员复用原任务界面**：共享任务直接使用原会话布局、左侧分组、状态图标及 Markdown 渲染，探索图、发现、漏洞关系、复测、资产、审批记录、报告和逆向档案复用原栏目。跨设备消息指导、执行端编号和分页保留，查看与操作仍按成员权限判定。
- **Android 连续逆向交互**：同一 Frida 会话内启动应用、读取 UI 树和截图、点击、输入、按键、滑动并观察方法参数与返回；每步证据持久保存。停止、取消、超时和 Worker 退出时清理，意外断开、清理或写库失败明确报错，结束后的新动作不误报成功。
- **浏览器逆向场景**：复用 REA 6.8.0，在隔离浏览器内执行多步交互并保存页面、截图、网络和控制台证据。每次调用建立新上下文，显式起始页和导航来源由环境配置限定；登录密码可引用管理员配置的密钥编号。
- **工作流修复**：分支提示词与实际 Node 工具、提交方式及自动核验模式对齐；操作规则不再误作资产白名单。已知系统默认 Planner/Reporter 提示词与续做工具描述同步，自定义配置保留。工作中断后可按已保存检查点或证据最多自动续做三次，兼容内容一致的新旧完成回执。

### 升级与兼容

- 主端与成员 Node 建议一并升级；自动协作和分支协议纠偏需要新版 Node。已有配对、模型凭据和自定义配置保留，不需要重新录入。
- 运行时授权上限扩展为 100 毫秒至 900 秒，数据库原授权值不自动提高；旧 Windows/Linux/Android 一次性观察接口仍最多 60 秒。持续交互针对 Android，浏览器场景不代表完整 Electron 桌面控制。
- Android、Frida、REA 与 Chromium 使用管理员已配置环境，ZIP 包含运行脚本和配置示例，不自动安装全部逆向引擎。已有部署除更新主程序外，还需同步其 profile 实际引用的 `scripts/reverse_runtime.py`；浏览器首次使用需配置允许来源。
- 检查点是续做信号，不能替代独立证据复核或主任务验收。静态分析、运行观察和已验证结论保持区别。

### 已完成的功能验证与已知限制

- 发布前合并专项 Go `-race` 回归：103 个测试及子测试通过、3 个条件测试跳过；各包使用独立数据库。Python 6 项测试通过，前端生产静态构建和类型检查通过。
- 自制 Android 15 和网页样本实际完成连续输入/点击、方法返回或网络响应、截图与证据保存，并验证独立意图复核及报告链路；Android 超时、取消、EOF 的清理另行通过。未运行现有业务任务。
- 自动协作与连续规划分别通过真实 Node 子进程、本机 TLS 服务和假模型闭环；成员原生界面、Markdown、历史分页与指导在隔离浏览器验证。上述结果不代表真实模型效果或第二台实体设备网络验收。
- 五包完整 race 回归有 924 项通过、2 项修改前也可复现的失败、14 项条件跳过。已知失败为资产继承测试的 `coverage.scope=nil`，以及复测测试清理与后台 Worker 全局工具钩子的竞态；本版没有宣称完整测试全绿。
- 正式五平台程序包、校验文件及双架构镜像由此标签触发发布流水线生成。开发记录中的 `0.5.0-*` 包、哈希和本机版本属于当时的预发布验收，不等同于 `v0.6.0` 正式产物验证。

下载：[v0.6.0 Release](https://github.com/cyy081021/ARTEX/releases/tag/v0.6.0)。镜像：`ghcr.io/cyy081021/artex:v0.6.0`。使用说明：[团队自动协作](https://github.com/cyy081021/ARTEX/blob/v0.6.0/docs/team-auto-collaboration.md)、[成员接入](https://github.com/cyy081021/ARTEX/blob/v0.6.0/docs/team-onboarding.md)、[逆向交互](https://github.com/cyy081021/ARTEX/blob/v0.6.0/docs/reverse-interactive-workflow.md)。

<a id="main-unreleased"></a>

## `main`（未发布，2026-11-11）

本轮为 `main` 上的协作可用性修复，不创建新 tag 或 Release。当前正式版仍是 `v0.5.0`。

### 逆向连续交互与工作流修复（2026-11-11）

- 新增 `reverse_runtime_session`，支持 Android 上连续启动应用、读取 UI 树与截图、点击、输入、按键、滑动，并在同一 Frida session 中观察调用及方法参数。结束、取消、超时和 Worker 退出时自动清理；Android 设备同一时刻由一个持续会话占用。原 `reverse_observe_runtime` 一次性观察仍最多 60 秒。
- 新增 `reverse_browser_scenario`，复用 REA 6.8.0 的隔离浏览器启动方式，在一次调用内执行原生多步页面动作并采集 DOM、截图、网络与控制台证据。每次调用创建新上下文；场景来源和显式导航目标受管理员配置的 `allowed_origins` 限制。
- 静态定位、动态交互、证据保存和独立 Reviewer 形成连续工作流；Reviewer 将证据充分且结论明确的结果标记为接受或拒绝，将证据不足、冲突或无法复现的结果保留为未决。保存的检查点可作为后续续做的进展信号，但不是已独立复核的成果，也不代表任务成功。
- Runtime policy 保留已有授权值；用户可显式设置 100 毫秒至 900 秒的最大观察时长。任务截止时间或实际 Worker 预算可更早终止执行。新 Node 获得分支工具与提交协议的运行期纠偏；已配对 Node 保持原配对关系。
- 分支使用对应职责与当前节点实际工具列表，避免调用主端专用接口；自动核验模式不再要求额外人工逐项接受。操作规则不再被误当作资产白名单；已知系统默认 Planner/Reporter 与续做工具说明自动同步，自定义配置保留。中断工作可在保存新检查点或证据后有界续做，最多三次；兼容内容一致的新旧完成回执。
- 意外调试断开、临时 UI 文件清理失败、最终状态写库失败会明确报告错误；会话结束后继续发来的点击不会被误报为已执行。安装包包含运行脚本、环境配置示例与交互指南。

验证结果：

- 使用自制合成 Android 与网页 fixture 验收。REA 6.8.0 浏览器实际完成 fill、click，并捕获网络响应、console 和 DOM；Android 15 在同一 Frida session 中完成输入、点击、snapshot 与方法参数保存，并通过独立意图接受报告链路。该流程使用合成 fixture，不代表真实模型任务验收。
- Android timeout、cancel、EOF 后的清理分别在隔离模拟器中验证，包已移除；Python 6 项 mock 测试通过。最终合并后的 Go `-race` 针对性回归为 103 个测试及子测试通过、3 个需显式启用的测试跳过。各包使用独立数据库，避免全局归档队列被其它夹具占用；真实引擎两项验收另行启用并通过。前端生产静态构建及类型检查通过。
- 针对性命令：`go test -race -p 1 ./server ./db ./agent ./collab ./cmd/artex-node -run 'TestReverse|TestInvokeReverseRuntime|Test(BranchPrompt|ConstraintRules|BranchToolProtocol|AutomaticWorkRetry|RetryProgress|AcceptanceCompatible|ReporterPromptSync|RetryToolDescriptionSync|BranchSetup|BranchPlannerProposes)' -count=1`，实际按包分开执行并分别配置隔离 `ARTEX_PG_DSN`；Python 为 `python -m unittest scripts.test_reverse_runtime -v`。实际引擎验收为设置合成材料清单后的 `go test ./server -run '^TestReverseRealEngineAcceptance$' -count=1`。
- 提示词与工作流侧补丁另有 37 项针对性测试通过、1 项预览跳过；真实 Node 子进程与本机假模型的两项协作闭环验收通过。五包完整 race 回归为 924 项通过、2 项已确认基线失败、14 项条件跳过：资产继承测试 `coverage.scope=nil`，以及复测测试清理与后台 Worker 读写全局工具钩子的竞态。两项均用修改前源码复现，未在本轮扩改，完整回归不能表述为全绿。

兼容性：保留旧版一次性观察接口及已配对 Node；浏览器场景仅覆盖隔离的 Web 多步交互，不代表完整 Electron 桌面控制、所有 Windows/Linux 调试器或已安装 Appium。上述更新位于未发布 `main`，没有新建 tag 或 Release。使用方式见[逆向 Android 与浏览器交互](docs/reverse-interactive-workflow.md)。

本机更新与打包结果：

- 功能提交 [`ea1bb6b`](https://github.com/cyy081021/ARTEX/commit/ea1bb6b60759362d2b4f2d4d0442c96356736a27) 已推送 `main`。原 Windows/WSL 脚本实例更新为 `0.5.0-reverseflow-ea1bb6b`，同时替换其实际引用的逆向 Python 运行脚本；未改动模型凭据或运行环境配置。
- Linux amd64 主程序与五平台 Node 构建、ZIP CRC、资源清单和哈希核对通过；Linux/Windows Node 实际执行 `-version` 通过。安装包 SHA-256：`857094b4004c9e6e991bf559c689694bee78d68de494b0507941e7d83d7d6fce`。包中包含本次逆向脚本及使用指南，没有创建新 tag、Release 或镜像。
- 启动前确认任务、对话、报告及团队工作空闲。39 张业务表内容摘要保持一致；另对 4 张配置表逐项核对：仅更新 5 个已知系统默认提示词、两个续做工具描述，并加入两个逆向工具绑定，自定义配置和原提示词历史保留。76,495 个证据文件的路径、大小和修改时间一致，未逐个重算文件内容哈希。原 14 个启动脚本一致，暂停任务没有恢复。
- 健康接口与运行程序版本一致，任务、团队与设置页面可访问；团队页面实际提供的 42 份网页脚本与本次静态构建一致。已有 Android/Linux/Windows 环境配置保留；浏览器首次使用仍需配置其允许来源，没有把测试地址或测试环境写入正式配置。
- 隔离模拟器、HTTP 夹具、ADB 服务及测试数据库已停止。删除被替代的 `native-sessions-20261111-170921` 旧备份，保留 `reverse-workflow-20261111-183710` 恢复点。

### 成员任务复用原界面（2026-11-11）

- 替换上一轮成员专用的通用表格与图布局。普通任务、成员任务直接调用共享 `TaskDetailFrame`、`TaskDetailViews` 和原栏目组件；探索图、漏洞关系图、资产覆盖图、资产筛选、报告、复测和逆向档案沿用原实现。
- 漏洞详情主体从原页面抽出共用，成员打开详情后仍留在共享任务内。仅按成员查看权限隐藏修改、启动和审批裁决入口；普通任务页面保持原操作，原有消息指导和协作执行入口继续可用。
- 新增按任务范围适配原 GET 接口的读取层，保留原响应结构、查询过滤与分页；拒绝跨任务参数、无关发现和未经授权的路由。任务统计不混入全实例数据，审批记录不返回工具参数与原始执行内容。
- 栏目切换使用页面内状态，同步栏目地址，避免静态导出模式下重复导航。旧成员读取接口保留兼容。

验证结果：

- 隔离 PostgreSQL 中运行 `go test -race ./server ./db ./report -run 'TestTeamTaskNative|TestTeamTaskContent|TestTeamTaskReport|TestTeamTaskDetail|TestInterceptFilter|TestInterceptDetail' -count=1 -v -timeout=5m` 通过。server 与 db 有匹配测试，report 仅编译。覆盖原接口响应结构、分页、审批筛选和详情、只读访问、跨任务拒绝、重复冲突参数、直接来源即时解除、撤销查看权限和逆向材料下载。
- 前端 `npm --prefix web run build:static -- --webpack` 通过，包含 TypeScript 和静态页面导出。
- 同一个 317 节点、312 连线的合成任务分别以普通身份和成员身份打开，浏览器确认原探索图、小地图和缩放控件相同；实际切换所有渗透资料栏目，打开原漏洞详情、复测记录、资产类型筛选与逆向档案，跨任务链接保持在成员工作区。普通任务的添加按钮保留，成员不显示写入入口。测试中发现的栏目重复导航已修复并重新验证。
- 浏览器测试使用独立数据库和合成材料，不启动模型或真实工具；未代替第二台实体设备网络验收。

兼容性：不修改数据库结构、Node 协议或任务调度逻辑，只需更新主端；设备无需重新配对。上一轮独立成员表格与其专用状态测试随实现移除，上述接口回归与浏览器检查覆盖替代流程。

本机更新与打包结果：

- 功能提交 [`2467d22`](https://github.com/cyy081021/ARTEX/commit/2467d227663023e81d2d807a6f86544f929ae8e2)，原 Windows/WSL 脚本实例已更新为 `0.5.0-nativeviews-2467d22`，健康接口和实际运行程序校验一致。
- Linux amd64 主程序与五平台 Node 构建、ZIP CRC、资源清单和文件哈希校验通过；Linux/Windows Node 的 `-version` 实际执行通过。安装包 SHA-256：`762dd1fd9b20833f596d3a2b59c1cde2ebd4c0f4fb7f295fb8c58d419b435938`。
- 换装前确认任务、会话、报告及团队工作均空闲。换装后 43 张业务表内容摘要、私有配置、14 个原启动脚本保持一致；76,495 个证据文件的路径、大小、修改时间一致，未逐个重算证据文件内容哈希。所有暂停状态保留，没有恢复真实任务。
- 团队首页和成员任务页实际提供的 41 份网页脚本与本次构建一致。对现有共享任务以只读方式检查 11 个原形读取请求，覆盖图、发现及分页、资产、审批、关系与跨流程记录；成员交互由隔离浏览器完成验证。
- 已删除上一份 `member-content-20261111-141943` 备份，保留 `native-member-20261111-145957` 恢复点。测试预览和独立测试数据库已停止。源码和说明推送 `main`，未创建 tag 或 Release。

### 成员任务资料完整查看（2026-11-11）

- 成员详情新增总览、探索链路、播报板、发现、漏洞关联、复测、测试资产、资产覆盖图、拦截审批记录、报告和跨流程协助；逆向任务提供材料及分析结论档案。
- 发现与资产支持同一任务内的详情阅读；图可缩放、查看节点，列表支持搜索与分页，定时刷新保留当前栏目。切换任务、栏目或详情时清除不匹配内容，避免旧请求覆盖当前视图。
- 使用既有任务 `read` 权限，无需新权限项或设备配对；不新增审批、删除、执行等操作。对主任务明确附加的直接来源，保持原任务上下文语义。修复普通及成员 Markdown 报告混入其他任务资产计数的问题。

验证结果：

- 隔离 PostgreSQL 中执行 `go test -race ./server ./db ./report -run 'TestTeamTaskContent|TestTeamTaskReport|TestTeamTaskDetail' -count=1 -v -timeout=5m` 通过。实际匹配的是 server 测试；db/report 在该筛选下仅完成编译。覆盖 11 个渗透栏目、逆向档案/报告、发现分页及详情、无关记录拒绝、直接来源解除、撤销查看权限及报告资产统计。
- `node --test web/src/lib/team-task-content-state.test.mjs` 的 3 项响应顺序与当前内容范围测试通过；前端 TypeScript 检查和 `npm --prefix web run build:static -- --webpack` 通过。
- 使用独立成员身份、合成数据和静态导出页面，浏览器实际打开全部新增渗透栏目，展开发现报告/复测历史、资产详情，检查关系图和逆向档案。没有运行真实模型、工具或外部目标；没有将本机浏览器验收视为第二台设备网络验收。

兼容性：不修改数据库结构、Node 协议或原任务的执行逻辑；这一批阅读功能只需更新主端。已配对 Node 的原有执行协议不变，之前自动协作所要求的能力报告条件不变；新配对仍使用主端提供的同版本接入包。使用方式见[成员任务资料](docs/team-shared-messages.md#查看任务资料)。

本机更新与打包结果：

- 功能提交 [`5059ef4`](https://github.com/cyy081021/ARTEX/commit/5059ef49f999f776a185bdb1d4a20bbfb4554b26)，构建版本 `0.5.0-memberviews-5059ef4`。Linux amd64 主程序及五平台 Node 构建通过，ZIP CRC、资源清单与文件哈希一致；Linux/Windows Node 的 `-version` 实际执行通过。
- 原 Windows/WSL 脚本启动实例已完成换装，健康接口返回该版本。换装前确认无任务、会话、报告或团队工作在执行；换装后 43 张业务表内容摘要、私有配置及启动脚本一致，76,495 个证据文件的相对路径、大小和修改时间一致，未逐个重算证据文件内容哈希。
- 团队首页和成员详情引用的 30 份网页脚本与构建文件一致。对既有共享任务做只读接口验证，11 个新栏目均正常返回；没有启动、恢复或更改真实任务。成员角色的页面操作由上述隔离浏览器验证覆盖。
- 删除上一份 `auto-collaboration-20261111-132757` 备份，保留 `member-content-20261111-141943` 恢复点。没有新建 tag 或 Release，未重新执行第二台实体设备网络验收。

### 自动配置与任务工作台（2026-11-11）

- 从主任务读取目标、授权资产、约束和登记材料，从成员 Node 的配置报告匹配角色及工具。生成预览后核对一次即可启用，不再填写能力键；启用保持暂停，点击“开始协作”才开始执行。
- 增加独立协调会话，负责拆分工作、分配资产和依赖、按预算发布子工作。服务端按设备自己的能力和空闲状态派发；不同工具配置的设备可共同执行，同一工作不会因并发轮询重复派发。
- 默认自动派发、自动发布和明确结果自动接收。核验角色引用实际执行证据版本，判断明确且验收满足时自动接收；判断不明、证据不足或版本不对应时转人工并记录原因。沿用现有核验与主任务验收，不额外增加逐项人工批准，也不自动宣布主任务完成。
- 团队首页以共享任务列表为主，任务详情默认打开会话。协调器和工作分支显示设备编号，可直接发送指导；工具执行明细不进入消息层，手动派发和管理收进高级入口。复审页仅列需要人工处理的分支。
- 修复分支消息目录被当前选择过滤、分支之间游标混用，以及撤销过程权限后旧消息缓存残留的问题。协调器忽略自己的心跳与状态计数变化，避免无新进展时重复调用模型。

本轮验证（隔离数据库、合成任务和自有测试材料，不运行真实目标任务）：

- `go test -race ./collab ./cmd/artex-node -count=1 -timeout=5m` 通过。
- `go test -race ./server ./db -run TestBranch -count=1 -v -timeout=5m` 通过。覆盖预览无副作用、确认前来源变更、不同设备工具匹配、暂停不派发及 8 次并发轮询不重复领取。
- 使用本轮构建的实际 Node 子进程，单独运行 `go test -race ./server -run 'TestBranchAutoNodeDispatchReviewEndToEnd|TestBranchRealNodeContinuousPlanningAndIndependentReview' -count=1 -v -timeout=5m` 通过。新流程记录 4 次协调请求、2 次执行请求和 1 次核验请求，子分支自动接收、主项目保持运行；后续 4 次轮询没有持续重复规划。旧手动流程记录 3 次规划、2 次执行和 1 次核验请求。模型均为本地测试服务，不代表真实模型效果。
- 前端静态构建、类型检查及 3 项消息目录/缓存纯函数测试通过。隔离浏览器完成任务列表进入详情、自动预览、确认启用、开始协作、自动建立调度分支、发送指导即时显示和仅显示待复审结果的操作。

兼容边界：没有数据库表结构迁移；旧手动项目保留原配置，不会被静默切为自动执行。自动配置需要配套新 Node 的能力报告，成员设备须更新 Node；模型凭据与工具仍留在成员本机。此次是本机隔离逻辑设备及真实 Node 进程验收，未重新验证第二台实体设备、真实模型或外部 MCP。使用说明见[团队自动协作](docs/team-auto-collaboration.md)。

### 自动协作构建与本机更新结果（2026-11-11）

- 功能提交：[`096de5d`](https://github.com/cyy081021/ARTEX/commit/096de5d26fdd7eb93eede6a704a3e30a189191c3)，构建版本 `0.5.0-autocollab-096de5d`。Linux amd64 主程序及 Linux/macOS amd64、arm64、Windows amd64 五平台 Node 构建通过；ZIP CRC、文件哈希、Node 清单与使用说明一致性检查通过。没有新建 tag、Release 或容器镜像。
- 原 Windows/WSL 启动脚本完成换装与重启，健康接口返回上述新版本。Linux 与 Windows Node 实际执行 `-version` 均通过；没有运行完整 Windows 主服务。
- 换装前确认任务、对话、报告和团队执行空闲，并保存本次恢复点。换装后 43 张业务表内容摘要一致，76,495 个证据文件的相对路径、大小与修改时间一致（未重新逐个计算文件内容哈希）；私有配置、任务状态和原启动脚本不变，暂停任务未被恢复。
- 任务列表、团队页及设置页 HTTP 检查通过；团队首页和任务详情引用的 27 份网页脚本与本次静态构建逐字节一致。页面交互由前述隔离浏览器验收覆盖，没有在真实任务上启用或启动自动协作。
- 已删除上一份被替代的 `network-refresh-20261111-122111` 备份，保留本次 `auto-collaboration-20261111-132757` 恢复点。更新成员 Node 时保留原配置与配对状态；无需重新录入模型凭据。

### 2026-11-10 协作可用性修复

### 修复与改进

- 同名团队显示编号；管理员可删除没有成员、设备、共享任务或协作历史的空团队，服务端以事务锁避免检查与删除之间的插入竞态，有历史的团队保留。
- 增加四项任务基础权限的精确保存与九项分支权限的独立授予/撤销。分支权限仍受任务基础查看和执行权限约束；撤销访问、过程或证据权限时清除已打开成员页的本地缓存。
- 发布工作单时可明确指定协调器工作并显示其标识。自动发布只创建可领取工作项；仍需成员认领、Node 就绪及管理者恢复主项目。
- 修复渗透任务启用分支时误读逆向材料库的问题；显式跨流程材料仍会被拒绝。独立成员 TLS 入口和 Relay 改用受限 Handler，保留成员登录、团队和设备操作，拒绝管理员登录、初始化、设置及普通任务 API。
- Node 增加只读 `check` 与 `-version`，可核对 TLS、协调器/Node 版本及本地角色和范围配置，不配对、不领取工作，也不调用模型或工具。Linux/Windows amd64 安装包包含同版本 Node、无凭据配置示例和接入指南。
- 打包使用仓库内受跟踪的指南与示例，移除对未跟踪本地旧文档的依赖，避免干净检出后因缺文件而失败。
- 管理 API 测试改用测试上下文并清理 Manager，避免遗留后台派发器干扰队列轮转测试；未降低队列尾项不饥饿断言。

### 验证结果

- 前端静态构建与 TypeScript 检查通过。DB、协作协议、Node、自更新 race 回归通过；分支启用专项回归通过。全量 `server` race 测试有 265 个顶层测试通过、5 个条件跳过、0 失败且无 race 报告。
- 独立 TLS 成员入口上的真实 Node 子进程闭环通过：3 次规划、2 次执行和 1 次复核模型请求使用合成模型及自有材料。
- Linux 与 Windows amd64 安装包构建、ZIP 内容/CRC/SHA-256/Node/文档一致性核对通过；两平台 Node `-version` 输出均为 `0.5.0-usability`，device/branch protocol 为 1。测试期间运行的包是未发布验收构建。
- 合成浏览器夹具覆盖团队编号和删除保护、基础与分支权限、撤权清缓存、协调器工作、渗透分支启用及成员入口。Node TLS 测试另行验证执行链；浏览器夹具本身不运行真实工作。

代表性验证命令（数据库须指向隔离测试库，真实节点用 `ARTEX_NODE_ACCEPTANCE_BINARY` 指定预先构建的 Node；前端命令在 `web` 目录执行）：

```bash
NEXT_EXPORT=1 NEXT_TELEMETRY_DISABLED=1 npm run build:static
go test -race ./db ./collab ./cmd/artex-node ./selfupdate -count=1 -timeout=8m
go test -race ./server -count=1 -v -timeout=8m
go test -race ./server -run TestBranchRealNodeContinuousPlanningAndIndependentReview -count=1 -v -timeout=4m
```

### 兼容性与边界

- 没有第二台实体设备；跨物理设备网络、防火墙、证书导入与 WSL 转发未验收。真实模型及 MCP 部署未验证，不能把合成模型链路表述为真实模型任务通过。
- 正式 `v0.5.0` tag、Release 与既有版本记录不改写；`main` 构建不替代在线更新的正式发布源。
- 全量 server 测试有五项条件跳过：`TestLiveContextReview`、`TestReverseRealEngineAcceptance`、`TestReverseHermesV94MaterialAcceptance`、`TestBranchBrowserPreview`、`TestTeamOnboardingBrowserPreview`。团队浏览器预览另行启动并通过；真实外部逆向引擎未在本轮重跑。
- 独立 TLS/Relay 入口不再提供管理员操作；管理员须使用原管理入口。任务基础与分支权限仍独立，不默认扩大授权；本次没有新增数据库迁移。

### 干净源码构建与本机部署验收（2026-11-10）

- 功能提交：[`edec98a`](https://github.com/cyy081021/ARTEX/commit/edec98a29b5816797adc37a1074b8ccd21b612d9)。从该提交的干净 Git 源码归档构建，复用本轮已通过静态导出与类型检查的前端；主程序及 Node 的构建版本均为 `0.5.0-main-edec98a`。这是 main 构建标识，不是新 tag。
- 修正打包文档依赖后，Linux/Windows amd64 两份 ZIP 重新构建通过；CRC、SHA-256、主/节点程序和受跟踪文档、配置示例内容核对通过。两平台 Node 的 `-version` 均实际执行成功。没有运行完整 Windows 主服务。
- 本机原 Windows/WSL 启动脚本完成停止、换装和重启；`/api/health` 返回 `0.5.0-main-edec98a`，脚本管理的后台会话保持运行。安装了同版本 Node 和接入文档，没有自动配对或启动执行节点。
- 换装前确认任务、主 Agent 对话、报告队列和团队执行空闲，保存程序及可读取的数据库备份。换装后 43 张受保护业务表的行数和内容摘要一致（忽略 `updated_at`）；76,015 个证据文件的相对路径、数量、大小和修改时间一致。本项未重新计算每个证据文件的内容哈希。
- 原有任务状态、模型/MCP/Agent 数据和私有配置保留，暂停任务没有恢复；原启动/停止脚本哈希一致。现有团队的删除资格和基础权限只读接口通过，未操作真实团队的删除或授权。
- 主页面、任务页、团队页和设置页 HTTP 检查通过；团队页引用的 26 份脚本与构建产物逐字节相同，包含新权限、删除资格、协调器工作及连接模板入口。交互渲染另由上述隔离浏览器验收覆盖。
- 本机换装不等于跨实体设备验收；成员 TLS 监听、端口转发、防火墙及真实模型/MCP 环境仍由使用者按[接入指南](docs/team-onboarding.md)配置。此轮只推送 main，不创建或移动 tag，不发布 Release 或容器镜像。

## `v0.5.0`

**正式版 · 发布于 2026-11-10 15:31。** 源码提交：[`eacb2c2`](https://github.com/cyy081021/ARTEX/commit/eacb2c237015ad23437c657b26ce1894d12f0970) · [下载](https://github.com/cyy081021/ARTEX/releases/tag/v0.5.0) · [相对 v0.4.1 的差异](https://github.com/cyy081021/ARTEX/compare/v0.4.1...v0.5.0)。

此版本增加共享主任务的执行分支协作，并收录此前已合入 `main` 的升级标记故障保护（`d59491a`）。

### 新增与修复

- 主任务可显式启用分支模式；成员认领自己的设备后创建独立 Planner、预算、工作单与历史。工作池按权限与设备能力分配，协调 Planner 也须认领设备并计账。
- 团队消息区分讨论和明确指导；指导具有 queued、received、applied/failed 状态，并绑定工作单与执行代次。页面展示执行端编号；消息按序增量补取、去重，权限撤销和封口仍受服务端检查。
- 支持渗透与逆向流程间的受额度约束协助、来源证据版本引用及变更失效传播；技术核验后要求未参与执行的另一名授权成员独立复核。归档恢复仅恢复审计，不恢复租约或执行授权。
- 远端独立执行或待复核且无本机可运行工作时可释放本机并发名额；本机新工作重新按 FIFO 申请名额。队首资源被占用时可选择后续可运行工作，指定工作 ID 仍不能绕过资源占用。
- 增强故障恢复、权限复核与幂等处理：未知操作保持资源占用；恢复补传结果而不重放外部副作用；重试/转交不重置已用预算；永久拒绝不会无限重放。证据变化使下游引用和验收失效。
- 修复自更新暂存阶段标记写入失败的处理：清理暂存文件并返回错误，清理失败也报告；缺失或不可读的升级标记会拒绝换装。相关回归见 `selfupdate/marker_failure_test.go`。

### 验证结果

本轮使用独立 PostgreSQL、真实 Node 子进程、本地 TLS API、假模型、合成材料及隔离浏览器预览；未连接真实模型或外部目标。代表性命令及实际结果：

```bash
go test -race ./db ./collab -count=1 -timeout 8m
go test -race ./db -run '^TestBranchAdmission' -count=1 -v -timeout 2m
go test -race ./server -count=1 -timeout 8m
go test -race ./cmd/artex-node -count=1
go test -race ./server -run '^(TestBranchRealNode|TestTeamRealNode)' -count=1 -v -timeout 3m
go test -count=1 ./selfupdate
go build ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/artex-node
NEXT_EXPORT=1 npm run build -- --webpack
```

数据库测试须设置指向独立测试库的 `ARTEX_PG_DSN`；真实节点测试还须用 `ARTEX_NODE_ACCEPTANCE_BINARY` 指定已构建的节点程序。前端命令在 `web` 目录执行。

以上数据库、服务端、节点、更新器及真实节点进程回归均通过；Linux 全包构建、Windows 节点交叉编译、前端静态导出与 TypeScript 检查通过。浏览器合成数据验收确认历史消息检索、讨论/指导保存、queued 状态、执行端编号及只读成员入口限制。测试还覆盖并发认领、离线待就绪、撤权、旧代次拒绝、预算、跨主任务资源互斥、协助取消、证据失效、独立复核、归档恢复与队列准入。

### 兼容性与边界

- 分支模式和节点 `execution.branches.enabled` 默认关闭；旧任务调度及单工作单交接保留。新消息交付需 Node 声明 `message_protocol: 1`；旧节点继续原有工作单，消息通道不开放。升级顺序为先 Hub、后 Node；含 `remote_resume` 的活跃任务完成或暂停前，不应回退到不识别该队列模式的旧 Hub。
- 本轮未在第二台物理设备、NAT 或公网 Relay 网络上实测；浏览器使用合成数据。Windows 结果仅为节点交叉编译，不是 Windows 进程实跑。自更新标记故障保护的新增回归见源码测试文件；本段没有声称全平台升级运行通过。
- 五平台包与双架构容器由 tag 发布流水线构建，产物可用性以对应 GitHub Actions 和 Release 记录为准。工具范围字段校验不等同于操作系统沙箱；额度按模型/工具/规划动作计数，不是 Token 或金额，工具内部 HTTP 请求频率仍由本机适配器或代理负责。

### v0.5.0 发布产物核验（2026-11-10）

- 源码提交：`eacb2c237015ad23437c657b26ce1894d12f0970`；新增附注 tag `v0.5.0`，历史 tag 保持不变。
- [本次 GitHub Actions](https://github.com/cyy081021/ARTEX/actions/runs/42775372771) 的 9 个 job 全部成功：发布前检查、前端、五平台程序包、Release 上传和双架构镜像发布。
- 5 个 ZIP 与 `SHA256SUMS` 已上传；清单与 GitHub 的五份资产摘要一致。实际匿名下载 Linux amd64 ZIP 并计算 SHA-256 通过：`9dc2c4398abe32fd89a95f5bbb20524f6cfe79ca09898299ca5999a9dabe5eb5`。
- 发布时的 `ghcr.io/cyy081021/artex:v0.5.0` 和当时的 `latest` 的匿名 OCI 清单读取通过，均指向 `sha256:cf54e762e804ad003b5775b862441d3bdefcb46ec4f9c4e772a27822a66bf018`，包含 `linux/amd64` 与 `linux/arm64`。
- 五个平台 ZIP 沿用主程序包格式。独立 Node 需从 `v0.5.0` 源码构建：`go build -o artex-node ./cmd/artex-node`（Windows 输出名使用 `artex-node.exe`）；配置与边界见仓库 [执行分支说明](docs/team-branches.md) 和 [节点配置示例](examples/team-node-branches.example.json)。
- CI 包含 Linux amd64 程序 `-h` 冒烟检查；交叉编译不代表五平台实跑。本轮容器核验限于匿名清单、平台和摘要，没有重拉全部镜像层或运行容器。本机生产部署未随此次推送更新。

## `v0.4.1`

**正式版 · 标签建立于 2026-11-09 23:59，Release 发布于 2026-11-10 00:04。** 源码提交：[`9ca476c`](https://github.com/cyy081021/ARTEX/commit/9ca476cbcf86b1b1155206abbe32911a6a7dc896) · [下载](https://github.com/cyy081021/ARTEX/releases/tag/v0.4.1) · [相对 v0.4.0 的差异](https://github.com/cyy081021/ARTEX/compare/v0.4.0...v0.4.1)。

修复旧内置提示词未随程序更新、升级覆盖自定义内容或错误标记完成、并发保存版本冲突，以及资产覆盖率误计。

### 修复内容

- 启动时识别并升级仍由系统维护的旧内置提示词；保留自定义内容、无法识别的模板及完整历史。默认模板哈希与版本更新原子提交，升级失败可在下次启动重试，重复启动不追加相同版本。
- 移除旧的一次性强制重置逻辑，避免覆盖自定义提示词或在写入失败后误记升级完成。升级旧库时，识别仍由系统维护的已知 goals、mainagent、planner 默认模板并追加新版本；人工保存的自定义版本及未知文本不被覆盖。
- 提示词保存、空白初始化和默认升级共用 Agent 行锁，避免并发计算相同版本号，保留完整版本历史。
- 当前任务与直接来源任务的资产覆盖仅统计 confirmed fact，初始化 origin 与已否定 dismissed fact 不再计入已测；覆盖图、覆盖统计和未测列表保持一致。

### 验证结果

以下修复验收于 2026-11-07 在独立 PostgreSQL 与本机隔离环境中完成，发布前核对了代码差异和验收记录：

- 数据库回归与 race 检查通过：已知旧默认升级、未知/自定义内容保留、后续默认更新、幂等、空模板/不存在的 Agent 拒绝、注入写入故障后的回滚与重试、24 路并发保存，以及 20 路初始化和保存/同步竞争。
- 相关 Agent 与服务端回归通过，覆盖真实历史 Planner 默认模板升级及自定义 Worker 保留。
- Linux amd64 内嵌前端程序构建成功。完整进程连续启动两次，实际登录及 Agent/覆盖 API 验收通过：旧默认只追加一次升级版本，自定义 Worker 内容不变；origin、dismissed、confirmed 三条合成事实的覆盖率返回 **1/3**。
- 当前任务和直接来源任务的覆盖统计、未测列表、覆盖图一致；同一资产的多个 confirmed 锚点只计一次。
- 本机应用修复时，任务、报告、活动、资产、约束、复测/关系和模型/MCP/工具配置的记录数及内容摘要保持一致。正式 ARTEX 未启动、任务未恢复；数据库维护完成后恢复停止。

回归命令（须设置指向独立测试库的 `ARTEX_PG_DSN`）：

```bash
go test -race -count=1 ./db -run 'TestPrompt|TestCoverageCountsOnlyConfirmedFactAnchors|TestConfigStores'
go test -count=1 ./server -run 'TestSeedPrompts|TestMgmtAPI|TestFindingRetest|TestExecutionFinal|TestPrompt'
go test -count=1 ./agent -run 'TestPrompt|TestPlanner|TestWorker|TestExecutionContract'
```

### 升级及验收边界

- 升级会新增 `agent_prompt_defaults` 元数据表；历史提示词版本保留，自定义内容不自动改为新版默认。升级前按常规备份数据库和配置。
- 资产覆盖仍表示有效事实关联的资产范围，不等于所有适用漏洞类别都已充分测试。有效阴性观察仍可作为 confirmed fact 计入，漏洞处置状态与独立复测结论继续分别保留。
- 本轮没有执行外部目标测试、真实模型任务、第二台物理设备验收或全平台运行验证。五平台程序与双架构容器由 tag 发布流水线构建，流水线结果以对应 GitHub Actions 运行记录为准。

### 本次正式发布验收（2026-11-10）

- 源码提交：`9ca476cbcf86b1b1155206abbe32911a6a7dc896`；新增附注标签 `v0.4.1`，原有标签保持不变。
- [GitHub Actions 发布运行 #42650461728](https://github.com/cyy081021/ARTEX/actions/runs/42650461728) 的 9 个 job 全部成功：版本及更新器/启动脚本检查、前端构建、五平台程序包、Release 上传和双架构 Docker 镜像发布。此次从 `v0.4.1` 手动触发同一发布工作流。
- Release 的 5 个 ZIP 和 `SHA256SUMS` 均已上传。校验清单与 GitHub 记录的五个文件摘要一致；另实际匿名下载 Linux amd64 ZIP 并计算 SHA-256，通过校验：`255d3a25bb40c208249cec91f917cbce88a4cd433e271d099da99afd23414f81`。
- 发布时的 `ghcr.io/cyy081021/artex:v0.4.1` 与当时的 `latest` 的匿名 OCI 清单读取通过，两者指向同一摘要 `sha256:b0cb2fd18eaf543396c8ab3dff6a466d2e40cb5716514b323a12819d86ef2edf`，包含 `linux/amd64` 与 `linux/arm64`。
- 本次 CI 包含 Linux amd64 程序的 `-h` 冒烟检查；没有将交叉编译成功等同于五平台运行验收。镜像校验限于匿名清单、平台和摘要，本轮未重新下载全部镜像层或运行容器；此前 v0.4.0 的完整匿名拉取记录仍归属于旧版本。

## `v0.4.0`

**正式版 · 发布于 2026-11-06 15:03。** 核心源码提交：[`bcfced8`](https://github.com/cyy081021/ARTEX/commit/bcfced88b666c69e8dbdce60ca986ea601d35b94) · [下载](https://github.com/cyy081021/ARTEX/releases/tag/v0.4.0) · [相对协作 v1 的差异](https://github.com/cyy081021/ARTEX/compare/artex-collaboration-v1...v0.4.0)。

将 ARTEX 的安装和更新发布源迁移到 `cyy081021/ARTEX`，并建立本仓库的正式二进制与容器发布流程。包含此前 `artex-collaboration-v1` 的完整源码功能。

### 新增与修复

- 在线更新固定查询本仓库 Releases，沿用 HTTPS、SHA-256 校验、暂存换装和失败回滚。
- Docker Compose 默认使用 `ghcr.io/cyy081021/artex`，安装和更新脚本遇到拉取失败会停止；旧 ARTEX origin 仅在确认同步时定向迁移，其他自定义源不变。
- `vX.Y.Z` 标签触发更新器测试、前端静态构建、五平台 Go 交叉编译、zip/SHA256SUMS 上传，以及 Linux amd64/arm64 镜像发布。GHCR 使用本仓库的 `GITHUB_TOKEN`，不再依赖原作者的 Docker Hub 密钥。
- 每个正式版本须在本文件提供独立说明，由流水线提取写入对应 Release。`artex-*` 源码标签不触发二进制发布，也不参与在线更新版本比较。
- 首次从旧更新源或带后缀的本地构建迁移，需要手动安装新正式包；后续正式版本使用页面更新。原 Go 模块标识及 `norma` SDK 是编译依赖标识，与 ARTEX 下载来源不同，本次不作全仓重命名。

### 验证结果

- [发布流水线](https://github.com/cyy081021/ARTEX/actions/runs/42177961544) 完成五平台程序包、`SHA256SUMS` 与 Linux amd64/arm64 镜像发布；安装源迁移、拒绝同步保留自定义源、镜像拉取失败停止和缺少版本说明拒绝发布等回归通过。
- 使用独立且没有登录凭据的 Docker 配置，实际匿名拉取两个架构的镜像，并在禁用网络、无宿主数据挂载的容器中通过 ARTEX `-h` 及工具版本检查。arm64 运行使用 amd64 宿主上的 Docker 仿真，不代表原生 arm64 设备验收。
- 镜像源码标签、版本和下载包一致性通过核对；发布时 `v0.4.0` 与当时的 `latest` 指向 `sha256:721710856af948e966cfbc1a2328dd444983145210af6ad488df78d710e1bdfe`。`latest` 随后续正式版本移动，不用于固定旧版部署。

### 兼容性与边界

协作、逆向功能的测试边界仍见下方协作版本记录：本机逻辑设备与自有样本验收不等于第二台物理设备或公网 NAT 验收。容器内默认工具链沿用现有 Dockerfile；APK/.NET/原生逆向引擎及动态运行环境仍需依照逆向配置文档安装。此版本的 GHCR 包已完成公开与匿名拉取验收；使用明确版本标签可避免后续 `latest` 变化。

### 2026-11-06 运行交接材料补充

- 增补 `ARTEX-runtime-handoff-v0.4.0.zip` 与独立 `.zip.sha256` 附件，源码材料见 [`profiles/runtime-handoff-v0.4.0/`](profiles/runtime-handoff-v0.4.0/RUNBOOK.zh-CN.md)。这是已有核心版本的部署补充；`v0.4.0` 标签、程序包与镜像保持原构建。
- 交接材料对应后续提交 [`4cb7410`](https://github.com/cyy081021/ARTEX/commit/4cb7410db04298eefe1f5a5e0a4b25507745e01d)，不在 `v0.4.0` 标签源码内。下载：[交接 ZIP](https://github.com/cyy081021/ARTEX/releases/download/v0.4.0/ARTEX-runtime-handoff-v0.4.0.zip) · [独立校验文件](https://github.com/cyy081021/ARTEX/releases/download/v0.4.0/ARTEX-runtime-handoff-v0.4.0.zip.sha256)；ZIP SHA-256：`a52e024a40c8cda1835c83d293f20dca16faeb4edd4fe8385b43f0caeb3170f6`。
- 包含本机实际 integrations 的路径参数化副本、MCP 启动脚本、四个 privacy 工具及 Windows DNS/配置采集依赖、Python/Node 锁文件、13 个绑定技能和当前 16 个 Agent/11 个 MCP 的脱敏配置。保留逐文件来源哈希、适配差异、触发与全局拦截配置，不附带密钥、任务数据、浏览器会话或 Tor 状态。
- 本机隔离验证通过 33 项合成测试、7 个本地 MCP 握手及 Chromium 本地测试页导航，复用现有依赖。目标机器全新安装、Windows Edge 探测和真实模型调用未验收；ScopeSentry 声明启用但未配 URL，不计作可用远端 MCP。
- 交接快照中的 Tor 开关关闭，模型凭据和目标设备路径由接收方自行配置；配置数量是该日期的快照，不代表后续版本的完整默认配置。

## `artex-collaboration-v1`

**源码里程碑 · 开发验收于 2026-11-05，标签建立于 2026-11-06。** 对应提交：[`87e3e08`](https://github.com/cyy081021/ARTEX/commit/87e3e08d955cd3a4c4d11f87449221e424bc0246) · [相对逆向 v1.1 的差异](https://github.com/cyy081021/ARTEX/compare/artex-reverse-v1.1...artex-collaboration-v1)。

### 新增功能

小团队多设备协作的首个公开里程碑。团队负责人可将工作明确加入队列，由协调器按任务和成员权限、设备在线与空闲状态、角色及能力匹配节点；排队本身不授予执行权。节点可按本地策略调用命令和 stdio MCP 工具，交付候选结果后由另一名有权限的成员复核。队列可查看等待原因并取消，派发前会重新检查权限、任务范围和所选材料，范围或材料摘要变化会使请求失效。

动态观察要求负责人明确授权、指定设备和运行配置，并把授权材料摘要绑定到本次工作。节点按材料哈希验证下载及缓存；动态运行器按本地配置的时限和环境变量白名单运行，并返回脚本、材料及清理证据。授权不延续到后续任务。工具角色与只读标记属于应用层控制，命令、MCP 服务和运行器仍以节点操作系统账户权限运行，不能替代操作系统隔离。

节点支持故障退避重连、耐久结果 Outbox、分段续传与完整性校验，并在每次工具调用后同步证据。执行开始标记用于避免进程重启后自动重放副作用。传输优先尝试 TLS 保护的 LAN 直连；不可用时可经 TLS Relay，LAN 连续两次间隔探测成功后再切回，并保留进行中的请求。团队归档保留来源、交接、证据和复核的只读历史；恢复不会重建设备凭据、租约、成员权限或运行授权。

本版交接单位为负责人明确派发的工作单；`v0.5.0` 才新增共享主任务下可持续规划的执行分支、共享消息和带回执的指导。配置入口见 [协作配置与执行说明](examples/README.md)。

### 验证范围与限制

- 协调器、节点、Relay、数据库和前端的定向构建及测试有记录；真实节点进程端到端验证使用本地 TLS 协调器、两个逻辑设备和本地确定性 OpenAI 兼容模型替身。它验证平台交接链路，不是对真实模型能力的验证，也不是两台真实设备之间的网络验收。
- Linux、Windows 和 Android 的动态观察分别使用项目自有样本与 Frida 实际运行器完成，并记录观察结果和清理状态。这是运行器及样本的验证，与上面的本地模型替身节点 E2E 属于不同证据，不能合并表述为完整的多设备模型任务已通过。
- 当前验收未使用第二台真实物理设备；真实 NAT、公网 Relay、跨主机账户和防火墙组合也未验证。LAN 地址需手动配置，没有零配置网络发现。因此不据此宣称跨物理设备或生产环境已验收。
- 页面/API 验收使用独立预览环境及无执行内容的文本材料；相关队列和分配在验收后取消。该记录不表示当前本机部署或生产部署已成功。
- 定向测试：独立 PostgreSQL 测试库中运行 `go test -count=1 -p 1 -timeout 6m ./db ./server ./collab ./cmd/artex-node ./cmd/artex ./cmd/artex-relay`；设置 `ARTEX_NODE_ACCEPTANCE_BINARY` 后包括真实节点子进程验收。另运行 `go test -race -count=1 ./collab ./cmd/artex-node ./reamcp`。Windows 节点原生测试通过 30 项，真实运行器测试通过专用样本配置另行执行。
- 构建：Next.js webpack 静态构建及 TypeScript 检查、Linux 协调器/节点/Relay、Windows 节点。动态样本验证使用 Frida 17.23.2；Linux/Android 观察到自有样本 `transform(3)=16`，Windows 观察到自有样本调用 `GetTickCount64`，运行器清理检查通过。

## `artex-reverse-v1.1`

**源码里程碑 · 标签建立于 2026-11-05。** 对应提交：[`9929dbc`](https://github.com/cyy081021/ARTEX/commit/9929dbc131207cde7bae30d26738b776947361ca) · [相对逆向 v1 的差异](https://github.com/cyy081021/ARTEX/compare/artex-reverse-v1...artex-reverse-v1.1)。包含此前 `e24dcd8` 的角色隔离与跨流程协助。

### 新增与修复

- 独立解析逆向主 Agent、目标拆解、Planner、静态、动态和核验角色及模型/工具绑定；渗透与逆向按问题、所选材料和预算互相请求协助。
- 新增受大小及路径约束的 APK 派生材料提取和 Hermes 字节码静态检查，保留父子材料哈希；提供版本、字符串、函数和分页指令索引。
- 工作验收使用稳定 ID，拒绝缺失、重复、未知验收项及过期证据；证据读取按任务范围和结果哈希检查，缩小工作空间与结论返回内容。
- 修复失败前置的阻塞与依赖恢复；向 Worker 显示有效轮次/时间预算和接续点。任务活动流增加心跳、游标重放、断线补取及活动 Worker 会话恢复。

### 验证结果

- 独立 PostgreSQL 的 db、server、collab、命令程序和 mcphttp 相关包回归通过；发布源码的 agent/db/server 逆向、执行合同、依赖、跨流程和消息流定向回归通过。
- Hermes v94 样本的摘要、字符串、函数及指令静态查询通过；隔离程序的健康接口、工具注册和验收参数检查通过，前端消息流/合并测试通过。
- 未恢复生产自主任务，未测得端到端速度或费用改善。上述结果是相关包及定向回归，不是全仓库测试全绿声明。

### 兼容性与边界

- 新验收 ID 兼容旧文字回执，工具参数迁移保留操作员开关和绑定；依赖恢复策略限定逆向任务。
- Hermes 检查固定 `hermes-dec==0.1.8`，要求 CPU/内存限制及 30 秒超时。本机 Windows 使用 WSL 引擎；缺少资源限制的原生 Windows 路径会拒绝运行。字节码不会执行，也不保证恢复原始 JS。
- 详见 [逆向角色与跨流程协助](docs/逆向角色与跨流程协助.md) 和 [执行恢复说明](docs/reverse-execution-recovery.md)。本版不包含后续跨设备执行功能。

## `artex-reverse-v1`

**源码里程碑 · 标签建立于 2026-11-04。** 对应提交：[`b6e3031`](https://github.com/cyy081021/ARTEX/commit/b6e3031725ac0d19e2da066fc5bb255a2f2b0a6e) · [相对优化版的差异](https://github.com/cyy081021/ARTEX/compare/artex-optimized...artex-reverse-v1)。

### 新增与修复

- 创建任务时区分渗透与逆向；逆向具有材料、候选结论、独立核验、目标证明与档案导出流程。
- 接入 REA 6.8.0 的 JavaScript、APK/JADX、.NET 和原生/Ghidra 分析；提供单独授权的 Windows、Linux、Android Frida 运行时观察、取消与清理记录。
- 修复任务消息依赖 SSE 时无法实时更新的问题，发送后补取、断线期间轮询、恢复后按序号合并；修复暂停任务的报告重写队列与错误反馈。
- 提供可显式导入的本地 Agent/MCP/Skills/隐私网关配置，保留启用状态及绑定，排除真实凭据和任务数据。

### 验证结果

- 自有样本的 JS、APK、.NET、原生引擎链路，以及 Windows/Linux/Android 动态观察、实际取消与清理均有通过记录。
- 真实模型的 JS 有界任务完成 2/2 目标，修复后的 .NET 定向任务完成 1/1、工具错误为 0；多材料联合任务在 12 分钟内完成 0/3 目标，保留其未完成和结论分歧记录。
- 暂停任务的 9 条待重写报告处理至 0；10 个 Agent、11 个 MCP、59 个工具及 2 个触发器的隔离重复导入通过。前端生产构建和消息合并检查通过。
- 相关后端专项通过；当时完整 `go test ./...` 仍有既有 `TestGraphOverviewExpandsAssociatedCompanyScope` 失败。完整记录见 [逆向验收记录](docs/逆向验收记录.md)。

### 兼容性与边界

- 固定工具版本的样本通过不代表任意程序或系统兼容：该轮使用 Ghidra 12.1.4、Frida 17.23.2 和 Android 15；Ghidra 12.2 被拒绝，Android 9 未通过。
- 本版具有逆向流程，但专职角色及配置绑定的完整隔离、渗透/逆向跨流程交接由后续 `artex-reverse-v1.1` 补齐。多设备执行仍属于后续版本。

## `artex-optimized`

**源码里程碑 · 2026-11-03 部署源码快照，标签建立于 2026-11-04。** 对应提交：[`90509db`](https://github.com/cyy081021/ARTEX/commit/90509dba41066ea2b890829784e88ba290062fbe) · [相对基线的差异](https://github.com/cyy081021/ARTEX/compare/artex-baseline...artex-optimized)。包括此前的 `f7339b0` 实时引导与漏洞协作改动。

### 新增与修复

- 运行中可对主 Agent 与 Worker 提供引导；温和暂停停在工具边界，保留独立的立即停止入口。
- 新增结构化工作合同、前置依赖等待、方向去重、资源互斥与有界续做；Worker 提交证据版本与验收结果，目标证明后进入收尾流程。
- 在模型请求和工具执行边界刷新约束，记录等待/无进展原因及恢复条件，减少态势未变化时的重复规划。
- 修复工作输出及运行意图读取窗口截断、领取错误静默丢失；漏洞归并保留原证据，关联图按真实有向关系分组展示，支持循环、筛选和未关联列表。

### 验证结果

- 独立 PostgreSQL 中的执行合同、约束刷新、暂停和归档定向测试通过，模拟模型实际走过 `record_fact → node_detail → complete_intent → 结算`。
- 全新数据库回归的 db、server 包通过；agent 包仍有既有 `TestGraphOverviewExpandsAssociatedCompanyScope` 失败，未宣称全套通过。
- 后端构建、TypeScript 和前端静态构建通过；关联图布局的 6 项测试通过，含 1,400 节点样例。

### 兼容性与边界

- 旧的无合同工作单保留兼容结算；新合同要求有效结果与证据。资源键和方向键依赖正确填写，未提供方向键时仅保证规范化文本精确去重。
- 当时未验证真实模型规划质量或成本改善；关联图未完成真实浏览器交互验收。此版本尚无多设备 Hub/Node 执行链路。机制详见 [执行链路验收与调度](docs/执行链路验收与调度.md)。

## `artex-baseline`

**源码里程碑 · 标签建立于 2026-11-04。** 对应提交：[`5c0dbd4`](https://github.com/cyy081021/ARTEX/commit/5c0dbd4bec940f3c0faf20705a56d879b57d3dfe) · [标签源码](https://github.com/cyy081021/ARTEX/tree/artex-baseline)。

### 基线内容

- 保留 ARTEX 0.3.15 原始源码，包含原有渗透测试、资产与探索图、Worker、证据报告、流量、审批和配置功能，作为后续版本比较起点。
- 原始版本变更沿用 [0.3.15 更新日志](CHANGELOG.md#0315---2026-10-07)；此标签本身没有新增逆向或跨设备协作功能。

### 验证与兼容边界

- 建立标签时只确认源码基线身份，没有为该标签重新执行整套验收或发布五平台包。上游日志中的测试声明保留原历史语境，不视为本仓库重新验证。
- 历史源码保留当时的安装及更新源配置；上游失效后的修复从 `v0.4.0` 起提供。新部署使用正式版本，不依赖基线中的旧下载源。
