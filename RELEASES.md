# 发布说明

本文覆盖本仓库全部 8 个版本标签，按版本演进倒序记录新增功能、修复、验证结果和兼容边界。当前正式版为 **v0.5.0**；`artex-*` 是历史源码里程碑，未发布独立二进制下载包，不参与在线更新。下载以 [ARTEX Releases](https://github.com/cyy081021/ARTEX/releases) 的实际资产为准。

日期和时间均按北京时间（UTC+8）记录，区分源码快照、标签建立和 Release 发布时点。本文于 2026-11-10 补齐历史说明，保留原标签指向；下面的测试结果属于各版原验收记录，不表示本次重新运行了历史测试。上游 0.3.15 及更早的继承记录保留在 [CHANGELOG.md](CHANGELOG.md)，不代表本仓库另有对应正式 Release。研发过程中的“v2”是内部迭代名称，首个公开协作标签为 `artex-collaboration-v1`。

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
