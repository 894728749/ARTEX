# Linux x86-64 原生分析与自动任务分流

本次变更在现有逆向工作流内加入原生分析工具，不新增持久化任务种类。创建界面统一填写对象、目标和可选材料；`kind:auto` 在创建前使用已配置模型判定主工作流与能力，实际保存的 `tasks.kind` 仍为 `pentest` 或 `reverse`，已有任务身份不变。未传 kind 的旧 API 调用仍按 pentest 处理。分类失败返回 503，不用关键词替代模型判断。

路由只使用描述、目标和文件名/大小。模型无法从这些信息可靠推断文件内容，路由理由及待补材料写入任务活动。混合任务继续通过现有跨工作流请求协作。逆向任务创建后暂停，上传材料后使用既有启动入口；执行样本仍需用户指定环境、材料和时长授权。

## 第一版已实现的流程

1. `native_inspect` 核验材料 SHA-256，静态解析 ELF64 little-endian x86-64；报告 ELF 类型、入口、NX、RELRO、canary 导入迹象、解释器、动态依赖名称和符号表情况。不会调用 ldd 或执行样本。PIE 候选与 canary 导入都是迹象，不能代替函数级检查或运行时验证。
2. `native_session` 在已授权 Docker 环境建立当前工作单私有会话。exec 模式通过 base64 传输 stdin/stdout，支持 NUL 等任意字节和多次 send/recv；debug 模式使用类型化 GDB/MI 的 run/start、断点、单步、继续、寄存器、栈、内存和模块查询。
3. debug 模式的 inferior I/O 定向到 `/dev/null`，不接受 send/close_stdin。这样目标输出不能冒充 GDB/MI 控制记录。需要交互输入的调试器 TTY 是后续扩展项。
4. `native_case` 保存不可变的 stdin/argv/环境/预期退出或信号案例，并启动独立的普通执行重放。每次执行产生新的 runtime run，服务端重新计算匹配结果。运行器成功、样本退出、崩溃、超时和清理失败分别记录。
5. `native_publish_finding` 限 reverse_reviewer；要求当前审核意图与案例/结论的提交意图不同、结论已接受、审核者成功重放同一案例。发布在既有 Finding 事务中完成并保留通知事件；同一结论重复发布幂等。崩溃不等于代码执行，影响仍必须由结论证据支撑。

Finding 快照保存样本字节、案例、运行环境、重放结果、结论及有界原始证据，独立于源任务保留。当前单样本上限 8 MiB，单原始结果 2 MiB、原始结果总计 6 MiB、完整快照 24 MiB。超过上限保留逆向候选，不悄悄丢弃内容后发布。可通过 `GET /api/findings/{id}/native-evidence` 读取并验证快照 SHA-256。

### 重放计划 v1

`native_case` 的 `create` 可带可选 `replay_plan`，例如
`{"version":1,"input_mode":"stdin","assertion":{"type":"exit_code","value":0}}`。
v1 支持已有 stdin 重放及 `exit_code`（0–125）/`signal`（1–64）预期；信号匹配仍使用 Docker `128+signal` 退出约定。`input_mode` 省略时归一化为 `stdin`。
计划断言与顶层 `expected_exit`、`expected_signal` 三者必须恰好选一个，也可保留顶层预期并使用不带 assertion 的计划。
v1 不接受 file 输入、依赖/loader/harness 或输出标记断言。未知字段及不支持的版本会拒绝，扩展能力使用 v2。

计划进入案例 SHA-256、数据库、任务上下文、只读状态、Finding 案例快照及任务归档；重放前核验案例哈希，服务端把计划转换为现有 runner 参数并独立计算匹配结果。
没有计划的旧案例仍使用原来的哈希算法。读取旧记录及恢复旧归档不需要补造计划；含计划的归档恢复须通过计划与哈希校验。

### 重放计划 v2 与独立审核

v2 将样本 SHA-256、固定镜像与执行策略修订号绑定到案例，可引用本任务已登记的依赖、loader 和 Python harness。执行前核对所有附件的哈希、任务归属与授权；模型不能指定宿主路径或外部地址。支持 stdin，或用 argv 中的 `{input}` 接入只读输入文件；harness 仅支持 exec/stdin。

`stdout_contains_base64` 使用 `data_base64` 指定目标输出中的字节标记。harness 输出不作为目标影响证据。`native_case repeat` 返回实际 n/N；`minimize` 仅对 v2 目标输出标记执行有界输入缩减，每次试验登记新运行，保留原案例并创建子版本。信号断言不能直接作为稳定崩溃签名用于缩减。

`native_review` 将结论绑定到独立审核者的案例哈希和重放运行。案例版本、配置或执行策略变化后须重新核验；v2 Finding 发布需要该精确绑定。`GET /api/findings/{id}/native-export` 导出样本、输入、附件、观察、重放条件与文件哈希。上述能力仍需要各自运行证据，不能以构建或单元测试通过证明完整 N01–N15 验收。

## 环境配置

运行端需要 Linux x86-64、Python 3、Docker，以及包含 GDB 和匹配动态加载器/库的固定镜像。服务端调用管理员配置的 runner；模型不能传入任意宿主命令或选择任意镜像。

`scripts/native-runtime-profiles.example.json` 使用与现有 Frida 配置相同的数组格式。将条目合并进 `ARTEX_REVERSE_RUNTIME_PROFILES` 指向的现有配置，保留已有条目及凭据处理；填写绝对的 `scripts/native_runtime.py` 路径和固定 image ID/digest，启用 settings.enabled。Windows 服务可通过既有 profile 的 command/args/path_mappings 调用 WSL 中的 runner，不能将 Windows 材料路径直接当作 Linux 路径。

镜像必须使用 `sha256:...` 或 `repository@sha256:...`。执行固定 `--pull=never`、`--init`、网络关闭、只读根文件系统与样本、非 root 用户、cap-drop、no-new-privileges、PID/CPU/内存/tmp 限制。debug 使用仓库随附的默认拒绝 seccomp profile，只为 GDB 子进程调试开放所需系统调用，不使用 privileged 或 unconfined。

`deploy/native-lab/Dockerfile` 固定 Debian 基础镜像及直接工具链包版本。最近的真实容器验收使用官方 Debian 软件包离线构建的本地候选镜像；这证明该候选镜像能运行所测夹具，不等于仓库 Dockerfile 的在线 apt 构建已经通过。完整传递依赖未全部锁定，本地 image ID 也不是已发布的 registry manifest digest。部署前须按目标环境构建、冻结实际镜像并执行验收；此变更不自动安装或启用生产环境。

## 权限、证据与恢复

- `analysis` / `pwn` 配置只是分析偏好，不能替代 runtime policy。调整配置要求暂停/终态且无仍在运行的观察。
- 显式原生配置启用最终工具过滤，额外 Skill/MCP 以及旧的通用 Frida/浏览器执行工具不能绕过 native runner；REA 静态入口保留。旧逆向任务不因上传 ELF 自动切换工具权限。
- 会话归属于当前 worker invocation；request_id 用于幂等重试，受限于会话缓存和证据大小。工作单结束、取消和超时触发清理。缺少完整终止/清理证据时标记失败，服务重启不会盲目重放。
- exec 的信号号来自 Docker 的 `128+signal` 退出约定，应结合 debugger/根因证据解释。宿主 Docker 客户端遭信号终止是引擎失败。GDB 的 SIGSEGV stop 可直接保留为调试观察。
- 归档格式提升至 5，兼容读取旧 1–4 版本；恢复 native 表时校验任务引用，关闭执行授权，将未结束运行置为失败。保留 Finding 的任务删除不会删除其独立快照。

## 验收命令与范围

定向 Go 验证使用独立 PostgreSQL 测试库，通过临时 `ARTEX_PG_DSN` 注入连接；不要对运行中的业务数据库执行测试。

```sh
go test ./db ./agent ./server -run 'TestNative|TestValidateNative|TestReverse|TestClassifyTask|TestTaskArchive|TestTeam.*Native' -count=1
python3 -m unittest scripts.native_runner.test_native_runner scripts.native_runner.test_native_cases scripts.native_runner.test_native_contract -v
# 仅在专用 Docker 实验环境；脚本仅编译和执行仓库内合成 C 样本。
NATIVE_IMAGE_TAG=<已构建的实验镜像> python3 -m scripts.native_runner.test_native_integration --acceptance-json /path/to/results.json
cd web && NEXT_EXPORT=1 npx next build --webpack
```

真实容器验收覆盖二进制多步 I/O 与 EOF、非零退出、SIGSEGV、超时/清理、可变镜像拒绝，以及 GDB 信号停止后的寄存器/栈读取。Go 验证覆盖授权拒绝、会话协议、角色边界、重放断言、独立审核与幂等 Finding、归档恢复和证据保留。模型分类使用 mock provider 验证，没有借测试调用真实付费模型。

v0.7.0 增加默认关闭的 [AFL++ 最小闭环](native-fuzzing.md)：支持已插桩的 Linux x86-64 ELF、stdin/文件输入、有界 campaign、候选导入和独立重放。环境须另行准备并显式授权；普通 native 镜像不保证包含 AFL++。示例中的 `enabled` 和 `fuzz_enabled` 均默认 false。

仍不包括远程服务 tube、完整交互调试 TTY、自动 ROP/堆利用生成、全架构/内核分析或任意 libc 自动下载。合成 SIGSEGV 和 AFL crash 均不代替真实产品漏洞证明。验收范围与跳过项见 [v0.7.0 原生功能验收](native-release-validation.md)。
