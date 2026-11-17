# ARTEX Linux x86-64 AFL++ 最小闭环

状态：最小闭环已合入 v0.7.0 源码。验证使用 `testdata/reverse/native/fuzz_fixture.c` 合成样本和固定本地镜像；未测试真实产品目标、外部网络或真实模型效果。默认关闭，需要管理员准备实验环境并显式启用。

## 1. 安全边界与默认关闭

- 默认关闭。只有 `profile.settings.fuzz_enabled === true`（严格布尔真）才允许启动。
- 仍使用现有 task / artifact / `ReverseRuntimePolicy` / profile / policy revision 授权链。
- `native_fuzz` 只挂载给 `reverse_dynamic` 角色；`reverse_static`、`reverse_reviewer`、
  `reverse_main` 等角色不暴露该工具。既有 `native_inspect` 保持原有
  `reverse_static`/`reverse_dynamic`/`reverse_reviewer` 绑定；其他未知 `native_*`
  工具仍默认拒绝。
- `profile.settings.image` 必须是不可变 `sha256:...` 或 `name@sha256:...`，容器始终
  `--pull=never`。
- 不调用 QEMU、FRIDA、Unicorn、NYX、闭源自动模式、网络服务目标、shell 目标或自动下载。
- 目标二进制固定为容器内 `/work/sample`，AFL 可执行文件固定为
  `/usr/bin/afl-fuzz` / `/usr/bin/afl-showmap`，不接受模型传入的额外可执行文件、AFL
  参数或环境变量。
- 不继承宿主秘密。Docker 客户端只使用固定 allowlist 环境：
  `PATH/HOME/DOCKER_HOST/DOCKER_CONFIG/DOCKER_CERT_PATH/DOCKER_TLS_VERIFY/
  DOCKER_CONTEXT/DOCKER_API_VERSION/XDG_RUNTIME_DIR/LANG/LC_ALL`，容器内只注入固定的
  `AFL_*` 非秘密变量。

## 2. 工具接口

`native_fuzz` 是一个同步工具，action 仅允许：

- `run`：一次有界 campaign。
- `list`：列出最近 100 条 native run 中的 fuzz campaign。
- `import_candidate`：从已完成的 campaign 证据导入候选为不可变 `NativeCase`，
  但**不重放**。
- `replay_candidate`：导入并显式要求 `nativeReplay` 独立重放；只有重放匹配才进入
  受控重放证据。

每个 action 使用严格的字段集合，未知字段和跨 action 字段都会被拒绝。工具输入上限
256 KiB，所有 seed/crash base64 按 4096 字节单项上限解码并校验 SHA-256。

### 2.1 Python JSONL 请求

```json
{
  "operation": "fuzz",
  "request_id": "fuzz-1",
  "artifact_path": "/absolute/path/to/owned/fixture.elf",
  "sha256": "64 lowercase hex chars",
  "argv": [],
  "input_mode": "stdin",
  "profile": {
    "image": "sha256:...",
    "fuzz_enabled": true,
    "enabled": true,
    "platform": "linux",
    "network": "none",
    "read_only_root": true,
    "max_duration_ms": 60000
  },
  "duration_ms": 10000,
  "seeds": [
    {"sha256": "...", "data_base64": "Wlg="}
  ],
  "max_executions": 2000,
  "max_crashes": 2
}
```

约束：

- `duration_ms` 1000..60000，且不超过 profile / runtime policy 上限。
- `seeds` 1..32 项，每项 1..4096 字节，总计不超过 65536 字节。
- `max_executions` 100..1000000；`max_crashes` 1..8。
- `input_mode` 只允许 `stdin` 或 `file`。
- `file` 模式 argv 必须恰好有一个独立参数 `{input}`；`stdin` 模式不得出现
  `{input}`。任何参数都不得包含 `@@`。
- `profile.settings` 只接受已审查字段；`secrets`、`command`、`flags`、`afl_path`、
  `showmap_path`、`qemu`、`remote` 等越权字段被拒绝。

### 2.2 final frame

```json
{
  "request_id": "fuzz-1",
  "kind": "final",
  "observation": {
    "engine": "afl++",
    "target_state": "completed",
    "manifest": {
      "engine": "afl++",
      "artifact_sha256": "...",
      "image": "sha256:...",
      "input_mode": "stdin",
      "afl_version": "4.04c",
      "showmap_version": "4.04c",
      "options_verified": true,
      "probe_edges": 4,
      "probe_executions": 1,
      "output_disk_limit_bytes": 67108864,
      "single_worker": true
    },
    "stats": {"execs_done": 123},
    "corpus": [{"sha256": "...", "data_base64": "..."}],
    "crashes": [{"sha256": "...", "data_base64": "..."}],
    "cleanup": {
      "owned_process_terminated": true,
      "container_removed": true,
      "staging_removed": true
    },
    "cleanup_verified": true,
    "errors": [],
    "stats_trusted": false,
    "coverage_claimed": false,
    "candidate_status": "unverified_requires_replay",
    "truncated": false,
    "limited": false,
    "reason": null
  }
}
```

`target_state` 只允许 `completed` / `failed` / `cancelled` / `timeout`。
成功 campaign 必须至少有一个 corpus 项。Go 侧再次校验 manifest 身份、AFL 参数探测、
资源上限、cleanup、base64/hash、候选数量与总字节，未知字段拒绝。

## 3. 一次 campaign 的执行流程

1. 严格校验任务、artifact SHA-256、profile、策略 revision 和字段集合。
2. 在宿主临时目录中逐个创建只读 sample / seeds。
3. 以唯一 owned 容器名运行 `afl-fuzz -h` 和 `afl-showmap -h`，解析版本和
   `-V/-E/-G/-i/-o/-m/-t/-q` 等必需参数；这里只接受 4.04c 已确认支持的能力。
4. 独立 `afl-showmap` probe：只对 seed 执行一次，证明目标确实有 AFL 插桩；
   probe 的 map 被有界解析，不计入“覆盖率证明”。
5. `afl-fuzz` campaign：
   - `-V` 墙钟预算、`-E max_executions-1`（为 probe 保留一次执行）、
     `-G 4096` 输入上限、`-D` 确定性阶段、`-m 256`、`-t 500`。
   - stdin 模式把 seed 喂给 showmap，target stdin 由 AFL 驱动。
   - file 模式把 argv 中唯一的 `{input}` 映射为 AFL 的 `@@`。
6. 捕获 EOF/取消/超时，停止并核验容器、Docker CLI 进程、staging 清理。
7. 只保留受限语料、崩溃候选和 stats；candidate 永远不带 Finding 语义。

时间预算包含工具检查、showmap probe、campaign 执行和清理预留（当前预留 350 ms）。
当预算耗尽时返回 `timeout`，不会把仍在运行的进程或容器当作成功。所有者取消在
help 探测前、两个 help 探测之间、help/probe/campaign 进行中和清理阶段均优先于
真实工具错误：被取消的进程会立即终止，`target_state` 严格为 `cancelled`，不会
被误记为 `failed` 或等待整个 campaign budget 才返回。

清理时先终止并等待本地 Docker CLI 退出，避免 CLI 在 `stop/inspect` 之后才晚创建
容器。随后 `docker stop` 的显式 `No such container`，以及 `inspect` 的显式
`No such object/container`，表示 owned 容器未创建或已不存在，属于成功清理；daemon
不可达、权限错误、其它未知错误，或 inspect 仍显示 running，都必须保持 `failed`，
不能吞掉清理错误。`docker rm -f` 的显式 no-such 也按“已不存在”处理。

## 4. 隔离和硬资源限制

`docker run` 固定参数：

- `--network=none`
- `--read-only`
- `--cap-drop=ALL`
- `--security-opt=no-new-privileges`
- `--user=65534:65534`
- `--cpus=1`
- `--memory=512m`
- `--pids-limit=128`
- `--ulimit core=0`
- `--ulimit nofile=256:256`
- `--log-driver=none`
- `--tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m,nr_inodes=2048`
- `--tmpfs /work/out:rw,nosuid,nodev,noexec,size=64m,nr_inodes=2048,mode=1777`
- 仅 `/work/sample`、`/work/seeds` 两个只读 bind mount；没有宿主可写输出 bind mount。
- `--entrypoint /usr/bin/python3`，执行固定的容器内 supervisor；目标程序只由该
  supervisor 以固定 argv 启动，不使用 shell。

输出/磁盘硬边界：

- 容器输出盘是 64 MiB tmpfs、2048 inode，容器结束即消失。
- 固定 supervisor 只读取 `probe.map`、queue/crashes、`fuzzer_stats` 和白名单文件；
  拒绝 symlink、special file、越界文件名和超大文件。
- supervisor 的 `read_regular` 以可信 `/work/out` 目录 fd 为锚点，逐段使用
  `O_DIRECTORY|O_NOFOLLOW` 打开父目录，最终文件以 `dir_fd` 相对打开并做
  `fstat` 普通文件/大小校验；不再先 lstat 再按路径 open。文件、数量、总量和
  只读 tmpfs 限额保持不变，目录替换或被替换为 symlink/FIFO 时拒绝读取，不会
  读取 `/work/out` 之外的文件。
- supervisor 最多回传 2 MiB JSON；宿主 ByteReader 另有 2 MiB 日志预算。
- 返回 corpus 最多 32 个 / 65536 字节；crashes 最多 `max_crashes` 个 / 每项 4096
  字节；候选在宿主端重新校验长度、规范 base64 和 SHA-256。
- `fuzzer_stats` 只作为不可信输入保存；`stats_trusted=false`。
- 所有 owned container 名以 `artex-afl-` 前缀和随机 UUID 生成，清理时逐个 `rm -f`
  并用 `inspect` 确认不存在；任何清理未确认都会把结果降级为 `failed`。

## 5. 账本、角色和证据权威

- `BeginNativeRuntimeRun` 记录 runtime run；`BeginNativeRun` 写入 `mode=fuzz` 的
  native run，仍绑定 task/artifact/intent/config revision/policy revision。
- `db/schema.sql` 将既有 `reverse_native_runs_mode_check` 从
  `exec/debug/replay` 扩展为 `exec/debug/replay/fuzz`；升级路径是
  `DROP CONSTRAINT IF EXISTS` + `ADD CONSTRAINT`，幂等且保留旧行。
- campaign 证据文件 authority 固定为 `candidate-only`，不会被称为 controlled replay。
- `nativeReplay` 写出的证据 authority 才是 `controlled-replay`。
- 证据上限分离：旧 `native_session` 合法流上限为 3 MiB，因此其证据 envelope 保持
  4 MiB 的独立有界上限；fuzz 证据单独限制为 256 KiB observation + 8 KiB envelope。
  旧的 512 KiB 上限不再错误裁剪 >512 KiB 且 <3 MiB 的合法 session 证据。
- fuzz 在写文件/账本前先序列化完整 request+observation 并检查合并上限 256 KiB。
  合法但合并超限时只生成一份紧凑失败证据，`validated_campaign=false`，
  `target_state=failed`，并让证据文件与账本使用同一份 JSON；不会先保存成功证据
  再把超限 JSON 写入账本。
- `import_candidate` 只生成不可变 `NativeCase`，返回 `replayed=false`，不写 Finding。
- `replay_candidate` 显式要求 `expected_signal 1..64` 和 replay duration，创建 case 后
  通过现有 `nativeReplay` 独立重放；未匹配时返回失败，不自动发布 Finding。
- 候选导入要求源 campaign `target_state=completed`，并读取、核对实际证据文件与账本
  observation 一致；同时校验当前 profile image、policy revision、artifact SHA-256。

## 6. 信任边界

- AFL 的 `fuzzer_stats`、queue/crashes 内容、showmap 结果都是不可信的运行时观察。
- `probe_edges` 只证明“目标有可观测插桩边”，**不证明 campaign 覆盖率**。
- `coverage_claimed=false`、`stats_trusted=false` 是 schema 强制值；不能据此声称
  已覆盖某代码路径、发现漏洞或证明可利用性。
- crash 只是 candidate。只有独立 reviewer 通过不可变 case 的 `nativeReplay` 匹配
  信号/退出断言，并完成既有结论审核后，才可能进入 Finding 工作流；本实现没有自动
  Finding。
- 当前只支持源码插桩的 stdin 或精确 `{input}` 文件模式。没有 QEMU、闭源自动模式、
  网络服务、shell 目标或自动下载。

## 7. 验收依据

隔离候选已完成独立组合验收：Linux 132/132 通过，Windows 122 通过、10 项平台跳过；真实 AFL 容器 5/5 通过，启动阶段取消 8/8 通过。Go/数据库两轮合计 168 个顶层通过事件（含子测试 508 个通过、10 个 opt-in 跳过）；真实 AFL 与 native/GDB 链路两轮合计 4 个顶层通过（含子测试 12 个通过、无跳过）。这些计数不能解释为每轮 168 个顶层测试。

GDB 修复在同一把锁内读取 MI 记录及队列排空后的 EOF，避免正常退出与读取线程关闭并发时被误判为调试器死亡。隔离修复有 200 次确定性交错回归通过，最终组合单测包含对应测试。

合入时逐项核对最终 16 文件 SHA-256 清单，并补做必要回归和真实链路检查。最新结果、复跑命令和证据边界见 [原生功能验收](native-release-validation.md)。

## 8. 配置示例

以下示例表示管理员**显式启用后**的配置。仓库随附 profile 的两个开关均为 false；不要直接将下例覆盖现有运行配置。实验镜像须包含已验证的 AFL++ 4.04c、Python 3、对应 loader/libc，普通 native 镜像不含 AFL++。镜像需事先构建并冻结为不可变 ID/digest；本版不自动拉取或安装实验环境。

```json
[
  {
    "id": "native-x86_64-fuzz",
    "name": "Linux x86-64 fuzz lab",
    "engine": "docker-native",
    "platform": "linux",
    "command": "python3",
    "args": ["/absolute/path/to/artex/scripts/native_runtime.py"],
    "settings": {
      "image": "sha256:<immutable-image-id>",
      "fuzz_enabled": true,
      "enabled": true,
      "network": "none",
      "read_only_root": true,
      "max_duration_ms": 60000
    }
  }
]
```

## 9. 明确未实现

- 持久后台恢复、断点续跑、campaign 队列。
- 多 worker / 多实例并行 AFL。
- 自动下载依赖、外部镜像拉取、网络服务或真实业务目标。
- QEMU、FRIDA、Unicorn、NYX、闭源自动模式或 shell 目标。
- 基于 AFL stats/map 的覆盖率证明、漏洞确认、自动 Finding 或利用链生成。
- 候选自动发布；仍需既有 reviewer 的独立不可变 case 重放和结论审核。
