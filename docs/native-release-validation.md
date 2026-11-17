# v0.7.0 原生功能验收

日期：2026-11-17（北京时间）。范围是已授权的本地合成样本，Linux x86-64 原生分析、AFL++ 最小闭环和 GDB 结束竞态修复。不是 ARTEX 全功能、真实产品漏洞、真实模型效果或原设计 N01–N15 全矩阵签核。

## 候选与合入

隔离候选基于 `f967144`，最终清单包含 16 个新增/修改文件、无删除。合入前逐项核对 SHA-256，并把候选中其余已跟踪文件与该基线归档比较；程序和测试文件原样合入。随后补充版本说明、默认关闭的 profile 字段和安装包文档。

候选来自本机 Harness 实现及 Codex 独立复核。既有最终组合证据位于工作目录的 `fuzz-minimal-20261117/evidence/FINAL-INDEPENDENT-ACCEPTANCE.md` 和 `final-candidate-manifest.json`。该轮 Linux 单测 132/132、Windows 122 通过和 10 平台跳过；真实 AFL 5/5；启动取消 8/8；Go/DB 两轮合计 168 个顶层通过，真实 AFL 与 native/GDB 链路两轮合计 4 个顶层通过。上述是两轮合计，不能写成每轮 168 个顶层通过。

## 合入后的独立检查

本轮日志集中在工作目录 `release-v0.7.0-20261117/`；`integration.json`、`candidate-verification.json` 记录源文件与哈希，以下日志均独立保留。

| 检查 | 实际结果 | 日志 |
| --- | --- | --- |
| Linux Python 单元/协议 | 132 通过，0 跳过 | `python-linux.log` |
| Windows Python 单元/协议 | 122 通过、10 平台跳过 | `python-windows.log` |
| Go/DB 定向回归 | 87 个顶层通过；含子测试 257 通过、5 opt-in 跳过 | `go-regression.log`、`go-regression.json` |
| Go → Python → Docker → PG 真实链路 | AFL、原 native/GDB 两个顶层测试通过；含子测试 6 通过、0 跳过 | `go-real-chains.log`、`go-real-chains.json` |
| 真实 AFL 容器集成 | 5/5 通过，0 跳过 | `docker-afl.log` |
| Linux / Windows amd64 构建 | 均通过；未启动 Windows 程序 | `go-build-linux.log`、`go-build-windows.log` |
| 自动更新包 / 发布脚本 | `go test -count=1 ./selfupdate` 与四个 shell 脚本语法检查通过 | `release-go-gate.log`、`shell-syntax.log` |
| 临时 PostgreSQL 清理 | 本轮私有 Unix socket 实例已停止 | `pg-stop.log` |

真实 AFL 检查覆盖 stdin 与文件输入的 campaign→crash→独立 replay、未插桩拒绝、启动取消、确认运行后的取消。运行态检查观察到 `execs_done=8` 后取消，约 0.321 秒返回并通过清理断言。该数字是本次观测，不是时延承诺或覆盖率证明。

Go/DB 常规回归使用真实独立 PostgreSQL、模拟 runner/provider。跳过的两项原生/AFL 真实链路已单独启用并通过；另外三项是逆向真实引擎、Hermes 材料、团队浏览器预览，未在本轮补跑或算作通过。Windows 平台跳过涉及 symlink 权限、Linux 文件描述符 API 和 core reader；对应 Linux 检查已执行。

首次 Linux 构建因 root 读取 Windows 挂载仓库触发 Git 所有权检查而失败，原日志保留为 `go-build-linux.attempt1.log`。仅为本次构建命令设置该目录的 `safe.directory` 后通过，未禁用 VCS 信息、未修改全局 Git 或凭据配置。前端源码未改，复用此前静态构建证据，并由标签流水线重新执行前端构建。

## 复跑入口

```sh
python3 -B -m unittest \
  scripts.native_runner.test_native_runner \
  scripts.native_runner.test_native_cases \
  scripts.native_runner.test_native_contract \
  scripts.native_runner.test_native_fuzz \
  scripts.native_runner.test_gdb_eof_atomic -v

# ARTEX_PG_DSN 必须指向新建的隔离测试库，不能使用业务数据库。
ARTEX_FUZZ_TEST_DB=1 go test ./db ./agent ./server -p 1 \
  -run 'TestNative|TestValidateNative|TestReverse|TestClassifyTask|TestAuto|TestTaskArchive|TestTeam.*Native' \
  -count=1 -timeout=5m -json

# 预先准备固定的本地实验镜像；测试只执行仓库合成 fixture。
ARTEX_FUZZ_REAL_DOCKER=1 ARTEX_FUZZ_REAL_IMAGE=<immutable-afl-image> \
  python3 -B -m unittest scripts.native_runner.test_native_fuzz_integration -v

# 同时设置隔离 ARTEX_PG_DSN 和显式测试开关：
ARTEX_FUZZ_TEST_DB=1 ARTEX_FUZZ_REAL_DOCKER=1 \
ARTEX_FUZZ_REAL_IMAGE=<immutable-afl-image> \
ARTEX_NATIVE_CHAIN_ALLOW_TEST_DB=1 ARTEX_NATIVE_CHAIN_IMAGE=<immutable-native-image> \
  go test ./server -run '^Test(NativeFuzzRealContainerClosedLoop|NativeRealPythonDockerChain)$' \
  -count=1 -timeout=4m -json
```

## 环境和结论边界

- Native 镜像 ID：`sha256:3d6f2e5ae0ab60a4c4cfcd8d49f5d65976327471222f696b259c05eca04c1963`；AFL 镜像 ID：`sha256:adb642984dc2d4ea23abda236ec24f9a0855c6c694b3e0149274a19a983c59da`。本地固定 Debian 工具链，AFL++ 4.04c。这是本地 image ID，不能当作已发布实验镜像的 registry digest。
- 实验镜像使用官方 Debian 包离线准备，未验证仓库 native Dockerfile 在线 apt 重建，未发布该实验镜像。主程序 GHCR 镜像与实验镜像不同，不自动配置 Docker、AFL++、GDB 或运行授权。
- 此轮临时数据库使用新建私有 Unix socket，未连接业务库或改动已有集群；未调用真实模型，未部署或重启 ARTEX 业务实例。
- Native case v1/v2、独立审核与 Finding/归档代码已有相应单元和模拟集成证据，但本次真实端到端测试并未穷尽这些组合。完整 N01–N15 中配对 ASan/普通构建追溯、服务重启/lease 联合场景、最小化负例等仍需额外场景验收，不宣称全矩阵通过。
- 仅支持源码插桩 ELF 的同步单 worker AFL campaign；无持久恢复/队列、多 worker、QEMU/Frida binary-only、网络服务目标、自动利用链或自动 Finding。crash 只是候选，AFL 统计与 map 不作为漏洞或覆盖率证明。
