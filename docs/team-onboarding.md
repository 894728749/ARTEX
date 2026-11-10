# 团队网页与执行节点接入

本指南对应带 `artex-node check` 和受限成员监听的版本。升级主程序不会自动开放网络、创建成员、分配权限或启动节点。现有 v0.5.0 Release 的安装包没有 Node；使用本次修复源码构建的配套 Node。本次修改后生成的安装包会附带同版本 `artex-node`、配置示例及本指南。不要把文档更新当作旧二进制已经具备新功能。

## 1. 分清三个入口

| 入口 | 用途 | 身份 |
| --- | --- | --- |
| 主端 `http://127.0.0.1:8787` | 管理员、原本机任务与配置 | 管理员密码 |
| 成员 `https://团队主机:8789/team-login/` | 团队工作区、认领、讨论、指导、复核 | 团队编号 + 成员账号密码 |
| Node `https://团队主机:8789` | 配对、状态和获准的设备工作 | 一次性配对码换取设备身份 |

第二台设备上的 `localhost` 指向它自己，不能填主端的 localhost。Node 必须使用 HTTPS origin（不带路径、查询参数或用户名密码）。网页和 Node 都要信任协调端证书，名称必须匹配。模型、MCP 凭据与工具路径不随团队同步。

## 2. 主端选择网络方案

建议小团队先用团队 VPN 或受限 LAN。管理员监听保留回环，只开放独立成员端口，不做公网路由器端口映射。浏览器需要可到达的 HTTPS 地址；Node 的 LAN/Relay 切换不会为浏览器提供隧道。

主端程序已支持以下参数；把它们加入自己实际使用的启动脚本参数中，**在任务空闲时**重启。保留原有数据库、`-data`、代理及环境变量：

```sh
./start.sh -addr 127.0.0.1:8787 -proxy 127.0.0.1:8788 -data /existing/runtime/data \
  -team-addr 192.168.1.10:8789 \
  -tls-cert /private/team-server.pem -tls-key /private/team-server.key
```

将示例 IP 和路径换成实际配置。`-team-addr` 必须是当前系统能绑定的地址。仅设置 `-tls-cert/-tls-key` 而不设置 `-team-addr` 会让原 HTTP 监听整体改用 TLS，不能用于保持旧本机启动检查不变的方案。

独立成员监听和 Relay 只提供成员登录、团队工作区及设备 API；管理员登录、初始化、模型/MCP 配置及普通任务 API 被拒绝，管理员 JWT 也不能在成员入口执行管理操作。原本机 `-addr` 的管理员行为不变。

### TLS 证书

使用已有团队 CA 或可信内部证书；通过独立可信渠道核对公开 CA/证书指纹。仅公开证书分发给成员，私钥留在主端。证书 SAN 必须包含实际使用的 DNS 名或 IP。若没有团队 CA，可为受控试用生成短期自签证书，例如：

```sh
umask 077
openssl req -x509 -newkey rsa:3072 -nodes -days 90 \
  -keyout team-server.key -out team-server.pem \
  -subj '/CN=artex-team.local' \
  -addext 'subjectAltName=DNS:artex-team.local,IP:192.168.1.10' \
  -addext 'extendedKeyUsage=serverAuth'
openssl x509 -in team-server.pem -noout -fingerprint -sha256
```

生成前替换名称/IP，不覆盖已有私钥。成员 Node 用 `ca_file` 指向收到并核对的公开证书；浏览器使用自己的证书信任机制。不要通过关闭证书校验来排除错误。

### Windows 脚本启动的 WSL 实例

原脚本中的 `-addr 127.0.0.1:8787` 应保留。WSL NAT 下，Windows 的 localhost 转发不等于其他 LAN 主机能访问 WSL：

1. 找出当前 WSL 网卡 IPv4，将成员监听绑定到该 WSL 地址的 `8789` 端口。
2. 如无团队 VPN/既有转发，管理员可在提升权限的 PowerShell 中为**一个 Windows LAN 地址、一个成员端口**配置转发。示例命令只用于说明，不会由 ARTEX 自动执行：

```powershell
# 三个地址均需按当前机器与成员网段填写；WSL 重启后应重新核对其 IP。
netsh interface portproxy add v4tov4 listenaddress=192.168.1.10 listenport=8789 connectaddress=172.24.130.20 connectport=8789
New-NetFirewallRule -DisplayName 'ARTEX team LAN 8789' -Direction Inbound -Action Allow -Protocol TCP -LocalAddress 192.168.1.10 -LocalPort 8789 -RemoteAddress 192.168.1.0/24 -Profile Private
```

撤销时删除同一条规则和同一地址/端口的转发；不要改 `8787` 管理入口。已有同端口转发时先核对，不覆盖别的服务。若选择 VPN，先确认 VPN 路由到的是成员监听，并使用 VPN 允许的来源范围。

## 3. 安装并核对 Node

配套安装包含 `artex-node`（Windows 为 `artex-node.exe`）。也可从与主端相同源码版本构建：

```sh
go build -trimpath -ldflags '-X main.version=你的构建版本' -o artex-node ./cmd/artex-node
./artex-node -version
```

Windows 在 PowerShell 使用 `./artex-node.exe`；WSL 使用 Linux 二进制。`-version` 不读取配置、不连接网络。旧 v0.5.0 Node 没有此开关，应更新配套 Node 后再照本指南执行。

在节点自己的私有目录保存 `node.json` 和 `coordinator-ca.pem`：

```json
{
  "coordinator_url": "https://artex-team.local:8789",
  "server_name": "artex-team.local",
  "ca_file": "coordinator-ca.pem",
  "lan_addresses": ["192.168.1.10:8789"]
}
```

`server_name` 按证书名称填写。LAN 候选可直接写 IP:端口，无需修改 TLS 身份。相对 CA 路径以启动工作目录解析。

```sh
./artex-node -config node.json check
./artex-node -config node.json -name member-laptop pair
./artex-node -config node.json status
```

`check` 只验证配置、TLS 和 `/api/health`，显示 LAN/Relay 路线与主端/节点版本；不创建身份、不领取工作、不调用模型或启动 MCP。版本不同会明确提示，应使用同版本构建。第一次 `pair` 按提示输入网页生成的 10 分钟单次配对码，不把它写入共享配置或命令历史。默认身份文件为 `node-state/identity.json`，不要上传、复制到另一台设备或覆盖已有身份。每台设备独立配对。

## 4. 配置本地模型与 MCP

以 `examples/team-node-branches.example.json` 的 `execution` 为起点，合并到连接配置；保持未用能力为空。按需配置渗透 `planner/worker/reviewer` 或逆向 `reverse_planner/reverse_static/reverse_reviewer`，不同工作流不得借用另一类角色兜底。动态观察另需本地 profile 和主端针对具体工作单的单次授权。

- `models` 中只放端点、模型名和 `api_key_env` 名称，实际密钥通过节点进程环境提供。
- `roles` 指向节点本地模型与允许能力。Planner 没有外部工具能力。
- `commands` 或 `mcp_servers/mcp_tools` 显式绑定本地可执行文件与工具别名；执行路径不从共享工作单获取。
- 外部能力同时需要主任务角色、工作单和本机角色授权；`branches.scope_fields` 指定工具输入中的目标字段，限制在获准资产内。这不等同于操作系统沙箱。
- `read_material` 由节点内置提供，不要将它注册为外部命令/MCP 或放进本地角色的外部能力列表；主端角色可授权它。
- `work_dir/outbox_dir` 使用节点自己的绝对私有目录。配置 `branches.enabled: true` 后，先运行 `check` 检查角色、工具文件、范围字段及密钥环境变量是否齐全，再运行 `run`。

```sh
./artex-node -config node.json check
./artex-node -config node.json run
```

`check` 不保证模型服务和 MCP 实际调用成功；执行前是否具备某个分支要求，仍以节点就绪回执为准。`run` 是持续进程，停止后未完成工作留在原分支，不会生成新的主任务。

## 5. 界面完成授权与工作闭环

1. 管理员创建团队，记下选择框/管理卡片展示的编号；同名团队以编号辨识。创建执行成员和另一位独立复核成员。
2. “任务基础授权”选择任务编号和成员，一次保存所选权限，已有授权可见并可编辑。全部取消会撤销此成员的基础授权。通常先给予任务查看，执行成员再明确给予执行。
3. 在已共享、已暂停且没有旧执行的任务中启用执行分支，设置目标、资产、角色能力与总额度。
4. 展开“成员分支权限”，逐项授予 `read/process/evidence/discuss/execute/guide/control/review/manage`。这些权限相互独立；基础查看+执行不自动获得分支权限。执行者需要分支查看+执行；消息查看需过程权限，讨论和指导分别授权；复核者独立授予查看及复核，证据访问另行授予。
5. 成员配对并运行自己的节点。管理员发布普通工作项，成员登录工作区，选择自己的设备认领。待就绪原因会显示在分支中；成员不能冒用其他成员的设备。
6. 管理者恢复主项目。讨论只记录共享消息，“发送指导”才进入设备队列，回执区分已排队、收到和应用。工具证据内容需额外证据权限，消息查看不等于获得工具返回内容。
7. 节点技术核验完成后，另一名没有参与执行的获授权成员独立复核。分支验收不自动完成主任务。

需要自动拆分工作时，在发布表单勾选“作为协调器工作”，并分配预算、范围和验收条件；该协调器分支也必须被成员认领到就绪节点并在主项目恢复后运行。`auto_publish` 未勾选时提议待管理者批准；勾选后也只在既定范围/总预算内发布，不会替成员自动认领。普通分支不能充当协调器发布任意工作。

权限撤销在下一次服务端检查生效，节点失去权限后不启动下一操作；已经开始的有界操作按现有停止规则处理。网页失去权限会清除内存中的不可见内容，已经下载的文件无法远程收回。

## 6. LAN 首选与 Relay 回退

Node 的 `lan_addresses` 按序尝试。网络不可达时，设置以下字段才启用 Relay；TLS 身份错误不会通过换路线绕过校验：

```json
{
  "relay_url": "wss://relay.example/relay",
  "relay_room": "your-private-team-room",
  "relay_peer": "stable-coordinator-id",
  "relay_secret_env": "ARTEX_RELAY_SECRET"
}
```

实际 Relay URL 路径按自己的服务配置，主端同时配置 `-relay-url`、`-relay-room`、`-relay-peer` 和环境变量 `ARTEX_RELAY_SECRET`。Relay 是字节转发，协调端 TLS 仍在两端验证；公开证书、room、peer 保持同一团队身份。Relay 密钥只配置到相关进程环境。

`artex-relay` 源码位于 `cmd/artex-relay`，默认监听回环，远程使用需自己已有的 TLS 入口；不要把未认证的代理当作 Relay。浏览器异地访问采用团队 VPN，不能把 `wss://` 填进成员网页地址。

## 删除与故障排查

仅管理员可删除真正空团队，需输入团队编号确认；有成员（包括已撤销成员）、配对、设备、任务或协作历史时明确拒绝，保留审计。本版没有擦除历史的强制删除入口。

| 现象 | 检查 |
| --- | --- |
| 网页有任务但分支报无权限 | 基础权限与“成员分支权限”都需分别配置；读不隐含过程或执行 |
| 无法选择设备 | Node 已配对、正在 run、分支协议开启、设备属于当前成员且具备工作所需角色 |
| 等待设备就绪 | 查看原因，检查本地角色、模型密钥变量、工具能力和材料版本；不重复配对 |
| 无自动发布 | 已勾 auto_publish，并实际发布/认领 coordinator 工作，项目已恢复，预算足够 |
| HTTP 地址被拒绝 | Node 仅支持 HTTPS；检查独立成员监听而不是原管理员 localhost |
| TLS 错误 | 地址/名称/SAN、公开 CA、证书时间与信任来源；不要关校验 |
| WSL 本机能开、第二台打不开 | 检查成员监听绑定、当前 WSL IP、指定端口转发和来源受限的防火墙 |

验收只使用本机隔离数据库、合成团队/身份、TLS 服务和假模型。物理第二台设备、生产 LAN/NAT/VPN 与远程 Relay 需要在具备对应设备/网络后另行实测。
