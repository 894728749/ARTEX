"use client";

import * as React from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";

export function TeamConnectionGuide({ team, admin }: { team: string; admin: boolean }) {
  const [origin, setOrigin] = React.useState("");
  const [address, setAddress] = React.useState("");
  const [current, setCurrent] = React.useState("");
  const [error, setError] = React.useState("");
  const [notice, setNotice] = React.useState("");
  React.useEffect(() => { setCurrent(window.location.origin); if (window.location.protocol === "https:") setOrigin(window.location.origin); }, []);
  function download() {
    setError(""); setNotice("");
    try {
      const url = new URL(origin);
      if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || (url.pathname !== "/" && url.pathname !== "")) throw new Error("请填写不含路径、凭据或查询参数的 HTTPS 协调端地址。");
      if (["localhost", "127.0.0.1", "[::1]", "0.0.0.0"].includes(url.hostname)) throw new Error("第二台设备不能使用本机回环地址，请填写成员设备可到达且匹配证书的主机名或 LAN 地址。");
      const lan = address.trim();
      if (lan && (!/^(?:[a-zA-Z0-9.-]+|\[[0-9a-fA-F:]+\]):\d{1,5}$/.test(lan) || Number(lan.split(":").at(-1)) < 1 || Number(lan.split(":").at(-1)) > 65535)) throw new Error("LAN 地址应为主机名或 IP:有效端口，例如 192.168.1.10:8789。");
      const config = { coordinator_url: url.origin, server_name: url.hostname.replace(/^\[|\]$/g, ""), ca_file: "coordinator-ca.pem", lan_addresses: [lan || (url.port ? url.host : `${url.hostname}:443`)] };
      const blob = new Blob([JSON.stringify(config, null, 2) + "\n"], { type: "application/json" });
      const downloadURL = URL.createObjectURL(blob); const link = document.createElement("a"); link.href = downloadURL; link.download = "node.json"; link.click(); URL.revokeObjectURL(downloadURL);
      setNotice("连接模板已下载；请放入已核对来源的证书，运行 check 验证。模板不含配对码、设备身份、模型密钥或执行授权。");
    } catch (e) { setError((e as Error).message); }
  }
  return <Card><CardHeader><CardTitle>跨设备接入</CardTitle></CardHeader><CardContent className="space-y-4">
    <p className="text-sm">团队编号 <strong>{team}</strong>。成员使用团队账号登录网页；执行设备使用独立 Node 身份，两者分别授权。</p>
    {current.startsWith("http:") && <p role="status" className="rounded-md border p-3 text-sm">当前是 {current}。此地址不能直接用作 Node 的 HTTPS 协调端；localhost 也不能供另一台设备访问。</p>}
    <details className="rounded-md border p-3"><summary className="cursor-pointer py-1 font-medium">接入步骤与地址配置</summary><div className="mt-3 space-y-4 text-sm">
      <ol className="list-decimal space-y-3 pl-5">
        <li>{admin ? "管理员保留本机 HTTP 管理入口，另开启仅供成员/设备使用的 TLS 监听。" : "向管理员获取成员 HTTPS 地址、团队编号、账号和协调端证书。"}主机端使用 <code>-team-addr LAN_IP:8789 -tls-cert server.pem -tls-key server.key</code>；证书名称必须匹配成员地址。先按安装包中的 <code>docs/team-onboarding.md</code> 配置网络，再修改启动参数。</li>
        <li>成员浏览器访问 <code>https://协调端:8789/team-login/</code>。私有 CA 需先经可信渠道核对并导入浏览器信任。WSL NAT 环境还需要把这个成员端口定向转发至 WSL，并限制 Windows 防火墙的来源地址。</li>
        <li>执行端安装与主端同版本的 <code>artex-node</code>（Windows 为 <code>artex-node.exe</code>）。检查 <code>artex-node -version</code>，保存下方连接模板和公开 CA 证书；私钥留在主端。</li>
        <li>执行 <code>artex-node -config node.json check</code> 检查 TLS 和本地配置。再在本页生成配对码，执行 <code>artex-node -config node.json pair</code>，按提示输入一次性码，然后用 <code>status</code> 确认设备编号。</li>
        <li>在节点本地补充 <code>execution</code>、独立模型角色和 MCP/命令绑定，启用 <code>execution.branches.enabled</code>。密钥只由环境变量读取；运行 <code>check</code> 后再运行 <code>artex-node -config node.json run</code>。配对本身不会执行任务。</li>
        <li>管理员先授予任务基础权限，再启用分支并授予分支权限。发布工作 → 成员用自己的就绪设备领取 → 管理者恢复主项目 → 查看消息、发送指导 → 由另一名获授权成员复核。自动发布需要单独发布并认领“协调器工作”。</li>
      </ol>
      <p className="text-muted-foreground">Node 优先连接 LAN 候选地址，连接故障时可按配置回退至 Relay，仍校验同一个协调端证书。浏览器不会自动使用 Node 的 Relay；异地成员网页建议通过团队 VPN 访问成员 HTTPS 地址。Relay 地址、房间及密钥环境变量需由管理员另行提供。</p>
      <div className="grid gap-3 sm:grid-cols-2"><div className="space-y-2"><Label htmlFor="team-coordinator-origin">成员与设备 HTTPS 地址</Label><Input id="team-coordinator-origin" value={origin} onChange={(e) => setOrigin(e.target.value)} placeholder="https://artex-team.example:8789" /></div><div className="space-y-2"><Label htmlFor="team-lan-address">LAN 候选 IP:端口（可选）</Label><Input id="team-lan-address" value={address} onChange={(e) => setAddress(e.target.value)} placeholder="192.168.1.10:8789" /></div></div>
      <Button type="button" variant="outline" onClick={download}>下载不含凭据的连接模板</Button>
      <p className="text-xs text-muted-foreground">此处只生成文件，不会开放端口、修改服务器设置或探测输入地址。连通性以 Node check 的实际结果为准。</p>
      {error && <p role="alert" className="text-destructive">{error}</p>}{notice && <p role="status">{notice}</p>}
    </div></details>
  </CardContent></Card>;
}
