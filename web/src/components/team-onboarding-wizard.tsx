"use client";

import * as React from "react";
import { http } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

type Address = { ip: string; interface: string; cidr: string; host: boolean };
type Device = { id: number; name: string; online: boolean; execution_enabled: boolean; branch_protocol: number; role_count: number };
type Check = { code: string; status: string; title: string; detail: string };
type Onboarding = {
  admin: boolean;
  environment: { os: string; arch: string; wsl: boolean; distro?: string; addresses: Address[] };
  state: { enabled: boolean; external: boolean; origin?: string; listen_address?: string; allowed_cidr?: string; fingerprint?: string; expires_at?: string; needs_host_bridge: boolean; local_tls_verified: boolean; error?: string };
  platforms: string[];
  ai_available: boolean;
  devices: Device[];
  checks: Check[];
};
type Plan = { id: string; input: { bind_ip: string; public_ip: string; port: number; allowed_cidr: string }; origin: string; steps: string[]; needs_host_bridge: boolean; expires_at: string };
type Member = { id: number; login: string; revoked: boolean };
type Assist = { source: "ai" | "checks"; summary: string; steps: string[]; recommended_action: string };
type Workspace = { member_id: number };

const issueOptions = [
  ["explain", "解释当前状态"], ["tls", "TLS 证书或名称校验"], ["unreachable", "成员设备无法连接"],
  ["model", "模型未就绪"], ["tools", "本地工具未配置"], ["pairing", "设备配对问题"],
] as const;
const actionNames: Record<string, string> = { prepare: "预览主端方案", host_bridge: "配置 Windows 桥接", download: "下载成员接入包", pair: "生成配对码", configure_models: "在成员本机配置模型", configure_tools: "在成员本机配置工具", refresh: "刷新接入状态" };
const platformNames: Record<string, string> = { "windows-amd64": "Windows · x64", "windows-arm64": "Windows · ARM64", "linux-amd64": "Linux · x64", "linux-arm64": "Linux · ARM64", "darwin-amd64": "macOS · Intel", "darwin-arm64": "macOS · Apple 芯片" };

function teamPath(team: string) { return `/teams/${encodeURIComponent(team)}/onboarding`; }
function getToken() { return typeof window === "undefined" ? null : localStorage.getItem("artex_token"); }
async function downloadAuthorized(path: string, fallback: string) {
  const token = getToken();
  const response = await fetch(`/api${path}`, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
  if (!response.ok) {
    let message = `下载失败（${response.status}）`;
    try { const body = await response.json() as { error?: string }; if (body.error) message = body.error; } catch { /* status is enough */ }
    throw new Error(message);
  }
  const blob = await response.blob();
  const disposition = response.headers.get("Content-Disposition") ?? "";
  const match = disposition.match(/filename\*?=(?:UTF-8'')?"?([^";]+)/i);
  const filename = match?.[1] ? decodeURIComponent(match[1]) : fallback;
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a"); anchor.href = url; anchor.download = filename; document.body.append(anchor); anchor.click(); anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function statusLabel(status: string) {
  if (["ok", "ready", "pass", "available", "verified"].includes(status.toLowerCase())) return "就绪";
  if (["error", "failed", "blocked"].includes(status.toLowerCase())) return "需处理";
  if (["warning", "warn", "pending", "missing"].includes(status.toLowerCase())) return "待检查";
  if (status === "manual") return "需确认";
  return status || "未知";
}

export function TeamOnboardingWizard({ team, admin }: { team: string; admin: boolean }) {
  const [data, setData] = React.useState<Onboarding | null>(null);
  const [members, setMembers] = React.useState<Member[]>([]);
  const [memberID, setMemberID] = React.useState<number | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");
  const [notice, setNotice] = React.useState("");
  const [bindIP, setBindIP] = React.useState("");
  const [publicIP, setPublicIP] = React.useState("");
  const [port, setPort] = React.useState("8789");
  const [allowedCIDR, setAllowedCIDR] = React.useState("");
  const [plan, setPlan] = React.useState<Plan | null>(null);
  const [issue, setIssue] = React.useState<(typeof issueOptions)[number][0]>("explain");
  const [assist, setAssist] = React.useState<Assist | null>(null);
  const [platform, setPlatform] = React.useState("");
  const [pairingCode, setPairingCode] = React.useState("");

  const refresh = React.useCallback(async () => {
    setLoading(true); setError("");
    try {
      const result = await http<Onboarding>(teamPath(team));
      setData(result);
      const local = result.environment.addresses.find((a) => !a.host);
      const published = result.environment.addresses.find((a) => a.host) ?? local;
      setBindIP((old) => old || local?.ip || "");
      setPublicIP((old) => old || published?.ip || "");
      setAllowedCIDR((old) => old || published?.cidr || "");
      const preferredPlatform = navigator.userAgent.includes("Windows") ? "windows-amd64" : navigator.userAgent.includes("Mac") ? "darwin-arm64" : "linux-amd64";
      setPlatform((old) => old || (result.platforms.includes(preferredPlatform) ? preferredPlatform : result.platforms[0]) || "");
      if (admin) {
        const [memberList] = await Promise.all([http<Member[]>(`/teams/${encodeURIComponent(team)}/members`)]);
        setMembers(memberList.filter((m) => !m.revoked));
      } else {
        const workspace = await http<Workspace>(`/teams/${encodeURIComponent(team)}/workspace`);
        setMemberID(workspace.member_id);
      }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  }, [admin, team]);
  React.useEffect(() => { void refresh(); }, [refresh]);
  React.useEffect(() => {
    if (!pairingCode) return;
    const timer = window.setTimeout(() => setPairingCode(""), 600000);
    return () => window.clearTimeout(timer);
  }, [pairingCode]);

  React.useEffect(() => {
    const timer = window.setInterval(() => {
      if (busy || document.hidden) return;
      void http<Onboarding>(teamPath(team)).then(setData).catch(() => {
        setError("自动刷新失败，设备状态可能已过期。请点击刷新状态重试。");
      });
    }, 10000);
    return () => window.clearInterval(timer);
  }, [busy, team]);

  async function action<T>(fn: () => Promise<T>, success?: string): Promise<T | undefined> {
    if (busy) return;
    setBusy(true); setError(""); setNotice("");
    try { const value = await fn(); if (success) setNotice(success); return value; }
    catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  }
  async function createPlan(event: React.FormEvent) {
    event.preventDefault(); setPlan(null);
    const result = await action(() => http<Plan>(`${teamPath(team)}/plan`, { method: "POST", body: JSON.stringify({ bind_ip: bindIP, public_ip: publicIP, port: Number(port), allowed_cidr: allowedCIDR }) }), "方案已生成；确认前不会变更监听设置。");
    if (result) setPlan(result);
  }
  async function applyPlan() {
    if (!plan || !window.confirm(`请确认应用以下受限 TLS 监听计划：\n\n${plan.steps.join("\n")}\n\n此操作会向所选网段开放成员连接。`)) return;
    const result = await action(() => http<Onboarding["state"]>(`${teamPath(team)}/apply`, { method: "POST", body: JSON.stringify({ plan_id: plan.id, confirm: true }) }), "受管成员 TLS 监听已应用。");
    if (result) { setPlan(null); await refresh(); }
  }
  async function disable() {
    if (!window.confirm("停用所有团队共用的成员 TLS 入口？所有团队的远端成员和设备会断开连接。本机任务引擎继续运行。")) return;
    const result = await action(() => http<Onboarding["state"]>(`${teamPath(team)}/disable`, { method: "POST", body: JSON.stringify({ confirm: true }) }), "成员 TLS 监听已停用。");
    if (result) await refresh();
  }
  async function explain() {
    const result = await action(() => http<Assist>(`${teamPath(team)}/assist`, { method: "POST", body: JSON.stringify({ issue }) }));
    if (result) setAssist(result);
  }
  async function getPairing() {
    const owner = memberID;
    if (!owner) { setError("请先选择设备所属成员。"); return; }
    const result = await action(() => http<{ pairing_token: string }>(`/teams/${encodeURIComponent(team)}/pairings`, { method: "POST", body: JSON.stringify({ member_id: owner }) }));
    if (result) setPairingCode(result.pairing_token);
  }
  const state = data?.state;

  return <Card>
    <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3 space-y-0">
      <div><CardTitle>跨设备接入向导</CardTitle><p className="mt-1 text-sm text-muted-foreground">准备主端 → 成员运行接入包 → 核对设备。地址和网段会根据本机环境预填。</p></div>
      <Button type="button" variant="outline" disabled={busy || loading} onClick={() => void refresh()}>刷新状态</Button>
    </CardHeader>
    <CardContent className="space-y-5">
      {error && <p role="alert" className="rounded-md border border-destructive/40 p-3 text-sm text-destructive">{error} <Button className="ml-2" variant="outline" size="sm" disabled={busy} onClick={() => void refresh()}>重试</Button></p>}
      {notice && <p role="status" className="rounded-md border border-primary/30 bg-primary/5 p-3 text-sm">{notice}</p>}
      {loading && !data ? <p role="status" className="text-sm text-muted-foreground">正在读取接入状态…</p> : null}
      {!loading && !data && !error && <p className="text-sm text-muted-foreground">当前账号没有可用的接入信息。</p>}
      {data && <>
        <section aria-labelledby="onboarding-status-title" className="space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2"><h3 id="onboarding-status-title" className="font-medium">当前状态</h3><Badge variant={state?.enabled ? "secondary" : "outline"}>{state?.enabled ? "成员入口已启用" : "尚未启用"}</Badge></div>
          <p className="text-xs text-muted-foreground">每 10 秒核对设备状态。配对成功但未启动 Node 时会显示离线；本机 TLS 自检不能证明第二台设备可达。</p>
          {state?.external && <p className="rounded-md border border-amber-500/40 bg-amber-500/5 p-3 text-sm">TLS/Relay 入口由外部 CLI 管理。向导不会接管或覆盖；请继续使用现有配置，或先在 CLI 中完成管理。</p>}
          {state?.enabled && <dl className="grid gap-2 rounded-md border p-3 text-sm sm:grid-cols-2"><div><dt className="text-muted-foreground">成员地址</dt><dd className="break-all font-mono">{state.origin || "未发布"}</dd></div><div><dt className="text-muted-foreground">监听地址 / 网段</dt><dd className="break-all font-mono">{state.listen_address || "未知"}{state.allowed_cidr ? ` · ${state.allowed_cidr}` : ""}</dd></div><div><dt className="text-muted-foreground">TLS 指纹</dt><dd className="break-all font-mono">{state.fingerprint || "未知"}</dd></div><div><dt className="text-muted-foreground">有效期</dt><dd>{state.expires_at || "由协调端管理"}</dd></div></dl>}
          {state?.error && <p role="alert" className="rounded-md border border-destructive/40 p-3 text-sm text-destructive">{state.error}</p>}
          <p className="text-xs text-muted-foreground">检测环境：{data.environment.os} · {data.environment.arch}{data.environment.wsl ? ` · WSL${data.environment.distro ? ` (${data.environment.distro})` : ""}` : ""}</p>
          {state?.needs_host_bridge && <p className="rounded-md border border-amber-500/40 p-3 text-sm">检测到 WSL 主机桥接需求。下载脚本仅供预览；请交由 Windows 管理员审阅并使用 <code>-Apply</code> 执行。该脚本不会由 AI 生成。</p>}
          <div className="grid gap-2 md:grid-cols-2">{data.checks.map((check) => <div key={check.code} className="flex items-start justify-between gap-3 rounded-md border p-3 text-sm"><div><p className="font-medium">{check.title}</p><p className="mt-1 text-muted-foreground">{check.detail}</p></div><Badge className="shrink-0" variant={statusLabel(check.status) === "需处理" ? "destructive" : "outline"}>{statusLabel(check.status)}</Badge></div>)}</div>
        </section>

        {admin && !state?.external && <details open={!state?.enabled} className="space-y-3 border-t pt-4">
          <summary className="cursor-pointer py-2 font-medium">1. 准备主端{state?.enabled ? "（已完成，展开查看设置）" : ""}</summary>
          <p className="text-sm text-muted-foreground">向导只根据本机检测出的地址生成受限计划。WSL 环境可将检测到的 Windows 主机地址作为公开地址；不会重启任务引擎。</p>
          <form className="grid gap-3 sm:grid-cols-2" onSubmit={(e) => void createPlan(e)}>
            <div className="space-y-2"><Label htmlFor="onboarding-bind">本机监听 IPv4</Label><select id="onboarding-bind" value={bindIP} required disabled={busy || data.environment.addresses.length === 0} onChange={(e) => { setBindIP(e.target.value); if (!data.environment.wsl) { const selected = data.environment.addresses.find((a) => a.ip === e.target.value); setPublicIP(e.target.value); setAllowedCIDR(selected?.cidr ?? ""); } setPlan(null); }} className="min-h-10 w-full rounded-md border bg-background px-3 text-sm"><option value="">选择检测到的地址</option>{data.environment.addresses.filter((a) => !a.host).map((a) => <option key={`${a.ip}-${a.interface}`} value={a.ip}>{a.ip} · {a.interface} · {a.cidr}</option>)}</select></div>
            <div className="space-y-2"><Label htmlFor="onboarding-public">成员可访问地址 IP</Label><select id="onboarding-public" value={publicIP} required disabled={busy} onChange={(e) => { setPublicIP(e.target.value); setAllowedCIDR(data.environment.addresses.find((a) => a.ip === e.target.value)?.cidr ?? ""); setPlan(null); }} className="min-h-10 w-full rounded-md border bg-background px-3 text-sm"><option value="">选择成员可访问地址</option>{data.environment.addresses.map((a) => <option key={`${a.ip}-${a.interface}`} value={a.ip}>{a.ip} · {a.host ? `${a.interface}（Windows 主机）` : a.interface}</option>)}</select></div>
            <div className="space-y-2"><Label htmlFor="onboarding-port">成员 TLS 端口</Label><Input id="onboarding-port" type="number" min={1024} max={65535} value={port} required disabled={busy} onChange={(e) => { setPort(e.target.value); setPlan(null); }} /></div>
            <div className="space-y-2"><Label htmlFor="onboarding-cidr">允许来源网段（CIDR）</Label><Input id="onboarding-cidr" value={allowedCIDR} required disabled={busy} onChange={(e) => { setAllowedCIDR(e.target.value); setPlan(null); }} placeholder="例如 192.168.1.0/24" /></div>
            <div className="sm:col-span-2"><Button disabled={busy || state?.enabled || data.environment.addresses.length === 0}>检测并预览方案</Button>{data.environment.addresses.length === 0 && <p className="mt-2 text-sm text-muted-foreground">本机没有可用私有 IPv4；自动 LAN 方案暂不可用，请查看下方手动接入说明。</p>}</div>
          </form>
          {plan && <div className="space-y-3 rounded-md border border-primary/30 bg-primary/5 p-4"><div className="flex flex-wrap items-center justify-between gap-2"><h4 className="font-medium">方案预览</h4><Badge variant="outline">仅预览，尚未应用</Badge></div><p className="font-mono text-sm">{plan.origin} · 来源 {plan.input.allowed_cidr} · 到期 {plan.expires_at}</p><ol className="list-decimal space-y-1 pl-5 text-sm">{plan.steps.map((step, i) => <li key={`${i}-${step}`}>{step}</li>)}</ol>{plan.needs_host_bridge && <p className="text-sm">需要 Windows 主机桥接；为此下载固定脚本并交由管理员审阅。</p>}<Button disabled={busy} onClick={() => void applyPlan()}>确认并应用此方案</Button></div>}
          {state?.enabled && <Button variant="destructive" disabled={busy} onClick={() => void disable()}>停用成员入口…</Button>}
          {state?.enabled && state.needs_host_bridge && <Button variant="outline" disabled={busy} onClick={() => void action(() => downloadAuthorized(`${teamPath(team)}/host-script`, `artex-host-bridge-${team}.ps1`), "Windows 主机桥接脚本已下载。默认只预览；由管理员检查后使用 -Apply。")}>下载 Windows 主机桥接脚本</Button>}
        </details>}

        <section className="space-y-3 border-t pt-4">
          <h3 className="font-medium">2. 成员接入与设备核对</h3>
          {data.devices.length === 0 ? <p className="text-sm text-muted-foreground">尚无对你可见的已配对设备。成员账号只能查看自己的设备状态和下载包，不能更改团队接入设置。</p> : <div className="space-y-2">{data.devices.map((device) => <div key={device.id} className="flex flex-wrap items-center justify-between gap-3 rounded-md border p-3 text-sm"><div><p className="font-medium">{device.name} <span className="font-normal text-muted-foreground">#{device.id}</span></p><p className="mt-1 text-muted-foreground">{device.online ? "在线" : "离线"} · 本机执行配置 {device.execution_enabled ? "已启用" : "未启用"} · 分支协议 {device.branch_protocol || "未配置"} · 角色 {device.role_count}</p></div><Badge variant={device.online ? "secondary" : "outline"}>{device.online ? "在线" : "离线"}</Badge></div>)}</div>}
          {data.platforms.length === 0 ? <p className="rounded-md border p-3 text-sm text-muted-foreground">当前版本没有可下载的平台接入包。请从与协调端相同版本的已验证发行包获取 Node；向导不会生成替代包。</p> : <div className="flex flex-wrap items-end gap-3"><div className="min-w-56 space-y-2"><Label htmlFor="onboarding-platform">平台包</Label><select id="onboarding-platform" value={platform} disabled={busy} onChange={(e) => setPlatform(e.target.value)} className="min-h-10 w-full rounded-md border bg-background px-3 text-sm">{data.platforms.map((p) => <option key={p} value={p}>{platformNames[p] || p}</option>)}</select></div><Button variant="outline" disabled={busy || !platform || !state?.enabled || state.external} onClick={() => void action(() => downloadAuthorized(`${teamPath(team)}/bundle?platform=${encodeURIComponent(platform)}`, `artex-node-${platform}.zip`), "接入包已下载。包中不含配对码；请在本机运行 setup 向导并分别配置模型与工具。")}>下载接入包</Button></div>}
          {!state?.enabled && <p className="text-sm text-muted-foreground">尚未发布的受管入口不能提供有效接入包。若入口由 CLI 管理，请沿用其现有邀请流程。</p>}
          <div className="flex flex-wrap items-end gap-3"><div className="min-w-56 space-y-2"><Label htmlFor="onboarding-member">设备所属成员</Label>{admin ? <select id="onboarding-member" value={memberID ?? ""} onChange={(e) => { setMemberID(Number(e.target.value) || null); setPairingCode(""); }} className="min-h-10 w-full rounded-md border bg-background px-3 text-sm" disabled={busy || members.length === 0}><option value="">选择团队成员</option>{members.map((m) => <option key={m.id} value={m.id}>{m.login}</option>)}</select> : <p className="min-h-10 py-2 text-sm">仅为当前登录成员生成</p>}</div><Button variant="outline" disabled={busy || (admin && members.length === 0)} onClick={() => void getPairing()}>生成一次性配对码</Button></div>
          {pairingCode && <div role="status" className="space-y-2 rounded-md border p-3"><p className="text-sm">一次性配对码只显示在此处，不会写入 ZIP。请交给所选设备所有者，在本机 Node setup 向导中输入。</p><code className="block break-all text-sm">{pairingCode}</code><p className="text-xs text-muted-foreground">10 分钟有效，只能使用一次；页面刷新后不再显示。</p><Button variant="outline" size="sm" onClick={() => void action(() => navigator.clipboard.writeText(pairingCode), "配对码已复制，请只交给设备所有者。")}>复制配对码</Button></div>}
        </section>

        {admin && <section className="space-y-3 border-t pt-4">
          <div className="flex flex-wrap items-center justify-between gap-3"><div><h3 className="font-medium">AI 状态解释</h3><p className="mt-1 text-sm text-muted-foreground">只发送固定 issue 与结构化检测结果，不需要粘贴日志；建议永远不会自动执行。</p></div><Badge variant="outline">{data.ai_available ? "模型可用" : "无模型：使用固定检查说明"}</Badge></div>
          <div className="flex flex-wrap items-end gap-3"><div className="min-w-56 space-y-2"><Label htmlFor="onboarding-issue">要解释的问题</Label><select id="onboarding-issue" value={issue} disabled={busy} onChange={(e) => setIssue(e.target.value as typeof issue)} className="min-h-10 w-full rounded-md border bg-background px-3 text-sm">{issueOptions.map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select></div><Button variant="outline" disabled={busy} onClick={() => void explain()}>{data.ai_available ? "解释并给出建议" : "查看固定检查建议"}</Button></div>
          {assist && <div role="status" className="space-y-2 rounded-md border p-3 text-sm"><p>{assist.summary}</p>{assist.steps.length > 0 && <ol className="list-decimal space-y-1 pl-5">{assist.steps.map((step, i) => <li key={`${i}-${step}`}>{step}</li>)}</ol>}<p className="text-muted-foreground">建议操作：{actionNames[assist.recommended_action] ?? "刷新接入状态"}。请由管理员自行审核和执行。</p><p className="text-xs text-muted-foreground">说明来源：{assist.source === "ai" ? "模型建议，未执行" : "固定状态检查"}</p></div>}
        </section>}
      </>}
    </CardContent>
  </Card>;
}
