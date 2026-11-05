"use client";

import * as React from "react";
import Link from "next/link";
import { http } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { ExecutionPanel } from "./execution-panel";

type Team = { id: number; name: string };
type Member = { id: number; login: string; revoked: boolean };
type Device = { id: number; name: string; owner_member_id: number; revoked: boolean };
type Workspace = { is_admin: boolean; member_id: number; remote_execution_available: boolean; tasks: { id: number; name: string; kind: string; status: string }[]; devices: Device[] };
const send = <T,>(path: string, body?: unknown, method = "POST") => http<T>(path, { method, ...(body ? { body: JSON.stringify(body) } : {}) });

export default function TeamPage() {
  const [teams, setTeams] = React.useState<Team[]>([]);
  const [selected, setSelected] = React.useState("");
  const [admin, setAdmin] = React.useState(false);
  const [workspace, setWorkspace] = React.useState<Workspace | null>(null);
  const [members, setMembers] = React.useState<Member[]>([]);
  const [revision, refresh] = React.useReducer((v: number) => v + 1, 0);
  const [loading, setLoading] = React.useState(true);
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");
  const [notice, setNotice] = React.useState("");
  const [pairing, setPairing] = React.useState("");

  React.useEffect(() => {
    let alive = true;
    http<{ teams: Team[]; is_admin: boolean }>("/teams").then((r) => {
      if (!alive) return;
      setTeams(r.teams); setAdmin(r.is_admin);
      setSelected((id) => r.teams.some((t) => String(t.id) === id) ? id : String(r.teams[0]?.id ?? ""));
    }).catch((e) => { if (alive) setError(e.message); }).finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [revision]);
  React.useEffect(() => {
    let alive = true;
    setWorkspace(null); setMembers([]); setPairing("");
    if (!selected) return;
    Promise.all([http<Workspace>(`/teams/${selected}/workspace`), http<Member[]>(`/teams/${selected}/members`)]).then(([w, m]) => {
      if (alive) { setWorkspace(w); setMembers(m); }
    }).catch((e) => { if (alive) setError(e.message); });
    return () => { alive = false; };
  }, [selected, revision]);

  async function act(action: () => Promise<unknown>, success: string) {
    if (busy) return;
    setBusy(true); setError(""); setNotice("");
    try { await action(); setNotice(success); refresh(); }
    catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  }
  const fields = (event: React.FormEvent<HTMLFormElement>) => { event.preventDefault(); return new FormData(event.currentTarget); };
  const activeMembers = members.filter((m) => !m.revoked);

  return <div className="space-y-6 p-4 md:p-6">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div><h1 className="text-2xl font-semibold">团队协作</h1><p className="mt-1 text-sm text-muted-foreground">管理共享任务、成员权限和已配对设备。</p></div>
      <Button variant="outline" disabled={busy || loading} onClick={() => refresh()}>刷新</Button>
    </div>
    {error && <p role="alert" className="rounded-md border border-destructive/40 p-3 text-sm text-destructive">{error}</p>}
    {notice && <p role="status" className="text-sm">{notice}</p>}
    <div className="flex flex-wrap items-center gap-3"><Label htmlFor="team-choice">当前团队</Label><select id="team-choice" value={selected} disabled={loading || busy} onChange={(e) => { setError(""); setSelected(e.target.value); }} className="min-h-10 min-w-48 rounded-md border bg-background px-3 text-sm"><option value="">{loading ? "加载中…" : "请选择团队"}</option>{teams.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</select><Link href="/team-login" className="text-sm underline">成员登录入口</Link></div>
    {admin && <Card><CardHeader><CardTitle>创建团队</CardTitle></CardHeader><CardContent><form className="flex flex-wrap items-end gap-3" onSubmit={(e) => { const f = fields(e); void act(() => send("/teams", { name: f.get("name") }), "团队已创建"); }}><div className="space-y-2"><Label htmlFor="team-name">团队名称</Label><Input id="team-name" name="name" required maxLength={200} disabled={busy} /></div><Button disabled={busy}>创建</Button></form></CardContent></Card>}
    {!loading && teams.length === 0 && <p className="text-sm text-muted-foreground">还没有可访问的团队。</p>}
    {workspace && <>
      <ExecutionPanel key={selected} team={selected} tasks={workspace.tasks} members={members} memberID={workspace.member_id} admin={workspace.is_admin} />
      <Card><CardHeader><CardTitle>共享任务</CardTitle></CardHeader><CardContent className="space-y-3">
        {!workspace.remote_execution_available && <p className="text-sm text-muted-foreground">设备远程派工尚未开放。配对设备后不会自动启动或迁移任务。</p>}
        {workspace.tasks.length === 0 ? <p className="text-sm text-muted-foreground">还没有授权给你的共享任务。</p> : workspace.tasks.map((task) => <div key={task.id} className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-3"><span>{workspace.is_admin ? <Link className="underline" href={`/function/tasks/detail/?id=${task.id}`}>{task.name || `任务 ${task.id}`}</Link> : task.name || `任务 ${task.id}`}</span><div className="flex gap-2"><Badge variant="outline">{task.kind === "reverse" ? "逆向" : "渗透"}</Badge><Badge variant="secondary">{task.status}</Badge></div></div>)}
      </CardContent></Card>
      {admin && <Card><CardHeader><CardTitle>成员与任务授权</CardTitle></CardHeader><CardContent className="space-y-5">
        <form className="flex flex-wrap items-end gap-3" onSubmit={(e) => { const f = fields(e); const form = e.currentTarget; void act(async () => { await send(`/teams/${selected}/members`, { login: f.get("login"), password: f.get("password") }); form.reset(); }, "成员已创建"); }}><div className="space-y-2"><Label htmlFor="member-login">成员账号</Label><Input id="member-login" name="login" required maxLength={160} disabled={busy} autoComplete="off" /></div><div className="space-y-2"><Label htmlFor="member-password">初始密码</Label><Input id="member-password" name="password" type="password" required minLength={8} disabled={busy} autoComplete="new-password" /></div><Button disabled={busy}>添加成员</Button></form>
        <form className="flex flex-wrap items-end gap-3" onSubmit={(e) => { const f = fields(e); void act(() => send(`/teams/${selected}/tasks/${f.get("task")}/permissions`, { member_id: Number(f.get("member")), permission: f.get("permission") }), "任务权限已授予"); }}><div className="space-y-2"><Label htmlFor="grant-member">成员</Label><select id="grant-member" name="member" required disabled={busy} className="block min-h-10 rounded-md border bg-background px-3 text-sm">{activeMembers.map((m) => <option key={m.id} value={m.id}>{m.login}</option>)}</select></div><div className="space-y-2"><Label htmlFor="grant-task">要共享的任务编号</Label><Input id="grant-task" name="task" type="number" min={1} required disabled={busy} /></div><div className="space-y-2"><Label htmlFor="grant-permission">权限</Label><select id="grant-permission" name="permission" className="block min-h-10 rounded-md border bg-background px-3 text-sm" disabled={busy}><option value="read">查看</option><option value="execute">执行</option><option value="review">复核</option><option value="manage">管理</option></select></div><Button disabled={busy || activeMembers.length === 0}>授予</Button></form>
        <div className="space-y-2">{members.map((m) => <div key={m.id} className="flex items-center justify-between gap-3 rounded-md border p-3"><span>{m.login}</span><Button size="sm" variant="outline" disabled={busy || m.revoked} onClick={() => void act(() => send(`/teams/${selected}/members/${m.id}`, undefined, "DELETE"), "成员及其设备已撤销")}>{m.revoked ? "已撤销" : "撤销成员"}</Button></div>)}</div>
      </CardContent></Card>}
      <Card><CardHeader><CardTitle>设备配对</CardTitle></CardHeader><CardContent className="space-y-4">
        <form className="flex flex-wrap items-end gap-3" onSubmit={async (e) => { const f = fields(e); if (busy) return; setBusy(true); setError(""); try { const r = await send<{ pairing_token: string }>(`/teams/${selected}/pairings`, { member_id: admin ? Number(f.get("owner")) : workspace.member_id }); setPairing(r.pairing_token); } catch (e) { setError((e as Error).message); } finally { setBusy(false); } }}>{admin && <div className="space-y-2"><Label htmlFor="device-owner">设备所属成员</Label><select id="device-owner" name="owner" required className="block min-h-10 rounded-md border bg-background px-3 text-sm" disabled={busy}>{activeMembers.map((m) => <option key={m.id} value={m.id}>{m.login}</option>)}</select></div>}<Button disabled={busy || activeMembers.length === 0}>生成一次性配对码</Button></form>
        {pairing && <div className="space-y-2 rounded-md border p-3" role="status"><p className="text-sm">配对码 10 分钟内有效，仅可使用一次。交给对应设备所有者。</p><code className="block break-all text-sm">{pairing}</code></div>}
        {workspace.devices.length === 0 ? <p className="text-sm text-muted-foreground">暂无已配对设备。</p> : workspace.devices.map((d) => <div key={d.id} className="flex flex-wrap items-center justify-between gap-3 rounded-md border p-3"><span>{d.name} <span className="text-sm text-muted-foreground">设备 {d.id}</span></span><Button variant="outline" size="sm" disabled={busy || d.revoked} onClick={() => void act(() => send(`/teams/${selected}/devices/${d.id}`, undefined, "DELETE"), "设备已撤销")}>{d.revoked ? "已撤销" : "撤销配对"}</Button></div>)}
      </CardContent></Card>
    </>}
  </div>;
}
