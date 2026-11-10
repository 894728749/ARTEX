"use client";

import * as React from "react";
import { http } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";

type Member = { id: number; login: string; revoked: boolean };
type Permission = { task_id: number; member_id: number; permission: string };
const names: Record<string, string> = { read: "查看任务", execute: "执行任务", review: "复核结果", manage: "管理任务" };
const selectClass = "min-h-10 rounded-md border bg-background px-3 text-sm";

export function TeamTaskPermissions({ team, members, onSaved }: { team: string; members: Member[]; onSaved: () => void }) {
  const [rows, setRows] = React.useState<Permission[]>([]);
  const [task, setTask] = React.useState("");
  const [member, setMember] = React.useState("");
  const [selected, setSelected] = React.useState<string[]>([]);
  const [busy, setBusy] = React.useState(false);
  const [loaded, setLoaded] = React.useState(false);
  const [error, setError] = React.useState("");
  const [notice, setNotice] = React.useState("");
  const [revision, refresh] = React.useReducer((v: number) => v + 1, 0);
  React.useEffect(() => {
    let active = true;
    setLoaded(false);
    http<Permission[]>(`/teams/${team}/permissions`).then((value) => { if (active) { setRows(value); setLoaded(true); } }).catch((e) => { if (active) setError(e.message); });
    return () => { active = false; };
  }, [team, revision]);
  React.useEffect(() => { setSelected(rows.filter((p) => String(p.task_id) === task && String(p.member_id) === member).map((p) => p.permission)); }, [rows, task, member]);
  const grouped = [...new Set(rows.map((p) => `${p.task_id}:${p.member_id}`))];
  return <section className="space-y-3" aria-label="任务基础授权">
    <h3 className="font-medium">任务基础授权</h3>
    <p className="text-sm text-muted-foreground">选择成员和任务后，一次保存所选权限。各项独立；查看不会附带执行。启用共享分支后，还需在该任务的“分支权限”中授权过程、讨论、执行等能力。</p>
    <form className="space-y-3" onSubmit={async (e) => {
      e.preventDefault(); if (busy || !loaded) return; setBusy(true); setError(""); setNotice("");
      try { await http(`/teams/${team}/tasks/${task}/permissions`, { method: "PUT", body: JSON.stringify({ member_id: Number(member), permissions: selected }) }); setNotice(selected.length ? "已保存全部所选权限，未勾选的基础权限已撤销。" : "已撤销此成员的全部任务基础权限；历史保留。"); refresh(); onSaved(); }
      catch (e) { setError((e as Error).message); } finally { setBusy(false); }
    }}>
      <div className="flex flex-wrap items-end gap-3">
        <div className="space-y-2"><Label htmlFor="grant-member">成员</Label><select id="grant-member" value={member} onChange={(e) => setMember(e.target.value)} required disabled={busy || !loaded} className={selectClass}><option value="">选择成员</option>{members.filter((m) => !m.revoked).map((m) => <option key={m.id} value={m.id}>{m.login} · #{m.id}</option>)}</select></div>
        <div className="space-y-2"><Label htmlFor="grant-task">要共享的任务编号</Label><Input id="grant-task" value={task} onChange={(e) => setTask(e.target.value)} type="number" min={1} required disabled={busy || !loaded} /></div>
      </div>
      <fieldset disabled={busy || !loaded || !member || !task} className="flex flex-wrap gap-3"><legend className="mb-2 text-sm">保存后的权限（全部取消将撤销访问）</legend>{Object.entries(names).map(([key, name]) => <label key={key} className="flex min-h-11 items-center gap-2 rounded-md border px-3 text-sm"><input type="checkbox" checked={selected.includes(key)} onChange={(e) => setSelected(e.target.checked ? [...selected, key] : selected.filter((p) => p !== key))} />{name}</label>)}</fieldset>
      <Button disabled={busy || !loaded || !member || !task}>{busy ? "保存中…" : "保存任务权限"}</Button>
    </form>
    {error && <p role="alert" className="text-sm text-destructive">{error}</p>}{notice && <p role="status" className="text-sm">{notice}</p>}
    {!loaded ? <p role="status" className="text-sm">正在读取现有授权…</p> : grouped.length === 0 ? <p className="text-sm text-muted-foreground">尚未授予任务基础权限。</p> : <ul className="space-y-2">{grouped.map((key) => { const [t, m] = key.split(":"); const who = members.find((v) => String(v.id) === m); return <li key={key} className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-3 text-sm"><span>任务 #{t} · {who?.login ?? `成员 #${m}`}{who?.revoked ? "（已撤销成员）" : ""}：{rows.filter((p) => String(p.task_id) === t && String(p.member_id) === m).map((p) => names[p.permission] ?? p.permission).join("、")}</span><Button type="button" variant="outline" size="sm" disabled={busy || who?.revoked} onClick={() => { setTask(t); setMember(m); setNotice(""); }}>编辑授权</Button></li>; })}</ul>}
  </section>;
}

export function TeamLifecycle({ team, name, onDeleted }: { team: string; name: string; onDeleted: () => void }) {
  const [eligibility, setEligibility] = React.useState<{ deletable: boolean; reasons: string[] } | null>(null);
  const [confirm, setConfirm] = React.useState("");
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  React.useEffect(() => { let alive = true; http<{ deletable: boolean; reasons: string[] }>(`/teams/${team}/deletion-eligibility`).then((v) => { if (alive) setEligibility(v); }).catch((e) => { if (alive) setError(e.message); }); return () => { alive = false; }; }, [team]);
  return <Card><CardHeader><CardTitle>团队管理 · #{team}</CardTitle></CardHeader><CardContent className="space-y-3">
    <p className="text-sm">当前团队：{name}（编号 {team}）。成员登录时填写此编号，同名团队通过编号区分。</p>
    <p className="text-sm text-muted-foreground">仅可删除没有成员、设备、配对、共享任务及协作历史的空团队。有历史的团队保留用于审计，撤销成员或设备不会清除历史。</p>
    {eligibility && !eligibility.deletable && <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">{eligibility.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>}
    {eligibility?.deletable && <form className="flex flex-wrap items-end gap-3" onSubmit={async (e) => { e.preventDefault(); if (busy || confirm !== team) return; setBusy(true); setError(""); try { await http(`/teams/${team}`, { method: "DELETE" }); onDeleted(); } catch (e) { setError((e as Error).message); setBusy(false); } }}><div className="space-y-2"><Label htmlFor="delete-team-confirm">确认删除：输入团队编号 {team}</Label><Input id="delete-team-confirm" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" disabled={busy} /></div><Button variant="destructive" disabled={busy || confirm !== team}>{busy ? "删除中…" : "删除这个空团队"}</Button></form>}
    {!eligibility && !error && <p role="status" className="text-sm">正在检查删除条件…</p>}{error && <p role="alert" className="text-sm text-destructive">{error}</p>}
  </CardContent></Card>;
}
