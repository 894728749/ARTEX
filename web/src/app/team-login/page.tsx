"use client";

import * as React from "react";
import Link from "next/link";
import { auth } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export default function TeamLoginPage() {
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");
  const [teamOnly, setTeamOnly] = React.useState(false);
  React.useEffect(() => { let active = true; fetch("/api/health").then((response) => { if (active) setTeamOnly(response.headers.get("X-ARTEX-Entry") === "team"); }).catch(() => {}); return () => { active = false; }; }, []);
  return <main className="flex min-h-screen items-center justify-center p-4"><Card className="w-full max-w-md"><CardHeader><CardTitle>团队成员登录</CardTitle></CardHeader><CardContent><form className="space-y-4" onSubmit={async (event) => { event.preventDefault(); if (busy) return; const form = new FormData(event.currentTarget); setBusy(true); setError(""); try { const response = await fetch("/api/auth/team-login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ team_id: Number(form.get("team")), login: form.get("login"), password: form.get("password") }) }); const result = await response.json(); if (!response.ok) throw new Error(result.error || "登录失败"); auth.setToken(result.token); window.location.href = "/function/team/"; } catch (e) { setError((e as Error).message); setBusy(false); } }}>
    <div className="space-y-2"><Label htmlFor="login-team">团队编号</Label><Input id="login-team" name="team" type="number" min={1} required disabled={busy} /></div>
    <div className="space-y-2"><Label htmlFor="login-name">成员账号</Label><Input id="login-name" name="login" autoComplete="username" required disabled={busy} /></div>
    <div className="space-y-2"><Label htmlFor="login-password">密码</Label><Input id="login-password" name="password" type="password" autoComplete="current-password" required disabled={busy} /></div>
    {error && <p role="alert" className="text-sm text-destructive">{error}</p>}<Button className="w-full" disabled={busy}>{busy ? "登录中…" : "登录团队"}</Button>{teamOnly ? <p className="text-sm text-muted-foreground">此地址仅用于团队成员登录。管理员请使用主机原管理入口。</p> : <Link className="block text-sm underline" href="/login">管理员登录</Link>}
  </form></CardContent></Card></main>;
}
