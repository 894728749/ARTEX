"use client";

import * as React from "react";
import Link from "next/link";
import { LoaderCircleIcon, RefreshCwIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { Task, WorkflowRequest } from "@/lib/types";

const STATUS: Record<string, { label: string; variant: "secondary" | "default" | "outline" | "destructive" }> = {
  pending: { label: "处理中", variant: "secondary" },
  completed: { label: "已完成", variant: "default" },
  cancelled: { label: "已取消", variant: "outline" },
  expired: { label: "已过期", variant: "destructive" },
};

function lines(value: string) {
  return value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
}

function taskLabel(task: Task) {
  return task.name?.trim() || task.description || `任务 ${task.id}`;
}

export function WorkflowRequestsTab({ taskId, taskKind }: { taskId: string; taskKind: "pentest" | "reverse" }) {
  const [requests, setRequests] = React.useState<WorkflowRequest[]>([]);
  const [tasks, setTasks] = React.useState<Task[]>([]);
  const [taskLoadError, setTaskLoadError] = React.useState("");
  const [loading, setLoading] = React.useState(true);
  const [refreshError, setRefreshError] = React.useState("");
  const [formError, setFormError] = React.useState("");
  const [refreshing, setRefreshing] = React.useState(false);
  const [submitting, setSubmitting] = React.useState(false);
  const [cancelling, setCancelling] = React.useState<number | null>(null);
  const [question, setQuestion] = React.useState("");
  const [targetTaskID, setTargetTaskID] = React.useState("");
  const [acceptance, setAcceptance] = React.useState("");
  const [files, setFiles] = React.useState("");
  const [budgetSeconds, setBudgetSeconds] = React.useState("600");
  const requestKeyRef = React.useRef<string | null>(null);
  const sequenceRef = React.useRef(0);
  const inFlightRef = React.useRef(false);

  const refresh = React.useCallback(async () => {
    if (inFlightRef.current) return;
    inFlightRef.current = true;
    const sequence = ++sequenceRef.current;
    setRefreshing(true);
    try {
      const rows = await api.workflowRequests(taskId);
      if (sequenceRef.current === sequence) {
        setRequests(rows);
        setRefreshError("");
      }
    } catch (error) {
      if (sequenceRef.current === sequence) setRefreshError(`读取协助请求失败：${(error as Error).message}`);
    } finally {
      if (sequenceRef.current === sequence) {
        inFlightRef.current = false;
        setRefreshing(false);
        setLoading(false);
      }
    }
  }, [taskId]);

  React.useEffect(() => {
    let alive = true;
    setLoading(true);
    setRefreshError("");
    setTaskLoadError("");
    setRequests([]);
    const loadTasks = async () => {
      try {
        const result = await api.tasks();
        if (alive) { setTasks(result.tasks); setTaskLoadError(""); }
      } catch (error) {
        if (alive) { setTasks([]); setTaskLoadError(`无法读取目标任务列表：${(error as Error).message}`); }
      }
    };
    void loadTasks();
    void refresh();
    const poll = () => {
      if (alive && document.visibilityState === "visible") void refresh();
    };
    const timer = window.setInterval(poll, 5000);
    document.addEventListener("visibilitychange", poll);
    return () => {
      alive = false;
      sequenceRef.current++;
      inFlightRef.current = false;
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", poll);
    };
  }, [refresh, taskId]);

  const candidates = tasks.filter((task) =>
    task.id !== taskId && (task.kind ?? "pentest") === (taskKind === "reverse" ? "pentest" : "reverse") &&
    !["done", "failed", "timeout"].includes(task.status),
  );
  const inputChanged = (set: (value: string) => void) => (value: string) => {
    requestKeyRef.current = null;
    setFormError("");
    set(value);
  };

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const q = question.trim();
    const selectedFiles = lines(files);
    const target = targetTaskID ? Number(targetTaskID) : 0;
    const budget = Math.floor(Number(budgetSeconds));
    if (!q) { setFormError("请填写要解决的问题。"); return; }
    if (taskKind === "reverse" && !target) { setFormError("逆向任务必须选择一个已有的授权渗透任务。"); return; }
    if (taskKind === "pentest" && !target && selectedFiles.length === 0) {
      setFormError("自动建立逆向协助任务时，至少选择一个来源任务目录中的文件。"); return;
    }
    if (selectedFiles.length > 8) { setFormError("每次最多选择 8 个文件。"); return; }
    if (selectedFiles.some((path) => path.startsWith("/") || /^[a-zA-Z]:/.test(path) || path.split(/[\\/]/).includes(".."))) {
      setFormError("文件路径必须是当前任务目录内的相对路径，不能包含绝对路径或 ..。"); return;
    }
    if (!Number.isFinite(budget) || budget < 1 || budget > 3600) { setFormError("预算需为 1 到 3600 秒。"); return; }
    if (!requestKeyRef.current) {
      try {
        if (!globalThis.crypto?.randomUUID) throw new Error("当前浏览器不支持安全请求编号生成");
        requestKeyRef.current = globalThis.crypto.randomUUID();
      } catch (error) {
        setFormError(`无法生成请求编号：${(error as Error).message}。请使用安全上下文浏览器后重试。`);
        return;
      }
    }
    setSubmitting(true);
    setFormError("");
    try {
      await api.createWorkflowRequest(taskId, {
        request_key: requestKeyRef.current,
        target_task_id: target,
        question: q,
        acceptance: lines(acceptance),
        files: selectedFiles,
        evidence_refs: [],
        budget_seconds: budget,
      });
      requestKeyRef.current = null;
      setQuestion(""); setAcceptance(""); setFiles(""); setTargetTaskID("");
      await refresh();
    } catch (error) {
      // Keep request_key unchanged so submitting the same draft retries idempotently.
      setFormError(`提交失败：${(error as Error).message}。原请求编号已保留；保持表单不变后可安全重试。`);
    } finally {
      setSubmitting(false);
    }
  }

  async function cancel(requestID: number) {
    setCancelling(requestID);
    setFormError("");
    try {
      await api.cancelWorkflowRequest(taskId, requestID);
      await refresh();
    } catch (error) {
      setFormError(`取消请求失败：${(error as Error).message}`);
    } finally {
      setCancelling(null);
    }
  }

  return (
    <div className="grid gap-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-3 space-y-0">
          <div>
            <CardTitle className="text-base">跨流程协助</CardTitle>
            <p className="text-muted-foreground mt-1 text-xs">只发送你选定的问题与材料，不共享整项任务上下文或授权。</p>
          </div>
          <Button type="button" variant="outline" size="sm" onClick={() => void refresh()} disabled={refreshing}>
            {refreshing ? <LoaderCircleIcon className="animate-spin" data-icon="inline-start" /> : <RefreshCwIcon data-icon="inline-start" />}
            刷新
          </Button>
        </CardHeader>
        <CardContent>
          <form className="grid gap-3" onSubmit={submit}>
            <div className="grid gap-1.5">
              <Label htmlFor="workflow-question">需要解决的问题</Label>
              <Textarea id="workflow-question" rows={3} value={question} onChange={(e) => inputChanged(setQuestion)(e.target.value)} placeholder="描述一个可独立回答、可验收的问题" required disabled={submitting} />
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="grid gap-1.5">
                <Label htmlFor="workflow-target">目标任务</Label>
                <select id="workflow-target" value={targetTaskID} onChange={(e) => inputChanged(setTargetTaskID)(e.target.value)} className="border-input bg-background h-9 rounded-md border px-3 text-sm" disabled={submitting}>
                  <option value="">{taskKind === "pentest" ? "自动建立逆向协助任务" : "选择已有授权渗透任务"}</option>
                  {candidates.map((task) => <option key={task.id} value={task.id}>#{task.id} · {taskLabel(task)}</option>)}
                </select>
                <p className="text-muted-foreground text-xs">{taskKind === "pentest" ? "留空会新建独立逆向任务；必须同时选至少一个文件。" : "逆向任务只能委托给已存在的渗透任务。"}</p>
                {taskLoadError && <p role="alert" className="text-destructive text-xs">{taskLoadError}</p>}
                {!taskLoadError && tasks.length > 0 && candidates.length === 0 && <p className="text-muted-foreground text-xs">当前没有可选择的在用对侧任务。</p>}
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="workflow-budget">预算（秒）</Label>
                <Input id="workflow-budget" type="number" min={1} max={3600} value={budgetSeconds} onChange={(e) => inputChanged(setBudgetSeconds)(e.target.value)} disabled={submitting} />
              </div>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="workflow-acceptance">验收条件（每行一项，可留空）</Label>
              <Textarea id="workflow-acceptance" rows={2} value={acceptance} onChange={(e) => inputChanged(setAcceptance)(e.target.value)} placeholder="例如：给出相关代码位置和可复核证据" disabled={submitting} />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="workflow-files">所选文件相对路径（每行一项，最多 8 个，可留空）</Label>
              <Textarea id="workflow-files" rows={2} value={files} onChange={(e) => inputChanged(setFiles)(e.target.value)} placeholder="例如：reverse/artifacts/sample.apk" disabled={submitting} />
              <p className="text-muted-foreground text-xs">路径相对于当前任务目录；文件会按所选内容复制给目标任务。</p>
            </div>
            {formError && <p role="alert" className="text-destructive text-sm">{formError}</p>}
            <div className="flex justify-end">
              <Button type="submit" disabled={submitting}>
                {submitting && <LoaderCircleIcon className="animate-spin" data-icon="inline-start" />}
                {submitting ? "提交中…" : "发起协助"}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      <section aria-labelledby="workflow-list-title" className="grid gap-3">
        <div className="flex items-center justify-between gap-3">
          <h2 id="workflow-list-title" className="text-base font-semibold">协助记录</h2>
          <span className="text-muted-foreground text-xs" role="status">每 5 秒在页面可见时更新</span>
        </div>
        {refreshError && <p role="alert" className="text-destructive text-sm">{refreshError}</p>}
        {loading ? <p role="status" className="text-muted-foreground py-6 text-center text-sm">正在读取协助记录…</p> : requests.length === 0 ? (
          <p className="text-muted-foreground rounded-md border border-dashed py-8 text-center text-sm">暂无跨流程协助请求</p>
        ) : requests.map((request) => {
          const outgoing = request.source_task_id === Number(taskId);
          const status = STATUS[request.status] ?? { label: request.status, variant: "outline" as const };
          const inputFiles = request.input_snapshot?.files ?? [];
          const evidence = request.input_snapshot?.evidence ?? [];
          return (
            <Card key={request.id}>
              <CardContent className="grid gap-3 pt-5">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge variant={status.variant}>{status.label}</Badge>
                  <Badge variant="outline">{outgoing ? "我方发出" : "收到请求"}</Badge>
                  <span className="text-muted-foreground text-xs">请求 #{request.id} · {request.budget_seconds} 秒</span>
                  {request.parent_request_id && <span className="text-muted-foreground text-xs">上游请求 #{request.parent_request_id}</span>}
                  <div className="ml-auto flex items-center gap-2 text-xs">
                    <Link className="text-primary hover:underline" href={`/function/tasks/detail?id=${request.source_task_id}`}>来源任务 #{request.source_task_id}</Link>
                    <span aria-hidden="true">→</span>
                    <Link className="text-primary hover:underline" href={`/function/tasks/detail?id=${request.target_task_id}`}>目标任务 #{request.target_task_id}</Link>
                  </div>
                </div>
                <div>
                  <p className="text-xs font-medium">问题</p>
                  <p className="mt-1 whitespace-pre-wrap text-sm">{request.question}</p>
                </div>
                <div>
                  <p className="text-xs font-medium">验收条件</p>
                  {request.acceptance?.length ? <ul className="text-muted-foreground mt-1 list-disc pl-5 text-sm">{request.acceptance.map((item, index) => <li key={`${index}-${item}`}>{item}</li>)}</ul> : <p className="text-muted-foreground mt-1 text-sm">未单独指定</p>}
                </div>
                <div>
                  <p className="text-xs font-medium">所选输入</p>
                  {inputFiles.length || evidence.length ? <ul className="text-muted-foreground mt-1 grid gap-1 text-sm">
                    {inputFiles.map((file, index) => <li key={`${file.path}-${index}`} className="break-all">文件：<code>{file.path}</code> · {file.size.toLocaleString()} B</li>)}
                    {evidence.map((item, index) => <li key={`${item.node_id}-${index}`}>证据节点 #{item.node_id} · 版本 {item.version}{item.kind ? ` · ${item.kind}` : ""}</li>)}
                  </ul> : <p className="text-muted-foreground mt-1 text-sm">未附加文件或证据</p>}
                </div>
                {request.result && <div className="rounded-md border bg-muted/30 p-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="text-xs font-medium">结果</p>
                    <Badge variant={request.result.status === "accepted" ? "default" : "outline"}>{request.result.status === "accepted" ? "已接受" : "未解决"}</Badge>
                  </div>
                  <p className="mt-1 whitespace-pre-wrap text-sm">{request.result.summary}</p>
                  {request.result.limitations && <p className="text-muted-foreground mt-2 whitespace-pre-wrap text-xs">局限：{request.result.limitations}</p>}
                </div>}
                {outgoing && request.status === "pending" && <div className="flex justify-end">
                  <Button type="button" variant="outline" size="sm" disabled={cancelling === request.id} onClick={() => void cancel(request.id)}>
                    {cancelling === request.id && <LoaderCircleIcon className="animate-spin" data-icon="inline-start" />}
                    {cancelling === request.id ? "正在取消…" : "取消请求"}
                  </Button>
                </div>}
              </CardContent>
            </Card>
          );
        })}
      </section>
    </div>
  );
}
