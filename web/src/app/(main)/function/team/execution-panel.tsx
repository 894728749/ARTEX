"use client";

import * as React from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { http } from "@/lib/api";

type Intent = {
  id: number;
  state: string;
  payload: {
    summary?: string;
    task?: string;
    contract?: { execution_role?: string; remote_assignment_pending?: boolean; remote_dispatch_pending?: boolean };
  };
};
type RuntimeProfile = { id: string; name: string; platform: string; digest: string; max_duration_ms: number };
type Device = {
  id: number;
  name: string;
  revoked: boolean;
  owner_member_id: number;
  capabilities: {
    execution_enabled?: boolean;
    roles?: string[];
    capabilities?: string[];
    role_capabilities?: Record<string,string[]>;
    runtime_profiles?: RuntimeProfile[];
  };
};
type Work = {
  intents: Intent[];
  materials: { id: number; name: string; size_bytes: number }[];
  devices: Device[];
  dispatch_queue?: DispatchQueueItem[];
  permissions: { manage: boolean; review: boolean };
  paused: boolean;
};
type Evidence = {
  id: string;
  tool: string;
  sha256: string;
  content: string;
  is_error: boolean;
  input?: unknown;
  truncated?: boolean;
};
type Assignment = {
  id: number;
  intent_id: number;
  device_id: number;
  member_id: number;
  epoch: number;
  state: string;
  lease_until: string;
  config_snapshot: { role: string };
  result?: { summary: string; outcome: string; model: string; evidence?: Evidence[]; evidence_count?: number };
  review_decision?: string;
  review_note?: string;
  review_member_id?: number;
};
type DispatchQueueItem = {
  id: number;
  intent_id: number;
  state: "queued" | "assigned" | "cancelled" | "blocked" | string;
  last_error?: string;
  waiting_reason?: string;
  device_id?: number;
  runtime_profile_id?: string;
  assignment_id?: number;
  request?: { assignment?: {device_id?:number; runtime_profile_id?:string} };
  created_at?: string;
};
type TeamHistoryItem = {
  id: number;
  kind: string;
  source_key: string;
  snapshot: Record<string, unknown>;
  created_at: string;
};
type DispatchMode = "manual" | "auto";
const stateNames: Record<string, string> = {
  assigned: "待设备接手",
  claimed: "已领取",
  running: "执行中",
  completed: "待独立复核",
  cancelled: "已取消",
  expired: "租约过期",
};
const roleNames: Record<string, string> = {
  worker: "渗透执行",
  reverse_static: "逆向静态分析",
  reverse_dynamic: "逆向动态观察",
  reverse_reviewer: "逆向复核",
};
const queueStateNames: Record<string, string> = {
  queued: "等待设备",
  assigned: "已派至设备",
  cancelled: "已取消",
  blocked: "暂不可派发",
};
const control = "min-h-10 w-full rounded-md border bg-background px-3 py-2 text-sm";
const post = <T,>(path: string, body: unknown) => http<T>(path, { method: "POST", body: JSON.stringify(body) });

function historyText(snapshot: Record<string, unknown>, key: string): string {
  const value = snapshot[key];
  return typeof value === "string" || typeof value === "number" ? String(value) : "";
}

function historyEvidenceKey(entry: unknown): string {
  if (entry && typeof entry === "object") {
    const value = entry as Record<string, unknown>;
    if (typeof value.id === "string" || typeof value.id === "number") return String(value.id);
    if (typeof value.sha256 === "string") return value.sha256;
  }
  return JSON.stringify(entry) ?? "empty-evidence";
}

function runtimeDuration(milliseconds: number): string {
  if (milliseconds <= 0) return "未提供时限";
  if (milliseconds % 60000 === 0) return `${milliseconds / 60000} 分钟`;
  if (milliseconds % 1000 === 0) {
    const seconds = milliseconds / 1000;
    const minutes = Math.floor(seconds / 60);
    const remainder = seconds % 60;
    return minutes ? `${minutes} 分 ${remainder} 秒` : `${seconds} 秒`;
  }
  return `${milliseconds} 毫秒`;
}

function assignmentLabel(assignment: Assignment): string {
  if (assignment.review_decision === "accept") return "证据已接收，待原流程验收";
  if (assignment.review_decision === "reject") return "复核退回";
  return stateNames[assignment.state] ?? assignment.state;
}

function TeamHistoryRow({ item }: { item: TeamHistoryItem }) {
  const snapshot = item.snapshot;
  const result =
    snapshot.result && typeof snapshot.result === "object" ? (snapshot.result as Record<string, unknown>) : {};
  let evidence: unknown[] = [];
  if (Array.isArray(result.evidence)) evidence = result.evidence;
  else if (Array.isArray(snapshot.evidence)) evidence = snapshot.evidence;
  const identities = [
    historyText(snapshot, "team_name"),
    historyText(snapshot, "member_login"),
    historyText(snapshot, "device_name"),
    historyText(snapshot, "review_member_login"),
  ].filter(Boolean);
  const summary =
    historyText(result, "summary") || historyText(snapshot, "permission") || historyText(snapshot, "resource_key");
  return (
    <article className="rounded-md border p-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <p className="font-medium text-sm">
            {item.kind} · {item.source_key}
          </p>
          {identities.length > 0 && <p className="text-muted-foreground text-xs">{identities.join(" / ")}</p>}
          {summary && <p className="mt-1 break-words text-sm">{summary}</p>}
        </div>
        <span className="text-muted-foreground text-xs">{new Date(item.created_at).toLocaleString()}</span>
      </div>
      <details className="mt-2">
        <summary className="cursor-pointer py-2 text-sm">
          展开来源与复核记录{evidence.length ? ` · ${evidence.length} 条证据` : ""}
        </summary>
        {evidence.length > 0 && (
          <details className="ml-3 border-l pl-3">
            <summary className="cursor-pointer py-2 text-sm">查看原始证据</summary>
            <div className="space-y-2">
              {evidence.map((entry, index) => (
                <details key={historyEvidenceKey(entry)} className="rounded-md bg-muted p-2">
                  <summary className="cursor-pointer text-sm">
                    证据 {index + 1}
                    {entry && typeof entry === "object" && "tool" in entry ? ` · ${String(entry.tool)}` : ""}
                  </summary>
                  <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all text-xs">
                    {JSON.stringify(entry, null, 2)}
                  </pre>
                </details>
              ))}
            </div>
          </details>
        )}
        <details className="ml-3 border-l pl-3">
          <summary className="cursor-pointer py-2 text-sm">查看完整来源快照</summary>
          <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded-md bg-muted p-3 text-xs">
            {JSON.stringify(snapshot, null, 2)}
          </pre>
        </details>
      </details>
    </article>
  );
}

export function ExecutionPanel({
  team,
  tasks,
  members,
  memberID,
  admin,
}: {
  team: string;
  tasks: { id: number; name: string; kind: string }[];
  members: { id: number; login: string }[];
  memberID: number;
  admin: boolean;
}) {
  const [taskID, setTaskID] = React.useState("");
  const [work, setWork] = React.useState<Work | null>(null);
  const [assignments, setAssignments] = React.useState<Assignment[]>([]);
  const [intentID, setIntentID] = React.useState("");
  const [deviceID, setDeviceID] = React.useState("");
  const [dispatchMode, setDispatchMode] = React.useState<DispatchMode>("manual");
  const [runtimeProfileID, setRuntimeProfileID] = React.useState("");
  const [authorizeRuntime, setAuthorizeRuntime] = React.useState(false);
  const [caps, setCaps] = React.useState<string[]>([]);
  const [materials, setMaterials] = React.useState<number[]>([]);
  const [context, setContext] = React.useState("");
  const [error, setError] = React.useState("");
  const [notice, setNotice] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [loading, setLoading] = React.useState(false);
  const [refresh, bump] = React.useReducer((v: number) => v + 1, 0);
  const [details, setDetails] = React.useState<Record<number, Evidence[]>>({});
  const [detailLoading, setDetailLoading] = React.useState<Record<number, boolean>>({});
  const [updated, setUpdated] = React.useState("");
  const [history, setHistory] = React.useState<TeamHistoryItem[] | null>(null);
  const [historyTaskID, setHistoryTaskID] = React.useState("");
  const [historyLoadingTask, setHistoryLoadingTask] = React.useState("");
  const historyScope = `${team}:${taskID}`;
  const activeTaskScope = React.useRef(historyScope);
  const previousTeam = React.useRef(team);
  const previousTaskID = React.useRef(taskID);
  React.useEffect(() => {
    activeTaskScope.current = historyScope;
  }, [historyScope]);
  React.useEffect(() => {
    if (previousTeam.current === team) return;
    previousTeam.current = team;
    setTaskID("");
    setIntentID("");
    setDeviceID("");
    setCaps([]);
    setMaterials([]);
    setRuntimeProfileID("");
    setAuthorizeRuntime(false);
    setContext("");
    setWork(null);
    setAssignments([]);
    setHistory(null);
    setHistoryTaskID("");
    setHistoryLoadingTask("");
  }, [team]);
  React.useEffect(() => {
    if (previousTaskID.current === taskID) return;
    previousTaskID.current = taskID;
    setIntentID("");
    setDeviceID("");
    setCaps([]);
    setMaterials([]);
    setRuntimeProfileID("");
    setAuthorizeRuntime(false);
    setContext("");
    setWork(null);
    setAssignments([]);
    setHistory(null);
    setHistoryTaskID("");
    setHistoryLoadingTask("");
  }, [taskID]);
  // The refresh counter deliberately restarts polling after a successful mutation.
  // biome-ignore lint/correctness/useExhaustiveDependencies: refresh is a polling restart signal.
  React.useEffect(() => {
    if (!taskID) return;
    let alive = true,
      timer: ReturnType<typeof setTimeout>;
    const load = async () => {
      try {
        const [w, a] = await Promise.all([
          http<Work>(`/teams/${team}/tasks/${taskID}/work`),
          http<Assignment[]>(`/teams/${team}/assignments?task_id=${taskID}`),
        ]);
        if (alive) {
          setWork(w);
          setAssignments(a);
          setUpdated(new Date().toLocaleTimeString());
          setError("");
        }
      } catch (e) {
        if (alive) setError(`同步失败，显示的是上次状态：${(e as Error).message}`);
      } finally {
        if (alive) {
          setLoading(false);
          timer = setTimeout(load, 5000);
        }
      }
    };
    setLoading(true);
    void load();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [team, taskID, refresh]);
  const selectedTask = tasks.find((t) => String(t.id) === taskID);
  const intent = work?.intents.find((i) => String(i.id) === intentID);
  const rawRole = intent?.payload.contract?.execution_role || "reverse_static";
  const role =
    selectedTask?.kind === "reverse"
      ? ((
          { static: "reverse_static", dynamic: "reverse_dynamic", reviewer: "reverse_reviewer" } as Record<
            string,
            string
          >
        )[rawRole] ?? rawRole)
      : "worker";
  const devices =
    work?.devices.filter(
      (d) => !d.revoked && d.capabilities.execution_enabled && d.capabilities.roles?.includes(role),
    ) ?? [];
  React.useEffect(() => {
    if (deviceID && !devices.some((d) => String(d.id) === deviceID)) {
      setDeviceID("");
      setCaps([]);
      setRuntimeProfileID("");
      setAuthorizeRuntime(false);
    }
    if (intentID && !work?.intents.some((i) => String(i.id) === intentID)) {
      setIntentID("");
      setAuthorizeRuntime(false);
    }
  }, [deviceID, devices, intentID, work]);
  const device = devices.find((d) => String(d.id) === deviceID);
  const deviceRoleCaps = (d: Device) => d.capabilities.role_capabilities
    ? d.capabilities.role_capabilities[role] ?? [] : d.capabilities.capabilities ?? [];
  const availableCaps = Array.from(new Set((device ? [device] : devices).flatMap(deviceRoleCaps)))
    .filter((cap) => cap !== "reverse_observe_runtime").sort();
  const runtimeProfiles = device?.capabilities.runtime_profiles ?? [];
  const runtimeProfile = runtimeProfiles.find((p) => String(p.id) === runtimeProfileID);
  // Re-advertising a changed local environment requires a fresh explicit choice.
  const runtimeBinding = runtimeProfile
    ? `${runtimeProfile.id}:${runtimeProfile.digest}:${runtimeProfile.platform}:${runtimeProfile.max_duration_ms}`
    : "";
  React.useEffect(() => { setAuthorizeRuntime(false); }, [runtimeBinding]);
  const memberName = (id: number) => members.find((m) => m.id === id)?.login ?? `成员 ${id}`;
  const deviceName = (id: number) => work?.devices.find((d) => d.id === id)?.name ?? `设备 ${id}`;
  const queueDeviceLabel = (item: DispatchQueueItem) => {
    const id = assignments.find((a) => a.id === item.assignment_id)?.device_id
      || item.request?.assignment?.device_id || item.device_id;
    return id ? ` · ${deviceName(id)}` : " · 自动匹配设备";
  };
  const canDispatch = !!work && (admin || work.permissions.manage);
  const isDynamic = role === "reverse_dynamic";
  const dispatchReady =
    !!intentID &&
    (dispatchMode === "auto" || !!device) &&
    (!isDynamic || (!!device && !!runtimeProfile && materials.length > 0 && authorizeRuntime));
  let submitLabel = dispatchMode === "auto" ? "加入自动派发队列" : "派出工作单";
  if (busy) submitLabel = "正在提交…";
  async function act(fn: () => Promise<unknown>, message: string) {
    if (busy) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await fn();
      setNotice(message);
      setHistory(null);
      setHistoryTaskID("");
      bump();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function loadHistory() {
    if (!taskID || historyLoadingTask === historyScope || historyTaskID === historyScope) return;
    const requestedTask = taskID;
    const requestedScope = historyScope;
    setHistoryLoadingTask(requestedScope);
    try {
      const items = await http<TeamHistoryItem[]>(`/teams/${team}/tasks/${requestedTask}/history`);
      if (activeTaskScope.current === requestedScope) {
        setHistory(items);
        setHistoryTaskID(requestedScope);
      }
    } catch (e) {
      if (activeTaskScope.current === requestedScope) setError(`归档来源读取失败：${(e as Error).message}`);
    } finally {
      if (activeTaskScope.current === requestedScope) setHistoryLoadingTask("");
    }
  }
  async function loadEvidence(id: number) {
    if (details[id] || detailLoading[id]) return;
    setDetailLoading((v) => ({ ...v, [id]: true }));
    try {
      const detail = await http<Assignment>(`/teams/${team}/assignments/${id}`);
      setDetails((v) => ({ ...v, [id]: detail.result?.evidence ?? [] }));
    } catch (e) {
      setError(`证据读取失败：${(e as Error).message}`);
    } finally {
      setDetailLoading((v) => ({ ...v, [id]: false }));
    }
  }
  function reviewPanel(a: Assignment) {
    if (a.state !== "completed" || a.review_decision) return null;
    if (admin)
      return <p className="text-muted-foreground text-sm">请由独立成员使用自己的账号登录复核，管理员不能代签。</p>;
    if (a.member_id === memberID)
      return <p className="text-muted-foreground text-sm">等待另一名有复核权限的成员检查；提交人不能自行复核。</p>;
    if (!work?.permissions.review) return null;
    return (
      <form
        className="space-y-2 border-t pt-3"
        onSubmit={(e) => {
          e.preventDefault();
          const data = new FormData(e.currentTarget);
          void act(
            () =>
              post(`/teams/${team}/assignments/${a.id}/review`, {
                decision: data.get("decision"),
                note: data.get("note"),
              }),
            "复核已保存，结果交回原任务。",
          );
        }}
      >
        <Label htmlFor={`review-note-${a.id}`}>复核依据与局限</Label>
        <textarea
          id={`review-note-${a.id}`}
          className={control}
          name="note"
          required
          maxLength={8000}
          rows={2}
          disabled={busy}
        />
        <div className="flex flex-wrap gap-2">
          <Label className="sr-only" htmlFor={`review-decision-${a.id}`}>
            复核决定
          </Label>
          <select id={`review-decision-${a.id}`} className={`${control} max-w-64`} name="decision" disabled={busy}>
            <option value="accept">接收为补充证据</option>
            <option value="reject">退回重做</option>
          </select>
          <Button disabled={busy}>提交独立复核</Button>
        </div>
      </form>
    );
  }
  return (
    <Card>
      <CardHeader>
        <CardTitle>工作交接与独立复核</CardTitle>
        <p className="text-muted-foreground text-sm">
          设备执行一个明确工作单，返回带来源的候选证据。独立成员复核后，原任务继续验收。
        </p>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="max-w-xl space-y-2">
          <Label htmlFor="execution-task">共享任务</Label>
          <select
            id="execution-task"
            className={control}
            value={taskID}
            disabled={busy}
            onChange={(e) => {
              setTaskID(e.target.value);
              setIntentID("");
              setDeviceID("");
              setCaps([]);
              setMaterials([]);
              setRuntimeProfileID("");
              setAuthorizeRuntime(false);
              setContext("");
            }}
          >
            <option value="">选择任务以查看交接</option>
            {tasks.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name || `任务 ${t.id}`}
              </option>
            ))}
          </select>
        </div>
        {error && (
          <p role="alert" className="rounded-md border border-destructive/40 p-3 text-destructive text-sm">
            {error}
          </p>
        )}
        {notice && (
          <p role="status" className="text-sm">
            {notice}
          </p>
        )}
        {loading && !work && (
          <p role="status" className="text-muted-foreground text-sm">
            正在读取工作单…
          </p>
        )}
        {work && (
          <>
            <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
              <span className="text-muted-foreground">每 5 秒同步 · 最近成功同步 {updated}</span>
              <Button type="button" variant="outline" size="sm" disabled={busy || loading} onClick={() => bump()}>
                立即刷新
              </Button>
            </div>
            {work.paused && (
              <p className="rounded-md border p-3 text-sm">
                任务已暂停，可先准备交接。设备会在任务恢复后接手；待接手分配最多保留 24 小时。
              </p>
            )}
            {(work.dispatch_queue?.length ?? 0) > 0 && (
              <section aria-labelledby="dispatch-queue-heading" className="space-y-3 rounded-md border p-4">
                <div>
                  <h3 id="dispatch-queue-heading" className="font-medium">
                    自动派发队列
                  </h3>
                  <p className="text-muted-foreground text-xs">
                    队列状态随工作单同步更新；等待原因会显示在对应条目下。
                  </p>
                </div>
                {work.dispatch_queue?.map((item) => (
                  <article
                    key={item.id}
                    className="flex flex-wrap items-start justify-between gap-3 rounded-md bg-muted/50 p-3"
                  >
                    <div className="min-w-0 space-y-1">
                      <p className="font-medium text-sm">
                        派发 #{item.id} · 工作单 #{item.intent_id}
                      </p>
                      <p className="text-muted-foreground text-xs">
                        {queueStateNames[item.state] ?? item.state}
                        {queueDeviceLabel(item)}
                        {(item.request?.assignment?.runtime_profile_id || item.runtime_profile_id)
                          ? ` · 运行环境 ${item.request?.assignment?.runtime_profile_id || item.runtime_profile_id}` : ""}
                        {item.created_at ? ` · ${new Date(item.created_at).toLocaleTimeString()}` : ""}
                      </p>
                      {(item.last_error || item.waiting_reason) && (
                        <p className="break-words text-amber-700 text-sm dark:text-amber-300">
                          {item.last_error || item.waiting_reason}
                        </p>
                      )}
                    </div>
                    {canDispatch && item.state === "queued" && (
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        disabled={busy}
                        onClick={() =>
                          void act(
                            () => post(`/teams/${team}/tasks/${taskID}/dispatch/${item.id}/cancel`, {}),
                            "已取消队列派发。",
                          )
                        }
                      >
                        取消排队
                      </Button>
                    )}
                  </article>
                ))}
              </section>
            )}
            {canDispatch && (
              <form
                className="space-y-4 rounded-md border p-4"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (!dispatchReady) return;
                  void act(
                    async () => {
                      await post(`/teams/${team}/tasks/${taskID}/${dispatchMode === "auto" ? "dispatch" : "assignments"}`, {
                        intent_id: Number(intentID),
                        device_id: Number(deviceID) || 0,
                        capabilities: caps,
                        artifact_ids: materials,
                        context,
                        runtime_profile_id: isDynamic ? runtimeProfileID : "",
                        authorize_runtime: isDynamic && authorizeRuntime,
                        runtime_digest: runtimeProfile?.digest || undefined,
                      });
                      setIntentID("");
                      setContext("");
                      setAuthorizeRuntime(false);
                      setRuntimeProfileID("");
                    },
                    dispatchMode === "auto" ? "工作单已加入自动派发队列。" : "工作单已派出，等待设备接手。",
                  );
                }}
              >
                <div className="space-y-2">
                  <Label htmlFor="dispatch-mode">派发方式</Label>
                  <select
                    id="dispatch-mode"
                    className={`${control} max-w-xl`}
                    value={dispatchMode}
                    disabled={busy}
                    onChange={(e) => {
                      const mode = e.target.value as DispatchMode;
                      setDispatchMode(mode);
                      setDeviceID("");
                      setCaps([]);
                      setRuntimeProfileID("");
                      setAuthorizeRuntime(false);
                    }}
                  >
                    <option value="manual">手动选择设备</option>
                    <option value="auto">自动排队</option>
                  </select>
                  <p className="text-muted-foreground text-xs">
                    自动排队会按可用角色、能力和设备状态选择接手设备；动态观察需要指定设备与运行环境。
                  </p>
                </div>
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="execution-intent">待交接工作单</Label>
                    <select
                      id="execution-intent"
                      className={control}
                      required
                      value={intentID}
                      disabled={busy}
                      onChange={(e) => {
                        setIntentID(e.target.value);
                        setDeviceID("");
                        setCaps([]);
                        setRuntimeProfileID("");
                        setAuthorizeRuntime(false);
                      }}
                    >
                      <option value="">选择已有工作单</option>
                      {work.intents
                        .filter(
                          (i) =>
                            ["open", "waiting"].includes(i.state) &&
                            !i.payload.contract?.remote_assignment_pending &&
                            !i.payload.contract?.remote_dispatch_pending,
                        )
                        .map((i) => (
                          <option key={i.id} value={i.id}>
                            #{i.id} · {i.payload.summary || i.payload.task || "工作单"}
                          </option>
                        ))}
                    </select>
                    <p className="text-muted-foreground text-xs">
                      角色：{roleNames[role] ?? role}。依赖未完成的工作单无法派出。
                    </p>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="execution-device">接手设备</Label>
                    <select
                      id="execution-device"
                      className={control}
                      required={dispatchMode === "manual" || isDynamic}
                      value={deviceID}
                      disabled={busy || !intentID}
                      onChange={(e) => {
                        setDeviceID(e.target.value);
                        setCaps([]);
                        setRuntimeProfileID("");
                        setAuthorizeRuntime(false);
                      }}
                    >
                      <option value="">
                        {dispatchMode === "auto" && !isDynamic ? "自动选择兼容设备" : "选择已开放此角色的设备"}
                      </option>
                      {devices.map((d) => (
                        <option key={d.id} value={d.id}>
                          {d.name} · {memberName(d.owner_member_id)}
                        </option>
                      ))}
                    </select>
                    <p className="text-muted-foreground text-xs">
                      {dispatchMode === "auto" && !isDynamic
                        ? "也可指定设备；留空时由队列自动匹配。"
                        : "设备所有者需要该任务的查看和执行权限。"}
                    </p>
                  </div>
                </div>
                {(device || dispatchMode === "auto") && (
                  <fieldset className="space-y-2">
                    <legend className="font-medium text-sm">本次允许使用的设备能力</legend>
                    <p className="text-muted-foreground text-xs">
                      {isDynamic
                        ? "动态观察由下方的运行授权开启；这里可选择额外的只读能力。"
                        : "未勾选任何能力时，仅能读取选定材料。模型由设备本地按角色绑定。"}
                    </p>
                    <div className="flex flex-wrap gap-4">
                      {availableCaps.map((cap) => (
                        <label key={cap} className="flex min-h-10 items-center gap-2 text-sm">
                          <input
                            type="checkbox"
                            disabled={busy}
                            checked={caps.includes(cap)}
                            onChange={(e) => {
                              setCaps(e.target.checked ? [...caps, cap] : caps.filter((c) => c !== cap));
                              setAuthorizeRuntime(false);
                            }}
                          />
                          {cap}
                        </label>
                      ))}
                    </div>
                  </fieldset>
                )}
                {work.materials.length > 0 && (
                  <fieldset className="space-y-2">
                    <legend className="font-medium text-sm">共享给此工作单的材料</legend>
                    <div className="max-h-48 overflow-auto rounded-md border p-2">
                      {work.materials.map((m) => (
                        <label key={m.id} className="flex min-h-10 items-center gap-2 text-sm">
                          <input
                            type="checkbox"
                            disabled={busy}
                            checked={materials.includes(m.id)}
                            onChange={(e) => {
                              setMaterials(
                                e.target.checked ? [...materials, m.id] : materials.filter((id) => id !== m.id),
                              );
                              setAuthorizeRuntime(false);
                            }}
                          />
                          <span className="break-all">
                            {m.name} · {(m.size_bytes / 1048576).toFixed(1)} MiB
                          </span>
                        </label>
                      ))}
                    </div>
                  </fieldset>
                )}
                {isDynamic && (
                  <div className="space-y-4 rounded-md border border-amber-500/40 p-4">
                    <div className="space-y-2">
                      <Label htmlFor="runtime-profile">本次动态运行环境</Label>
                      <select
                        id="runtime-profile"
                        className={control}
                        required
                        value={runtimeProfileID}
                        disabled={busy || !device}
                        onChange={(e) => {
                          setRuntimeProfileID(e.target.value);
                          setAuthorizeRuntime(false);
                        }}
                      >
                        <option value="">选择该设备开放的运行环境</option>
                        {runtimeProfiles.map((p) => (
                          <option key={p.id} value={p.id}>
                            {p.name} · {p.platform} · 最长 {runtimeDuration(p.max_duration_ms)}
                          </option>
                        ))}
                      </select>
                      {runtimeProfile && (
                        <p className="text-muted-foreground text-sm">
                          平台：{runtimeProfile.platform} · 本次观察上限：
                          {runtimeDuration(runtimeProfile.max_duration_ms)}
                          {runtimeProfile.digest ? ` · 环境摘要 ${runtimeProfile.digest}` : ""}
                        </p>
                      )}
                      {device && runtimeProfiles.length === 0 && (
                        <p className="text-destructive text-sm">该设备尚未公布可用的动态运行环境。</p>
                      )}
                    </div>
                    <label className="flex items-start gap-3 text-sm">
                      <input
                        type="checkbox"
                        className="mt-1"
                        disabled={busy || !runtimeProfile || materials.length === 0}
                        checked={authorizeRuntime}
                        onChange={(e) => setAuthorizeRuntime(e.target.checked)}
                      />
                      <span>
                        我明确授权本次选定的 {materials.length}{" "}
                        项材料在所选环境中按上述时限进行动态观察。授权只适用于本次派发。
                      </span>
                    </label>
                    {materials.length === 0 && (
                      <p className="text-muted-foreground text-xs">请先选定至少一项材料，动态运行授权才会启用。</p>
                    )}
                  </div>
                )}
                <div className="space-y-2">
                  <Label htmlFor="execution-context">交接说明</Label>
                  <textarea
                    id="execution-context"
                    className={control}
                    rows={3}
                    value={context}
                    maxLength={16000}
                    disabled={busy}
                    onChange={(e) => setContext(e.target.value)}
                    placeholder="已有发现、需要另一环境验证的问题、复核重点"
                  />
                </div>
                <Button disabled={busy || !dispatchReady}>{submitLabel}</Button>
              </form>
            )}
            <div className="space-y-3">
              {assignments.length === 0 && <p className="text-muted-foreground text-sm">此任务还没有设备交接记录。</p>}
              {assignments.map((a) => (
                <article key={a.id} className="space-y-3 rounded-md border p-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <p className="font-medium">
                        工作单 #{a.intent_id} · {roleNames[a.config_snapshot.role] ?? a.config_snapshot.role}
                      </p>
                      <p className="mt-1 text-muted-foreground text-sm">
                        {memberName(a.member_id)} / {deviceName(a.device_id)} · 第 {a.epoch} 次分配
                      </p>
                    </div>
                    <Badge variant="outline">{assignmentLabel(a)}</Badge>
                  </div>
                  {["assigned", "claimed", "running"].includes(a.state) && (
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="text-muted-foreground text-xs">
                        当前租约到 {new Date(a.lease_until).toLocaleTimeString()}
                      </span>
                      {canDispatch && (
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={busy}
                          onClick={() =>
                            void act(
                              () => post(`/teams/${team}/assignments/${a.id}/cancel`, {}),
                              "已撤销工作单；设备下一次许可检查将停止。",
                            )
                          }
                        >
                          取消交接
                        </Button>
                      )}
                    </div>
                  )}
                  {a.result && (
                    <>
                      <p className="whitespace-pre-wrap break-words text-sm">{a.result.summary}</p>
                      <p className="text-muted-foreground text-xs">
                        执行结果：{a.result.outcome} · 模型：{a.result.model}
                      </p>
                      <details
                        onToggle={(e) => {
                          if (e.currentTarget.open) void loadEvidence(a.id);
                        }}
                      >
                        <summary className="cursor-pointer py-2 text-sm">
                          查看 {a.result.evidence_count ?? 0} 条原始证据
                        </summary>
                        {detailLoading[a.id] && (
                          <p role="status" className="text-sm">
                            正在读取证据…
                          </p>
                        )}
                        <div className="space-y-3">
                          {details[a.id]?.map((e) => (
                            <div key={e.id} className="rounded-md bg-muted p-3">
                              <p className="text-sm">
                                {e.tool} · {e.is_error ? "工具错误" : "工具输出"}
                                {e.truncated ? " · 已截断" : ""}
                              </p>
                              {e.input != null && (
                                <pre className="my-2 max-h-32 overflow-auto whitespace-pre-wrap break-all text-xs">
                                  输入：{JSON.stringify(e.input, null, 2)}
                                </pre>
                              )}
                              <p className="break-all font-mono text-xs">SHA256 {e.sha256}</p>
                              <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all text-xs">
                                {e.content}
                              </pre>
                            </div>
                          ))}
                        </div>
                      </details>
                    </>
                  )}
                  {a.review_decision && (
                    <p className="whitespace-pre-wrap text-sm">
                      复核人：{a.review_member_id ? memberName(a.review_member_id) : "未知成员"} · {a.review_note}
                    </p>
                  )}
                  {reviewPanel(a)}
                </article>
              ))}
            </div>
            <section aria-labelledby="team-history-heading" className="rounded-md border p-4">
              <details
                key={historyScope}
                onToggle={(e) => {
                  if (e.currentTarget.open) void loadHistory();
                }}
              >
                <summary id="team-history-heading" className="cursor-pointer font-medium">
                  归档协作来源与复核历史
                </summary>
                <p className="my-2 text-muted-foreground text-xs">
                  仅在展开时读取一次；内容是只读来源快照，不会恢复成员授权、设备令牌或可执行派发。
                </p>
                {historyLoadingTask === historyScope && (
                  <p role="status" className="py-2 text-muted-foreground text-sm">
                    正在读取历史快照…
                  </p>
                )}
                {historyTaskID === historyScope && history?.length === 0 && (
                  <p className="py-2 text-muted-foreground text-sm">尚无归档协作历史。</p>
                )}
                {historyTaskID === historyScope && !!history?.length && (
                  <div className="mt-3 space-y-2">
                    {history.map((item) => (
                      <TeamHistoryRow key={item.id} item={item} />
                    ))}
                  </div>
                )}
                {historyTaskID !== historyScope && historyLoadingTask !== historyScope && (
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="mt-2"
                    onClick={(e) => {
                      e.preventDefault();
                      void loadHistory();
                    }}
                  >
                    读取归档来源
                  </Button>
                )}
              </details>
            </section>
          </>
        )}
      </CardContent>
    </Card>
  );
}
