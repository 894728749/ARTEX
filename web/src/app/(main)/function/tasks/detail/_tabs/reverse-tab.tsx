"use client";

import * as React from "react";

import { DownloadIcon, FileUpIcon, RefreshCwIcon } from "lucide-react";
import { toast } from "sonner";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Spinner } from "@/components/ui/spinner";
import { api } from "@/lib/api";
import type {
  ReverseArtifact,
  ReverseConclusion,
  ReverseReadiness,
  ReverseRuntimePolicy,
  ReverseRuntimeProfile,
  ReverseRuntimeRun,
} from "@/lib/types";

const stateLabel: Record<ReverseConclusion["state"], string> = {
  proposed: "待复核",
  accepted: "已采纳",
  rejected: "已驳回",
  unresolved: "未解决",
};
const formatBytes = (n: number) =>
  n < 1024 ? `${n} B` : n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} KB` : `${(n / (1024 * 1024)).toFixed(1)} MB`;

export function ReverseTab({ taskId, paused, onStart }: { taskId: string; paused: boolean; onStart: () => void }) {
  const [artifacts, setArtifacts] = React.useState<ReverseArtifact[]>([]);
  const [conclusions, setConclusions] = React.useState<ReverseConclusion[]>([]);
  const [readiness, setReadiness] = React.useState<ReverseReadiness | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState("");
  const [uploading, setUploading] = React.useState(false);
  const [source, setSource] = React.useState("");
  const [version, setVersion] = React.useState("");
  const [file, setFile] = React.useState<File | null>(null);
  const [reporting, setReporting] = React.useState(false);
  const [runtimeProfiles, setRuntimeProfiles] = React.useState<ReverseRuntimeProfile[]>([]);
  const [runtimePolicy, setRuntimePolicy] = React.useState<ReverseRuntimePolicy>({
    enabled: false,
    profile_ids: [],
    artifact_ids: [],
    max_duration_ms: 10000,
  });
  const [runtimeRuns, setRuntimeRuns] = React.useState<ReverseRuntimeRun[]>([]);
  const [runtimeSaving, setRuntimeSaving] = React.useState(false);
  const [runtimeLoading, setRuntimeLoading] = React.useState(true);
  const [runtimeLoaded, setRuntimeLoaded] = React.useState(false);
  const [runtimeRefresh, setRuntimeRefresh] = React.useState(0);
  const refresh = React.useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [a, c, r] = await Promise.all([
        api.reverseArtifacts(taskId),
        api.reverseConclusions(taskId),
        api.reverseReadiness(),
      ]);
      setArtifacts(a);
      setConclusions(c);
      setReadiness(r);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [taskId]);
  React.useEffect(() => {
    void refresh();
  }, [refresh]);
  React.useEffect(() => {
    let alive = true;
    setRuntimeLoading(true);
    setRuntimeLoaded(false);
    void Promise.all([api.reverseRuntimeProfiles(), api.reverseRuntime(taskId)])
      .then(([profiles, state]) => {
        if (alive) {
          setRuntimeProfiles(profiles);
          setRuntimePolicy(state.policy);
          setRuntimeRuns(state.runs);
          setRuntimeLoaded(true);
        }
      })
      .catch((e: Error) => {
        if (alive) setError(e.message);
      })
      .finally(() => {
        if (alive) setRuntimeLoading(false);
      });
    const timer = window.setInterval(() => {
      void api
        .reverseRuntime(taskId)
        .then((state) => {
          if (alive) setRuntimeRuns(state.runs);
        })
        .catch(() => {});
    }, 5000);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, [taskId, runtimeRefresh]);
  React.useEffect(() => {
    if (paused) return;
    const timer = window.setInterval(() => {
      if (document.visibilityState !== "visible") return;
      void Promise.all([api.reverseArtifacts(taskId), api.reverseConclusions(taskId)])
        .then(([a, c]) => {
          setArtifacts(a);
          setConclusions(c);
        })
        .catch((e: Error) => setError(e.message));
    }, 10000);
    return () => window.clearInterval(timer);
  }, [taskId, paused]);

  async function upload() {
    if (!file) {
      toast.error("请选择样本或符号文件");
      return;
    }
    if (file.size > 256 * 1024 * 1024) {
      toast.error("单个文件不能超过 256 MiB");
      return;
    }
    setUploading(true);
    try {
      await api.uploadReverseArtifact(taskId, file, source.trim(), version.trim());
      toast.success("材料已上传");
      setFile(null);
      setSource("");
      setVersion("");
      await refresh();
    } catch (e) {
      toast.error(`上传失败：${(e as Error).message}`);
    } finally {
      setUploading(false);
    }
  }

  async function exportReport() {
    setReporting(true);
    try {
      await api.downloadReverseReport(taskId);
    } catch (e) {
      toast.error(`报告导出失败：${(e as Error).message}`);
    } finally {
      setReporting(false);
    }
  }

  return (
    <div className="mx-auto grid w-full max-w-6xl gap-4">
      {paused && (
        <Alert>
          <AlertTitle>逆向任务已暂停</AlertTitle>
          <AlertDescription className="flex flex-wrap items-center justify-between gap-3">
            <span>可上传或补充样本与符号材料，确认引擎就绪后继续分析。</span>
            <Button
              size="sm"
              onClick={onStart}
              disabled={artifacts.length === 0 || readiness?.available !== true || loading}
            >
              <RefreshCwIcon data-icon="inline-start" />
              启动分析
            </Button>
          </AlertDescription>
        </Alert>
      )}
      {error && (
        <Alert variant="destructive">
          <AlertTitle>档案加载失败</AlertTitle>
          <AlertDescription className="flex flex-wrap items-center justify-between gap-3">
            <span>{error}</span>
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                void refresh();
                setRuntimeRefresh((n) => n + 1);
              }}
            >
              重试
            </Button>
          </AlertDescription>
        </Alert>
      )}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">运行时观察</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-3 text-sm">
          <p className="text-muted-foreground">
            静态分析默认不会运行样本。启用后，Agent 可在所选实验环境运行所选材料，并保存调用、输出与清理记录。
          </p>
          <label className="flex min-h-10 items-center gap-2">
            <input
              type="checkbox"
              checked={runtimePolicy.enabled}
              disabled={!paused || runtimeSaving || runtimeLoading || !runtimeLoaded}
              onChange={(e) => setRuntimePolicy((p) => ({ ...p, enabled: e.target.checked }))}
            />
            允许运行时观察
          </label>
          {runtimeLoading && <p className="text-muted-foreground">正在检查调试环境…</p>}
          {!runtimeLoading && runtimeLoaded && runtimeProfiles.length === 0 && (
            <p className="text-muted-foreground">
              尚未配置调试环境。请先安装运行器并配置 Linux、Windows 或 Android 实验环境。
            </p>
          )}
          <div className="grid gap-2 sm:grid-cols-2">
            <fieldset
              disabled={!paused || runtimeSaving || runtimeLoading || !runtimeLoaded}
              className="grid gap-1 rounded-md border p-3"
            >
              <legend className="px-1">实验环境</legend>
              {runtimeProfiles.map((profile) => (
                <label key={profile.id} className="flex min-h-10 items-center gap-2">
                  <input
                    type="checkbox"
                    checked={runtimePolicy.profile_ids.includes(profile.id)}
                    disabled={!profile.available}
                    onChange={(e) =>
                      setRuntimePolicy((p) => ({
                        ...p,
                        profile_ids: e.target.checked
                          ? [...p.profile_ids, profile.id]
                          : p.profile_ids.filter((id) => id !== profile.id),
                      }))
                    }
                  />
                  <span>
                    {profile.name || profile.id} · {profile.platform} ·{" "}
                    {profile.available ? "运行器就绪" : "运行器不可用"}
                  </span>
                </label>
              ))}
            </fieldset>
            <fieldset
              disabled={!paused || runtimeSaving || runtimeLoading || !runtimeLoaded}
              className="grid gap-1 rounded-md border p-3"
            >
              <legend className="px-1">可运行材料</legend>
              {artifacts.map((artifact) => (
                <label key={artifact.id} className="flex min-h-10 items-center gap-2">
                  <input
                    type="checkbox"
                    checked={runtimePolicy.artifact_ids.includes(artifact.id)}
                    onChange={(e) =>
                      setRuntimePolicy((p) => ({
                        ...p,
                        artifact_ids: e.target.checked
                          ? [...p.artifact_ids, artifact.id]
                          : p.artifact_ids.filter((id) => id !== artifact.id),
                      }))
                    }
                  />
                  <span className="break-all">{artifact.name}</span>
                </label>
              ))}
            </fieldset>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <Label htmlFor="reverse-runtime-duration">每次观察上限（秒）</Label>
            <Input
              id="reverse-runtime-duration"
              type="number"
              min={1}
              max={60}
              className="w-24"
              value={runtimePolicy.max_duration_ms / 1000}
              disabled={!paused || runtimeSaving || runtimeLoading || !runtimeLoaded}
              onChange={(e) =>
                setRuntimePolicy((p) => ({
                  ...p,
                  max_duration_ms: Math.max(100, Math.min(60000, Number(e.target.value) * 1000)),
                }))
              }
            />
            <Button
              size="sm"
              disabled={!paused || runtimeSaving || runtimeLoading || !runtimeLoaded}
              onClick={async () => {
                setRuntimeSaving(true);
                try {
                  setRuntimePolicy(await api.setReverseRuntime(taskId, runtimePolicy));
                  toast.success("运行时设置已保存");
                } catch (e) {
                  toast.error((e as Error).message);
                } finally {
                  setRuntimeSaving(false);
                }
              }}
            >
              {runtimeSaving ? "保存中…" : "保存运行时设置"}
            </Button>
          </div>
          {!paused && <p className="text-muted-foreground">暂停任务后可调整材料与环境授权。</p>}
          {runtimeRuns.map((run) => (
            <div key={run.id} className="flex flex-wrap items-center gap-2 rounded-md border p-2">
              <Badge variant={run.status === "failed" ? "destructive" : "secondary"}>
                {{ running: "观察中", completed: "已完成", failed: "失败", cancelled: "已取消" }[run.status]}
              </Badge>
              <span>
                {runtimeProfiles.find((p) => p.id === run.profile_id)?.name || run.profile_id} ·{" "}
                {artifacts.find((a) => a.id === run.artifact_id)?.name || "材料"}
              </span>
              {run.last_error && (
                <span role="status" className="text-destructive">
                  {run.last_error}
                </span>
              )}
              {run.result_path && (
                <Button
                  size="sm"
                  variant="link"
                  onClick={() =>
                    void api
                      .workspaceDownload(run.result_path!)
                      .catch((e: Error) => toast.error(`证据下载失败：${e.message}`))
                  }
                >
                  下载运行时证据
                </Button>
              )}
            </div>
          ))}
        </CardContent>
      </Card>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">分析引擎</CardTitle>
          </CardHeader>
          <CardContent>
            {loading && !readiness ? (
              <p className="text-sm text-muted-foreground">正在检查引擎…</p>
            ) : readiness ? (
              <div className="grid gap-2 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge variant={readiness.available ? "default" : "destructive"}>
                    {readiness.available ? "可用" : "不可用"}
                  </Badge>
                  <span>
                    {readiness.command || "未配置命令"} {readiness.version}
                  </span>
                </div>
                <p>
                  已发现工具：{readiness.tool_count} · 支持格式：{readiness.formats.join("、") || "未报告"}
                </p>
                {readiness.engines?.map((engine) => (
                  <div key={engine.id} className="flex flex-wrap items-center gap-2">
                    <Badge variant={engine.available ? "secondary" : "outline"}>
                      {engine.available ? "就绪" : "未就绪"}
                    </Badge>
                    <span>{engine.name}</span>
                    {!engine.available && engine.reason && (
                      <span className="break-words text-xs text-muted-foreground">{engine.reason}</span>
                    )}
                  </div>
                ))}
                {readiness.error && <p className="text-destructive">{readiness.error}</p>}
                {readiness.limitations.length > 0 && (
                  <ul className="list-disc pl-5 text-muted-foreground">
                    {readiness.limitations.map((x, i) => (
                      <li key={i}>{x}</li>
                    ))}
                  </ul>
                )}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">暂无引擎状态</p>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">上传分析材料</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="reverse-file">样本 / 符号文件（单个最大 256 MiB）</Label>
              <Input id="reverse-file" type="file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="grid gap-1.5">
                <Label htmlFor="reverse-source">来源</Label>
                <Input
                  id="reverse-source"
                  value={source}
                  onChange={(e) => setSource(e.target.value)}
                  placeholder="例如：用户提供"
                />
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="reverse-version">版本 / 构建号</Label>
                <Input
                  id="reverse-version"
                  value={version}
                  onChange={(e) => setVersion(e.target.value)}
                  placeholder="可选"
                />
              </div>
            </div>
            <Button onClick={() => void upload()} disabled={!file || uploading} className="justify-self-start">
              {uploading ? <Spinner data-icon="inline-start" /> : <FileUpIcon data-icon="inline-start" />}
              {uploading ? "上传中" : "上传材料"}
            </Button>
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2">
          <CardTitle className="text-base">材料与结论</CardTitle>
          <Button size="sm" variant="outline" onClick={() => void exportReport()} disabled={reporting}>
            {reporting ? <Spinner data-icon="inline-start" /> : <DownloadIcon data-icon="inline-start" />}
            {reporting ? "生成中" : "导出 Markdown 报告"}
          </Button>
        </CardHeader>
        <CardContent className="grid gap-6">
          <section aria-labelledby="reverse-materials-heading">
            <h3 id="reverse-materials-heading" className="mb-2 text-sm font-medium">
              材料（{artifacts.length}）
            </h3>
            {loading && artifacts.length === 0 ? (
              <p className="text-sm text-muted-foreground">加载中…</p>
            ) : artifacts.length === 0 ? (
              <p className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">
                尚无材料。上传文件后可开始分析。
              </p>
            ) : (
              <ul className="divide-y">
                {artifacts.map((a) => (
                  <li key={a.id} className="flex flex-wrap items-center justify-between gap-2 py-3">
                    <div className="min-w-0">
                      <p className="break-all text-sm font-medium">{a.name}</p>
                      <p className="text-xs text-muted-foreground">
                        {a.format} · {formatBytes(a.size_bytes)} · {a.source || "来源未注明"}{" "}
                        {a.version && `· ${a.version}`} · SHA-256 {a.sha256}
                      </p>
                    </div>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() =>
                        api
                          .downloadReverseArtifact(taskId, a.id)
                          .catch((e) => toast.error(`下载失败：${(e as Error).message}`))
                      }
                    >
                      <DownloadIcon data-icon="inline-start" />
                      下载
                    </Button>
                  </li>
                ))}
              </ul>
            )}
          </section>
          <section aria-labelledby="reverse-conclusions-heading">
            <h3 id="reverse-conclusions-heading" className="mb-2 text-sm font-medium">
              分析结论（{conclusions.length}）
            </h3>
            {loading && conclusions.length === 0 ? (
              <p className="text-sm text-muted-foreground">加载中…</p>
            ) : conclusions.length === 0 ? (
              <p className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">
                暂无分析结论；结论生成后会在此显示证据引用与复核状态。
              </p>
            ) : (
              <div className="grid gap-3">
                {conclusions.map((c) => (
                  <article key={c.id} className="rounded-lg border p-4">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <h4 className="font-medium">{c.question}</h4>
                      <Badge variant={c.state === "accepted" ? "default" : "secondary"}>{stateLabel[c.state]}</Badge>
                    </div>
                    <p className="mt-2 whitespace-pre-wrap text-sm">{c.answer}</p>
                    {c.evidence.length > 0 && (
                      <div className="mt-3 grid gap-1 text-xs text-muted-foreground">
                        {c.evidence.map((ev, i) => (
                          <div key={`${ev.artifact_id}-${ev.locator}-${i}`} className="min-w-0 break-words">
                            证据 #{ev.artifact_id} · {ev.locator}: {ev.observation}
                            {ev.result_path && (
                              <Button
                                size="sm"
                                variant="link"
                                className="ml-1 h-auto px-1 py-0 text-xs"
                                onClick={() =>
                                  void api
                                    .workspaceDownload(ev.result_path!)
                                    .catch((e: Error) => toast.error(`证据下载失败：${e.message}`))
                                }
                              >
                                下载原始证据
                              </Button>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                    {c.limitations && <p className="mt-2 text-xs text-muted-foreground">限制：{c.limitations}</p>}
                    {c.review && <p className="mt-2 text-xs">复核：{c.review}</p>}
                  </article>
                ))}
              </div>
            )}
          </section>
        </CardContent>
      </Card>
    </div>
  );
}
