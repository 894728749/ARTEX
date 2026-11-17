"use client";

import * as React from "react";

import { RefreshCwIcon, SearchCheckIcon, StethoscopeIcon } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Spinner } from "@/components/ui/spinner";
import type { NativeMode, NativeState } from "@/lib/native-api";
import { useTaskView } from "@/lib/task-view-context";
import type { ReverseArtifact } from "@/lib/types";

export function ReverseNativePanel({
  taskId,
  artifacts,
  readOnly = false,
  editable = false,
}: {
  taskId: string;
  artifacts: ReverseArtifact[];
  readOnly?: boolean;
  editable?: boolean;
}) {
  const { nativeApi } = useTaskView();
  const [state, setState] = React.useState<NativeState | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);
  const [error, setError] = React.useState("");
  const [selectedArtifact, setSelectedArtifact] = React.useState("");
  const [inspection, setInspection] = React.useState<Record<string, unknown> | null>(null);
  const [inspectBusy, setInspectBusy] = React.useState(false);
  const [doctorBusy, setDoctorBusy] = React.useState("");
  const [doctorResults, setDoctorResults] = React.useState<
    Record<string, { available: boolean; observation: Record<string, unknown> }>
  >({});

  const refresh = React.useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      setState(await nativeApi.get(taskId));
    } catch (e) {
      setError((e as Error).message || "原生分析状态加载失败");
    } finally {
      setLoading(false);
    }
  }, [taskId, nativeApi]);

  React.useEffect(() => {
    void refresh();
  }, [refresh]);
  React.useEffect(() => {
    if (!selectedArtifact && artifacts.length > 0) setSelectedArtifact(String(artifacts[0].id));
  }, [artifacts, selectedArtifact]);

  async function saveMode(mode: NativeMode) {
    if (!editable || readOnly) return;
    setSaving(true);
    setError("");
    try {
      const config = await nativeApi.setMode(taskId, mode);
      setState((old) => (old ? { ...old, config } : old));
    } catch (e) {
      setError((e as Error).message || "模式保存失败");
    } finally {
      setSaving(false);
    }
  }

  async function inspectArtifact() {
    const artifactId = Number(selectedArtifact);
    if (!Number.isSafeInteger(artifactId) || artifactId <= 0) return;
    setInspectBusy(true);
    setError("");
    try {
      setInspection(await nativeApi.inspect(taskId, artifactId));
    } catch (e) {
      setError((e as Error).message || "ELF 检查失败");
    } finally {
      setInspectBusy(false);
    }
  }

  async function checkProfile(profileId: string) {
    setDoctorBusy(profileId);
    setError("");
    try {
      const result = await nativeApi.doctor(taskId, profileId);
      setDoctorResults((previous) => ({ ...previous, [profileId]: result }));
    } catch (e) {
      setError((e as Error).message || "运行环境检查失败");
    } finally {
      setDoctorBusy("");
    }
  }

  return (
    <Card>
      <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2">
        <CardTitle className="text-base">原生材料分析</CardTitle>
        <Button size="sm" variant="outline" onClick={() => void refresh()} disabled={loading}>
          {loading ? <Spinner data-icon="inline-start" /> : <RefreshCwIcon data-icon="inline-start" />}
          刷新
        </Button>
      </CardHeader>
      <CardContent className="grid gap-4">
        <p className="text-sm text-muted-foreground">
          模式只调整分析偏好，不会授权执行。原生样本运行授权与环境选择沿用上方运行环境设置。
        </p>
        {error && (
          <Alert variant="destructive">
            <AlertTitle>原生分析面板出错</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        {loading && !state && (
          <p className="flex items-center gap-2 text-sm text-muted-foreground">
            <Spinner />
            正在读取原生分析状态…
          </p>
        )}
        {!loading && !state && <p className="text-sm text-muted-foreground">暂无原生分析状态。</p>}
        {state && (
          <>
            <section className="grid gap-2 rounded-md border p-3 sm:grid-cols-[1fr_auto] sm:items-center">
              <div>
                <p className="text-sm font-medium">分析模式</p>
                <p className="text-xs text-muted-foreground">
                  配置修订 {state.config.revision} · 修改后只影响后续分析请求
                </p>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant={state.config.mode === "pwn" ? "destructive" : "secondary"}>{state.config.mode}</Badge>
                <select
                  aria-label="原生分析模式"
                  className="h-9 rounded-md border bg-background px-2 text-sm"
                  value={state.config.mode}
                  disabled={!(editable && !readOnly && !saving)}
                  onChange={(event) => void saveMode(event.target.value as NativeMode)}
                >
                  <option value="analysis">analysis · 行为分析</option>
                  <option value="pwn">pwn · 利用研究偏好</option>
                </select>
                {saving && <Spinner />}
              </div>
            </section>

            <section className="grid gap-2">
              <h3 className="text-sm font-medium">ELF 静态检查</h3>
              {artifacts.length === 0 ? (
                <p className="rounded-md border border-dashed p-3 text-sm text-muted-foreground">
                  先在材料列表上传文件，再选择 ELF 材料检查。
                </p>
              ) : (
                <div className="flex flex-wrap items-center gap-2">
                  <select
                    aria-label="选择 ELF 材料"
                    className="h-9 min-w-48 max-w-full rounded-md border bg-background px-2 text-sm"
                    value={selectedArtifact}
                    onChange={(event) => setSelectedArtifact(event.target.value)}
                  >
                    {artifacts.map((artifact) => (
                      <option key={artifact.id} value={artifact.id}>
                        {artifact.name}
                      </option>
                    ))}
                  </select>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => void inspectArtifact()}
                    disabled={!(readOnly === false && inspectBusy === false && selectedArtifact.length > 0)}
                  >
                    {inspectBusy ? <Spinner data-icon="inline-start" /> : <SearchCheckIcon data-icon="inline-start" />}
                    检查 ELF
                  </Button>
                </div>
              )}
              {inspection && (
                <details className="rounded-md border p-3">
                  <summary className="cursor-pointer text-sm">ELF 静态检查结果</summary>
                  <pre className="mt-2 max-h-96 overflow-auto whitespace-pre-wrap break-words text-xs">
                    {JSON.stringify(inspection, null, 2)}
                  </pre>
                </details>
              )}
            </section>

            <section className="grid gap-2">
              <h3 className="text-sm font-medium">运行环境检查</h3>
              {state.cases.length === 0 ? (
                <p className="text-sm text-muted-foreground">当前没有 case 可用于定位运行环境。</p>
              ) : (
                <div className="grid gap-2 sm:grid-cols-2">
                  {[...new Set(state.cases.map((item) => item.profile_id))].map((profileId) => {
                    const result = doctorResults[profileId];
                    return (
                      <div key={profileId} className="flex flex-wrap items-center gap-2 rounded-md border p-2 text-sm">
                        <span className="min-w-0 flex-1 break-all">环境 {profileId}</span>
                        {result && (
                          <Badge variant={result.available ? "secondary" : "destructive"}>
                            {result.available ? "可用" : "不可用"}
                          </Badge>
                        )}
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => void checkProfile(profileId)}
                          disabled={!(readOnly === false && doctorBusy !== profileId)}
                        >
                          {doctorBusy === profileId ? (
                            <Spinner data-icon="inline-start" />
                          ) : (
                            <StethoscopeIcon data-icon="inline-start" />
                          )}
                          Doctor
                        </Button>
                        {result && (
                          <p className="w-full break-words text-xs text-muted-foreground">
                            {JSON.stringify(result.observation)}
                          </p>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </section>

            <section className="grid gap-2">
              <h3 className="text-sm font-medium">执行记录（{state.runs.length}）</h3>
              {state.runs.length === 0 ? (
                <p className="rounded-md border border-dashed p-3 text-sm text-muted-foreground">暂无原生运行记录。</p>
              ) : (
                <div className="grid gap-2">
                  {state.runs.map((run) => (
                    <details key={run.run_id} className="rounded-md border p-3">
                      <summary className="flex cursor-pointer flex-wrap items-center gap-2 text-sm">
                        <Badge variant={run.target_state === "failed" ? "destructive" : "secondary"}>
                          {run.target_state || "状态未知"}
                        </Badge>
                        <span className="break-all">{run.run_id}</span>
                        <span className="text-muted-foreground">
                          {run.mode} · 修订 {run.config_revision} · 材料 #{run.artifact_id}
                        </span>
                      </summary>
                      <pre className="mt-2 max-h-80 overflow-auto whitespace-pre-wrap break-words text-xs">
                        {JSON.stringify(run, null, 2)}
                      </pre>
                    </details>
                  ))}
                </div>
              )}
            </section>

            <section className="grid gap-2">
              <h3 className="text-sm font-medium">测试用例（{state.cases.length}）</h3>
              {state.cases.length === 0 ? (
                <p className="rounded-md border border-dashed p-3 text-sm text-muted-foreground">暂无测试用例。</p>
              ) : (
                <div className="grid gap-2">
                  {state.cases.map((item) => (
                    <details key={item.id} className="rounded-md border p-3">
                      <summary className="cursor-pointer text-sm font-medium">
                        {item.title || `Case ${item.id}`} · 材料 #{item.artifact_id} · SHA-256 {item.sha256}
                      </summary>
                      <pre className="mt-2 max-h-80 overflow-auto whitespace-pre-wrap break-words text-xs">
                        {JSON.stringify(item, null, 2)}
                      </pre>
                    </details>
                  ))}
                </div>
              )}
            </section>
          </>
        )}
      </CardContent>
    </Card>
  );
}
