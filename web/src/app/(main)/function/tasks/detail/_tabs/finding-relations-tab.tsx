"use client";

import * as React from "react";

import Link from "next/link";
import { useRouter } from "next/navigation";

import { Background, Controls, type Edge, MarkerType, type Node, ReactFlow } from "@xyflow/react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import type { FindingRelationEdge, FindingRelationKind, FindingRelationStatus, FindingRelations } from "@/lib/types";

const KIND_LABELS: Record<FindingRelationKind, string> = {
  prerequisite: "前置条件",
  enables: "提供能力",
  supports: "支持",
  contradicts: "矛盾",
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#ca8a04",
  low: "#2563eb",
};

function relationLabel(edge: FindingRelationEdge): string {
  return `${edge.status === "verified" ? "已验证" : "待验证"} · ${KIND_LABELS[edge.kind]}`;
}

export function FindingRelationsTab({ taskId }: { taskId: string }) {
  const router = useRouter();
  const [data, setData] = React.useState<FindingRelations>({ nodes: [], edges: [] });
  const [loading, setLoading] = React.useState(true);
  const [loadError, setLoadError] = React.useState("");
  const [source, setSource] = React.useState("");
  const [target, setTarget] = React.useState("");
  const [kind, setKind] = React.useState<FindingRelationKind>("supports");
  const [status, setStatus] = React.useState<FindingRelationStatus>("proposed");
  const [rationale, setRationale] = React.useState("");
  const [evidence, setEvidence] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [rowError, setRowError] = React.useState("");

  const load = React.useCallback(async () => {
    try {
      const result = await api.findingRelations(taskId);
      setData({ nodes: result.nodes ?? [], edges: result.edges ?? [] });
      setLoadError("");
      setSource((current) =>
        result.nodes.some((node) => node.id === current) ? current : (result.nodes[0]?.id ?? ""),
      );
      setTarget((current) =>
        result.nodes.some((node) => node.id === current) ? current : (result.nodes[1]?.id ?? ""),
      );
    } catch (error) {
      setLoadError((error as Error).message || "加载漏洞关联失败");
    } finally {
      setLoading(false);
    }
  }, [taskId]);

  React.useEffect(() => {
    void load();
    const timer = setInterval(() => void load(), 10000);
    return () => clearInterval(timer);
  }, [load]);

  const nodes = React.useMemo<Node[]>(() => {
    const count = Math.max(data.nodes.length, 1);
    return data.nodes.map((item, index) => ({
      id: item.id,
      position: { x: 80 + (index % 3) * 260, y: 50 + Math.floor(index / 3) * 160 },
      data: { label: `${item.name}\n${item.severity} · ${item.status}` },
      style: {
        width: 210,
        whiteSpace: "pre-line",
        borderColor: SEVERITY_COLORS[item.severity] ?? "#64748b",
        borderWidth: 2,
        borderRadius: 10,
        padding: 12,
        cursor: "pointer",
      },
      ariaLabel: `${item.name}, ${item.severity}, ${item.status}. 打开漏洞详情`,
      zIndex: count,
    }));
  }, [data.nodes]);

  const edges = React.useMemo<Edge[]>(
    () =>
      data.edges.map((edge) => ({
        id: edge.id,
        source: edge.source,
        target: edge.target,
        label: relationLabel(edge),
        markerEnd: { type: MarkerType.ArrowClosed },
        style:
          edge.status === "verified"
            ? { stroke: "#16a34a", strokeWidth: 2 }
            : { stroke: "#d97706", strokeWidth: 2, strokeDasharray: "6 4" },
        labelStyle: { fill: edge.status === "verified" ? "#15803d" : "#b45309", fontSize: 11 },
        labelBgStyle: { fill: "var(--background)", fillOpacity: 0.9 },
      })),
    [data.edges],
  );

  async function createRelation(event: React.FormEvent) {
    event.preventDefault();
    setRowError("");
    if (!source || !target) return setRowError("请选择关系两端的漏洞。");
    if (source === target) return setRowError("一条关系不能连接同一个漏洞。");
    if (!rationale.trim()) return setRowError("请填写关系理由。");
    setBusy(true);
    try {
      await api.addFindingRelation(taskId, {
        source,
        target,
        kind,
        rationale: rationale.trim(),
        evidence: evidence.trim(),
        status,
      });
      setRationale("");
      setEvidence("");
      await load();
      toast.success(status === "verified" ? "已添加已验证关系" : "已添加待验证关系");
    } catch (error) {
      setRowError((error as Error).message || "添加关系失败");
    } finally {
      setBusy(false);
    }
  }

  async function removeRelation(edge: FindingRelationEdge) {
    if (busy) return;
    setBusy(true);
    setRowError("");
    try {
      await api.deleteFindingRelation(taskId, edge.id);
      await load();
    } catch (error) {
      setRowError((error as Error).message || "删除关系失败");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle>漏洞关联图</CardTitle>
          <CardDescription>
            展示漏洞之间的前置、使能、支持或矛盾关系。虚线橙色边表示待验证；绿色实线表示已验证。合并关系不在此图中。
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loadError && (
            <p role="alert" className="mb-3 text-sm text-destructive">
              {loadError}
            </p>
          )}
          {loading && <p className="py-10 text-center text-sm text-muted-foreground">正在加载漏洞关联…</p>}
          {!loading && data.nodes.length === 0 && (
            <div className="rounded-md border border-dashed px-4 py-12 text-center text-sm text-muted-foreground">
              当前任务还没有可关联的漏洞。先在“发现”页登记漏洞，随后即可建立关联。
            </div>
          )}
          {!loading && data.nodes.length > 0 && (
            <>
              <section aria-label="漏洞关联图" className="h-[58vh] min-h-80 overflow-hidden rounded-md border">
                <ReactFlow
                  nodes={nodes}
                  edges={edges}
                  fitView
                  nodesConnectable={false}
                  onNodeClick={(_, node) =>
                    router.push(
                      `/function/findings/detail?id=${encodeURIComponent(node.id)}&context_task=${encodeURIComponent(taskId)}`,
                    )
                  }
                  proOptions={{ hideAttribution: true }}
                >
                  <Background />
                  <Controls />
                </ReactFlow>
              </section>
              <div className="mt-4 flex flex-col gap-3">
                <h3 className="text-sm font-medium">可访问的节点与关系列表</h3>
                <ul className="list-disc space-y-1 pl-5 text-sm">
                  {data.nodes.map((node) => (
                    <li key={node.id}>
                      <Link
                        className="text-primary underline-offset-4 hover:underline"
                        href={`/function/findings/detail?id=${encodeURIComponent(node.id)}&context_task=${encodeURIComponent(taskId)}`}
                      >
                        {node.name}
                      </Link>{" "}
                      <span className="text-muted-foreground">
                        （{node.severity} · {node.status}）
                      </span>
                    </li>
                  ))}
                </ul>
                <ul className="space-y-2 text-sm">
                  {data.edges.map((edge) => {
                    const from = data.nodes.find((node) => node.id === edge.source)?.name ?? edge.source;
                    const to = data.nodes.find((node) => node.id === edge.target)?.name ?? edge.target;
                    return (
                      <li key={edge.id} className="rounded-md border p-3">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <span
                            className={
                              edge.status === "verified"
                                ? "font-medium text-emerald-700 dark:text-emerald-400"
                                : "font-medium text-amber-700 dark:text-amber-400"
                            }
                          >
                            {from} → {to} · {relationLabel(edge)}
                          </span>
                          <Button size="sm" variant="ghost" disabled={busy} onClick={() => void removeRelation(edge)}>
                            删除
                          </Button>
                        </div>
                        <p className="mt-1">理由：{edge.rationale}</p>
                        {edge.evidence && <p className="mt-1 text-muted-foreground">证据：{edge.evidence}</p>}
                      </li>
                    );
                  })}
                  {data.edges.length === 0 && <li className="text-muted-foreground">尚无漏洞关联。</li>}
                </ul>
              </div>
            </>
          )}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>手动添加关系</CardTitle>
          <CardDescription>人工补充关系时，尚未确认的关系请保留“待验证”状态。</CardDescription>
        </CardHeader>
        <CardContent>
          {data.nodes.length < 2 ? (
            <p className="text-sm text-muted-foreground">至少需要两个漏洞才能建立关系。</p>
          ) : (
            <form className="flex flex-col gap-3" onSubmit={(event) => void createRelation(event)}>
              <div className="grid gap-3 sm:grid-cols-2">
                <label className="flex flex-col gap-1 text-sm">
                  起点漏洞
                  <select
                    className="h-9 rounded-md border bg-background px-2"
                    value={source}
                    onChange={(event) => setSource(event.target.value)}
                  >
                    {data.nodes.map((node) => (
                      <option key={node.id} value={node.id}>
                        {node.name}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="flex flex-col gap-1 text-sm">
                  终点漏洞
                  <select
                    className="h-9 rounded-md border bg-background px-2"
                    value={target}
                    onChange={(event) => setTarget(event.target.value)}
                  >
                    {data.nodes.map((node) => (
                      <option key={node.id} value={node.id}>
                        {node.name}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="flex flex-col gap-1 text-sm">
                  关系类型
                  <select
                    className="h-9 rounded-md border bg-background px-2"
                    value={kind}
                    onChange={(event) => setKind(event.target.value as FindingRelationKind)}
                  >
                    {Object.entries(KIND_LABELS).map(([value, label]) => (
                      <option key={value} value={value}>
                        {label}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="flex flex-col gap-1 text-sm">
                  验证状态
                  <select
                    className="h-9 rounded-md border bg-background px-2"
                    value={status}
                    onChange={(event) => setStatus(event.target.value as FindingRelationStatus)}
                  >
                    <option value="proposed">待验证</option>
                    <option value="verified">已验证</option>
                  </select>
                </label>
              </div>
              <Input
                aria-label="关系理由"
                placeholder="关系理由（必填）"
                value={rationale}
                onChange={(event) => setRationale(event.target.value)}
              />
              <textarea
                aria-label="关系证据"
                className="min-h-20 rounded-md border bg-background p-2 text-sm"
                placeholder="证据（可选）"
                value={evidence}
                onChange={(event) => setEvidence(event.target.value)}
              />
              {rowError && (
                <p role="alert" className="text-sm text-destructive">
                  {rowError}
                </p>
              )}
              <Button type="submit" disabled={busy}>
                {busy ? "处理中…" : "添加关系"}
              </Button>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
