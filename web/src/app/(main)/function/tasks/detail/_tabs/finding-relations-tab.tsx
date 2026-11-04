"use client";

import * as React from "react";

import { GitBranch, Loader2, Plus } from "lucide-react";
import { toast } from "sonner";

import { FindingRelationGraph, RELATION_LABELS } from "@/components/finding-relation-graph";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type {
  FindingRelationEdge,
  FindingRelationKind,
  FindingRelationStatus,
  FindingRelations,
  FindingReviewStatus,
} from "@/lib/types";

export function FindingRelationsTab({ taskId }: { taskId: string }) {
  const [data, setData] = React.useState<FindingRelations>({ nodes: [], edges: [] });
  const [loading, setLoading] = React.useState(true);
  const [loadError, setLoadError] = React.useState("");
  const [review, setReview] = React.useState<FindingReviewStatus>();
  const [reviewBusy, setReviewBusy] = React.useState(false);
  const [reviewError, setReviewError] = React.useState("");
  const [source, setSource] = React.useState("");
  const [target, setTarget] = React.useState("");
  const [kind, setKind] = React.useState<FindingRelationKind>("prerequisite");
  const [status, setStatus] = React.useState<FindingRelationStatus>("proposed");
  const [rationale, setRationale] = React.useState("");
  const [evidence, setEvidence] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [rowError, setRowError] = React.useState("");
  const formDetails = React.useRef<HTMLDetailsElement>(null);
  const signature = React.useRef("");
  const activeTask = React.useRef(taskId);
  activeTask.current = taskId;

  const load = React.useCallback(async () => {
    try {
      const result = await api.findingRelations(taskId);
      if (activeTask.current !== taskId) return;
      const normalized = { nodes: result.nodes ?? [], edges: result.edges ?? [] };
      const nextSignature = JSON.stringify(normalized);
      if (signature.current !== nextSignature) {
        signature.current = nextSignature;
        setData(normalized);
      }
      setLoadError("");
      setSource((current) => (result.nodes.some((n) => n.id === current) ? current : (result.nodes[0]?.id ?? "")));
      setTarget((current) => (result.nodes.some((n) => n.id === current) ? current : (result.nodes[1]?.id ?? "")));
    } catch (error) {
      if (activeTask.current === taskId) setLoadError((error as Error).message || "加载漏洞关联失败");
    } finally {
      if (activeTask.current === taskId) setLoading(false);
    }
  }, [taskId]);

  const loadReview = React.useCallback(async () => {
    try {
      const result = await api.findingReviewStatus(taskId);
      if (activeTask.current === taskId) {
        setReview(result);
        setReviewError("");
      }
    } catch (error) {
      if (activeTask.current === taskId) setReviewError((error as Error).message || "无法读取归类检查状态");
    }
  }, [taskId]);

  React.useEffect(() => {
    signature.current = "";
    setData({ nodes: [], edges: [] });
    setLoading(true);
    setReview(undefined);
    setSource("");
    setTarget("");
    setRationale("");
    setEvidence("");
    setRowError("");
    void load();
    void loadReview();
    const timer = setInterval(() => {
      void load();
      void loadReview();
    }, 10000);
    return () => clearInterval(timer);
  }, [load, loadReview]);

  function openForm(nodeId?: string) {
    if (nodeId) {
      setSource(nodeId);
      if (target === nodeId) setTarget(data.nodes.find((n) => n.id !== nodeId)?.id ?? "");
    }
    if (formDetails.current) {
      formDetails.current.open = true;
      formDetails.current.scrollIntoView({ behavior: "instant", block: "start" });
      formDetails.current.querySelector<HTMLSelectElement>("select")?.focus({ preventScroll: true });
    }
  }
  async function runReview() {
    setReviewBusy(true);
    setReviewError("");
    try {
      const result = await api.runFindingReview(taskId);
      if (!result.accepted) {
        setReviewError("没有可检查的漏洞，或已有检查正在运行。");
        return;
      }
      setReview((current) => (current ? { ...current, running: true } : current));
      toast.success("已提交漏洞归类与关联检查");
      await loadReview();
    } catch (error) {
      setReviewError((error as Error).message || "提交检查失败");
    } finally {
      setReviewBusy(false);
    }
  }
  async function createRelation(event: React.FormEvent) {
    event.preventDefault();
    setRowError("");
    if (!source || !target) return setRowError("请选择关系两端的漏洞。");
    if (source === target) return setRowError("一条关系不能连接同一个漏洞。");
    if (!rationale.trim()) return setRowError("请填写关系理由。");
    if (!evidence.trim()) return setRowError("请填写关系证据；尚未验证时说明需要验证什么。");
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
      toast.success("已删除关系，漏洞记录保留");
    } catch (error) {
      setRowError((error as Error).message || "删除关系失败");
    } finally {
      setBusy(false);
    }
  }
  const selectClass = "h-10 min-w-0 max-w-full rounded-lg border bg-background px-3";
  return (
    <div className="flex min-w-0 flex-col gap-4">
      <div>
        <h2 className="text-xl font-semibold tracking-tight">漏洞关联</h2>
        <p className="mt-1 text-sm leading-6 text-muted-foreground">
          从前置漏洞到进一步影响，沿关系查看利用条件、理由与证据。
        </p>
      </div>
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border bg-card p-4">
        <div className="min-w-0 flex-1">
          <h3 className="flex items-center gap-2 text-sm font-medium">
            <GitBranch className="size-4" aria-hidden="true" />
            归类与关联检查
          </h3>
          <p className="mt-1 text-xs leading-5 text-muted-foreground">
            {review
              ? review.running
                ? "检查正在运行，结果会自动刷新。"
                : `${review.enabled ? `自动检查已开启，每新增 ${review.batch_size} 条触发。` : "自动检查已关闭。"} 当前新增待检查 ${review.pending_count} 条。`
              : "正在读取检查状态…"}{" "}
            历史漏洞可手动检查；检查可能合并同根因漏洞并重写报告，原始证据保留。
          </p>
          {!loading && data.nodes.length > 0 && data.edges.length === 0 && (
            <p className="mt-1 text-xs leading-5 text-muted-foreground">
              当前尚无关系记录。待检查为 0 不表示已有漏洞已完成关联分析；检查也可能得出没有关联的结论。
            </p>
          )}
          {(reviewError || review?.last_error) && (
            <p role="alert" className="mt-2 break-words text-sm text-destructive">
              {reviewError || review?.last_error}
            </p>
          )}
        </div>
        <Button
          variant="outline"
          className="min-h-10"
          disabled={reviewBusy || !!review?.running || data.nodes.length === 0}
          onClick={() => void runReview()}
        >
          {(reviewBusy || review?.running) && (
            <Loader2 className="animate-spin motion-reduce:animate-none" aria-hidden="true" />
          )}
          {reviewBusy || review?.running ? "检查中…" : "检查归类与关联"}
        </Button>
      </div>
      {loadError && (
        <p role="alert" className="text-sm text-destructive">
          {loadError}
        </p>
      )}
      {rowError && (
        <p role="alert" className="text-sm text-destructive">
          {rowError}
        </p>
      )}
      {loading ? (
        <div className="flex min-h-80 items-center justify-center gap-2 rounded-xl border text-sm text-muted-foreground">
          <Loader2 className="size-4 animate-spin motion-reduce:animate-none" aria-hidden="true" />
          正在加载漏洞关联…
        </div>
      ) : data.nodes.length === 0 ? (
        <div className="rounded-xl border border-dashed px-4 py-16 text-center text-sm text-muted-foreground">
          当前任务还没有可关联的漏洞。先在“发现”页登记漏洞，再建立关联。
        </div>
      ) : (
        <FindingRelationGraph
          key={taskId}
          taskId={taskId}
          data={data}
          busy={busy}
          onRemove={(edge) => void removeRelation(edge)}
          onAdd={openForm}
        />
      )}
      <details ref={formDetails} className="scroll-mt-6 rounded-xl border bg-card">
        <summary className="cursor-pointer rounded-xl px-5 py-4 text-sm font-medium focus-visible:outline-2 focus-visible:outline-ring">
          <Plus className="mr-2 inline size-4" aria-hidden="true" />
          手动添加关系
        </summary>
        <div className="border-t p-5">
          <p className="mb-4 text-sm leading-6 text-muted-foreground">
            方向为“起点 → 终点”。例如：泄露的凭据 → 使用凭据访问管理功能。未确认的关系保留为待验证，并说明验证条件。
          </p>
          {data.nodes.length < 2 ? (
            <p className="text-sm text-muted-foreground">至少需要两个漏洞才能建立关系。</p>
          ) : (
            <form className="flex flex-col gap-4" onSubmit={(event) => void createRelation(event)}>
              <div className="grid gap-4 sm:grid-cols-2">
                <label className="flex min-w-0 flex-col gap-2 text-sm">
                  起点漏洞
                  <select className={selectClass} value={source} onChange={(e) => setSource(e.target.value)}>
                    {data.nodes.map((n) => (
                      <option key={n.id} value={n.id}>
                        {n.name}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="flex min-w-0 flex-col gap-2 text-sm">
                  终点漏洞
                  <select className={selectClass} value={target} onChange={(e) => setTarget(e.target.value)}>
                    {data.nodes.map((n) => (
                      <option key={n.id} value={n.id}>
                        {n.name}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="flex flex-col gap-2 text-sm">
                  关系类型
                  <select
                    className={selectClass}
                    value={kind}
                    onChange={(e) => setKind(e.target.value as FindingRelationKind)}
                  >
                    {Object.entries(RELATION_LABELS).map(([value, label]) => (
                      <option key={value} value={value}>
                        {label}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="flex flex-col gap-2 text-sm">
                  验证状态
                  <select
                    className={selectClass}
                    value={status}
                    onChange={(e) => setStatus(e.target.value as FindingRelationStatus)}
                  >
                    <option value="proposed">待验证</option>
                    <option value="verified">已验证</option>
                  </select>
                </label>
              </div>
              <label className="flex flex-col gap-2 text-sm">
                关系理由（必填）
                <textarea
                  required
                  className="min-h-20 rounded-lg border bg-background p-3"
                  placeholder="为什么起点漏洞是终点的前提，或提供了什么能力？"
                  value={rationale}
                  onChange={(e) => setRationale(e.target.value)}
                />
              </label>
              <label className="flex flex-col gap-2 text-sm">
                证据 / 待验证内容（必填）
                <textarea
                  required
                  className="min-h-24 rounded-lg border bg-background p-3"
                  placeholder="填写能支撑此关系的证据；待验证关系应说明仍需验证什么。"
                  value={evidence}
                  onChange={(e) => setEvidence(e.target.value)}
                />
              </label>
              {rowError && (
                <p role="alert" className="text-sm text-destructive">
                  {rowError}
                </p>
              )}
              <Button type="submit" className="min-h-10 self-start" disabled={busy}>
                {busy ? "处理中…" : "添加关系"}
              </Button>
            </form>
          )}
        </div>
      </details>
    </div>
  );
}
