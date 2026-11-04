"use client";

import * as React from "react";

import Link from "next/link";

import { ArrowDownIcon, ArrowUpIcon, ArrowUpRightIcon, ChevronRightIcon } from "lucide-react";
import { toast } from "sonner";

import { StatusBadge } from "@/components/status-badge";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger } from "@/components/ui/select";
import { api } from "@/lib/api";
import { useStoredSortPreference } from "@/lib/sort-preference";
import { statusMeta } from "@/lib/status";
import type { Finding, FindingReviewStatus, FindingStatus } from "@/lib/types";
import { cn } from "@/lib/utils";

type FindingSortField = "time";

const FINDING_SORT_FIELDS: readonly FindingSortField[] = ["time"];
const FINDING_SORT_PREFERENCE_KEY = "artex_task_findings_sort";

function findingLabel(finding: Finding): string {
  if (finding.name?.trim()) return finding.name;
  if (finding.vulnclass?.trim()) return finding.vulnclass;
  return "未分类";
}

const FINDING_STATUSES: FindingStatus[] = [
  "pending",
  "in_progress",
  "confirmed",
  "resolved",
  "fixed",
  "false_positive",
  "ignored",
  "duplicate",
  "risk_accepted",
];

function Row({
  f,
  contextTaskId,
  onStatus,
}: {
  f: Finding;
  contextTaskId: string;
  onStatus: (f: Finding, next: FindingStatus) => void;
}) {
  const [open, setOpen] = React.useState(false);
  return (
    <div className="border-b last:border-b-0">
      <div className="flex w-full items-center gap-3 px-4 py-3 text-sm hover:bg-accent/40">
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          className="flex min-w-0 flex-1 items-center gap-3 text-left"
        >
          <ChevronRightIcon
            className={cn("size-4 shrink-0 text-muted-foreground transition-transform", open && "rotate-90")}
          />
          <StatusBadge domain="severity" value={f.severity} dot />
          <div className="flex min-w-0 flex-1 flex-col gap-1">
            <div className="flex min-w-0 items-center gap-2">
              <span className="truncate font-medium">{findingLabel(f)}</span>
              {f.inherited && f.source_task_id && (
                <Badge variant="outline" className="shrink-0">
                  来源 #{f.source_task_id} · 只读
                </Badge>
              )}
            </div>
            <span className="truncate text-xs text-muted-foreground">{f.summary}</span>
          </div>
        </button>
        <Badge variant="outline">流量证据 {f.traffic_count ?? 0} 条</Badge>
        {f.assets && f.assets.length > 0 && (
          <div className="hidden shrink-0 flex-wrap justify-end gap-1 sm:flex">
            {f.assets.slice(0, 2).map((a) => (
              <code
                key={a.id}
                className="max-w-[10rem] truncate rounded bg-muted px-1.5 py-0.5 font-mono text-xs"
                title={`${a.type} · ${a.label}`}
              >
                {a.label}
              </code>
            ))}
            {f.assets.length > 2 && <span className="text-xs text-muted-foreground">+{f.assets.length - 2}</span>}
          </div>
        )}
        {f.finding_id && !f.inherited ? (
          <Select value={f.status} onValueChange={(v) => onStatus(f, v as FindingStatus)}>
            <SelectTrigger size="sm" className="h-7 w-28 shrink-0 border-none px-1 shadow-none focus-visible:ring-0">
              <StatusBadge domain="finding" value={f.status} dot />
            </SelectTrigger>
            <SelectContent position="popper" align="end">
              <SelectGroup>
                {FINDING_STATUSES.map((st) => (
                  <SelectItem key={st} value={st}>
                    {statusMeta("finding", st).label}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
        ) : (
          <StatusBadge domain="finding" value={f.status} dot />
        )}
        <span className="hidden shrink-0 text-xs text-muted-foreground md:block">
          {new Date(f.ts).toLocaleString("zh-CN")}
        </span>
        {f.finding_id && (
          <Link
            href={
              f.inherited
                ? `/function/findings/detail?id=${f.finding_id}&context_task=${contextTaskId}`
                : `/function/findings/detail?id=${f.finding_id}`
            }
            className="text-muted-foreground hover:text-primary inline-flex shrink-0 items-center gap-0.5 text-xs"
            title="查看漏洞详情"
          >
            详情
            <ArrowUpRightIcon className="size-3" />
          </Link>
        )}
      </div>
      {open && (
        <div className="bg-muted/30 px-4 pb-4 pl-11">
          <div className="mb-1 text-xs font-medium text-muted-foreground">证据 / PoC</div>
          <pre className="overflow-auto rounded-md border bg-background p-3 font-mono text-xs whitespace-pre-wrap">
            {f.evidence}
          </pre>
        </div>
      )}
    </div>
  );
}

export function FindingsTab({ taskId }: { taskId: string }) {
  const [findings, setFindings] = React.useState<Finding[]>([]);
  const [review, setReview] = React.useState<FindingReviewStatus | null>(null);
  const [reviewError, setReviewError] = React.useState("");
  const [reviewBusy, setReviewBusy] = React.useState(false);
  const [rewriteRetryBusy, setRewriteRetryBusy] = React.useState(false);
  const [batchSizeDraft, setBatchSizeDraft] = React.useState(3);
  const [sortPreference, setSortPreference] = useStoredSortPreference(
    FINDING_SORT_PREFERENCE_KEY,
    FINDING_SORT_FIELDS,
    "time",
    "desc",
  );

  React.useEffect(() => {
    let active = true;
    const load = () => {
      api
        .findings(taskId)
        .then((fs) => {
          if (active) setFindings(fs);
        })
        .catch(() => {
          // Keep the last successful snapshot during transient refresh failures.
        });
    };
    load();
    const t = setInterval(load, 3000);
    return () => {
      active = false;
      clearInterval(t);
    };
  }, [taskId]);

  React.useEffect(() => {
    let active = true;
    const load = () =>
      api
        .findingReviewStatus(taskId)
        .then((value) => {
          if (!active) return;
          setReview(value);
          setBatchSizeDraft(value.batch_size || 3);
          setReviewError(value.last_error ?? value.error ?? "");
        })
        .catch(() => {});
    void load();
    const timer = setInterval(load, 5000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [taskId]);

  const runReview = async () => {
    if (reviewBusy || review?.running) return;
    setReviewBusy(true);
    setReviewError("");
    try {
      const result = await api.runFindingReview(taskId);
      if (!result.accepted) {
        setReviewError("没有可检查的漏洞，或已有检查正在运行。");
        return;
      }
      toast.success("已提交本任务漏洞归类检查");
      setReview((current) => (current ? { ...current, running: true } : current));
    } catch (error) {
      setReviewError((error as Error).message || "提交检查失败");
    } finally {
      setReviewBusy(false);
    }
  };

  const updateReviewConfig = async (input: { enabled?: boolean; batch_size?: number }) => {
    try {
      const updated = await api.updateFindingReviewStatus(taskId, input);
      setReview(updated);
      setBatchSizeDraft(updated.batch_size || 3);
    } catch (error) {
      setReviewError((error as Error).message || "更新复核设置失败");
    }
  };

  const retryReportRewrites = async () => {
    if (rewriteRetryBusy) return;
    setRewriteRetryBusy(true);
    try {
      const result = await api.retryFindingReportRewrites(taskId);
      toast.success(result.retried ? `已重新排队 ${result.retried} 份报告` : "没有可重试的失败报告");
      const updated = await api.findingReviewStatus(taskId);
      setReview(updated);
    } catch (error) {
      toast.error((error as Error).message || "报告重试失败");
    } finally {
      setRewriteRetryBusy(false);
    }
  };

  const onStatus = React.useCallback(async (f: Finding, next: FindingStatus) => {
    if (f.inherited || !f.finding_id || next === f.status) return;
    const prev = f.status;
    setFindings((cur) => cur.map((x) => (x.id === f.id ? { ...x, status: next } : x)));
    try {
      await api.setFindingStatus(f.finding_id, next);
      toast.success(`已标记为「${statusMeta("finding", next).label}」`);
    } catch (e) {
      setFindings((cur) => cur.map((x) => (x.id === f.id ? { ...x, status: prev } : x)));
      toast.error("更新失败：" + (e as Error).message);
    }
  }, []);

  const items = findings
    .filter((f) => f.task_id === taskId || f.inherited)
    .sort((a, b) => {
      const compared = Date.parse(a.ts) - Date.parse(b.ts);
      if (compared !== 0) return sortPreference.direction === "asc" ? compared : -compared;
      return b.id.localeCompare(a.id, undefined, { numeric: true });
    });

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardContent className="flex flex-wrap items-center gap-3 p-4">
          <div className="min-w-0 flex-1">
            <div className="text-sm font-medium">漏洞归类检查</div>
            <p className="text-xs text-muted-foreground">
              {review?.enabled
                ? `自动检查开启：每新增 ${review.batch_size || 3} 条后台检查一次，当前待检查 ${review.pending_count ?? 0} 条。`
                : "自动检查已关闭。可手动提交一次任务内漏洞归类检查。"}
              {review?.running ? " 检查正在运行。" : ""}
            </p>
            <p className="mt-1 text-xs text-muted-foreground">
              确认为同一具体根因时自动整理为一个漏洞并重写报告，原始证据保留。不同漏洞的前置依赖在“漏洞关联”页展示。
            </p>
            {!!review?.report_pending && <p className="mt-1 text-xs text-muted-foreground">{review.report_pending} 份报告正在等待重写或重写中。</p>}
            {review?.report_error && <p role="alert" className="mt-1 text-xs text-destructive">报告重写未完成：{review.report_error}</p>}
            {reviewError && (
              <p role="alert" className="mt-1 text-xs text-destructive">
                {reviewError}
              </p>
            )}
          </div>
          <label className="flex items-center gap-2 text-xs">
            <input
              type="checkbox"
              checked={review?.enabled ?? false}
              disabled={!review}
              onChange={(event) => void updateReviewConfig({ enabled: event.target.checked })}
            />
            自动检查
          </label>
          <label className="flex items-center gap-2 text-xs">
            触发条数
            <Input
              type="number"
              min={2}
              max={20}
              className="h-8 w-20"
              value={batchSizeDraft}
              onChange={(event) => setBatchSizeDraft(Number(event.target.value))}
              onBlur={() => {
                const size = Math.max(2, Math.min(20, Math.floor(batchSizeDraft || 3)));
                setBatchSizeDraft(size);
                if (size !== review?.batch_size) void updateReviewConfig({ batch_size: size });
              }}
            />
          </label>
          {!!review?.report_error && <Button size="sm" variant="outline" onClick={() => void retryReportRewrites()} disabled={rewriteRetryBusy}>{rewriteRetryBusy ? "提交中…" : "重试失败报告"}</Button>}
          <Button size="sm" onClick={() => void runReview()} disabled={reviewBusy || !!review?.running}>
            {reviewBusy || review?.running ? "检查中…" : "立即检查 / 归类"}
          </Button>
        </CardContent>
      </Card>
      <Card className="overflow-hidden py-0">
        <CardContent className="px-0">
          <div className="flex items-center border-b px-4 py-2 text-xs text-muted-foreground">
            <span className="min-w-0 flex-1">漏洞</span>
            <button
              type="button"
              className="inline-flex items-center gap-1 outline-none focus-visible:underline"
              aria-label={`发现时间当前${sortPreference.direction === "asc" ? "正序" : "倒序"}，点击切换排序方向`}
              onClick={() =>
                setSortPreference((current) => ({
                  field: "time",
                  direction: current.direction === "asc" ? "desc" : "asc",
                }))
              }
            >
              <span>发现时间</span>
              {sortPreference.direction === "asc" ? (
                <ArrowUpIcon className="size-3.5" />
              ) : (
                <ArrowDownIcon className="size-3.5" />
              )}
            </button>
          </div>
          {items.map((f) => (
            <Row key={f.id} f={f} contextTaskId={taskId} onStatus={onStatus} />
          ))}
          {items.length === 0 && (
            <p className="px-4 py-8 text-center text-sm text-muted-foreground">本任务及直接关联任务暂无确认发现。</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
