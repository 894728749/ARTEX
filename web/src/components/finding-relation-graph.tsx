"use client";

import * as React from "react";

import Link from "next/link";

import {
  Background,
  Controls,
  type Edge,
  Handle,
  MarkerType,
  MiniMap,
  type Node,
  type NodeProps,
  Position,
  ReactFlow,
  type ReactFlowInstance,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { ArrowRight, Bug, Check, ExternalLink, Focus, GitBranch, Maximize2, Search, Unlink, X } from "lucide-react";

import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  analyzeFindingRelations,
  layoutFindingRelations,
  RELATION_NODE_HEIGHT,
  RELATION_NODE_WIDTH,
} from "@/lib/finding-relation-layout";
import { statusMeta } from "@/lib/status";
import type { FindingRelationEdge, FindingRelationKind, FindingRelationNode, FindingRelations } from "@/lib/types";
import { cn } from "@/lib/utils";

export const RELATION_LABELS: Record<FindingRelationKind, string> = {
  prerequisite: "前置条件",
  enables: "提供能力",
  supports: "证据支持",
  contradicts: "相互矛盾",
};
const RELATION_COLORS: Record<FindingRelationKind, string> = {
  prerequisite: "#2563eb",
  enables: "#7c3aed",
  supports: "#64748b",
  contradicts: "#e11d48",
};
const SEVERITY_COLORS: Record<string, string> = {
  critical: "#e11d48",
  high: "#ef4444",
  medium: "#d97706",
  low: "#64748b",
};
type FindingFlowNode = Node<
  { finding: FindingRelationNode; degree: number; dimmed: boolean; onInspect: () => void },
  "finding"
>;

function FindingNode({ data, selected }: NodeProps<FindingFlowNode>) {
  return (
    <button
      type="button"
      onClick={data.onInspect}
      aria-pressed={selected}
      className={cn(
        "flex h-full w-full flex-col rounded-xl border bg-card px-4 py-3 text-left text-card-foreground shadow-sm transition-[box-shadow,opacity] focus-visible:outline-2 focus-visible:outline-ring",
        selected ? "border-primary ring-2 ring-primary/25" : "border-border hover:border-primary/60 hover:shadow-md",
        data.dimmed && "opacity-35",
      )}
    >
      <Handle type="target" position={Position.Left} className="!size-2 !border-background !bg-muted-foreground" />
      <div className="mb-2 flex items-center justify-between gap-2">
        <StatusBadge domain="severity" value={data.finding.severity} />
        <span className="flex items-center gap-1 text-xs text-muted-foreground">
          <GitBranch className="size-3" aria-hidden="true" />
          {data.degree} 条关联
        </span>
      </div>
      <div className="line-clamp-3 break-words text-sm font-medium leading-5" title={data.finding.name}>
        {data.finding.name}
      </div>
      <div className="mt-auto flex items-center justify-between pt-2 text-xs text-muted-foreground">
        <span>{statusMeta("finding", data.finding.status).label}</span>
        <span>{selected ? "正在查看" : "点击查看关系"}</span>
      </div>
      <Handle type="source" position={Position.Right} className="!size-2 !border-background !bg-muted-foreground" />
    </button>
  );
}
const nodeTypes = { finding: FindingNode };

function FindingLink({ taskId, node }: { taskId: string; node: FindingRelationNode }) {
  return (
    <Button asChild variant="outline" className="min-h-10 w-full">
      <Link
        href={`/function/findings/detail?id=${encodeURIComponent(node.id)}&context_task=${encodeURIComponent(taskId)}`}
      >
        打开漏洞详情
        <ExternalLink className="size-4" aria-hidden="true" />
      </Link>
    </Button>
  );
}

export function FindingRelationGraph({
  taskId,
  data,
  busy,
  onRemove,
  onAdd,
}: {
  taskId: string;
  data: FindingRelations;
  busy: boolean;
  onRemove: (edge: FindingRelationEdge) => void;
  onAdd: (source?: string) => void;
}) {
  const [query, setQuery] = React.useState("");
  const [kind, setKind] = React.useState("all");
  const [verification, setVerification] = React.useState("all");
  const [group, setGroup] = React.useState("");
  const [selection, setSelection] = React.useState<{ node?: string; edge?: string }>({});
  const [expanded, setExpanded] = React.useState(false);
  const searchId = React.useId();
  const flow = React.useRef<ReactFlowInstance<FindingFlowNode, Edge> | null>(null);
  const nodeMap = React.useMemo(() => new Map(data.nodes.map((n) => [n.id, n])), [data.nodes]);
  const validEdges = React.useMemo(
    () => data.edges.filter((e) => e.source !== e.target && nodeMap.has(e.source) && nodeMap.has(e.target)),
    [data.edges, nodeMap],
  );
  const all = React.useMemo(() => analyzeFindingRelations(data.nodes, validEdges), [data.nodes, validEdges]);
  const filteredEdges = React.useMemo(
    () =>
      validEdges.filter(
        (e) => (kind === "all" || e.kind === kind) && (verification === "all" || e.status === verification),
      ),
    [validEdges, kind, verification],
  );
  const filtered = React.useMemo(() => analyzeFindingRelations(data.nodes, filteredEdges), [data.nodes, filteredEdges]);
  const matches = React.useMemo(() => {
    const q = query.trim().toLocaleLowerCase();
    return new Set(data.nodes.filter((n) => !q || n.name.toLocaleLowerCase().includes(q)).map((n) => n.id));
  }, [data.nodes, query]);
  // A search chooses matching groups, keeping intermediates so a chain is never cut in half.
  const groups = React.useMemo(
    () => filtered.components.filter((c) => c.nodeIds.some((id) => matches.has(id))),
    [filtered.components, matches],
  );
  const currentGroup = groups.find((c) => c.id === group) ?? groups[0];
  const viewIds = React.useMemo(() => new Set(currentGroup?.nodeIds ?? []), [currentGroup]);
  const viewNodes = React.useMemo(() => data.nodes.filter((n) => viewIds.has(n.id)), [data.nodes, viewIds]);
  const viewEdges = React.useMemo(
    () => filteredEdges.filter((e) => viewIds.has(e.source) && viewIds.has(e.target)),
    [filteredEdges, viewIds],
  );
  const isolated = data.nodes.filter((n) => all.isolatedIds.includes(n.id) && matches.has(n.id));
  const selectedNode = selection.node ? nodeMap.get(selection.node) : undefined;
  const selectedEdge = validEdges.find((e) => e.id === selection.edge);
  const connectedEdges = validEdges.filter((e) => e.source === selectedNode?.id || e.target === selectedNode?.id);
  const neighbours = new Set(connectedEdges.flatMap((e) => [e.source, e.target]));
  const positions = React.useMemo(() => layoutFindingRelations(viewNodes, viewEdges), [viewNodes, viewEdges]);
  const nodes: FindingFlowNode[] = viewNodes.map((finding) => ({
    id: finding.id,
    type: "finding",
    position: positions.get(finding.id) ?? { x: 0, y: 0 },
    data: {
      finding,
      degree: viewEdges.filter((e) => e.source === finding.id || e.target === finding.id).length,
      dimmed: !!selectedNode && !neighbours.has(finding.id) && selectedNode.id !== finding.id,
      onInspect: () => setSelection({ node: finding.id }),
    },
    selected: selection.node === finding.id,
    style: { width: RELATION_NODE_WIDTH, height: RELATION_NODE_HEIGHT },
    ariaLabel: `${finding.name}，${statusMeta("severity", finding.severity).label}。按回车查看关联详情`,
  }));
  const edges: Edge[] = viewEdges.map((e) => ({
    id: e.id,
    source: e.source,
    target: e.target,
    type: "smoothstep",
    label: `${e.status === "verified" ? "✓ " : "待验证 · "}${RELATION_LABELS[e.kind]}`,
    markerEnd: { type: MarkerType.ArrowClosed, color: RELATION_COLORS[e.kind] },
    interactionWidth: 24,
    style: {
      stroke: RELATION_COLORS[e.kind],
      strokeWidth: selection.edge === e.id ? 3 : 2,
      strokeDasharray: e.status === "proposed" ? "7 5" : undefined,
      opacity: selectedNode && !connectedEdges.some((edge) => edge.id === e.id) ? 0.2 : 1,
    },
    labelStyle: { fill: "var(--foreground)", fontSize: 12 },
    labelBgStyle: { fill: "var(--card)", fillOpacity: 0.96 },
    labelBgPadding: [8, 5],
    labelBgBorderRadius: 5,
    ariaLabel: `${nodeMap.get(e.source)?.name} → ${nodeMap.get(e.target)?.name}，${RELATION_LABELS[e.kind]}，${e.status === "verified" ? "已验证" : "待验证"}`,
  }));
  const graphKey = JSON.stringify([
    taskId,
    currentGroup?.id,
    viewNodes.map((n) => n.id).sort(),
    viewEdges.map((e) => e.id).sort(),
  ]);

  React.useEffect(() => {
    if (!expanded) return;
    function close(event: KeyboardEvent) {
      if (event.key === "Escape") setExpanded(false);
    }
    document.addEventListener("keydown", close);
    return () => document.removeEventListener("keydown", close);
  }, [expanded]);

  function chooseNode(id: string) {
    setSelection({ node: id });
    const component = filtered.components.find((c) => c.nodeIds.includes(id));
    if (component) setGroup(component.id);
    if (viewIds.has(id)) {
      const p = positions.get(id);
      if (p)
        void flow.current?.setCenter(p.x + RELATION_NODE_WIDTH / 2, p.y + RELATION_NODE_HEIGHT / 2, {
          zoom: 1,
          duration: 0,
        });
    }
  }
  function chooseGroup(id: string) {
    setGroup(id);
    setSelection({});
  }
  function addRelation(id?: string) {
    setExpanded(false);
    onAdd(id);
  }

  return (
    <div className={cn("flex min-w-0 flex-col rounded-xl border bg-card", expanded && "fixed inset-3 z-50 shadow-2xl")}>
      <div className="flex flex-wrap items-center justify-between gap-3 border-b px-4 py-3">
        <div className="flex flex-wrap items-center gap-x-5 gap-y-1 text-sm">
          <span className="font-medium">{all.components.length} 个关联组</span>
          <span className="text-muted-foreground">{data.nodes.length - all.isolatedIds.length} 个关联漏洞</span>
          <span className="text-muted-foreground">
            {validEdges.filter((e) => e.status === "verified").length} 条已验证关系
          </span>
          <span className="text-muted-foreground">{all.isolatedIds.length} 个尚无关联</span>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" className="min-h-10" onClick={() => addRelation(selectedNode?.id)}>
            <GitBranch aria-hidden="true" />
            添加关系
          </Button>
          <Button variant="ghost" className="min-h-10" aria-pressed={expanded} onClick={() => setExpanded(!expanded)}>
            {expanded ? <X aria-hidden="true" /> : <Maximize2 aria-hidden="true" />}
            {expanded ? "退出展开" : "展开画布"}
          </Button>
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-2 border-b bg-muted/20 px-4 py-3">
        <label htmlFor={searchId} className="relative min-w-44 flex-1 sm:max-w-80">
          <Search className="absolute top-3 left-3 size-4 text-muted-foreground" aria-hidden="true" />
          <Input
            id={searchId}
            aria-label="搜索漏洞名称"
            className="h-10 pl-9"
            placeholder="搜索漏洞，定位所在关联组…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </label>
        <label className="text-sm">
          <span className="sr-only">关系类型</span>
          <select
            aria-label="筛选关系类型"
            className="h-10 max-w-full rounded-lg border bg-background px-3"
            value={kind}
            onChange={(e) => {
              setKind(e.target.value);
              setSelection({});
            }}
          >
            <option value="all">全部关系类型</option>
            {Object.entries(RELATION_LABELS).map(([k, name]) => (
              <option key={k} value={k}>
                {name}
              </option>
            ))}
          </select>
        </label>
        <label className="text-sm">
          <span className="sr-only">验证状态</span>
          <select
            aria-label="筛选验证状态"
            className="h-10 rounded-lg border bg-background px-3"
            value={verification}
            onChange={(e) => {
              setVerification(e.target.value);
              setSelection({});
            }}
          >
            <option value="all">全部验证状态</option>
            <option value="verified">仅已验证</option>
            <option value="proposed">仅待验证</option>
          </select>
        </label>
        {(query || kind !== "all" || verification !== "all") && (
          <Button
            variant="ghost"
            className="min-h-10"
            onClick={() => {
              setQuery("");
              setKind("all");
              setVerification("all");
              setSelection({});
            }}
          >
            清除筛选
          </Button>
        )}
      </div>
      <div className={cn("grid min-h-0 min-w-0 lg:grid-cols-[244px_minmax(0,1fr)]", expanded && "flex-1")}>
        <aside
          aria-label="关联组与独立漏洞"
          className={cn(
            "max-h-64 overflow-y-auto border-b bg-muted/10 p-3 lg:max-h-none lg:border-r lg:border-b-0",
            !expanded && "lg:h-[68vh] lg:min-h-[540px]",
          )}
        >
          <div className="mb-2 px-2 text-xs font-medium text-muted-foreground">关联组 · 按规模排列</div>
          <div className="space-y-2">
            {groups.map((component, index) => {
              const first = nodeMap.get(component.nodeIds[0]);
              return (
                <button
                  type="button"
                  key={component.id}
                  aria-pressed={currentGroup?.id === component.id}
                  className={cn(
                    "w-full rounded-lg border p-3 text-left transition-colors focus-visible:outline-2 focus-visible:outline-ring",
                    currentGroup?.id === component.id
                      ? "border-primary/40 bg-primary/5"
                      : "border-transparent hover:bg-muted",
                  )}
                  onClick={() => chooseGroup(component.id)}
                >
                  <div className="mb-1 flex items-center justify-between gap-2 text-sm font-medium">
                    <span>关联组 {index + 1}</span>
                    <span className="text-xs text-muted-foreground">{component.nodeIds.length} 个漏洞</span>
                  </div>
                  <div className="line-clamp-2 break-words text-xs leading-5 text-muted-foreground">{first?.name}</div>
                  <div className="mt-2 flex items-center gap-1 text-xs text-muted-foreground">
                    <GitBranch className="size-3" aria-hidden="true" />
                    {component.edgeIds.length} 条关系<span className="ml-auto">{component.verifiedCount} 条已验证</span>
                  </div>
                </button>
              );
            })}
            {groups.length === 0 && (
              <p className="px-2 py-4 text-sm text-muted-foreground">
                {validEdges.length ? "当前筛选下没有关联组。" : "尚未登记漏洞关系。"}
              </p>
            )}
          </div>
          <details className="mt-4 border-t pt-3" open={validEdges.length === 0 ? true : undefined}>
            <summary className="cursor-pointer rounded px-2 py-2 text-sm font-medium focus-visible:outline-2">
              尚无关联的漏洞（{isolated.length}）
            </summary>
            <p className="px-2 py-2 text-xs leading-5 text-muted-foreground">暂未建立关系，单独列出以保持画布清晰。</p>
            <div className="space-y-1">
              {isolated.map((n) => (
                <button
                  type="button"
                  key={n.id}
                  className={cn(
                    "flex w-full items-start gap-2 rounded-lg p-2 text-left hover:bg-muted focus-visible:outline-2 focus-visible:outline-ring",
                    selectedNode?.id === n.id && "bg-muted",
                  )}
                  onClick={() => chooseNode(n.id)}
                >
                  <Bug className="mt-1 size-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                  <span className="line-clamp-2 break-words text-xs leading-5">{n.name}</span>
                </button>
              ))}
            </div>
          </details>
        </aside>
        <div className={cn("flex min-h-0 min-w-0 flex-col", !expanded && "h-[68vh] min-h-[540px]")}>
          <div className="flex flex-wrap items-center justify-between gap-2 border-b px-4 py-2 text-xs text-muted-foreground">
            <span>
              {currentGroup
                ? `${viewNodes.length} 个漏洞 · ${viewEdges.length} 条关系 · 按箭头方向阅读`
                : "漏洞关系画布"}
            </span>
            <span>实线：已验证　虚线：待验证</span>
          </div>
          <div className="relative min-h-80 min-w-0 flex-1 bg-muted/15">
            {viewNodes.length > 0 ? (
              <ReactFlow<FindingFlowNode, Edge>
                key={graphKey}
                nodes={nodes}
                edges={edges}
                nodeTypes={nodeTypes}
                onInit={(instance) => {
                  flow.current = instance;
                }}
                fitView
                fitViewOptions={{ padding: 0.22, minZoom: 0.75, maxZoom: 1 }}
                minZoom={0.25}
                maxZoom={1.6}
                nodesConnectable={false}
                nodesDraggable={false}
                nodesFocusable={false}
                elementsSelectable={true}
                deleteKeyCode={null}
                onNodeClick={(_, node) => setSelection({ node: node.id })}
                onEdgeClick={(_, edge) => setSelection({ edge: edge.id })}
                onPaneClick={() => setSelection({})}
                proOptions={{ hideAttribution: true }}
                aria-label="漏洞关系有向图"
              >
                <Background gap={22} size={1} color="var(--border)" />
                <Controls showInteractive={false} fitViewOptions={{ padding: 0.22, minZoom: 0.75, maxZoom: 1 }} />
                <MiniMap
                  className="!h-24 !w-36 !border !border-border !bg-card"
                  maskColor="var(--muted)"
                  nodeColor={(n) => SEVERITY_COLORS[(n.data as FindingFlowNode["data"]).finding.severity] ?? "#64748b"}
                  pannable
                  zoomable
                  ariaLabel="关联图缩略导航"
                />
              </ReactFlow>
            ) : (
              <div className="flex h-full flex-col items-center justify-center gap-3 px-6 py-12 text-center">
                <div className="rounded-2xl border bg-card p-4">
                  <Unlink className="size-7 text-muted-foreground" aria-hidden="true" />
                </div>
                <h3 className="text-base font-medium">
                  {validEdges.length ? "没有符合筛选的关系" : "还没有可展示的漏洞链路"}
                </h3>
                <p className="max-w-md text-sm leading-6 text-muted-foreground">
                  {validEdges.length
                    ? "调整关系类型、验证状态或搜索条件后再查看。"
                    : "漏洞清单不等于利用链。归类检查或人工补充关系后，这里会按前置、能力与证据关系展开；未关联漏洞保留在左侧列表。"}
                </p>
                {!validEdges.length && (
                  <Button variant="outline" className="min-h-10" onClick={() => addRelation(selectedNode?.id)}>
                    添加第一条关系
                    <ArrowRight aria-hidden="true" />
                  </Button>
                )}
              </div>
            )}
          </div>
          <div className="flex flex-wrap gap-x-5 gap-y-2 border-t px-4 py-3 text-xs text-muted-foreground">
            {Object.entries(RELATION_LABELS).map(([k, name]) => (
              <span key={k} className="inline-flex items-center gap-2">
                <span className="w-5 border-t-2" style={{ borderColor: RELATION_COLORS[k as FindingRelationKind] }} />
                {name}
              </span>
            ))}
            <span>支持与矛盾关系不代表可利用步骤</span>
          </div>
        </div>
      </div>
      <div aria-live="polite" className="border-t bg-muted/10 px-4 py-4">
        {selectedNode ? (
          <div className="grid gap-4 md:grid-cols-[minmax(0,1fr)_minmax(240px,1fr)]">
            <div className="min-w-0">
              <div className="mb-2 flex flex-wrap items-center gap-2">
                <Bug className="size-4 text-muted-foreground" aria-hidden="true" />
                <StatusBadge domain="severity" value={selectedNode.severity} />
                <StatusBadge domain="finding" value={selectedNode.status} />
              </div>
              <h3 className="mb-3 break-words text-sm font-medium leading-6">{selectedNode.name}</h3>
              <div className="flex flex-wrap gap-2">
                <FindingLink taskId={taskId} node={selectedNode} />
                <Button variant="ghost" className="min-h-10" onClick={() => addRelation(selectedNode.id)}>
                  以此漏洞添加关系
                </Button>
              </div>
            </div>
            <div className="min-w-0">
              <h4 className="mb-2 text-sm font-medium">直接关联（{connectedEdges.length}）</h4>
              <div className="max-h-52 space-y-2 overflow-y-auto">
                {connectedEdges.map((e) => (
                  <button
                    key={e.id}
                    type="button"
                    className="w-full rounded-lg border bg-card p-3 text-left text-sm hover:border-primary/50 focus-visible:outline-2 focus-visible:outline-ring"
                    onClick={() => setSelection({ edge: e.id })}
                  >
                    <span className="mb-1 flex items-center gap-2 text-xs text-muted-foreground">
                      {e.source === selectedNode.id ? "指向后续" : "来自上游"} · {RELATION_LABELS[e.kind]} ·{" "}
                      {e.status === "verified" ? "已验证" : "待验证"}
                    </span>
                    <span className="line-clamp-2 break-words">
                      {nodeMap.get(e.source === selectedNode.id ? e.target : e.source)?.name}
                    </span>
                  </button>
                ))}
                {!connectedEdges.length && (
                  <p className="text-sm leading-6 text-muted-foreground">
                    这个漏洞尚未登记关联。可以查看完整报告，再根据证据补充。
                  </p>
                )}
              </div>
            </div>
          </div>
        ) : selectedEdge ? (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <span className="inline-flex items-center gap-2 text-sm font-medium">
                {selectedEdge.status === "verified" ? (
                  <Check className="size-4" aria-hidden="true" />
                ) : (
                  <GitBranch className="size-4" aria-hidden="true" />
                )}
                {RELATION_LABELS[selectedEdge.kind]} · {selectedEdge.status === "verified" ? "已验证" : "待验证"}
              </span>
              <Button variant="destructive" className="min-h-10" disabled={busy} onClick={() => onRemove(selectedEdge)}>
                删除此关系
              </Button>
            </div>
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <button
                type="button"
                className="max-w-full break-words text-left underline underline-offset-4"
                onClick={() => chooseNode(selectedEdge.source)}
              >
                {nodeMap.get(selectedEdge.source)?.name}
              </button>
              <ArrowRight className="size-4 shrink-0" aria-hidden="true" />
              <button
                type="button"
                className="max-w-full break-words text-left underline underline-offset-4"
                onClick={() => chooseNode(selectedEdge.target)}
              >
                {nodeMap.get(selectedEdge.target)?.name}
              </button>
            </div>
            <div className="grid gap-4 text-sm md:grid-cols-2">
              <div>
                <h4 className="mb-1 font-medium">关系理由</h4>
                <p className="whitespace-pre-wrap break-words leading-6 text-muted-foreground">
                  {selectedEdge.rationale}
                </p>
              </div>
              <div>
                <h4 className="mb-1 font-medium">证据 / 待验证内容</h4>
                <p className="max-h-60 overflow-y-auto whitespace-pre-wrap break-words leading-6 text-muted-foreground">
                  {selectedEdge.evidence || "未记录证据"}
                </p>
              </div>
            </div>
          </div>
        ) : (
          <p className="flex items-center gap-2 text-sm leading-6 text-muted-foreground">
            <Focus className="size-4 shrink-0" aria-hidden="true" />
            点击漏洞查看上下游，点击连线查看关系理由与证据。也可使用下方文字列表。
          </p>
        )}
      </div>
      {viewNodes.length > 0 && (
        <details className="border-t px-4 py-3">
          <summary className="cursor-pointer py-1 text-sm font-medium">文字浏览当前关联组</summary>
          <div className="mt-3 grid gap-4 md:grid-cols-2">
            <ul className="space-y-1">
              {viewNodes.map((n) => (
                <li key={n.id}>
                  <button
                    type="button"
                    className="w-full rounded p-2 text-left text-sm hover:bg-muted focus-visible:outline-2"
                    onClick={() => chooseNode(n.id)}
                  >
                    {n.name}
                  </button>
                </li>
              ))}
            </ul>
            <ul className="space-y-2">
              {viewEdges.map((e) => (
                <li key={e.id}>
                  <button
                    type="button"
                    className="w-full rounded border p-3 text-left text-sm hover:bg-muted focus-visible:outline-2"
                    onClick={() => setSelection({ edge: e.id })}
                  >
                    {nodeMap.get(e.source)?.name} → {nodeMap.get(e.target)?.name}
                    <span className="mt-1 block text-xs text-muted-foreground">
                      {RELATION_LABELS[e.kind]} · {e.status === "verified" ? "已验证" : "待验证"}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </div>
        </details>
      )}
    </div>
  );
}
