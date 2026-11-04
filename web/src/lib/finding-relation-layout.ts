import type { FindingRelationEdge, FindingRelationNode } from "./types";

export const RELATION_NODE_WIDTH = 280;
export const RELATION_NODE_HEIGHT = 152;

const COLUMN_GAP = 160;
const ROW_GAP = 48;
const COMPONENT_GAP = 96;

const compareIds = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

type RelationAnalysis = {
  components: Array<{ id: string; nodeIds: string[]; edgeIds: string[]; verifiedCount: number }>;
  isolatedIds: string[];
};

function validEdges(nodes: FindingRelationNode[], edges: FindingRelationEdge[]) {
  const nodeIds = new Set(nodes.map((node) => node.id));
  return edges.filter((edge) => edge.source !== edge.target && nodeIds.has(edge.source) && nodeIds.has(edge.target));
}

export function analyzeFindingRelations(nodes: FindingRelationNode[], edges: FindingRelationEdge[]): RelationAnalysis {
  const orderedNodes = [...nodes].sort((a, b) => compareIds(a.id, b.id));
  const valid = validEdges(orderedNodes, edges);
  const adjacent = new Map(orderedNodes.map((node) => [node.id, new Set<string>()]));
  for (const edge of valid) {
    adjacent.get(edge.source)?.add(edge.target);
    adjacent.get(edge.target)?.add(edge.source);
  }

  const seen = new Set<string>();
  const groups: RelationAnalysis["components"] = [];
  const isolatedIds: string[] = [];
  for (const node of orderedNodes) {
    const neighbors = adjacent.get(node.id)!;
    if (neighbors.size === 0) {
      isolatedIds.push(node.id);
      continue;
    }
    if (seen.has(node.id)) continue;
    const stack = [node.id];
    const nodeIds: string[] = [];
    seen.add(node.id);
    while (stack.length) {
      const current = stack.pop()!;
      nodeIds.push(current);
      for (const next of adjacent.get(current)!) {
        if (!seen.has(next)) {
          seen.add(next);
          stack.push(next);
        }
      }
    }
    nodeIds.sort(compareIds);
    const memberIds = new Set(nodeIds);
    const componentEdges = valid.filter((edge) => memberIds.has(edge.source) && memberIds.has(edge.target));
    groups.push({
      id: nodeIds[0],
      nodeIds,
      edgeIds: componentEdges.map((edge) => edge.id).sort(compareIds),
      verifiedCount: componentEdges.filter((edge) => edge.status === "verified").length,
    });
  }
  groups.sort((a, b) => b.nodeIds.length - a.nodeIds.length || compareIds(a.id, b.id));
  isolatedIds.sort(compareIds);
  return { components: groups, isolatedIds };
}

function stronglyConnected(nodes: string[], outgoing: Map<string, Set<string>>) {
  const visited = new Set<string>();
  const finish: string[] = [];
  for (const start of nodes) {
    if (visited.has(start)) continue;
    visited.add(start);
    const stack: Array<{ id: string; targets: string[]; next: number }> = [
      { id: start, targets: [...outgoing.get(start)!].sort(compareIds), next: 0 },
    ];
    while (stack.length) {
      const top = stack[stack.length - 1];
      if (top.next < top.targets.length) {
        const target = top.targets[top.next++];
        if (!visited.has(target)) {
          visited.add(target);
          stack.push({ id: target, targets: [...outgoing.get(target)!].sort(compareIds), next: 0 });
        }
      } else {
        finish.push(top.id);
        stack.pop();
      }
    }
  }
  const reverse = new Map(nodes.map((id) => [id, new Set<string>()]));
  for (const [source, targets] of outgoing) for (const target of targets) reverse.get(target)!.add(source);
  visited.clear();
  const groups: string[][] = [];
  for (const start of finish.reverse()) {
    if (visited.has(start)) continue;
    const group: string[] = [];
    const stack = [start];
    visited.add(start);
    while (stack.length) {
      const id = stack.pop()!;
      group.push(id);
      for (const target of reverse.get(id)!)
        if (!visited.has(target)) {
          visited.add(target);
          stack.push(target);
        }
    }
    groups.push(group.sort(compareIds));
  }
  return groups;
}

export function layoutFindingRelations(
  nodes: FindingRelationNode[],
  edges: FindingRelationEdge[],
): Map<string, { x: number; y: number }> {
  const orderedNodes = [...nodes].sort((a, b) => compareIds(a.id, b.id));
  const valid = validEdges(orderedNodes, edges);
  const analysis = analyzeFindingRelations(orderedNodes, valid);
  const positions = new Map<string, { x: number; y: number }>();
  const rowStep = RELATION_NODE_HEIGHT + ROW_GAP;
  const columnStep = RELATION_NODE_WIDTH + COLUMN_GAP;
  let componentTop = 0;

  for (const component of analysis.components) {
    const member = new Set(component.nodeIds);
    const outgoing = new Map(component.nodeIds.map((id) => [id, new Set<string>()]));
    for (const edge of valid)
      if (member.has(edge.source) && member.has(edge.target)) outgoing.get(edge.source)!.add(edge.target);
    const sccs = stronglyConnected(component.nodeIds, outgoing);
    const sccIndex = new Map<string, number>();
    sccs.forEach((group, i) => {
      for (const id of group) sccIndex.set(id, i);
    });
    const dag = sccs.map(() => new Set<number>());
    const indegree = sccs.map(() => 0);
    for (const edge of valid) {
      if (!member.has(edge.source) || !member.has(edge.target)) continue;
      const from = sccIndex.get(edge.source)!;
      const to = sccIndex.get(edge.target)!;
      if (from !== to && !dag[from].has(to)) {
        dag[from].add(to);
        indegree[to]++;
      }
    }
    const rank = sccs.map(() => 0);
    const ready = indegree
      .map((degree, i) => ({ degree, i }))
      .filter((item) => item.degree === 0)
      .map((item) => item.i);
    ready.sort((a, b) => compareIds(sccs[a][0], sccs[b][0]));
    while (ready.length) {
      const current = ready.shift()!;
      for (const target of [...dag[current]].sort((a, b) => compareIds(sccs[a][0], sccs[b][0]))) {
        rank[target] = Math.max(rank[target], rank[current] + 1);
        indegree[target]--;
        if (indegree[target] === 0) {
          ready.push(target);
          ready.sort((a, b) => compareIds(sccs[a][0], sccs[b][0]));
        }
      }
    }
    const layers = new Map<number, string[]>();
    for (const id of component.nodeIds) {
      const layer = rank[sccIndex.get(id)!];
      const ids = layers.get(layer) ?? [];
      ids.push(id);
      layers.set(layer, ids);
    }
    let maxRows = 0;
    for (const [layer, ids] of layers) {
      ids.sort(compareIds);
      maxRows = Math.max(maxRows, ids.length);
      ids.forEach((id, row) => {
        positions.set(id, { x: layer * columnStep, y: componentTop + row * rowStep });
      });
    }
    componentTop += maxRows * rowStep + COMPONENT_GAP;
  }

  for (const [i, id] of analysis.isolatedIds.entries()) {
    const columns = Math.max(1, Math.floor(Math.sqrt(analysis.isolatedIds.length) * 1.6));
    const row = Math.floor(i / columns);
    const column = i % columns;
    positions.set(id, { x: column * columnStep, y: componentTop + row * rowStep });
  }
  return new Map([...positions.entries()].sort(([a], [b]) => compareIds(a, b)));
}
