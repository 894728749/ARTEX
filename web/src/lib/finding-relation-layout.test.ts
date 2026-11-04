import {
  analyzeFindingRelations,
  layoutFindingRelations,
  RELATION_NODE_HEIGHT,
  RELATION_NODE_WIDTH,
} from "./finding-relation-layout";
import type { FindingRelationEdge, FindingRelationNode } from "./types";
import assert from "node:assert/strict";
import test from "node:test";

const node = (id: string): FindingRelationNode => ({ id, name: id, severity: "medium", status: "pending" });
const edge = (
  id: string,
  source: string,
  target: string,
  status: FindingRelationEdge["status"] = "proposed",
): FindingRelationEdge => ({
  id,
  source,
  target,
  kind: "supports",
  rationale: "",
  evidence: "",
  status,
});

function noOverlap(nodes: FindingRelationNode[], edges: FindingRelationEdge[]) {
  const positions = layoutFindingRelations(nodes, edges);
  for (const [id, point] of positions) {
    assert.ok(Number.isFinite(point.x) && Number.isFinite(point.y), `${id} has finite coordinates`);
  }
  const items = [...positions.entries()];
  for (let i = 0; i < items.length; i++)
    for (let j = i + 1; j < items.length; j++) {
      const [, a] = items[i];
      const [, b] = items[j];
      assert.ok(
        a.x + RELATION_NODE_WIDTH <= b.x ||
          b.x + RELATION_NODE_WIDTH <= a.x ||
          a.y + RELATION_NODE_HEIGHT <= b.y ||
          b.y + RELATION_NODE_HEIGHT <= a.y,
        `${items[i][0]} overlaps ${items[j][0]}`,
      );
    }
  return positions;
}

test("analyzes directed chains and forks as weakly connected groups", () => {
  const nodes = ["a", "b", "c", "d"].map(node);
  const edges = [edge("ab", "a", "b", "verified"), edge("bc", "b", "c"), edge("bd", "b", "d")];
  const result = analyzeFindingRelations(nodes, edges);
  assert.deepEqual(result, {
    components: [{ id: "a", nodeIds: ["a", "b", "c", "d"], edgeIds: ["ab", "bc", "bd"], verifiedCount: 1 }],
    isolatedIds: [],
  });
  const positions = noOverlap(nodes, edges);
  assert.ok(positions.get("a")!.x < positions.get("b")!.x);
  assert.ok(positions.get("b")!.x < positions.get("c")!.x);
  assert.ok(positions.get("b")!.x < positions.get("d")!.x);
  assert.notEqual(positions.get("c")!.y, positions.get("d")!.y);
});

test("places strongly connected cycles in a stable layer and continues beyond them", () => {
  const nodes = ["a", "b", "c", "d"].map(node);
  const edges = [edge("ab", "a", "b"), edge("ba", "b", "a"), edge("bc", "b", "c"), edge("cd", "c", "d")];
  const positions = noOverlap(nodes, edges);
  assert.equal(positions.get("a")!.x, positions.get("b")!.x);
  assert.notEqual(positions.get("a")!.y, positions.get("b")!.y);
  assert.ok(positions.get("b")!.x < positions.get("c")!.x);
  assert.ok(positions.get("c")!.x < positions.get("d")!.x);
});

test("ignores self loops and dangling edges while keeping truly isolated nodes", () => {
  const nodes = ["a", "b", "solo", "loop"].map(node);
  const edges = [edge("ab", "a", "b"), edge("self", "loop", "loop", "verified"), edge("dangling", "absent", "a")];
  const result = analyzeFindingRelations(nodes, edges);
  assert.deepEqual(result, {
    components: [{ id: "a", nodeIds: ["a", "b"], edgeIds: ["ab"], verifiedCount: 0 }],
    isolatedIds: ["loop", "solo"],
  });
  assert.equal(noOverlap(nodes, edges).size, nodes.length);
});

test("separates independent components and the final isolated region", () => {
  const nodes = ["a", "b", "c", "d", "solo"].map(node);
  const edges = [edge("ab", "a", "b"), edge("cd", "c", "d")];
  const result = analyzeFindingRelations(nodes, edges);
  assert.deepEqual(
    result.components.map(({ id }) => id),
    ["a", "c"],
  );
  const positions = noOverlap(nodes, edges);
  assert.notEqual(positions.get("a")!.y, positions.get("c")!.y);
  assert.ok(positions.get("solo")!.y > Math.max(...["a", "b", "c", "d"].map((id) => positions.get(id)!.y)));
});

test("handles a large directed chain without recursion limits or missing nodes", () => {
  const nodes = Array.from({ length: 1400 }, (_, i) => node(`n${String(i).padStart(4, "0")}`));
  const edges = nodes.slice(1).map((item, i) => edge(`e${i}`, nodes[i].id, item.id));
  const positions = layoutFindingRelations(nodes, edges);
  assert.equal(positions.size, nodes.length);
  assert.ok(positions.get("n1399")!.x > positions.get("n0000")!.x);
});

test("layout is invariant to node and edge input order", () => {
  const nodes = ["a", "b", "c", "d", "solo"].map(node);
  const edges = [edge("ab", "a", "b"), edge("bc", "b", "c"), edge("cd", "c", "d")];
  assert.deepEqual(
    [...layoutFindingRelations(nodes, edges)],
    [...layoutFindingRelations([...nodes].reverse(), [...edges].reverse())],
  );
});
