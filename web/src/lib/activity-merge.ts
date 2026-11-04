import type { Activity } from "./types";

// History and live responses can overlap or arrive out of order. A persisted
// activity's seq is its identity; replay must not duplicate rows or token totals.
export function mergeActivities(current: Activity[], incoming: Activity[]): Activity[] {
  const bySeq = new Map<number, Activity>();
  for (const activity of current) bySeq.set(activity.seq, activity);
  for (const activity of incoming) bySeq.set(activity.seq, activity);
  return [...bySeq.values()].sort((left, right) => left.seq - right.seq);
}

// A history request can contain newer persisted state for an existing seq, such
// as a tool row whose result was appended after its initial tool_use. Preserve a
// same-seq live update that arrived after the request started.
export function mergeHistoryRefresh(
  current: Activity[],
  incoming: Activity[],
  requestSnapshot: Map<number, Activity>,
): Activity[] {
  const bySeq = new Map<number, Activity>();
  for (const activity of current) bySeq.set(activity.seq, activity);
  for (const activity of incoming) {
    const existing = bySeq.get(activity.seq);
    if (!existing || requestSnapshot.get(activity.seq) === existing) bySeq.set(activity.seq, activity);
  }
  return [...bySeq.values()].sort((left, right) => left.seq - right.seq);
}
