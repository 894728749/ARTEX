"use client";

import * as React from "react";
import { ArrowUpIcon, Loader2Icon, RotateCwIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { TeamSession, TeamSessionMessage } from "@/lib/types";

const PAGE_SIZE = 100;

function senderLabel(message: TeamSessionMessage, sessionID: string) {
  if (message.kind === "user") {
    if (message.member_id === 0) {
      if (sessionID.startsWith("main:")) return "主 Agent";
      if (sessionID === "plan") return "Planner";
      return "本机用户";
    }
    return `成员 #${message.member_id}`;
  }
  return message.executor_id === 0 ? "本机执行端" : `设备 #${message.executor_id}`;
}

function guidanceStatusLabel(status: TeamSessionMessage["guidance_status"]) {
  if (status === "pending") return "待交付";
  if (status === "delivered") return "已交付执行边界";
  return status === "closed" ? "本轮结束，未交付" : "";
}

function mergeMessages(current: TeamSessionMessage[], incoming: TeamSessionMessage[]) {
  const byID = new Map(current.map((message) => [message.id, message]));
  for (const message of incoming) byID.set(message.id, message);
  return [...byID.values()].sort((a, b) => a.id - b.id);
}

function newRequestID() {
  return globalThis.crypto?.randomUUID?.() ?? `team-message-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

export function TeamSessionWorkspace({ team, taskId }: { team: string; taskId: string }) {
  const [sessions, setSessions] = React.useState<TeamSession[]>([]);
  const [canSteer, setCanSteer] = React.useState(false);
  const [sessionID, setSessionID] = React.useState("");
  const [error, setError] = React.useState("");
  const scopeRef = React.useRef(0);

  React.useEffect(() => {
    const scope = ++scopeRef.current;
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    const load = async () => {
      try {
        const result = await api.teamSessions(team, taskId);
        if (!alive || scope !== scopeRef.current) return;
        setSessions(result.sessions);
        setCanSteer(result.canSteer);
        setSessionID((current) =>
          result.sessions.some((session) => session.id === current) ? current : (result.sessions[0]?.id ?? ""),
        );
        setError("");
      } catch (e) {
        if (alive && scope === scopeRef.current) setError((e as Error).message);
      } finally {
        if (alive && scope === scopeRef.current) timer = setTimeout(load, 5000);
      }
    };
    setSessions([]);
    setSessionID("");
    void load();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [team, taskId]);

  const session = sessions.find((item) => item.id === sessionID);
  return (
    <section className="space-y-3 rounded-md border p-3" aria-label="共享会话消息">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-sm font-medium">共享会话</h3>
        {!canSteer && <Badge variant="outline">只读</Badge>}
        <label className="sr-only" htmlFor="team-session-select">
          选择共享会话
        </label>
        <select
          id="team-session-select"
          className="ml-auto min-h-8 max-w-full rounded-md border bg-background px-2 text-sm"
          value={sessionID}
          onChange={(event) => setSessionID(event.target.value)}
          disabled={!sessions.length}
        >
          {!sessions.length && <option value="">暂无共享会话</option>}
          {sessions.map((item) => (
            <option key={item.id} value={item.id}>
              {item.title || item.id}
            </option>
          ))}
        </select>
      </div>
      {error && (
        <p role="alert" className="text-xs text-destructive">
          会话列表读取失败：{error}
        </p>
      )}
      {session ? (
        <TeamSessionMessages team={team} taskId={taskId} session={session} canSteer={canSteer} />
      ) : (
        <p className="text-sm text-muted-foreground">当前任务还没有可查看的共享会话。</p>
      )}
    </section>
  );
}

export function TeamSessionMessages({
  team,
  taskId,
  session,
  canSteer = true,
}: {
  team: string;
  taskId: string;
  session: TeamSession;
  canSteer?: boolean;
}) {
  const [messages, setMessages] = React.useState<TeamSessionMessage[]>([]);
  const [hasMore, setHasMore] = React.useState(false);
  const [loadingOlder, setLoadingOlder] = React.useState(false);
  const [loading, setLoading] = React.useState(true);
  const [loadError, setLoadError] = React.useState("");
  const [sendError, setSendError] = React.useState("");
  const [draft, setDraft] = React.useState("");
  const [requestID, setRequestID] = React.useState("");
  const [sending, setSending] = React.useState(false);
  const [notice, setNotice] = React.useState("");
  const requestScope = React.useRef(0);
  const activeStreamKey = React.useRef("");
  const latestCursor = React.useRef(0);
  const messageScroller = React.useRef<HTMLDivElement>(null);
  const followLatest = React.useRef(true);
  const restoreScroll = React.useRef<{ height: number; top: number; follow: boolean } | null>(null);
  const sessionID = session.id;
  const assignmentID = session.assignment_id;
  const epoch = session.epoch;
  const streamKey = `${team}:${taskId}:${sessionID}:${assignmentID}:${epoch}`;

  React.useEffect(() => {
    const scope = ++requestScope.current;
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    let hasLoadedSnapshot = false;
    const reset = () => {
      setMessages([]);
      setHasMore(false);
      setLoadingOlder(false);
      setLoading(true);
      setLoadError("");
      setSendError("");
      setDraft("");
      setRequestID("");
      setSending(false);
      setNotice("");
      latestCursor.current = 0;
      followLatest.current = true;
      restoreScroll.current = null;
    };
    if (activeStreamKey.current !== streamKey) {
      activeStreamKey.current = streamKey;
      reset();
    }
    const loadLatest = async () => {
      try {
        if (!hasLoadedSnapshot) {
          const page = await api.teamSessionMessages(team, taskId, sessionID, 0, PAGE_SIZE);
          if (!alive || scope !== requestScope.current) return;
          setMessages((current) => mergeMessages(current, page.items));
          setHasMore(page.hasMore);
          latestCursor.current = page.items.at(-1)?.id ?? 0;
          hasLoadedSnapshot = true;
        } else {
          const afterCursor = latestCursor.current;
          // Refresh the newest page so pending/delivered guidance states can advance.
          const latest = await api.teamSessionMessages(team, taskId, sessionID, 0, PAGE_SIZE);
          if (!alive || scope !== requestScope.current) return;
          setMessages((current) => mergeMessages(current, latest.items));

          // Recover every message missed while offline, even when the gap is larger
          // than one page. `after` is ascending and has_more means another page exists.
          let cursor = afterCursor;
          let page = await api.teamSessionMessagesAfter(team, taskId, sessionID, cursor, PAGE_SIZE);
          while (alive && scope === requestScope.current) {
            if (page.items.length) {
              setMessages((current) => mergeMessages(current, page.items));
              cursor = Math.max(cursor, page.items.at(-1)?.id ?? cursor);
            }
            if (!page.hasMore || !page.items.length || cursor <= afterCursor) break;
            page = await api.teamSessionMessagesAfter(team, taskId, sessionID, cursor, PAGE_SIZE);
          }
          if (alive && scope === requestScope.current) latestCursor.current = Math.max(latestCursor.current, cursor);
        }
        if (!alive || scope !== requestScope.current) return;
        setLoadError("");
      } catch (e) {
        if (alive && scope === requestScope.current) setLoadError((e as Error).message);
      } finally {
        if (alive && scope === requestScope.current) {
          setLoading(false);
          timer = setTimeout(loadLatest, 2000);
        }
      }
    };
    void loadLatest();
    return () => {
      alive = false;
      clearTimeout(timer);
      requestScope.current += 1;
    };
  }, [team, taskId, sessionID, streamKey]);

  React.useLayoutEffect(() => {
    const element = messageScroller.current;
    if (!element) return;
    const hasMessages = messages.length > 0;
    const restore = restoreScroll.current;
    if (restore) {
      element.scrollTop = restore.top + element.scrollHeight - restore.height;
      followLatest.current = restore.follow;
      restoreScroll.current = null;
    } else if (followLatest.current && hasMessages) {
      element.scrollTop = element.scrollHeight;
    }
  }, [messages]);

  async function loadOlder() {
    if (loadingOlder || !hasMore || !messages.length) return;
    const scope = requestScope.current;
    setLoadingOlder(true);
    try {
      const page = await api.teamSessionMessages(team, taskId, sessionID, messages[0].id, PAGE_SIZE);
      if (scope !== requestScope.current) return;
      const element = messageScroller.current;
      if (element) {
        restoreScroll.current = {
          height: element.scrollHeight,
          top: element.scrollTop,
          follow: followLatest.current,
        };
      }
      setMessages((current) => {
        return mergeMessages(page.items, current);
      });
      setHasMore(page.hasMore);
    } catch (e) {
      if (scope === requestScope.current) setLoadError((e as Error).message);
    } finally {
      if (scope === requestScope.current) setLoadingOlder(false);
    }
  }

  async function send() {
    const message = draft.trim();
    if (!message || !canSend || sending) return;
    const id = requestID || newRequestID();
    const scope = requestScope.current;
    if (!requestID) setRequestID(id);
    setSending(true);
    setNotice("");
    try {
      const intentID = Number(session.id.startsWith("intent:") ? session.id.slice(7) : 0);
      const result = await api.sendTeamSessionMessage(team, taskId, {
        intent_id: intentID,
        assignment_id: assignmentID,
        epoch,
        request_id: id,
        message,
      });
      if (scope !== requestScope.current) return;
      setDraft("");
      setRequestID("");
      setSendError("");
      followLatest.current = true;
      const element = messageScroller.current;
      if (element) element.scrollTop = element.scrollHeight;
      setNotice(
        result.status === "steering"
          ? "消息已交付执行端，实际执行效果待后续消息确认。"
          : "消息已接受，等待交付到执行端。",
      );
    } catch (e) {
      // Keep both the draft and request ID so retry remains idempotent.
      if (scope !== requestScope.current) return;
      setSendError(`发送失败，可重试：${(e as Error).message}`);
    } finally {
      if (scope === requestScope.current) setSending(false);
    }
  }

  const canSend = canSteer && session.can_message;
  const reason = !canSteer ? "当前账号只有查看权限，不能发送引导。" : (session.reason ?? "此会话当前不可发送引导。");
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2 text-xs text-muted-foreground">
        <span>{session.executor_id === 0 ? "执行端：本机" : `执行端：设备 #${session.executor_id}`}</span>
        <span>{session.state}</span>
      </div>
      {hasMore && (
        <Button type="button" variant="ghost" size="sm" disabled={loadingOlder} onClick={() => void loadOlder()}>
          {loadingOlder ? <Loader2Icon className="animate-spin" /> : <RotateCwIcon />}
          加载更早消息
        </Button>
      )}
      <div
        ref={messageScroller}
        onScroll={(event) => {
          const element = event.currentTarget;
          followLatest.current = element.scrollHeight - element.scrollTop - element.clientHeight <= 32;
        }}
        className="max-h-72 min-h-24 space-y-2 overflow-y-auto rounded-md bg-muted/30 p-2"
        aria-live="polite"
      >
        {loading && !messages.length && <p className="text-xs text-muted-foreground">正在读取消息…</p>}
        {!loading && !messages.length && <p className="text-xs text-muted-foreground">还没有共享消息。</p>}
        {messages.map((message) => (
          <article key={message.id} className="rounded-md border bg-background p-2 text-sm">
            <div className="mb-1 flex flex-wrap items-center gap-2 text-[10px] text-muted-foreground">
              <span>{senderLabel(message, sessionID)}</span>
              <time>{message.created_at ? new Date(message.created_at).toLocaleString() : ""}</time>
              {message.guidance_status && (
                <Badge variant="outline" className="h-4 px-1 text-[9px]">
                  {guidanceStatusLabel(message.guidance_status)}
                </Badge>
              )}
            </div>
            <p className="whitespace-pre-wrap break-words">{message.text}</p>
          </article>
        ))}
      </div>
      {loadError && (
        <p role="alert" className="text-xs text-destructive">
          消息读取失败：{loadError}
        </p>
      )}
      {sendError && (
        <p role="alert" className="text-xs text-destructive">
          {sendError}
        </p>
      )}
      {notice && (
        <p role="status" className="text-xs text-muted-foreground">
          {notice}
        </p>
      )}
      {!canSend && <p className="text-xs text-muted-foreground">{reason}</p>}
      <div className="flex items-end gap-2">
        <Textarea
          aria-label="发送共享会话消息"
          placeholder={canSend ? "输入消息，调整执行方向…" : reason}
          value={draft}
          onChange={(event) => {
            if (event.target.value !== draft) {
              setRequestID("");
              setSendError("");
            }
            setDraft(event.target.value);
            setNotice("");
          }}
          onKeyDown={(event) => {
            if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
              event.preventDefault();
              void send();
            }
          }}
          disabled={!canSend || sending}
          rows={2}
          className="min-h-16 max-h-36 resize-y text-sm"
        />
        <Button
          type="button"
          size="icon"
          aria-label="发送消息"
          title="发送消息"
          disabled={!canSend || sending || !draft.trim()}
          onClick={() => void send()}
        >
          {sending ? <Loader2Icon className="animate-spin" /> : <ArrowUpIcon />}
        </Button>
      </div>
      <p className="text-[10px] text-muted-foreground">Ctrl/⌘ + Enter 发送</p>
    </div>
  );
}
