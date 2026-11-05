export type ActivityStreamState = "connecting" | "live" | "reconnecting";

type StreamSource = Pick<EventSource, "close" | "addEventListener" | "onopen" | "onerror" | "onmessage">;

// Own retries explicitly: EventSource does not retry every failure (CLOSED), and
// a half-open stream can otherwise leave a task stale indefinitely. Recreated
// streams resume from the last delivered activity, never a session-only poll.
export function openActivityStream<T extends { seq: number }>(options: {
  url: (cursor: number) => string;
  cursor: number;
  onActivity: (activity: T) => void;
  onState: (state: ActivityStreamState) => void;
  createSource?: (url: string) => StreamSource;
  heartbeatTimeout?: number;
  retryDelay?: number;
}) {
  let cursor = options.cursor;
  let source: StreamSource | null = null;
  let retry: ReturnType<typeof setTimeout> | undefined;
  let watchdog: ReturnType<typeof setTimeout> | undefined;
  let closed = false;
  let generation = 0;
  let failures = 0;
  const createSource = options.createSource ?? ((url: string) => new EventSource(url));

  function clearTimers() {
    clearTimeout(retry);
    clearTimeout(watchdog);
  }
  function disconnect() {
    generation++;
    source?.close();
    source = null;
    clearTimers();
  }
  function retryLater() {
    if (closed) return;
    disconnect();
    options.onState("reconnecting");
    const delay = Math.min(15_000, (options.retryDelay ?? 1000) * 2 ** Math.min(failures++, 4));
    retry = setTimeout(connect, delay);
  }
  function armWatchdog() {
    clearTimeout(watchdog);
    watchdog = setTimeout(retryLater, options.heartbeatTimeout ?? 50_000);
  }
  function connect() {
    if (closed) return;
    disconnect();
    const current = generation;
    try {
      source = createSource(options.url(cursor));
      const active = () => !closed && current === generation;
      source.onopen = () => {
        if (!active()) return;
        options.onState("live");
        armWatchdog();
      };
      source.addEventListener("heartbeat", () => {
        if (!active()) return;
        failures = 0;
        options.onState("live");
        armWatchdog();
      });
      source.onerror = () => {
        if (active()) retryLater();
      };
      source.onmessage = (event) => {
        if (!active()) return;
        let activity: T;
        try {
          activity = JSON.parse(event.data) as T;
        } catch {
          return;
        }
        if (!Number.isSafeInteger(activity?.seq) || activity.seq <= cursor) return;
        options.onActivity(activity);
        cursor = activity.seq;
        failures = 0;
        options.onState("live");
        armWatchdog();
      };
      // Also bound a connect which never opens or emits an error.
      armWatchdog();
    } catch {
      retryLater();
    }
  }

  options.onState("connecting");
  connect();
  return {
    reconnect() {
      if (!closed) connect();
    },
    close() {
      closed = true;
      disconnect();
    },
  };
}
