import assert from "node:assert/strict";
import test from "node:test";
import { openActivityStream } from "./activity-stream.ts";

function fixture(t, extra = {}) {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const sources = [], states = [], rows = [];
  const stream = openActivityStream({
    url: (cursor) => `/events?since=${cursor}`,
    cursor: 10,
    onActivity: (row) => rows.push(row),
    onState: (state) => states.push(state),
    createSource(url) {
      const s = { url, listeners: {}, closed: false, close() { this.closed = true; }, addEventListener(k, fn) { this.listeners[k] = fn; } };
      sources.push(s);
      return s;
    },
    ...extra,
  });
  t.after(() => stream.close());
  return { stream, sources, states, rows };
}

test("failed/closed transport is recreated and resumes at the last delivered cursor", (t) => {
  const f = fixture(t);
  f.sources[0].onopen();
  f.sources[0].onmessage({ data: '{"seq":11}' });
  f.sources[0].onerror();
  assert.equal(f.sources[0].closed, true);
  assert.equal(f.states.at(-1), "reconnecting");
  t.mock.timers.tick(1000);
  assert.equal(f.sources[1].url, "/events?since=11");
  f.sources[1].onmessage({ data: '{"seq":11}' });
  f.sources[1].onmessage({ data: '{"seq":12}' });
  assert.deepEqual(f.rows.map((row) => row.seq), [11, 12]);
});

test("idle heartbeats keep the connection live without changing the activity cursor", (t) => {
  const f = fixture(t);
  f.sources[0].onopen();
  t.mock.timers.tick(40_000);
  f.sources[0].listeners.heartbeat();
  t.mock.timers.tick(40_000);
  assert.equal(f.sources.length, 1);
  assert.deepEqual(f.rows, []);
  f.stream.reconnect();
  assert.equal(f.sources[1].url, "/events?since=10");
});

test("silent half-open stream is closed and automatically recovered", (t) => {
  const f = fixture(t);
  f.sources[0].onopen();
  t.mock.timers.tick(50_000);
  assert.equal(f.sources[0].closed, true);
  t.mock.timers.tick(1000);
  assert.equal(f.sources.length, 2);
});

test("constructor failures retry; unmount stops retries and ignores stale callbacks", (t) => {
  let attempts = 0;
  const f = fixture(t, { createSource() { attempts++; throw new Error("offline"); } });
  assert.equal(f.states.at(-1), "reconnecting");
  t.mock.timers.tick(1000);
  assert.equal(attempts, 2);
  f.stream.close();
  t.mock.timers.tick(60_000);
  assert.equal(attempts, 2);
});

test("callbacks from a replaced connection cannot regress state or deliver stale frames", (t) => {
  const f = fixture(t);
  f.stream.reconnect();
  f.sources[1].onopen();
  f.sources[0].onerror();
  f.sources[0].onmessage({ data: '{"seq":99}' });
  assert.equal(f.states.at(-1), "live");
  assert.deepEqual(f.rows, []);
});
