// Tiny in-process pub/sub for run progress (HELM-P2-U4 Run/SSE wiring).
// One daemon process, one EventEmitter — no cross-process fanout needed
// (loopback-only, single-writer daemon per D8).
import { EventEmitter } from "node:events";

const bus = new EventEmitter();
bus.setMaxListeners(0); // unbounded: cap is enforced by MAX_SSE_CONNECTIONS in server.mjs, not here

// Kernel-compute steps finish in milliseconds — a subscriber that opens
// /events after the POST /run/start round-trip can easily miss every event.
// Remembering the last event per run and replaying it to a fresh subscriber
// means a late connection still sees the run's current (possibly terminal)
// state instead of nothing.
const lastEventByRun = new Map();

export function publishRunEvent(runId, data) {
  lastEventByRun.set(runId, data);
  bus.emit(`run:${runId}`, data);
}

export function subscribeRunEvents(runId, handler) {
  const event = `run:${runId}`;
  bus.on(event, handler);
  const last = lastEventByRun.get(runId);
  if (last) handler(last);
  return () => bus.off(event, handler);
}
