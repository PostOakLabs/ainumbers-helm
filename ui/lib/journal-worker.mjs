// Dedicated worker: sole owner of the OPFS journal file (P3-D7). OPFS itself
// refuses a second createSyncAccessHandle on the same path while one is open,
// so routing every read/write through this one worker (never the main thread
// or any other worker) is what makes "one dedicated worker owns OPFS" true by
// construction, not by convention. Browser-only — no node:test coverage here;
// BrowserJournal (browser-journal.mjs) carries the tested framing/scan logic,
// this file is a thin postMessage shim around it.
import { BrowserJournal } from "./browser-journal.mjs";

const FILE_NAME = "helm-journal.bin";
let journal = null;

async function openHandle() {
  const root = await navigator.storage.getDirectory();
  const fileHandle = await root.getFileHandle(FILE_NAME, { create: true });
  const accessHandle = await fileHandle.createSyncAccessHandle();
  return accessHandle;
}

self.onmessage = async (ev) => {
  const { id, type, payload } = ev.data;
  try {
    if (type === "init") {
      const handle = await openHandle();
      journal = new BrowserJournal(handle);
      const { entries, truncated } = await journal.open();
      self.postMessage({ id, ok: true, result: { entries, truncated } });
      return;
    }
    if (type === "append") {
      if (!journal) throw new Error("journal-worker: append before init");
      const result = await journal.append(payload.entry);
      self.postMessage({ id, ok: true, result });
      return;
    }
    if (type === "close") {
      journal?.close();
      journal = null;
      self.postMessage({ id, ok: true, result: null });
      return;
    }
    throw new Error(`journal-worker: unknown message type "${type}"`);
  } catch (err) {
    self.postMessage({ id, ok: false, error: String(err?.message || err) });
  }
};
