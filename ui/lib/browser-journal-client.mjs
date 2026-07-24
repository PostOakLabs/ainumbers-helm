// Main-thread orchestrator for the browser journal (P3-D7, HELM-P3-U2).
// Wires the tested primitives (browser-journal.mjs, durability-banner.mjs)
// to real browser globals: the dedicated worker, Web Locks, Storage Manager,
// and pagehide/pageshow (BFCache). Every global is a constructor parameter
// so production code is the only caller that ever supplies the real ones —
// same injection discipline as handoff.mjs.
import { electWriterRole } from "./browser-journal.mjs";
import { bannerFor, renderBannerHtml } from "./durability-banner.mjs";

let rpcId = 0;
function rpc(worker, type, payload) {
  return new Promise((resolve, reject) => {
    const id = ++rpcId;
    const onMessage = (ev) => {
      if (ev.data.id !== id) return;
      worker.removeEventListener("message", onMessage);
      if (ev.data.ok) resolve(ev.data.result);
      else reject(new Error(ev.data.error));
    };
    worker.addEventListener("message", onMessage);
    worker.postMessage({ id, type, payload });
  });
}

export class BrowserJournalClient {
  constructor({
    createWorker = () => new Worker(new URL("./journal-worker.mjs", import.meta.url), { type: "module" }),
    locksApi = navigator.locks,
    storageManager = navigator.storage,
    onBannerChange = () => {},
    onOfferBundleDownload = () => {},
  } = {}) {
    this.createWorker = createWorker;
    this.locksApi = locksApi;
    this.storageManager = storageManager;
    this.onBannerChange = onBannerChange;
    this.onOfferBundleDownload = onOfferBundleDownload;
    this.worker = null;
    this.writerRole = "reader";
    this.release = () => {};
    this.entries = [];
  }

  async start() {
    const opfsSupported = typeof navigator !== "undefined" && !!navigator.storage?.getDirectory && typeof Worker !== "undefined";
    if (!opfsSupported) {
      this.onBannerChange(renderBannerHtml(bannerFor({ writerRole: "reader", durable: false })));
      return { entries: [], truncated: false };
    }

    const { role, release } = await electWriterRole(this.locksApi);
    this.writerRole = role;
    this.release = release;

    let durable = false;
    if (role === "writer") {
      try {
        durable = await this.storageManager.persisted();
      } catch {
        durable = false;
      }
    }
    this.onBannerChange(renderBannerHtml(bannerFor({ writerRole: role, durable })));

    if (role !== "writer") return { entries: [], truncated: false };

    this.worker = this.createWorker();
    const opened = await rpc(this.worker, "init", {});
    this.entries = opened.entries;
    this._wireLifecycle();
    return opened;
  }

  _wireLifecycle() {
    // Release the writer lock (and the worker's OPFS handle) on pagehide so a
    // backgrounded/BFCached tab never holds the write lock indefinitely; a
    // fresh election runs on pageshow (BFCache restore re-runs boot() in the
    // app, which calls start() again).
    addEventListener("pagehide", () => {
      this.worker?.postMessage({ id: 0, type: "close", payload: {} });
      this.release();
    });
  }

  async append(entry) {
    if (this.writerRole !== "writer" || !this.worker) {
      throw new Error("browser-journal-client: cannot append from a read-only tab");
    }
    const result = await rpc(this.worker, "append", { entry });
    this.entries.push(entry);
    // P3-D7: auto-offer the anchored bundle download after every run — OPFS
    // is a cache, this offer is the real archive. Bundle *contents* (offline
    // verifier embed, anchoring) are owned by P3-A5/V9; this hook is where
    // that bundle gets built once those land.
    this.onOfferBundleDownload(this.entries);
    return result;
  }
}

// Builds and triggers a same-tab download of a JSON snapshot of journal
// entries — the minimal honest "real archive" until P3-A5/V9 wire the
// anchored, verifier-embedded bundle.zip through this same hook.
export function offerJsonBundleDownload(entries, filename = `helm-journal-${Date.now()}.json`) {
  const blob = new Blob([JSON.stringify(entries, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
