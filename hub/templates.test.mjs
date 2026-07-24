// HELM-P3-G10: template gallery — curated scenarios over compiled packs,
// pre-wired sample data, deep-linkable one-click run.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request } from "node:http";
import { TEMPLATES, listTemplates, getTemplate, buildTemplateManifest } from "./templates.mjs";
import { getPack } from "./packs.mjs";

test("every template points at a workflow_id that's actually in the compiled catalog", () => {
  for (const t of TEMPLATES) {
    assert.ok(getPack(t.workflow_id), `template ${t.slug} references unknown pack ${t.workflow_id}`);
  }
});

test("there are at least 5 templates (G10 done-criterion)", () => {
  assert.ok(TEMPLATES.length >= 5, `expected >=5 templates, got ${TEMPLATES.length}`);
});

test("listTemplates() exposes slug/title/blurb/workflow_id, nothing else", () => {
  const list = listTemplates();
  assert.equal(list.length, TEMPLATES.length);
  for (const t of list) {
    assert.deepEqual(Object.keys(t).sort(), ["blurb", "slug", "title", "workflow_id"]);
  }
});

test("getTemplate() returns null for an unknown slug", () => {
  assert.equal(getTemplate("does-not-exist"), null);
});

test("buildTemplateManifest() stamps sample policy_parameters onto every node", () => {
  const template = getTemplate("emir-field-check");
  const manifest = buildTemplateManifest(template);
  assert.ok(manifest);
  for (const node of manifest.nodes) {
    assert.deepEqual(node.policy_parameters, template.sample_data[node.node_id]);
  }
  // The pack on disk is untouched — templates never mutate packs/.
  const pack = getPack(template.workflow_id);
  assert.ok(pack.manifest.nodes.every((n) => n.policy_parameters === undefined));
});

const TMP = mkdtempSync(join(tmpdir(), "helm-templates-test-"));
process.env.HELM_HOME = TMP;

const PORT = 42098;
const ORIGIN = "null";

writeFileSync(join(TMP, "config.json"), JSON.stringify({ port: PORT, allowedOrigin: ORIGIN }));

const { loadConfig } = await import("./config.mjs");
const { loadOrCreateToken } = await import("./token.mjs");
const { openJournal } = await import("./journal.mjs");
const { createHelmServer } = await import("./server.mjs");

const config = loadConfig();
const token = loadOrCreateToken();
const db = openJournal(join(TMP, "journal.db"));
let server;

before(() => {
  server = createHelmServer({ port: config.port, allowedOrigin: config.allowedOrigin, token, db });
});

after(() => {
  server.close();
  db.close();
  rmSync(TMP, { recursive: true, force: true });
});

function headers(overrides = {}) {
  return { Host: `127.0.0.1:${PORT}`, Origin: ORIGIN, Authorization: `Bearer ${token}`, ...overrides };
}

function get(path, hdrs) {
  return new Promise((resolve, reject) => {
    const req = request({ host: "127.0.0.1", port: PORT, path, method: "GET", headers: hdrs }, (res) => {
      let body = "";
      res.on("data", (c) => (body += c));
      res.on("end", () => resolve({ status: res.statusCode, body }));
    });
    req.on("error", reject);
    req.end();
  });
}

function post(path, body, hdrs) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = request(
      { host: "127.0.0.1", port: PORT, path, method: "POST", headers: { ...hdrs, "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) } },
      (res) => {
        let resBody = "";
        res.on("data", (c) => (resBody += c));
        res.on("end", () => resolve({ status: res.statusCode, body: resBody }));
      }
    );
    req.on("error", reject);
    req.end(data);
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

test("GET /templates lists the gallery", async () => {
  const res = await get("/templates", headers());
  assert.equal(res.status, 200);
  const { templates } = JSON.parse(res.body);
  assert.ok(templates.length >= 5);
  assert.ok(templates.some((t) => t.slug === "emir-field-check"));
});

test("GET /templates/:slug returns a runnable manifest with sample data baked in", async () => {
  const res = await get("/templates/emir-field-check", headers());
  assert.equal(res.status, 200);
  const detail = JSON.parse(res.body);
  assert.equal(detail.workflow_id, "pack-emir-trade-report-validation");
  assert.ok(detail.title);
  assert.ok(Array.isArray(detail.manifest.nodes) && detail.manifest.nodes.length > 0);
  assert.ok(detail.manifest.nodes.every((n) => n.policy_parameters !== undefined));
});

test("GET /templates/:slug 404s for an unknown slug", async () => {
  const res = await get("/templates/does-not-exist", headers());
  assert.equal(res.status, 404);
});

test("POST /run/start with template_slug runs end to end using the template's sample data", async () => {
  const startRes = await post("/run/start", { template_slug: "emir-field-check", dry_run: true }, headers());
  assert.equal(startRes.status, 200);
  const { run_id: runId, state } = JSON.parse(startRes.body);
  assert.ok(runId);
  assert.equal(state, "queued");

  let steps = [];
  for (let i = 0; i < 20; i++) {
    const timelineRes = await get(`/run/timeline?run_id=${runId}`, headers());
    steps = JSON.parse(timelineRes.body).steps;
    if (steps.some((s) => s.state === "completed")) break;
    await sleep(25);
  }
  assert.ok(steps.some((s) => s.state === "completed"), `expected a completed transition, got: ${steps.map((s) => s.state).join(",")}`);
});

test("POST /run/start with an unknown template_slug 404s", async () => {
  const res = await post("/run/start", { template_slug: "does-not-exist", dry_run: true }, headers());
  assert.equal(res.status, 404);
});
