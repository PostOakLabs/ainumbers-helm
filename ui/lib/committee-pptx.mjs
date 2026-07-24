// Committee deck .pptx renderer (HELM-P4-A2). Turns a buildCommitteeDeckSpec()
// data object into a downloadable .pptx Blob using the vendored PptxGenJS
// UMD bundle (ui/vendored/pptxgen.bundle.js, MIT, see PORT.md). Browser-only
// (canvas rasterization + a lazily-injected <script> global) — the DOM-free
// slide *content* decisions live in committee-deck.mjs, not here.
//
// Macro-free by construction: PptxGenJS has no VBA/OLE/DDE authoring surface,
// only produces plain OOXML, and this module only ever calls addImage() with
// a `data:` URI it rasterized itself — never a remote `path` — so building a
// deck makes zero network requests (bank DLP passes plain OOXML with no
// embedded macros or external references).
let pptxGenJsLoad;
function loadPptxGenJs() {
  if (window.PptxGenJS) return Promise.resolve(window.PptxGenJS);
  if (pptxGenJsLoad) return pptxGenJsLoad;
  pptxGenJsLoad = new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = new URL("../vendored/pptxgen.bundle.js", import.meta.url).href;
    s.onload = () => (window.PptxGenJS ? resolve(window.PptxGenJS) : reject(new Error("PptxGenJS did not attach to window")));
    s.onerror = () => reject(new Error("failed to load vendored pptxgen.bundle.js"));
    document.head.appendChild(s);
  });
  return pptxGenJsLoad;
}

// Rasterizes an SVG string to a PNG data: URI via an off-screen canvas — the
// only way to embed a diagram pptxgenjs (and PowerPoint's OOXML image part)
// can render reliably, since raw <svg> in a slide has patchy PowerPoint
// support. No network access: the source is a data: URI SVG, decoded
// entirely by the browser's own image decoder.
function svgToPngDataUri(svg, width, height) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement("canvas");
      const scale = 2; // 2x for legible text when projected
      canvas.width = width * scale;
      canvas.height = height * scale;
      const ctx = canvas.getContext("2d");
      ctx.fillStyle = "#fff";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.scale(scale, scale);
      ctx.drawImage(img, 0, 0, width, height);
      resolve(canvas.toDataURL("image/png"));
    };
    img.onerror = () => reject(new Error("could not rasterize process-map SVG"));
    img.src = `data:image/svg+xml;base64,${btoa(unescape(encodeURIComponent(svg)))}`;
  });
}

function viewBoxSize(svg) {
  const m = svg.match(/viewBox="0 0 ([\d.]+) ([\d.]+)"/);
  return m ? { width: Number(m[1]), height: Number(m[2]) } : { width: 800, height: 400 };
}

const TITLE_SLIDE_BG = "FFFFFF";

function addTitleSlide(pptx, title) {
  const slide = pptx.addSlide();
  slide.background = { color: TITLE_SLIDE_BG };
  slide.addText("Committee Pack", { x: 0.5, y: 0.5, w: 9, h: 0.8, fontSize: 28, bold: true });
  const rows = [
    ["Entity", title.entity, "Period", title.period],
    ["Preparer", title.preparer, "Date", title.generatedAt],
  ];
  slide.addTable(rows, { x: 0.5, y: 1.5, w: 9, fontSize: 12, border: { type: "solid", color: "CCCCCC", pt: 0.5 } });
  slide.addText(`Version / digest: ${title.versionDigest}`, { x: 0.5, y: 2.6, w: 9, h: 0.4, fontSize: 10, color: "666666" });
}

async function addProcessMapSlide(pptx, processMap) {
  const slide = pptx.addSlide();
  slide.addText("Process map", { x: 0.5, y: 0.3, w: 9, h: 0.5, fontSize: 20, bold: true });
  if (!processMap.available) {
    slide.addText(processMap.note, { x: 0.5, y: 1.2, w: 9, h: 1, fontSize: 12, italic: true, color: "888888" });
    return;
  }
  const { width, height } = viewBoxSize(processMap.svg);
  const png = await svgToPngDataUri(processMap.svg, width, height);
  const slideW = 9;
  const slideH = Math.min(5.5, slideW * (height / width));
  slide.addImage({ data: png, x: 0.5, y: 1, w: slideW, h: slideH });
}

function addDecisionTableSlide(pptx, decisionTable) {
  const slide = pptx.addSlide();
  slide.addText("Decision table", { x: 0.5, y: 0.3, w: 9, h: 0.5, fontSize: 20, bold: true });
  const headerRow = decisionTable.headers.map((h) => ({ text: h, options: { bold: true, fill: "F0F0F0" } }));
  const rows = decisionTable.rows.length ? decisionTable.rows : [["—", "—", "—", "no steps recorded"]];
  // autoPage: true spills onto additional slides (re-drawing the header row)
  // when the decision table has more steps than one slide fits — no manual
  // pagination math needed.
  slide.addTable([headerRow, ...rows], {
    x: 0.5,
    y: 1,
    w: 9,
    fontSize: 10,
    border: { type: "solid", color: "CCCCCC", pt: 0.5 },
    autoPage: true,
    autoPageCharWeight: 0,
  });
}

function addEvidenceStatusSlide(pptx, evidenceStatus) {
  const slide = pptx.addSlide();
  slide.addText("Evidence status", { x: 0.5, y: 0.3, w: 9, h: 0.5, fontSize: 20, bold: true });
  slide.addText(evidenceStatus.overallOk ? "✓ Verifies clean" : "△ Needs review", {
    x: 0.5,
    y: 1,
    w: 9,
    h: 0.6,
    fontSize: 18,
    bold: true,
    color: evidenceStatus.overallOk ? "1A7F37" : "9A6700",
  });
  const headlineText = evidenceStatus.headline.map((h) => `${h.value} ${h.label}`).join("   ·   ");
  slide.addText(headlineText, { x: 0.5, y: 1.7, w: 9, h: 0.5, fontSize: 14 });
  slide.addText(`Run date: ${evidenceStatus.runDate}`, { x: 0.5, y: 2.2, w: 9, h: 0.4, fontSize: 11, color: "666666" });
  const countRows = [
    [{ text: "Trust label", options: { bold: true, fill: "F0F0F0" } }, { text: "Count", options: { bold: true, fill: "F0F0F0" } }],
    ...evidenceStatus.trustCounts.map((c) => [c.label, String(c.n)]),
  ];
  slide.addTable(countRows, { x: 0.5, y: 2.8, w: 9, fontSize: 11, border: { type: "solid", color: "CCCCCC", pt: 0.5 } });
}

export async function buildCommitteeDeckPptxBlob(spec) {
  const PptxGenJS = await loadPptxGenJs();
  const pptx = new PptxGenJS();
  pptx.title = "Committee Pack";
  addTitleSlide(pptx, spec.title);
  await addProcessMapSlide(pptx, spec.processMap);
  addDecisionTableSlide(pptx, spec.decisionTable);
  addEvidenceStatusSlide(pptx, spec.evidenceStatus);
  return pptx.write({ outputType: "blob" });
}
