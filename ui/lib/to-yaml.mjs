// Minimal JSON->YAML for display only (Canvas manifest side-by-side view).
// Not a general YAML emitter — handles the plain object/array/scalar shapes
// that come out of workflow-manifest JSON. Pure, DOM-free, unit-testable.
function scalar(v) {
  if (v === null) return "null";
  if (typeof v === "string") return /[:#\[\]{}\-\n]|^\s|\s$|^$/.test(v) ? JSON.stringify(v) : v;
  return String(v);
}

export function toYaml(v, indent = 0) {
  const pad = "  ".repeat(indent);
  if (Array.isArray(v)) {
    if (v.length === 0) return `${pad}[]\n`;
    return v
      .map((item) => {
        if (item && typeof item === "object") {
          const body = toYaml(item, indent + 1).replace(new RegExp(`^${"  ".repeat(indent + 1)}`), `${pad}- `);
          return body;
        }
        return `${pad}- ${scalar(item)}\n`;
      })
      .join("");
  }
  if (v && typeof v === "object") {
    const keys = Object.keys(v);
    if (keys.length === 0) return `${pad}{}\n`;
    return keys
      .map((k) => {
        const val = v[k];
        if (val && typeof val === "object" && Object.keys(val).length > 0) {
          return `${pad}${k}:\n${toYaml(val, indent + 1)}`;
        }
        if (Array.isArray(val) && val.length === 0) return `${pad}${k}: []\n`;
        if (val && typeof val === "object") return `${pad}${k}: {}\n`;
        return `${pad}${k}: ${scalar(val)}\n`;
      })
      .join("");
  }
  return `${pad}${scalar(v)}\n`;
}
