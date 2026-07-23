// schema-validator.mjs — zero-dep JSON Schema (draft 2020-12 subset) validator.
// Subset implemented: type, required, properties, additionalProperties, enum,
// const, pattern, minLength, minItems, items, oneOf, $ref to a LOCAL #/$defs
// path (same document only — the Control Plane profile schemas never $ref
// across files, D2 zero-dep discipline). Mirrors the validator shape already
// shipped in the site repo's chaingraph/standard/schema-validate.mjs.

export function validate(schema, data, root = schema, path = "$", errs = []) {
  if (schema.$ref) {
    const def = resolveRef(schema.$ref, root);
    if (!def) { errs.push(`${path}: unresolved $ref ${schema.$ref}`); return errs; }
    return validate(def, data, root, path, errs);
  }
  if (schema.oneOf) {
    const branchErrs = schema.oneOf.map((s) => validate(s, data, root, path, []));
    const passing = branchErrs.filter((e) => e.length === 0).length;
    if (passing !== 1) {
      errs.push(`${path}: matched ${passing} of ${schema.oneOf.length} oneOf branches (need exactly 1)`);
      const closest = branchErrs.reduce((a, b) => (b.length < a.length ? b : a));
      closest.slice(0, 4).forEach((e) => errs.push(`  ↳ ${e}`));
    }
    return errs;
  }
  if (schema.const !== undefined && JSON.stringify(data) !== JSON.stringify(schema.const))
    errs.push(`${path}: expected const ${JSON.stringify(schema.const)}`);
  if (schema.enum && !schema.enum.some((v) => JSON.stringify(v) === JSON.stringify(data)))
    errs.push(`${path}: ${JSON.stringify(data)} not in enum [${schema.enum.join(", ")}]`);
  if (schema.type && !typeOk(schema.type, data)) {
    errs.push(`${path}: expected type ${schema.type}, got ${jsType(data)}`);
    return errs; // further checks assume the type
  }
  if (typeof data === "string") {
    if (schema.pattern && !new RegExp(schema.pattern).test(data))
      errs.push(`${path}: "${trunc(data)}" does not match /${schema.pattern}/`);
    if (schema.minLength != null && data.length < schema.minLength)
      errs.push(`${path}: shorter than minLength ${schema.minLength}`);
  }
  if (Array.isArray(data)) {
    if (schema.minItems != null && data.length < schema.minItems)
      errs.push(`${path}: fewer than minItems ${schema.minItems}`);
    if (schema.items) data.forEach((d, i) => validate(schema.items, d, root, `${path}[${i}]`, errs));
  }
  if (isObj(data)) {
    (schema.required || []).forEach((k) => { if (!(k in data)) errs.push(`${path}: missing required "${k}"`); });
    if (schema.properties)
      for (const [k, s] of Object.entries(schema.properties))
        if (k in data) validate(s, data[k], root, `${path}.${k}`, errs);
    if (schema.additionalProperties === false && schema.properties) {
      const allowed = new Set(Object.keys(schema.properties));
      for (const k of Object.keys(data))
        if (!allowed.has(k)) errs.push(`${path}: additional property "${k}" not allowed (strict)`);
    }
  }
  return errs;
}

function resolveRef(ref, root) {
  if (!ref.startsWith("#/")) return null;
  return ref.slice(2).split("/").reduce((o, seg) => (o ? o[seg] : undefined), root);
}
function typeOk(t, d) {
  if (Array.isArray(t)) return t.some((x) => typeOk(x, d));
  return t === "object" ? isObj(d)
    : t === "null" ? d === null
    : t === "array" ? Array.isArray(d)
    : t === "string" ? typeof d === "string"
    : t === "number" ? typeof d === "number"
    : t === "integer" ? Number.isInteger(d)
    : t === "boolean" ? typeof d === "boolean"
    : true;
}
const isObj = (d) => d !== null && typeof d === "object" && !Array.isArray(d);
const jsType = (d) => (Array.isArray(d) ? "array" : d === null ? "null" : typeof d);
const trunc = (s) => (s.length > 50 ? s.slice(0, 47) + "…" : s);
