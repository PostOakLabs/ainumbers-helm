// Structured JSON-lines logger. One object per line: ts, level, msg, ...fields.
function emit(level, msg, fields) {
  const line = { ts: new Date().toISOString(), level, msg, ...fields };
  const out = level === "error" ? process.stderr : process.stdout;
  out.write(JSON.stringify(line) + "\n");
}

export const log = {
  info: (msg, fields) => emit("info", msg, fields),
  warn: (msg, fields) => emit("warn", msg, fields),
  error: (msg, fields) => emit("error", msg, fields),
};
