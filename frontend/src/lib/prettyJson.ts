/**
 * Re-indent a JSON document for humans WITHOUT re-serialising its values.
 *
 * JSON.parse → JSON.stringify would silently rewrite number literals (large
 * integers, 1.0 → 1, exponent forms) and string escapes. Exported BOMs are
 * evidence, so only insignificant whitespace is changed here: every string,
 * number, literal and key order is copied through byte-for-byte.
 *
 * Returns null when the input is not valid JSON (the caller keeps the
 * original bytes) or is already multi-line.
 */
export function prettyJson(text: string, indent = 2): string | null {
  const src = text.replace(/^\uFEFF/, "");
  try { JSON.parse(src); } catch { return null; }
  const trimmed = src.trim();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return null;
  // already formatted: leave it exactly as served
  if (/\n\s+["{\[\]}]/.test(trimmed)) return null;

  const pad = " ".repeat(indent);
  let out = "";
  let depth = 0;
  let inString = false;
  for (let i = 0; i < trimmed.length; i++) {
    const ch = trimmed[i];
    if (inString) {
      out += ch;
      if (ch === "\\") { out += trimmed[++i] ?? ""; continue; }
      if (ch === "\"") inString = false;
      continue;
    }
    switch (ch) {
      case "\"": inString = true; out += ch; break;
      case "{": case "[": {
        // keep empty containers compact: {} and []
        let j = i + 1;
        while (j < trimmed.length && /\s/.test(trimmed[j])) j++;
        const close = ch === "{" ? "}" : "]";
        if (trimmed[j] === close) { out += ch + close; i = j; break; }
        depth++;
        out += ch + "\n" + pad.repeat(depth);
        break;
      }
      case "}": case "]":
        depth--;
        out += "\n" + pad.repeat(depth) + ch;
        break;
      case ",": out += ",\n" + pad.repeat(depth); break;
      case ":": out += ": "; break;
      case " ": case "\t": case "\n": case "\r": break; // insignificant whitespace
      default: out += ch;
    }
  }
  return out + "\n";
}

/** Indent a downloaded blob when (and only when) it is a JSON document. */
export async function readableJsonBlob(blob: Blob): Promise<Blob> {
  try {
    if (blob.size === 0 || blob.size > 64 * 1024 * 1024 || typeof blob.text !== "function") return blob;
    if (/zip|pdf|octet-stream|csv|markdown|html|ndjson|jsonl/i.test(blob.type || "")) return blob;
    const head = (await blob.slice(0, 64).text()).replace(/^\uFEFF/, "").trimStart();
    if (!head.startsWith("{") && !head.startsWith("[")) return blob;
    const formatted = prettyJson(await blob.text());
    return formatted === null ? blob : new Blob([formatted], { type: blob.type || "application/json" });
  } catch { return blob; }
}
