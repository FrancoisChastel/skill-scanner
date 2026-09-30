/** Offset and line bookkeeping shared by rules and reporters. */

export interface LineIndex {
  readonly text: string;
  /** Offset of the first character of each line. */
  readonly starts: readonly number[];
}

export function indexLines(text: string): LineIndex {
  const starts = [0];
  for (let i = 0; i < text.length; i += 1) if (text.charCodeAt(i) === 10) starts.push(i + 1);
  return { text, starts };
}

/** 1-based line and column of an offset. */
export function positionAt(index: LineIndex, offset: number): { line: number; column: number } {
  let lo = 0;
  let hi = index.starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (index.starts[mid]! <= offset) lo = mid;
    else hi = mid - 1;
  }
  return { line: lo + 1, column: offset - index.starts[lo]! + 1 };
}

export function lineText(index: LineIndex, line: number): string {
  const start = index.starts[line - 1];
  if (start === undefined) return "";
  const next = index.starts[line];
  const end = next === undefined ? index.text.length : next - 1;
  return index.text.slice(start, end).replace(/\r$/, "");
}

const MAX_SNIPPET = 160;

/** A single-line, bounded excerpt of the text around a match, with invisible characters made visible. */
export function snippetAt(index: LineIndex, offset: number, length: number): string {
  const { line } = positionAt(index, offset);
  const full = lineText(index, line);
  const lineStart = index.starts[line - 1]!;
  const col = offset - lineStart;
  let text = full;
  if (full.length > MAX_SNIPPET) {
    const from = Math.max(0, Math.min(col - 40, full.length - MAX_SNIPPET));
    text = `${from > 0 ? "\u2026" : ""}${full.slice(from, from + MAX_SNIPPET)}${from + MAX_SNIPPET < full.length ? "\u2026" : ""}`;
  }
  const shown = revealInvisible(text.trim());
  return shown.length > 0 ? shown : revealInvisible(index.text.slice(offset, offset + Math.min(length, MAX_SNIPPET)));
}

/** Replace invisible and control characters with `<U+XXXX>` so reports never smuggle them onward. */
export function revealInvisible(s: string): string {
  let out = "";
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    out += isInvisible(cp) || (cp < 0x20 && cp !== 0x09) || cp === 0x7f ? `<U+${cp.toString(16).toUpperCase().padStart(4, "0")}>` : ch;
  }
  return out;
}

export function isInvisible(cp: number): boolean {
  return (
    (cp >= 0x200b && cp <= 0x200f) ||
    (cp >= 0x202a && cp <= 0x202e) ||
    (cp >= 0x2060 && cp <= 0x2064) ||
    (cp >= 0x2066 && cp <= 0x2069) ||
    cp === 0xfeff ||
    cp === 0x00ad ||
    cp === 0x180e ||
    cp === 0x034f ||
    cp === 0x115f ||
    cp === 0x1160 ||
    cp === 0x3164 ||
    cp === 0xffa0 ||
    (cp >= 0xfe00 && cp <= 0xfe0f) ||
    (cp >= 0xe0000 && cp <= 0xe007f) ||
    (cp >= 0xe0100 && cp <= 0xe01ef)
  );
}

export function clip(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n - 1)}\u2026` : s;
}
