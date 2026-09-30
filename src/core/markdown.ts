/**
 * Split Markdown into the regions an agent reads differently from a human: frontmatter (always
 * in the agent's context), prose, fenced code (often executed as written), inline code, and
 * hidden regions (HTML comments, comment-style link definitions, CSS-hidden elements) that a
 * rendered view never shows but the model reads verbatim.
 */

export type RegionKind = "frontmatter" | "prose" | "code" | "inline-code" | "hidden";

export interface Region {
  readonly kind: RegionKind;
  readonly start: number;
  readonly end: number;
  /** Fence info string for code regions, e.g. `bash`. */
  readonly lang?: string;
  /** For hidden regions: what hides it. */
  readonly via?: "html-comment" | "link-definition" | "hidden-element";
}

const FENCE_RE = /^ {0,3}(`{3,}|~{3,})\s*([^`\s]*)[^\n]*$/;
const LINK_COMMENT_RE = /^ {0,3}\[[^\]\n]*\]:\s*(?:#|<>|\/\/)\s+(?:"[^"\n]*"|'[^'\n]*'|\([^)\n]*\))\s*$/gm;
const HIDDEN_ELEMENT_RE =
  /<(div|span|p|section|small|font)\b[^>]*?(?:\bhidden\b|display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0(?:\.0+)?\b)[^>]*>[\s\S]*?<\/\1\s*>/gi;

export function segmentMarkdown(text: string, frontmatterEnd = 0): Region[] {
  const regions: Region[] = [];
  if (frontmatterEnd > 0) regions.push({ kind: "frontmatter", start: 0, end: frontmatterEnd });

  // Fenced code blocks, line by line.
  const code: Region[] = [];
  let offset = 0;
  let open: { marker: string; lang: string; contentStart: number } | undefined;
  for (const line of text.split("\n")) {
    const lineEnd = offset + line.length;
    if (offset >= frontmatterEnd) {
      const m = FENCE_RE.exec(line.replace(/\r$/, ""));
      if (open) {
        if (m && m[1]![0] === open.marker[0] && m[1]!.length >= open.marker.length && m[2] === "") {
          code.push({ kind: "code", start: open.contentStart, end: offset, lang: open.lang });
          open = undefined;
        }
      } else if (m) {
        open = { marker: m[1]!, lang: (m[2] ?? "").toLowerCase(), contentStart: Math.min(lineEnd + 1, text.length) };
      }
    }
    offset = lineEnd + 1;
  }
  if (open) code.push({ kind: "code", start: open.contentStart, end: text.length, lang: open.lang });
  regions.push(...code);

  const insideCode = (i: number): boolean => code.some((r) => i >= r.start && i < r.end);
  const outside = (i: number): boolean => i >= frontmatterEnd && !insideCode(i);

  // Inline code spans: a run of N backticks closed by the next run of exactly N on the same line.
  // Found first because, as in CommonMark, a `<!--` inside a code span is literal text, not a comment.
  const spans: Region[] = [];
  for (const m of text.matchAll(/(`+)([^`\n](?:[^\n]*?[^`\n])?)\1(?!`)/g)) {
    if (outside(m.index)) spans.push({ kind: "inline-code", start: m.index, end: m.index + m[0].length });
  }
  const inSpan = (i: number): boolean => spans.some((r) => i > r.start && i < r.end);

  // HTML comments (may span lines).
  for (let i = text.indexOf("<!--", frontmatterEnd); i !== -1; i = text.indexOf("<!--", i + 4)) {
    if (!outside(i) || inSpan(i)) continue;
    const close = text.indexOf("-->", i + 4);
    const end = close === -1 ? text.length : close + 3;
    regions.push({ kind: "hidden", start: i, end, via: "html-comment" });
    i = end - 4;
  }
  for (const m of text.matchAll(LINK_COMMENT_RE)) {
    if (outside(m.index)) regions.push({ kind: "hidden", start: m.index, end: m.index + m[0].length, via: "link-definition" });
  }
  for (const m of text.matchAll(HIDDEN_ELEMENT_RE)) {
    if (outside(m.index) && !inSpan(m.index))
      regions.push({ kind: "hidden", start: m.index, end: m.index + m[0].length, via: "hidden-element" });
  }
  // A code span that starts inside a hidden region is part of what is hidden.
  for (const span of spans) if (!inHidden(regions, span.start)) regions.push(span);
  return regions.sort((a, b) => a.start - b.start || b.end - a.end);
}

const inHidden = (regions: readonly Region[], i: number): boolean => regions.some((r) => r.kind === "hidden" && i >= r.start && i < r.end);

const PRIORITY: Readonly<Record<RegionKind, number>> = { hidden: 4, "inline-code": 3, code: 2, frontmatter: 1, prose: 0 };

/** The region an offset falls in; hidden wins over code, code over prose. */
export function regionAt(regions: readonly Region[], offset: number): Region {
  let best: Region | undefined;
  for (const r of regions) {
    if (r.start > offset) break;
    if (offset < r.end && (!best || PRIORITY[r.kind] > PRIORITY[best.kind])) best = r;
  }
  return best ?? { kind: "prose", start: offset, end: offset };
}
