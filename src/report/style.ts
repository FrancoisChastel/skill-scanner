import type { Severity, Verdict } from "../core/types";

/**
 * Terminal styling shared by the human-readable outputs: plain ANSI SGR codes, no dependencies, and
 * no escape codes at all when color is off. Source stays ASCII, so glyphs are written as escapes.
 */

const ESC = String.fromCharCode(27);
const MIN_WRAP = 30;

export type Paint = (s: string) => string;

export interface Palette {
  readonly bold: Paint;
  readonly dim: Paint;
  readonly underline: Paint;
  readonly ok: Paint;
  readonly warn: Paint;
  readonly bad: Paint;
  readonly accent: Paint;
  /** The verdict as a solid badge: colored background with color, brackets without. */
  readonly badge: Readonly<Record<Verdict, Paint>>;
  readonly verdict: Readonly<Record<Verdict, Paint>>;
  readonly severity: Readonly<Record<Severity, Paint>>;
}

const sgr =
  (code: string): Paint =>
  (s) =>
    `${ESC}[${code}m${s}${ESC}[0m`;
const plain: Paint = (s) => s;
const bracket: Paint = (s) => `[${s.slice(1, -1)}]`;

export const COLORS: Palette = {
  bold: sgr("1"),
  dim: sgr("2"),
  underline: sgr("4"),
  ok: sgr("32"),
  warn: sgr("33"),
  bad: sgr("31"),
  accent: sgr("36"),
  badge: { block: sgr("1;30;41"), warn: sgr("1;30;43"), pass: sgr("1;30;42") },
  verdict: { block: sgr("1;31"), warn: sgr("1;33"), pass: sgr("1;32") },
  severity: { critical: sgr("1;91"), high: sgr("31"), medium: sgr("33"), low: sgr("36"), info: sgr("2") },
};

export const NO_COLORS: Palette = {
  bold: plain,
  dim: plain,
  underline: plain,
  ok: plain,
  warn: plain,
  bad: plain,
  accent: plain,
  badge: { block: bracket, warn: bracket, pass: bracket },
  verdict: { block: plain, warn: plain, pass: plain },
  severity: { critical: plain, high: plain, medium: plain, low: plain, info: plain },
};

export const palette = (color: boolean): Palette => (color ? COLORS : NO_COLORS);

export const GLYPH = {
  /** Severity marker before each finding. */
  dot: "\u25CF",
  /** Gutter between a line number and the code it quotes. */
  bar: "\u2502",
  /** Gutter for the continuation of a wrapped code line. */
  dots: "\u250A",
  /** Horizontal rule above the summary. */
  rule: "\u2500",
  /** Separator inside a line. */
  sep: "\u00B7",
  /** Bullet for next steps. */
  arrow: "\u203A",
} as const;

const ANSI = new RegExp(`${ESC}\\[[0-9;]*m`, "g");

export const stripAnsi = (s: string): string => s.replace(ANSI, "");

/** Columns `s` takes on screen: its length without ANSI codes. */
export const visibleWidth = (s: string): number => stripAnsi(s).length;

/**
 * Wrap `text` to `width` columns with `indent` before every line. Breaks at spaces; words longer
 * than a line, and all of `text` when `hard` is set (code snippets), are cut at the column limit.
 */
export function wrap(text: string, width: number, indent: string, hard = false): string[] {
  const avail = Math.max(MIN_WRAP, width - indent.length);
  const out: string[] = [];
  for (const para of text.split("\n")) {
    if (hard) {
      for (let i = 0; i < Math.max(1, para.length); i += avail) out.push(indent + para.slice(i, i + avail));
      continue;
    }
    let line = "";
    for (const word of para.split(/ +/).filter(Boolean)) {
      let w = word;
      if (line && line.length + 1 + w.length > avail) {
        out.push(indent + line);
        line = "";
      }
      while (w.length > avail) {
        out.push(indent + w.slice(0, avail));
        w = w.slice(avail);
      }
      line = line ? `${line} ${w}` : w;
    }
    out.push(indent + line);
  }
  return out;
}
