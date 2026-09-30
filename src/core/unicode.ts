/**
 * Invisible and deceptive Unicode. Models read characters a human never sees, so a skill can
 * carry a second, hidden set of instructions. Each detector returns runs with their decoded
 * payload when one exists, so reports can show what was hidden.
 */

export type UnicodeIssue = "tag" | "variation-selector" | "bidi" | "zero-width" | "invisible-filler";

export interface UnicodeRun {
  readonly issue: UnicodeIssue;
  readonly start: number;
  readonly end: number;
  readonly count: number;
  /** ASCII or bytes smuggled in the run, when it decodes to something readable. */
  readonly decoded?: string;
}

const isTag = (cp: number): boolean => cp >= 0xe0000 && cp <= 0xe007f;
const isVariationSelector = (cp: number): boolean => (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef);
const isBidi = (cp: number): boolean =>
  (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069) || cp === 0x200e || cp === 0x200f || cp === 0x061c;
const isZeroWidth = (cp: number): boolean =>
  cp === 0x200b || cp === 0x200c || cp === 0x200d || cp === 0x2060 || cp === 0xfeff || cp === 0x180e || (cp >= 0x2061 && cp <= 0x2064);
const isFiller = (cp: number): boolean =>
  cp === 0x115f || cp === 0x1160 || cp === 0x3164 || cp === 0xffa0 || cp === 0x034f || cp === 0x00ad;

/** Emoji and pictographs, where ZWJ and VS16 are legitimate. */
const isPictographic = (cp: number): boolean =>
  (cp >= 0x1f000 && cp <= 0x1faff) ||
  (cp >= 0x2600 && cp <= 0x27bf) ||
  (cp >= 0x2300 && cp <= 0x23ff) ||
  (cp >= 0x2b00 && cp <= 0x2bff) ||
  cp === 0x00a9 ||
  cp === 0x00ae ||
  (cp >= 0x1f1e6 && cp <= 0x1f1ff) ||
  cp === 0x20e3;

/** Scripts where ZWJ and ZWNJ shape text: Arabic, Indic, Persian, and friends. */
const isJoiningScript = (cp: number): boolean =>
  (cp >= 0x0600 && cp <= 0x06ff) ||
  (cp >= 0x0900 && cp <= 0x0dff) ||
  (cp >= 0x0750 && cp <= 0x077f) ||
  (cp >= 0x08a0 && cp <= 0x08ff) ||
  (cp >= 0x1780 && cp <= 0x17ff);

interface Cp {
  readonly cp: number;
  readonly index: number;
  readonly width: number;
}

function codepoints(text: string): Cp[] {
  const out: Cp[] = [];
  for (let i = 0; i < text.length; ) {
    const cp = text.codePointAt(i)!;
    const width = cp > 0xffff ? 2 : 1;
    out.push({ cp, index: i, width });
    i += width;
  }
  return out;
}

/** Quick pre-check so most files skip the per-codepoint walk. */
const SUSPECT_RE =
  /\u034F|[\u00AD\u061C\u115F\u1160\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2069\u3164\uFE00-\uFE0F\uFEFF\uFFA0]|\uDB40[\uDC00-\uDDEF]/;

export function findUnicodeRuns(text: string): UnicodeRun[] {
  if (!SUSPECT_RE.test(text)) return [];
  const cps = codepoints(text);
  const runs: UnicodeRun[] = [];
  let i = 0;
  while (i < cps.length) {
    const c = cps[i]!;
    const issue = classify(cps, i);
    if (!issue) {
      i += 1;
      continue;
    }
    let j = i;
    while (j + 1 < cps.length && classify(cps, j + 1) === issue) j += 1;
    const run = cps.slice(i, j + 1);
    const last = run[run.length - 1]!;
    runs.push({
      issue,
      start: c.index,
      end: last.index + last.width,
      count: run.length,
      ...decodeRun(
        issue,
        run.map((r) => r.cp),
      ),
    });
    i = j + 1;
  }
  return runs;
}

function classify(cps: readonly Cp[], i: number): UnicodeIssue | undefined {
  const { cp, index } = cps[i]!;
  const prev = cps[i - 1]?.cp;
  const next = cps[i + 1]?.cp;
  if (isTag(cp)) {
    // A tag sequence right after a flag emoji (subdivision flags like England) is legitimate.
    return prev !== undefined && (prev === 0x1f3f4 || isTag(prev)) && isLegitFlagSequence(cps, i) ? undefined : "tag";
  }
  if (isVariationSelector(cp)) {
    const single = !(prev !== undefined && isVariationSelector(prev)) && !(next !== undefined && isVariationSelector(next));
    // One selector after a visible character picks a glyph variant: emoji or text style (U+2139 U+FE0F),
    // or a CJK ideographic variant (U+E0100 and up). It carries one byte at most; smuggling needs a run.
    if (single && prev !== undefined && isVisibleBase(prev)) return undefined;
    return "variation-selector";
  }
  if (isBidi(cp)) return "bidi";
  if (isZeroWidth(cp)) {
    if (cp === 0xfeff && index === 0) return undefined;
    if (
      cp === 0x200d &&
      prev !== undefined &&
      next !== undefined &&
      (isPictographic(prev) || isVariationSelector(prev)) &&
      isPictographic(next)
    )
      return undefined;
    if (
      (cp === 0x200c || cp === 0x200d) &&
      ((prev !== undefined && isJoiningScript(prev)) || (next !== undefined && isJoiningScript(next)))
    )
      return undefined;
    return "zero-width";
  }
  if (isFiller(cp)) {
    if (cp === 0x00ad && prev !== undefined && next !== undefined && isLetter(prev) && isLetter(next)) return undefined;
    return "invisible-filler";
  }
  return undefined;
}

const isLetter = (cp: number): boolean => /\p{L}/u.test(String.fromCodePoint(cp));

/** A character a variation selector can legitimately modify: anything visible, not whitespace or another invisible. */
const isVisibleBase = (cp: number): boolean =>
  cp > 0x20 &&
  cp !== 0x7f &&
  !/\s/u.test(String.fromCodePoint(cp)) &&
  !isZeroWidth(cp) &&
  !isBidi(cp) &&
  !isTag(cp) &&
  !isFiller(cp) &&
  !isVariationSelector(cp);

function isLegitFlagSequence(cps: readonly Cp[], i: number): boolean {
  // \u{1F3F4} + tag letters + CANCEL TAG (U+E007F), at most 6 letters.
  let start = i;
  while (start > 0 && isTag(cps[start - 1]!.cp)) start -= 1;
  if (cps[start - 1]?.cp !== 0x1f3f4) return false;
  let end = i;
  while (end + 1 < cps.length && isTag(cps[end + 1]!.cp)) end += 1;
  const body = cps.slice(start, end + 1).map((c) => c.cp);
  return (
    body.length <= 7 &&
    body[body.length - 1] === 0xe007f &&
    body.slice(0, -1).every((cp) => (cp >= 0xe0061 && cp <= 0xe007a) || (cp >= 0xe0030 && cp <= 0xe0039))
  );
}

function decodeRun(issue: UnicodeIssue, cps: readonly number[]): { decoded?: string } {
  if (issue === "tag") {
    const s = cps
      .filter((cp) => cp !== 0xe0001 && cp !== 0xe007f)
      .map((cp) => String.fromCharCode(cp - 0xe0000))
      .join("");
    return s.trim() ? { decoded: s } : {};
  }
  if (issue === "variation-selector" && cps.length >= 4) {
    // "Emoji smuggling": each selector carries one byte (FE00-FE0F = 0-15, E0100-E01EF = 16-255).
    const bytes = cps.map((cp) => (cp <= 0xfe0f ? cp - 0xfe00 : cp - 0xe0100 + 16));
    const s = new TextDecoder("utf-8", { fatal: false }).decode(new Uint8Array(bytes));
    return printableRatio(s) > 0.8 ? { decoded: s } : {};
  }
  if (issue === "zero-width" && cps.length >= 16) {
    // Binary steganography: two distinct zero-width characters as 0 and 1.
    const kinds = [...new Set(cps)];
    if (kinds.length === 2) {
      for (const [zero, one] of [
        [kinds[0], kinds[1]],
        [kinds[1], kinds[0]],
      ] as const) {
        const bits = cps.map((cp) => (cp === one ? "1" : cp === zero ? "0" : "")).join("");
        const bytes: number[] = [];
        for (let k = 0; k + 8 <= bits.length; k += 8) bytes.push(Number.parseInt(bits.slice(k, k + 8), 2));
        const s = String.fromCharCode(...bytes);
        if (printableRatio(s) > 0.9) return { decoded: s };
      }
    }
  }
  return {};
}

export function printableRatio(s: string): number {
  if (s.length === 0) return 0;
  let ok = 0;
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    if ((cp >= 0x20 && cp < 0x7f) || cp === 0x0a || cp === 0x0d || cp === 0x09 || (cp >= 0xa0 && cp !== 0xfffd)) ok += 1;
  }
  return ok / [...s].length;
}

/** Scripts that commonly impersonate Latin letters. */
const CONFUSABLE_SCRIPTS: ReadonlyArray<readonly [string, RegExp]> = [
  ["Cyrillic", /\p{Script=Cyrillic}/u],
  ["Greek", /\p{Script=Greek}/u],
  ["Armenian", /\p{Script=Armenian}/u],
  ["Cherokee", /\p{Script=Cherokee}/u],
];

export interface MixedScriptWord {
  readonly word: string;
  readonly index: number;
  readonly scripts: readonly string[];
}

/** Words mixing Latin with a look-alike script, e.g. `p\u0430ypal` with a Cyrillic `\u0430`. */
export function findMixedScriptWords(text: string): MixedScriptWord[] {
  if (!/[\u0370-\u058F\u13A0-\u13FF]/.test(text)) return [];
  const out: MixedScriptWord[] = [];
  for (const m of text.matchAll(/[\p{L}\p{M}\d]{3,}/gu)) {
    const word = m[0];
    if (!/[A-Za-z]/.test(word)) continue;
    const scripts = CONFUSABLE_SCRIPTS.filter(([, re]) => re.test(word)).map(([name]) => name);
    if (scripts.length > 0) out.push({ word, index: m.index, scripts: ["Latin", ...scripts] });
  }
  return out;
}
