import { contextualize } from "../core/context";
import { regionAt } from "../core/markdown";
import type { FileContext, FileRule } from "../core/rule";
import { TEXT_KINDS } from "../core/rule";
import { clip, revealInvisible } from "../core/text";
import type { Confidence, Severity } from "../core/types";
import { findMixedScriptWords, findUnicodeRuns, type UnicodeIssue, type UnicodeRun } from "../core/unicode";

/** Invisible characters in a test fixture are usually the test's input; the grading helper knows where files sit. */
function inContext(ctx: FileContext, offset: number, length: number, severity: Severity): { severity: Severity; confidence: Confidence } {
  return contextualize(ctx, offset, length, { severity, confidence: "high" }, { cautionAware: false }) ?? { severity, confidence: "high" };
}

/** One rule per issue, sharing a single pass over the file. */
const cache = new WeakMap<object, UnicodeRun[]>();
function runs(ctx: FileContext): UnicodeRun[] {
  let r = cache.get(ctx.file);
  if (!r) {
    r = findUnicodeRuns(ctx.text);
    cache.set(ctx.file, r);
  }
  return r;
}

function inFrontmatter(ctx: FileContext, offset: number): boolean {
  return ctx.regions ? regionAt(ctx.regions, offset).kind === "frontmatter" : false;
}

function unicodeRule(
  id: string,
  issue: UnicodeIssue,
  title: string,
  severity: Severity,
  description: string,
  decide: (ctx: FileContext, run: UnicodeRun, all: readonly UnicodeRun[]) => { severity?: Severity; message: string } | undefined,
  extra?: (ctx: FileContext) => void,
): FileRule {
  return {
    id,
    title,
    category: "hidden-content",
    severity,
    confidence: "high",
    hard: true,
    description,
    remediation:
      "Open the file in an editor that shows invisible characters (or run `cat -v`) and remove them. Do not install a skill that hides text this way.",
    scope: "file",
    kinds: TEXT_KINDS,
    check(ctx) {
      const all = runs(ctx).filter((r) => r.issue === issue);
      let reported = 0;
      for (const run of all) {
        const verdict = decide(ctx, run, all);
        if (!verdict) continue;
        const g = inContext(ctx, run.start, run.end - run.start, verdict.severity ?? severity);
        ctx.report({
          offset: run.start,
          length: run.end - run.start,
          message: verdict.message,
          severity: g.severity,
          confidence: g.confidence,
          ...(run.decoded ? { evidence: `decoded: ${clip(revealInvisible(run.decoded), 400)}` } : {}),
        });
        if (++reported >= 5) break;
      }
      extra?.(ctx);
    },
  };
}

/** `\U000E0041`, `\u{E0041}`, `\uDB40\uDC41`: tag characters written as escapes, which code turns into invisible text at run time. */
const ESCAPED_TAG_RE = /(?:\\U000[eE]00[0-7][0-9A-Fa-f]|\\u\{[eE]00[0-7][0-9A-Fa-f]\}|\\u[dD][bB]40\\u[dD][cC][0-7][0-9A-Fa-f])+/g;

function escapedTags(ctx: FileContext): void {
  if (ctx.file.kind !== "script" || !/\\(?:U000[eE]00|u\{[eE]00|u[dD][bB]40)/.test(ctx.text)) return;
  for (const m of ctx.text.matchAll(ESCAPED_TAG_RE)) {
    const decoded = [...m[0].matchAll(/[0-7][0-9A-Fa-f](?=\}|\\|$)/g)].map((h) => String.fromCharCode(Number.parseInt(h[0], 16))).join("");
    const g = contextualize(ctx, m.index, m[0].length, { severity: "high", confidence: "medium" }, { cautionAware: false });
    if (!g) continue;
    ctx.report({
      offset: m.index,
      length: m[0].length,
      severity: g.severity,
      confidence: g.confidence,
      message: "Tag characters written as escapes: the code produces invisible text when it runs",
      ...(decoded.trim() ? { evidence: `decoded: ${clip(revealInvisible(decoded), 400)}` } : {}),
    });
    return;
  }
}

export const unicodeRules: readonly FileRule[] = [
  unicodeRule(
    "unicode/tag-characters",
    "tag",
    "Invisible Unicode tag characters",
    "critical",
    "Unicode tag characters (U+E0000 to U+E007F) render as nothing but spell out ASCII the model reads. This is the ASCII-smuggling technique for hiding instructions.",
    (_ctx, run) => ({
      message: run.decoded
        ? `${run.count} invisible tag characters spell out: "${clip(revealInvisible(run.decoded), 120)}"`
        : `${run.count} invisible tag characters`,
    }),
    escapedTags,
  ),
  unicodeRule(
    "unicode/variation-selector-smuggling",
    "variation-selector",
    "Data smuggled in variation selectors",
    "high",
    "A run of variation selectors that do not modify a visible glyph. Each selector can carry one hidden byte.",
    (_ctx, run) => ({
      severity: run.decoded ? "critical" : "high",
      message: run.decoded
        ? `${run.count} variation selectors decode to: "${clip(revealInvisible(run.decoded), 120)}"`
        : `${run.count} variation selectors with no glyph to modify`,
    }),
  ),
  unicodeRule(
    "unicode/bidi-control",
    "bidi",
    "Bidirectional control characters",
    "high",
    "Right-to-left overrides and isolates reorder how text displays, so code or instructions read differently to a reviewer than to the machine (Trojan Source, CVE-2021-42574).",
    (ctx, run) => {
      const rtlProse = /[\u0590-\u08FF]/.test(ctx.text.slice(Math.max(0, run.start - 20), run.end + 20));
      if (rtlProse && ctx.file.kind !== "script" && run.count === 1) return undefined;
      return {
        severity: ctx.file.kind === "script" || ctx.file.kind === "manifest" ? "high" : "medium",
        message: `${run.count} bidirectional control character(s) change how the surrounding text displays`,
      };
    },
  ),
  unicodeRule(
    "unicode/zero-width",
    "zero-width",
    "Zero-width characters",
    "medium",
    "Zero-width characters split keywords so filters miss them, or encode hidden bits.",
    (ctx, run, all) => {
      if (run.decoded)
        return {
          severity: "critical",
          message: `${run.count} zero-width characters encode hidden text: "${clip(revealInvisible(run.decoded), 120)}"`,
        };
      const total = all.reduce((n, r) => n + r.count, 0);
      const insideWord =
        /[A-Za-z]$/.test(ctx.text.slice(Math.max(0, run.start - 1), run.start)) && /^[A-Za-z]/.test(ctx.text.slice(run.end, run.end + 1));
      if (inFrontmatter(ctx, run.start))
        return { severity: "high", message: "Zero-width characters in the frontmatter, which every session loads" };
      if (insideWord && (ctx.file.kind === "script" || ctx.file.kind === "manifest"))
        return { severity: "high", message: "A zero-width character splits a word in code, which hides it from text search and review" };
      if (run.count >= 3 || total >= 5) return { message: `${run.count} zero-width characters in a row (${total} in the file)` };
      if (insideWord) return { severity: "low", message: "A zero-width character splits a word" };
      return undefined;
    },
  ),
  unicodeRule(
    "unicode/invisible-filler",
    "invisible-filler",
    "Invisible filler characters",
    "medium",
    "Hangul fillers and similar blank letters make identifiers and text that look empty or identical but are not.",
    (ctx, run) => ({ severity: ctx.file.kind === "script" ? "high" : "medium", message: `${run.count} invisible filler character(s)` }),
  ),
  {
    id: "unicode/terminal-escape",
    title: "Terminal escape sequences or control characters",
    category: "hidden-content",
    severity: "high",
    confidence: "high",
    hard: true,
    description:
      "ANSI escape sequences and control characters can hide or rewrite text when a file or command output is shown in a terminal, so the reviewer sees something different from what the agent reads.",
    scope: "file",
    kinds: ["skill-md", "markdown", "text", "manifest"],
    check(ctx) {
      // A bare carriage return rewrites the line in a terminal, unless the file simply uses CR line endings.
      const crEndings = (ctx.text.match(/\r(?!\n)/g)?.length ?? 0) > (ctx.text.match(/\n/g)?.length ?? 0);
      const re = crEndings
        ? /\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07\x1b]{0,200}(?:\x07|\x1b\\)|[\x00-\x08\x0b\x0c\x0e-\x1a\x1c-\x1f\x7f]/
        : /\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07\x1b]{0,200}(?:\x07|\x1b\\)|[\x00-\x08\x0b\x0c\x0e-\x1a\x1c-\x1f\x7f]|\r(?!\n)/;
      const m = re.exec(ctx.text);
      if (m) {
        const g = inContext(ctx, m.index, m[0].length, "high");
        ctx.report({
          offset: m.index,
          length: m[0].length,
          severity: g.severity,
          confidence: g.confidence,
          message: m[0].startsWith("\x1b") ? "ANSI escape sequence in a text file" : "Control character in a text file",
        });
      }
    },
  },
  {
    id: "unicode/mixed-script",
    title: "Look-alike letters from another script",
    category: "hidden-content",
    severity: "low",
    confidence: "medium",
    description:
      "Words that mix Latin with Cyrillic, Greek, or other look-alike letters, e.g. a domain or command name that reads the same but is not.",
    scope: "file",
    kinds: TEXT_KINDS,
    check(ctx) {
      let n = 0;
      for (const w of findMixedScriptWords(ctx.text)) {
        const around = ctx.text.slice(Math.max(0, w.index - 60), w.index + w.word.length + 5);
        const inUrl = /https?:\/\/\S*$/.test(around.slice(0, 60 + 1)) || /\.[a-z]{2,}\b/i.test(w.word);
        const inFm = inFrontmatter(ctx, w.index);
        const g = inContext(ctx, w.index, w.word.length, inUrl || inFm || ctx.file.kind === "script" ? "high" : "low");
        ctx.report({
          offset: w.index,
          length: w.word.length,
          severity: g.severity,
          confidence: g.confidence === "high" ? "medium" : g.confidence,
          message: `"${w.word}" mixes ${w.scripts.join(" and ")} letters${inUrl ? " in what looks like a URL or domain" : inFm ? " in the frontmatter" : ""}`,
        });
        if (++n >= 5) break;
      }
    },
  },
];
