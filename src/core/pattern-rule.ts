import { contextualize, inLineComment, inPatternLiteral, isCautionary, pathContext } from "./context";
import { regionAt } from "./markdown";
import type { FileContext, FileRole, FileRule, RegionEffect, RegionPolicy, RuleMeta, SignalTag } from "./rule";
import { TEXT_KINDS } from "./rule";
import { lineText, positionAt } from "./text";
import type { Confidence, FileKind, Language, Severity } from "./types";

export interface PatternRuleSpec extends RuleMeta {
  readonly kinds?: readonly FileKind[];
  readonly languages?: readonly Language[];
  /** Global regexes. Keep quantifiers bounded: the input is hostile. */
  readonly patterns: readonly RegExp[];
  /** Effect of the Markdown region a match falls in. Unlisted regions keep the rule's defaults. */
  readonly regions?: RegionPolicy;
  /** Effect of the file's role. Unlisted roles keep the rule's defaults. */
  readonly roles?: Partial<Record<FileRole, RegionEffect>>;
  /** Drop a match whose line matches this, e.g. placeholders. */
  readonly ignoreLine?: RegExp;
  /** Drop a match for which this returns true. */
  readonly ignoreMatch?: (m: RegExpExecArray, ctx: FileContext) => boolean;
  /** Lower confidence when the sentence around a Markdown match warns against it. Default true. */
  readonly cautionAware?: boolean;
  /** Treat a quoted match, or one in a Markdown table row, as an example being discussed. Default false. */
  readonly quoteAware?: boolean;
  readonly message?: (m: RegExpExecArray) => string;
  /** Per-match base severity or confidence, e.g. a trusted host lowers severity. Region, role, and context effects apply on top. */
  readonly adjust?: (
    m: RegExpExecArray,
    ctx: FileContext,
  ) => { severity?: Severity; confidence?: Confidence; message?: string } | undefined;
  /** Also record a capability signal for correlation, for every match or for the matches a function picks. */
  readonly signal?: SignalTag | ((m: RegExpExecArray) => SignalTag | undefined);
  readonly maxHitsPerFile?: number;
  /**
   * A cheap, non-global regex that must match somewhere in the file before the patterns run.
   * Only a speed-up: it must accept every text any pattern could match.
   */
  readonly prefilter?: RegExp;
  /**
   * Run the patterns only on lines this matches. A speed-up for patterns that never span lines:
   * a write to `~/.bashrc` is only looked for on lines that mention `.bashrc`.
   */
  readonly lineHint?: RegExp;
}

export { applyEffect, inLineComment, isCautionary } from "./context";

export function patternRule(spec: PatternRuleSpec): FileRule {
  const {
    patterns,
    kinds,
    languages,
    regions,
    roles,
    ignoreLine,
    ignoreMatch,
    message,
    adjust,
    signal,
    maxHitsPerFile,
    cautionAware,
    quoteAware,
    prefilter,
    lineHint,
    ...meta
  } = spec;
  for (const re of patterns) if (!re.global) throw new Error(`rule ${meta.id}: pattern ${re} must be global`);
  if (prefilter?.global || prefilter?.sticky) throw new Error(`rule ${meta.id}: prefilter ${prefilter} must not be global or sticky`);
  const hintAll = lineHint ? new RegExp(lineHint.source, `${lineHint.flags.replace(/[gy]/g, "")}g`) : undefined;
  const limit = maxHitsPerFile ?? 5;
  const contextOptions = {
    ...(roles ? { roles } : {}),
    ...(regions ? { regions } : {}),
    ...(cautionAware !== undefined ? { cautionAware } : {}),
    ...(quoteAware !== undefined ? { quoteAware } : {}),
  };
  return {
    ...meta,
    scope: "file",
    kinds: kinds ?? TEXT_KINDS,
    ...(languages ? { languages } : {}),
    check(ctx: FileContext) {
      if (prefilter && !prefilter.test(ctx.text)) return;
      let hits = 0;
      const consider = (m: RegExpExecArray): void => {
        if (ignoreLine?.test(lineText(ctx.index, positionAt(ctx.index, m.index).line))) return;
        if (ignoreMatch?.(m, ctx)) return;
        const override = adjust?.(m, ctx);
        const base = { severity: override?.severity ?? meta.severity, confidence: override?.confidence ?? meta.confidence };
        const graded = contextualize(ctx, m.index, m[0].length, base, contextOptions);
        if (!graded) return;
        // Only matches that stand as evidence feed correlations; warnings and hunches do not.
        const tag = typeof signal === "function" ? signal(m) : signal;
        if (tag && graded.confidence !== "low") ctx.signal(tag, m.index, m[0]);
        const text = override?.message ?? message?.(m);
        ctx.report({
          offset: m.index,
          length: m[0].length,
          severity: graded.severity,
          confidence: graded.confidence,
          ...(text ? { message: text } : {}),
        });
        hits += 1;
      };
      const scan = (text: string, offset: number): void => {
        for (const re of patterns) {
          re.lastIndex = 0;
          for (let m = re.exec(text); m !== null && hits < limit; m = re.exec(text)) {
            if (m[0].length === 0) {
              re.lastIndex += 1;
              continue;
            }
            if (offset !== 0) m.index += offset;
            consider(m);
          }
        }
      };
      if (!hintAll) {
        scan(ctx.text, 0);
        return;
      }
      hintAll.lastIndex = 0;
      let lastLine = 0;
      for (let h = hintAll.exec(ctx.text); h !== null && hits < limit; h = hintAll.exec(ctx.text)) {
        if (h[0].length === 0) hintAll.lastIndex += 1;
        const { line } = positionAt(ctx.index, h.index);
        if (line === lastLine) continue;
        lastLine = line;
        scan(lineText(ctx.index, line), ctx.index.starts[line - 1] ?? 0);
      }
    },
  };
}

/** A rule that only records a capability signal, for correlation. It never reports on its own. */
export function signalRule(
  id: string,
  tag: SignalTag,
  patterns: readonly RegExp[],
  opts: { kinds?: readonly FileKind[]; ignoreMatch?: (m: RegExpExecArray) => boolean } = {},
): FileRule {
  return {
    id,
    title: `signal: ${tag}`,
    category: "execution-surface",
    severity: "info",
    confidence: "low",
    description: `Records ${tag} capability for correlation rules. Never reported on its own.`,
    scope: "file",
    kinds: opts.kinds ?? ["script", "skill-md", "markdown", "manifest"],
    check(ctx) {
      for (const re of patterns) {
        re.lastIndex = 0;
        for (let m = re.exec(ctx.text); m !== null; m = re.exec(ctx.text)) {
          if (m[0].length === 0) {
            re.lastIndex += 1;
            continue;
          }
          if (opts.ignoreMatch?.(m)) continue;
          // Tests, container builds, attack write-ups, and detection patterns describe capabilities; they do not give the skill any.
          if (!ctx.decoded && pathContext(ctx.bundle, ctx.file) !== undefined) continue;
          if (!ctx.decoded && ctx.file.kind === "script" && (inLineComment(ctx, m.index) || inPatternLiteral(ctx, m.index, m[0].length)))
            continue;
          if (ctx.regions && !ctx.decoded) {
            const kind = regionAt(ctx.regions, m.index).kind;
            if (kind === "prose" && isCautionary(ctx, m.index)) continue;
          }
          ctx.signal(tag, m.index, m[0]);
        }
      }
    },
  };
}
