import { type PathContext, pathContextOf, roleOf } from "./classify";
import { extractEmbedded } from "./embedded";
import { regionAt } from "./markdown";
import type { FileContext, FileRole, RegionEffect, RegionPolicy } from "./rule";
import { demote, lowerConfidence, promote } from "./severity";
import { lineText, positionAt } from "./text";
import type { Confidence, Severity, SkillBundle, SkillFile } from "./types";

/**
 * Where a match sits changes what it means. These helpers turn a rule's severity for a match into
 * the severity it counts for, given the file's role, the Markdown region, the sentence around it,
 * and where the file lives in the skill. Pattern rules apply them automatically; custom rules call
 * `contextualize` themselves.
 */

export interface Graded {
  readonly severity: Severity;
  readonly confidence: Confidence;
}

/** Words that mark a sentence as a warning or an explanation rather than an instruction. */
const CAUTION_RE =
  /\b(never|do not|don't|dont|must not|should not|shouldn't|avoid|beware|warning|danger(?:ous)?|malicious|attacker|attack(?:s|er)?|exploit|red flags?|detect(?:s|ed|ion)?|flag(?:s|ged)?|block(?:s|ed)?|example of|for instance|refuse|reject|forbidden|not allowed|prohibited|unsafe|insecure|anti-?patterns?|bad practice|incorrect|vulnerable)\b|\be\.g\.|\u274C|\u26D4|\uD83D\uDEAB/i;

export function isCautionary(ctx: FileContext, offset: number): boolean {
  const { line } = positionAt(ctx.index, offset);
  const here = lineText(ctx.index, line);
  if (CAUTION_RE.test(here)) return true;
  const before = line > 1 ? lineText(ctx.index, line - 1) : "";
  if (/[:]\s*$/.test(before)) return CAUTION_RE.test(before);
  // A sentence wrapped onto this line: "Do not use plan mode or\n`--flag`." The warning is on the line before.
  const wrapped = before.trim() !== "" && !/[.!?]\s*$/.test(before) && !/^\s*(?:[-*+]\s|\d+[.)]\s|#|\||```)/.test(here);
  if (wrapped && CAUTION_RE.test(before.slice(Math.max(before.search(/[^.!?]*$/), 0)))) return true;
  return LIST_ITEM_RE.test(here) && CAUTION_RE.test(listLead(ctx, line));
}

const LIST_ITEM_RE = /^\s*(?:[-*+]|\d+[.)])\s/;

/** The heading or lead-in line a list hangs from ("## Must Never", "Avoid:"), found by walking up over its items. */
function listLead(ctx: FileContext, line: number): string {
  for (let l = line - 1; l >= 1 && l >= line - 40; l -= 1) {
    const t = lineText(ctx.index, l);
    if (t.trim() === "" || LIST_ITEM_RE.test(t) || /^\s{2,}\S/.test(t)) continue;
    // A heading, a bold label, or a short lead-in ("Avoid:"); a long paragraph ending in a colon is instructions.
    return /^\s*#{1,6}\s|^\s*\*\*[^*]+\*\*:?\s*$/.test(t) || (/:\s*$/.test(t) && t.trim().length <= 80) ? t : "";
  }
  return "";
}

/** Whether the match sits after a `#`, `//`, or `-- ` comment marker, or on a block-comment line (` * ...`). */
export function inLineComment(ctx: FileContext, offset: number): boolean {
  const { line } = positionAt(ctx.index, offset);
  const before = ctx.text.slice(ctx.index.starts[line - 1] ?? 0, offset);
  return /(?:^|\s)(?:#(?![!{])|\/\/|--\s)|^\s*(?:\/\*|\*(?:\s|$))/.test(before);
}

/** "e.g. ~/.ssh/id_rsa", "for example ...", "such as ...": an example given in a message or doc string. */
function introducedAsExample(ctx: FileContext, offset: number): boolean {
  const { text, col } = lineAround(ctx, offset);
  return /\b(?:e\.g\.|for example|for instance|such as|i\.e\.)[^.;\n]{0,40}$/i.test(text.slice(Math.max(0, col - 60), col));
}

/** Spans of JavaScript regex literals on one line, found by a small tokenizer that skips strings and comments. */
function regexLiteralSpans(line: string): Array<[number, number]> {
  const spans: Array<[number, number]> = [];
  let prev = "";
  let i = 0;
  while (i < line.length) {
    const c = line[i]!;
    if (c === '"' || c === "'" || c === "`") {
      i += 1;
      while (i < line.length && line[i] !== c) i += line[i] === "\\" ? 2 : 1;
      i += 1;
      prev = c;
      continue;
    }
    if (c === "/" && line[i + 1] === "/") break;
    if (c === "/" && line[i + 1] === "*") {
      const end = line.indexOf("*/", i + 2);
      if (end === -1) break;
      i = end + 2;
      continue;
    }
    const startsRegex =
      c === "/" &&
      (prev === "" ||
        "(,=:[!&|?{};+-*%<>^".includes(prev) ||
        /\b(?:return|typeof|case|in|of|delete|void|throw|new|yield|await)$/.test(line.slice(0, i).trimEnd()));
    if (startsRegex) {
      let j = i + 1;
      let inClass = false;
      while (j < line.length) {
        const d = line[j]!;
        if (d === "\\") j += 1;
        else if (d === "[") inClass = true;
        else if (d === "]") inClass = false;
        else if (d === "/" && !inClass) break;
        j += 1;
      }
      if (j >= line.length) break;
      j += 1;
      while (j < line.length && /[a-z]/.test(line[j]!)) j += 1;
      spans.push([i, j]);
      i = j;
      prev = "/";
      continue;
    }
    if (!/\s/.test(c)) prev = c;
    i += 1;
  }
  return spans;
}

/** Calls and literal forms that hold a pattern to search for, not a command to run. */
const PATTERN_CALL_RE =
  /\b(?:new\s+)?RegExp\s*\(|String\.raw`|\bre\.(?:compile|search|match|fullmatch|findall|finditer|sub|subn|split)\s*\(|\bregexp?\.MustCompile\s*\(|\bRegex\s*\(/;

/**
 * Whether a match in code is part of a pattern: a regex literal, a raw string (`r"..."`,
 * `String.raw`), or an argument to a regex constructor. Detectors, linters, and scanners are full
 * of the very strings they look for; a pattern is data, never an action.
 */
export function inPatternLiteral(ctx: FileContext, offset: number, length: number): boolean {
  const { text, col } = lineAround(ctx, offset);
  if (PATTERN_CALL_RE.test(text)) return true;
  // Regex literal syntax only exists in JavaScript and TypeScript, raw strings in Python: `~/.aws/x` in shell is a path.
  const lang = ctx.file.language ?? (ctx.regions ? regionAt(ctx.regions, offset).lang : undefined) ?? "";
  if (/^(?:javascript|typescript|js|jsx|ts|tsx|mjs|cjs)$/.test(lang)) {
    if (regexLiteralSpans(text).some(([s, e]) => col >= s && col + length <= e)) return true;
  }
  if (/^(?:python|py|python3)$/.test(lang)) {
    for (const m of text.matchAll(/\b[rR][bB]?(["'])(?:(?!\1).)*\1/g)) {
      if (col >= m.index && col + length <= m.index + m[0].length) return true;
    }
  }
  return false;
}

function lineAround(ctx: FileContext, offset: number): { text: string; col: number } {
  const { line } = positionAt(ctx.index, offset);
  return { text: lineText(ctx.index, line), col: offset - (ctx.index.starts[line - 1] ?? 0) };
}

/**
 * Whether the match is quoted on its line: inside "...", curly quotes, or (in code) '...'. A quoted
 * phrase is usually an example being discussed, like `Watch for "ignore previous instructions"`.
 */
export function inQuotes(ctx: FileContext, offset: number, length: number, singleQuotes = false): boolean {
  const { text, col } = lineAround(ctx, offset);
  const before = text.slice(0, col);
  // A match may wrap onto the next line; the closing quote is then on the line where it ends.
  const endLine = lineAround(ctx, offset + Math.max(0, length - 1));
  const after = endLine.text.slice(endLine.col + 1);
  const straight = (q: string): boolean => {
    const n = before.split(q).length - 1 - (before.split(`\\${q}`).length - 1);
    return n % 2 === 1 && after.includes(q);
  };
  const curly = before.lastIndexOf("\u201C") > before.lastIndexOf("\u201D") && after.includes("\u201D");
  return straight('"') || curly || (singleQuotes && straight("'"));
}

/** A Markdown table row: its cells describe things side by side rather than give orders. */
export function isTableRow(ctx: FileContext, offset: number): boolean {
  const { text } = lineAround(ctx, offset);
  return /^\s*\|.*\|/.test(text);
}

/** Text after `ssh host`, `kubectl exec ... --`, `docker exec|run`, `az vm run-command --scripts`, or a sandbox exec call runs elsewhere. */
const REMOTE_RE =
  /(?:\bssh\s+(?:-\S+\s+(?:\S+\s+)?)*[\w.@-]+\s+["']|\bkubectl\s+exec\b.*\s--\s|\bdocker\s+(?:exec|run)\b|\bpodman\s+(?:exec|run)\b|\baz\s+vm\s+run-command\b|--scripts?\s+["']|\bsandbox\.exec\s*\(|\bgcloud\s+compute\s+ssh\b|\s--command[=\s]+["'])/i;

export function inRemoteCommand(ctx: FileContext, offset: number): boolean {
  const { text, col } = lineAround(ctx, offset);
  return REMOTE_RE.test(text.slice(0, col));
}

/** Lines longer than this are minified or generated. */
const MINIFIED_LINE = 1000;

const pathContextCache = new WeakMap<SkillFile, PathContext | null>();
const referenceCache = new WeakMap<SkillBundle, string>();

/**
 * Text of everything the skill runs or the agent reads as instructions: SKILL.md, instruction and
 * reference Markdown, scripts, and the commands harnesses run by themselves (hooks, MCP launchers,
 * lifecycle scripts). READMEs and development, container, or attack-reference files do not count,
 * and neither does the rest of a manifest (a `files` list or a `test` script runs nothing on install).
 */
function referenceText(bundle: SkillBundle): string {
  let text = referenceCache.get(bundle);
  if (text === undefined) {
    const own = bundle.files
      .filter(
        (f) =>
          f.text !== undefined &&
          (f.kind === "skill-md" || f.kind === "markdown" || f.kind === "script") &&
          pathContextOf(f) === undefined &&
          roleOf(f, bundle.kind) !== "readme",
      )
      .map((f) => f.text!);
    const automatic = [...extractEmbedded(bundle).commands.values()]
      .flat()
      .filter((c) => c.trigger !== "npm-script")
      .map((c) => c.command);
    text = [...own, ...automatic].join("\n");
    referenceCache.set(bundle, text);
  }
  return text;
}

/** Words before a path that make it something run, loaded, or read as instructions, rather than listed or checked for. */
const RUNS_BEFORE_RE =
  /\b(?:node|python[0-9.]*|bash|sh|zsh|deno|bun|ruby|perl|pwsh|powershell|npx|tsx|ts-node|uv\s+run|source|require|import|from|spawn\w*|exec\w*|run\w*|execute|invoke|call|launch|start|use|load|read|see|follow|open)\b[^\n]{0,40}$/i;

function referencedToRun(text: string, key: string): boolean {
  let seen = 0;
  for (let i = text.indexOf(key); i !== -1 && seen < 50; i = text.indexOf(key, i + key.length), seen += 1) {
    if (RUNS_BEFORE_RE.test(text.slice(Math.max(0, i - 60), i))) return true;
  }
  return false;
}

/** How a reference names a file: its last two path segments (`tests/check.py`), or the name alone when it sits at the root. */
function referenceKey(path: string): string {
  return path.split("!/")[0]!.split("/").slice(-2).join("/");
}

/**
 * The path context of the file a rule is looking at, if it discounts findings there. Attack
 * write-ups (by path, or because the whole skill is about security review) always count as
 * mentions; container build files always run inside the container. Development files (tests,
 * fixtures, evals, CI, repository docs) lose their discount when something the skill runs or
 * reads as instructions names them, unless they are plain data that nothing can run.
 */
export function pathContext(bundle: SkillBundle, file: SkillFile): PathContext | undefined {
  const cached = pathContextCache.get(file);
  if (cached !== undefined) return cached ?? undefined;
  // Virtual files (hook commands, decoded payloads) take the context of the real file they came from.
  const parentPath = file.virtualOf?.path ?? file.path.split("#")[0]!;
  const probe =
    parentPath === file.path ? file : (bundle.files.find((f) => f.path === parentPath) ?? { path: parentPath, kind: file.kind });
  let pc = pathContextOf(probe);
  if (pc !== "educational" && pathContextOf({ path: `${bundle.dirName}/${probe.path}`, kind: probe.kind }) === "educational")
    pc = "educational";
  if (pc === "dev" && probe.kind !== "text" && referencedToRun(referenceText(bundle), referenceKey(probe.path))) pc = undefined;
  pathContextCache.set(file, pc ?? null);
  return pc;
}

export function applyEffect(sev: Severity, conf: Confidence, effect: RegionEffect | undefined): Graded | undefined {
  switch (effect) {
    case "skip":
      return undefined;
    case "raise":
      return { severity: promote(sev), confidence: conf };
    case "lower-confidence":
      return { severity: sev, confidence: lowerConfidence(conf) };
    case "lower-severity":
      return { severity: demote(sev), confidence: conf };
    default:
      return { severity: sev, confidence: conf };
  }
}

/** A mention, not a use: one step down and low confidence. */
export const asMention = (g: Graded): Graded => ({ severity: demote(g.severity), confidence: "low" });
const lowered = (g: Graded): Graded => ({ severity: g.severity, confidence: lowerConfidence(g.confidence) });

export interface ContextOptions {
  readonly roles?: Partial<Record<FileRole, RegionEffect>>;
  readonly regions?: RegionPolicy;
  /** Treat a match in a warning sentence as a mention. Default true. */
  readonly cautionAware?: boolean;
  /** Treat a quoted match, or one in a Markdown table, as an example being discussed. Default false. */
  readonly quoteAware?: boolean;
}

/**
 * Grade one match in context. Returns undefined when the context says to drop it. Decoded payloads
 * get no discount: nobody encodes documentation.
 */
export function contextualize(
  ctx: FileContext,
  offset: number,
  length: number,
  base: Graded,
  opts: ContextOptions = {},
): Graded | undefined {
  if (ctx.decoded) {
    // Decoded text gets no benefit of the doubt from regions or wording, but a sample in a test fixture is still a sample.
    const pc = pathContext(ctx.bundle, ctx.file);
    return pc === "container" ? lowered(base) : pc ? asMention(base) : base;
  }
  let g = applyEffect(base.severity, base.confidence, opts.roles?.[ctx.role]);
  if (!g) return undefined;
  const region = ctx.regions ? regionAt(ctx.regions, offset).kind : undefined;
  if (region) {
    g = applyEffect(g.severity, g.confidence, opts.regions?.[region]);
    if (!g) return undefined;
  }
  // Hidden text gets no benefit of the doubt, and frontmatter quotes are YAML syntax, not quotation.
  const describable = region !== "hidden" && region !== "frontmatter";
  if (describable && region !== undefined && (opts.cautionAware ?? true) && isCautionary(ctx, offset)) g = asMention(g);
  else if (describable && opts.quoteAware && (region !== undefined || ctx.file.kind === "script")) {
    if (inQuotes(ctx, offset, length, region === "code" || ctx.file.kind === "script")) g = asMention(g);
    else if (region === "prose" && isTableRow(ctx, offset)) g = lowered(g);
  }
  // Inside a comment or a pattern in code, or given as an example in a message, a match describes rather than does.
  const inCode = ctx.file.kind === "script" || region === "code";
  if (inCode && (inLineComment(ctx, offset) || inPatternLiteral(ctx, offset, length) || introducedAsExample(ctx, offset))) g = asMention(g);
  if (inRemoteCommand(ctx, offset)) g = lowered(g);
  // Minified or generated code: one line carries a whole library, so a match there says little about intent.
  if (ctx.file.kind === "script" && lineAround(ctx, offset).text.length > MINIFIED_LINE) g = lowered(g);
  const pc = pathContext(ctx.bundle, ctx.file);
  if (pc === "container") g = lowered(g);
  else if (pc) g = asMention(g);
  return g;
}
