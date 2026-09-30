import { roleOf } from "./classify";
import { pathContext } from "./context";
import { findEncodedBlobs } from "./decode";
import { extractEmbedded } from "./embedded";
import { segmentMarkdown } from "./markdown";
import type { BundleContext, FileContext, FileRule, Hit, Rule, Signal } from "./rule";
import { redactSecrets } from "./secrets";
import { compareFindings, demote, severityRank } from "./severity";
import { clip, indexLines, type LineIndex, lineText, positionAt, revealInvisible, snippetAt } from "./text";
import type { Finding, Location, SkillBundle, SkillFile } from "./types";

export interface AnalyzeOptions {
  readonly rules: readonly Rule[];
  /** How many layers of encoding to peel. Default 2. */
  readonly maxDecodeDepth?: number;
}

const MAX_FINDINGS_PER_BUNDLE = 500;

/** Run every rule over one bundle. Pure: the bundle already holds file contents. */
export function analyzeBundle(bundle: SkillBundle, opts: AnalyzeOptions): Finding[] {
  const fileRules = opts.rules.filter((r): r is FileRule => r.scope === "file");
  const bundleRules = opts.rules.filter((r) => r.scope === "bundle");
  const { virtualFiles } = extractEmbedded(bundle);
  const findings: Finding[] = [];
  const signals: Signal[] = [];
  const depth = opts.maxDecodeDepth ?? 2;

  for (const file of [...bundle.files, ...virtualFiles]) {
    if (file.text === undefined) continue;
    scanText(bundle, file, file.text, fileRules, findings, signals, { depth, origin: undefined });
  }

  for (const rule of bundleRules) {
    const ctx: BundleContext = {
      bundle,
      signals,
      report: (f) =>
        findings.push({
          ruleId: rule.id,
          title: rule.title,
          category: rule.category,
          severity: f.severity ?? rule.severity,
          confidence: f.confidence ?? rule.confidence,
          message: redactSecrets(f.message),
          location: {
            file: joinPath(bundle.root, f.file),
            ...(f.line ? { line: f.line } : {}),
            ...(f.snippet ? { snippet: clip(redactSecrets(revealInvisible(f.snippet)), 160) } : {}),
          },
          bundle: bundle.name,
          source: rule.id.startsWith("correlation/") ? "correlation" : "static",
          ...(f.evidence ? { evidence: redactSecrets(f.evidence) } : {}),
          ...(rule.remediation ? { remediation: rule.remediation } : {}),
        }),
    };
    rule.check(ctx);
  }
  return dedupe(findings).sort(compareFindings).slice(0, MAX_FINDINGS_PER_BUNDLE);
}

interface Origin {
  /** Location in the real file where the encoded payload sits. */
  readonly location: Location;
  readonly encoding: string;
}

function scanText(
  bundle: SkillBundle,
  file: SkillFile,
  text: string,
  rules: readonly FileRule[],
  findings: Finding[],
  signals: Signal[],
  state: { depth: number; origin: Origin | undefined },
): void {
  const index = indexLines(text);
  const isMarkdown = file.kind === "skill-md" || file.kind === "markdown";
  const fmEnd = file.kind === "skill-md" && bundle.frontmatter ? offsetOfLine(index, bundle.frontmatter.bodyStartLine) : 0;
  const regions = isMarkdown && !state.origin ? segmentMarkdown(text, fmEnd) : undefined;
  const role = roleOf(file, bundle.kind);
  const decoded = state.origin !== undefined;

  for (const rule of rules) {
    if (!rule.kinds.includes(file.kind)) continue;
    if (rule.languages && (!file.language || !rule.languages.includes(file.language))) continue;
    const ctx: FileContext = {
      bundle,
      file,
      text,
      index,
      role,
      ...(regions ? { regions } : {}),
      ...(decoded ? { decoded } : {}),
      report: (hit) => findings.push(toFinding(rule, bundle, file, index, hit, state.origin)),
      signal: (tag, offset, detail) => {
        const loc = state.origin?.location ?? locate(bundle, file, index, offset);
        // Signals carry bundle-relative paths, like every other bundle-rule input.
        signals.push({ tag, file: stripRoot(bundle.root, loc.file), offset, line: loc.line ?? 1, detail: clip(detail, 120) });
      },
    };
    try {
      rule.check(ctx);
    } catch (e) {
      findings.push(internalError(rule.id, bundle, file, e));
    }
  }

  if (state.depth <= 0 || file.kind === "binary") return;
  for (const blob of findEncodedBlobs(text)) {
    const location = state.origin?.location ?? locate(bundle, file, index, blob.start, blob.end - blob.start);
    const before = findings.length;
    const payload: SkillFile = {
      path: `${file.path}#${blob.encoding}@${location.line ?? 1}`,
      kind: "script",
      language: "shell",
      size: blob.decoded.length,
      text: blob.decoded,
    };
    scanText(bundle, payload, blob.decoded, rules, findings, signals, {
      depth: state.depth - 1,
      origin: { location, encoding: blob.encoding },
    });
    const hidden = findings.slice(before).filter((f) => severityRank(f.severity) >= severityRank("medium"));
    if (hidden.length > 0) {
      const worst = hidden.reduce((a, b) => (severityRank(b.severity) > severityRank(a.severity) ? b : a));
      const severity = severityRank(worst.severity) >= severityRank("high") ? "critical" : "high";
      // A payload in a test fixture or an attack write-up is a sample, unless the skill runs that file.
      const where = state.origin ? undefined : pathContext(bundle, file);
      findings.push({
        ruleId: "obfuscation/encoded-payload",
        title: "Encoded payload hides risky content",
        category: "obfuscation",
        severity: where === "dev" || where === "educational" ? demote(severity) : severity,
        confidence: where ? "low" : "high",
        message: `${blob.encoding}-encoded text decodes to content that triggers: ${[...new Set(hidden.map((f) => f.ruleId))].join(", ")}`,
        location,
        bundle: bundle.name,
        source: "static",
        evidence: clip(redactSecrets(revealInvisible(blob.decoded)), 400),
        remediation: "Do not install. Legitimate skills have no reason to hide commands or instructions behind an encoding.",
      });
    }
  }
}

function toFinding(rule: FileRule, bundle: SkillBundle, file: SkillFile, index: LineIndex, hit: Hit, origin: Origin | undefined): Finding {
  const location = origin?.location ?? locate(bundle, file, index, hit.offset, hit.length);
  const base = hit.message ?? rule.description;
  const message = origin
    ? `In ${origin.encoding}-decoded content: ${base}`
    : file.virtualOf
      ? `${describeVirtual(file.path)}: ${base}`
      : base;
  const evidence =
    hit.evidence ?? (origin ? clip(redactSecrets(revealInvisible(linesAround(index, hit.offset, hit.length))), 300) : undefined);
  return {
    ruleId: rule.id,
    title: rule.title,
    category: rule.category,
    severity: hit.severity ?? rule.severity,
    confidence: hit.confidence ?? rule.confidence,
    message: redactSecrets(message),
    location,
    bundle: bundle.name,
    source: "static",
    ...(evidence ? { evidence: redactSecrets(evidence) } : {}),
    ...(rule.remediation ? { remediation: rule.remediation } : {}),
  };
}

function describeVirtual(path: string): string {
  const pointer = path.slice(path.indexOf("#") + 1);
  if (pointer.startsWith("scripts.")) return `npm script '${pointer.slice(8)}'`;
  if (pointer.includes("hooks")) return `hook command (${pointer})`;
  if (pointer.startsWith("mcp")) return `MCP server launch command (${pointer})`;
  if (pointer.startsWith("load-shell")) return "shell command expanded when the skill loads";
  return `embedded command (${pointer})`;
}

function locate(bundle: SkillBundle, file: SkillFile, index: LineIndex, offset: number, length = 0): Location {
  if (file.virtualOf) {
    const { line } = positionAt(index, offset);
    return {
      file: joinPath(bundle.root, file.virtualOf.path),
      line: file.virtualOf.line + line - 1,
      snippet: safeSnippet(index, offset, length),
    };
  }
  const { line, column } = positionAt(index, offset);
  return { file: joinPath(bundle.root, file.path), line, column, snippet: safeSnippet(index, offset, length) };
}

/**
 * A bounded snippet with secrets masked. Masking happens on the whole line first, so a token cut
 * in half by the snippet window can never leak its visible part.
 */
function safeSnippet(index: LineIndex, offset: number, length: number): string {
  const { line } = positionAt(index, offset);
  const full = lineText(index, line);
  const masked = redactSecrets(full);
  if (masked === full) return snippetAt(index, offset, length);
  return clip(revealInvisible(masked.trim()), 160);
}

/** The full lines covering a span, so evidence never starts or ends inside a token. */
function linesAround(index: LineIndex, offset: number, length: number): string {
  const first = positionAt(index, offset).line;
  const last = positionAt(index, offset + Math.max(0, length - 1)).line;
  const out: string[] = [];
  for (let l = first; l <= last && out.length < 5; l += 1) out.push(lineText(index, l));
  return out.join("\n");
}

function offsetOfLine(index: LineIndex, line: number): number {
  return index.starts[line - 1] ?? index.text.length;
}

function stripRoot(root: string, path: string): string {
  return root === "." || root === "" || !path.startsWith(`${root}/`) ? path : path.slice(root.length + 1);
}

export function joinPath(root: string, path: string): string {
  return root === "." || root === "" ? path : `${root}/${path}`;
}

function internalError(ruleId: string, bundle: SkillBundle, file: SkillFile, e: unknown): Finding {
  return {
    ruleId: "scanner/rule-error",
    title: "A rule failed on this file",
    category: "packaging",
    severity: "low",
    confidence: "low",
    message: `rule ${ruleId} threw: ${e instanceof Error ? e.message : String(e)}. The file was only partly analyzed.`,
    location: { file: joinPath(bundle.root, file.virtualOf?.path ?? file.path) },
    bundle: bundle.name,
    source: "static",
  };
}

/** One finding per rule and line; keep the most severe. */
function dedupe(findings: readonly Finding[]): Finding[] {
  const best = new Map<string, Finding>();
  for (const f of findings) {
    const key = `${f.ruleId}\0${f.location.file}\0${f.location.line ?? 0}`;
    const prev = best.get(key);
    if (!prev || severityRank(f.severity) > severityRank(prev.severity)) best.set(key, f);
  }
  return [...best.values()];
}
