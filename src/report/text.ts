import { atLeast, DEFAULT_POLICY, severityRank } from "../core/severity";
import type { BundleReport, Finding, JudgeNote, ScanReport, Severity, Verdict } from "../core/types";
import { clean, countsPhrase, describeBundles, formatLocation, plural, totalFindings, VERDICT_LABEL, verdictCounts } from "./shared";
import type { TextOptions } from "./types";

/** Human-readable terminal report. Plain ANSI codes, no dependencies; no escape codes at all when `color` is false. */

const ESC = String.fromCharCode(27);
const DEFAULT_WIDTH = 100;
const MIN_WRAP = 30;

type Paint = (s: string) => string;

interface Palette {
  readonly bold: Paint;
  readonly dim: Paint;
  readonly verdict: Readonly<Record<Verdict, Paint>>;
  readonly severity: Readonly<Record<Severity, Paint>>;
}

const sgr =
  (code: string): Paint =>
  (s) =>
    `${ESC}[${code}m${s}${ESC}[0m`;
const plain: Paint = (s) => s;

const COLORS: Palette = {
  bold: sgr("1"),
  dim: sgr("2"),
  verdict: { block: sgr("1;31"), warn: sgr("1;33"), pass: sgr("1;32") },
  severity: { critical: sgr("1;31"), high: sgr("31"), medium: sgr("33"), low: sgr("36"), info: sgr("2") },
};

const NO_COLORS: Palette = {
  bold: plain,
  dim: plain,
  verdict: { block: plain, warn: plain, pass: plain },
  severity: { critical: plain, high: plain, medium: plain, low: plain, info: plain },
};

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

function judgeLine(j: JudgeNote): string {
  const effect = j.effect === "none" ? "no change" : j.effect;
  const p = j.pTrue !== undefined ? ` (p=${j.pTrue.toFixed(2)})` : "";
  return `judge ${clean(j.model)}: ${effect}${p}`;
}

function findingLines(f: Finding, opts: TextOptions, c: Palette): string[] {
  const width = opts.width ?? DEFAULT_WIDTH;
  const label = c.severity[f.severity](f.severity.toUpperCase().padEnd(8));
  const where = clean(formatLocation(f.location));
  const low = f.confidence === "low" ? "  (low confidence)" : "";
  const oneLine = `  ${f.severity.padEnd(8)}  ${f.ruleId}  ${where}${low}`;
  // Too wide for one line: the location moves under the rule id rather than wrapping mid-path.
  const lines =
    oneLine.length <= width
      ? [`  ${label}  ${f.ruleId}  ${where}${c.dim(low)}`]
      : [`  ${label}  ${f.ruleId}`, ...wrap(where, width, " ".repeat(12), true), ...(low ? [c.dim(`${" ".repeat(12)}${low.trim()}`)] : [])];
  lines.push(...wrap(clean(f.message), width, "    "));
  if (f.location.snippet) lines.push(...wrap(clean(f.location.snippet), width, "    > ", true).map(c.dim));
  if (!opts.verbose) return lines;
  if (f.evidence) lines.push(...wrap(`evidence: ${clean(f.evidence)}`, width, "    ", true));
  if (f.remediation) lines.push(...wrap(`remediation: ${clean(f.remediation)}`, width, "    "));
  if (f.source !== "static" && f.source !== "correlation") lines.push(`    source: ${clean(f.source)}`);
  if (f.judge) lines.push(`    ${judgeLine(f.judge)}`);
  return lines;
}

function bundleLines(r: BundleReport, report: ScanReport, opts: TextOptions, c: Palette): string[] {
  const b = r.bundle;
  const where = b.root === "." ? report.target : b.root;
  const kind = b.kind === "skill" ? "" : ` (${b.kind})`;
  const lines = [`${c.verdict[r.verdict](VERDICT_LABEL[r.verdict].padEnd(5))}  ${c.bold(clean(b.name))}${kind}  ${c.dim(clean(where))}`];
  for (const note of b.notes) lines.push(...wrap(`note: ${clean(note)}`, opts.width ?? DEFAULT_WIDTH, "  "));
  const floor = opts.minSeverity ?? "low";
  const shown = r.findings.filter((f) => atLeast(f.severity, floor));
  for (const f of shown) lines.push(...findingLines(f, opts, c));
  const hidden = r.findings.length - shown.length;
  if (hidden > 0) {
    const note = `${plural(hidden, "finding")} below ${floor} not shown (--min-severity info shows all)`;
    lines.push(...wrap(note, opts.width ?? DEFAULT_WIDTH, "  ").map(c.dim));
  }
  return lines;
}

function policyLine(opts: TextOptions): string {
  const p = opts.policy ?? DEFAULT_POLICY;
  const warn = severityRank(p.warnAt) < severityRank(p.blockAt) ? `, warns at >= ${p.warnAt}` : "";
  return `Blocks at effective severity >= ${p.blockAt}${warn}; low-confidence findings count one level lower.`;
}

function analyzerLine(report: ScanReport): string | undefined {
  if (report.analyzers.length === 0) return undefined;
  const parts = report.analyzers.map((a) => `${clean(a.name)} ${a.status}${a.detail ? ` (${clean(a.detail)})` : ""}`);
  return `Analyzers: ${parts.join("; ")}.`;
}

function footerLines(report: ScanReport, opts: TextOptions): string[] {
  const width = opts.width ?? DEFAULT_WIDTH;
  const lines: string[] = [];
  const what = describeBundles(report);
  if (report.bundles.length === 0) lines.push(`No skills found in ${report.target}.`);
  else if (totalFindings(report) === 0) lines.push(`No findings in ${what}.`);
  else {
    const v = verdictCounts(report);
    lines.push(`Scanned ${what}: ${v.block} blocked, ${v.warn} warned, ${v.pass} passed.`);
    lines.push(`Findings: ${countsPhrase(report.counts)}.`);
  }
  if (report.verdict !== "pass") lines.push(policyLine(opts));
  if (report.suppressed > 0) lines.push(`${plural(report.suppressed, "finding")} suppressed by ignore entries in your config.`);
  const analyzers = analyzerLine(report);
  if (analyzers) lines.push(analyzers);
  if (report.verdict !== "pass") {
    lines.push("Reviewed the skill and still want it? Approve it with: skill-scanner trust <path>");
    lines.push('To silence a rule, add an "ignore" entry to ~/.skill-scanner/config.json');
  }
  return lines.flatMap((l) => wrap(l, width, ""));
}

export function formatText(report: ScanReport, opts: TextOptions): string {
  const c = opts.color ? COLORS : NO_COLORS;
  const blocks = report.bundles.map((r) => bundleLines(r, report, opts, c));
  const body: string[] = [];
  for (const block of blocks) {
    body.push(...block);
    // A bundle with only its header line stays compact; one with findings gets breathing room.
    if (block.length > 1) body.push("");
  }
  if (body.length > 0 && body.at(-1) !== "") body.push("");
  return `${[...body, ...footerLines(report, opts)].join("\n")}\n`;
}
