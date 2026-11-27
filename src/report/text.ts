import { atLeast, compareFindings, countBySeverity, DEFAULT_POLICY, severityRank } from "../core/severity";
import { type BundleReport, type Finding, type JudgeNote, type ScanReport, SEVERITIES, type Severity, type Verdict } from "../core/types";
import { clean, describeBundles, plural, VERDICT_LABEL, verdictCounts } from "./shared";
import { GLYPH, type Palette, palette, stripAnsi, visibleWidth, wrap } from "./style";
import type { TextOptions } from "./types";

export { wrap } from "./style";

/**
 * Human-readable terminal report. Each skill gets a verdict badge and its counts, then its findings
 * grouped by file: severity and title, what was found, and the quoted line with its number. A summary
 * closes the report. Plain ANSI codes, and none at all when `color` is false.
 */

const DEFAULT_WIDTH = 100;
/** Column of a skill's name, after the 7-column badge. */
const NAME = " ".repeat(9);
const FILE = "  ";
const FINDING = "    ";
/** Column where a finding's title, message, and quoted code start: after "    * CRITICAL  ". */
const BODY = " ".repeat(16);
/** Line numbers end here, so the gutter bar sits just left of BODY. */
const LINE_NO = BODY.length - 3;
const LABEL = 11;

const VERDICT_MEANING: Readonly<Record<Verdict, string>> = { block: "do not install", warn: "worth a look", pass: "passes" };
const DESCENDING: readonly Severity[] = [...SEVERITIES].reverse();

interface Layout {
  readonly width: number;
  readonly verbose: boolean;
  readonly c: Palette;
}

/** "2 critical, 4 high", each count in its severity's color. */
function coloredCounts(counts: Readonly<Record<Severity, number>>, c: Palette): string {
  return DESCENDING.filter((s) => counts[s] > 0)
    .map((s) => c.severity[s](`${counts[s]} ${s}`))
    .join(", ");
}

/** The first line of `lines` with `label` (which it starts with, after `indent`) dimmed. */
function dimLabel(lines: string[], indent: string, label: string, c: Palette): string[] {
  const [first = "", ...rest] = lines;
  return [`${indent}${c.dim(label)}${first.slice(indent.length + label.length)}`, ...rest];
}

function headerLines(f: Finding, { width, c }: Layout): string[] {
  const sev = f.severity.toUpperCase().padEnd(8);
  const title = clean(f.title) || f.ruleId;
  const low = f.confidence === "low" ? " (low confidence)" : "";
  const rule = title === f.ruleId ? "" : f.ruleId;
  const lead = `${FINDING}${c.severity[f.severity](`${GLYPH.dot} ${sev}`)}  `;
  if (BODY.length + title.length + low.length + 2 + rule.length <= width)
    return [`${lead}${c.bold(title)}${low ? c.dim(low) : ""}${rule ? `  ${c.dim(rule)}` : ""}`];
  // Too wide for one line: the title wraps at BODY and the rule id moves under it.
  const [first = "", ...rest] = wrap(`${title}${low}`, width, BODY);
  const ruleLines = rule ? wrap(rule, width, BODY, true).map(c.dim) : [];
  return [`${lead}${c.bold(first.slice(BODY.length))}`, ...rest.map(c.bold), ...ruleLines];
}

/** The message; when there is no quoted line to number, the line number goes at its end. */
function messageLines(f: Finding, { width, c }: Layout): string[] {
  const at = f.location.snippet || !f.location.line ? "" : `(line\u00A0${f.location.line})`;
  const lines = wrap(at ? `${clean(f.message)} ${at}` : clean(f.message), width, BODY);
  const last = lines.at(-1) ?? "";
  return at && last.endsWith(at) ? [...lines.slice(0, -1), `${last.slice(0, -at.length)}${c.dim(at)}`] : lines;
}

/** The quoted code, behind a gutter with its line number: "    10 | code". */
function codeLines(f: Finding, { width, c }: Layout): string[] {
  if (!f.location.snippet) return [];
  const num = f.location.line ? String(f.location.line) : "";
  const code = wrap(clean(f.location.snippet), width, BODY, true).map((l) => l.slice(BODY.length));
  return code.map((l, i) => `${c.dim(`${(i === 0 ? num : "").padStart(LINE_NO)} ${i === 0 ? GLYPH.bar : GLYPH.dots}`)} ${l}`);
}

function judgeLine(j: JudgeNote): string {
  const effect = j.effect === "none" ? "no change" : j.effect;
  const p = j.pTrue !== undefined ? ` (p=${j.pTrue.toFixed(2)})` : "";
  return `judge ${clean(j.model)}: ${effect}${p}`;
}

function verboseLines(f: Finding, { width, c }: Layout): string[] {
  const out: string[] = [];
  const add = (label: string, text: string, hard = false) =>
    out.push(...dimLabel(wrap(`${label} ${text}`, width, BODY, hard), BODY, label, c));
  if (f.evidence) add("evidence:", clean(f.evidence), true);
  if (f.remediation) add("remediation:", clean(f.remediation));
  if (f.source !== "static" && f.source !== "correlation") add("source:", clean(f.source));
  if (f.judge) out.push(`${BODY}${c.dim(judgeLine(f.judge))}`);
  return out;
}

function findingLines(f: Finding, layout: Layout): string[] {
  return [
    ...headerLines(f, layout),
    ...messageLines(f, layout),
    ...codeLines(f, layout),
    ...(layout.verbose ? verboseLines(f, layout) : []),
  ];
}

/** Findings by file, files in the order of their most severe finding, each file's findings most severe first. */
function byFile(findings: readonly Finding[]): ReadonlyMap<string, readonly Finding[]> {
  const groups = new Map<string, Finding[]>();
  for (const f of [...findings].sort(compareFindings)) groups.set(f.location.file, [...(groups.get(f.location.file) ?? []), f]);
  return groups;
}

function bundleHeader(r: BundleReport, report: ScanReport, { width, c }: Layout): string[] {
  const b = r.bundle;
  const where = b.root === "." ? report.target : b.root;
  const kind = b.kind === "skill" ? "" : ` (${b.kind})`;
  const label = VERDICT_LABEL[r.verdict];
  const badge = `${c.badge[r.verdict](` ${label} `)}${" ".repeat(5 - label.length)}`;
  const lines = [`${badge}  ${c.bold(clean(b.name))}${kind}  ${c.dim(clean(where))}`];
  if (r.findings.length > 0) {
    const meaning = c.verdict[r.verdict](VERDICT_MEANING[r.verdict]);
    lines.push(...fitOrWrap(`${meaning} ${c.dim(GLYPH.sep)} ${coloredCounts(countBySeverity(r.findings), c)}`, width, NAME));
  }
  for (const note of b.notes) lines.push(...wrap(`note: ${clean(note)}`, width, NAME).map(c.dim));
  return lines;
}

function bundleLines(r: BundleReport, report: ScanReport, opts: TextOptions, layout: Layout): string[] {
  const { width, c } = layout;
  const lines = bundleHeader(r, report, layout);
  const floor = opts.minSeverity ?? "low";
  const shown = r.findings.filter((f) => atLeast(f.severity, floor));
  for (const [file, findings] of byFile(shown)) {
    lines.push("", `${FILE}${c.underline(c.bold(clean(file)))}`);
    // A blank line between findings, so each reads as one block.
    lines.push(...findings.flatMap((f, i) => [...(i > 0 ? [""] : []), ...findingLines(f, layout)]));
  }
  const hidden = r.findings.length - shown.length;
  if (hidden > 0) {
    const note = `${plural(hidden, "finding")} below ${floor} not shown (--min-severity info shows all)`;
    lines.push(...(shown.length > 0 ? [""] : []), ...wrap(note, width, FILE).map(c.dim));
  }
  return lines;
}

/** `colored` after `indent` when it fits on one line; otherwise its plain text, wrapped. */
function fitOrWrap(colored: string, width: number, indent: string): string[] {
  return indent.length + visibleWidth(colored) <= width ? [indent + colored] : wrap(stripAnsi(colored), width, indent);
}

/** "  Label      value", the value wrapped under itself when it does not fit. */
function field(label: string, value: string, { width, c }: Layout): string[] {
  const indent = " ".repeat(FILE.length + LABEL);
  const [first = "", ...rest] = fitOrWrap(value, width, indent);
  return [`${FILE}${c.dim(label.padEnd(LABEL))}${first.slice(indent.length)}`, ...rest];
}

function policyText(opts: TextOptions): string {
  const p = opts.policy ?? DEFAULT_POLICY;
  const warn = severityRank(p.warnAt) < severityRank(p.blockAt) ? `, warns from ${p.warnAt}` : "";
  return `blocks from ${p.blockAt}${warn}; low-confidence findings count one level lower`;
}

function analyzersText(report: ScanReport, c: Palette): string {
  const status = { ran: c.ok, skipped: c.warn, failed: c.bad } as const;
  return report.analyzers
    .map((a) => `${clean(a.name)} ${status[a.status](a.status)}${a.detail ? c.dim(` (${clean(a.detail)})`) : ""}`)
    .join(` ${c.dim(GLYPH.sep)} `);
}

function scannedText(report: ScanReport, c: Palette): string {
  const v = verdictCounts(report);
  const count = (verdict: Verdict, word: string) => (v[verdict] > 0 ? c.verdict[verdict] : c.dim)(`${v[verdict]} ${word}`);
  return `${describeBundles(report)}: ${count("block", "blocked")}, ${count("warn", "warned")}, ${count("pass", "passed")}`;
}

function summaryLines(report: ScanReport, opts: TextOptions, layout: Layout): string[] {
  const { width, c } = layout;
  const findings = coloredCounts(report.counts, c);
  const lines = [
    c.dim(GLYPH.rule.repeat(Math.min(width, DEFAULT_WIDTH))),
    ...field("Scanned", scannedText(report, c), layout),
    ...field("Findings", findings || c.ok("none"), layout),
  ];
  if (report.verdict !== "pass") lines.push(...field("Policy", policyText(opts), layout));
  if (report.suppressed > 0)
    lines.push(...field("Suppressed", `${plural(report.suppressed, "finding")}, by ignore entries in your config`, layout));
  if (report.analyzers.length > 0) lines.push(...field("Analyzers", analyzersText(report, c), layout));
  if (report.verdict === "pass") return lines;
  return [
    ...lines,
    "",
    ...nextStep("Reviewed the skill and still want it?", "skill-scanner trust <path>", layout),
    ...nextStep("To silence a rule, add an", '"ignore" entry to ~/.skill-scanner/config.json', layout),
  ];
}

/** "  > text command", the command highlighted when the step fits on one line. */
function nextStep(text: string, command: string, { width, c }: Layout): string[] {
  const indent = `${FILE}  `;
  if (indent.length + text.length + 1 + command.length <= width) return [`${FILE}${c.accent(GLYPH.arrow)} ${text} ${c.accent(command)}`];
  const [first = "", ...rest] = wrap(`${text} ${command}`, width, indent);
  return [`${FILE}${c.accent(GLYPH.arrow)} ${first.slice(indent.length)}`, ...rest];
}

export function formatText(report: ScanReport, opts: TextOptions): string {
  if (report.bundles.length === 0) return `No skills found in ${report.target}.\n`;
  const layout: Layout = { width: opts.width ?? DEFAULT_WIDTH, verbose: opts.verbose ?? false, c: palette(opts.color) };
  const body: string[] = [];
  for (const r of report.bundles) {
    const block = bundleLines(r, report, opts, layout);
    body.push(...block);
    // A skill with only its header line stays compact; one with findings gets breathing room.
    if (block.length > 1) body.push("");
  }
  if (body.at(-1) !== "") body.push("");
  return `${[...body, ...summaryLines(report, opts, layout)].join("\n")}\n`;
}
