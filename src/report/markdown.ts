import { atLeast, DEFAULT_POLICY } from "../core/severity";
import type { BundleReport, Finding, ScanReport, Verdict } from "../core/types";
import { clean, countsPhrase, describeBundles, formatLocation, plural, totalFindings, VERDICT_LABEL } from "./shared";
import type { MarkdownOptions } from "./types";

/**
 * GitHub-flavored Markdown for PR comments and `$GITHUB_STEP_SUMMARY`. Skill text is untrusted, so
 * it never renders as HTML, links, or mentions: specials are escaped and URLs and @names are code.
 */

const DEFAULT_MAX_ROWS = 150;

const HEADLINE: Readonly<Record<Verdict, string>> = {
  block: "blocked",
  warn: "found issues to review in",
  pass: "passed",
};

/** Inline code that survives backticks in the content. */
export function inlineCode(s: string): string {
  const longest = Math.max(0, ...[...s.matchAll(/`+/g)].map((m) => m[0].length));
  const fence = "`".repeat(longest + 1);
  const pad = s.startsWith("`") || s.endsWith("`") || s.startsWith(" ") ? " " : "";
  return `${fence}${pad}${s}${pad}${fence}`;
}

const escapeText = (s: string): string => s.replace(/[\\`*_[\]<>~!&#{}()]/g, "\\$&");

/** Escaped Markdown text in which URLs and @mentions become code, so they are neither linked nor notified. */
export function mdText(s: string): string {
  return s
    .split(/((?:https?:\/\/|www\.)\S+|@[A-Za-z0-9][\w-]*)/)
    .map((part, i) => (i % 2 === 1 ? inlineCode(part) : escapeText(part)))
    .join("");
}

/** A table cell: pipes escaped (also inside code spans, per GFM tables) and no line breaks. */
const cell = (s: string): string => s.replace(/\r?\n/g, " ").replaceAll("|", "\\|");

function row(f: Finding): string {
  const cells = [f.severity, inlineCode(f.ruleId), inlineCode(clean(formatLocation(f.location))), mdText(clean(f.message))];
  return `| ${cells.map(cell).join(" | ")} |`;
}

function bundleSection(r: BundleReport, report: ScanReport, opts: MarkdownOptions, budget: { rows: number }): string[] {
  const floor = opts.minSeverity ?? "low";
  const shown = r.findings.filter((f) => atLeast(f.severity, floor));
  const where = r.bundle.root === "." ? report.target : r.bundle.root;
  const lines = [`### ${VERDICT_LABEL[r.verdict]} ${inlineCode(clean(r.bundle.name))} in ${inlineCode(clean(where))}`, ""];
  for (const note of r.bundle.notes) lines.push(`> Note: ${mdText(clean(note))}`, "");
  if (shown.length > 0) {
    lines.push("| Severity | Rule | Location | Message |", "| --- | --- | --- | --- |");
    const fits = shown.slice(0, Math.max(0, budget.rows));
    budget.rows -= fits.length;
    lines.push(...fits.map(row));
    if (fits.length < shown.length) lines.push("", `${plural(shown.length - fits.length, "more finding")} not shown.`);
    lines.push("");
  }
  const hidden = r.findings.length - shown.length;
  if (hidden > 0) lines.push(`${plural(hidden, "finding")} below ${floor} not shown.`, "");
  return lines;
}

function summaryLine(report: ScanReport, opts: MarkdownOptions): string {
  const what = describeBundles(report);
  if (report.bundles.length === 0) return "No skills found.";
  if (totalFindings(report) === 0) return `No findings in ${what}.`;
  const policy = opts.policy ?? DEFAULT_POLICY;
  const why =
    report.verdict === "pass" ? "" : ` Blocks at effective severity >= ${policy.blockAt}; low-confidence findings count one level lower.`;
  return `${countsPhrase(report.counts)} in ${what}.${why}`;
}

function footer(report: ScanReport): string[] {
  const parts = [`${report.tool.name} ${report.tool.version}`];
  if (report.suppressed > 0) parts.push(`${plural(report.suppressed, "finding")} suppressed`);
  for (const a of report.analyzers) parts.push(`${mdText(clean(a.name))} ${a.status}${a.detail ? `: ${mdText(clean(a.detail))}` : ""}`);
  return [`<sub>${parts.join(". ")}.</sub>`];
}

export function formatMarkdown(report: ScanReport, opts: MarkdownOptions = {}): string {
  const budget = { rows: opts.maxRows ?? DEFAULT_MAX_ROWS };
  const flagged = report.bundles.filter(
    (b) => b.verdict !== "pass" || b.findings.some((f) => atLeast(f.severity, opts.minSeverity ?? "low")),
  );
  const passed = report.bundles.filter((b) => !flagged.includes(b));
  const lines = [`## skill-scanner ${HEADLINE[report.verdict]} ${inlineCode(clean(report.target))}`, "", summaryLine(report, opts), ""];
  for (const b of flagged) lines.push(...bundleSection(b, report, opts, budget));
  if (passed.length > 0 && flagged.length > 0) {
    lines.push(`Passed: ${passed.map((b) => inlineCode(clean(b.bundle.name))).join(", ")}.`, "");
  }
  lines.push(...footer(report));
  return `${lines.join("\n")}\n`;
}
