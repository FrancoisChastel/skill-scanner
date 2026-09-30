/**
 * Reporters: pure functions from a ScanReport to text in each output format.
 */
import { clip } from "../core/text";
import type { ScanReport } from "../core/types";
import { formatJson } from "./json";
import { formatMarkdown } from "./markdown";
import { formatSarif } from "./sarif";
import { clean, countsPhrase, describeBundles, formatLocation, sortedFindings, totalFindings } from "./shared";
import { formatText } from "./text";
import type { ReportFormat, ReportOptions } from "./types";

export { formatJson, type JsonBundle, type JsonFinding, type JsonReport, toJsonReport } from "./json";
export { formatMarkdown } from "./markdown";
export { formatSarif, type SarifLog, type SarifResult, type SarifRule, type SarifRun, toSarifLog } from "./sarif";
export { knownRules } from "./shared";
export { formatText } from "./text";
export {
  isReportFormat,
  type MarkdownOptions,
  REPORT_FORMATS,
  type ReportFormat,
  type ReportOptions,
  type SarifOptions,
  type TextOptions,
} from "./types";

export function formatReport(report: ScanReport, format: ReportFormat, opts: ReportOptions): string {
  return formatReports([report], format, opts);
}

/**
 * Several targets in one output: text and Markdown are concatenated, SARIF gets one run per
 * target, and JSON is an array (an object when there is exactly one report).
 */
export function formatReports(reports: readonly ScanReport[], format: ReportFormat, opts: ReportOptions): string {
  switch (format) {
    case "json":
      return formatJson(reports.length === 1 ? reports[0]! : reports);
    case "sarif":
      return formatSarif(reports, opts);
    case "markdown":
      return reports.map((r) => formatMarkdown(r, opts)).join("\n");
    case "text":
      return reports.map((r) => formatText(r, opts)).join("\n");
  }
}

const AGENT_LIMIT = 1500;
const AGENT_LINE_LIMIT = 300;
/** Room kept for the "- and N more." line. */
const AGENT_TAIL = 40;

/** A short, plain summary for hook messages: verdict, counts, and the top findings, one per line. */
export function summarizeForAgent(report: ScanReport, maxFindings = 5): string {
  const target = clean(report.target);
  if (report.verdict === "pass") {
    const n = totalFindings(report);
    return n === 0
      ? `skill-scanner found no issues in ${target}.`
      : `skill-scanner passed ${target} (${countsPhrase(report.counts)}, below the warning threshold).`;
  }
  const verb = report.verdict === "block" ? "blocked" : "flagged";
  const head = `skill-scanner ${verb} ${target}: ${countsPhrase(report.counts)}.`;
  const findings = sortedFindings(report);
  const lines = [clip(head, AGENT_LIMIT - AGENT_TAIL)];
  let used = lines[0]!.length;
  let listed = 0;
  for (const f of findings.slice(0, Math.max(0, maxFindings))) {
    const line = clip(`- [${f.severity}] ${f.ruleId} at ${clean(formatLocation(f.location))}: ${clean(f.message)}`, AGENT_LINE_LIMIT);
    if (used + 1 + line.length > AGENT_LIMIT - AGENT_TAIL) break;
    lines.push(line);
    used += 1 + line.length;
    listed += 1;
  }
  if (listed < findings.length) lines.push(`- and ${findings.length - listed} more.`);
  return lines.join("\n");
}

/** One line for stderr when the report itself went to a file. */
export function oneLineSummary(report: ScanReport): string {
  const counts = countsPhrase(report.counts);
  return `skill-scanner: ${report.verdict} for ${clean(report.target)} (${describeBundles(report)}${counts ? `; ${counts}` : ""})`;
}
