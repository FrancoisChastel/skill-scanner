import type { AnalyzerRun, BundleKind, BundleReport, Finding, JudgeNote, Location, ScanReport, Severity, Verdict } from "../core/types";
import { clean } from "./shared";

/**
 * Machine-readable report. `schemaVersion` changes only on breaking changes. File contents never
 * appear: a bundle is described by its name, root, digest, and file count, and findings carry
 * only the bounded, redacted snippet the rule chose.
 */

export interface JsonFinding {
  readonly ruleId: string;
  readonly title: string;
  readonly category: Finding["category"];
  readonly severity: Severity;
  readonly confidence: Finding["confidence"];
  readonly message: string;
  readonly location: Location;
  readonly bundle: string;
  readonly source: Finding["source"];
  readonly evidence?: string;
  readonly remediation?: string;
  readonly judge?: JudgeNote;
}

export interface JsonBundle {
  readonly name: string;
  readonly kind: BundleKind;
  readonly root: string;
  readonly digest: string;
  readonly verdict: Verdict;
  readonly fileCount: number;
  readonly notes: readonly string[];
  readonly findings: readonly JsonFinding[];
}

export interface JsonReport {
  readonly schemaVersion: 1;
  readonly tool: { readonly name: string; readonly version: string };
  readonly target: string;
  readonly verdict: Verdict;
  readonly counts: Readonly<Record<Severity, number>>;
  readonly suppressed: number;
  readonly startedAt: string;
  readonly durationMs: number;
  readonly analyzers: readonly AnalyzerRun[];
  readonly bundles: readonly JsonBundle[];
}

function toJsonFinding(f: Finding): JsonFinding {
  const loc = f.location;
  return {
    ruleId: f.ruleId,
    title: clean(f.title),
    category: f.category,
    severity: f.severity,
    confidence: f.confidence,
    message: clean(f.message),
    location: {
      file: clean(loc.file),
      ...(loc.line !== undefined ? { line: loc.line } : {}),
      ...(loc.column !== undefined ? { column: loc.column } : {}),
      ...(loc.endLine !== undefined ? { endLine: loc.endLine } : {}),
      ...(loc.snippet !== undefined ? { snippet: clean(loc.snippet) } : {}),
    },
    bundle: clean(f.bundle),
    source: f.source,
    ...(f.evidence !== undefined ? { evidence: clean(f.evidence) } : {}),
    ...(f.remediation !== undefined ? { remediation: clean(f.remediation) } : {}),
    ...(f.judge ? { judge: { ...f.judge, model: clean(f.judge.model) } } : {}),
  };
}

function toJsonBundle(r: BundleReport): JsonBundle {
  const b = r.bundle;
  return {
    name: clean(b.name),
    kind: b.kind,
    root: clean(b.root),
    digest: b.digest,
    verdict: r.verdict,
    fileCount: b.files.length,
    notes: b.notes.map(clean),
    findings: r.findings.map(toJsonFinding),
  };
}

export function toJsonReport(report: ScanReport): JsonReport {
  return {
    schemaVersion: 1,
    tool: { name: report.tool.name, version: report.tool.version },
    target: report.target,
    verdict: report.verdict,
    counts: { ...report.counts },
    suppressed: report.suppressed,
    startedAt: report.startedAt,
    durationMs: report.durationMs,
    analyzers: report.analyzers.map((a) => ({ name: a.name, status: a.status, ...(a.detail ? { detail: clean(a.detail) } : {}) })),
    bundles: report.bundles.map(toJsonBundle),
  };
}

/** One report as an object, several as an array. Pretty printed with a trailing newline. */
export function formatJson(reports: ScanReport | readonly ScanReport[]): string {
  const value = Array.isArray(reports) ? (reports as readonly ScanReport[]).map(toJsonReport) : toJsonReport(reports as ScanReport);
  return `${JSON.stringify(value, null, 2)}\n`;
}
