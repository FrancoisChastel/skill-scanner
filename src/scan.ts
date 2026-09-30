import { analyzeBundle } from "./core/engine";
import type { Rule } from "./core/rule";
import { compareFindings, countBySeverity, DEFAULT_POLICY, type VerdictPolicy, verdictFor, worstVerdict } from "./core/severity";
import { isSuppressed, type Suppression } from "./core/suppress";
import type { AnalyzerRun, BundleReport, Finding, ScanReport, SkillBundle } from "./core/types";
import { type CollectLimits, collect, DEFAULT_LIMITS } from "./io/collect";
import { BUILTIN_RULES } from "./rules";
import { TOOL_NAME, VERSION } from "./version";

/** An optional second opinion on one bundle. It may confirm or doubt findings, and add its own. */
export interface BundleJudge {
  readonly name: string;
  review(bundle: SkillBundle, findings: readonly Finding[], signal?: AbortSignal): Promise<JudgeReview>;
}

export interface JudgeReview {
  readonly status: "ok" | "skipped" | "failed";
  readonly detail?: string;
  /** The findings after review. Must contain every input finding, possibly annotated. */
  readonly findings: readonly Finding[];
}

/** An optional external open-source tool run over the whole target. */
export interface ExternalAnalyzer {
  readonly name: string;
  /** Resolves to a reason string when the tool cannot run here, undefined when it can. */
  unavailable(): Promise<string | undefined>;
  /** Findings with `location.file` relative to `root` and `bundle` left empty; the scanner assigns bundles. */
  run(root: string, signal?: AbortSignal): Promise<Finding[]>;
}

export interface ScanOptions {
  readonly rules?: readonly Rule[];
  readonly policy?: VerdictPolicy;
  readonly limits?: Partial<CollectLimits>;
  readonly suppressions?: readonly Suppression[];
  readonly judge?: BundleJudge;
  readonly analyzers?: readonly ExternalAnalyzer[];
  /** Only report on skills with these names (case-insensitive); other bundles are dropped. */
  readonly onlySkills?: readonly string[];
  /** What to call the target in the report. Defaults to the path. */
  readonly label?: string;
  readonly signal?: AbortSignal;
  readonly now?: () => Date;
}

export async function scanPath(target: string, opts: ScanOptions = {}): Promise<ScanReport> {
  const now = opts.now ?? (() => new Date());
  const started = now();
  const t0 = performance.now();
  const { root, bundles: all } = await collect(target, { ...DEFAULT_LIMITS, ...opts.limits });
  const wanted = opts.onlySkills?.map((s) => s.toLowerCase());
  const bundles = wanted
    ? all.filter((b) => b.kind !== "skill" || wanted.includes(b.name.toLowerCase()) || wanted.includes(b.dirName.toLowerCase()))
    : all;

  const rules = opts.rules ?? BUILTIN_RULES;
  const policy = opts.policy ?? DEFAULT_POLICY;
  const analyzerRuns: AnalyzerRun[] = [];
  const external = await runAnalyzers(root, opts.analyzers ?? [], analyzerRuns, opts.signal);
  let suppressed = 0;
  const reports: BundleReport[] = [];

  for (const bundle of bundles) {
    let findings: Finding[] = [
      ...analyzeBundle(bundle, { rules }),
      ...external.filter((f) => ownerOf(f.location.file, bundles) === bundle).map((f) => ({ ...f, bundle: bundle.name })),
    ];
    if (opts.judge) {
      const review = await safeReview(opts.judge, bundle, findings, opts.signal);
      findings = [...review.findings];
      recordRun(analyzerRuns, opts.judge.name, review.status, review.detail);
    }
    const kept = findings.filter((f) => {
      if (isSuppressed(f, bundle.digest, opts.suppressions ?? [])) {
        suppressed += 1;
        return false;
      }
      return true;
    });
    kept.sort(compareFindings);
    reports.push({ bundle, findings: kept, verdict: verdictFor(kept, policy) });
  }

  const allFindings = reports.flatMap((r) => r.findings);
  return {
    schemaVersion: 1,
    tool: { name: TOOL_NAME, version: VERSION },
    target: opts.label ?? target,
    startedAt: started.toISOString(),
    durationMs: Math.round(performance.now() - t0),
    bundles: reports,
    verdict: worstVerdict(reports.map((r) => r.verdict)),
    counts: countBySeverity(allFindings),
    analyzers: analyzerRuns,
    suppressed,
  };
}

/** The bundle a path relative to the scan root belongs to: the deepest skill root containing it, else the root bundle. */
function ownerOf(file: string, bundles: readonly SkillBundle[]): SkillBundle | undefined {
  let best: SkillBundle | undefined;
  for (const b of bundles) {
    if (b.root === ".") continue;
    if ((file === b.root || file.startsWith(`${b.root}/`)) && (!best || b.root.length > best.root.length)) best = b;
  }
  return best ?? bundles.find((b) => b.root === ".");
}

async function runAnalyzers(
  root: string,
  analyzers: readonly ExternalAnalyzer[],
  runs: AnalyzerRun[],
  signal?: AbortSignal,
): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const a of analyzers) {
    const why = await a.unavailable().catch((e: unknown) => String(e));
    if (why) {
      runs.push({ name: a.name, status: "skipped", detail: why });
      continue;
    }
    try {
      out.push(...(await a.run(root, signal)));
      runs.push({ name: a.name, status: "ran" });
    } catch (e) {
      runs.push({ name: a.name, status: "failed", detail: e instanceof Error ? e.message : String(e) });
    }
  }
  return out;
}

async function safeReview(judge: BundleJudge, bundle: SkillBundle, findings: Finding[], signal?: AbortSignal): Promise<JudgeReview> {
  try {
    const review = await judge.review(bundle, findings, signal);
    // A judge may annotate or add findings but never drop one.
    if (review.findings.length < findings.length)
      return { status: "failed", detail: "judge dropped findings; its review was ignored", findings };
    return review;
  } catch (e) {
    return { status: "failed", detail: e instanceof Error ? e.message : String(e), findings };
  }
}

function recordRun(runs: AnalyzerRun[], name: string, status: "ok" | "skipped" | "failed", detail?: string): void {
  const existing = runs.find((r) => r.name === name);
  const mapped = status === "ok" ? "ran" : status;
  if (!existing) {
    runs.push({ name, status: mapped, ...(detail ? { detail } : {}) });
    return;
  }
  // Summarize across bundles: any failure wins, then any run.
  if (existing.status !== "failed" && mapped !== existing.status && (mapped === "failed" || mapped === "ran")) {
    runs[runs.indexOf(existing)] = { name, status: mapped, ...(detail ? { detail } : {}) };
  }
}
