import { CONFIDENCES, type Confidence, type Finding, SEVERITIES, type Severity, type Verdict } from "./types";

export const severityRank = (s: Severity): number => SEVERITIES.indexOf(s);
export const confidenceRank = (c: Confidence): number => CONFIDENCES.indexOf(c);

export const atLeast = (s: Severity, floor: Severity): boolean => severityRank(s) >= severityRank(floor);

export function isSeverity(value: unknown): value is Severity {
  return typeof value === "string" && (SEVERITIES as readonly string[]).includes(value);
}

/** One step down, never below `info`. */
export function demote(s: Severity): Severity {
  return SEVERITIES[Math.max(0, severityRank(s) - 1)]!;
}

/** One step up, never above `critical`. */
export function promote(s: Severity): Severity {
  return SEVERITIES[Math.min(SEVERITIES.length - 1, severityRank(s) + 1)]!;
}

export function lowerConfidence(c: Confidence): Confidence {
  return CONFIDENCES[Math.max(0, confidenceRank(c) - 1)]!;
}

/**
 * The severity a finding counts for when deciding a verdict. Low confidence costs one step,
 * so a hunch never blocks on its own but still shows up as a warning.
 */
export function effectiveSeverity(f: Pick<Finding, "severity" | "confidence">): Severity {
  return f.confidence === "low" ? demote(f.severity) : f.severity;
}

export interface VerdictPolicy {
  /** Block when any finding's effective severity reaches this. Default `high`. */
  readonly blockAt: Severity;
  /** Warn when any finding's effective severity reaches this. Default `medium`. */
  readonly warnAt: Severity;
}

export const DEFAULT_POLICY: VerdictPolicy = Object.freeze({ blockAt: "high", warnAt: "medium" });

export function verdictFor(findings: readonly Finding[], policy: VerdictPolicy = DEFAULT_POLICY): Verdict {
  let verdict: Verdict = "pass";
  for (const f of findings) {
    const s = effectiveSeverity(f);
    if (atLeast(s, policy.blockAt)) return "block";
    if (atLeast(s, policy.warnAt)) verdict = "warn";
  }
  return verdict;
}

const VERDICT_ORDER: readonly Verdict[] = ["pass", "warn", "block"];
export const worstVerdict = (verdicts: readonly Verdict[]): Verdict =>
  verdicts.reduce<Verdict>((acc, v) => (VERDICT_ORDER.indexOf(v) > VERDICT_ORDER.indexOf(acc) ? v : acc), "pass");

export function countBySeverity(findings: readonly Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const f of findings) counts[f.severity] += 1;
  return counts;
}

/** Most severe first, then by file and line, so output is stable. */
export function compareFindings(a: Finding, b: Finding): number {
  return (
    severityRank(b.severity) - severityRank(a.severity) ||
    confidenceRank(b.confidence) - confidenceRank(a.confidence) ||
    a.location.file.localeCompare(b.location.file) ||
    (a.location.line ?? 0) - (b.location.line ?? 0) ||
    a.ruleId.localeCompare(b.ruleId)
  );
}
