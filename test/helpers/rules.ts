import { expect } from "bun:test";
import { effectiveSeverity, severityRank } from "../../src/core/severity";
import type { Confidence, Finding, Severity } from "../../src/core/types";
import { type BundleOptions, type FileSpec, scanFiles } from "./bundle";

/**
 * Assertions for rule tests. Every catalog rule has a `describe("<rule id>", ...)` block in
 * test/rules with at least one `expectFinding` (a positive case) and one `expectQuiet` or
 * `expectNone` (a realistic negative); test/rules/catalog.test.ts enforces it.
 */

type Files = Readonly<Record<string, FileSpec>>;

export interface Expected {
  readonly severity?: Severity;
  readonly confidence?: Confidence;
  /** Substring the message must contain. */
  readonly message?: string;
  /** Path (relative to the scan root) the finding must point at. */
  readonly file?: string;
}

/** The findings of one rule for an in-memory bundle. */
export function findings(files: Files, ruleId: string, opts: BundleOptions = {}): Finding[] {
  return scanFiles(files, opts).findings.filter((f) => f.ruleId === ruleId);
}

/** Assert the rule fires, and return its most severe finding. */
export function expectFinding(files: Files, ruleId: string, want: Expected = {}, opts: BundleOptions = {}): Finding {
  const found = findings(files, ruleId, opts);
  expect(found.map((f) => f.ruleId)).toContain(ruleId);
  const best = found.reduce((a, b) => (severityRank(b.severity) > severityRank(a.severity) ? b : a));
  if (want.severity) expect(best.severity).toBe(want.severity);
  if (want.confidence) expect(best.confidence).toBe(want.confidence);
  if (want.message) expect(best.message).toContain(want.message);
  if (want.file) expect(best.location.file).toBe(want.file);
  return best;
}

/** Assert the rule does not fire at all. */
export function expectNone(files: Files, ruleId: string, opts: BundleOptions = {}): void {
  expect(findings(files, ruleId, opts).map((f) => `${f.location.file}:${f.location.line ?? ""} ${f.message}`)).toEqual([]);
}

/**
 * Assert the rule may still report, but nothing it reports counts toward a warning: every finding's
 * effective severity (low confidence costs a step) stays below medium.
 */
export function expectQuiet(files: Files, ruleId: string, opts: BundleOptions = {}): void {
  const loud = findings(files, ruleId, opts).filter((f) => severityRank(effectiveSeverity(f)) >= severityRank("medium"));
  expect(loud.map((f) => `${f.severity}/${f.confidence} ${f.location.file}:${f.location.line ?? ""} ${f.message}`)).toEqual([]);
}
