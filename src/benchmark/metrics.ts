/**
 * Classification metrics for a benchmark arm: a bundle labelled malicious is a positive, and a
 * verdict counts as a detection at a chosen threshold (block, or warn-or-block). Pure: the harness
 * and the report generator feed it rows; tests feed it fixtures.
 */

export type Label = "malicious" | "benign";
export type Verdict = "pass" | "warn" | "block";
export type Threshold = "block" | "warn";

export interface Scored {
  readonly label: Label;
  readonly verdict: Verdict;
}

export interface Confusion {
  readonly tp: number;
  readonly fp: number;
  readonly fn: number;
  readonly tn: number;
}

export interface Metrics extends Confusion {
  readonly precision: number;
  readonly recall: number;
  readonly specificity: number;
  readonly f1: number;
  /** Balanced accuracy: the mean of recall and specificity, which a skewed corpus cannot inflate. */
  readonly balancedAccuracy: number;
  readonly total: number;
}

export function detects(verdict: Verdict, threshold: Threshold): boolean {
  return verdict === "block" || (threshold === "warn" && verdict === "warn");
}

export function confusion(rows: readonly Scored[], threshold: Threshold): Confusion {
  let tp = 0;
  let fp = 0;
  let fn = 0;
  let tn = 0;
  for (const r of rows) {
    const hit = detects(r.verdict, threshold);
    if (r.label === "malicious") {
      if (hit) tp += 1;
      else fn += 1;
    } else if (hit) fp += 1;
    else tn += 1;
  }
  return { tp, fp, fn, tn };
}

const ratio = (num: number, den: number): number => (den === 0 ? 0 : num / den);

export function metrics(rows: readonly Scored[], threshold: Threshold): Metrics {
  const c = confusion(rows, threshold);
  const precision = ratio(c.tp, c.tp + c.fp);
  const recall = ratio(c.tp, c.tp + c.fn);
  const specificity = ratio(c.tn, c.tn + c.fp);
  const f1 = ratio(2 * precision * recall, precision + recall);
  return { ...c, precision, recall, specificity, f1, balancedAccuracy: (recall + specificity) / 2, total: rows.length };
}

export interface CostInputs {
  /** Bytes sent to the judge across the arm. */
  readonly judgeBytes: number;
  /** Input tokens the provider reported, when it did; otherwise estimated from bytes. */
  readonly judgeTokensReported?: number;
  readonly usdPerMillionInputTokens: number;
  readonly bundles: number;
}

export interface Cost {
  readonly tokens: number;
  readonly tokensEstimated: boolean;
  readonly usd: number;
  readonly usdPer1000Bundles: number;
}

/** Four characters per token is the common estimate for English and code; the provider's count wins when given. */
export const CHARS_PER_TOKEN = 4;

export function cost(c: CostInputs): Cost {
  const estimated = c.judgeTokensReported === undefined;
  const tokens = estimated ? Math.round(c.judgeBytes / CHARS_PER_TOKEN) : c.judgeTokensReported!;
  const usd = (tokens / 1_000_000) * c.usdPerMillionInputTokens;
  return { tokens, tokensEstimated: estimated, usd, usdPer1000Bundles: c.bundles === 0 ? 0 : (usd / c.bundles) * 1000 };
}

export const pct = (x: number): string => `${(x * 100).toFixed(1)}%`;
