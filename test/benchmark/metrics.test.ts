import { describe, expect, test } from "bun:test";
import { confusion, cost, detects, metrics, pct, type Scored } from "../../src/benchmark/metrics";

const rows: Scored[] = [
  { label: "malicious", verdict: "block" },
  { label: "malicious", verdict: "warn" },
  { label: "malicious", verdict: "pass" },
  { label: "benign", verdict: "pass" },
  { label: "benign", verdict: "warn" },
  { label: "benign", verdict: "block" },
];

describe("detects", () => {
  test("block counts at both thresholds, warn only at the warn threshold", () => {
    expect(detects("block", "block")).toBe(true);
    expect(detects("warn", "block")).toBe(false);
    expect(detects("warn", "warn")).toBe(true);
    expect(detects("pass", "warn")).toBe(false);
  });
});

describe("confusion and metrics", () => {
  test("counts each quadrant at the block threshold", () => {
    expect(confusion(rows, "block")).toEqual({ tp: 1, fp: 1, fn: 2, tn: 2 });
  });

  test("counts each quadrant at the warn threshold", () => {
    expect(confusion(rows, "warn")).toEqual({ tp: 2, fp: 2, fn: 1, tn: 1 });
  });

  test("derives precision, recall, specificity, F1, and balanced accuracy", () => {
    const m = metrics(rows, "block");
    expect(m.precision).toBeCloseTo(0.5);
    expect(m.recall).toBeCloseTo(1 / 3);
    expect(m.specificity).toBeCloseTo(2 / 3);
    expect(m.f1).toBeCloseTo(0.4);
    expect(m.balancedAccuracy).toBeCloseTo(0.5);
    expect(m.total).toBe(6);
  });

  test("an empty arm is all zeros, never NaN", () => {
    const m = metrics([], "block");
    expect(m).toMatchObject({ tp: 0, fp: 0, fn: 0, tn: 0, precision: 0, recall: 0, f1: 0, balancedAccuracy: 0 });
  });
});

describe("cost", () => {
  test("estimates tokens from bytes when the provider reports none", () => {
    const c = cost({ judgeBytes: 4_000_000, usdPerMillionInputTokens: 0.042, bundles: 500 });
    expect(c.tokens).toBe(1_000_000);
    expect(c.tokensEstimated).toBe(true);
    expect(c.usd).toBeCloseTo(0.042);
    expect(c.usdPer1000Bundles).toBeCloseTo(0.084);
  });

  test("prefers the reported token count", () => {
    const c = cost({ judgeBytes: 4_000_000, judgeTokensReported: 250_000, usdPerMillionInputTokens: 0.042, bundles: 1000 });
    expect(c.tokens).toBe(250_000);
    expect(c.tokensEstimated).toBe(false);
    expect(c.usdPer1000Bundles).toBeCloseTo(0.0105);
  });

  test("zero bundles cost nothing per thousand", () => {
    expect(cost({ judgeBytes: 0, usdPerMillionInputTokens: 0.042, bundles: 0 }).usdPer1000Bundles).toBe(0);
  });
});

describe("pct", () => {
  test("formats a ratio as one-decimal percent", () => {
    expect(pct(0.9876)).toBe("98.8%");
    expect(pct(0)).toBe("0.0%");
  });
});
