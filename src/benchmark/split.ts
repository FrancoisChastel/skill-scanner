import { createHash } from "node:crypto";

/**
 * The split tuning works on. Rules and judge probes are changed by reading the training bundles,
 * an edit is kept only if it beats the current best on the validation bundles, and the result is
 * reported on bundles neither step ever saw: a random test slice of the same corpora, and whole
 * corpora held out, so the report shows how tuning carries to attack families and repositories it
 * never read.
 */
export type Split = "train" | "val" | "test" | "held-out";

/** Whole corpora (manifest names) kept out of tuning: three attack families and seven repositories. */
export const HELD_OUT_CORPORA: ReadonlySet<string> = new Set([
  "malicious/msb-SRC004",
  "malicious/msb-SRC006",
  "malicious/cisco-test-malicious",
  "malicious/snyk-toxicskills",
  "malicious/trailofbits-overtly",
  "malicious/nedlir-bypass",
  "benign/microsoft__skills",
  "benign/trailofbits__skills",
  "benign/openai__skills",
  "benign/getsentry__skills",
  "benign/huggingface__skills",
  "benign/hashicorp__agent-skills",
  "benign/cloudflare__skills",
]);

/**
 * Bundles of held-out corpora that were read while the split was being chosen. They count as
 * training data, so nothing in the held-out score was seen before the tuning started.
 */
export const READ_BEFORE_THE_SPLIT: ReadonlySet<string> = new Set([
  "calibration/msb/SRC004/packages/00007_ASB04_002011/skill",
  "calibration/msb/SRC004/packages/00009_ASB04_002179/skill/test-fixtures/evasive-11-polyglot-json",
  "calibration/msb/SRC006/packages/00007_ASB04_001062",
  "calibration/msb/SRC006/packages/00059_ASB04_005317",
]);

/**
 * Where a bundle falls: held out with its corpus, or by a hash of its directory (relative to the
 * corpora root, so the split is the same on any machine): half train, a quarter each validation and test.
 */
export function splitOf(corpus: string, bundleDir: string): Split {
  if (READ_BEFORE_THE_SPLIT.has(bundleDir.replace(/\/+$/, ""))) return "train";
  if (HELD_OUT_CORPORA.has(corpus)) return "held-out";
  const quarter = createHash("sha256").update(bundleDir.replace(/\/+$/, "")).digest()[0]! % 4;
  return quarter < 2 ? "train" : quarter === 2 ? "val" : "test";
}
