import { describe, expect, test } from "bun:test";
import { HELD_OUT_CORPORA, splitOf } from "../../src/benchmark/split";

describe("splitOf", () => {
  test("a held-out corpus is held out whatever the directory", () => {
    // Arrange
    const corpus = [...HELD_OUT_CORPORA][0]!;

    // Act
    const splits = ["a", "b/c", "calibration/msb/x"].map((dir) => splitOf(corpus, dir));

    // Assert
    expect(new Set(splits)).toEqual(new Set(["held-out"]));
  });

  test("the same directory always lands in the same split, trailing slash or not", () => {
    expect(splitOf("benign/x", "calibration/benign/x/skills/a")).toBe(splitOf("benign/x", "calibration/benign/x/skills/a/"));
  });

  test("other corpora split about half train, a quarter validation, a quarter test", () => {
    // Act
    const counts = { train: 0, val: 0, test: 0, "held-out": 0 };
    for (let i = 0; i < 4000; i++) counts[splitOf("benign/x", `calibration/benign/x/skills/s${i}`)]++;

    // Assert
    expect(counts["held-out"]).toBe(0);
    expect(counts.train / 4000).toBeCloseTo(0.5, 1);
    expect(counts.val / 4000).toBeCloseTo(0.25, 1);
    expect(counts.test / 4000).toBeCloseTo(0.25, 1);
  });
});

describe("bundles read before the split", () => {
  test("count as training data even inside a held-out corpus", () => {
    expect(splitOf("malicious/msb-SRC006", "calibration/msb/SRC006/packages/00059_ASB04_005317")).toBe("train");
    expect(splitOf("malicious/msb-SRC006", "calibration/msb/SRC006/packages/00059_ASB04_005318")).toBe("held-out");
  });
});
