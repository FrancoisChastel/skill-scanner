import { describe, expect, test } from "bun:test";
import {
  atLeast,
  compareFindings,
  confidenceRank,
  countBySeverity,
  DEFAULT_POLICY,
  demote,
  effectiveSeverity,
  isSeverity,
  lowerConfidence,
  promote,
  severityRank,
  verdictFor,
  worstVerdict,
} from "../../src/core/severity";
import type { Confidence, Finding, Severity } from "../../src/core/types";

function finding(severity: Severity, confidence: Confidence = "high", extra: Partial<Finding> = {}): Finding {
  return {
    ruleId: "test/rule",
    title: "t",
    category: "metadata",
    severity,
    confidence,
    message: "m",
    location: { file: "SKILL.md", line: 1 },
    bundle: "b",
    source: "static",
    ...extra,
  };
}

describe("severity steps", () => {
  test("ranks severities and confidences in order", () => {
    // Arrange / Act / Assert
    expect(["info", "low", "medium", "high", "critical"].map((s) => severityRank(s as Severity))).toEqual([0, 1, 2, 3, 4]);
    expect(["low", "medium", "high"].map((c) => confidenceRank(c as Confidence))).toEqual([0, 1, 2]);
  });

  test("demotes and promotes by one step within bounds", () => {
    // Arrange / Act / Assert
    expect(demote("critical")).toBe("high");
    expect(demote("low")).toBe("info");
    expect(demote("info")).toBe("info");
    expect(promote("info")).toBe("low");
    expect(promote("high")).toBe("critical");
    expect(promote("critical")).toBe("critical");
  });

  test("lowers confidence by one step, never below low", () => {
    // Arrange / Act / Assert
    expect(lowerConfidence("high")).toBe("medium");
    expect(lowerConfidence("medium")).toBe("low");
    expect(lowerConfidence("low")).toBe("low");
  });

  test("compares against a floor", () => {
    // Arrange / Act / Assert
    expect(atLeast("high", "high")).toBe(true);
    expect(atLeast("critical", "high")).toBe(true);
    expect(atLeast("medium", "high")).toBe(false);
  });

  test("recognizes only valid severity strings", () => {
    // Arrange / Act / Assert
    expect(isSeverity("medium")).toBe(true);
    expect(isSeverity("severe")).toBe(false);
    expect(isSeverity(3)).toBe(false);
    expect(isSeverity(undefined)).toBe(false);
  });
});

describe("effectiveSeverity and verdictFor", () => {
  test("low confidence costs one severity step; medium and high cost nothing", () => {
    // Arrange / Act / Assert
    expect(effectiveSeverity({ severity: "high", confidence: "low" })).toBe("medium");
    expect(effectiveSeverity({ severity: "critical", confidence: "low" })).toBe("high");
    expect(effectiveSeverity({ severity: "high", confidence: "medium" })).toBe("high");
    expect(effectiveSeverity({ severity: "info", confidence: "low" })).toBe("info");
  });

  test("passes with no findings or only low and info ones", () => {
    // Arrange / Act / Assert
    expect(verdictFor([])).toBe("pass");
    expect(verdictFor([finding("low"), finding("info"), finding("medium", "low")])).toBe("pass");
  });

  test("warns at medium effective severity", () => {
    // Arrange / Act / Assert
    expect(verdictFor([finding("medium")])).toBe("warn");
    expect(verdictFor([finding("high", "low")])).toBe("warn");
  });

  test("blocks at high effective severity", () => {
    // Arrange / Act / Assert
    expect(verdictFor([finding("low"), finding("high", "medium")])).toBe("block");
    expect(verdictFor([finding("critical", "low")])).toBe("block");
  });

  test("honours a custom policy", () => {
    // Arrange
    const strict = { blockAt: "medium", warnAt: "low" } as const;
    const lax = { blockAt: "critical", warnAt: "high" } as const;

    // Act / Assert
    expect(verdictFor([finding("medium")], strict)).toBe("block");
    expect(verdictFor([finding("low")], strict)).toBe("warn");
    expect(verdictFor([finding("high")], lax)).toBe("warn");
    expect(verdictFor([finding("medium")], lax)).toBe("pass");
  });

  test("the default policy blocks at high and warns at medium", () => {
    // Arrange / Act / Assert
    expect(DEFAULT_POLICY).toEqual({ blockAt: "high", warnAt: "medium" });
    expect(Object.isFrozen(DEFAULT_POLICY)).toBe(true);
  });
});

describe("worstVerdict and countBySeverity", () => {
  test("picks the worst verdict, pass when empty", () => {
    // Arrange / Act / Assert
    expect(worstVerdict([])).toBe("pass");
    expect(worstVerdict(["pass", "warn", "pass"])).toBe("warn");
    expect(worstVerdict(["warn", "block", "pass"])).toBe("block");
  });

  test("counts findings by their raw severity", () => {
    // Arrange
    const findings = [finding("high"), finding("high", "low"), finding("info"), finding("critical")];

    // Act
    const counts = countBySeverity(findings);

    // Assert
    expect(counts).toEqual({ info: 1, low: 0, medium: 0, high: 2, critical: 1 });
  });
});

describe("compareFindings", () => {
  test("sorts by severity, confidence, file, line, then rule id", () => {
    // Arrange
    const a = finding("critical", "high", { ruleId: "a/a", location: { file: "z.md", line: 9 } });
    const b = finding("high", "high", { ruleId: "a/a", location: { file: "a.md", line: 1 } });
    const c = finding("high", "medium", { ruleId: "a/a", location: { file: "a.md", line: 1 } });
    const d = finding("high", "medium", { ruleId: "a/a", location: { file: "b.md", line: 1 } });
    const e = finding("high", "medium", { ruleId: "a/a", location: { file: "b.md", line: 5 } });
    const f = finding("high", "medium", { ruleId: "b/b", location: { file: "b.md", line: 5 } });
    const g = finding("high", "medium", { ruleId: "a/a", location: { file: "b.md" } });

    // Act
    const sorted = [f, e, d, c, b, a, g].sort(compareFindings);

    // Assert
    expect(sorted).toEqual([a, b, c, g, d, e, f]);
  });
});
