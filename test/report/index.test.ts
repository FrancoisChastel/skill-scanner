import { describe, expect, test } from "bun:test";
import { formatReport, formatReports, oneLineSummary, summarizeForAgent } from "../../src/report";
import { cleanReport, ESC, FAKE_TOKEN, makeReport } from "./fixture";

describe("formatReport", () => {
  test("dispatches to each format", () => {
    // Arrange
    const report = makeReport();

    // Act
    const outputs = {
      text: formatReport(report, "text", { color: false }),
      json: formatReport(report, "json", { color: false }),
      sarif: formatReport(report, "sarif", { color: false }),
      markdown: formatReport(report, "markdown", { color: false }),
    };

    // Assert
    expect(outputs.text).toContain("BLOCK  helper");
    expect(JSON.parse(outputs.json).schemaVersion).toBe(1);
    expect(JSON.parse(outputs.sarif).version).toBe("2.1.0");
    expect(outputs.markdown.startsWith("## skill-scanner blocked")).toBe(true);
  });

  test("combines several reports: one SARIF run each, a JSON array, concatenated text", () => {
    const reports = [makeReport(), cleanReport()];

    expect(JSON.parse(formatReports(reports, "sarif", { color: false })).runs).toHaveLength(2);
    expect(JSON.parse(formatReports(reports, "json", { color: false }))).toHaveLength(2);
    expect(formatReports(reports, "text", { color: false })).toContain("No findings in 1 skill.");
  });
});

describe("summarizeForAgent", () => {
  test("names the verdict, target, and counts, then the top findings one per line", () => {
    const out = summarizeForAgent(makeReport());

    const lines = out.split("\n");
    expect(lines[0]).toBe("skill-scanner blocked ./repo: 1 critical, 1 high, 2 medium, 1 info.");
    expect(lines[1]).toBe(
      "- [critical] exec/download-and-run at skills/helper/scripts/setup.sh:2: Runs whatever https://payload.example/x.sh returns",
    );
    expect(lines[2]).toBe("- [high] packaging/executable-binary at skills/helper/bin/tool: bin/tool is a Mach-O executable");
  });

  test("lists at most the requested number of findings and counts the rest", () => {
    const out = summarizeForAgent(makeReport(), 2);

    expect(out.split("\n")).toHaveLength(4);
    expect(out.endsWith("- and 3 more.")).toBe(true);
  });

  test("stays under 1500 characters with no ANSI and no secrets", () => {
    const long = makeReport({ target: "t".repeat(3000) });

    const out = summarizeForAgent(long, 50);

    expect(out.length).toBeLessThanOrEqual(1500);
    expect(out.includes(ESC)).toBe(false);
    expect(summarizeForAgent(makeReport(), 50).includes(FAKE_TOKEN)).toBe(false);
  });

  test("returns a one-liner for a passing scan", () => {
    const out = summarizeForAgent(cleanReport());

    expect(out).toBe("skill-scanner found no issues in skills/dates.");
  });

  test("says flagged rather than blocked for a warning", () => {
    const report = makeReport({ verdict: "warn" });

    expect(summarizeForAgent(report).startsWith("skill-scanner flagged ./repo:")).toBe(true);
  });
});

describe("oneLineSummary", () => {
  test("gives verdict, target, bundles, and counts", () => {
    expect(oneLineSummary(makeReport())).toBe("skill-scanner: block for ./repo (3 skills; 1 critical, 1 high, 2 medium, 1 info)");
    expect(oneLineSummary(cleanReport())).toBe("skill-scanner: pass for skills/dates (1 skill)");
  });
});
