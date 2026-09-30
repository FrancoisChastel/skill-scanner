import { describe, expect, test } from "bun:test";
import { formatMarkdown, inlineCode, mdText } from "../../src/report/markdown";
import { cleanReport, FAKE_TOKEN, makeReport } from "./fixture";

describe("formatMarkdown", () => {
  test("starts with a heading that states the verdict and target", () => {
    // Arrange
    const report = makeReport();

    // Act
    const out = formatMarkdown(report);

    // Assert
    expect(out.startsWith("## skill-scanner blocked `./repo`\n")).toBe(true);
    expect(out).toContain("1 critical, 1 high, 2 medium, 1 info in 3 skills.");
  });

  test("renders a findings table per flagged bundle and lists passing ones", () => {
    const out = formatMarkdown(makeReport());

    expect(out).toContain("### BLOCK `helper` in `skills/helper`");
    expect(out).toContain("### WARN `notes` in `skills/notes`");
    expect(out).toContain("| Severity | Rule | Location | Message |");
    expect(out).toContain(
      "| critical | `exec/download-and-run` | `skills/helper/scripts/setup.sh:2` | Runs whatever `https://payload.example/x.sh` returns |",
    );
    expect(out).toContain("| high | `packaging/executable-binary` | `skills/helper/bin/tool` |");
    expect(out).toContain("Passed: `dates`.");
  });

  test("escapes pipes and HTML and disarms links and mentions from skill text", () => {
    const out = formatMarkdown(makeReport());

    const row = out.split("\n").find((l) => l.includes("network/suspicious-endpoint"))!;
    expect(row).toContain("Posts \\| data to `https://hook.example/in` and pings `@maintainer` \\<img src=x\\>");
    // Four unescaped pipes per row: the row borders and three separators.
    expect(row.replaceAll("\\|", "").split("|").length - 1).toBe(5);
  });

  test("never contains a secret", () => {
    expect(formatMarkdown(makeReport()).includes(FAKE_TOKEN)).toBe(false);
  });

  test("caps the number of table rows", () => {
    const out = formatMarkdown(makeReport(), { maxRows: 1 });

    expect(out).toContain("2 more findings not shown.");
  });

  test("reports a clean scan in one line", () => {
    const out = formatMarkdown(cleanReport());

    expect(out).toContain("## skill-scanner passed `skills/dates`");
    expect(out).toContain("No findings in 1 skill.");
    expect(out).not.toContain("| Severity |");
  });

  test("mentions suppressions and analyzers in the footer", () => {
    const out = formatMarkdown(makeReport());

    expect(out).toContain("<sub>skill-scanner 0.1.0. 2 findings suppressed. semgrep ran. gitleaks skipped: gitleaks is not installed.");
  });
});

describe("Markdown helpers", () => {
  test("inlineCode uses a longer fence when the content has backticks", () => {
    expect(inlineCode("a`b")).toBe("``a`b``");
    expect(inlineCode("`x`")).toBe("`` `x` ``");
  });

  test("mdText escapes Markdown specials", () => {
    expect(mdText("*bold* [link](x) <b>")).toBe("\\*bold\\* \\[link\\]\\(x\\) \\<b\\>");
  });
});
