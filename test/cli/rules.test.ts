import { describe, expect, test } from "bun:test";
import { UsageError } from "../../src/cli/args";
import { rulesCommand } from "../../src/cli/commands/rules";
import type { CliIO } from "../../src/cli/io";
import { JUDGE_RULES } from "../../src/judge";
import { ruleCatalog } from "../../src/rules";

function fakeIO(): { io: CliIO; out: () => string } {
  const out: string[] = [];
  const io: CliIO = {
    stdout: (t) => out.push(t),
    stderr: () => {},
    isTTY: false,
    env: {},
    cwd: "/",
    readStdin: async () => "",
    confirm: async () => false,
  };
  return { io, out: () => out.join("") };
}

interface RuleJson {
  id: string;
  category: string;
  severity: string;
  confidence: string;
  hard: boolean;
  description: string;
}

describe("rules command", () => {
  test("lists rules as text grouped by category", async () => {
    // Arrange
    const { io, out } = fakeIO();

    // Act
    const code = await rulesCommand.run([], io);

    // Assert
    expect(code).toBe(0);
    expect(out()).toMatch(/^prompt-injection\n/);
    expect(out()).toMatch(/\n {2}CRITICAL {2}high {4}exec\/download-and-run +Downloads code and runs it\n/);
  });

  test("lists every catalog and judge rule as JSON", async () => {
    const { io, out } = fakeIO();

    await rulesCommand.run(["--format", "json"], io);

    const rules = JSON.parse(out()) as RuleJson[];
    const ids = rules.map((r) => r.id);
    for (const r of [...ruleCatalog(), ...JUDGE_RULES]) expect(ids).toContain(r.id);
    expect(rules.every((r) => typeof r.hard === "boolean" && r.description.length > 0)).toBe(true);
  });

  test("filters by category", async () => {
    const { io, out } = fakeIO();

    await rulesCommand.run(["--category", "remote-execution", "-f", "json"], io);

    const rules = JSON.parse(out()) as RuleJson[];
    expect(rules.length).toBeGreaterThan(0);
    expect(rules.every((r) => r.category === "remote-execution")).toBe(true);
  });

  test("renders Markdown tables", async () => {
    const { io, out } = fakeIO();

    await rulesCommand.run(["--format=markdown"], io);

    expect(out()).toContain("### remote-execution\n\n| Rule | Severity | Confidence | Title |\n| --- | --- | --- | --- |\n");
    expect(out()).toContain("| `exec/download-and-run` | critical | high | Downloads code and runs it |");
  });

  test("rejects an unknown category, format, or argument", async () => {
    const { io } = fakeIO();

    await expect(rulesCommand.run(["--category", "nope"], io)).rejects.toThrow(UsageError);
    await expect(rulesCommand.run(["--format", "sarif"], io)).rejects.toThrow(UsageError);
    await expect(rulesCommand.run(["extra"], io)).rejects.toThrow(UsageError);
  });
});
