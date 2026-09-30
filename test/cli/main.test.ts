import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { CliIO } from "../../src/cli/io";
import { COMMANDS, commandHelp, main } from "../../src/cli/main";
import { VERSION } from "../../src/version";

function fakeIO(): { io: CliIO; out: () => string; err: () => string } {
  const out: string[] = [];
  const err: string[] = [];
  const io: CliIO = {
    stdout: (t) => out.push(t),
    stderr: (t) => err.push(t),
    isTTY: false,
    // A home that does not exist, so no command reads the real user config.
    env: { SKILL_SCANNER_HOME: join(tmpdir(), "skill-scanner-test-missing-home") },
    cwd: tmpdir(),
    readStdin: async () => "",
    confirm: async () => false,
  };
  return { io, out: () => out.join(""), err: () => err.join("") };
}

describe("main", () => {
  test("prints help and exits 2 with no arguments", async () => {
    // Arrange
    const { io, out } = fakeIO();

    // Act
    const code = await main([], io);

    // Assert
    expect(code).toBe(2);
    expect(out()).toContain("Usage:\n  skill-scanner <command> [options]");
    expect(out()).toContain("  scan ");
    expect(out()).not.toContain("  hook ");
  });

  test.each(["help", "--help", "-h"])("prints help and exits 0 for %s", async (arg) => {
    const { io, out } = fakeIO();

    expect(await main([arg], io)).toBe(0);
    expect(out()).toContain("Commands:");
  });

  test("prints a command's help for help <command>", async () => {
    const { io, out } = fakeIO();

    expect(await main(["help", "scan"], io)).toBe(0);
    expect(out()).toContain("skill-scanner scan [target...] [options]");
    expect(out()).toContain("--fail-on <level>");
  });

  test.each(["--version", "-v", "version"])("prints the version for %s", async (arg) => {
    const { io, out } = fakeIO();

    expect(await main([arg], io)).toBe(0);
    expect(out()).toBe(`${VERSION}\n`);
  });

  test("keeps the version in sync with package.json", () => {
    const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as { version: string };

    expect(VERSION).toBe(pkg.version);
  });

  test("rejects an unknown command with exit 2", async () => {
    const { io, err } = fakeIO();

    expect(await main(["frobnicate"], io)).toBe(2);
    expect(err()).toContain('unknown command "frobnicate"');
  });

  const helpable = COMMANDS.filter((c) => c.name !== "add" && c.name !== "guard");
  test.each(helpable.map((c) => [c.name, c] as const))("prints help for %s --help", async (_name, command) => {
    const { io, out } = fakeIO();

    expect(await main([command.name, "--help"], io)).toBe(0);
    expect(out()).toBe(commandHelp(command));
  });

  test("turns a usage error into exit 2 with a hint", async () => {
    const { io, err } = fakeIO();

    expect(await main(["scan", "--bogus"], io)).toBe(2);
    expect(err()).toContain("skill-scanner scan: unknown option --bogus");
    expect(err()).toContain("Run `skill-scanner help scan`.");
  });

  test("runs the rules command", async () => {
    const { io, out } = fakeIO();

    expect(await main(["rules", "--format", "json"], io)).toBe(0);
    expect((JSON.parse(out()) as unknown[]).length).toBeGreaterThan(10);
  });
});

describe("help for an unknown command", () => {
  test("errors instead of printing the general help", async () => {
    const f = fakeIO();
    expect(await main(["help", "scn"], f.io)).toBe(2);
    expect(f.err()).toContain('unknown command "scn"');
    expect(f.out()).toBe("");
  });
});
