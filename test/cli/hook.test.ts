import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdir, writeFile } from "node:fs/promises";
import { hookCommand, runHook } from "../../src/cli/commands/hook";
import type { CliIO } from "../../src/cli/io";
import { skillRoots } from "../../src/guard/locations";
import { scannerPaths } from "../../src/paths";
import { fixedReport, fixedSources, markerScanner, type TempHome, tempHome, writeSkill } from "../guard/helpers";

let h: TempHome;
beforeEach(async () => {
  h = await tempHome();
  await mkdir(h.path("proj"), { recursive: true });
});
afterEach(async () => {
  await h.cleanup();
});

interface FakeIO extends CliIO {
  readonly out: string[];
  readonly err: string[];
}

function fakeIO(stdin: string, cwd = h.path("proj"), env: NodeJS.ProcessEnv = h.env): FakeIO {
  const out: string[] = [];
  const err: string[] = [];
  return {
    out,
    err,
    stdout: (t) => out.push(t),
    stderr: (t) => err.push(t),
    isTTY: false,
    env,
    cwd,
    readStdin: async () => stdin,
    confirm: async () => false,
  };
}

const bash = (command: string, cwd = h.path("proj")) =>
  JSON.stringify({ session_id: "s", cwd, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command }, tool_use_id: "u" });

describe("skill-scanner hook", () => {
  test("an ordinary command: exit 0, no output", async () => {
    const io = fakeIO(bash("echo hello"));
    expect(await hookCommand.run(["claude-code"], io)).toBe(0);
    expect(io.out).toEqual([]);
    expect(io.err).toEqual([]);
  });

  test("invalid JSON, oversized input, and unknown harnesses never block", async () => {
    for (const stdin of ["", "{nope", "[1,2]", `"x"`, `{"a":"${"x".repeat(1024 * 1024)}"}`]) {
      const io = fakeIO(stdin);
      expect(await hookCommand.run(["claude-code"], io)).toBe(0);
      expect(io.out).toEqual([]);
    }
    const io = fakeIO(bash("ls"));
    expect(await hookCommand.run(["cursor"], io)).toBe(0);
    expect(io.err.join("")).toContain('unknown harness "cursor"');
    expect(await hookCommand.run([], fakeIO(""))).toBe(0);
  });

  test("a broken config falls back to defaults and says so on stderr", async () => {
    await mkdir(scannerPaths(h.env).home, { recursive: true });
    await writeFile(scannerPaths(h.env).config, "{ broken");
    const io = fakeIO(bash("echo hi"));
    expect(await hookCommand.run(["claude-code"], io)).toBe(0);
    expect(io.out).toEqual([]);
    expect(io.err.join("")).toMatch(/^skill-scanner: .*config.*using defaults\n$/s);
  });

  test("dispatches to the Claude Code and Codex handlers with the payload's cwd", async () => {
    const roots = skillRoots("all", h.path("proj"), h.env).filter((r) => r.path.startsWith(h.home));
    const deps = { roots, scanSource: fixedSources({ "o/bad": fixedReport("block", "bad") }), scanPath: markerScanner().scan };
    const claude = fakeIO(bash("npx skills add o/bad"), "/");
    expect(await runHook(["claude-code"], claude, deps)).toBe(0);
    expect(JSON.parse(claude.out.join("")).hookSpecificOutput.permissionDecision).toBe("deny");
    const codex = fakeIO(bash("npx skills add o/bad"));
    expect(await runHook(["codex"], codex, deps)).toBe(0);
    const body = JSON.parse(codex.out.join(""));
    expect(Object.keys(body.hookSpecificOutput)).toEqual(["hookEventName", "permissionDecision", "permissionDecisionReason"]);
  });

  test("git-post-checkout delegates to the checkout scanner", async () => {
    const dir = await writeSkill(h.path("checkout"), "fine");
    const io = fakeIO("", dir);
    expect(await hookCommand.run(["git-post-checkout", "0".repeat(40), "1".repeat(40), "1"], io)).toBe(0);
    expect(io.err.join("")).toContain("skill-scanner");
  });

  test("stays out of the command list", () => {
    expect(hookCommand.name).toBe("hook");
    expect(hookCommand.usage).toContain("claude-code|codex|git-post-checkout");
  });
});
