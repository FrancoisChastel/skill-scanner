import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { lstat, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { auditInstalledDetailed } from "../../src/guard/audit";
import { handleCodexEvent } from "../../src/guard/codex";
import type { HandlerDeps } from "../../src/guard/hook-common";
import { skillRoots } from "../../src/guard/locations";
import { flaggedReason } from "../../src/guard/messages";
import { loadFlagged } from "../../src/guard/state";
import type { GuardContext, SkillRoot } from "../../src/guard/types";
import { summarizeForAgent } from "../../src/report/index";
import { BLOCK_MARK, fixedReport, fixedSources, guardCtx, markerScanner, type TempHome, tempHome, WARN_MARK, writeSkill } from "./helpers";

let h: TempHome;
let ctx: GuardContext;
let roots: SkillRoot[];
let deps: HandlerDeps;

const SOURCES = { "o/bad": fixedReport("block", "bad"), "o/warn": fixedReport("warn", "warn"), "o/good": fixedReport("pass", "good") };

beforeEach(async () => {
  h = await tempHome();
  ctx = guardCtx(h.env, h.path("proj"), { harness: "codex" });
  await mkdir(ctx.cwd, { recursive: true });
  roots = skillRoots("all", ctx.cwd, h.env).filter((r) => r.path.startsWith(h.home));
  deps = { roots, scanSource: fixedSources(SOURCES), scanPath: markerScanner().scan };
});
afterEach(async () => {
  await h.cleanup();
});

const event = (hook_event_name: string, rest: Record<string, unknown> = {}) => ({
  session_id: "s",
  turn_id: "t",
  transcript_path: "/t",
  cwd: ctx.cwd,
  hook_event_name,
  model: "gpt-5-codex",
  permission_mode: "default",
  ...rest,
});
const bash = (command: unknown, name = "PreToolUse") => event(name, { tool_name: "Bash", tool_input: { command }, tool_use_id: "u" });
const line = (o: unknown): string => `${JSON.stringify(o)}\n`;
const deny = (reason: string): string =>
  line({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: reason } });

describe("PreToolUse", () => {
  test("garbage and ordinary commands produce nothing", async () => {
    for (const p of [null, "{", {}, event("Stop"), bash("ls -la"), bash(42), event("PreToolUse", { tool_name: "Read" })]) {
      expect(await handleCodexEvent(p, ctx, deps)).toEqual({ exitCode: 0 });
    }
  });

  test("a blocked install gets exactly the documented deny object", async () => {
    const out = await handleCodexEvent(bash("npx skills add o/bad"), { ...ctx, runtime: { node: "/n", script: "/s" } }, deps);
    const reason = `${summarizeForAgent(SOURCES["o/bad"])}\nDo not retry or work around this. Tell the user what was found; they can review it with \`skill-scanner scan o/bad\` and approve it with \`skill-scanner trust\`.`;
    expect(out).toEqual({ exitCode: 0, stdout: deny(reason) });
  });

  test("Codex has no ask: a warning becomes a deny that tells the agent to ask the user", async () => {
    const out = await handleCodexEvent(bash("npx skills add o/warn"), ctx, deps);
    const body = JSON.parse(out.stdout ?? "{}");
    expect(Object.keys(body.hookSpecificOutput)).toEqual(["hookEventName", "permissionDecision", "permissionDecisionReason"]);
    expect(body.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(body.hookSpecificOutput.permissionDecisionReason).toContain(
      "Codex hooks cannot ask the user, so this was refused. Ask the user whether to go ahead",
    );
  });

  test("a clean install passes with no output, even with a runtime (Codex cannot rewrite)", async () => {
    expect(await handleCodexEvent(bash("npx skills add o/good"), { ...ctx, runtime: { node: "/n", script: "/s" } }, deps)).toEqual({
      exitCode: 0,
    });
  });

  test("argv-style commands from older shell tools are understood", async () => {
    const out = await handleCodexEvent(
      event("PreToolUse", { tool_name: "shell", tool_input: { command: ["bash", "-lc", "npx skills add o/bad"] } }),
      ctx,
      deps,
    );
    expect(JSON.parse(out.stdout ?? "{}").hookSpecificOutput.permissionDecision).toBe("deny");
  });

  test("apply_patch adding a blocked skill is denied; updates are left to the post-change audit", async () => {
    const patch = [
      "*** Begin Patch",
      `*** Add File: ${h.path(".codex", "skills", "n", "SKILL.md")}`,
      "+---",
      "+name: n",
      "+description: x",
      "+---",
      `+${BLOCK_MARK}`,
      "*** End Patch",
    ].join("\n");
    const out = await handleCodexEvent(event("PreToolUse", { tool_name: "apply_patch", tool_input: { command: patch } }), ctx, deps);
    expect(JSON.parse(out.stdout ?? "{}").hookSpecificOutput.permissionDecision).toBe("deny");
    const update = `*** Begin Patch\n*** Update File: ${h.path(".codex", "skills", "n", "SKILL.md")}\n@@\n-a\n+b\n*** End Patch`;
    expect(await handleCodexEvent(event("PreToolUse", { tool_name: "apply_patch", tool_input: { command: update } }), ctx, deps)).toEqual({
      exitCode: 0,
    });
    const elsewhere = `*** Begin Patch\n*** Add File: src/x.ts\n+${BLOCK_MARK}\n*** End Patch`;
    expect(
      await handleCodexEvent(event("PreToolUse", { tool_name: "apply_patch", tool_input: { command: elsewhere } }), ctx, deps),
    ).toEqual({ exitCode: 0 });
  });

  test("reading a blocked skill through the shell is refused; managing it is not", async () => {
    await writeSkill(h.path(".agents", "skills", "evil"), "evil", BLOCK_MARK);
    await auditInstalledDetailed(ctx, { roots, scan: markerScanner().scan });
    const entry = (await loadFlagged(h.env)).find((e) => e.name === "evil")!;
    expect((await handleCodexEvent(bash("sed -n '1,200p' ~/.agents/skills/evil/SKILL.md"), ctx, deps)).stdout).toBe(
      deny(flaggedReason(entry)),
    );
    expect(await handleCodexEvent(bash("rm -rf ~/.agents/skills/evil"), ctx, deps)).toEqual({ exitCode: 0 });
    expect(await handleCodexEvent(bash("cat ~/.agents/skills/other/SKILL.md"), ctx, deps)).toEqual({ exitCode: 0 });
  });
});

describe("PostToolUse, SessionStart, UserPromptSubmit", () => {
  test("post-change audit blocks the tool result for a newly blocked skill", async () => {
    await writeSkill(h.path(".codex", "skills", "dropped"), "dropped", BLOCK_MARK);
    const out = await handleCodexEvent({ ...bash("cp -r /tmp/dropped ~/.codex/skills/", "PostToolUse"), tool_response: "done" }, ctx, deps);
    const body = JSON.parse(out.stdout ?? "{}");
    expect(Object.keys(body)).toEqual(["decision", "reason", "systemMessage"]);
    expect(body.reason).toContain("- dropped (block, quarantined)");
    expect(await lstat(h.path(".codex", "skills", "dropped")).catch(() => undefined)).toBeUndefined();
    expect(await handleCodexEvent({ ...bash("make build", "PostToolUse"), tool_response: "ok" }, ctx, deps)).toEqual({ exitCode: 0 });
  });

  test("session start tells the model and the user, without Claude-only fields", async () => {
    await writeSkill(h.path(".codex", "skills", "bad"), "bad", BLOCK_MARK);
    await writeSkill(h.path(".codex", "skills", "meh"), "meh", WARN_MARK);
    const out = await handleCodexEvent(event("SessionStart", { source: "startup" }), ctx, deps);
    const body = JSON.parse(out.stdout ?? "{}");
    expect(Object.keys(body)).toEqual(["hookSpecificOutput", "systemMessage"]);
    expect(Object.keys(body.hookSpecificOutput)).toEqual(["hookEventName", "additionalContext"]);
    expect(body.hookSpecificOutput.additionalContext).toContain("- bad (block, quarantined)");
    expect(body.hookSpecificOutput.additionalContext).toContain("- meh (warn)");
    expect(body.systemMessage).toBe(
      "skill-scanner: 2 skills flagged (1 blocked, 1 with warnings); 1 moved to quarantine. Run `skill-scanner audit` for details.",
    );
  });

  test("a $mention of a blocked skill is refused; other dollars are not", async () => {
    await writeSkill(h.path(".codex", "skills", "bad"), "bad", BLOCK_MARK);
    await auditInstalledDetailed(ctx, { roots, scan: markerScanner().scan });
    const entry = (await loadFlagged(h.env)).find((e) => e.name === "bad")!;
    const out = await handleCodexEvent(event("UserPromptSubmit", { prompt: "please use $bad to fix it" }), ctx, deps);
    expect(out.stdout).toBe(line({ decision: "block", reason: flaggedReason(entry) }));
    expect(await handleCodexEvent(event("UserPromptSubmit", { prompt: "echo $HOME costs $5" }), ctx, deps)).toEqual({ exitCode: 0 });
  });
});

test("the session audit honours its deadline", async () => {
  await writeSkill(join(h.path(".codex", "skills"), "x"), "x");
  const t0 = Date.now();
  const out = await handleCodexEvent(event("SessionStart"), ctx, {
    ...deps,
    auditDeadlineMs: 50,
    scanPath: () => new Promise<never>(() => undefined),
  });
  expect(Date.now() - t0).toBeLessThan(1000);
  expect(out.timedOut).toBe(true);
});
