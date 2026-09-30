import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { lstat, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { auditInstalledDetailed } from "../../src/guard/audit";
import { handleClaudeCodeEvent } from "../../src/guard/claude-code";
import type { HandlerDeps } from "../../src/guard/hook-common";
import { skillRoots } from "../../src/guard/locations";
import { flaggedAskReason, flaggedReason } from "../../src/guard/messages";
import { addTrust, loadFlagged, saveFlagged } from "../../src/guard/state";
import type { FlaggedEntry, GuardContext, SkillRoot } from "../../src/guard/types";
import { summarizeForAgent } from "../../src/report/index";
import { guardCommandLine } from "../../src/sources/guard-env";
import { BLOCK_MARK, fixedReport, fixedSources, guardCtx, markerScanner, type TempHome, tempHome, WARN_MARK, writeSkill } from "./helpers";

let h: TempHome;
let ctx: GuardContext;
let roots: SkillRoot[];
let deps: HandlerDeps;

const SOURCES = { "o/bad": fixedReport("block", "bad"), "o/warn": fixedReport("warn", "warn"), "o/good": fixedReport("pass", "good") };
const DO_NOT_RETRY = (s: string): string =>
  `Do not retry or work around this. Tell the user what was found; they can review it with \`skill-scanner scan ${s}\` and approve it with \`skill-scanner trust\`.`;

beforeEach(async () => {
  h = await tempHome();
  ctx = guardCtx(h.env, h.path("proj"));
  await mkdir(ctx.cwd, { recursive: true });
  roots = skillRoots("all", ctx.cwd, h.env).filter((r) => r.path.startsWith(h.home));
  deps = { roots, scanSource: fixedSources(SOURCES), scanPath: markerScanner().scan };
});
afterEach(async () => {
  await h.cleanup();
});

const pre = (tool_name: string, tool_input: Record<string, unknown>) => ({
  session_id: "s",
  transcript_path: "/t",
  cwd: ctx.cwd,
  permission_mode: "default",
  hook_event_name: "PreToolUse",
  tool_name,
  tool_input,
  tool_use_id: "u",
});
const line = (o: unknown): string => `${JSON.stringify(o)}\n`;
const exists = (p: string): Promise<boolean> =>
  lstat(p).then(
    () => true,
    () => false,
  );

describe("fail open", () => {
  test("garbage, unknown events, and unknown tools produce nothing", async () => {
    for (const p of [
      null,
      "x",
      42,
      [],
      {},
      { hook_event_name: "Nope" },
      { hook_event_name: "PreToolUse" },
      pre("Read", { file_path: "/etc/passwd" }),
    ]) {
      expect(await handleClaudeCodeEvent(p, ctx, deps)).toEqual({ exitCode: 0 });
    }
  });

  test("an internal error on an ordinary call is a silent pass (stderr only when debugging)", async () => {
    const broken = { ...deps, roots: 42 as unknown as SkillRoot[] };
    expect(await handleClaudeCodeEvent(pre("Bash", { command: "cp a b" }), ctx, broken)).toEqual({ exitCode: 0 });
    const debug = await handleClaudeCodeEvent(
      pre("Bash", { command: "cp a b" }),
      { ...ctx, env: { ...ctx.env, SKILL_SCANNER_DEBUG: "1" } },
      broken,
    );
    expect(debug.exitCode).toBe(0);
    expect(debug.stdout).toBeUndefined();
    expect(debug.stderr).toStartWith("skill-scanner: ");
  });
});

describe("PreToolUse", () => {
  test("ordinary commands pass with no output", async () => {
    expect(await handleClaudeCodeEvent(pre("Bash", { command: "git status && ls" }), ctx, deps)).toEqual({ exitCode: 0 });
  });

  test("a blocked install is denied, and the deny carries nothing else", async () => {
    const out = await handleClaudeCodeEvent(
      pre("Bash", { command: "npx skills add o/bad", description: "install" }),
      { ...ctx, runtime: { node: "/n", script: "/s" } },
      deps,
    );
    const reason = `${summarizeForAgent(SOURCES["o/bad"])}\n${DO_NOT_RETRY("o/bad")}`;
    expect(out).toEqual({
      exitCode: 0,
      stdout: line({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: reason } }),
    });
  });

  test("a warning asks the user", async () => {
    const out = await handleClaudeCodeEvent(pre("Bash", { command: "npx skills add o/warn" }), ctx, deps);
    const reason = `${summarizeForAgent(SOURCES["o/warn"])}\nskill-scanner found issues worth a look before installing o/warn. Approve only if you trust it; \`skill-scanner scan o/warn\` shows the details.`;
    expect(out.stdout).toBe(
      line({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "ask", permissionDecisionReason: reason } }),
    );
  });

  test("a clean install with a runtime is rewritten through guard without a permission decision", async () => {
    const runtime = { node: "/usr/bin/node", script: "/h/.skill-scanner/bin/skill-scanner.mjs" };
    const input = { command: "npx skills add o/good", description: "install", timeout: 1000 };
    const out = await handleClaudeCodeEvent(pre("Bash", input), { ...ctx, runtime }, deps);
    const updatedInput = { ...input, command: guardCommandLine(runtime, input.command) };
    expect(out.stdout).toBe(line({ hookSpecificOutput: { hookEventName: "PreToolUse", updatedInput } }));
  });

  test("an ask keeps the rewrite, so an approved install still runs under guard", async () => {
    const runtime = { node: "/n", script: "/s/skill-scanner.mjs" };
    const out = await handleClaudeCodeEvent(pre("Bash", { command: "npx skills add o/warn" }), { ...ctx, runtime }, deps);
    const body = JSON.parse(out.stdout ?? "{}");
    expect(body.hookSpecificOutput.permissionDecision).toBe("ask");
    expect(body.hookSpecificOutput.updatedInput).toEqual({ command: guardCommandLine(runtime, "npx skills add o/warn") });
  });

  test("the install deadline answers before the harness timeout", async () => {
    const t0 = Date.now();
    const out = await handleClaudeCodeEvent(
      pre("Bash", { command: "npx skills add o/slow" }),
      guardCtx(h.env, ctx.cwd, { hooks: { onError: "deny" } }),
      { ...deps, scanSource: () => new Promise<never>(() => undefined), installDeadlineMs: 50 },
    );
    expect(Date.now() - t0).toBeLessThan(1000);
    expect(JSON.parse(out.stdout ?? "{}").hookSpecificOutput.permissionDecision).toBe("deny");
  });

  test("Write and Edit into a skill directory are scanned with the change applied", async () => {
    const skillFile = h.path(".claude", "skills", "w", "SKILL.md");
    const write = await handleClaudeCodeEvent(
      pre("Write", { file_path: skillFile, content: `---\nname: w\ndescription: x\n---\n${BLOCK_MARK}\n` }),
      ctx,
      deps,
    );
    expect(JSON.parse(write.stdout ?? "{}").hookSpecificOutput.permissionDecision).toBe("deny");
    expect(await handleClaudeCodeEvent(pre("Write", { file_path: h.path("proj", "a.md"), content: BLOCK_MARK }), ctx, deps)).toEqual({
      exitCode: 0,
    });
    await writeSkill(h.path(".claude", "skills", "e"), "e", "harmless");
    const edit = await handleClaudeCodeEvent(
      pre("Edit", { file_path: h.path(".claude", "skills", "e", "SKILL.md"), old_string: "harmless", new_string: BLOCK_MARK }),
      ctx,
      deps,
    );
    expect(JSON.parse(edit.stdout ?? "{}").hookSpecificOutput.permissionDecision).toBe("deny");
    const multi = await handleClaudeCodeEvent(
      pre("MultiEdit", {
        file_path: h.path(".claude", "skills", "e", "SKILL.md"),
        edits: [{ old_string: "harmless", new_string: WARN_MARK }],
      }),
      ctx,
      deps,
    );
    expect(JSON.parse(multi.stdout ?? "{}").hookSpecificOutput.additionalContext).toContain("skill-scanner warns about the skill in");
  });

  test("the Skill tool: blocked skills are denied, warned ones ask, trusted ones pass", async () => {
    const bad: FlaggedEntry = {
      name: "bad",
      path: h.path(".claude", "skills", "bad"),
      realPath: h.path(".claude", "skills", "bad"),
      digest: `sha256:${"b".repeat(64)}`,
      verdict: "block",
      summary: ["critical x/y: z (SKILL.md:1)"],
      flaggedAt: "t",
    };
    const warn: FlaggedEntry = {
      ...bad,
      name: "meh",
      path: "/p/meh",
      realPath: "/p/meh",
      digest: `sha256:${"c".repeat(64)}`,
      verdict: "warn",
    };
    await saveFlagged([bad, warn], h.env);
    const denied = await handleClaudeCodeEvent(pre("Skill", { skill: "bad" }), ctx, deps);
    expect(denied.stdout).toBe(
      line({
        hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: flaggedReason(bad) },
      }),
    );
    const asked = await handleClaudeCodeEvent(pre("Skill", { skill: "meh" }), ctx, deps);
    expect(asked.stdout).toBe(
      line({
        hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "ask", permissionDecisionReason: flaggedAskReason(warn) },
      }),
    );
    await addTrust({ digest: bad.digest, name: "bad", path: bad.path }, h.env);
    expect(await handleClaudeCodeEvent(pre("Skill", { skill: "bad" }), ctx, deps)).toEqual({ exitCode: 0 });
  });

  test("the Skill tool checks a skill that is on disk but not yet audited", async () => {
    await writeSkill(h.path(".claude", "skills", "fresh"), "fresh", BLOCK_MARK);
    const out = await handleClaudeCodeEvent(pre("Skill", { skill: "fresh" }), ctx, deps);
    expect(JSON.parse(out.stdout ?? "{}").hookSpecificOutput.permissionDecision).toBe("deny");
    expect(await handleClaudeCodeEvent(pre("Skill", { skill: "unknown-skill" }), ctx, deps)).toEqual({ exitCode: 0 });
  });
});

describe("PostToolUse", () => {
  const post = (tool_name: string, tool_input: Record<string, unknown>) => ({
    ...pre(tool_name, tool_input),
    hook_event_name: "PostToolUse",
    tool_response: { stdout: "", stderr: "", interrupted: false },
  });

  test("unrelated commands do not trigger an audit", async () => {
    const scanner = markerScanner();
    expect(await handleClaudeCodeEvent(post("Bash", { command: "npm test" }), ctx, { ...deps, scanPath: scanner.scan })).toEqual({
      exitCode: 0,
    });
    expect(scanner.calls).toEqual([]);
  });

  test("a newly blocked skill is reported to Claude, told to the user, and quarantined", async () => {
    await writeSkill(h.path(".claude", "skills", "dropped"), "dropped", BLOCK_MARK);
    const out = await handleClaudeCodeEvent(post("Bash", { command: "cp -r /tmp/dropped ~/.claude/skills/" }), ctx, deps);
    const body = JSON.parse(out.stdout ?? "{}");
    expect(Object.keys(body)).toEqual(["decision", "reason", "systemMessage"]);
    expect(body.decision).toBe("block");
    expect(body.reason).toContain(`- dropped (block, quarantined) ${h.path(".claude", "skills", "dropped")}: critical test/marker`);
    expect(body.systemMessage).toBe(
      "skill-scanner: 1 skill flagged (1 blocked, 0 with warnings); 1 moved to quarantine. Run `skill-scanner audit` for details.",
    );
    expect(await exists(h.path(".claude", "skills", "dropped"))).toBe(false);
    // Reported once: the next change does not repeat it.
    expect(await handleClaudeCodeEvent(post("Bash", { command: "ls ~/.claude/skills" }), ctx, deps)).toEqual({ exitCode: 0 });
  });

  test("a newly warned skill adds context without blocking", async () => {
    await writeSkill(h.path(".claude", "skills", "w"), "w", WARN_MARK);
    const out = await handleClaudeCodeEvent(
      post("Write", { file_path: h.path(".claude", "skills", "w", "SKILL.md"), content: "x" }),
      ctx,
      deps,
    );
    const body = JSON.parse(out.stdout ?? "{}");
    expect(Object.keys(body)).toEqual(["systemMessage", "hookSpecificOutput"]);
    expect(body.hookSpecificOutput.hookEventName).toBe("PostToolUse");
    expect(body.hookSpecificOutput.additionalContext).toContain("- w (warn)");
  });
});

describe("SessionStart, ConfigChange, UserPromptExpansion", () => {
  test("session start audits, quarantines blocks, and asks Claude Code to reload skills", async () => {
    await writeSkill(h.path(".claude", "skills", "bad"), "bad", BLOCK_MARK);
    await writeSkill(h.path(".claude", "skills", "good"), "good");
    const out = await handleClaudeCodeEvent({ hook_event_name: "SessionStart", source: "startup", cwd: ctx.cwd }, ctx, deps);
    const body = JSON.parse(out.stdout ?? "{}");
    expect(body.hookSpecificOutput.hookEventName).toBe("SessionStart");
    expect(body.hookSpecificOutput.reloadSkills).toBe(true);
    expect(body.hookSpecificOutput.additionalContext).toStartWith(
      "skill-scanner audited the installed skills and flagged these:\n- bad (block, quarantined)",
    );
    expect(body.systemMessage).toContain("1 moved to quarantine");
    expect(await exists(h.path(".claude", "skills", "bad"))).toBe(false);
    expect(await handleClaudeCodeEvent({ hook_event_name: "SessionStart" }, ctx, deps)).toEqual({ exitCode: 0 });
  });

  test("session start without quarantine still warns; a slow audit reports pending skills", async () => {
    await writeSkill(h.path(".claude", "skills", "bad"), "bad", BLOCK_MARK);
    const noQ = guardCtx(h.env, ctx.cwd, { hooks: { quarantine: false } });
    const body = JSON.parse((await handleClaudeCodeEvent({ hook_event_name: "SessionStart" }, noQ, deps)).stdout ?? "{}");
    expect(body.hookSpecificOutput.reloadSkills).toBeUndefined();
    expect(await exists(h.path(".claude", "skills", "bad"))).toBe(true);
    await writeSkill(h.path(".claude", "skills", "later"), "later");
    const slow = { ...deps, auditDeadlineMs: 50, scanPath: () => new Promise<never>(() => undefined) };
    const out = await handleClaudeCodeEvent({ hook_event_name: "SessionStart" }, noQ, slow);
    expect(out.timedOut).toBe(true);
    expect(JSON.parse(out.stdout ?? "{}").systemMessage).toContain("1 not scanned yet");
  });

  test("ConfigChange for a written skill blocks the change and quarantines it", async () => {
    await writeSkill(h.path(".claude", "skills", "cc"), "cc", BLOCK_MARK);
    const out = await handleClaudeCodeEvent(
      { hook_event_name: "ConfigChange", source: "skills", file_path: h.path(".claude", "skills", "cc", "SKILL.md") },
      ctx,
      deps,
    );
    const body = JSON.parse(out.stdout ?? "{}");
    expect(body.decision).toBe("block");
    expect(body.reason).toStartWith("skill-scanner flagged a skill that was just written:\n- cc (block, quarantined)");
    expect(await exists(h.path(".claude", "skills", "cc"))).toBe(false);
    expect(await handleClaudeCodeEvent({ hook_event_name: "ConfigChange", source: "user_settings" }, ctx, deps)).toEqual({ exitCode: 0 });
  });

  test("UserPromptExpansion refuses a blocked skill before it expands", async () => {
    await writeSkill(h.path(".claude", "skills", "bad"), "bad", BLOCK_MARK);
    await auditInstalledDetailed(ctx, { roots, scan: markerScanner().scan });
    const entry = (await loadFlagged(h.env)).find((e) => e.name === "bad")!;
    const out = await handleClaudeCodeEvent(
      { hook_event_name: "UserPromptExpansion", expansion_type: "slash_command", command_name: "/bad" },
      ctx,
      deps,
    );
    expect(out.stdout).toBe(line({ decision: "block", reason: flaggedReason(entry) }));
    expect(await handleClaudeCodeEvent({ hook_event_name: "UserPromptExpansion", command_name: "review" }, ctx, deps)).toEqual({
      exitCode: 0,
    });
  });
});

test("plugin skills are blocked by their plugin-prefixed name", async () => {
  const plugin = h.path(".claude", "plugins", "cache", "mkt", "plug", "1.0");
  await writeSkill(join(plugin, "skills", "s1"), "s1", BLOCK_MARK);
  await writeFile(join(plugin, "README.md"), "x");
  await auditInstalledDetailed(ctx, { roots, scan: markerScanner().scan });
  const out = await handleClaudeCodeEvent(pre("Skill", { skill: "plug:s1" }), ctx, deps);
  expect(JSON.parse(out.stdout ?? "{}").hookSpecificOutput.permissionDecision).toBe("deny");
});
