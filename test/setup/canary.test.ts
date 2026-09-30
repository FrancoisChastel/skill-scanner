import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { scanPath } from "../../src/scan";
import { canarySkill, hookCanaryPayload, hookDenial, judgeHookCanary, judgeScanCanary, runCanaries } from "../../src/setup/canary";
import { opencodeShim, piShim } from "../../src/setup/plans";
import { makeSkillTree } from "../helpers/tree";
import { makeTempEnv, type TempEnv } from "./env";

const ok = { code: 0, stdout: "", stderr: "", timedOut: false };

describe("canary verdicts", () => {
  test("hook: exit 0 without a deny passes; a deny, a crash, or a timeout fails", () => {
    expect(judgeHookCanary(ok).ok).toBe(true);
    expect(judgeHookCanary({ ...ok, stdout: '{"hookSpecificOutput":{"permissionDecision":"ask"}}' }).ok).toBe(true);
    const denied = judgeHookCanary({
      ...ok,
      stdout: '{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"bad"}}',
    });
    expect(denied).toMatchObject({ ok: false, detail: "denied: bad" });
    expect(judgeHookCanary({ ...ok, code: 2, stderr: "boom\n" })).toMatchObject({ ok: false, detail: "exit 2: boom" });
    expect(judgeHookCanary({ ...ok, code: null, timedOut: true }).ok).toBe(false);
    expect(hookDenial('{"decision":"block","reason":"r"}')).toBe("r");
    expect(hookDenial("plain text")).toBeUndefined();
  });

  test("scan: only exit 1 with a block verdict passes", () => {
    expect(judgeScanCanary({ ...ok, code: 1, stdout: '{"verdict":"block"}' }).ok).toBe(true);
    expect(judgeScanCanary({ ...ok, code: 1, stderr: "Error: Cannot find module" })).toMatchObject({ ok: false });
    expect(judgeScanCanary({ ...ok, stdout: '{"verdict":"pass"}' }).detail).toContain("verdict pass for a skill it must block");
    expect(judgeScanCanary({ ...ok, code: 2, stderr: "bad args" }).ok).toBe(false);
  });

  test("the payload is a Claude Code PreToolUse event for a harmless command", () => {
    const p = JSON.parse(hookCanaryPayload("/tmp/x"));
    expect(p).toMatchObject({ hook_event_name: "PreToolUse", tool_name: "Bash", cwd: "/tmp/x" });
    expect(p.tool_input.command).toBe("echo skill-scanner-canary");
  });

  test("the canary skill really blocks with the built-in rules", async () => {
    const tree = await makeSkillTree({ "canary-skill/SKILL.md": canarySkill() });
    try {
      const report = await scanPath(join(tree.root, "canary-skill"));
      expect(report.verdict).toBe("block");
      // Each indicator alone must block, so one retuned rule cannot turn the canary green.
      const blocking = report.bundles[0]!.findings.filter((f) => f.severity === "high" || f.severity === "critical");
      expect(new Set(blocking.map((f) => f.ruleId.split("/")[0])).size).toBeGreaterThanOrEqual(2);
    } finally {
      await tree.cleanup();
    }
  });
});

describe("runCanaries against a runtime", () => {
  let t: TempEnv;
  beforeEach(async () => {
    t = await makeTempEnv();
  });
  afterEach(async () => {
    await t.cleanup();
  });

  test("passes with a runtime that allows the hook and blocks the scan", async () => {
    const results = await runCanaries(join(t.env.PATH!, "node"), join(t.runtimeDir, "skill-scanner.mjs"), t.env, 20_000);
    expect(results.map((r) => r.ok)).toEqual([true, true]);
  });

  test("fails when the hook denies a harmless command", async () => {
    const env = { ...t.env, FAKE_HOOK_DENY: "1" };
    const [hook] = await runCanaries(join(t.env.PATH!, "node"), join(t.runtimeDir, "skill-scanner.mjs"), env, 20_000);
    expect(hook).toMatchObject({ ok: false, detail: "denied: nope" });
  });

  test("fails cleanly when the runtime is missing", async () => {
    const results = await runCanaries(join(t.env.PATH!, "node"), join(t.root, "missing.mjs"), t.env, 20_000);
    expect(results.every((r) => !r.ok)).toBe(true);
  });
});

describe("shims load their runtime modules", () => {
  let t: TempEnv;
  beforeEach(async () => {
    t = await makeTempEnv();
  });
  afterEach(async () => {
    await t.cleanup();
  });

  test("the OpenCode shim exposes exactly the plugin function; the Pi shim its default export", async () => {
    const { writeFile } = await import("node:fs/promises");
    const oc = join(t.root, "oc-shim.js");
    const pi = join(t.root, "pi-shim.js");
    await writeFile(oc, opencodeShim(join(t.runtimeDir, "opencode-plugin.mjs")));
    await writeFile(pi, piShim(join(t.runtimeDir, "pi-extension.mjs")));
    const ocMod = (await import(pathToFileURL(oc).href)) as Record<string, unknown>;
    expect(Object.keys(ocMod)).toEqual(["SkillScanner"]);
    expect(await (ocMod.SkillScanner as () => Promise<unknown>)()).toEqual({ marker: "opencode" });
    const piMod = (await import(pathToFileURL(pi).href)) as { default: () => string };
    expect(piMod.default()).toBe("pi");
  });
});
