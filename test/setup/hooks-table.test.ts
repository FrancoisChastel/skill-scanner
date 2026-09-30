import { describe, expect, test } from "bun:test";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  CLAUDE_CODE_HOOKS,
  CODEX_HOOKS,
  type HookHarness,
  isOurHandler,
  pluginHookCommand,
  pluginHooksFile,
  runtimeHookCommand,
} from "../../src/setup/hooks-table";
import { planHooksInstall } from "../../src/setup/plans";
import { VERSION } from "../../src/version";

const ROOT = join(import.meta.dir, "..", "..");
const PLUGIN_FILES: Readonly<Record<HookHarness, string>> = {
  "claude-code": join(ROOT, "plugins", "claude-code", "hooks", "hooks.json"),
  codex: join(ROOT, "plugins", "codex", "hooks.json"),
};

type Group = { matcher?: string; hooks: { command: string; timeout: number; statusMessage?: string }[] };

/** Event, matcher, timeout, and status message of every group, without the command. */
const shape = (hooks: Record<string, Group[]>) =>
  Object.entries(hooks).map(([event, groups]) => ({
    event,
    groups: groups.map((g) => ({ matcher: g.matcher, handlers: g.hooks.map((h) => [h.timeout, h.statusMessage]) })),
  }));

describe("plugin templates match the hook table", () => {
  for (const harness of ["claude-code", "codex"] as const) {
    test(`plugins hooks.json for ${harness} is generated from the table`, async () => {
      // Regenerate after changing the table: UPDATE_PLUGIN_FILES=1 bun test test/setup/hooks-table.test.ts
      if (process.env.UPDATE_PLUGIN_FILES) await writeFile(PLUGIN_FILES[harness], pluginHooksFile(harness));
      expect(await readFile(PLUGIN_FILES[harness], "utf8")).toBe(pluginHooksFile(harness));
    });

    test(`setup and the ${harness} plugin register the same events, matchers, and timeouts`, async () => {
      const plugin = JSON.parse(await readFile(PLUGIN_FILES[harness], "utf8")) as { hooks: Record<string, Group[]> };
      const plan = planHooksInstall(harness, "/x/settings.json", undefined, runtimeHookCommand("/n", "/s/skill-scanner.mjs", harness));
      if (plan.op?.kind !== "write") throw new Error("expected a write");
      const setup = JSON.parse(plan.op.after) as { hooks: Record<string, Group[]> };
      expect(shape(plugin.hooks)).toEqual(shape(setup.hooks));
      for (const groups of Object.values(plugin.hooks))
        for (const g of groups) expect(g.hooks[0]!.command).toBe(pluginHookCommand(harness));
    });
  }

  test("the table covers the events DESIGN.md promises", () => {
    expect(CLAUDE_CODE_HOOKS.map((h) => h.event)).toEqual([
      "PreToolUse",
      "PostToolUse",
      "SessionStart",
      "ConfigChange",
      "UserPromptExpansion",
    ]);
    expect(CODEX_HOOKS.map((h) => h.event)).toEqual(["SessionStart", "PreToolUse", "PostToolUse", "UserPromptSubmit"]);
  });

  test("plugin.json and the marketplace carry the package version and point at the plugin", async () => {
    const plugin = JSON.parse(await readFile(join(ROOT, "plugins", "claude-code", ".claude-plugin", "plugin.json"), "utf8"));
    expect(plugin.name).toBe("skill-scanner");
    expect(plugin.version).toBe(VERSION);
    expect(plugin.license).toBe("MIT");
    const market = JSON.parse(await readFile(join(ROOT, ".claude-plugin", "marketplace.json"), "utf8"));
    expect(market.name).toBe("skill-scanner");
    expect(market.plugins).toEqual([expect.objectContaining({ name: "skill-scanner", source: "./plugins/claude-code" })]);
  });
});

describe("runtime hook command", () => {
  test("quotes both paths and is recognised as ours for its harness only", () => {
    const c = runtimeHookCommand("/opt/node dir/node", "/home/u/.skill-scanner/bin/skill-scanner.mjs", "codex");
    expect(c).toBe('"/opt/node dir/node" "/home/u/.skill-scanner/bin/skill-scanner.mjs" hook codex');
    expect(isOurHandler({ command: c }, "codex")).toBe(true);
    expect(isOurHandler({ command: c }, "claude-code")).toBe(false);
    expect(isOurHandler({ command: "skill-scanner hook codex" }, "codex")).toBe(false);
    expect(isOurHandler({ command: `${c} --extra` }, "codex")).toBe(true);
    expect(isOurHandler(null, "codex")).toBe(false);
  });

  test("refuses paths that double quotes would not protect", () => {
    for (const bad of ['/a"b/node', "/a$HOME/node", "/a`id`/node", "/a\\b/node", "/a\nb/node"])
      expect(() => runtimeHookCommand(bad, "/s.mjs", "codex")).toThrow("shell escaping");
    expect(runtimeHookCommand("C:\\Program Files\\nodejs\\node.exe", "C:\\u\\s.mjs", "codex")).toContain('"C:\\Program Files');
  });
});
