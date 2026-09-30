import { describe, expect, test } from "bun:test";
import { CLAUDE_CODE_HOOKS, CODEX_HOOKS, runtimeHookCommand } from "../../src/setup/hooks-table";
import type { FileOp } from "../../src/setup/ops";
import {
  CLAUDE_PLUGIN_ID,
  CONFIG_SCHEMA_URL,
  codexHooksDisabled,
  codexInlineHooks,
  countOurHandlers,
  isManagedShim,
  opencodeShim,
  outdatedEvents,
  piShim,
  planConfig,
  planHooksInstall,
  planHooksUninstall,
  planShimInstall,
  planShimUninstall,
  SHIM_MARKER,
} from "../../src/setup/plans";

const CLAUDE = "/h/.claude/settings.json";
const CODEX = "/h/.codex/hooks.json";
const cmd = (h: "claude-code" | "codex", node = "/usr/local/bin/node") =>
  runtimeHookCommand(node, "/h/.skill-scanner/bin/skill-scanner.mjs", h);

type Handler = { type: string; command: string; timeout?: number; statusMessage?: string };
type Group = { matcher?: string; hooks: Handler[] };
type HooksFile = { hooks: Record<string, Group[]>; [k: string]: unknown };

const written = (op: FileOp | undefined): HooksFile => {
  if (op?.kind !== "write") throw new Error(`expected a write, got ${op?.kind}`);
  return JSON.parse(op.after) as HooksFile;
};
const afterText = (op: FileOp | undefined): string => {
  if (op?.kind !== "write") throw new Error("expected a write");
  return op.after;
};

describe("planHooksInstall: Claude Code settings.json", () => {
  test("a missing file gets every table event with the quoted runtime command", () => {
    const plan = planHooksInstall("claude-code", CLAUDE, undefined, cmd("claude-code"));
    const out = written(plan.op);
    expect(Object.keys(out.hooks)).toEqual(CLAUDE_CODE_HOOKS.map((h) => h.event));
    for (const spec of CLAUDE_CODE_HOOKS) {
      const groups = out.hooks[spec.event]!;
      expect(groups).toHaveLength(1);
      expect(groups[0]!.matcher).toBe(spec.matcher);
      expect(groups[0]!.hooks).toEqual([{ type: "command", command: cmd("claude-code"), timeout: spec.timeout }]);
    }
    expect(out.hooks.UserPromptExpansion![0]).not.toHaveProperty("matcher");
    expect(cmd("claude-code")).toBe('"/usr/local/bin/node" "/h/.skill-scanner/bin/skill-scanner.mjs" hook claude-code');
    expect(plan.op?.kind === "write" && plan.op.before).toBeUndefined();
    expect(plan.op?.summary).toBe("add hooks: PreToolUse, PostToolUse, SessionStart, ConfigChange, UserPromptExpansion");
  });

  test("keeps every other key and hook, and appends ours after existing groups", () => {
    const existing = {
      model: "opus",
      permissions: { allow: ["Bash(ls:*)"] },
      hooks: {
        PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "my-guard.sh" }] }],
        Stop: [{ hooks: [{ type: "command", command: "notify" }] }],
      },
    };
    const out = written(planHooksInstall("claude-code", CLAUDE, JSON.stringify(existing), cmd("claude-code")).op);
    expect(out.model).toBe("opus");
    expect(out.permissions).toEqual({ allow: ["Bash(ls:*)"] });
    expect(out.hooks.Stop).toEqual(existing.hooks.Stop);
    expect(out.hooks.PreToolUse).toHaveLength(2);
    expect(out.hooks.PreToolUse![0]).toEqual(existing.hooks.PreToolUse[0]!);
    expect(out.hooks.PreToolUse![1]!.hooks[0]!.command).toBe(cmd("claude-code"));
    expect(Object.keys(out.hooks)[0]).toBe("PreToolUse");
  });

  test("re-running on its own output changes nothing", () => {
    const first = afterText(planHooksInstall("claude-code", CLAUDE, undefined, cmd("claude-code")).op);
    const second = planHooksInstall("claude-code", CLAUDE, first, cmd("claude-code"));
    expect(second.op).toBeUndefined();
    expect(second.error).toBeUndefined();
  });

  test("a user hook added after ours does not make setup move ours", () => {
    const first = written(planHooksInstall("claude-code", CLAUDE, undefined, cmd("claude-code")).op);
    first.hooks.PreToolUse!.push({ matcher: "Write", hooks: [{ type: "command", command: "later.sh", timeout: 5 }] });
    expect(planHooksInstall("claude-code", CLAUDE, JSON.stringify(first, null, 2), cmd("claude-code")).op).toBeUndefined();
  });

  test("a new Node path replaces our old entries instead of duplicating them", () => {
    const first = afterText(planHooksInstall("claude-code", CLAUDE, undefined, cmd("claude-code", "/old/node")).op);
    const plan = planHooksInstall("claude-code", CLAUDE, first, cmd("claude-code", "/new/node"));
    const out = written(plan.op);
    expect(countOurHandlers(out.hooks, "claude-code")).toBe(CLAUDE_CODE_HOOKS.length);
    expect(JSON.stringify(out)).not.toContain("/old/node");
    expect(plan.op?.summary.startsWith("update hooks:")).toBe(true);
  });

  test("our handler inside a user's group is removed from it without touching the user's handler", () => {
    const existing = {
      hooks: {
        PostToolUse: [
          {
            matcher: "Bash",
            hooks: [
              { type: "command", command: "fmt.sh" },
              { type: "command", command: cmd("claude-code", "/old/node") },
            ],
          },
        ],
      },
    };
    const out = written(planHooksInstall("claude-code", CLAUDE, JSON.stringify(existing), cmd("claude-code")).op);
    expect(out.hooks.PostToolUse![0]).toEqual({ matcher: "Bash", hooks: [{ type: "command", command: "fmt.sh" }] } as unknown as Group);
    expect(out.hooks.PostToolUse).toHaveLength(2);
  });

  test("an entry from an older version under an event no longer in the table is removed", () => {
    const existing = { hooks: { Notification: [{ hooks: [{ type: "command", command: cmd("claude-code") }] }] } };
    const out = written(planHooksInstall("claude-code", CLAUDE, JSON.stringify(existing), cmd("claude-code")).op);
    expect(out.hooks.Notification).toBeUndefined();
  });

  test("accepts JSON with comments and trailing commas, and warns that comments are dropped", () => {
    const jsonc = '{\n  // my settings\n  "model": "opus", /* inline */\n  "env": { "A": "1", },\n}\n';
    const plan = planHooksInstall("claude-code", CLAUDE, jsonc, cmd("claude-code"));
    const out = written(plan.op);
    expect(out.model).toBe("opus");
    expect(out.env).toEqual({ A: "1" });
    expect(plan.warnings.some((w) => w.includes("comments") && w.includes(".skill-scanner.bak"))).toBe(true);
  });

  test("refuses an unparsable file and explains", () => {
    const plan = planHooksInstall("claude-code", CLAUDE, '{ "model": "opus", ', cmd("claude-code"));
    expect(plan.op).toBeUndefined();
    expect(plan.error).toContain("not valid JSON");
    expect(plan.error).toContain(CLAUDE);
  });

  test("refuses when the top level or hooks has the wrong shape", () => {
    expect(planHooksInstall("claude-code", CLAUDE, "[1, 2]", cmd("claude-code")).error).toContain("JSON object");
    expect(planHooksInstall("claude-code", CLAUDE, '{"hooks": []}', cmd("claude-code")).error).toContain('"hooks" is not an object');
    expect(planHooksInstall("claude-code", CLAUDE, '{"hooks": {"PreToolUse": {}}}', cmd("claude-code")).error).toContain("not a list");
  });

  test("keeps the file's indentation and asks for a backup of existing files", () => {
    const plan = planHooksInstall("claude-code", CLAUDE, '{\n    "model": "opus"\n}\n', cmd("claude-code"));
    expect(afterText(plan.op)).toStartWith('{\n    "model": "opus",\n    "hooks": {');
    expect(plan.op?.kind === "write" && plan.op.backup).toBe(true);
  });

  test("warns when hooks are disabled or the marketplace plugin is also enabled", () => {
    const text = JSON.stringify({ disableAllHooks: true, enabledPlugins: { [CLAUDE_PLUGIN_ID]: true } });
    const plan = planHooksInstall("claude-code", CLAUDE, text, cmd("claude-code"));
    expect(plan.warnings.some((w) => w.includes("disableAllHooks"))).toBe(true);
    expect(plan.warnings.some((w) => w.includes("runs twice"))).toBe(true);
  });

  test("a __proto__ event name stays a plain key", () => {
    const text = '{"hooks": {"__proto__": [{"hooks": [{"type": "command", "command": "x"}]}]}}';
    const out = JSON.parse(afterText(planHooksInstall("claude-code", CLAUDE, text, cmd("claude-code")).op));
    expect(Object.hasOwn(out.hooks, "__proto__")).toBe(true);
    expect(Object.getPrototypeOf(out.hooks)).toBe(Object.prototype);
  });
});

describe("planHooksInstall: Codex hooks.json", () => {
  test("creates the file with only the handler fields Codex accepts", () => {
    const out = written(planHooksInstall("codex", CODEX, undefined, cmd("codex")).op);
    expect(Object.keys(out)).toEqual(["hooks"]);
    expect(Object.keys(out.hooks)).toEqual(CODEX_HOOKS.map((h) => h.event));
    const session = out.hooks.SessionStart![0]!;
    expect(session.matcher).toBe("startup|resume|clear");
    expect(session.hooks[0]).toEqual({
      type: "command",
      command: cmd("codex"),
      timeout: 60,
      statusMessage: "skill-scanner: checking skills",
    });
    expect(out.hooks.PreToolUse![0]!.matcher).toBe("^(Bash|shell|exec_command|apply_patch)$");
    for (const groups of Object.values(out.hooks))
      for (const h of groups[0]!.hooks)
        for (const k of Object.keys(h)) expect(["type", "command", "timeout", "statusMessage"]).toContain(k);
  });

  test("does not treat Claude Code entries as its own", () => {
    const existing = { hooks: { PreToolUse: [{ hooks: [{ type: "command", command: cmd("claude-code") }] }] } };
    const out = written(planHooksInstall("codex", CODEX, JSON.stringify(existing), cmd("codex")).op);
    expect(out.hooks.PreToolUse).toHaveLength(2);
  });
});

describe("planHooksUninstall", () => {
  test("removes only our handlers and keeps the user's", () => {
    const installed = written(
      planHooksInstall(
        "claude-code",
        CLAUDE,
        JSON.stringify({ model: "opus", hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "mine" }] }] } }),
        cmd("claude-code"),
      ).op,
    );
    const plan = planHooksUninstall("claude-code", CLAUDE, JSON.stringify(installed));
    const out = written(plan.op);
    expect(out).toEqual({
      model: "opus",
      hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "mine" } as Handler] }] },
    });
    expect(plan.op?.summary).toBe(`remove ${CLAUDE_CODE_HOOKS.length} skill-scanner hooks`);
  });

  test("install then uninstall of a settings file without hooks leaves the original keys only", () => {
    const original = JSON.stringify({ model: "opus" }, null, 2);
    const installed = afterText(planHooksInstall("claude-code", CLAUDE, original, cmd("claude-code")).op);
    expect(JSON.parse(afterText(planHooksUninstall("claude-code", CLAUDE, installed).op))).toEqual({ model: "opus" });
  });

  test("a Codex hooks.json left empty is deleted; one with other hooks is rewritten", () => {
    const ours = afterText(planHooksInstall("codex", CODEX, undefined, cmd("codex")).op);
    const removal = planHooksUninstall("codex", CODEX, ours).op;
    expect(removal).toEqual({ kind: "remove", path: CODEX, before: ours, summary: `remove ${CODEX_HOOKS.length} skill-scanner hooks` });
    const mixed = afterText(
      planHooksInstall("codex", CODEX, JSON.stringify({ hooks: { Stop: [{ hooks: [{ type: "command", command: "x" }] }] } }), cmd("codex"))
        .op,
    );
    expect(written(planHooksUninstall("codex", CODEX, mixed).op)).toEqual({
      hooks: { Stop: [{ hooks: [{ type: "command", command: "x" } as Handler] }] },
    });
  });

  test("nothing to do for a missing file or a file without our hooks", () => {
    expect(planHooksUninstall("codex", CODEX, undefined)).toEqual({ warnings: [] });
    expect(planHooksUninstall("claude-code", CLAUDE, '{"hooks": {"Stop": []}}').op).toBeUndefined();
  });

  test("an unparsable file is refused, not rewritten", () => {
    expect(planHooksUninstall("claude-code", CLAUDE, "{ nope").error).toContain("may still contain");
  });
});

describe("outdatedEvents", () => {
  test("lists events missing or registered with other settings", () => {
    const out = written(planHooksInstall("claude-code", CLAUDE, undefined, cmd("claude-code")).op);
    expect(outdatedEvents(out.hooks, "claude-code")).toEqual([]);
    out.hooks.PreToolUse![0]!.hooks[0]!.timeout = 5;
    delete out.hooks.ConfigChange;
    expect(outdatedEvents(out.hooks, "claude-code")).toEqual(["PreToolUse", "ConfigChange"]);
  });
});

describe("codexHooksDisabled", () => {
  test("reads [features] hooks = false and the dotted form", () => {
    expect(codexHooksDisabled(undefined)).toBe(false);
    expect(codexHooksDisabled('model = "x"\n[features]\nweb = true\nhooks = false\n')).toBe(true);
    expect(codexHooksDisabled("[features]\ncodex_hooks = false\n[other]\n")).toBe(true);
    expect(codexHooksDisabled("features.hooks = false\n")).toBe(true);
    expect(codexHooksDisabled("[features]\nhooks = true\n[profiles.x]\nhooks = false\n")).toBe(false);
  });
});

describe("codexInlineHooks", () => {
  test("spots inline hook tables only", () => {
    expect(codexInlineHooks('[[hooks.PreToolUse]]\nmatcher = "^Bash$"\n')).toBe(true);
    expect(codexInlineHooks("[hooks]\n")).toBe(true);
    expect(codexInlineHooks("[features]\nhooks = true\n")).toBe(false);
    expect(codexInlineHooks(undefined)).toBe(false);
  });
});

describe("shims", () => {
  test("OpenCode shim re-exports exactly one function from a file URL; Pi shim uses the absolute path", () => {
    const oc = opencodeShim("/h/.skill-scanner/bin/opencode-plugin.mjs");
    expect(oc.split("\n")[0]).toBe(SHIM_MARKER);
    expect(oc).toContain('export { SkillScanner } from "file:///h/.skill-scanner/bin/opencode-plugin.mjs";');
    expect(oc.match(/^export /gm)).toHaveLength(1);
    const pi = piShim("/h/.skill-scanner/bin/pi-extension.mjs");
    expect(pi).toContain('export { default } from "/h/.skill-scanner/bin/pi-extension.mjs";');
    expect(isManagedShim(pi)).toBe(true);
    expect(opencodeShim("/h/a b/p.mjs")).toContain("file:///h/a%20b/p.mjs");
  });

  test("install creates, updates ours, is idempotent, and refuses a foreign file", () => {
    const want = piShim("/new/pi-extension.mjs");
    expect(planShimInstall("/p", undefined, want, "Pi extension").op?.summary).toBe("add Pi extension");
    expect(planShimInstall("/p", piShim("/old/pi-extension.mjs"), want, "Pi extension").op?.summary).toBe("update Pi extension");
    expect(planShimInstall("/p", want, want, "Pi extension").op).toBeUndefined();
    expect(planShimInstall("/p", "export default () => {}\n", want, "Pi extension").error).toContain("not written by skill-scanner");
  });

  test("uninstall removes only a managed shim", () => {
    const text = piShim("/x.mjs");
    expect(planShimUninstall("/p", text, "Pi extension").op).toEqual({
      kind: "remove",
      path: "/p",
      before: text,
      summary: "remove Pi extension",
    });
    expect(planShimUninstall("/p", "mine\n", "Pi extension").op).toBeUndefined();
    expect(planShimUninstall("/p", undefined, "Pi extension")).toEqual({ warnings: [] });
  });
});

describe("planConfig", () => {
  test("writes the starter config only when there is none", () => {
    const op = planConfig("/h/.skill-scanner/config.json", undefined);
    expect(JSON.parse(afterText(op))).toEqual({ $schema: CONFIG_SCHEMA_URL, blockAt: "high", warnAt: "medium" });
    expect(planConfig("/h/.skill-scanner/config.json", "{}")).toBeUndefined();
  });
});
