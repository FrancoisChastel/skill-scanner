import { describe, expect, test } from "bun:test";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import skillScanner, { createPiExtension } from "../../src/adapters/pi";
import {
  allow,
  ask,
  deny,
  EVIL,
  EVIL_DIR,
  type FakeGuardOptions,
  fakeGuard,
  fixture,
  HOME,
  installed,
  never,
  PROJECT,
  until,
} from "./fakes";

type Handler = (event: unknown, ctx: unknown) => unknown;

/** Records what the extension registers; `emit` calls the one handler the way Pi's runner does. */
class FakePi {
  readonly handlers = new Map<string, Handler>();
  readonly commands = new Map<string, { description?: string; handler: (args: string, ctx: unknown) => Promise<void> }>();

  on(event: string, handler: Handler): void {
    if (this.handlers.has(event)) throw new Error(`second handler for ${event}`);
    this.handlers.set(event, handler);
  }

  registerCommand(name: string, options: { description?: string; handler: (args: string, ctx: unknown) => Promise<void> }): void {
    this.commands.set(name, options);
  }

  async emit(event: string, payload: object, ctx: FakeCtx): Promise<unknown> {
    const handler = this.handlers.get(event);
    if (!handler) throw new Error(`no handler for ${event}`);
    // Keep accessors: Pi 0.87 defines `systemPrompt` as a getter on the event itself.
    return handler(Object.defineProperties({ type: event }, Object.getOwnPropertyDescriptors(payload)), ctx);
  }
}

interface FakeCtx {
  hasUI: boolean;
  cwd: string;
  ui: { notify(message: string, level?: string): void; confirm(title: string, message: string): Promise<boolean> };
  notes: { message: string; level: string | undefined }[];
  confirms: { title: string; message: string }[];
}

function fakeCtx(opts: { hasUI?: boolean; confirm?: boolean } = {}): FakeCtx {
  const notes: FakeCtx["notes"] = [];
  const confirms: FakeCtx["confirms"] = [];
  return {
    hasUI: opts.hasUI ?? true,
    cwd: PROJECT,
    notes,
    confirms,
    ui: {
      notify: (message, level) => void notes.push({ message, level }),
      confirm: async (title, message) => {
        confirms.push({ title, message });
        return opts.confirm ?? false;
      },
    },
  };
}

function start(opts: FakeGuardOptions = {}) {
  const guard = fakeGuard(opts);
  const pi = new FakePi();
  createPiExtension(guard.deps)(pi as unknown as ExtensionAPI);
  const tool = (ctx: FakeCtx, toolName: string, input: Record<string, unknown>) =>
    pi.emit("tool_call", { toolCallId: "call_1", toolName, input }, ctx) as Promise<{ block?: boolean; reason?: string } | undefined>;
  return { guard, pi, tool };
}

const EVIL_BLOCK = [
  "  <skill>",
  "    <name>evil-helper</name>",
  "    <description>Helps with &quot;everything&quot;; it&apos;s great.</description>",
  `    <location>${EVIL_DIR}/SKILL.md</location>`,
  "  </skill>",
  "",
].join("\n");

// Pi's own renderer from the 0.87 devDependency, driven below the way its runner drives before_agent_start.
const real = await import("../../node_modules/@earendil-works/pi-coding-agent/dist/core/system-prompt.js").catch(() => undefined);

const skill = (name: string, dir: string) => ({
  name,
  description: name,
  filePath: `${dir}/SKILL.md`,
  baseDir: dir,
  disableModelInvocation: false,
});

describe("registration", () => {
  test("registers the handlers and the /skill-scan command", () => {
    const pi = new FakePi();
    skillScanner(pi as unknown as ExtensionAPI);
    expect([...pi.handlers.keys()].sort()).toEqual([
      "before_agent_start",
      "input",
      "session_start",
      "tool_call",
      "tool_result",
      "user_bash",
    ]);
    expect(pi.commands.has("skill-scan")).toBe(true);
  });
});

describe("session_start", () => {
  test("audits in the background and notifies about flagged skills", async () => {
    const { pi, guard } = start({ audit: async () => [installed("evil-helper", EVIL_DIR, "block", ["critical prompt-injection"])] });
    const ctx = fakeCtx();
    await pi.emit("session_start", { reason: "startup" }, ctx);
    await until(() => ctx.notes.length > 0);
    expect(ctx.notes[0]?.level).toBe("warning");
    expect(ctx.notes[0]?.message).toContain("evil-helper (block): critical prompt-injection");
    expect(ctx.notes[0]?.message).toContain("skill-scanner audit");
    await pi.emit("session_start", { reason: "new" }, ctx);
    expect(guard.calls.audits).toBe(1);
  });

  test("does not wait for a slow audit", async () => {
    const { pi } = start({ audit: () => never() });
    const ctx = fakeCtx();
    await pi.emit("session_start", { reason: "startup" }, ctx);
    expect(ctx.notes).toEqual([]);
  });
});

describe("bash tool_call", () => {
  test("a deny blocks with the reason", async () => {
    const { tool } = start({ decide: () => deny("evil/repo scans as block.") });
    expect(await tool(fakeCtx(), "bash", { command: "npx skills add evil/repo" })).toEqual({
      block: true,
      reason: "evil/repo scans as block.",
    });
  });

  test("an ask with UI confirms; yes runs the rewrite, no blocks", async () => {
    const decide = () => ask("medium findings in ok/repo", "skill-scanner guard -- npx skills add ok/repo");
    const { tool } = start({ decide });
    const yes = fakeCtx({ confirm: true });
    const input = { command: "npx skills add ok/repo" };
    expect(await tool(yes, "bash", input)).toBeUndefined();
    expect(input.command).toBe("skill-scanner guard -- npx skills add ok/repo");
    expect(yes.confirms[0]?.message).toContain("medium findings in ok/repo");
    expect(yes.confirms[0]?.message).toContain("Command: npx skills add ok/repo");

    const no = fakeCtx({ confirm: false });
    const denied = await tool(no, "bash", { command: "npx skills add ok/repo" });
    expect(denied?.block).toBe(true);
    expect(denied?.reason).toContain("declined");
  });

  test("an ask without UI follows onWarn: ask blocks with review steps, allow proceeds", async () => {
    const headless = fakeCtx({ hasUI: false });
    const blocked = await start({ decide: () => ask("medium findings") }).tool(headless, "bash", { command: "npx skills add ok/repo" });
    expect(blocked?.block).toBe(true);
    expect(blocked?.reason).toContain("skill-scanner scan ok/repo");
    expect(headless.confirms).toEqual([]);

    const permissive = start({ decide: () => ask("medium findings"), config: { onWarn: "allow" } });
    expect(await permissive.tool(headless, "bash", { command: "npx skills add ok/repo" })).toBeUndefined();
  });

  test("an allow with a rewrite edits event.input in place", async () => {
    const { tool } = start({ decide: () => allow("skill-scanner guard -- pi install npm:x") });
    const input = { command: "pi install npm:x", timeout: 60 };
    expect(await tool(fakeCtx(), "bash", input)).toBeUndefined();
    expect(input).toEqual({ command: "skill-scanner guard -- pi install npm:x", timeout: 60 });
  });

  test("internal errors never throw; ordinary commands pass, installs follow onError", async () => {
    const failing = {
      decide: (): never => {
        throw new Error("boom");
      },
    };
    const { tool } = start(failing);
    expect(await tool(fakeCtx(), "bash", { command: "git status" })).toBeUndefined();
    const strict = start({ ...failing, config: { onError: "deny" } });
    expect((await strict.tool(fakeCtx(), "bash", { command: "npx skills add x/y" }))?.block).toBe(true);
    const broken = fakeGuard();
    const pi = new FakePi();
    createPiExtension({
      ...broken.deps,
      skillRoots: () => {
        throw new Error("roots exploded");
      },
      loadFlagged: () => {
        throw new Error("registry exploded");
      },
    })(pi as unknown as ExtensionAPI);
    expect(await pi.emit("tool_call", { toolCallId: "c", toolName: "read", input: { path: "/x" } }, fakeCtx())).toBeUndefined();
  });

  test("reading a flagged skill through bash is blocked (Pi 0.87 loads skills with bash when read is off)", async () => {
    const { tool } = start({ flagged: () => [EVIL] });
    expect((await tool(fakeCtx(), "bash", { command: `cat ${EVIL_DIR}/SKILL.md` }))?.block).toBe(true);
    expect(await tool(fakeCtx(), "bash", { command: `rm -rf ${EVIL_DIR}` })).toBeUndefined();
  });
});

describe("read and write tool_call", () => {
  test("reading a file inside a flagged skill is blocked, in any spelling Pi accepts", async () => {
    const { tool } = start({ flagged: () => [EVIL] });
    const ctx = fakeCtx();
    for (const path of [`${EVIL_DIR}/SKILL.md`, "~/.agents/skills/evil-helper/SKILL.md", "@~/.agents/skills/evil-helper/scripts/run.sh"]) {
      const result = await tool(ctx, "read", { path });
      expect(result?.block).toBe(true);
      expect(result?.reason).toContain('the skill "evil-helper"');
    }
    expect(await tool(ctx, "read", { path: `${HOME}/.agents/skills/evil-helper-2/SKILL.md` })).toBeUndefined();
    expect(await tool(ctx, "read", { path: "README.md" })).toBeUndefined();
  });

  test("a write into a skill root is evaluated; an ask without UI blocks", async () => {
    const { tool, guard } = start({ decideWrite: () => ask("the new SKILL.md asks for credentials") });
    const result = await tool(fakeCtx({ hasUI: false }), "write", { path: ".pi/skills/new/SKILL.md", content: "hello" });
    expect(result?.block).toBe(true);
    expect(result?.reason).toContain("the new SKILL.md asks for credentials");
    expect(guard.calls.writes).toEqual([{ path: `${PROJECT}/.pi/skills/new/SKILL.md`, content: "hello" }]);
    expect(await tool(fakeCtx(), "write", { path: "src/a.ts", content: "x" })).toBeUndefined();
    expect(guard.calls.writes).toHaveLength(1);
  });
});

describe("user_bash", () => {
  test("a deny returns a failed result instead of running", async () => {
    const { pi } = start({ decide: () => deny("evil/repo scans as block.") });
    const result = await pi.emit("user_bash", { command: "npx skills add evil/repo", excludeFromContext: false, cwd: PROJECT }, fakeCtx());
    expect(result).toEqual({ result: { output: "evil/repo scans as block.\n", exitCode: 1, cancelled: false, truncated: false } });
  });

  test("ordinary commands run as usual", async () => {
    const { pi } = start();
    expect(await pi.emit("user_bash", { command: "ls -la", excludeFromContext: false, cwd: PROJECT }, fakeCtx())).toBeUndefined();
  });

  test("a rewrite runs through our shell operations, then rescans", async () => {
    const { pi, guard } = start({
      decide: () => allow("echo rewritten"),
      reconcile: async () => ({ newlyFlagged: [installed("evil-helper", EVIL_DIR, "block")], quarantined: [] }),
    });
    const ctx = fakeCtx();
    const result = (await pi.emit("user_bash", { command: "npx skills add ok/repo", excludeFromContext: false, cwd: PROJECT }, ctx)) as {
      operations: { exec: (c: string, cwd: string, o: { onData: (d: Buffer) => void }) => Promise<{ exitCode: number | null }> };
    };
    const chunks: string[] = [];
    const run = await result.operations.exec("npx skills add ok/repo", process.cwd(), { onData: (d) => void chunks.push(d.toString()) });
    expect(run.exitCode).toBe(0);
    expect(chunks.join("")).toBe("rewritten\n");
    await until(() => ctx.notes.some((n) => n.message.includes("skill-scanner WARNING")));
    expect(guard.calls.reconciles).toBe(1);
  });
});

describe("input", () => {
  test("/skill:<flagged> is swallowed with a notice; anything else continues", async () => {
    const { pi } = start({ flagged: () => [EVIL] });
    const ctx = fakeCtx();
    expect(await pi.emit("input", { text: "/skill:evil-helper do it", source: "interactive" }, ctx)).toEqual({ action: "handled" });
    expect(ctx.notes[0]?.message).toContain("evil-helper");
    expect(await pi.emit("input", { text: "/skill:pdf-tools", source: "interactive" }, ctx)).toEqual({ action: "continue" });
    expect(await pi.emit("input", { text: "hello", source: "interactive" }, ctx)).toEqual({ action: "continue" });
  });
});

describe("before_agent_start", () => {
  const fixture083 = fixture("pi-0.83-system-prompt.txt");
  const fixture087 = fixture("pi-0.87-system-prompt.txt");

  test("fixtures carry the flagged block as Pi renders it", () => {
    expect(fixture083).toContain(EVIL_BLOCK);
    expect(fixture087).toContain(EVIL_BLOCK);
  });

  test("Pi 0.83: strips the flagged skill from the finished prompt and leaves the options alone", async () => {
    const { pi } = start({ flagged: () => [EVIL] });
    const options = { skills: [skill("pdf-tools", `${HOME}/.pi/agent/skills/pdf-tools`), skill("evil-helper", EVIL_DIR)] };
    const result = await pi.emit("before_agent_start", { prompt: "hi", systemPrompt: fixture083, systemPromptOptions: options }, fakeCtx());
    expect(result).toEqual({ systemPrompt: fixture083.replace(EVIL_BLOCK, "") });
    expect(options.skills).toHaveLength(2);
  });

  test("Pi 0.87: filters the per-turn skills so the structured prompt re-renders without it", async () => {
    const { pi } = start({ flagged: () => [EVIL] });
    const options = { skills: [skill("pdf-tools", `${HOME}/.pi/agent/skills/pdf-tools`), skill("evil-helper", EVIL_DIR)] };
    const event = {
      prompt: "hi",
      systemPromptOptions: options,
      get systemPrompt() {
        return options.skills.some((s) => s.name === "evil-helper") ? fixture087 : fixture087.replace(EVIL_BLOCK, "");
      },
    };
    expect(await pi.emit("before_agent_start", event, fakeCtx())).toBeUndefined();
    expect(options.skills.map((s) => s.name)).toEqual(["pdf-tools"]);
  });

  test("leaves the prompt alone when nothing is flagged or the listing format is unknown", async () => {
    const { pi } = start({ flagged: () => [EVIL] });
    const other = `Skills:\n- evil-helper: ${EVIL_DIR}/SKILL.md\n`;
    expect(await pi.emit("before_agent_start", { prompt: "hi", systemPrompt: other, systemPromptOptions: {} }, fakeCtx())).toBeUndefined();
    const clean = start();
    const result = await clean.pi.emit(
      "before_agent_start",
      { prompt: "hi", systemPrompt: fixture083, systemPromptOptions: {} },
      fakeCtx(),
    );
    expect(result).toBeUndefined();
  });

  test.skipIf(!real)("with Pi's real 0.87 renderer, the flagged skill disappears and sections stay structured", async () => {
    if (!real) return;
    const { pi } = start({ flagged: () => [EVIL] });
    const options = real.normalizeBuildSystemPromptOptions({
      cwd: PROJECT,
      skills: [skill("pdf-tools", `${HOME}/.pi/agent/skills/pdf-tools`), skill("evil-helper", EVIL_DIR)].map((s) => ({
        ...s,
        sourceInfo: { path: s.filePath, source: "local", scope: "user", origin: "top-level" },
      })),
    });
    const event = {
      prompt: "hi",
      systemPromptOptions: options,
      get systemPrompt() {
        return real.buildSystemPrompt(options);
      },
    };
    expect(event.systemPrompt).toContain("<name>evil-helper</name>");
    expect(await pi.emit("before_agent_start", event, fakeCtx())).toBeUndefined();
    expect(event.systemPrompt).not.toContain("evil-helper");
    expect(event.systemPrompt).toContain("<name>pdf-tools</name>");
    expect(options.forceSystemPrompt).toBeUndefined();
  });
});

describe("tool_result", () => {
  const newlyFlagged = [installed("evil-helper", EVIL_DIR, "block", ["critical exfiltration"])];

  test("appends a warning after an install that landed a flagged skill", async () => {
    const { pi } = start({ reconcile: async () => ({ newlyFlagged, quarantined: [] }) });
    const ctx = fakeCtx();
    const result = (await pi.emit(
      "tool_result",
      {
        toolCallId: "c",
        toolName: "bash",
        input: { command: "npx skills add evil/repo" },
        content: [{ type: "text", text: "added" }],
        isError: false,
      },
      ctx,
    )) as { content: { type: string; text: string }[] };
    expect(result.content[0]).toEqual({ type: "text", text: "added" });
    expect(result.content[1]?.text).toContain("skill-scanner WARNING");
    expect(result.content[1]?.text).toContain("evil-helper (block): critical exfiltration");
    expect(ctx.notes.some((n) => n.level === "warning")).toBe(true);
  });

  test("edits in skill roots are reconciled; unrelated results are untouched", async () => {
    const { pi, guard } = start({ reconcile: async () => ({ newlyFlagged: [], quarantined: [] }) });
    const base = { toolCallId: "c", content: [{ type: "text", text: "ok" }], isError: false };
    expect(
      await pi.emit("tool_result", { ...base, toolName: "edit", input: { path: ".pi/skills/a/SKILL.md" } }, fakeCtx()),
    ).toBeUndefined();
    expect(await pi.emit("tool_result", { ...base, toolName: "bash", input: { command: "npm test" } }, fakeCtx())).toBeUndefined();
    expect(guard.calls.reconciles).toBe(1);
  });
});

describe("/skill-scan", () => {
  test("rescans and reports", async () => {
    const { pi, guard } = start({ audit: async () => [installed("evil-helper", EVIL_DIR, "warn", ["medium network"])] });
    const ctx = fakeCtx();
    await pi.commands.get("skill-scan")?.handler("", ctx as unknown as ExtensionContext);
    expect(guard.calls.audits).toBe(1);
    const last = ctx.notes.at(-1);
    expect(last?.level).toBe("warning");
    expect(last?.message).toContain("scanned 1 installed skill.");
    expect(last?.message).toContain("evil-helper (warn): medium network");
  });
});
