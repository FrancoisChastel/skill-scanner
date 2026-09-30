import { describe, expect, test } from "bun:test";
import type { Hooks, PluginInput } from "@opencode-ai/plugin";
import * as openCodeModule from "../../src/adapters/opencode";
import { createSkillScannerPlugin } from "../../src/adapters/shared";
import { allow, ask, deny, EVIL, EVIL_DIR, type FakeGuardOptions, fakeGuard, HOME, installed, never, PROJECT, until } from "./fakes";

interface Toast {
  title?: string;
  message: string;
  variant: string;
}

async function start(opts: FakeGuardOptions = {}) {
  const guard = fakeGuard(opts);
  const toasts: Toast[] = [];
  const logs: { level: string; message: string }[] = [];
  const input = {
    client: {
      tui: { showToast: async (o: { body: Toast }) => void toasts.push(o.body) },
      app: { log: async (o: { body: { level: string; message: string } }) => void logs.push(o.body) },
    },
    directory: PROJECT,
    worktree: PROJECT,
  } as unknown as PluginInput;
  const hooks: Hooks = await createSkillScannerPlugin(guard.deps)(input);
  const before = hooks["tool.execute.before"];
  const after = hooks["tool.execute.after"];
  const command = hooks["command.execute.before"];
  if (!before || !after || !command) throw new Error("plugin is missing a hook");
  const call = { sessionID: "ses_1", callID: "call_1" };
  return {
    guard,
    toasts,
    logs,
    before: (tool: string, args: Record<string, unknown>) => before({ tool, ...call }, { args }),
    after: async (tool: string, args: Record<string, unknown>, text = "done") => {
      const output = { title: tool, output: text, metadata: {} };
      await after({ tool, args, ...call }, output);
      return output.output;
    },
    command: (name: string) => command({ command: name, sessionID: "ses_1", arguments: "" }, { parts: [] }),
  };
}

describe("OpenCode plugin module", () => {
  test("exports only functions, because OpenCode calls every export as a plugin", () => {
    const entries = Object.entries(openCodeModule);
    expect(entries.map(([k]) => k)).toEqual(["SkillScanner"]);
    for (const [, v] of entries) expect(typeof v).toBe("function");
  });
});

describe("bash", () => {
  test("a deny throws the guard's reason", async () => {
    const oc = await start({ decide: () => deny("skill-scanner: evil/repo scans as block (prompt injection).") });
    await expect(oc.before("bash", { command: "npx skills add evil/repo" })).rejects.toThrow("scans as block (prompt injection)");
  });

  test("an ask throws, telling the agent to have the user review and trust it", async () => {
    const oc = await start({ decide: () => ask("evil/repo has medium findings.") });
    const err = await oc.before("bash", { command: "npx skills add evil/repo" }).then(
      () => undefined,
      (e: Error) => e.message,
    );
    expect(err).toContain("evil/repo has medium findings.");
    expect(err).toContain("skill-scanner scan evil/repo");
    expect(err).toContain("skill-scanner trust");
    expect(err).toContain("Do not retry");
  });

  test("an allow with a rewrite edits args.command in place", async () => {
    const oc = await start({ decide: () => allow("skill-scanner guard -- npx skills add ok/repo") });
    const args = { command: "npx skills add ok/repo", timeout: 1000 };
    await oc.before("bash", args);
    expect(args).toEqual({ command: "skill-scanner guard -- npx skills add ok/repo", timeout: 1000 });
  });

  test("the guard sees the harness, the working directory, and the config", async () => {
    const oc = await start();
    await oc.before("bash", { command: "ls", workdir: "sub" });
    const ctx = oc.guard.calls.commands[0]?.ctx;
    expect(ctx?.harness).toBe("opencode");
    expect(ctx?.cwd).toBe(`${PROJECT}/sub`);
    expect(ctx?.config.hooks.onError).toBe("ask");
    expect(ctx?.signal).toBeInstanceOf(AbortSignal);
  });

  test("an internal error lets an ordinary command through", async () => {
    const oc = await start({
      decide: () => {
        throw new Error("boom");
      },
    });
    const args = { command: "git status" };
    await oc.before("bash", args);
    expect(args.command).toBe("git status");
    await until(() => oc.toasts.some((t) => t.variant === "error"));
  });

  test("an internal error on an install follows hooks.onError", async () => {
    const failing = {
      decide: (): never => {
        throw new Error("clone failed");
      },
    };
    const denying = await start({ ...failing, config: { onError: "deny" } });
    await expect(denying.before("bash", { command: "npx skills add evil/repo" })).rejects.toThrow(
      "could not check this install: clone failed",
    );
    const asking = await start(failing);
    await expect(asking.before("bash", { command: "npx skills add evil/repo" })).rejects.toThrow("skill-scanner scan evil/repo");
    const allowing = await start({ ...failing, config: { onError: "allow" } });
    await allowing.before("bash", { command: "npx skills add evil/repo" });
  });

  test("a scan that hangs past its deadline counts as an error", async () => {
    const oc = await start({ decide: () => never(), config: { onError: "deny" } });
    await expect(oc.before("bash", { command: "npx skills add slow/repo" })).rejects.toThrow("did not finish");
    const plain = await start({ decide: () => never() });
    await plain.before("bash", { command: "echo hi" });
  });

  test("a command that reaches into a flagged skill is blocked, removing it is not", async () => {
    const oc = await start({ flagged: () => [EVIL] });
    await expect(oc.before("bash", { command: "cat ~/.agents/skills/evil-helper/SKILL.md" })).rejects.toThrow('the skill "evil-helper"');
    await expect(oc.before("bash", { command: `bash ${EVIL_DIR}/scripts/setup.sh` })).rejects.toThrow("flagged (block)");
    await oc.before("bash", { command: "rm -rf ~/.agents/skills/evil-helper" });
    await oc.before("bash", { command: "cat ~/.agents/skills/evil-helper-2/SKILL.md" });
  });
});

describe("skills", () => {
  test("the skill tool throws for a flagged name and passes others", async () => {
    const oc = await start({ flagged: () => [EVIL] });
    await expect(oc.before("skill", { name: "evil-helper" })).rejects.toThrow("skill-scanner audit");
    await oc.before("skill", { name: "pdf-tools" });
  });

  test("a flagged name outside this harness's skill roots does not block a same-named skill", async () => {
    const elsewhere = { ...EVIL, path: `${HOME}/.codex/skills/evil-helper`, realPath: `${HOME}/.codex/skills/evil-helper` };
    const oc = await start({ flagged: () => [elsewhere] });
    await oc.before("skill", { name: "evil-helper" });
  });

  test("reading a file inside a flagged skill throws", async () => {
    const oc = await start({ flagged: () => [EVIL] });
    await expect(oc.before("read", { filePath: `${EVIL_DIR}/SKILL.md` })).rejects.toThrow("evil-helper");
    await expect(oc.before("read", { filePath: "../.agents/skills/evil-helper/references/x.md" })).rejects.toThrow("evil-helper");
    await oc.before("read", { filePath: `${PROJECT}/README.md` });
  });

  test("the gate lifts once the registry no longer lists the skill (trusted)", async () => {
    let entries = [EVIL];
    const oc = await start({ flagged: () => entries });
    await expect(oc.before("skill", { name: "evil-helper" })).rejects.toThrow();
    entries = [];
    await oc.before("skill", { name: "evil-helper" });
  });

  test("command.execute.before blocks a flagged skill's slash command", async () => {
    const oc = await start({ flagged: () => [EVIL] });
    await expect(oc.command("evil-helper")).rejects.toThrow("evil-helper");
    await oc.command("review");
  });
});

describe("writes", () => {
  test("a write into a skill root is evaluated with its full content", async () => {
    const oc = await start({ decideWrite: () => deny("SKILL.md hides instructions in an HTML comment.") });
    const path = `${HOME}/.config/opencode/skills/new-skill/SKILL.md`;
    await expect(oc.before("write", { filePath: path, content: "---\nname: new-skill\n---\n" })).rejects.toThrow("HTML comment");
    expect(oc.guard.calls.writes).toEqual([{ path, content: "---\nname: new-skill\n---\n" }]);
  });

  test("an ask on a write blocks with instructions", async () => {
    const oc = await start({ decideWrite: () => ask("medium findings") });
    await expect(oc.before("write", { filePath: `${PROJECT}/.pi/skills/x/SKILL.md`, content: "x" })).rejects.toThrow(
      "needs the user's approval",
    );
  });

  test("writes elsewhere and edits are not evaluated", async () => {
    const oc = await start({ decideWrite: () => deny("no") });
    await oc.before("write", { filePath: `${PROJECT}/src/index.ts`, content: "x" });
    await oc.before("edit", { filePath: `${HOME}/.agents/skills/a/SKILL.md`, oldString: "a", newString: "b" });
    expect(oc.guard.calls.writes).toEqual([]);
  });

  test("apply_patch evaluates added files inside skill roots", async () => {
    const oc = await start({ decideWrite: (path) => (path.endsWith("bad/SKILL.md") ? deny("bad skill") : allow()) });
    const patchText = [
      "*** Begin Patch",
      "*** Add File: .pi/skills/bad/SKILL.md",
      "+---",
      "+name: bad",
      "+---",
      "*** Update File: src/app.ts",
      "@@",
      "-a",
      "+b",
      "*** End Patch",
    ].join("\n");
    await expect(oc.before("apply_patch", { patchText })).rejects.toThrow("bad skill");
    expect(oc.guard.calls.writes).toEqual([{ path: `${PROJECT}/.pi/skills/bad/SKILL.md`, content: "---\nname: bad\n---\n" }]);
  });
});

describe("after changes", () => {
  const newlyFlagged = [installed("evil-helper", EVIL_DIR, "block", ["critical exfiltration: posts ~/.ssh to a webhook"])];

  test("an install is reconciled and a warning appended to the output and toasted", async () => {
    const oc = await start({ reconcile: async () => ({ newlyFlagged, quarantined: [EVIL_DIR] }) });
    const output = await oc.after("bash", { command: "npx skills add evil/repo" }, "Installed 1 skill");
    expect(output).toStartWith("Installed 1 skill\n\nskill-scanner WARNING");
    expect(output).toContain("evil-helper (block): critical exfiltration");
    expect(output).toContain(`Quarantined (moved out of the skill directories): ${EVIL_DIR}`);
    expect(oc.toasts.some((t) => t.variant === "warning" && t.message.includes("evil-helper"))).toBe(true);
  });

  test("commands that do not touch skills are not reconciled", async () => {
    const oc = await start({ reconcile: async () => ({ newlyFlagged, quarantined: [] }) });
    expect(await oc.after("bash", { command: "npm test" })).toBe("done");
    expect(oc.guard.calls.reconciles).toBe(0);
    await oc.after("bash", { command: "cp -r x ~/.agents/skills/x" });
    await oc.after("edit", { filePath: `${PROJECT}/.pi/skills/y/SKILL.md` });
    expect(oc.guard.calls.reconciles).toBe(2);
  });

  test("a failing rescan leaves the output alone and reports the error once", async () => {
    const oc = await start({ reconcile: async () => Promise.reject(new Error("disk full")) });
    expect(await oc.after("bash", { command: "npx skills add evil/repo" })).toBe("done");
    await until(() => oc.toasts.some((t) => t.variant === "error" && t.message.includes("disk full")));
  });

  test("a slow rescan does not hold the result and toasts when it lands", async () => {
    let finish: (v: { newlyFlagged: typeof newlyFlagged; quarantined: string[] }) => void = () => undefined;
    const late = new Promise<{ newlyFlagged: typeof newlyFlagged; quarantined: string[] }>((r) => {
      finish = r;
    });
    const oc = await start({ reconcile: () => late });
    expect(await oc.after("bash", { command: "npx skills add evil/repo" })).toBe("done");
    finish({ newlyFlagged, quarantined: [] });
    await until(() => oc.toasts.some((t) => t.message.includes("skill-scanner WARNING")));
  });
});

describe("startup", () => {
  test("the audit runs in the background and toasts flagged skills", async () => {
    const oc = await start({
      audit: async () => [
        installed("evil-helper", EVIL_DIR, "block", ["critical prompt-injection"]),
        installed("ok", `${HOME}/.agents/skills/ok`, "pass"),
      ],
    });
    await until(() => oc.toasts.length > 0);
    expect(oc.guard.calls.audits).toBe(1);
    expect(oc.toasts[0]?.message).toContain("1 installed skill is flagged");
    expect(oc.toasts[0]?.message).toContain("evil-helper (block): critical prompt-injection");
    expect(oc.toasts[0]?.message).toContain("skill-scanner audit");
    expect(oc.logs.some((l) => l.level === "warn")).toBe(true);
  });

  test("plugin init does not wait for the audit", async () => {
    const oc = await start({ audit: () => never() });
    await oc.before("bash", { command: "ls" });
    expect(oc.guard.calls.audits).toBe(1);
  });

  test("an audit past its deadline falls back to the registry", async () => {
    const oc = await start({ audit: () => never(), flagged: () => [EVIL] });
    await until(() => oc.toasts.length > 0);
    expect(oc.toasts[0]?.message).toContain("evil-helper");
  });
});
