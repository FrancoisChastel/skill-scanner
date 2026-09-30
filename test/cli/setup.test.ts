import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { setupCommand } from "../../src/cli/commands/setup";
import { main } from "../../src/cli/main";
import { SHIM_MARKER } from "../../src/setup/plans";
import { SKILL_MARKER } from "../../src/setup/skill";
import { VERSION } from "../../src/version";
import { fakeIO, makeTempEnv, type TempEnv } from "../setup/env";

let t: TempEnv;
beforeEach(async () => {
  t = await makeTempEnv();
});
afterEach(async () => {
  await t.cleanup();
});

const ALL = ["claude-code", "codex", "opencode", "pi"];
const run = async (argv: string[], opts: { tty?: boolean; answer?: boolean; env?: NodeJS.ProcessEnv; cwd?: string } = {}) => {
  const io = fakeIO(opts.env ?? t.env, opts.cwd ?? t.root, opts);
  const code = await setupCommand.run(argv, io);
  return { code, out: io.out(), err: io.err(), asked: io.asked };
};
const read = (...p: string[]) => readFile(join(t.home, ...p), "utf8");
const exists = (...p: string[]) =>
  stat(join(t.home, ...p)).then(
    () => true,
    () => false,
  );
const claudeSettings = () => read(".claude", "settings.json").then((s) => JSON.parse(s));

describe("setup --dry-run", () => {
  test("prints the plan for every named harness and writes nothing", async () => {
    const r = await run([...ALL, "--dry-run"]);
    expect(r.code).toBe(0);
    for (const s of ["Runtime", "Claude Code", "Codex", "OpenCode", "Pi", "~/.claude/settings.json", "~/.codex/hooks.json"])
      expect(r.out).toContain(s);
    expect(r.out).toContain("add hooks: PreToolUse, PostToolUse, SessionStart, ConfigChange, UserPromptExpansion");
    expect(r.out).toContain("Codex skips new hooks until you trust them");
    expect(r.out).toContain("Dry run: nothing was changed");
    expect(await readdir(t.home)).toEqual([]);
  });
});

describe("setup --yes", () => {
  test("installs the runtime, config, and all four harness files, then passes the canary", async () => {
    const r = await run([...ALL, "--yes"]);
    expect(r.err).toBe("");
    expect(r.code).toBe(0);
    const node = join(t.env.PATH!, "node");
    const script = join(t.state, "bin", "skill-scanner.mjs");

    expect(await read(".skill-scanner", "bin", "VERSION")).toBe(`${VERSION}\n`);
    expect((await stat(script)).mode & 0o111).not.toBe(0);
    expect(JSON.parse(await read(".skill-scanner", "config.json"))).toMatchObject({ blockAt: "high", warnAt: "medium" });

    const settings = await claudeSettings();
    expect(settings.hooks.PreToolUse[0].hooks[0].command).toBe(`"${node}" "${script}" hook claude-code`);
    const codex = JSON.parse(await read(".codex", "hooks.json"));
    expect(codex.hooks.SessionStart[0].hooks[0].command).toBe(`"${node}" "${script}" hook codex`);
    const oc = await read(".config", "opencode", "plugins", "skill-scanner.js");
    expect(oc.split("\n")[0]).toBe(SHIM_MARKER);
    expect(oc).toContain("opencode-plugin.mjs");
    expect(await read(".pi", "agent", "extensions", "skill-scanner.js")).toContain(join(t.state, "bin", "pi-extension.mjs"));

    expect(r.out).toContain("ok      hook claude-code allows a harmless command");
    expect(r.out).toContain("ok      scan blocks a malicious test skill");
    expect(r.out).toContain("run /hooks, and trust the skill-scanner entries");
    expect(r.out).toContain("skill-scanner doctor");
  });

  test("a second run changes nothing and makes no backup", async () => {
    await run([...ALL, "--yes"]);
    const again = await run([...ALL, "--yes"]);
    expect(again.code).toBe(0);
    expect(again.out).toContain("Nothing to change.");
    expect(again.out).not.toContain("Applied");
    expect(await exists(".claude", "settings.json.skill-scanner.bak")).toBe(false);
  });

  test("merges into an existing settings.json, keeping the user's hooks and a backup of the original", async () => {
    await mkdir(join(t.home, ".claude"), { recursive: true });
    const original = JSON.stringify(
      { model: "opus", hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "mine.sh" }] }] } },
      null,
      2,
    );
    await writeFile(join(t.home, ".claude", "settings.json"), original);
    const r = await run(["claude-code", "--yes"]);
    expect(r.code).toBe(0);
    const s = await claudeSettings();
    expect(s.model).toBe("opus");
    expect(s.hooks.PreToolUse[0].hooks[0].command).toBe("mine.sh");
    expect(s.hooks.PreToolUse).toHaveLength(2);
    expect(await read(".claude", "settings.json.skill-scanner.bak")).toBe(original);
    expect(r.out).toContain("backup  ~/.claude/settings.json.skill-scanner.bak");
  });

  test("refuses an unparsable file but sets up the other harnesses, and exits 2", async () => {
    await mkdir(join(t.home, ".claude"), { recursive: true });
    await writeFile(join(t.home, ".claude", "settings.json"), "{ broken");
    const r = await run(["claude-code", "pi", "--yes"]);
    expect(r.code).toBe(2);
    expect(r.out).toContain("refuse");
    expect(r.out).toContain("not valid JSON");
    expect(await read(".claude", "settings.json")).toBe("{ broken");
    expect(await exists(".pi", "agent", "extensions", "skill-scanner.js")).toBe(true);
  });

  test("reports a failing canary and exits 2", async () => {
    const r = await run(["claude-code", "--yes"], { env: { ...t.env, FAKE_HOOK_DENY: "1" } });
    expect(r.code).toBe(2);
    expect(r.out).toContain("fail    hook claude-code allows a harmless command: denied: nope");
    expect(r.err).toContain("the canary failed");
  });
});

describe("confirmation", () => {
  test("without a terminal and without --yes, prints the plan and exits 2", async () => {
    const r = await run(["codex"]);
    expect(r.code).toBe(2);
    expect(r.out).toContain("~/.codex/hooks.json");
    expect(r.err).toContain("--yes");
    expect(await readdir(t.home)).toEqual([]);
  });

  test("on a terminal, asks, and applies only on yes", async () => {
    const no = await run(["codex"], { tty: true, answer: false });
    expect(no.code).toBe(1);
    expect(no.asked).toHaveLength(1);
    expect(await exists(".codex", "hooks.json")).toBe(false);
    const yes = await run(["codex"], { tty: true, answer: true });
    expect(yes.code).toBe(0);
    expect(await exists(".codex", "hooks.json")).toBe(true);
  });
});

describe("harness selection", () => {
  test("with no harness named, sets up only the detected ones", async () => {
    await mkdir(join(t.home, ".codex"), { recursive: true });
    const r = await run(["--yes"]);
    expect(r.code).toBe(0);
    expect(r.out).toContain("install for Codex (user scope)");
    expect(r.out).toContain("not detected: Claude Code, OpenCode, Pi");
    expect(await exists(".claude", "settings.json")).toBe(false);
  });

  test("with nothing detected, explains how to name one", async () => {
    const r = await run(["--yes"]);
    expect(r.code).toBe(2);
    expect(r.err).toContain("no coding agent found");
    expect(r.err).toContain("setup claude-code");
  });

  test("an unknown harness is a usage error", async () => {
    const io = fakeIO(t.env, t.root);
    expect(await main(["setup", "cursor"], io)).toBe(2);
    expect(io.err()).toContain('unknown harness "cursor"');
  });

  test("--project writes into the current directory", async () => {
    const proj = join(t.root, "proj");
    await mkdir(proj);
    const r = await run(["claude-code", "codex", "opencode", "pi", "--project", "--yes"], { cwd: proj });
    expect(r.code).toBe(0);
    for (const p of [".claude/settings.json", ".codex/hooks.json", ".opencode/plugins/skill-scanner.js", ".pi/extensions/skill-scanner.js"])
      expect(await stat(join(proj, p)).then(() => true)).toBe(true);
    expect(await exists(".claude", "settings.json")).toBe(false);
  });
});

describe("--with-skill", () => {
  test("copies the bundled skill for Claude Code and the shared .agents directory, and uninstall removes the copies", async () => {
    const r = await run(["claude-code", "codex", "--with-skill", "--yes"]);
    expect(r.code).toBe(0);
    for (const dir of [
      [".claude", "skills", "skill-scanner"],
      [".agents", "skills", "skill-scanner"],
    ]) {
      expect(await read(...dir, "SKILL.md")).toContain("name: skill-scanner");
      expect(await exists(...dir, SKILL_MARKER)).toBe(true);
    }
    const u = await run(["--uninstall", "--yes"]);
    expect(u.code).toBe(0);
    expect(await exists(".claude", "skills", "skill-scanner")).toBe(false);
    expect(await exists(".agents", "skills", "skill-scanner")).toBe(false);
  });
});

describe("setup --uninstall", () => {
  test("removes only what setup added, keeps state unless --purge", async () => {
    await mkdir(join(t.home, ".claude"), { recursive: true });
    const mine = { hooks: { Stop: [{ hooks: [{ type: "command", command: "notify.sh" }] }] } };
    await writeFile(join(t.home, ".claude", "settings.json"), JSON.stringify(mine));
    await mkdir(join(t.home, ".pi", "agent", "extensions"), { recursive: true });
    await writeFile(join(t.home, ".pi", "agent", "extensions", "other.js"), "export default () => {};\n");
    await run([...ALL, "--yes"]);

    const u = await run(["--uninstall", "--yes"]);
    expect(u.code).toBe(0);
    expect(await claudeSettings()).toEqual(mine);
    expect(await exists(".codex", "hooks.json")).toBe(false);
    expect(await exists(".config", "opencode", "plugins", "skill-scanner.js")).toBe(false);
    expect(await exists(".pi", "agent", "extensions", "skill-scanner.js")).toBe(false);
    expect(await exists(".pi", "agent", "extensions", "other.js")).toBe(true);
    expect(await exists(".skill-scanner", "bin")).toBe(false);
    expect(await exists(".skill-scanner", "config.json")).toBe(true);
    expect(await exists(".claude", "settings.json.skill-scanner.bak")).toBe(true);

    const again = await run(["--uninstall", "--yes"]);
    expect(again.out).toContain("Nothing to remove.");

    const purge = await run(["--purge", "--yes"]);
    expect(purge.code).toBe(0);
    expect(await exists(".skill-scanner")).toBe(false);
  });

  test("uninstalling one harness leaves the others and the runtime in place", async () => {
    await run(["codex", "pi", "--yes"]);
    const u = await run(["codex", "--uninstall", "--yes"]);
    expect(u.code).toBe(0);
    expect(await exists(".codex", "hooks.json")).toBe(false);
    expect(await exists(".pi", "agent", "extensions", "skill-scanner.js")).toBe(true);
    expect(await exists(".skill-scanner", "bin", "skill-scanner.mjs")).toBe(true);
  });

  test("a project uninstall keeps the user-level runtime; --purge is user-level only", async () => {
    const proj = join(t.root, "proj");
    await mkdir(proj);
    await run(["pi", "--yes"]);
    await run(["pi", "--project", "--yes"], { cwd: proj });
    const u = await run(["--uninstall", "--project", "--yes"], { cwd: proj });
    expect(u.code).toBe(0);
    expect(await stat(join(proj, ".pi", "extensions", "skill-scanner.js")).catch(() => undefined)).toBeUndefined();
    expect(await exists(".pi", "agent", "extensions", "skill-scanner.js")).toBe(true);
    expect(await exists(".skill-scanner", "bin", "skill-scanner.mjs")).toBe(true);
    await expect(run(["--purge", "--project", "--yes"], { cwd: proj })).rejects.toThrow("without --project");
  });

  test("a plain uninstall removes only runtime files when bin holds something else", async () => {
    await run(["pi", "--yes"]);
    await writeFile(join(t.state, "bin", "notes.txt"), "mine");
    const u = await run(["--uninstall", "--yes"]);
    expect(u.code).toBe(0);
    expect(u.out).toContain("also holds notes.txt; left in place");
    expect(await readdir(join(t.state, "bin"))).toEqual(["notes.txt"]);
  });

  test("--purge of a custom state directory named .skill-scanner still checks its contents", async () => {
    const custom = join(t.root, "elsewhere", ".skill-scanner");
    await mkdir(custom, { recursive: true });
    await writeFile(join(custom, "data.db"), "x");
    const r = await run(["--purge", "--yes"], { env: { ...t.env, SKILL_SCANNER_HOME: custom } });
    expect(r.code).toBe(2);
    expect(await readFile(join(custom, "data.db"), "utf8")).toBe("x");
  });

  test("--purge refuses a state directory holding files it did not create", async () => {
    const custom = join(t.root, "custom-state");
    await mkdir(custom);
    await writeFile(join(custom, "thesis.docx"), "precious");
    const r = await run(["--purge", "--yes"], { env: { ...t.env, SKILL_SCANNER_HOME: custom } });
    expect(r.code).toBe(2);
    expect(r.out).toContain("did not create (thesis.docx)");
    expect(await readFile(join(custom, "thesis.docx"), "utf8")).toBe("precious");
  });
});
