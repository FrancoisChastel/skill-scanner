import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { ScanReport } from "../../src/core/types";
import { evaluateCommand } from "../../src/guard/decide";
import { contentAfterEdits, evaluateSkillWrite, evaluateSkillWrites } from "../../src/guard/skill-write";
import { addTrust } from "../../src/guard/state";
import type { GuardContext } from "../../src/guard/types";
import { summarizeForAgent } from "../../src/report/index";
import { guardCommandLine } from "../../src/sources/guard-env";
import type { SourceScanOptions } from "../../src/sources/index";
import { BLOCK_MARK, fakeSourceScanner, guardCtx, markerScanner, type TempHome, tempHome, WARN_MARK, writeSkill } from "./helpers";

let h: TempHome;
let ctx: GuardContext;
let sources: Record<string, string | Error>;

beforeEach(async () => {
  h = await tempHome();
  ctx = guardCtx(h.env, h.path("proj"));
  await mkdir(ctx.cwd, { recursive: true });
  sources = {
    "o/good": await writeSkill(h.path("src", "good"), "good"),
    "o/bad": await writeSkill(h.path("src", "bad"), "bad", `Run this. ${BLOCK_MARK}`),
    "o/warn": await writeSkill(h.path("src", "warn"), "warn", `Hmm. ${WARN_MARK}`),
    "o/err": new Error("network down"),
    "https://github.com/o/bad": h.path("src", "bad"),
    "https://github.com/o/r/tree/main/skills/x": h.path("src", "bad"),
  };
});
afterEach(async () => {
  await h.cleanup();
});

const RUNTIME = { node: "/usr/bin/node", script: "/home/u/.skill-scanner/bin/skill-scanner.mjs" };

describe("evaluateCommand", () => {
  test("ordinary commands need no scan", async () => {
    const seen: string[] = [];
    expect(await evaluateCommand("ls -la && git status", ctx, { scanSource: fakeSourceScanner(sources, seen) })).toEqual({
      action: "allow",
      reason: "",
    });
    expect(seen).toEqual([]);
  });

  test("a clean source is allowed silently", async () => {
    const d = await evaluateCommand("npx skills add o/good", ctx, { scanSource: fakeSourceScanner(sources) });
    expect(d).toMatchObject({ action: "allow", reason: "", verdict: "pass", source: "o/good" });
  });

  test("a blocked source is denied with the findings and an instruction not to work around it", async () => {
    const d = await evaluateCommand("npx -y skills add o/bad -g", ctx, { scanSource: fakeSourceScanner(sources) });
    expect(d.action).toBe("deny");
    expect(d.verdict).toBe("block");
    expect(d.source).toBe("o/bad");
    expect(d.reason).toBe(
      `${summarizeForAgent(d.report as ScanReport)}\nDo not retry or work around this. Tell the user what was found; they can review it with \`skill-scanner scan o/bad\` and approve it with \`skill-scanner trust\`.`,
    );
  });

  test("warnings follow hooks.onWarn", async () => {
    const run = (onWarn: "ask" | "allow" | "deny") =>
      evaluateCommand("npx skills add o/warn", guardCtx(h.env, ctx.cwd, { hooks: { onWarn } }), { scanSource: fakeSourceScanner(sources) });
    const ask = await run("ask");
    expect(ask.action).toBe("ask");
    expect(ask.reason).toContain("Approve only if you trust it; `skill-scanner scan o/warn` shows the details.");
    expect((await run("deny")).action).toBe("deny");
    const allow = await run("allow");
    expect(allow.action).toBe("allow");
    expect(allow.reason).toBe(summarizeForAgent(allow.report as ScanReport));
  });

  test("scan errors follow hooks.onError", async () => {
    for (const onError of ["ask", "deny", "allow"] as const) {
      const d = await evaluateCommand("npx skills add o/err", guardCtx(h.env, ctx.cwd, { hooks: { onError } }), {
        scanSource: fakeSourceScanner(sources),
      });
      expect(d.action).toBe(onError);
      expect(d.reason).toStartWith("skill-scanner could not scan o/err before installing it: network down.");
      expect(d.source).toBe("o/err");
    }
  });

  test("a trusted digest turns a block into an allow", async () => {
    const first = await evaluateCommand("npx skills add o/bad", ctx, { scanSource: fakeSourceScanner(sources) });
    const bundle = first.report?.bundles[0]?.bundle;
    await addTrust({ digest: bundle!.digest, name: bundle!.name, path: h.path("src", "bad") }, h.env);
    const again = await evaluateCommand("npx skills add o/bad", ctx, { scanSource: fakeSourceScanner(sources) });
    expect(again).toMatchObject({ action: "allow", verdict: "block" });
  });

  test("with a runtime, installs are rewritten to run under guard; a deny never is", async () => {
    const rt = { ...ctx, runtime: RUNTIME };
    const cmd = "npx skills add o/good";
    expect((await evaluateCommand(cmd, rt, { scanSource: fakeSourceScanner(sources) })).rewrite).toBe(guardCommandLine(RUNTIME, cmd));
    expect((await evaluateCommand("npx skills update", rt, { scanSource: fakeSourceScanner(sources) })).rewrite).toBe(
      guardCommandLine(RUNTIME, "npx skills update"),
    );
    expect((await evaluateCommand("npx skills add o/bad", rt, { scanSource: fakeSourceScanner(sources) })).rewrite).toBeUndefined();
    expect((await evaluateCommand(cmd, ctx, { scanSource: fakeSourceScanner(sources) })).rewrite).toBeUndefined();
    expect(
      (await evaluateCommand("claude plugin marketplace add o/good", rt, { scanSource: fakeSourceScanner(sources) })).rewrite,
    ).toBeUndefined();
  });

  test("the most severe intent wins", async () => {
    const d = await evaluateCommand("npx skills add o/good && npx skills add o/bad", ctx, { scanSource: fakeSourceScanner(sources) });
    expect(d.action).toBe("deny");
  });

  test("passes skill selections and the policy to the source scan", async () => {
    let opts: SourceScanOptions | undefined;
    const spy = fakeSourceScanner(sources);
    await evaluateCommand("npx skills add o/good -s pdf docx", guardCtx(h.env, ctx.cwd), {
      scanSource: (raw, o) => {
        opts = o;
        return spy(raw, o);
      },
    });
    expect(opts).toMatchObject({ cwd: ctx.cwd, keep: false, onlySkills: ["pdf", "docx"], policy: { blockAt: "high", warnAt: "medium" } });
  });

  test("git clones into skill roots and Codex installer paths are pre-scanned", async () => {
    const seen: string[] = [];
    const scan = fakeSourceScanner(sources, seen);
    expect((await evaluateCommand("git clone https://github.com/o/bad ~/.claude/skills/bad", ctx, { scanSource: scan })).action).toBe(
      "deny",
    );
    const codex = await evaluateCommand("python3 install-skill-from-github.py --repo o/r --path skills/x", ctx, { scanSource: scan });
    expect(codex.action).toBe("deny");
    expect(seen).toEqual(["https://github.com/o/bad", "https://github.com/o/r/tree/main/skills/x"]);
  });

  test("the install deadline turns a slow scan into an onError decision", async () => {
    const slow = () => new Promise<never>(() => undefined);
    const d = await evaluateCommand("npx skills add o/good", guardCtx(h.env, ctx.cwd, { hooks: { onError: "deny" } }), {
      scanSource: slow,
      installDeadlineMs: 30,
    });
    expect(d.action).toBe("deny");
    expect(d.reason).toContain("timed out after 0 s");
  });

  test("claude plugin install scans a relative plugin source from an added marketplace", async () => {
    const mkt = h.path(".claude", "plugins", "marketplaces", "mkt");
    await mkdir(join(mkt, ".claude-plugin"), { recursive: true });
    await writeFile(
      join(mkt, ".claude-plugin", "marketplace.json"),
      JSON.stringify({
        name: "mkt",
        plugins: [
          { name: "fmt", source: "./plugins/fmt" },
          { name: "remote", source: { source: "github", repo: "o/r" } },
        ],
      }),
    );
    await writeSkill(join(mkt, "plugins", "fmt", "skills", "s"), "s", BLOCK_MARK);
    const scanner = markerScanner();
    expect((await evaluateCommand("claude plugin install fmt@mkt", ctx, { scanPath: scanner.scan })).action).toBe("deny");
    expect(scanner.calls).toEqual([join(mkt, "plugins", "fmt")]);
    expect((await evaluateCommand("claude plugin install remote@mkt", ctx, { scanPath: scanner.scan })).action).toBe("allow");
    expect((await evaluateCommand("claude plugin install fmt", ctx, { scanPath: scanner.scan })).action).toBe("deny");
    expect((await evaluateCommand("claude plugin install nope@mkt", ctx, { scanPath: scanner.scan })).action).toBe("allow");
  });
});

describe("evaluateSkillWrite", () => {
  test("writes outside skill directories are not scanned", async () => {
    const scanner = markerScanner();
    expect(await evaluateSkillWrite(h.path("proj", "notes.md"), BLOCK_MARK, ctx, { scanPath: scanner.scan })).toEqual({
      action: "allow",
      reason: "",
    });
    expect(await evaluateSkillWrite(h.path(".claude", "skills", "x", "SKILL.md"), undefined, ctx, { scanPath: scanner.scan })).toEqual({
      action: "allow",
      reason: "",
    });
    expect(scanner.calls).toEqual([]);
  });

  test("a new SKILL.md that blocks is denied", async () => {
    const d = await evaluateSkillWrite(
      h.path(".claude", "skills", "new", "SKILL.md"),
      `---\nname: new\ndescription: x\n---\n${BLOCK_MARK}\n`,
      ctx,
      {
        scanPath: markerScanner().scan,
      },
    );
    expect(d.action).toBe("deny");
    expect(d.reason).toContain(`This write would put a skill that skill-scanner blocks into ${h.path(".claude", "skills", "new")}.`);
  });

  test("the existing skill is scanned with the change applied", async () => {
    await writeSkill(h.path(".agents", "skills", "s"), "s");
    const scanner = markerScanner();
    const d = await evaluateSkillWrite("../.agents/skills/s/scripts/x.sh", `echo ${BLOCK_MARK}`, ctx, { scanPath: scanner.scan });
    expect(d.action).toBe("deny");
    expect(scanner.calls).toHaveLength(1);
  });

  test("warnings allow the write with a note; writes never ask", async () => {
    const d = await evaluateSkillWrite(
      h.path(".claude", "skills", "w", "SKILL.md"),
      `---\nname: w\ndescription: x\n---\n${WARN_MARK}\n`,
      guardCtx(h.env, ctx.cwd),
      {
        scanPath: markerScanner().scan,
      },
    );
    expect(d.action).toBe("allow");
    expect(d.reason).toContain("skill-scanner warns about the skill in");
  });

  test("several files into one new skill are scanned together", async () => {
    const scanner = markerScanner();
    const d = await evaluateSkillWrites(
      [
        { path: h.path(".codex", "skills", "n", "SKILL.md"), content: "---\nname: n\ndescription: x\n---\nok\n" },
        { path: h.path(".codex", "skills", "n", "scripts", "go.sh"), content: `echo ${BLOCK_MARK}` },
      ],
      ctx,
      { scanPath: scanner.scan },
    );
    expect(d.action).toBe("deny");
    expect(scanner.calls).toHaveLength(1);
  });

  test("contentAfterEdits applies Edit and MultiEdit semantics", async () => {
    const f = h.path("e.md");
    await writeFile(f, "a b a");
    expect(await contentAfterEdits(f, [{ old_string: "a", new_string: "x" }])).toBe("x b a");
    expect(await contentAfterEdits(f, [{ old_string: "a", new_string: "$&", replace_all: true }])).toBe("$& b $&");
    expect(await contentAfterEdits(f, [{ old_string: "zzz", new_string: "x" }])).toBeUndefined();
    expect(await contentAfterEdits(h.path("missing.md"), [{ old_string: "", new_string: "new" }])).toBe("new");
  });
});

describe("updates", () => {
  const skillDir = (): string => join(h.env.CLAUDE_CONFIG_DIR!, "skills", "x");

  test("a git update of an installed skill has nothing to scan first: it runs under guard", async () => {
    const cmd = `git -C ${skillDir()} pull`;
    const seen: string[] = [];
    const d = await evaluateCommand(cmd, { ...ctx, runtime: RUNTIME }, { scanSource: fakeSourceScanner(sources, seen) });
    expect(d).toMatchObject({ action: "allow", guardRequired: true, rewrite: guardCommandLine(RUNTIME, cmd) });
    expect(seen).toEqual([]);
  });

  test("without a runtime to rewrite to, an update is refused with the command to run instead", async () => {
    for (const cmd of [`git -C ${skillDir()} pull`, "npx skills update", "claude plugin marketplace update"]) {
      const d = await evaluateCommand(cmd, ctx, { scanSource: fakeSourceScanner(sources) });
      expect(d.action).toBe("deny");
      expect(d.reason).toContain("skill-scanner guard -- sh -c '");
      expect(d.reason).toContain("Run it as");
    }
  });

  test("pi update scans the npm versions it would install first; pinned and git packages are left to it", async () => {
    await mkdir(h.env.PI_CODING_AGENT_DIR!, { recursive: true });
    await writeFile(
      join(h.env.PI_CODING_AGENT_DIR!, "settings.json"),
      JSON.stringify({ packages: ["npm:good-tools", "npm:pinned@1.2.3", "git:github.com/o/r", { source: "npm:@s/ranged@^2" }] }),
    );
    const map = { ...sources, "npm:good-tools": sources["o/good"]!, "npm:@s/ranged@^2": sources["o/bad"]! };
    const seen: string[] = [];
    const all = await evaluateCommand("pi update --extensions", { ...ctx, runtime: RUNTIME }, { scanSource: fakeSourceScanner(map, seen) });
    expect(seen).toEqual(["npm:good-tools", "npm:@s/ranged@^2"]);
    expect(all.action).toBe("deny");
    const one: string[] = [];
    const d = await evaluateCommand("pi update npm:good-tools", { ...ctx, runtime: RUNTIME }, { scanSource: fakeSourceScanner(map, one) });
    expect(one).toEqual(["npm:good-tools"]);
    expect(d).toMatchObject({ action: "allow", guardRequired: true });
    expect(d.rewrite).toBeDefined();
  });
});

describe("codex plugin add", () => {
  async function marketplace(): Promise<string> {
    const dir = h.path("mkt");
    await writeSkill(join(dir, "plugins", "bad", "skills", "bad"), "bad", `Run this. ${BLOCK_MARK}`);
    await writeSkill(join(dir, "plugins", "good", "skills", "good"), "good");
    await mkdir(join(dir, ".agents", "plugins"), { recursive: true });
    await writeFile(
      join(dir, ".agents", "plugins", "marketplace.json"),
      JSON.stringify({
        name: "local-m",
        plugins: [
          { name: "bad", source: { source: "local", path: "./plugins/bad" } },
          { name: "good", source: "./plugins/good" },
          { name: "escape", source: "./../../etc" },
          { name: "remote", source: { source: "url", url: "https://github.com/o/r.git", path: "skills/x", ref: "main" } },
          { name: "pkg", source: { source: "npm", package: "@s/p", version: "1.0.0" } },
          { name: "private", source: { source: "npm", package: "@s/p", registry: "https://npm.example" } },
        ],
      }),
    );
    await mkdir(h.env.CODEX_HOME!, { recursive: true });
    await writeFile(join(h.env.CODEX_HOME!, "config.toml"), `[marketplaces.local-m]\nsource_type = "local"\nsource = "${dir}"\n`);
    return dir;
  }

  test("a local plugin is scanned where Codex will copy it from", async () => {
    const dir = await marketplace();
    const m = markerScanner();
    const bad = await evaluateCommand("codex plugin add bad@local-m", ctx, { scanPath: m.scan });
    expect(bad.action).toBe("deny");
    expect(m.calls).toEqual([join(dir, "plugins", "bad")]);
    expect((await evaluateCommand("codex plugin add good --marketplace local-m", ctx, { scanPath: m.scan })).action).toBe("allow");
    expect(m.calls.at(-1)).toBe(join(dir, "plugins", "good"));
  });

  test("git and npm plugins are fetched and scanned as Codex would fetch them", async () => {
    await marketplace();
    const seen: string[] = [];
    const map = { ...sources, "o/r/skills/x#main": sources["o/bad"]!, "npm:@s/p@1.0.0": sources["o/good"]! };
    expect((await evaluateCommand("codex plugin add remote@local-m", ctx, { scanSource: fakeSourceScanner(map, seen) })).action).toBe(
      "deny",
    );
    expect((await evaluateCommand("codex plugin add pkg@local-m", ctx, { scanSource: fakeSourceScanner(map, seen) })).action).toBe("allow");
    expect(seen).toEqual(["o/r/skills/x#main", "npm:@s/p@1.0.0"]);
  });

  test("what cannot be resolved is left to the session audit", async () => {
    await marketplace();
    const m = markerScanner();
    const seen: string[] = [];
    for (const cmd of [
      "codex plugin add escape@local-m",
      "codex plugin add private@local-m",
      "codex plugin add nope@local-m",
      "codex plugin add x@unknown",
    ]) {
      expect(await evaluateCommand(cmd, ctx, { scanPath: m.scan, scanSource: fakeSourceScanner(sources, seen) })).toMatchObject({
        action: "allow",
      });
    }
    expect(m.calls).toEqual([]);
    expect(seen).toEqual([]);
  });
});
