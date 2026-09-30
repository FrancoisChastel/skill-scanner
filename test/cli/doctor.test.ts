import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { doctorCommand } from "../../src/cli/commands/doctor";
import { setupCommand } from "../../src/cli/commands/setup";
import type { DoctorReport } from "../../src/setup/doctor";
import { formatDecision, tailLines } from "../../src/setup/doctor-env";
import { CLAUDE_PLUGIN_ID } from "../../src/setup/plans";
import { fakeIO, makeTempEnv, type TempEnv } from "../setup/env";

let t: TempEnv;
beforeEach(async () => {
  t = await makeTempEnv();
});
afterEach(async () => {
  await t.cleanup();
});

const doctor = async (argv: string[] = [], env: NodeJS.ProcessEnv = t.env) => {
  const io = fakeIO(env, t.root);
  const code = await doctorCommand.run(argv, io);
  return { code, out: io.out(), err: io.err() };
};
const report = async (env: NodeJS.ProcessEnv = t.env): Promise<DoctorReport> => JSON.parse((await doctor(["--json"], env)).out);
const setup = async (...harnesses: string[]) => {
  const io = fakeIO(t.env, t.root);
  expect(await setupCommand.run([...harnesses, "--yes"], io)).toBe(0);
};
const check = (r: DoctorReport, area: string) => r.checks.filter((c) => c.area === area);
const settingsPath = () => join(t.home, ".claude", "settings.json");

describe("doctor", () => {
  test("fails when the runtime is missing, with the command that fixes it", async () => {
    const r = await doctor();
    expect(r.code).toBe(1);
    expect(r.out).toContain("fail  runtime");
    expect(r.out).toContain("fix: skill-scanner setup");
    expect(r.out).toMatch(/skip {2}claude-code +not detected/);
  });

  test("is all ok after setup, in text and JSON", async () => {
    await setup("claude-code", "codex", "opencode", "pi");
    const r = await doctor();
    expect(r.code).toBe(0);
    expect(r.out).toContain("0 failures, 0 warnings.");
    const json = await report();
    expect(json.ok).toBe(true);
    for (const area of ["runtime", "claude-code", "codex", "opencode", "pi", "config", "state"])
      expect(check(json, area).map((c) => c.status)).toEqual(["ok"]);
    expect(check(json, "codex")[0]!.message).toContain("/hooks");
  });

  test("a detected harness without our hooks is a warning", async () => {
    await setup("pi");
    await mkdir(join(t.home, ".codex"), { recursive: true });
    const r = await report();
    expect(check(r, "codex")).toEqual([
      { area: "codex", status: "warn", message: "skill-scanner hooks are not installed", fix: "skill-scanner setup codex" },
    ]);
    expect(r.ok).toBe(true);
  });

  test("fails when a hook's Node binary is gone", async () => {
    await setup("claude-code");
    const text = await readFile(settingsPath(), "utf8");
    await writeFile(settingsPath(), text.replaceAll(join(t.env.PATH!, "node"), "/nonexistent/node"));
    const r = await report();
    expect(r.ok).toBe(false);
    expect(check(r, "claude-code")).toContainEqual({
      area: "claude-code",
      status: "fail",
      message: `hooks in ${settingsPath()} run Node at /nonexistent/node, which no longer exists`,
      fix: "skill-scanner setup claude-code",
    });
  });

  test("warns about an old runtime, outdated hooks, and disabled hooks", async () => {
    await setup("claude-code");
    await writeFile(join(t.state, "bin", "VERSION"), "0.0.1\n");
    const s = JSON.parse(await readFile(settingsPath(), "utf8"));
    s.disableAllHooks = true;
    s.hooks.PreToolUse[0].hooks[0].timeout = 5;
    await writeFile(settingsPath(), JSON.stringify(s));
    const r = await report();
    expect(check(r, "runtime")[0]).toMatchObject({ status: "warn", fix: "skill-scanner setup" });
    const claude = check(r, "claude-code");
    expect(claude.some((c) => c.status === "warn" && c.message.includes("outdated or incomplete: PreToolUse"))).toBe(true);
    expect(claude.some((c) => c.status === "warn" && c.message.includes("disableAllHooks"))).toBe(true);
  });

  test("the marketplace plugin needs skill-scanner on PATH, and doubles up with setup's hooks", async () => {
    await setup("claude-code");
    const s = JSON.parse(await readFile(settingsPath(), "utf8"));
    await writeFile(settingsPath(), JSON.stringify({ ...s, enabledPlugins: { [CLAUDE_PLUGIN_ID]: true } }));
    const claude = check(await report(), "claude-code");
    expect(claude.some((c) => c.status === "fail" && c.fix === "npm install -g @french-castle/skill-scanner")).toBe(true);
    expect(claude.some((c) => c.status === "warn" && c.message.includes("runs twice"))).toBe(true);
  });

  test("a broken shim target and an unparsable config fail", async () => {
    await setup("pi");
    await rm(join(t.state, "bin", "pi-extension.mjs"));
    await writeFile(join(t.state, "config.json"), "{ nope");
    const r = await report();
    expect(check(r, "pi")[0]).toMatchObject({ status: "fail", fix: "skill-scanner setup pi" });
    expect(check(r, "config")[0]).toMatchObject({ status: "fail" });
    expect(check(r, "judge")[0]).toMatchObject({ status: "skip" });
  });

  test("an enabled judge without a key and an enabled analyzer that is missing are warnings", async () => {
    await setup("pi");
    await writeFile(join(t.state, "config.json"), JSON.stringify({ judge: { enabled: true }, analyzers: { gitleaks: true } }));
    const r = await report();
    expect(check(r, "judge")[0]).toMatchObject({ status: "warn" });
    expect(check(r, "judge")[0]!.message).toContain("enabled but unusable");
    expect(check(r, "gitleaks")[0]).toMatchObject({ status: "warn", message: expect.stringContaining("enabled in the config") });
    expect(check(r, "gitleaks")[0]!.fix).toBeTruthy();
    expect(r.ok).toBe(true);
  });

  test("lists quarantined skills", async () => {
    await setup("pi");
    const dir = join(t.state, "quarantine", "q1");
    await mkdir(dir, { recursive: true });
    const record = {
      id: "q1",
      originalPath: "/x/skills/evil",
      realPath: "/x/skills/evil",
      digest: "sha256:0",
      reason: "block",
      quarantinedAt: "2026-09-30T00:00:00Z",
      links: [],
    };
    await writeFile(join(dir, ".skill-scanner-quarantine.json"), JSON.stringify(record));
    const q = check(await report(), "quarantine");
    expect(q).toHaveLength(1);
    expect(q[0]!.message).toContain("1 skill moved aside after scanning as block (evil)");
  });

  test("shows the last hook decisions", async () => {
    await setup("pi");
    const lines = Array.from({ length: 7 }, (_, i) =>
      JSON.stringify({ ts: `2026-09-30T10:0${i}:00Z`, harness: "claude-code", action: i % 2 ? "deny" : "allow", target: `skill-${i}` }),
    );
    await writeFile(join(t.state, "decisions.jsonl"), `${lines.join("\n")}\n`);
    const r = await doctor();
    expect(r.out).toContain("Recent hook decisions (~/.skill-scanner/decisions.jsonl):");
    expect(r.out).toContain("2026-09-30T10:06:00Z  claude-code  allow  skill-6");
    expect(r.out).not.toContain("skill-1");
  });
});

describe("decision log helpers", () => {
  test("tailLines returns the last lines and nothing for a missing file", async () => {
    const p = join(t.root, "log.jsonl");
    await writeFile(p, "a\n\nb\nc\n");
    expect(await tailLines(p, 2)).toEqual(["b", "c"]);
    expect(await tailLines(p, 2, 3)).toEqual(["c"]);
    expect(await tailLines(join(t.root, "missing"), 5)).toEqual([]);
  });

  test("formatDecision prints known fields and clips unknown lines", () => {
    expect(
      formatDecision('{"ts":"T","harness":"codex","kind":"install","action":"deny","verdict":"block","command":"npx skills add x"}'),
    ).toBe("T  codex  install  deny (block)  npx skills add x");
    expect(formatDecision('{"ts":"T","harness":"claude-code","kind":"session","flagged":["/a","/b"],"quarantined":[]}')).toBe(
      "T  claude-code  session  flagged 2",
    );
    expect(formatDecision("not json")).toBe("not json");
    expect(formatDecision("x".repeat(500))).toHaveLength(160);
  });
});
