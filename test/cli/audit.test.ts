import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { lstat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { UsageError } from "../../src/cli/args";
import { auditCommand } from "../../src/cli/commands/audit";
import type { CliIO } from "../../src/cli/io";
import type { InstalledSkill } from "../../src/guard/types";
import { canarySkill } from "../../src/setup/canary";
import { link, type TempHome, tempHome, writeSkill } from "../guard/helpers";

let h: TempHome;
beforeEach(async () => {
  h = await tempHome();
  await writeSkill(h.path(".agents", "skills", "fine"), "fine");
  await link(h.path(".agents", "skills", "fine"), h.path(".claude", "skills", "fine"));
  const evil = h.path(".claude", "skills", "canary-skill");
  await writeSkill(evil, "canary-skill");
  await writeFile(join(evil, "SKILL.md"), canarySkill());
});
afterEach(async () => {
  await h.cleanup();
});

function fakeIO(): CliIO & { out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return {
    out,
    err,
    stdout: (t) => out.push(t),
    stderr: (t) => err.push(t),
    isTTY: false,
    env: h.env,
    cwd: h.path("proj"),
    readStdin: async () => "",
    confirm: async () => false,
  };
}

const mine = (skills: readonly InstalledSkill[]): InstalledSkill[] => skills.filter((s) => s.path.startsWith(h.home));
const exists = (p: string): Promise<boolean> =>
  lstat(p).then(
    () => true,
    () => false,
  );

describe("skill-scanner audit", () => {
  test("JSON lists each installed skill once and exits 1 while an untrusted block remains", async () => {
    const io = fakeIO();
    expect(await auditCommand.run(["--format", "json"], io)).toBe(1);
    const skills = mine(JSON.parse(io.out.join("")) as InstalledSkill[]);
    expect(skills.map((s) => `${s.name}:${s.verdict}`).sort()).toEqual(["canary-skill:block", "fine:pass"]);
  });

  test("the text table shows verdict, harness, scope, name, path, and top finding", async () => {
    const io = fakeIO();
    await auditCommand.run([], io);
    const text = io.out.join("");
    expect(text).toMatch(/^VERDICT\s+HARNESS\s+SCOPE\s+NAME\s+PATH\s+TOP FINDING\n/);
    expect(text).toMatch(/\nblock\s+claude-code\s+user\s+canary-skill\s+~\/\.claude\/skills\/canary-skill\s+\S+/);
    expect(text).toContain("from cache");
    const again = fakeIO();
    await auditCommand.run(["--no-cache"], again);
    expect(again.out.join("")).toContain("(0 from cache");
  });

  test("--quarantine moves blocked skills; --list-quarantine and --restore bring them back", async () => {
    const io = fakeIO();
    expect(await auditCommand.run(["--quarantine"], io)).toBe(0);
    expect(io.out.join("")).toMatch(/block \(quarantined\)/);
    expect(await exists(h.path(".claude", "skills", "canary-skill"))).toBe(false);

    const list = fakeIO();
    await auditCommand.run(["--list-quarantine", "--format", "json"], list);
    const [rec] = JSON.parse(list.out.join("")) as { id: string; originalPath: string }[];
    expect(rec?.originalPath).toBe(h.path(".claude", "skills", "canary-skill"));

    const restore = fakeIO();
    expect(await auditCommand.run(["--restore", rec!.id], restore)).toBe(0);
    expect(restore.out.join("")).toContain("flagged again unless you approve");
    expect(await exists(h.path(".claude", "skills", "canary-skill", "SKILL.md"))).toBe(true);
  });

  test("--harness narrows the roots and rejects unknown names", async () => {
    const io = fakeIO();
    expect(await auditCommand.run(["--harness", "codex", "--format", "json"], io)).toBe(0);
    expect(mine(JSON.parse(io.out.join(""))).map((s) => s.name)).toEqual(["fine"]);
    await expect(auditCommand.run(["--harness", "cursor"], fakeIO())).rejects.toBeInstanceOf(UsageError);
    await expect(auditCommand.run(["--format", "sarif"], fakeIO())).rejects.toBeInstanceOf(UsageError);
  });
});
