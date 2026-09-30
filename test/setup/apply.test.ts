import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { lstat, mkdir, mkdtemp, readdir, readFile, realpath, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { applyOps } from "../../src/setup/apply";
import { BACKUP_SUFFIX, type FileOp } from "../../src/setup/ops";
import { planSkillCopy, planSkillRemove, readTree, SKILL_MARKER } from "../../src/setup/skill";

let dir: string;
beforeEach(async () => {
  dir = await realpath(await mkdtemp(join(tmpdir(), "skill-scanner-apply-")));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

const write = (path: string, before: string | undefined, after: string, extra: Partial<FileOp> = {}): FileOp =>
  ({ kind: "write", path, ...(before !== undefined ? { before } : {}), after, backup: true, summary: "t", ...extra }) as FileOp;

describe("applyOps", () => {
  test("creates parent directories and writes new files without a backup", async () => {
    const p = join(dir, "a", "b", "settings.json");
    const r = await applyOps([write(p, undefined, "{}\n")]);
    expect(r.failed).toBeUndefined();
    expect(await readFile(p, "utf8")).toBe("{}\n");
    expect(r.backups).toEqual([]);
  });

  test("backs up an existing file once and never overwrites that first backup", async () => {
    const p = join(dir, "settings.json");
    await writeFile(p, "original");
    const first = await applyOps([write(p, "original", "one")]);
    expect(first.backups).toEqual([`${p}${BACKUP_SUFFIX}`]);
    const second = await applyOps([write(p, "one", "two")]);
    expect(second.backups).toEqual([]);
    expect(await readFile(`${p}${BACKUP_SUFFIX}`, "utf8")).toBe("original");
    expect(await readFile(p, "utf8")).toBe("two");
  });

  test("leaves no temp files behind and keeps the file's permissions", async () => {
    const p = join(dir, "settings.json");
    await writeFile(p, "x", { mode: 0o600 });
    await applyOps([write(p, "x", "y")]);
    expect((await stat(p)).mode & 0o777).toBe(0o600);
    expect((await readdir(dir)).sort()).toEqual(["settings.json", `settings.json${BACKUP_SUFFIX}`]);
  });

  test("applies an explicit mode", async () => {
    const p = join(dir, "bin", "skill-scanner.mjs");
    await applyOps([write(p, undefined, "#!/usr/bin/env node\n", { mode: 0o755, backup: false } as Partial<FileOp>)]);
    expect((await stat(p)).mode & 0o777).toBe(0o755);
  });

  test("writes through a symlink instead of replacing it", async () => {
    const real = join(dir, "dotfiles", "settings.json");
    await mkdir(join(dir, "dotfiles"));
    await writeFile(real, "a");
    const link = join(dir, "settings.json");
    await symlink(real, link);
    await applyOps([write(link, "a", "b")]);
    expect((await lstat(link)).isSymbolicLink()).toBe(true);
    expect(await readFile(real, "utf8")).toBe("b");
    expect(await readFile(`${link}${BACKUP_SUFFIX}`, "utf8")).toBe("a");
  });

  test("a broken symlink is reported plainly", async () => {
    const link = join(dir, "settings.json");
    await symlink(join(dir, "gone.json"), link);
    const r = await applyOps([write(link, undefined, "{}")]);
    expect(r.failed?.error).toContain("symlink to a file that does not exist");
  });

  test("stops at a file that changed after planning and reports what was done", async () => {
    const a = join(dir, "a.json");
    const b = join(dir, "b.json");
    const c = join(dir, "c.json");
    await writeFile(b, "changed by someone else");
    const r = await applyOps([write(a, undefined, "A"), write(b, "planned", "B"), write(c, undefined, "C")]);
    expect(r.applied.map((o) => o.path)).toEqual([a]);
    expect(r.failed?.op.path).toBe(b);
    expect(r.failed?.error).toContain("changed after setup read it");
    expect(await readFile(b, "utf8")).toBe("changed by someone else");
    await expect(stat(c)).rejects.toThrow();
  });

  test("removes files and directories", async () => {
    const f = join(dir, "shim.js");
    await writeFile(f, "x");
    await mkdir(join(dir, "d", "e"), { recursive: true });
    const r = await applyOps([
      { kind: "remove", path: f, before: "x", summary: "t" },
      { kind: "remove-dir", path: join(dir, "d"), summary: "t" },
    ]);
    expect(r.failed).toBeUndefined();
    expect(await readdir(dir)).toEqual([]);
  });
});

describe("skill copies", () => {
  test("copies the skill with a marker, updates it, and removes only a marked copy", async () => {
    const src = join(dir, "src");
    await mkdir(join(src, "references"), { recursive: true });
    await writeFile(join(src, "SKILL.md"), "---\nname: skill-scanner\n---\n");
    await writeFile(join(src, "references", "a.md"), "A");
    const target = join(dir, "skills", "skill-scanner");
    const source = (await readTree(src))!;

    const first = planSkillCopy(target, source, await readTree(target));
    expect((await applyOps(first.ops)).failed).toBeUndefined();
    expect((await readTree(target))!.map((f) => f.rel)).toEqual([SKILL_MARKER, "SKILL.md", "references/a.md"]);
    expect(planSkillCopy(target, source, await readTree(target)).ops).toEqual([]);

    await writeFile(join(target, "stale.md"), "old");
    const update = planSkillCopy(target, source, await readTree(target));
    expect(update.ops.map((o) => [o.kind, o.path])).toEqual([["remove", join(target, "stale.md")]]);

    expect(planSkillRemove(target, await readTree(target)).ops).toEqual([
      { kind: "remove-dir", path: target, summary: "remove the skill-scanner skill copy" },
    ]);
  });

  test("leaves a skill directory it did not create alone", async () => {
    const target = join(dir, "skills", "skill-scanner");
    await mkdir(target, { recursive: true });
    await writeFile(join(target, "SKILL.md"), "user's own");
    const tree = await readTree(target);
    const plan = planSkillCopy(target, [{ rel: "SKILL.md", text: "ours" }], tree);
    expect(plan.ops).toEqual([]);
    expect(plan.warnings[0]).toContain("not installed by setup");
    expect(planSkillRemove(target, tree).ops).toEqual([]);
    expect(await readTree(join(dir, "missing"))).toBeUndefined();
  });
});
