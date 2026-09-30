import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { lstat, readdir, readFile, readlink } from "node:fs/promises";
import { join } from "node:path";
import { skillRoots } from "../../src/guard/locations";
import { listQuarantine, QUARANTINE_RECORD, quarantineSkill, restoreQuarantined } from "../../src/guard/quarantine";
import { scannerPaths } from "../../src/paths";
import { link, type TempHome, tempHome, writeSkill } from "./helpers";

let h: TempHome;
beforeEach(async () => {
  h = await tempHome();
});
afterEach(async () => {
  await h.cleanup();
});

const exists = (p: string): Promise<boolean> =>
  lstat(p).then(
    () => true,
    () => false,
  );

describe("quarantine", () => {
  test("moves the real directory, removes every link to it, and restores both", async () => {
    const real = await writeSkill(h.path(".agents", "skills", "q"), "q", "body", { "scripts/run.sh": "echo hi" });
    await link("../../.agents/skills/q", h.path(".claude", "skills", "q"));
    await link(real, h.path(".pi", "agent", "skills", "q"));
    await writeSkill(h.path(".claude", "skills", "other"), "other");
    const roots = skillRoots("all", h.path("proj"), h.env);
    const now = () => new Date("2026-09-30T12:00:00.000Z");

    const rec = await quarantineSkill(h.path(".claude", "skills", "q"), "blocked: test", h.env, { roots, digest: "sha256:x", now });
    expect(rec.id).toBe("2026-09-30T12-00-00-000Z-q");
    expect(rec).toMatchObject({
      originalPath: h.path(".claude", "skills", "q"),
      realPath: real,
      reason: "blocked: test",
      digest: "sha256:x",
    });
    expect(rec.links.map((l) => l.path).sort()).toEqual([h.path(".claude", "skills", "q"), h.path(".pi", "agent", "skills", "q")].sort());
    expect(await exists(real)).toBe(false);
    expect(await exists(h.path(".claude", "skills", "q"))).toBe(false);
    expect(await exists(h.path(".pi", "agent", "skills", "q"))).toBe(false);
    expect(await exists(h.path(".claude", "skills", "other"))).toBe(true);
    const dir = join(scannerPaths(h.env).quarantine, rec.id);
    expect(await readFile(join(dir, "scripts", "run.sh"), "utf8")).toBe("echo hi");
    expect(JSON.parse(await readFile(join(dir, QUARANTINE_RECORD), "utf8")).originalPath).toBe(h.path(".claude", "skills", "q"));

    const listed = await listQuarantine(h.env);
    expect(listed.map((r) => r.id)).toEqual([rec.id]);

    const back = await restoreQuarantined(rec.id, h.env);
    expect(back.realPath).toBe(real);
    expect(await readdir(real)).toEqual(expect.arrayContaining(["SKILL.md", "scripts"]));
    expect(await exists(join(real, QUARANTINE_RECORD))).toBe(false);
    expect(await readlink(h.path(".claude", "skills", "q"))).toBe("../../.agents/skills/q");
    expect(await readlink(h.path(".pi", "agent", "skills", "q"))).toBe(real);
    expect(await listQuarantine(h.env)).toEqual([]);
  });

  test("restore refuses when something took the skill's place", async () => {
    const real = await writeSkill(h.path(".claude", "skills", "r"), "r");
    const rec = await quarantineSkill(real, "why", h.env, { roots: [] });
    await writeSkill(real, "r", "new install");
    await expect(restoreQuarantined(rec.id, h.env)).rejects.toThrow(/exists again/);
  });

  test("two quarantines of the same name at the same instant get distinct ids", async () => {
    const now = () => new Date("2026-01-01T00:00:00.000Z");
    const a = await quarantineSkill(await writeSkill(h.path(".claude", "skills", "dup"), "dup"), "a", h.env, { roots: [], now });
    const b = await quarantineSkill(await writeSkill(h.path(".claude", "skills", "dup"), "dup"), "b", h.env, { roots: [], now });
    expect(b.id).toBe(`${a.id}-2`);
  });

  test("refuses homes, roots, and bad ids", async () => {
    const roots = skillRoots("all", h.path("proj"), h.env);
    await writeSkill(h.path(".claude", "skills", "x"), "x");
    await expect(quarantineSkill(h.home, "no", h.env, { roots })).rejects.toThrow(/refusing/);
    await expect(quarantineSkill(h.path(".claude", "skills"), "no", h.env, { roots })).rejects.toThrow(/refusing/);
    await expect(quarantineSkill(h.path("missing"), "no", h.env, { roots })).rejects.toThrow();
    await expect(restoreQuarantined("../etc", h.env)).rejects.toThrow(/invalid quarantine id/);
    await expect(restoreQuarantined("nope", h.env)).rejects.toThrow(/no quarantined skill/);
  });
});
