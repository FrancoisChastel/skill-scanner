import { describe, expect, test } from "bun:test";
import {
  changeNotice,
  flaggedNotice,
  GuardSession,
  isWithin,
  patchTargets,
  resolveDeps,
  stripSkillListing,
  within,
} from "../../src/adapters/shared";
import { EVIL, EVIL_DIR, fakeGuard, fixture, flaggedEntry, HOME, installed, never, PROJECT } from "./fakes";

describe("stripSkillListing", () => {
  const prompt = fixture("pi-0.83-system-prompt.txt");

  test("removes only the blocks whose unescaped location is flagged", () => {
    const flagged = new Set([`${HOME}/R&D/.pi/skills/r-and-d/SKILL.md`, `${PROJECT}/.pi/skills/git-flow/SKILL.md`]);
    const out = stripSkillListing(prompt, (loc) => flagged.has(loc));
    expect(out).not.toContain("<name>r-and-d</name>");
    expect(out).not.toContain("<name>git-flow</name>");
    expect(out).not.toContain("for this repo.");
    expect(out).toContain("<name>pdf-tools</name>");
    expect(out).toContain("<name>evil-helper</name>");
    expect(out).toContain("  </skill>\n</available_skills>\nCurrent working directory");
    expect(out.replace(/<available_skills>[\s\S]*<\/available_skills>/, "")).toBe(
      prompt.replace(/<available_skills>[\s\S]*<\/available_skills>/, ""),
    );
  });

  test("an emptied listing keeps its tags", () => {
    const out = stripSkillListing(prompt, () => true);
    expect(out).toContain("<available_skills>\n</available_skills>");
  });

  test("text outside an <available_skills> listing is never touched", () => {
    const text = `  <skill>\n    <location>${EVIL_DIR}/SKILL.md</location>\n  </skill>\n`;
    expect(stripSkillListing(text, () => true)).toBe(text);
  });
});

describe("patchTargets", () => {
  test("lists added files with content, and updated, moved, and deleted paths", () => {
    const patch = [
      "*** Begin Patch",
      "*** Add File: a/SKILL.md",
      "+line 1",
      "+",
      "*** Update File: b.ts",
      "*** Move to: c.ts",
      "@@",
      "+x",
      "*** Delete File: d.ts",
      "*** End Patch",
    ].join("\n");
    expect(patchTargets(patch)).toEqual([
      { path: "a/SKILL.md", content: "line 1\n\n" },
      { path: "b.ts" },
      { path: "c.ts" },
      { path: "d.ts" },
    ]);
  });
});

describe("helpers", () => {
  test("within rejects on the deadline and swallows the late failure", async () => {
    await expect(within(never(), 20, "the thing")).rejects.toThrow("the thing did not finish within 0.02 s");
    const late = new Promise<never>((_, fail) => setTimeout(() => fail(new Error("late")), 30));
    await expect(within(late, 5, "x")).rejects.toThrow("did not finish");
    await new Promise((r) => setTimeout(r, 40));
    expect(await within(Promise.resolve(7), 20, "x")).toBe(7);
  });

  test("isWithin respects path boundaries", () => {
    expect(isWithin(`${EVIL_DIR}/SKILL.md`, EVIL_DIR)).toBe(true);
    expect(isWithin(EVIL_DIR, EVIL_DIR)).toBe(true);
    expect(isWithin(`${EVIL_DIR}-2/SKILL.md`, EVIL_DIR)).toBe(false);
    expect(isWithin("/anything", "")).toBe(false);
  });

  test("notices list skills, cap the list, and stay quiet when nothing changed", () => {
    const many = Array.from({ length: 10 }, (_, i) => flaggedEntry(`s${i}`, `${HOME}/.agents/skills/s${i}`, "warn", [`finding ${i}`]));
    const text = flaggedNotice(many);
    expect(text).toContain("10 installed skills are flagged");
    expect(text).toContain("- s0 (warn): finding 0");
    expect(text).toContain("- ... and 2 more");
    expect(changeNotice({ newlyFlagged: [], quarantined: [] })).toBeUndefined();
    expect(changeNotice({ newlyFlagged: [installed("x", "/x", "block")], quarantined: [] })).toContain("- x (block)");
  });
});

describe("GuardSession", () => {
  const session = (flagged = [EVIL]) => new GuardSession("pi", resolveDeps(fakeGuard({ flagged: () => flagged }).deps), () => undefined);

  test("matches names and registry aliases, case-insensitively", async () => {
    const aliased = { ...EVIL, name: "Evil Helper", aliases: ["evil-helper"] };
    const s = session([aliased]);
    expect((await s.flaggedNamed("EVIL HELPER", PROJECT))?.path).toBe(EVIL_DIR);
    expect((await s.flaggedNamed("evil-helper", PROJECT))?.path).toBe(EVIL_DIR);
    expect(await s.flaggedNamed("", PROJECT)).toBeUndefined();
  });

  test("drops malformed registry entries", async () => {
    const s = session([{ name: 3, path: "/x" } as never, { ...EVIL, summary: "not a list" as never }]);
    const list = await s.flagged();
    expect(list).toHaveLength(1);
    expect(list[0]?.summary).toEqual([]);
  });

  test("shouldReconcile spots installs and skill directories in any spelling", () => {
    const s = session([]);
    expect(s.shouldReconcile("npx skills add a/b", PROJECT)).toBe(true);
    expect(s.shouldReconcile("cp -r x $HOME/.pi/agent/skills/", PROJECT)).toBe(true);
    expect(s.shouldReconcile("unzip s.zip -d .pi/skills/s", PROJECT)).toBe(true);
    expect(s.shouldReconcile("git clone https://x/y ~/.config/opencode/skill/y", PROJECT)).toBe(true);
    expect(s.shouldReconcile("npm test && git status", PROJECT)).toBe(false);
  });
});
