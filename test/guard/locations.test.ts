import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { isInsideSkillRoot, locateSkillDir, skillRoots } from "../../src/guard/locations";
import type { SkillRoot } from "../../src/guard/types";
import { type TempHome, tempHome } from "./helpers";

let h: TempHome;
beforeEach(async () => {
  h = await tempHome();
});
afterEach(async () => {
  await h.cleanup();
});

const paths = (roots: readonly SkillRoot[]): string[] => roots.map((r) => r.path);

describe("skillRoots", () => {
  test("Claude Code: env overrides, project chain up to the repo root, synced buckets, plugin cache", async () => {
    const repo = h.path("work", "repo");
    await mkdir(join(repo, ".git"), { recursive: true });
    await mkdir(join(repo, "pkg", "sub"), { recursive: true });
    await mkdir(h.path(".claude", "skills", "synced", "bucket-1"), { recursive: true });
    const env = { ...h.env, CLAUDE_CONFIG_DIR: h.path("alt-claude") };
    await mkdir(h.path("alt-claude", "skills", "synced", "b2"), { recursive: true });
    const roots = skillRoots("claude-code", join(repo, "pkg", "sub"), env);
    expect(paths(roots)).toEqual(
      expect.arrayContaining([
        join(repo, "pkg", "sub", ".claude", "skills"),
        join(repo, "pkg", ".claude", "skills"),
        join(repo, ".claude", "skills"),
        h.path("alt-claude", "skills"),
        h.path("alt-claude", "skills", "synced", "b2"),
        h.path("alt-claude", "plugins", "cache"),
      ]),
    );
    expect(paths(roots)).not.toContain(h.path("work", ".claude", "skills"));
    expect(paths(roots)).not.toContain(h.path(".claude", "skills"));
    expect(roots.find((r) => r.path.endsWith(join("plugins", "cache")))?.kind).toBe("plugin-cache");
  });

  test("outside a repository only the working directory counts as a project", () => {
    const roots = skillRoots("claude-code", h.path("loose", "dir"), h.env);
    expect(roots.filter((r) => r.scope === "project").map((r) => r.path)).toEqual([h.path("loose", "dir", ".claude", "skills")]);
  });

  test("Codex: shared .agents roots, CODEX_HOME, .system, repo .codex/skills", async () => {
    const repo = h.path("r");
    await mkdir(join(repo, ".git"), { recursive: true });
    const env = { ...h.env, CODEX_HOME: h.path("cx") };
    const roots = skillRoots("codex", repo, env);
    expect(paths(roots)).toEqual(
      expect.arrayContaining([
        join(repo, ".agents", "skills"),
        join(repo, ".codex", "skills"),
        h.path(".agents", "skills"),
        h.path("cx", "skills"),
        h.path("cx", "skills", ".system"),
        h.path("cx", "plugins", "cache"),
      ]),
    );
    expect(roots.find((r) => r.path === h.path(".agents", "skills"))?.harness).toBe("shared");
  });

  test("OpenCode honours its disable switches and config dirs", () => {
    const on = skillRoots("opencode", h.path("p"), h.env);
    expect(paths(on)).toEqual(
      expect.arrayContaining([
        h.path(".claude", "skills"),
        h.path(".agents", "skills"),
        h.path(".config", "opencode", "skill"),
        h.path(".config", "opencode", "skills"),
        h.path("p", ".opencode", "skills"),
        h.path(".cache", "opencode", "skills"),
      ]),
    );
    expect(on.find((r) => r.path === h.path(".config", "opencode", "skills"))?.recursive).toBe(true);
    const off = skillRoots("opencode", h.path("p"), {
      ...h.env,
      OPENCODE_DISABLE_CLAUDE_CODE_SKILLS: "1",
      OPENCODE_DISABLE_EXTERNAL_SKILLS: "true",
    });
    expect(paths(off)).not.toContain(h.path(".claude", "skills"));
    expect(paths(off)).not.toContain(h.path(".agents", "skills"));
    const cfg = skillRoots("opencode", h.path("p"), { ...h.env, OPENCODE_CONFIG_DIR: h.path("oc") });
    expect(paths(cfg)).toContain(h.path("oc", "skill"));
  });

  test("Pi: agent dir override and package caches", () => {
    const roots = skillRoots("pi", h.path("p"), { ...h.env, PI_CODING_AGENT_DIR: h.path("pi-agent") });
    expect(paths(roots)).toEqual(
      expect.arrayContaining([
        h.path("pi-agent", "skills"),
        h.path(".agents", "skills"),
        h.path("p", ".pi", "skills"),
        h.path("pi-agent", "npm", "node_modules"),
      ]),
    );
    expect(roots.filter((r) => r.kind === "package-cache").length).toBe(2);
  });

  test("all harnesses: each path once", () => {
    const roots = skillRoots("all", h.path("p"), h.env);
    expect(new Set(paths(roots)).size).toBe(roots.length);
  });
});

describe("isInsideSkillRoot and locateSkillDir", () => {
  test("known roots, nested project skill folders, and plugin caches", () => {
    const roots = skillRoots("all", h.path("p"), h.env);
    expect(isInsideSkillRoot(h.path(".claude", "skills", "x", "SKILL.md"), roots)).toBe(true);
    expect(isInsideSkillRoot(h.path(".claude", "skills"), roots)).toBe(true);
    expect(isInsideSkillRoot("/elsewhere/deep/.claude/skills/x/run.sh", roots)).toBe(true);
    expect(isInsideSkillRoot("/elsewhere/.claude/plugins/cache/m/p/1/hooks.json", roots)).toBe(true);
    expect(isInsideSkillRoot(h.path("p", "src", "skills.ts"), roots)).toBe(false);
    expect(isInsideSkillRoot(h.path(".claude", "settings.json"), roots)).toBe(false);
  });

  test("finds the skill directory for a file", () => {
    const roots = skillRoots("all", h.path("p"), h.env);
    expect(locateSkillDir(h.path(".claude", "skills", "x", "scripts", "a.sh"), roots)?.skillDir).toBe(h.path(".claude", "skills", "x"));
    expect(locateSkillDir(h.path(".claude", "skills", "README.md"), roots)?.skillDir).toBeUndefined();
    expect(locateSkillDir(h.path(".claude", "plugins", "cache", "m", "p", "1.0", "skills", "s", "SKILL.md"), roots)?.skillDir).toBe(
      h.path(".claude", "plugins", "cache", "m", "p", "1.0"),
    );
    expect(locateSkillDir("/x/y/.claude/skills/z/SKILL.md", roots)).toEqual({
      rootPath: "/x/y/.claude/skills",
      skillDir: "/x/y/.claude/skills/z",
    });
    expect(locateSkillDir("/x/y/notes.md", roots)).toBeUndefined();
  });
});
