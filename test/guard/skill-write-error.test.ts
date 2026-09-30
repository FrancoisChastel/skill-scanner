import { afterAll, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DEFAULT_CONFIG } from "../../src/config";
import { evaluateSkillWrite } from "../../src/guard";

const dirs: string[] = [];
afterAll(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

async function setupRoot(): Promise<{ home: string; skillsRoot: string }> {
  const home = await mkdtemp(join(tmpdir(), "skill-scanner-test-"));
  dirs.push(home);
  const skillsRoot = join(home, ".claude", "skills");
  await mkdir(join(skillsRoot, "tidy"), { recursive: true });
  await writeFile(join(skillsRoot, "tidy", "SKILL.md"), "---\nname: tidy\ndescription: Tidies.\n---\nTidy up.\n");
  return { home, skillsRoot };
}

const failingScan = async (): Promise<never> => {
  throw new Error("scanner exploded");
};

describe("evaluateSkillWrite when the scan fails", () => {
  test("refuses the write under the default config", async () => {
    // Arrange
    const { home, skillsRoot } = await setupRoot();
    const ctx = {
      harness: "claude-code" as const,
      cwd: home,
      env: { HOME: home, SKILL_SCANNER_HOME: join(home, ".ss") },
      config: DEFAULT_CONFIG,
    };

    // Act
    const decision = await evaluateSkillWrite(join(skillsRoot, "tidy", "SKILL.md"), "new text\n", ctx, {
      roots: [{ harness: "claude-code", scope: "user", path: skillsRoot, kind: "skills" }],
      scanPath: failingScan,
    });

    // Assert
    expect(decision.action).toBe("deny");
    expect(decision.reason).toContain("could not check the write");
  });

  test("allows it only when hooks.onError is allow", async () => {
    const { home, skillsRoot } = await setupRoot();
    const config = { ...DEFAULT_CONFIG, hooks: { ...DEFAULT_CONFIG.hooks, onError: "allow" as const } };
    const ctx = { harness: "claude-code" as const, cwd: home, env: { HOME: home, SKILL_SCANNER_HOME: join(home, ".ss") }, config };
    const decision = await evaluateSkillWrite(join(skillsRoot, "tidy", "SKILL.md"), "new text\n", ctx, {
      roots: [{ harness: "claude-code", scope: "user", path: skillsRoot, kind: "skills" }],
      scanPath: failingScan,
    });
    expect(decision.action).toBe("allow");
  });
});
