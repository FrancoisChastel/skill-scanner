import { afterAll, describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { guardCommand } from "../../src/cli/commands/guard";
import { BENIGN_SKILL, fakeIO, hasGit, hermeticGitEnv, makeRepo, tempDir } from "../sources/helpers";

const root = tempDir("ss-guard-backstop-");
afterAll(() => root.remove());

describe("guard backstop", () => {
  test.skipIf(!hasGit)("a clone that switched the hook off is reported as refused", async () => {
    // Arrange: a command that clears the guard's git config from a sourced file, which no parser sees.
    const env = hermeticGitEnv(join(root.path, "home"), { SKILL_SCANNER_HOME: join(root.path, "ss") });
    const repo = join(root.path, "repo");
    makeRepo(repo, { "skills/tidy/SKILL.md": BENIGN_SKILL }, env);
    const envFile = join(root.path, "clear.env");
    await Bun.write(envFile, "unset GIT_CONFIG_COUNT\n");
    const dest = join(root.path, "dest");
    const f = fakeIO({ cwd: root.path, env });

    // Act
    const code = await guardCommand.run(["sh", "-c", `. ${envFile}; git clone -q file://${repo} ${dest}`], f.io);

    // Assert
    expect(existsSync(dest)).toBe(true);
    expect(code).toBe(1);
    expect(f.err()).toContain("no checkout went through the scan");
  });

  test("a command that installs nothing is not second-guessed", async () => {
    const f = fakeIO({ cwd: root.path, env: { SKILL_SCANNER_HOME: join(root.path, "ss2"), PATH: process.env.PATH ?? "" } });
    const code = await guardCommand.run(["sh", "-c", "true"], f.io);
    expect(code).toBe(0);
  });
});
