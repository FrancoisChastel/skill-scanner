import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { ANALYZER_RULES, ANALYZERS, createAnalyzers, detectAnalyzers } from "../../src/analyzers";
import { ANALYZER_NAMES, DEFAULT_CONFIG } from "../../src/config";

const IS_WINDOWS = process.platform === "win32";
let bin: string;

/** A fake tool that prints a version, enough for detection and `auto`. */
async function fakeTool(name: string, version: string): Promise<void> {
  const path = join(bin, name);
  await writeFile(path, `#!/bin/sh\necho "${name} version ${version}"\n`);
  await chmod(path, 0o755);
}

beforeAll(async () => {
  bin = await mkdtemp(join(tmpdir(), "analyzers-index-"));
  await fakeTool("gitleaks", "8.30.1");
  await fakeTool("skillspector", "2.12.0");
  await fakeTool("osv-scanner", "2.6.0");
  await fakeTool("semgrep", "1.178.0");
});

afterAll(async () => {
  await rm(bin, { recursive: true, force: true });
});

const fakeEnv = (): NodeJS.ProcessEnv => ({ PATH: [bin, "/usr/bin", "/bin"].join(delimiter) });
const names = (list: readonly { name: string }[]): string[] => list.map((a) => a.name);

describe("catalog", () => {
  test("describes every analyzer name, in config order, with how to install it", () => {
    // Arrange / Act / Assert
    expect(ANALYZERS.map((a) => a.name)).toEqual([...ANALYZER_NAMES]);
    for (const a of ANALYZERS) {
      expect(a.install.length).toBeGreaterThan(0);
      expect(a.homepage).toStartWith("https://github.com/");
      expect(a.license.length).toBeGreaterThan(0);
    }
    expect(ANALYZERS.filter((a) => a.network).map((a) => a.name)).toEqual(["osv-scanner", "semgrep"]);
  });

  test("has one rule per tool, named external/<tool>", () => {
    // Arrange / Act
    const byId = Object.fromEntries(ANALYZER_RULES.map((r) => [r.id, r]));

    // Assert
    expect(Object.keys(byId)).toEqual(ANALYZER_NAMES.map((n) => `external/${n}`));
    expect(byId["external/gitleaks"]?.category).toBe("secrets");
    expect(byId["external/osv-scanner"]?.category).toBe("supply-chain");
    expect(byId["external/semgrep"]).toMatchObject({ category: "packaging", severity: "medium", confidence: "medium" });
    expect(byId["external/cisco"]?.description).toBe(
      "Finding reported by Cisco AI Defense Skill Scanner; see its message for the tool's own rule.",
    );
  });
});

describe("createAnalyzers", () => {
  test.skipIf(IS_WINDOWS)("auto takes every installed analyzer that needs no network", async () => {
    // Arrange / Act
    const auto = await createAnalyzers(["auto"], DEFAULT_CONFIG, fakeEnv());

    // Assert: osv-scanner always needs the network; semgrep does with the default registry ruleset.
    expect(names(auto)).toEqual(["skillspector", "gitleaks"]);
  });

  test.skipIf(IS_WINDOWS)("auto includes semgrep when its config is a local path", async () => {
    // Arrange
    const cfg = { ...DEFAULT_CONFIG, semgrepConfig: "/home/me/skill-rules.yml" };

    // Act
    const auto = await createAnalyzers(["auto"], cfg, fakeEnv());

    // Assert
    expect(names(auto)).toEqual(["skillspector", "gitleaks", "semgrep"]);
  });

  test.skipIf(IS_WINDOWS)("keeps explicit names, network ones included, and drops duplicates", async () => {
    // Arrange / Act
    const list = await createAnalyzers(["gitleaks", "osv-scanner", "auto", "gitleaks"], DEFAULT_CONFIG, fakeEnv());

    // Assert
    expect(names(list)).toEqual(["gitleaks", "osv-scanner", "skillspector"]);
  });

  test("auto on a machine without any tool is empty", async () => {
    // Arrange / Act / Assert
    expect(await createAnalyzers(["auto"], DEFAULT_CONFIG, { PATH: "" })).toEqual([]);
  });

  test("an explicitly requested tool that is missing explains how to install it", async () => {
    // Arrange
    const list = await createAnalyzers([...ANALYZER_NAMES], DEFAULT_CONFIG, { PATH: "" });

    // Act
    const reasons = await Promise.all(list.map((a) => a.unavailable()));

    // Assert
    expect(names(list)).toEqual([...ANALYZER_NAMES]);
    reasons.forEach((why, i) => {
      expect(why).toContain("was not found on PATH");
      expect(why).toContain(ANALYZERS[i]!.install);
    });
    await expect(list[0]!.run(tmpdir())).rejects.toThrow(/was not found on PATH/);
  });

  test.skipIf(IS_WINDOWS)("an installed tool is available", async () => {
    // Arrange
    const [gitleaks] = await createAnalyzers(["gitleaks"], DEFAULT_CONFIG, fakeEnv());

    // Act / Assert
    expect(await gitleaks!.unavailable()).toBeUndefined();
  });
});

describe("detectAnalyzers", () => {
  test.skipIf(IS_WINDOWS)("reports the path and version of each installed tool, and nothing for missing ones", async () => {
    // Arrange / Act
    const found = await detectAnalyzers(fakeEnv());
    const byName = Object.fromEntries(found.map((d) => [d.info.name, d]));

    // Assert
    expect(found.map((d) => d.info.name)).toEqual([...ANALYZER_NAMES]);
    expect(byName.gitleaks).toMatchObject({ path: join(bin, "gitleaks"), version: "8.30.1" });
    expect(byName.skillspector).toMatchObject({ path: join(bin, "skillspector"), version: "2.12.0" });
    expect(byName.semgrep).toMatchObject({ path: join(bin, "semgrep"), version: "1.178.0" });
    expect(byName.cisco).toEqual({ info: ANALYZERS[1]! });
  });

  test.skipIf(IS_WINDOWS)(
    "gives up on a version probe that hangs, keeping the path",
    async () => {
      // Arrange
      const slow = await mkdtemp(join(tmpdir(), "analyzers-slow-"));
      await writeFile(join(slow, "gitleaks"), "#!/bin/sh\nsleep 30\n");
      await chmod(join(slow, "gitleaks"), 0o755);

      try {
        // Act
        const started = performance.now();
        const found = await detectAnalyzers({ PATH: [slow, "/usr/bin", "/bin"].join(delimiter) });

        // Assert
        const gitleaks = found.find((d) => d.info.name === "gitleaks");
        expect(gitleaks).toEqual({ info: ANALYZERS[2]!, path: join(slow, "gitleaks") });
        expect(performance.now() - started).toBeLessThan(10_000);
      } finally {
        await rm(slow, { recursive: true, force: true });
      }
    },
    15_000,
  );
});
