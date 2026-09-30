import { afterAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { BUILTIN_RULES } from "../src/rules";
import { scanPath } from "../src/scan";
import { isolatedScanner, ScanTimeoutError, workerScript } from "../src/scan-worker";
import { BENIGN_SKILL, MALICIOUS_SKILL, writeFiles } from "./sources/helpers";

const base = mkdtempSync(join(tmpdir(), "ss-scan-worker-"));
afterAll(() => rmSync(base, { recursive: true, force: true }));

const skill = (name: string, body: string): string => {
  const dir = join(base, name);
  writeFiles(dir, { [`skills/${name}/SKILL.md`]: body });
  return dir;
};

/** A worker entry that behaves badly, standing in for a scan that never yields or dies. */
const badWorker = (name: string, body: string): string => {
  const path = join(base, `${name}.mjs`);
  writeFileSync(path, body);
  return path;
};

const CLI = join(import.meta.dir, "../src/cli.ts");
const POLICY = { blockAt: "high", warnAt: "medium" } as const;

describe("isolatedScanner", () => {
  test("reports exactly what an in-process scan reports", async () => {
    // Arrange
    const dir = skill("evil", MALICIOUS_SKILL);
    const scan = isolatedScanner({ script: CLI });

    // Act
    const [isolated, direct] = await Promise.all([
      scan(dir, { policy: POLICY, label: "x" }),
      scanPath(dir, { policy: POLICY, label: "x" }),
    ]);

    // Assert
    expect(isolated.verdict).toBe("block");
    expect(isolated.target).toBe("x");
    expect(isolated.bundles.map((b) => [b.bundle.digest, b.verdict, b.findings.map((f) => f.ruleId)])).toEqual(
      direct.bundles.map((b) => [b.bundle.digest, b.verdict, b.findings.map((f) => f.ruleId)]),
    );
  });

  test("a scan that never yields is stopped at the hard limit", async () => {
    // Arrange
    const scan = isolatedScanner({ script: badWorker("spin", "for (;;) {}\n"), maxMs: 300 });
    const t0 = performance.now();

    // Act
    const outcome = scan(skill("tidy", BENIGN_SKILL), {});

    // Assert
    await expect(outcome).rejects.toBeInstanceOf(ScanTimeoutError);
    expect(performance.now() - t0).toBeLessThan(5_000);
  });

  test("aborting the signal terminates the worker at once", async () => {
    // Arrange
    const scan = isolatedScanner({ script: badWorker("spin2", "for (;;) {}\n") });
    const controller = new AbortController();
    const t0 = performance.now();

    // Act
    const outcome = scan(skill("tidy2", BENIGN_SKILL), { signal: controller.signal });
    setTimeout(() => controller.abort(new Error("deadline")), 200);

    // Assert
    await expect(outcome).rejects.toThrow("deadline");
    expect(performance.now() - t0).toBeLessThan(5_000);
  });

  test("an already aborted signal never starts a worker", async () => {
    const scan = isolatedScanner({ script: badWorker("never", "throw new Error('should not run');\n") });
    await expect(scan(base, { signal: AbortSignal.abort(new Error("gone")) })).rejects.toThrow("gone");
  });

  test("a worker that dies or exits without an answer is an error, not a pass", async () => {
    const crash = isolatedScanner({ script: badWorker("crash", "throw new Error('boom');\n") });
    await expect(crash(base, {})).rejects.toThrow("boom");
    const quiet = isolatedScanner({ script: badWorker("quiet", "process.exit(0);\n") });
    await expect(quiet(base, {})).rejects.toThrow("before it reported");
  });

  test("a scan error inside the worker comes back as an error", async () => {
    const scan = isolatedScanner({ script: CLI });
    await expect(scan(join(base, "does-not-exist"), {})).rejects.toThrow();
  });

  test("options a worker cannot receive keep the scan in-process", async () => {
    // A worker that would fail proves the scan did not go there.
    const scan = isolatedScanner({ script: badWorker("unused", "throw new Error('not in-process');\n") });
    const report = await scan(skill("rules", MALICIOUS_SKILL), { rules: BUILTIN_RULES, policy: POLICY });
    expect(report.verdict).toBe("block");
  });
});

describe("workerScript", () => {
  test("finds the CLI entry next to the module, and nothing elsewhere", () => {
    expect(workerScript(pathToFileURL(join(import.meta.dir, "../src/scan-worker.ts")).href)).toBe(CLI);
    expect(workerScript(pathToFileURL(join(base, "nothing-here.js")).href)).toBeUndefined();
  });
});
