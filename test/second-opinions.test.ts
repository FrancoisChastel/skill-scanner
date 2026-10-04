import { describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DEFAULT_CONFIG, parseConfig } from "../src/config";
import { createJudge, NO_JEV_KEY } from "../src/judge";
import { scanPath } from "../src/scan";
import { scanSkill } from "../src/scan-skill";
import {
  buildSecondOpinions,
  QUICK_JUDGE_MS,
  scanOptionsFrom,
  secondOpinionsFingerprint,
  secondOpinionsFrom,
} from "../src/second-opinions";
import { fakeKey } from "./judge/helpers";

/** An environment where no analyzer can be found and no key is set, unless a test adds one. */
const bare = (extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv => ({ PATH: "/nonexistent", HOME: "/nonexistent", ...extra });

describe("the judge's default mode, auto", () => {
  const auto = DEFAULT_CONFIG.judge;

  test("runs with a jev key: TYPESAFE_API_KEY or SKILL_SCANNER_JEV_KEY", () => {
    expect(createJudge(auto, bare({ TYPESAFE_API_KEY: fakeKey("ts_") })).judge).toBeDefined();
    expect(createJudge(auto, bare({ SKILL_SCANNER_JEV_KEY: fakeKey("ts_") })).judge).toBeDefined();
  });

  test("without one it stays off quietly: no key is the expected case, not an error", () => {
    expect(createJudge(auto, bare())).toEqual({ reason: NO_JEV_KEY, quiet: true });
  });

  test("never uses a general gateway key on its own: that key was set up for something else", () => {
    const env = bare({ OPENROUTER_API_KEY: fakeKey("sk-or-"), AI_GATEWAY_API_KEY: fakeKey("vck_") });
    expect(createJudge(auto, env)).toMatchObject({ quiet: true });
    expect(createJudge({ ...auto, enabled: true }, env).judge).toBeDefined();
    expect(createJudge({ ...auto, provider: "openrouter" }, env).judge).toBeDefined();
  });

  test("turned on explicitly, a missing key is a reason to warn, and turned off it never runs", () => {
    const on = createJudge({ ...auto, enabled: true }, bare());
    expect(on.judge).toBeUndefined();
    expect(on.quiet).toBeUndefined();
    expect(createJudge({ ...auto, enabled: false }, bare({ TYPESAFE_API_KEY: fakeKey("ts_") })).judge).toBeUndefined();
  });
});

describe("second opinions from a config", () => {
  test("carry the policy, the suppressions, the judge settings, and the analyzers turned on", () => {
    // Arrange
    const config = parseConfig({ blockAt: "critical", ignore: [{ rule: "x/y", reason: "r" }], analyzers: { semgrep: true } });

    // Act
    const opts = scanOptionsFrom(config, { quick: true });

    // Assert
    expect(opts.policy).toEqual({ blockAt: "critical", warnAt: "medium" });
    expect(opts.suppressions).toEqual(config.ignore);
    expect(opts.secondOpinions).toEqual({ judge: config.judge, analyzers: ["gitleaks", "semgrep"], quick: true });
  });

  test("leave out what cannot run here, without a word", async () => {
    const built = await buildSecondOpinions(secondOpinionsFrom(DEFAULT_CONFIG, true), bare());
    expect(built).toEqual({ analyzers: [] });
  });

  test("build the judge when a key is set, capped for install hooks", async () => {
    const built = await buildSecondOpinions(secondOpinionsFrom(DEFAULT_CONFIG, true), bare({ TYPESAFE_API_KEY: fakeKey("ts_") }));
    expect(built.judge?.name).toBe("jev");
    expect(QUICK_JUDGE_MS).toBeLessThan(DEFAULT_CONFIG.judge.timeoutMs);
  });

  test("change the cache fingerprint once a key is set, so cached verdicts are judged again", async () => {
    const s = secondOpinionsFrom(DEFAULT_CONFIG, true);
    const without = await secondOpinionsFingerprint(s, bare());
    const withKey = await secondOpinionsFingerprint(s, bare({ TYPESAFE_API_KEY: fakeKey("ts_") }));
    expect(without).toBe("judge:off;analyzers:");
    expect(withKey).toBe("judge:on;analyzers:");
  });
});

describe("scanPath with second opinions", () => {
  test("scans with the rules alone when none can run, and records nothing about them", async () => {
    // Arrange
    const dir = await mkdtemp(join(tmpdir(), "ss-opinions-"));
    try {
      await writeFile(join(dir, "SKILL.md"), "---\nname: ok\ndescription: Formats dates.\n---\n# OK\nFormat dates as ISO 8601.\n");
      const saved = { ...process.env };
      for (const k of ["TYPESAFE_API_KEY", "SKILL_SCANNER_JEV_KEY"]) delete process.env[k];
      process.env.PATH = "/nonexistent";

      // Act
      let report: Awaited<ReturnType<typeof scanPath>>;
      try {
        report = await scanPath(dir, scanOptionsFrom(DEFAULT_CONFIG, { quick: true }));
      } finally {
        process.env = saved;
      }

      // Assert
      expect(report.verdict).toBe("pass");
      expect(report.analyzers).toEqual([]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("scanSkill", () => {
  test("scans with the given config's second opinions, here none, and returns the rules' verdict", async () => {
    // Arrange
    const dir = await mkdtemp(join(tmpdir(), "ss-scanskill-"));
    try {
      await writeFile(join(dir, "SKILL.md"), "---\nname: ok\ndescription: Formats dates.\n---\n# OK\nFormat dates as ISO 8601.\n");
      const config = parseConfig({ judge: { enabled: false }, analyzers: { gitleaks: false } });

      // Act
      const report = await scanSkill(dir, { config });

      // Assert
      expect(report.verdict).toBe("pass");
      expect(report.analyzers).toEqual([]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
