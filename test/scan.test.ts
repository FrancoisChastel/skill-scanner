import { afterEach, describe, expect, test } from "bun:test";
import { join } from "node:path";
import { patternRule } from "../src/core/pattern-rule";
import type { FileRule } from "../src/core/rule";
import { effectiveSeverity, severityRank } from "../src/core/severity";
import type { Finding, Severity, SkillBundle } from "../src/core/types";
import { type BundleJudge, type ExternalAnalyzer, scanPath } from "../src/scan";
import { TOOL_NAME, VERSION } from "../src/version";
import { makeSkillTree, type SkillTree, skillMd, type TreeEntry } from "./helpers/tree";

const trees: SkillTree[] = [];
async function tree(files: Readonly<Record<string, TreeEntry>>): Promise<SkillTree> {
  const t = await makeSkillTree(files);
  trees.push(t);
  return t;
}
afterEach(async () => {
  await Promise.all(trees.splice(0).map((t) => t.cleanup()));
});

/** Custom rules keep these tests independent of how the built-in rules are calibrated. */
const marker = (word: string, id: string, severity: Severity): FileRule =>
  patternRule({
    id,
    title: word,
    category: "network",
    severity,
    confidence: "high",
    description: `Matches ${word}.`,
    patterns: [new RegExp(`\\b${word}\\b`, "g")],
    cautionAware: false,
  });
const RULES = [marker("WARNME", "test/warn", "medium"), marker("BLOCKME", "test/block", "high"), marker("NOTEME", "test/note", "low")];

const REPO = {
  "README.md": "Repository readme NOTEME",
  "skills/clean/SKILL.md": skillMd("Nothing to see.", { name: "clean" }),
  "skills/warny/SKILL.md": skillMd("Line with WARNME.", { name: "warny" }),
  "skills/blocky/SKILL.md": skillMd("Line with BLOCKME.", { name: "blocky" }),
  "skills/blocky/scripts/run.sh": "echo BLOCKME",
};

const fixedNow = () => new Date("2026-01-02T03:04:05.000Z");

describe("scanPath verdicts", () => {
  test("gives each bundle its own verdict and the target the worst one", async () => {
    // Arrange
    const t = await tree(REPO);

    // Act
    const report = await scanPath(t.root, { rules: RULES, now: fixedNow });

    // Assert
    const verdicts = Object.fromEntries(report.bundles.map((b) => [b.bundle.name, b.verdict]));
    expect(verdicts).toEqual({ clean: "pass", warny: "warn", blocky: "block", "(root)": "pass" });
    expect(report.verdict).toBe("block");
    expect(report.counts).toEqual({ info: 0, low: 1, medium: 1, high: 2, critical: 0 });
    expect(report.suppressed).toBe(0);
  });

  test("reports finding paths relative to the scan target", async () => {
    // Arrange
    const t = await tree(REPO);

    // Act
    const report = await scanPath(t.root, { rules: RULES });

    // Assert
    const blocky = report.bundles.find((b) => b.bundle.name === "blocky");
    expect(blocky?.findings.map((f) => f.location.file).sort()).toEqual(["skills/blocky/SKILL.md", "skills/blocky/scripts/run.sh"]);
    expect(blocky?.findings.every((f) => f.bundle === "blocky")).toBe(true);
  });

  test("passes a clean skill and fills in report metadata", async () => {
    // Arrange
    const t = await tree({ "SKILL.md": skillMd("Nothing here.") });

    // Act
    const report = await scanPath(t.root, { rules: RULES, now: fixedNow, label: "my-skill" });

    // Assert
    expect(report).toMatchObject({
      schemaVersion: 1,
      tool: { name: TOOL_NAME, version: VERSION },
      target: "my-skill",
      startedAt: "2026-01-02T03:04:05.000Z",
      verdict: "pass",
      analyzers: [],
      suppressed: 0,
    });
    expect(report.durationMs).toBeGreaterThanOrEqual(0);
  });

  test("uses the path as the target label by default", async () => {
    // Arrange
    const t = await tree({ "SKILL.md": skillMd("x") });

    // Act
    const report = await scanPath(t.root, { rules: RULES });

    // Assert
    expect(report.target).toBe(t.root);
  });

  test("applies a custom verdict policy", async () => {
    // Arrange
    const t = await tree({ "SKILL.md": skillMd("WARNME") });

    // Act
    const strict = await scanPath(t.root, { rules: RULES, policy: { blockAt: "medium", warnAt: "low" } });

    // Assert
    expect(strict.verdict).toBe("block");
  });

  test("applies collection limits from the options", async () => {
    // Arrange
    const t = await tree({ "SKILL.md": skillMd("x"), "a.txt": "a", "b.txt": "b" });

    // Act
    const report = await scanPath(t.root, { rules: RULES, limits: { maxFiles: 1 } });

    // Assert
    expect(report.bundles[0]?.bundle.files).toHaveLength(1);
    expect(report.bundles[0]?.bundle.notes).toContain("more than 1 files; the rest were not scanned");
  });
});

describe("scanPath suppressions", () => {
  test("drops suppressed findings by rule id and counts them", async () => {
    // Arrange
    const t = await tree(REPO);

    // Act
    const report = await scanPath(t.root, { rules: RULES, suppressions: [{ rule: "test/block" }] });

    // Assert
    expect(report.suppressed).toBe(2);
    expect(report.verdict).toBe("warn");
  });

  test("supports category wildcards and path globs", async () => {
    // Arrange
    const t = await tree(REPO);

    // Act
    const byGlob = await scanPath(t.root, { rules: RULES, suppressions: [{ rule: "test/*", path: "skills/blocky/**" }] });
    const byScript = await scanPath(t.root, { rules: RULES, suppressions: [{ rule: "test/block", path: "**/scripts/*.sh" }] });

    // Assert
    expect(byGlob.suppressed).toBe(2);
    expect(byGlob.bundles.find((b) => b.bundle.name === "blocky")?.verdict).toBe("pass");
    expect(byScript.suppressed).toBe(1);
    expect(byScript.bundles.find((b) => b.bundle.name === "blocky")?.verdict).toBe("block");
  });

  test("suppresses by digest only for the exact skill version", async () => {
    // Arrange
    const t = await tree(REPO);
    const first = await scanPath(t.root, { rules: RULES });
    const digest = first.bundles.find((b) => b.bundle.name === "blocky")!.bundle.digest;

    // Act
    const pinned = await scanPath(t.root, { rules: RULES, suppressions: [{ rule: "*", digest }] });
    const stale = await scanPath(t.root, { rules: RULES, suppressions: [{ rule: "*", digest: "sha256:0000" }] });

    // Assert
    expect(pinned.suppressed).toBe(2);
    expect(pinned.bundles.find((b) => b.bundle.name === "blocky")?.findings).toEqual([]);
    expect(pinned.bundles.find((b) => b.bundle.name === "warny")?.verdict).toBe("warn");
    expect(stale.suppressed).toBe(0);
  });
});

describe("scanPath onlySkills", () => {
  test("keeps only the named skills, by name or directory, case-insensitively, plus non-skill bundles", async () => {
    // Arrange
    const t = await tree({ ...REPO, "skills/dir-name/SKILL.md": skillMd("x", { name: "other-name" }) });

    // Act
    const report = await scanPath(t.root, { rules: RULES, onlySkills: ["WARNY", "dir-name"] });

    // Assert
    expect(report.bundles.map((b) => b.bundle.name).sort()).toEqual(["(root)", "other-name", "warny"]);
    expect(report.verdict).toBe("warn");
  });
});

describe("scanPath judge", () => {
  const annotate: BundleJudge = {
    name: "fake-judge",
    review: async (_bundle, findings) => ({
      status: "ok",
      findings: findings.map((f) => ({ ...f, judge: { model: "fake", pTrue: 0.9, effect: "confirmed" as const } })),
    }),
  };

  test("uses the judge's annotated findings and records that it ran", async () => {
    // Arrange
    const t = await tree(REPO);

    // Act
    const report = await scanPath(t.root, { rules: RULES, judge: annotate });

    // Assert
    const all = report.bundles.flatMap((b) => b.findings);
    expect(all.length).toBe(4);
    expect(all.every((f) => f.judge?.effect === "confirmed")).toBe(true);
    expect(report.analyzers).toEqual([{ name: "fake-judge", status: "ran" }]);
  });

  test("keeps a judge's added findings", async () => {
    // Arrange
    const t = await tree({ "SKILL.md": skillMd("clean") });
    const extra: Finding = {
      ruleId: "judge/semantic",
      title: "Semantic",
      category: "prompt-injection",
      severity: "high",
      confidence: "medium",
      message: "judge saw something",
      location: { file: "SKILL.md" },
      bundle: "demo-skill",
      source: "judge",
    };
    const adder: BundleJudge = { name: "adder", review: async (_b, findings) => ({ status: "ok", findings: [...findings, extra] }) };

    // Act
    const report = await scanPath(t.root, { rules: RULES, judge: adder });

    // Assert
    expect(report.bundles[0]?.findings).toEqual([extra]);
    expect(report.verdict).toBe("block");
  });

  test("ignores a judge that drops findings and records a failure", async () => {
    // Arrange
    const t = await tree({ "SKILL.md": skillMd("BLOCKME") });
    const dropper: BundleJudge = { name: "dropper", review: async () => ({ status: "ok", findings: [] }) };

    // Act
    const report = await scanPath(t.root, { rules: RULES, judge: dropper });

    // Assert
    expect(report.bundles[0]?.findings.map((f) => f.ruleId)).toEqual(["test/block"]);
    expect(report.verdict).toBe("block");
    expect(report.analyzers).toEqual([{ name: "dropper", status: "failed", detail: "judge dropped findings; its review was ignored" }]);
  });

  test("keeps the findings when the judge throws", async () => {
    // Arrange
    const t = await tree({ "SKILL.md": skillMd("WARNME") });
    const thrower: BundleJudge = {
      name: "thrower",
      review: async () => {
        throw new Error("model unavailable");
      },
    };

    // Act
    const report = await scanPath(t.root, { rules: RULES, judge: thrower });

    // Assert
    expect(report.verdict).toBe("warn");
    expect(report.analyzers).toEqual([{ name: "thrower", status: "failed", detail: "model unavailable" }]);
  });

  test("summarizes the judge across bundles: a failure anywhere wins", async () => {
    // Arrange
    const t = await tree(REPO);
    const flaky: BundleJudge = {
      name: "flaky",
      review: async (bundle: SkillBundle, findings) =>
        bundle.name === "warny"
          ? { status: "failed", detail: "timeout", findings }
          : { status: "skipped", detail: "nothing to do", findings },
    };

    // Act
    const report = await scanPath(t.root, { rules: RULES, judge: flaky });

    // Assert
    expect(report.analyzers).toEqual([{ name: "flaky", status: "failed", detail: "timeout" }]);
  });

  test("reports skipped when the judge skips every bundle", async () => {
    // Arrange
    const t = await tree({ "SKILL.md": skillMd("x") });
    const lazy: BundleJudge = { name: "lazy", review: async (_b, findings) => ({ status: "skipped", detail: "no key", findings }) };

    // Act
    const report = await scanPath(t.root, { rules: RULES, judge: lazy });

    // Assert
    expect(report.analyzers).toEqual([{ name: "lazy", status: "skipped", detail: "no key" }]);
  });
});

describe("scanPath external analyzers", () => {
  const external = (file: string, severity: Severity = "high"): Finding => ({
    ruleId: "external:tool/x",
    title: "External",
    category: "supply-chain",
    severity,
    confidence: "high",
    message: `external finding in ${file}`,
    location: { file },
    bundle: "",
    source: "external:tool",
  });

  test("assigns external findings to the deepest bundle that owns the path", async () => {
    // Arrange
    const t = await tree({ ...REPO, "skills/warny/nested/SKILL.md": skillMd("x", { name: "nested" }) });
    const tool: ExternalAnalyzer = {
      name: "tool",
      unavailable: async () => undefined,
      run: async () => [external("skills/warny/nested/a.py"), external("skills/warny/b.py"), external("top.txt", "low")],
    };

    // Act
    const report = await scanPath(t.root, { rules: [], analyzers: [tool] });

    // Assert
    const where = Object.fromEntries(report.bundles.map((b) => [b.bundle.name, b.findings.map((f) => [f.location.file, f.bundle])]));
    expect(where.nested).toEqual([["skills/warny/nested/a.py", "nested"]]);
    expect(where.warny).toEqual([["skills/warny/b.py", "warny"]]);
    expect(where["(root)"]).toEqual([["top.txt", "(root)"]]);
    expect(report.analyzers).toEqual([{ name: "tool", status: "ran" }]);
    expect(report.verdict).toBe("block");
  });

  test("records unavailable and failing analyzers without stopping the scan", async () => {
    // Arrange
    const t = await tree({ "SKILL.md": skillMd("WARNME") });
    const missing: ExternalAnalyzer = { name: "missing", unavailable: async () => "not installed", run: async () => [] };
    const rejecting: ExternalAnalyzer = {
      name: "rejecting",
      unavailable: () => Promise.reject(new Error("probe crashed")),
      run: async () => [],
    };
    const crashing: ExternalAnalyzer = {
      name: "crashing",
      unavailable: async () => undefined,
      run: async () => {
        throw new Error("exit 2");
      },
    };

    // Act
    const report = await scanPath(t.root, { rules: RULES, analyzers: [missing, rejecting, crashing] });

    // Assert
    expect(report.analyzers).toEqual([
      { name: "missing", status: "skipped", detail: "not installed" },
      { name: "rejecting", status: "skipped", detail: "Error: probe crashed" },
      { name: "crashing", status: "failed", detail: "exit 2" },
    ]);
    expect(report.verdict).toBe("warn");
  });

  test("passes the real scan root to analyzers", async () => {
    // Arrange
    const t = await tree({ "SKILL.md": skillMd("x") });
    let seen = "";
    const probe: ExternalAnalyzer = {
      name: "probe",
      unavailable: async () => undefined,
      run: async (root) => {
        seen = root;
        return [];
      },
    };

    // Act
    await scanPath(t.path("SKILL.md"), { rules: RULES, analyzers: [probe] });

    // Assert
    expect(seen.endsWith(t.root.split("/").pop()!)).toBe(true);
  });

  test("lets suppressions apply to external findings", async () => {
    // Arrange
    const t = await tree({ "SKILL.md": skillMd("x") });
    const tool: ExternalAnalyzer = { name: "tool", unavailable: async () => undefined, run: async () => [external("SKILL.md")] };

    // Act
    const report = await scanPath(t.root, { rules: [], analyzers: [tool], suppressions: [{ rule: "external:tool/x" }] });

    // Assert
    expect(report.suppressed).toBe(1);
    expect(report.verdict).toBe("pass");
  });
});

describe("self-scan", () => {
  test("the scanner's own source does not block", async () => {
    // Arrange
    const src = join(import.meta.dir, "..", "src");

    // Act
    const report = await scanPath(src, { label: "src" });
    const blocking = report.bundles.flatMap((b) => b.findings).filter((f) => severityRank(effectiveSeverity(f)) >= severityRank("high"));

    // Assert
    expect(blocking.map((f) => `${f.ruleId} ${f.location.file}:${f.location.line ?? ""}`)).toEqual([]);
    expect(report.verdict).not.toBe("block");
  });
});
