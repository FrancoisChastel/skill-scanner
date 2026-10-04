import { describe, expect, test } from "bun:test";
import { CATEGORIES, type Category, type Finding } from "../../src/core/types";
import { createJudge, DOUBT_BELOW, JUDGE_RULES, PROBE_FOR_CATEGORY, THREAT_AT, THREAT_RULE_ID, threatScore } from "../../src/judge";
import { applyScores } from "../../src/judge/apply";
import type { ProbeId, ThreatProbeId } from "../../src/judge/probes";
import { ruleCatalog } from "../../src/rules";
import { answersFor, fakeFetch, fakeKey, jsonResponse, judgeCfg, makeBundle, makeFinding, scoresOf, textFile } from "./helpers";

const MODEL = "jev-test";
const bundle = makeBundle();

function applyOne(finding: Finding, scores: Partial<Record<ProbeId | ThreatProbeId, number>>): Finding {
  const out = applyScores(bundle, [finding], scoresOf(scores), MODEL);
  return out[0]!;
}

/** Threat answers that put the score exactly at `score`: every probe at the same value gives that value. */
const threatAt = (score: number): Partial<Record<ThreatProbeId, number>> => ({
  hidden_instructions: score,
  purpose_mismatch: score,
  hidden_agenda: score,
  unexpected_behavior: score,
  malicious_intent: score,
  unofficial_download: score,
});

describe("existing findings", () => {
  test("a finding whose probe is below DOUBT_BELOW is doubted: confidence low, severity kept", () => {
    // Arrange
    const finding = makeFinding({ category: "exfiltration", severity: "high", confidence: "medium" });

    // Act
    const out = applyOne(finding, { data_exfiltration: 0.01 });

    // Assert
    expect(out).toEqual({ ...finding, confidence: "low", judge: { model: MODEL, pTrue: 0.01, effect: "doubted" } });
  });

  test("a high answer only annotates: the judge never raises a finding's confidence", () => {
    // Arrange
    const low = makeFinding({ category: "prompt-injection", ruleId: "injection/test", confidence: "low" });

    // Act
    const out = applyOne(low, { prompt_injection: 1 });

    // Assert
    expect(out).toEqual({ ...low, judge: { model: MODEL, pTrue: 1, effect: "none" } });
  });

  test("an answer at DOUBT_BELOW or above only annotates", () => {
    // Arrange
    const finding = makeFinding({ category: "network" });

    // Act
    const atDoubt = applyOne(finding, { data_exfiltration: DOUBT_BELOW });

    // Assert
    expect(atDoubt).toEqual({ ...finding, judge: { model: MODEL, pTrue: DOUBT_BELOW, effect: "none" } });
  });

  test("hard evidence is never doubted", () => {
    // Arrange
    const hard = ruleCatalog().find((r) => r.hard && r.severity !== "critical" && PROBE_FOR_CATEGORY[r.category]);
    expect(hard).toBeDefined();
    const fromCatalog = makeFinding({ ruleId: hard!.id, category: hard!.category, severity: hard!.severity, confidence: "medium" });
    const engine = makeFinding({ ruleId: "obfuscation/encoded-payload", category: "obfuscation", severity: "high", confidence: "medium" });

    // Act
    const out = applyScores(bundle, [fromCatalog, engine], scoresOf({}, 0), MODEL);

    // Assert
    expect(out.map((f) => [f.confidence, f.judge?.effect])).toEqual([
      ["medium", "none"],
      ["medium", "none"],
    ]);
  });

  test("a critical finding is never doubted", () => {
    // Arrange
    const finding = makeFinding({ category: "destructive", ruleId: "destructive/test-soft", severity: "critical", confidence: "medium" });

    // Act
    const out = applyOne(finding, { destructive_command: 0 });

    // Assert
    expect(out.confidence).toBe("medium");
    expect(out.judge?.effect).toBe("none");
  });

  test("findings in packaging, metadata and execution-surface are returned untouched", () => {
    // Arrange
    const unmapped = (["packaging", "metadata", "execution-surface"] as const).map((category) =>
      makeFinding({ category, ruleId: `${category}/test` }),
    );

    // Act
    const out = applyScores(bundle, unmapped, scoresOf({}, 0), MODEL);

    // Assert
    expect(out).toHaveLength(3);
    out.forEach((f, i) => {
      expect(f).toBe(unmapped[i]!);
    });
  });

  test("every category maps to the probe the design names", () => {
    // Act
    const mapped = Object.fromEntries(CATEGORIES.map((c) => [c, PROBE_FOR_CATEGORY[c]]));

    // Assert
    expect(mapped).toEqual({
      "prompt-injection": "prompt_injection",
      deception: "prompt_injection",
      "hidden-content": "obfuscation",
      exfiltration: "data_exfiltration",
      "credential-access": "sensitive_data_access",
      "remote-execution": "remote_hidden_execution",
      obfuscation: "obfuscation",
      persistence: "security_control_change",
      destructive: "destructive_command",
      privilege: "security_control_change",
      network: "data_exfiltration",
      secrets: "sensitive_data_access",
      "supply-chain": "supply_chain",
      packaging: undefined,
      metadata: undefined,
      "execution-surface": undefined,
    });
  });
});

describe("threatScore", () => {
  test("is half the mean of the five intent probes plus half the unofficial-download probe", () => {
    // Arrange
    const scores = scoresOf({
      hidden_instructions: 0.5,
      purpose_mismatch: 0.1,
      hidden_agenda: 0.2,
      unexpected_behavior: 0.1,
      malicious_intent: 0.1,
      unofficial_download: 0.4,
    });

    // Act
    const score = threatScore(scores);

    // Assert
    expect(score).toBeCloseTo((0.2 + 0.4) / 2);
  });

  test("ignores the review probes", () => {
    expect(threatScore(scoresOf({}, 1, 0))).toBe(0);
  });
});

describe("the judge's own finding", () => {
  test("a threat score at THREAT_AT or above adds one medium finding naming the strongest answers", () => {
    // Act
    const out = applyScores(bundle, [], scoresOf({ hidden_instructions: 0.9, unofficial_download: 0.6 }), MODEL);

    // Assert
    expect(out).toEqual([
      {
        ruleId: THREAT_RULE_ID,
        title: "jev: this skill looks malicious",
        category: "deception",
        severity: "medium",
        confidence: "medium",
        message:
          "jev: threat score 0.39, at or above 0.075; " +
          "it contains hidden or unexplained instructions acting against the user or outside its task (P = 0.90); " +
          "it tells the user to download and run software from an unofficial source (P = 0.60). " +
          "It is a model's opinion; no static rule needs to agree.",
        location: { file: "skills/demo/SKILL.md" },
        bundle: "demo",
        source: "judge",
        remediation: expect.any(String),
        judge: { model: MODEL, pTrue: expect.closeTo(0.39, 5), effect: "none" },
      },
    ]);
  });

  test("answers that alone reach a score below THREAT_AT add nothing", () => {
    // Act
    const out = applyScores(bundle, [], scoresOf({ hidden_agenda: 0.2, malicious_intent: 0.175 }), MODEL);

    // Assert
    expect(threatScore(scoresOf({ hidden_agenda: 0.2, malicious_intent: 0.175 }))).toBeCloseTo(0.0375);
    expect(out).toEqual([]);
  });

  test("the threshold is inclusive", () => {
    // Act
    const at = applyScores(bundle, [], scoresOf(threatAt(THREAT_AT)), MODEL);
    const below = applyScores(bundle, [], scoresOf(threatAt(THREAT_AT - 0.001)), MODEL);

    // Assert
    expect(at).toHaveLength(1);
    expect(below).toEqual([]);
  });

  test("a review probe never adds a finding, however sure: a deploy skill does delete, read and send", () => {
    expect(applyScores(bundle, [], scoresOf({}, 1, 0), MODEL)).toEqual([]);
  });

  test("is added next to static findings, which keep their own verdict", () => {
    // Arrange
    const hidden = makeFinding({ category: "hidden-content", ruleId: "unicode/test", severity: "medium" });

    // Act
    const out = applyScores(bundle, [hidden], scoresOf(threatAt(0.5)), MODEL);

    // Assert
    expect(out.map((f) => f.ruleId)).toEqual(["unicode/test", THREAT_RULE_ID]);
  });

  test("on a bundle without SKILL.md it points at the bundle root", () => {
    // Arrange
    const plugin = makeBundle({ kind: "plugin", name: "(root)", root: ".", files: [textFile("hooks/hooks.json", "manifest", "{}")] });

    // Act
    const out = applyScores(plugin, [], scoresOf(threatAt(0.5)), MODEL);

    // Assert
    expect(out[0]).toMatchObject({ ruleId: THREAT_RULE_ID, location: { file: "." }, bundle: "(root)" });
  });
});

describe("monotonic application", () => {
  const categories: readonly Category[] = CATEGORIES;
  const input = categories.flatMap((category) =>
    (["low", "medium", "high", "critical"] as const).map((severity) =>
      makeFinding({ category, severity, ruleId: `${category}/probe-${severity}`, message: `${category} ${severity}` }),
    ),
  );

  for (const fill of [0, 0.01, 0.05, 0.3, 0.5, 0.85, 1]) {
    test(`never drops a finding or changes a severity (all probes at ${fill})`, () => {
      // Act
      const out = applyScores(bundle, input, scoresOf({}, fill, fill), MODEL);

      // Assert
      expect(out.length).toBeGreaterThanOrEqual(input.length);
      input.forEach((f, i) => {
        const o = out[i]!;
        expect([o.ruleId, o.severity, o.category, o.message, o.location, o.bundle, o.source]).toEqual([
          f.ruleId,
          f.severity,
          f.category,
          f.message,
          f.location,
          f.bundle,
          f.source,
        ]);
        expect(o.confidence === f.confidence || o.confidence === "low").toBe(true);
      });
      expect(out.slice(input.length).every((f) => f.source === "judge" && f.severity === "medium")).toBe(true);
    });
  }

  test("the review returns every input finding, annotated, through the public judge", async () => {
    // Arrange
    const fake = fakeFetch(() => jsonResponse(answersFor(scoresOf({ data_exfiltration: 0.02, ...threatAt(0.4) }))));
    const { judge } = createJudge(judgeCfg(), { TYPESAFE_API_KEY: fakeKey("ts_") }, { fetch: fake.fetch });
    const findings = [makeFinding({ category: "exfiltration" }), makeFinding({ category: "packaging", ruleId: "packaging/test" })];

    // Act
    const review = await judge!.review(bundle, findings);

    // Assert
    expect(review.status).toBe("ok");
    expect(review.findings.map((f) => [f.ruleId, f.confidence, f.judge?.effect])).toEqual([
      ["exfiltration/test-soft-rule", "low", "doubted"],
      ["packaging/test", "medium", undefined],
      [THREAT_RULE_ID, "medium", "none"],
    ]);
  });

  test("a response missing a threat answer fails the review rather than judging on part of it", async () => {
    // Arrange
    const { unofficial_download: _dropped, ...partial } = scoresOf();
    const fake = fakeFetch(() => jsonResponse(answersFor(partial)));
    const { judge } = createJudge(judgeCfg(), { TYPESAFE_API_KEY: fakeKey("ts_") }, { fetch: fake.fetch });

    // Act
    const review = await judge!.review(bundle, [makeFinding({ category: "exfiltration" })]);

    // Assert
    expect(review.status).toBe("failed");
    expect(review.detail).toContain("unofficial_download");
  });
});

describe("JUDGE_RULES", () => {
  test("describes the one medium rule the judge can add, never colliding with built-in ids", () => {
    // Arrange
    const builtIn = new Set(ruleCatalog().map((r) => r.id));

    // Assert
    expect(JUDGE_RULES.map((r) => r.id)).toEqual([THREAT_RULE_ID]);
    for (const r of JUDGE_RULES) {
      expect(builtIn.has(r.id)).toBe(false);
      expect([r.severity, r.confidence]).toEqual(["medium", "medium"]);
      expect(r.description).toContain("model's opinion");
      expect(r.hard).toBeUndefined();
    }
  });
});
