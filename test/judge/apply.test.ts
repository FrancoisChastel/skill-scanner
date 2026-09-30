import { describe, expect, test } from "bun:test";
import { CATEGORIES, type Category, type Finding } from "../../src/core/types";
import { ADD_AT, CONFIRM_AT, createJudge, DOUBT_BELOW, JUDGE_RULES, PROBE_FOR_CATEGORY } from "../../src/judge";
import { applyScores } from "../../src/judge/apply";
import { PROBE_IDS, type ProbeId } from "../../src/judge/probes";
import { ruleCatalog } from "../../src/rules";
import { answersFor, fakeFetch, fakeKey, jsonResponse, judgeCfg, makeBundle, makeFinding, scoresOf, textFile } from "./helpers";

const MODEL = "jev-test";
const bundle = makeBundle();

function applyOne(finding: Finding, scores: Partial<Record<ProbeId, number>>): Finding {
  const out = applyScores(bundle, [finding], scoresOf(scores), MODEL);
  return out[0]!;
}

describe("existing findings", () => {
  test("a finding whose probe is below DOUBT_BELOW is doubted: confidence low, severity kept", () => {
    // Arrange
    const finding = makeFinding({ category: "exfiltration", severity: "high", confidence: "medium" });

    // Act
    const out = applyOne(finding, { data_exfiltration: 0.01 });

    // Assert
    expect(out).toEqual({ ...finding, confidence: "low", judge: { model: MODEL, pTrue: 0.01, effect: "doubted" } });
  });

  test("a finding whose probe is at CONFIRM_AT or above is confirmed: confidence raised one step", () => {
    // Arrange
    const low = makeFinding({ category: "prompt-injection", ruleId: "injection/test", confidence: "low" });
    const medium = makeFinding({ category: "prompt-injection", ruleId: "injection/test", confidence: "medium" });

    // Act
    const fromLow = applyOne(low, { prompt_injection: CONFIRM_AT });
    const fromMedium = applyOne(medium, { prompt_injection: CONFIRM_AT });

    // Assert
    expect(fromLow).toEqual({ ...low, confidence: "medium", judge: { model: MODEL, pTrue: CONFIRM_AT, effect: "confirmed" } });
    expect(fromMedium).toEqual({ ...medium, confidence: "high", judge: { model: MODEL, pTrue: CONFIRM_AT, effect: "confirmed" } });
  });

  test("a probe between the thresholds only annotates", () => {
    // Arrange
    const finding = makeFinding({ category: "network" });

    // Act
    const atDoubt = applyOne(finding, { data_exfiltration: DOUBT_BELOW });
    const middle = applyOne(finding, { data_exfiltration: 0.3 });

    // Assert
    expect(atDoubt).toEqual({ ...finding, judge: { model: MODEL, pTrue: DOUBT_BELOW, effect: "none" } });
    expect(middle.confidence).toBe(finding.confidence);
    expect(middle.judge?.effect).toBe("none");
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

  test("hard evidence can still be confirmed", () => {
    // Arrange
    const engine = makeFinding({
      ruleId: "obfuscation/encoded-payload",
      category: "obfuscation",
      severity: "critical",
      confidence: "medium",
    });

    // Act
    const out = applyOne(engine, { obfuscation: 0.9 });

    // Assert
    expect(out.confidence).toBe("high");
    expect(out.judge?.effect).toBe("confirmed");
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

describe("judge-added findings", () => {
  test("a probe at ADD_AT or above with no finding in its family adds one medium finding", () => {
    // Act
    const out = applyScores(bundle, [], scoresOf({ prompt_injection: 0.91 }), MODEL);

    // Assert
    expect(out).toEqual([
      {
        ruleId: "judge/prompt-injection",
        title: "jev: may manipulate the agent's instructions",
        category: "prompt-injection",
        severity: "medium",
        confidence: "medium",
        message:
          "jev: P(true) = 0.91 that this skill tries to override, ignore or manipulate an AI agent's instructions. " +
          "No static rule found this; it is a model's opinion.",
        location: { file: "skills/demo/SKILL.md" },
        bundle: "demo",
        source: "judge",
        remediation: expect.any(String),
        judge: { model: MODEL, pTrue: 0.91, effect: "none" },
      },
    ]);
  });

  test("the threshold is inclusive", () => {
    // Act
    const at = applyScores(bundle, [], scoresOf({ supply_chain: ADD_AT }), MODEL);
    const below = applyScores(bundle, [], scoresOf({ supply_chain: ADD_AT - 0.001 }), MODEL);

    // Assert
    expect(at.map((f) => f.ruleId)).toEqual(["judge/supply-chain"]);
    expect(below).toEqual([]);
  });

  test("nothing is added when a static finding already covers the family", () => {
    // Arrange
    const hidden = makeFinding({ category: "hidden-content", ruleId: "unicode/test", severity: "medium" });

    // Act
    const out = applyScores(bundle, [hidden], scoresOf({ obfuscation: 0.99 }), MODEL);

    // Assert
    expect(out).toHaveLength(1);
    expect(out[0]?.judge?.effect).toBe("confirmed");
  });

  test("a finding on a bundle without SKILL.md points at the bundle root", () => {
    // Arrange
    const plugin = makeBundle({ kind: "plugin", name: "(root)", root: ".", files: [textFile("hooks/hooks.json", "manifest", "{}")] });

    // Act
    const out = applyScores(plugin, [], scoresOf({ remote_hidden_execution: 0.95 }), MODEL);

    // Assert
    expect(out[0]).toMatchObject({ ruleId: "judge/remote-hidden-execution", location: { file: "." }, bundle: "(root)" });
  });

  test("every probe firing adds exactly the eight rules in JUDGE_RULES", () => {
    // Act
    const out = applyScores(bundle, [], scoresOf({}, 1), MODEL);

    // Assert
    expect(out.map((f) => f.ruleId).sort()).toEqual(JUDGE_RULES.map((r) => r.id).sort());
    for (const f of out) {
      const rule = JUDGE_RULES.find((r) => r.id === f.ruleId)!;
      expect([f.category, f.severity, f.confidence, f.title]).toEqual([rule.category, "medium", "medium", rule.title]);
    }
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
      const out = applyScores(bundle, input, scoresOf({}, fill), MODEL);

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
      });
      expect(out.slice(input.length).every((f) => f.source === "judge" && f.severity === "medium")).toBe(true);
    });
  }

  test("the review returns every input finding, annotated, through the public judge", async () => {
    // Arrange
    const fake = fakeFetch(() => jsonResponse(answersFor(scoresOf({ data_exfiltration: 0.02, prompt_injection: 0.95 }))));
    const { judge } = createJudge(judgeCfg(), { TYPESAFE_API_KEY: fakeKey("ts_") }, { fetch: fake.fetch });
    const findings = [makeFinding({ category: "exfiltration" }), makeFinding({ category: "packaging", ruleId: "packaging/test" })];

    // Act
    const review = await judge!.review(bundle, findings);

    // Assert
    expect(review.status).toBe("ok");
    expect(review.findings.map((f) => [f.ruleId, f.confidence, f.judge?.effect])).toEqual([
      ["exfiltration/test-soft-rule", "low", "doubted"],
      ["packaging/test", "medium", undefined],
      ["judge/prompt-injection", "medium", "none"],
    ]);
  });
});

describe("JUDGE_RULES", () => {
  test("describes eight medium rules that never collide with built-in ids", () => {
    // Arrange
    const builtIn = new Set(ruleCatalog().map((r) => r.id));

    // Assert
    expect(JUDGE_RULES).toHaveLength(PROBE_IDS.length);
    expect(new Set(JUDGE_RULES.map((r) => r.id)).size).toBe(PROBE_IDS.length);
    for (const r of JUDGE_RULES) {
      expect(r.id).toMatch(/^judge\/[a-z-]+$/);
      expect(builtIn.has(r.id)).toBe(false);
      expect([r.severity, r.confidence]).toEqual(["medium", "medium"]);
      expect(r.description).toContain("model's opinion");
      expect(r.hard).toBeUndefined();
    }
  });
});
