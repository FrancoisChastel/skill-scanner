import { describe, expect, test } from "bun:test";
import { applyEffect, inLineComment, isCautionary, patternRule, signalRule } from "../../src/core/pattern-rule";
import type { BundleRule, FileContext, Hit, Signal } from "../../src/core/rule";
import { indexLines } from "../../src/core/text";
import { type BundleOptions, bundleOf, type FileSpec, scanFiles, skill } from "../helpers/bundle";

/** A bare FileContext over `text`, recording what a rule reports and signals. */
function ctxFor(text: string, kind: "script" | "markdown" = "script"): { ctx: FileContext; hits: Hit[]; signals: Array<[string, number]> } {
  const hits: Hit[] = [];
  const signals: Array<[string, number]> = [];
  const bundle = bundleOf({ "x.sh": text });
  const ctx: FileContext = {
    bundle,
    file: { path: "x.sh", kind, size: text.length, text },
    text,
    index: indexLines(text),
    role: kind === "script" ? "code" : "reference",
    report: (h) => hits.push(h),
    signal: (tag, offset) => signals.push([tag, offset]),
  };
  return { ctx, hits, signals };
}

/** A pattern rule over the word TRIGGER with the given region and role policy. */
function triggerRule(spec: Partial<Parameters<typeof patternRule>[0]> = {}) {
  return patternRule({
    id: "test/trigger",
    title: "Trigger",
    category: "prompt-injection",
    severity: "high",
    confidence: "high",
    description: "Matches TRIGGER.",
    patterns: [/\bTRIGGER\b/g],
    ...spec,
  });
}

const run = (files: Readonly<Record<string, FileSpec>>, rule = triggerRule(), opts: BundleOptions = {}) =>
  scanFiles(files, { ...opts, rules: [rule] }).findings.filter((f) => f.ruleId === "test/trigger");

describe("applyEffect", () => {
  test("skip drops the match", () => {
    // Arrange / Act / Assert
    expect(applyEffect("high", "high", "skip")).toBeUndefined();
  });

  test("raise, lower-severity, and lower-confidence move one step", () => {
    // Arrange / Act / Assert
    expect(applyEffect("high", "high", "raise")).toEqual({ severity: "critical", confidence: "high" });
    expect(applyEffect("high", "high", "lower-severity")).toEqual({ severity: "medium", confidence: "high" });
    expect(applyEffect("high", "high", "lower-confidence")).toEqual({ severity: "high", confidence: "medium" });
  });

  test("keep and no effect leave the values unchanged", () => {
    // Arrange / Act / Assert
    expect(applyEffect("low", "medium", "keep")).toEqual({ severity: "low", confidence: "medium" });
    expect(applyEffect("low", "medium", undefined)).toEqual({ severity: "low", confidence: "medium" });
  });
});

describe("isCautionary", () => {
  test("detects warning words on the match's line", () => {
    // Arrange
    const { ctx } = ctxFor("Never run TRIGGER on a shared machine.\nRun TRIGGER now.");

    // Act / Assert
    expect(isCautionary(ctx, 10)).toBe(true);
    expect(isCautionary(ctx, 43)).toBe(false);
  });

  test("detects a warning that introduces the match on the previous line with a colon", () => {
    // Arrange
    const text = "Red flags to watch for:\n- TRIGGER\nSteps:\n- TRIGGER";
    const { ctx } = ctxFor(text);

    // Act / Assert
    expect(isCautionary(ctx, text.indexOf("TRIGGER"))).toBe(true);
    expect(isCautionary(ctx, text.lastIndexOf("TRIGGER"))).toBe(false);
  });
});

describe("inLineComment", () => {
  test("detects shell, JS, and SQL line comments before the match", () => {
    // Arrange
    const text = "# TRIGGER\n// TRIGGER\n-- TRIGGER\nx = 1  # TRIGGER\nTRIGGER";
    const { ctx } = ctxFor(text);
    const at = (n: number) => text.split("TRIGGER").slice(0, n).join("TRIGGER").length;

    // Act / Assert
    expect([1, 2, 3, 4].map((n) => inLineComment(ctx, at(n)))).toEqual([true, true, true, true]);
    expect(inLineComment(ctx, at(5))).toBe(false);
  });

  test("does not treat a shebang, a hash-brace, or a URL fragment as a comment", () => {
    // Arrange
    const text = "#!/bin/sh TRIGGER\n#{x} TRIGGER\nhttps://a.example/#frag TRIGGER";
    const { ctx } = ctxFor(text);
    const offsets = [...text.matchAll(/TRIGGER/g)].map((m) => m.index);

    // Act / Assert
    expect(offsets.map((o) => inLineComment(ctx, o))).toEqual([false, false, false]);
  });
});

describe("patternRule construction", () => {
  test("rejects a pattern without the global flag", () => {
    // Arrange / Act / Assert
    expect(() => triggerRule({ patterns: [/TRIGGER/] })).toThrow("must be global");
  });

  test("defaults to every text kind and carries its metadata", () => {
    // Arrange / Act
    const rule = triggerRule();

    // Assert
    expect(rule.scope).toBe("file");
    expect(rule.kinds).toEqual(["skill-md", "markdown", "script", "manifest", "text"]);
    expect(rule).toMatchObject({ id: "test/trigger", severity: "high", confidence: "high" });
  });

  test("reports each match with its offset and length, capped per file", () => {
    // Arrange
    const { ctx, hits } = ctxFor("TRIGGER TRIGGER TRIGGER TRIGGER TRIGGER TRIGGER TRIGGER");

    // Act
    triggerRule().check(ctx);

    // Assert
    expect(hits).toHaveLength(5);
    expect(hits[0]).toEqual({ offset: 0, length: 7, severity: "high", confidence: "high" });
  });

  test("honours maxHitsPerFile, ignoreLine, ignoreMatch, and message", () => {
    // Arrange
    const rule = triggerRule({
      maxHitsPerFile: 1,
      ignoreLine: /placeholder/,
      ignoreMatch: (m) => m.index < 5,
      message: (m) => `saw ${m[0]}`,
    });
    const { ctx, hits } = ctxFor("TRIGGER placeholder TRIGGER\nok TRIGGER\nTRIGGER");

    // Act
    rule.check(ctx);

    // Assert
    expect(hits).toEqual([{ offset: 31, length: 7, severity: "high", confidence: "high", message: "saw TRIGGER" }]);
  });

  test("records a signal only for matches that are not low confidence", () => {
    // Arrange
    const rule = triggerRule({ signal: "network-send" });
    const plain = ctxFor("TRIGGER");
    const commented = ctxFor("# TRIGGER");

    // Act
    rule.check(plain.ctx);
    rule.check(commented.ctx);

    // Assert
    expect(plain.signals).toEqual([["network-send", 0]]);
    expect(commented.signals).toEqual([]);
    expect(commented.hits[0]).toMatchObject({ severity: "medium", confidence: "low" });
  });

  test("applies an adjust override after the other effects", () => {
    // Arrange
    const rule = triggerRule({ adjust: () => ({ severity: "low", message: "adjusted" }) });
    const { ctx, hits } = ctxFor("TRIGGER");

    // Act
    rule.check(ctx);

    // Assert
    expect(hits).toEqual([{ offset: 0, length: 7, severity: "low", confidence: "high", message: "adjusted" }]);
  });
});

describe("patternRule region and role effects", () => {
  const regions = { hidden: "raise", frontmatter: "raise", code: "lower-confidence", prose: "skip" } as const;

  test("raises a match in a hidden HTML comment", () => {
    // Arrange
    const files = { "SKILL.md": skill("<!-- TRIGGER -->") };

    // Act
    const [f] = run(files, triggerRule({ regions }));

    // Assert
    expect(f).toMatchObject({ severity: "critical", confidence: "high" });
  });

  test("raises a match in the frontmatter", () => {
    // Arrange
    const files = { "SKILL.md": "---\nname: demo-skill\ndescription: TRIGGER the thing\n---\nbody\n" };

    // Act
    const [f] = run(files, triggerRule({ regions }));

    // Assert
    expect(f).toMatchObject({ severity: "critical", location: { line: 3 } });
  });

  test("lowers confidence in fenced code and skips prose when configured", () => {
    // Arrange
    const files = { "SKILL.md": skill("TRIGGER in prose\n\n```sh\nTRIGGER\n```") };

    // Act
    const found = run(files, triggerRule({ regions }));

    // Assert
    expect(found).toHaveLength(1);
    expect(found[0]).toMatchObject({ severity: "high", confidence: "medium" });
  });

  test("demotes and marks low confidence a match in a cautionary sentence", () => {
    // Arrange
    const files = { "SKILL.md": skill("Never TRIGGER anything.") };

    // Act
    const [f] = run(files);

    // Assert
    expect(f).toMatchObject({ severity: "medium", confidence: "low" });
  });

  test("keeps full weight for a cautionary sentence inside a hidden region", () => {
    // Arrange
    const files = { "SKILL.md": skill("<!-- never TRIGGER -->") };

    // Act
    const [f] = run(files, triggerRule({ regions }));

    // Assert
    expect(f).toMatchObject({ severity: "critical", confidence: "high" });
  });

  test("can turn caution awareness off", () => {
    // Arrange
    const files = { "SKILL.md": skill("Never TRIGGER anything.") };

    // Act
    const [f] = run(files, triggerRule({ cautionAware: false }));

    // Assert
    expect(f).toMatchObject({ severity: "high", confidence: "high" });
  });

  test("demotes a match inside a comment in fenced code", () => {
    // Arrange
    const files = { "SKILL.md": skill("```sh\n# TRIGGER here\n```") };

    // Act
    const [f] = run(files);

    // Assert
    expect(f).toMatchObject({ severity: "medium", confidence: "low" });
  });

  test("applies the file role effect before the region effect", () => {
    // Arrange
    const rule = triggerRule({ roles: { readme: "skip", reference: "lower-severity", code: "raise" } });
    const files = { "SKILL.md": skill("ok"), "README.md": "TRIGGER", "references/a.md": "TRIGGER", "scripts/a.py": "TRIGGER" };

    // Act
    const found = run(files, rule);

    // Assert
    expect(found.map((f) => [f.location.file, f.severity]).sort()).toEqual([
      ["references/a.md", "medium"],
      ["scripts/a.py", "critical"],
    ]);
  });

  test("keeps full weight for matches in decoded payloads regardless of roles", () => {
    // Arrange
    const payload = Buffer.from("TRIGGER inside a payload that is long enough to be decoded by the scanner, really").toString("base64");
    const rule = triggerRule({ roles: { readme: "skip" } });

    // Act
    const found = run({ "README.md": `blob: ${payload}` }, rule);

    // Assert
    expect(found).toHaveLength(1);
    expect(found[0]).toMatchObject({ severity: "high", confidence: "high" });
    expect(found[0]?.message).toStartWith("In base64-decoded content:");
  });
});

describe("signalRule", () => {
  test("records signals and never reports", () => {
    // Arrange
    const rule = signalRule("signal/test", "network", [/\bfetch\(/g]);
    const { ctx, hits, signals } = ctxFor("fetch(a); fetch(b)");

    // Act
    rule.check(ctx);

    // Assert
    expect(hits).toEqual([]);
    expect(signals).toEqual([
      ["network", 0],
      ["network", 10],
    ]);
    expect(rule.severity).toBe("info");
  });

  test("ignores cautionary prose in Markdown and honours ignoreMatch", () => {
    // Arrange
    const rule = signalRule("signal/test", "network", [/\bfetch\(\s*(\w+)/g], { ignoreMatch: (m) => m[1] === "skipme" });
    const signals: Signal[] = [];
    const collector: BundleRule = {
      id: "test/collect",
      title: "collect",
      category: "network",
      severity: "info",
      confidence: "low",
      description: "d",
      scope: "bundle",
      check: (ctx) => {
        signals.push(...ctx.signals);
      },
    };

    // Act
    scanFiles({ "SKILL.md": skill("Never fetch( secrets.\n\nfetch( data\n\nfetch( skipme") }, { rules: [rule, collector] });

    // Assert
    expect(signals).toEqual([{ tag: "network", file: "SKILL.md", offset: signals[0]?.offset ?? -1, line: 8, detail: "fetch( data" }]);
  });
});
