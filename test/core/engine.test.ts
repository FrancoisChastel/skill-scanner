import { describe, expect, test } from "bun:test";
import { analyzeBundle, joinPath } from "../../src/core/engine";
import { patternRule } from "../../src/core/pattern-rule";
import type { BundleRule, FileRule, Rule, Signal } from "../../src/core/rule";
import type { Severity } from "../../src/core/types";
import { type BundleOptions, bundleOf, type FileSpec, skill } from "../helpers/bundle";

const b64 = (s: string) => Buffer.from(s).toString("base64");

/** Matches TRIGGER in any text file (or only scripts), at the given severity. */
function trigger(severity: Severity = "high", kinds: FileRule["kinds"] = ["skill-md", "markdown", "script", "manifest", "text"]): FileRule {
  return patternRule({
    id: "test/trigger",
    title: "Trigger",
    category: "prompt-injection",
    severity,
    confidence: "high",
    description: "Matches TRIGGER.",
    patterns: [/\bTRIGGER\b/g],
    kinds,
    cautionAware: false,
  });
}

function collector(into: Signal[]): BundleRule {
  return {
    id: "test/collect",
    title: "collect",
    category: "network",
    severity: "info",
    confidence: "low",
    description: "Collects signals.",
    scope: "bundle",
    check: (ctx) => {
      into.push(...ctx.signals);
    },
  };
}

const analyze = (files: Readonly<Record<string, FileSpec>>, rules: readonly Rule[], opts: BundleOptions & { depth?: number } = {}) =>
  analyzeBundle(bundleOf(files, opts), { rules, ...(opts.depth !== undefined ? { maxDecodeDepth: opts.depth } : {}) });

// Long enough that its base64 passes the 80-character minimum.
const HIDDEN = "TRIGGER hidden inside an encoded blob, with enough padding to be decoded by the engine";

describe("analyzeBundle: encoded payloads", () => {
  test("rescans decoded base64 and reports it at the blob's line in the real file", () => {
    // Arrange
    const files = { "SKILL.md": skill(`Intro\n\nblob: ${b64(HIDDEN)}`) };

    // Act
    const findings = analyze(files, [trigger("high", ["script"])]);

    // Assert
    const inner = findings.find((f) => f.ruleId === "test/trigger");
    expect(inner?.message).toBe("In base64-decoded content: Matches TRIGGER.");
    expect(inner?.location).toMatchObject({ file: "SKILL.md", line: 8, column: 7 });
    expect(inner?.evidence).toContain("TRIGGER hidden");
  });

  test("adds an encoded-payload finding one step above the worst hidden finding", () => {
    // Arrange
    const high = { "a.md": `x ${b64(HIDDEN)}` };

    // Act
    const fromHigh = analyze(high, [trigger("high")]).find((f) => f.ruleId === "obfuscation/encoded-payload");
    const fromMedium = analyze(high, [trigger("medium")]).find((f) => f.ruleId === "obfuscation/encoded-payload");

    // Assert
    expect(fromHigh).toMatchObject({ severity: "critical", confidence: "high", category: "obfuscation", source: "static" });
    expect(fromHigh?.message).toBe("base64-encoded text decodes to content that triggers: test/trigger");
    expect(fromHigh?.evidence).toBe(HIDDEN);
    expect(fromMedium?.severity).toBe("high");
  });

  test("does not add an encoded-payload finding for low-severity hidden findings", () => {
    // Arrange
    const files = { "a.md": `x ${b64(HIDDEN)}` };

    // Act
    const findings = analyze(files, [trigger("low")]);

    // Assert
    expect(findings.map((f) => f.ruleId)).toEqual(["test/trigger"]);
  });

  test("peels two layers of encoding by default and none with depth 0", () => {
    // Arrange
    const files = { "a.txt": `x ${b64(`outer layer wrapping: ${b64(HIDDEN)}`)}` };

    // Act
    const deep = analyze(files, [trigger()]);
    const none = analyze(files, [trigger()], { depth: 0 });
    const one = analyze(files, [trigger()], { depth: 1 });

    // Assert
    expect(deep.some((f) => f.ruleId === "test/trigger")).toBe(true);
    expect(none).toEqual([]);
    expect(one.some((f) => f.ruleId === "test/trigger")).toBe(false);
  });

  test("keeps all decoded findings at the outer blob's location", () => {
    // Arrange
    const files = { "a.txt": `line1\nline2 ${b64(`outer layer wrapping: ${b64(HIDDEN)}`)}` };

    // Act
    const findings = analyze(files, [trigger()]);

    // Assert
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) expect(f.location).toMatchObject({ file: "a.txt", line: 2 });
  });

  test("does not decode binary files", () => {
    // Arrange
    const files: Record<string, FileSpec> = { "blob.bin": { kind: "binary", size: 10, binaryFormat: "unknown" } };

    // Act / Assert
    expect(analyze(files, [trigger()])).toEqual([]);
  });
});

describe("analyzeBundle: virtual files", () => {
  test("maps a finding in an npm script to the manifest line and names the script", () => {
    // Arrange
    const files = { "package.json": JSON.stringify({ name: "x", scripts: { postinstall: "echo TRIGGER" } }, null, 2) };

    // Act
    const [f] = analyze(files, [trigger("high", ["script"])]);

    // Assert
    expect(f?.message).toBe("npm script 'postinstall': Matches TRIGGER.");
    expect(f?.location.file).toBe("package.json");
    expect(f?.location.line).toBe(4);
    expect(f?.location.column).toBeUndefined();
  });

  test("maps a line inside a load-time shell block to the matching file line", () => {
    // Arrange
    const md = skill("Before\n\n```!\necho ok\necho TRIGGER\n```");

    // Act
    const [f] = analyze({ "SKILL.md": md }, [trigger("high", ["script"])]);

    // Assert
    expect(f?.message).toBe("shell command expanded when the skill loads: Matches TRIGGER.");
    expect(f?.location).toMatchObject({ file: "SKILL.md", line: 10 });
    expect(md.split("\n")[9]).toBe("echo TRIGGER");
  });

  test("describes hook and MCP commands", () => {
    // Arrange
    const files = {
      "hooks/hooks.json": JSON.stringify({ hooks: { Stop: [{ hooks: [{ type: "command", command: "TRIGGER" }] }] } }),
      ".mcp.json": JSON.stringify({ mcpServers: { s: { command: "TRIGGER" } } }),
    };

    // Act
    const messages = analyze(files, [trigger("high", ["script"])]).map((f) => f.message);

    // Assert
    expect(messages.sort()).toEqual([
      "MCP server launch command (mcpServers.s): Matches TRIGGER.",
      "hook command (hooks.Stop[0].hooks[0]): Matches TRIGGER.",
    ]);
  });
});

describe("analyzeBundle: dedupe, errors, ordering", () => {
  test("keeps one finding per rule and line, the most severe", () => {
    // Arrange
    const rule = patternRule({
      id: "test/two",
      title: "Two",
      category: "network",
      severity: "low",
      confidence: "high",
      description: "d",
      patterns: [/\bAAA\b/g, /\bBBB\b/g],
      adjust: (m) => (m[0] === "BBB" ? { severity: "high" } : undefined),
    });

    // Act
    const findings = analyze({ "a.txt": "AAA BBB\nAAA" }, [rule]);

    // Assert
    expect(findings.map((f) => [f.location.line, f.severity])).toEqual([
      [1, "high"],
      [2, "low"],
    ]);
  });

  test("turns a throwing rule into scanner/rule-error without stopping other rules", () => {
    // Arrange
    const boom: FileRule = {
      id: "test/boom",
      title: "Boom",
      category: "network",
      severity: "high",
      confidence: "high",
      description: "Always throws.",
      scope: "file",
      kinds: ["text"],
      check: () => {
        throw new Error("kaput");
      },
    };

    // Act
    const findings = analyze({ "a.txt": "TRIGGER" }, [boom, trigger()]);

    // Assert
    expect(findings.map((f) => f.ruleId).sort()).toEqual(["scanner/rule-error", "test/trigger"]);
    expect(findings.find((f) => f.ruleId === "scanner/rule-error")).toMatchObject({
      severity: "low",
      confidence: "low",
      category: "packaging",
      message: "rule test/boom threw: kaput. The file was only partly analyzed.",
      location: { file: "a.txt" },
    });
  });

  test("reports a rule error in a virtual file against the real file", () => {
    // Arrange
    const boom: FileRule = {
      id: "test/boom",
      title: "Boom",
      category: "network",
      severity: "high",
      confidence: "high",
      description: "Throws a string.",
      scope: "file",
      kinds: ["script"],
      check: () => {
        throw "bad";
      },
    };

    // Act
    const [f] = analyze({ "package.json": JSON.stringify({ scripts: { test: "x" } }) }, [boom], { root: "skills/s" });

    // Assert
    expect(f).toMatchObject({ ruleId: "scanner/rule-error", location: { file: "skills/s/package.json" } });
    expect(f?.message).toContain("threw: bad");
  });

  test("sorts findings most severe first and caps them per bundle", () => {
    // Arrange
    const text = Array.from({ length: 600 }, (_, i) => (i === 599 ? "BIG" : "TRIGGER")).join("\n");
    const big = patternRule({
      id: "test/big",
      title: "Big",
      category: "network",
      severity: "critical",
      confidence: "high",
      description: "d",
      patterns: [/\bBIG\b/g],
    });
    const many = patternRule({
      id: "test/trigger",
      title: "Trigger",
      category: "network",
      severity: "low",
      confidence: "high",
      description: "d",
      patterns: [/\bTRIGGER\b/g],
      maxHitsPerFile: 1000,
    });

    // Act
    const findings = analyze({ "a.txt": text }, [many, big]);

    // Assert
    expect(findings).toHaveLength(500);
    expect(findings[0]?.ruleId).toBe("test/big");
    expect(findings[1]?.location.line).toBe(1);
  });
});

describe("analyzeBundle: locations and bundle rules", () => {
  test("prefixes file paths with the bundle root and reports line and column", () => {
    // Arrange
    const files = { "scripts/run.sh": "echo ok\n  TRIGGER" };

    // Act
    const [f] = analyze(files, [trigger()], { root: "skills/demo" });

    // Assert
    expect(f?.location).toEqual({ file: "skills/demo/scripts/run.sh", line: 2, column: 3, snippet: "TRIGGER" });
    expect(f?.bundle).toBe("demo");
  });

  test("redacts secrets in snippets", () => {
    // Arrange
    const token = `${"gh"}p_${"Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2Yz"}`;
    const files = { "a.txt": `TRIGGER token=${token}` };

    // Act
    const [f] = analyze(files, [trigger()]);

    // Assert
    expect(f?.location.snippet).not.toContain(token);
    expect(f?.location.snippet).toContain("ghp_");
  });

  test("gives signals bundle-relative paths, also from decoded payloads", () => {
    // Arrange
    const signals: Signal[] = [];
    const sig = patternRule({
      id: "test/sig",
      title: "Sig",
      category: "network",
      severity: "info",
      confidence: "high",
      description: "d",
      patterns: [/\bTRIGGER\b/g],
      signal: "network-send",
    });
    const files = { "scripts/a.sh": "TRIGGER", "notes/b.txt": `one\ntwo ${b64(HIDDEN)}` };

    // Act
    analyze(files, [sig, collector(signals)], { root: "skills/demo" });

    // Assert
    expect(signals.map((s) => [s.tag, s.file, s.line])).toEqual([
      ["network-send", "scripts/a.sh", 1],
      ["network-send", "notes/b.txt", 2],
    ]);
  });

  test("builds bundle-rule findings with root-joined paths, visible and redacted snippets, and overrides", () => {
    // Arrange
    const token = `${"gh"}p_${"Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0Pp9Oo8Nn"}`;
    const rule: BundleRule = {
      id: "correlation/test",
      title: "Corr",
      category: "exfiltration",
      severity: "critical",
      confidence: "high",
      description: "d",
      remediation: "fix it",
      scope: "bundle",
      check: (ctx) => {
        ctx.report({
          file: "a.sh",
          line: 3,
          snippet: `x${String.fromCodePoint(0x200b)}y ${token}`,
          message: "m",
          severity: "high",
          confidence: "medium",
          evidence: `ev ${token}`,
        });
        ctx.report({ file: "b.sh", message: "plain" });
      },
    };

    // Act
    const findings = analyze({ "a.sh": "x" }, [rule], { root: "skills/demo" });

    // Assert
    const first = findings.find((f) => f.message === "m");
    expect(first).toMatchObject({
      ruleId: "correlation/test",
      source: "correlation",
      severity: "high",
      confidence: "medium",
      remediation: "fix it",
      location: { file: "skills/demo/a.sh", line: 3 },
    });
    expect(first?.location.snippet).toStartWith("x<U+200B>y ");
    expect(first?.location.snippet).not.toContain(token);
    expect(first?.evidence).not.toContain(token);
    expect(findings.find((f) => f.message === "plain")).toMatchObject({
      severity: "critical",
      confidence: "high",
      location: { file: "skills/demo/b.sh" },
    });
  });

  test("marks non-correlation bundle findings as static", () => {
    // Arrange
    const rule: BundleRule = {
      id: "packaging/test",
      title: "P",
      category: "packaging",
      severity: "low",
      confidence: "high",
      description: "d",
      scope: "bundle",
      check: (ctx) => ctx.report({ file: ".", message: "note" }),
    };

    // Act
    const [f] = analyze({ "a.txt": "x" }, [rule]);

    // Assert
    expect(f).toMatchObject({ source: "static", location: { file: "." } });
    expect(f?.remediation).toBeUndefined();
  });

  test("gives only SKILL.md a frontmatter region", () => {
    // Arrange
    const rule = patternRule({
      id: "test/trigger",
      title: "Trigger",
      category: "prompt-injection",
      severity: "medium",
      confidence: "high",
      description: "d",
      patterns: [/\bTRIGGER\b/g],
      regions: { frontmatter: "raise" },
    });
    const fm = "---\nname: demo-skill\ndescription: TRIGGER\n---\nbody\n";

    // Act
    const findings = analyze({ "SKILL.md": fm, "notes.md": fm }, [rule]);

    // Assert
    expect(findings.map((f) => [f.location.file, f.severity]).sort()).toEqual([
      ["SKILL.md", "high"],
      ["notes.md", "medium"],
    ]);
  });
});

describe("joinPath", () => {
  test("joins a root and a path, leaving the path alone for the scan root", () => {
    // Arrange / Act / Assert
    expect(joinPath(".", "a.md")).toBe("a.md");
    expect(joinPath("", "a.md")).toBe("a.md");
    expect(joinPath("skills/x", "a.md")).toBe("skills/x/a.md");
  });
});
