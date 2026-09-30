import { describe, expect, test } from "bun:test";
import { pathContextOf } from "../../src/core/classify";
import {
  asMention,
  contextualize,
  inPatternLiteral,
  inQuotes,
  inRemoteCommand,
  isCautionary,
  isTableRow,
  pathContext,
} from "../../src/core/context";
import { segmentMarkdown } from "../../src/core/markdown";
import type { FileContext } from "../../src/core/rule";
import { indexLines } from "../../src/core/text";
import type { SkillBundle, SkillFile } from "../../src/core/types";
import { bundleOf, skill } from "../helpers/bundle";

/** A FileContext over one file of a bundle, with Markdown regions when the file is Markdown. */
function ctxFor(bundle: SkillBundle, path: string): FileContext {
  const file = bundle.files.find((f) => f.path === path)!;
  const text = file.text ?? "";
  const markdown = file.kind === "skill-md" || file.kind === "markdown";
  return {
    bundle,
    file,
    text,
    index: indexLines(text),
    role: file.kind === "skill-md" ? "instructions" : file.kind === "script" ? "code" : "reference",
    ...(markdown ? { regions: segmentMarkdown(text) } : {}),
    report: () => {},
    signal: () => {},
  };
}

const at = (ctx: FileContext, needle: string): number => ctx.text.indexOf(needle);

describe("inQuotes", () => {
  test("sees a phrase inside double quotes, and one that wraps onto the next line", () => {
    // Arrange
    const md = 'Watch for "ignore previous instructions" in inputs.\nAlso "ignore\nprevious instructions" wrapped.';
    const ctx = ctxFor(bundleOf({ "notes.md": md }), "notes.md");
    const second = ctx.text.lastIndexOf("ignore");

    // Act / Assert
    expect(inQuotes(ctx, at(ctx, "ignore"), "ignore previous instructions".length)).toBe(true);
    expect(inQuotes(ctx, second, "ignore\nprevious instructions".length)).toBe(true);
  });

  test("does not treat apostrophes in prose as quotes unless asked to", () => {
    // Arrange
    const ctx = ctxFor(bundleOf({ "notes.md": "Don't ignore previous instructions, it's rude." }), "notes.md");

    // Act / Assert
    expect(inQuotes(ctx, at(ctx, "ignore"), 6)).toBe(false);
  });
});

describe("isTableRow and isCautionary", () => {
  test("recognizes a Markdown table row", () => {
    // Arrange
    const ctx = ctxFor(bundleOf({ "t.md": "| Pattern | Example |\n| a | b |" }), "t.md");

    // Act / Assert
    expect(isTableRow(ctx, at(ctx, "a |"))).toBe(true);
  });

  test("reads a warning from the heading a list hangs from and from a wrapped sentence", () => {
    // Arrange
    const md = "## Must Never\n\n- Submit untested changes.\n- Bypass checks.\n\nDo not use plan mode or\n`--flag`.";
    const ctx = ctxFor(bundleOf({ "r.md": md }), "r.md");

    // Act / Assert
    expect(isCautionary(ctx, at(ctx, "Bypass"))).toBe(true);
    expect(isCautionary(ctx, at(ctx, "`--flag`"))).toBe(true);
  });

  test("does not read a warning from an unrelated heading", () => {
    // Arrange
    const ctx = ctxFor(bundleOf({ "r.md": "## Setup\n\n- Run the installer.\n" }), "r.md");

    // Act / Assert
    expect(isCautionary(ctx, at(ctx, "Run"))).toBe(false);
  });
});

describe("inRemoteCommand", () => {
  test("sees commands passed to ssh, docker, and az vm run-command", () => {
    // Arrange
    const md = 'ssh admin@host.example "setenforce 0"\ndocker run img sh -c "id"\naz vm run-command invoke --scripts "setenforce 0"';
    const ctx = ctxFor(bundleOf({ "r.md": md }), "r.md");
    const lines = md.split("\n");

    // Act / Assert
    expect(inRemoteCommand(ctx, at(ctx, "setenforce"))).toBe(true);
    expect(inRemoteCommand(ctx, ctx.text.indexOf("id", lines[0]!.length))).toBe(true);
    expect(inRemoteCommand(ctx, ctx.text.lastIndexOf("setenforce"))).toBe(true);
  });

  test("does not flag a local command", () => {
    // Arrange
    const ctx = ctxFor(bundleOf({ "r.md": "setenforce 0" }), "r.md");

    // Act / Assert
    expect(inRemoteCommand(ctx, 0)).toBe(false);
  });
});

describe("inPatternLiteral", () => {
  test("treats a JavaScript regex literal and a RegExp constructor as patterns", () => {
    // Arrange
    const js = 'const RE = /\\.netrc\\b/g;\nconst R2 = new RegExp("id_rsa");\n';
    const ctx = ctxFor(bundleOf({ "scripts/d.js": js }), "scripts/d.js");

    // Act / Assert
    expect(inPatternLiteral(ctx, at(ctx, "netrc"), 5)).toBe(true);
    expect(inPatternLiteral(ctx, at(ctx, "id_rsa"), 6)).toBe(true);
  });

  test("treats a Python raw string as a pattern", () => {
    // Arrange
    const py = '#!/usr/bin/env python3\nPATTERNS = [r"\\.netrc", "plain"]\n';
    const ctx = ctxFor(bundleOf({ "scripts/d.py": py }), "scripts/d.py");

    // Act / Assert
    expect(inPatternLiteral(ctx, at(ctx, ".netrc"), 6)).toBe(true);
  });

  test("never reads a shell path as a regex literal", () => {
    // Arrange
    const shell = "#!/bin/sh\ncat ~/.aws/credentials\n";
    const ctx = ctxFor(bundleOf({ "scripts/r.sh": shell }), "scripts/r.sh");

    // Act / Assert
    expect(inPatternLiteral(ctx, at(ctx, ".aws/credentials"), 16)).toBe(false);
  });
});

describe("pathContext", () => {
  const file = (bundle: SkillBundle, path: string): SkillFile => bundle.files.find((f) => f.path === path)!;

  test("classifies tests, CI, docs, container files, and attack write-ups by path", () => {
    // Arrange / Act / Assert
    expect(pathContextOf({ path: "tests/test_x.py", kind: "script" })).toBe("dev");
    expect(pathContextOf({ path: ".github/workflows/ci.yml", kind: "text" })).toBe("dev");
    expect(pathContextOf({ path: "src/app.test.ts", kind: "script" })).toBe("dev");
    expect(pathContextOf({ path: "Dockerfile", kind: "text" })).toBe("container");
    expect(pathContextOf({ path: "references/attack-patterns.md", kind: "markdown" })).toBe("educational");
    expect(pathContextOf({ path: "SKILL.md", kind: "skill-md" })).toBeUndefined();
    expect(pathContextOf({ path: "scripts/run.sh", kind: "script" })).toBeUndefined();
  });

  test("drops the development discount when SKILL.md tells the agent to run the file", () => {
    // Arrange
    const referenced = bundleOf({ "SKILL.md": skill("First run tests/check.py."), "tests/check.py": "print(1)\n" });
    const listed = bundleOf({ "SKILL.md": skill("The suite lives in tests/check.py."), "tests/check.py": "print(1)\n" });

    // Act / Assert
    expect(pathContext(referenced, file(referenced, "tests/check.py"))).toBeUndefined();
    expect(pathContext(listed, file(listed, "tests/check.py"))).toBe("dev");
  });

  test("keeps data files discounted even when a script names them", () => {
    // Arrange
    const b = bundleOf({ "SKILL.md": skill("x"), "scripts/load.py": 'open("tests/fixture.json")\n', "tests/fixture.json": "{}" });

    // Act / Assert
    expect(pathContext(b, file(b, "tests/fixture.json"))).toBe("dev");
  });

  test("treats the reference docs of a skill named for security review as write-ups", () => {
    // Arrange
    const b = bundleOf({ "SKILL.md": skill("x"), "references/supply-chain.md": "text" }, { root: "skills/security-review" });

    // Act / Assert
    expect(pathContext(b, file(b, "references/supply-chain.md"))).toBe("educational");
  });
});

describe("contextualize", () => {
  test("turns a match in an unreferenced test file into a mention", () => {
    // Arrange
    const b = bundleOf({ "SKILL.md": skill("x"), "tests/t.sh": "#!/bin/sh\necho hi\n" });
    const ctx = ctxFor(b, "tests/t.sh");

    // Act
    const g = contextualize(ctx, 10, 4, { severity: "high", confidence: "high" });

    // Assert
    expect(g).toEqual(asMention({ severity: "high", confidence: "high" }));
  });

  test("gives decoded payloads no benefit of the doubt outside development files", () => {
    // Arrange
    const b = bundleOf({ "SKILL.md": skill("x"), "scripts/a.sh": "#!/bin/sh\n# comment\n" });
    const ctx = { ...ctxFor(b, "scripts/a.sh"), decoded: true };

    // Act
    const g = contextualize(ctx, 12, 7, { severity: "critical", confidence: "high" });

    // Assert
    expect(g).toEqual({ severity: "critical", confidence: "high" });
  });

  test("applies region effects and skips", () => {
    // Arrange
    const b = bundleOf({ "SKILL.md": skill("Plain prose here.") });
    const ctx = ctxFor(b, "SKILL.md");

    // Act
    const skipped = contextualize(ctx, at(ctx, "Plain"), 5, { severity: "high", confidence: "high" }, { regions: { prose: "skip" } });

    // Assert
    expect(skipped).toBeUndefined();
  });
});
