import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { BUILTIN_RULES, ENGINE_RULES, isSignalOnly, ruleCatalog } from "../../src/rules";

/**
 * Every rule in the catalog must be tested: a `describe("<rule id>", ...)` block in a test/rules
 * file, containing a positive case (`expectFinding`) and a realistic negative (`expectQuiet` or
 * `expectNone`). Adding a rule without tests fails here.
 */

const DIR = import.meta.dir;

interface Block {
  readonly file: string;
  readonly body: string;
}

function ruleBlocks(): Map<string, Block[]> {
  const out = new Map<string, Block[]>();
  for (const name of readdirSync(DIR).filter((n) => n.endsWith(".test.ts") && n !== "catalog.test.ts")) {
    const source = readFileSync(join(DIR, name), "utf8");
    const starts = [...source.matchAll(/^describe\("([a-z-]+\/[a-z0-9-]+)"/gm)];
    starts.forEach((m, i) => {
      const body = source.slice(m.index, starts[i + 1]?.index ?? source.length);
      out.set(m[1]!, [...(out.get(m[1]!) ?? []), { file: name, body }]);
    });
  }
  return out;
}

describe("rule catalog coverage", () => {
  const blocks = ruleBlocks();
  const catalog = ruleCatalog().map((r) => r.id);

  test("every catalog rule has a describe block in test/rules", () => {
    // Arrange / Act
    const missing = catalog.filter((id) => !blocks.has(id));

    // Assert
    expect(missing).toEqual([]);
  });

  test("every rule block has a positive and a negative case", () => {
    // Arrange / Act
    const incomplete = catalog.filter((id) => {
      const body = (blocks.get(id) ?? []).map((b) => b.body).join("\n");
      return !/\bexpectFinding\(/.test(body) || !/\bexpect(?:Quiet|None)\(/.test(body);
    });

    // Assert
    expect(incomplete).toEqual([]);
  });

  test("no describe block names a rule that does not exist", () => {
    // Arrange
    const known = new Set(catalog);

    // Act
    const unknown = [...blocks.keys()].filter((id) => !known.has(id));

    // Assert
    expect(unknown).toEqual([]);
  });

  test("rule ids are unique, well formed, and signal-only rules stay out of the catalog", () => {
    // Arrange
    const all = [...BUILTIN_RULES, ...ENGINE_RULES].map((r) => r.id);

    // Act / Assert
    expect(new Set(all).size).toBe(all.length);
    for (const id of all) expect(id).toMatch(/^[a-z-]+\/[a-z0-9-]+$/);
    expect(ruleCatalog().some(isSignalOnly)).toBe(false);
    expect(BUILTIN_RULES.some(isSignalOnly)).toBe(true);
  });

  test("every rule has a title, a description of one or two sentences, and a known severity", () => {
    // Arrange / Act / Assert
    for (const r of ruleCatalog()) {
      expect(r.title.length).toBeGreaterThan(5);
      expect(r.description.length).toBeGreaterThan(20);
      expect(["info", "low", "medium", "high", "critical"]).toContain(r.severity);
      expect(["low", "medium", "high"]).toContain(r.confidence);
    }
  });
});
