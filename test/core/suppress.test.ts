import { describe, expect, test } from "bun:test";
import { globToRegExp, isSuppressed, matchesRule, type Suppression } from "../../src/core/suppress";
import type { Finding } from "../../src/core/types";

const finding = (ruleId: string, file: string): Finding => ({
  ruleId,
  title: "t",
  category: "network",
  severity: "high",
  confidence: "high",
  message: "m",
  location: { file },
  bundle: "b",
  source: "static",
});

describe("globToRegExp", () => {
  test("* matches within one path segment only", () => {
    // Arrange
    const re = globToRegExp("scripts/*.sh");

    // Act / Assert
    expect(re.test("scripts/run.sh")).toBe(true);
    expect(re.test("scripts/sub/run.sh")).toBe(false);
    expect(re.test("scripts/.sh")).toBe(true);
  });

  test("** matches across segments", () => {
    // Arrange
    const re = globToRegExp("docs/**");

    // Act / Assert
    expect(re.test("docs/a.md")).toBe(true);
    expect(re.test("docs/a/b/c.md")).toBe(true);
    expect(re.test("other/docs/a.md")).toBe(false);
  });

  test("**/ matches zero or more leading directories", () => {
    // Arrange
    const re = globToRegExp("**/README.md");

    // Act / Assert
    expect(re.test("README.md")).toBe(true);
    expect(re.test("a/README.md")).toBe(true);
    expect(re.test("a/b/README.md")).toBe(true);
    expect(re.test("a/xREADME.md")).toBe(false);
  });

  test("a/**/b matches a/b and deeper", () => {
    // Arrange
    const re = globToRegExp("a/**/b.md");

    // Act / Assert
    expect(re.test("a/b.md")).toBe(true);
    expect(re.test("a/x/y/b.md")).toBe(true);
  });

  test("? matches one non-slash character", () => {
    // Arrange
    const re = globToRegExp("file?.txt");

    // Act / Assert
    expect(re.test("file1.txt")).toBe(true);
    expect(re.test("file.txt")).toBe(false);
    expect(re.test("file/.txt")).toBe(false);
  });

  test("escapes regex metacharacters and anchors the whole path", () => {
    // Arrange
    const re = globToRegExp("a.b+(c)[d]{e}$^|.md");

    // Act / Assert
    expect(re.test("a.b+(c)[d]{e}$^|.md")).toBe(true);
    expect(re.test("axb+(c)[d]{e}$^|.md")).toBe(false);
    expect(globToRegExp("x.md").test("prefix/x.md")).toBe(false);
  });
});

describe("matchesRule", () => {
  test("matches an exact id, a category wildcard, or everything", () => {
    // Arrange / Act / Assert
    expect(matchesRule("network/raw-ip-url", "network/raw-ip-url")).toBe(true);
    expect(matchesRule("network/*", "network/raw-ip-url")).toBe(true);
    expect(matchesRule("*", "exec/reverse-shell")).toBe(true);
    expect(matchesRule("network/*", "networking/x")).toBe(false);
    expect(matchesRule("network/raw", "network/raw-ip-url")).toBe(false);
  });
});

describe("isSuppressed", () => {
  const f = finding("network/raw-ip-url", "skill/scripts/run.sh");

  test("returns the first matching suppression", () => {
    // Arrange
    const list: Suppression[] = [{ rule: "exec/*" }, { rule: "network/*", reason: "known" }, { rule: "*" }];

    // Act
    const s = isSuppressed(f, "sha256:x", list);

    // Assert
    expect(s).toEqual({ rule: "network/*", reason: "known" });
  });

  test("requires the path glob to match when one is given", () => {
    // Arrange
    const hit: Suppression[] = [{ rule: "network/raw-ip-url", path: "**/scripts/*.sh" }];
    const miss: Suppression[] = [{ rule: "network/raw-ip-url", path: "docs/**" }];

    // Act / Assert
    expect(isSuppressed(f, "sha256:x", hit)).toBeDefined();
    expect(isSuppressed(f, "sha256:x", miss)).toBeUndefined();
  });

  test("requires the bundle digest to match when one is given", () => {
    // Arrange
    const list: Suppression[] = [{ rule: "*", digest: "sha256:abc" }];

    // Act / Assert
    expect(isSuppressed(f, "sha256:abc", list)).toBeDefined();
    expect(isSuppressed(f, "sha256:changed", list)).toBeUndefined();
  });

  test("returns undefined for an empty list", () => {
    // Arrange / Act / Assert
    expect(isSuppressed(f, "sha256:x", [])).toBeUndefined();
  });
});
