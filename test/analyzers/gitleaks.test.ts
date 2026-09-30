import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { gitleaksArgs, parseGitleaksOutput } from "../../src/analyzers/gitleaks";

const ROOT = "/tmp/scan-root";

/** Shaped like `gitleaks dir --redact --report-format json` output from gitleaks 8.30.1. */
function leak(overrides: Record<string, unknown>): Record<string, unknown> {
  return {
    RuleID: "github-pat",
    Description:
      "Uncovered a GitHub Personal Access Token, potentially leading to unauthorized repository access and sensitive content exposure.",
    StartLine: 2,
    EndLine: 2,
    StartColumn: 11,
    EndColumn: 50,
    Match: "REDACTED",
    Secret: "REDACTED",
    File: join(ROOT, "skills/evil/scripts/run.py"),
    SymlinkFile: "",
    Commit: "",
    Entropy: 4.553056,
    Author: "",
    Email: "",
    Date: "",
    Message: "",
    Tags: [],
    Fingerprint: `${join(ROOT, "skills/evil/scripts/run.py")}:github-pat:2`,
    ...overrides,
  };
}

describe("parseGitleaksOutput", () => {
  test("maps each leak to a secrets finding relative to the root", () => {
    // Arrange
    const report = JSON.stringify([
      leak({}),
      leak({
        RuleID: "generic-api-key",
        StartLine: 3,
        EndLine: 3,
        StartColumn: 2,
        Match: 'KEY = "REDACTED"',
        Description: "Detected a Generic API Key.",
      }),
    ]);

    // Act
    const [pat, generic] = parseGitleaksOutput(report, ROOT);

    // Assert
    expect(pat).toMatchObject({
      ruleId: "external/gitleaks",
      title: "Embedded secret (github-pat)",
      category: "secrets",
      severity: "medium",
      confidence: "medium",
      source: "external:gitleaks",
      bundle: "",
      location: { file: "skills/evil/scripts/run.py", line: 2, column: 11, snippet: "REDACTED" },
    });
    expect(pat?.message.startsWith("[github-pat] Uncovered a GitHub Personal Access Token")).toBe(true);
    expect(generic).toMatchObject({ severity: "low", location: { line: 3, snippet: 'KEY = "REDACTED"' } });
  });

  test("never copies the secret, even from a report written without --redact", () => {
    // Arrange: a fake value assembled at run time, never a real credential.
    const secret = ["fake", "Value", "0123456789", "abcdef"].join("");
    const report = JSON.stringify([
      leak({ RuleID: "stripe-access-token", Match: `stripe_key = "${secret}"`, Secret: secret, Fingerprint: `x:${secret}` }),
    ]);

    // Act
    const [finding] = parseGitleaksOutput(report, ROOT);

    // Assert
    expect(JSON.stringify(finding)).not.toContain(secret);
    expect(finding?.location.snippet).toStartWith('stripe_key = "fake');
  });

  test("rates private keys high", () => {
    // Arrange / Act
    const [finding] = parseGitleaksOutput(JSON.stringify([leak({ RuleID: "private-key" })]), ROOT);

    // Assert
    expect(finding?.severity).toBe("high");
  });

  test("returns nothing for an empty report and tolerates unknown fields", () => {
    // Arrange / Act / Assert
    expect(parseGitleaksOutput("[]", ROOT)).toEqual([]);
    expect(parseGitleaksOutput(JSON.stringify([leak({ NewField: { nested: true } })]), ROOT)).toHaveLength(1);
  });

  test("throws a clear error on malformed output", () => {
    // Arrange / Act / Assert
    expect(() => parseGitleaksOutput("[{", ROOT)).toThrow(/gitleaks produced malformed JSON/);
    expect(() => parseGitleaksOutput("", ROOT)).toThrow(/gitleaks produced no JSON output/);
    expect(() => parseGitleaksOutput('{"leaks": []}', ROOT)).toThrow(/not an array/);
  });
});

describe("gitleaksArgs", () => {
  test("pins the config, redacts, and ignores in-tree allow comments", () => {
    // Arrange / Act
    const args = gitleaksArgs("/r", "/w/gitleaks.json", "/w/gitleaks.toml", "/w");

    // Assert
    expect(args.slice(0, 2)).toEqual(["dir", "/r"]);
    expect(args).toContain("--redact");
    expect(args).toContain("--ignore-gitleaks-allow");
    expect(args.join(" ")).toContain("--exit-code 0");
    expect(args.join(" ")).toContain("--config /w/gitleaks.toml");
    expect(args.join(" ")).toContain("--gitleaks-ignore-path /w");
    expect(args.join(" ")).toContain("--report-format json --report-path /w/gitleaks.json");
  });
});
