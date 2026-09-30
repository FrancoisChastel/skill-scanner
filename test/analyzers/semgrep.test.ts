import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import {
  DEFAULT_SEMGREP_CONFIG,
  engineOf,
  isRegistryConfig,
  parseSemgrepOutput,
  resolveSemgrepConfig,
  semgrepArgs,
  semgrepDriver,
} from "../../src/analyzers/semgrep";
import { DEFAULT_CONFIG } from "../../src/config";

const ROOT = "/tmp/scan-root";

/** A p/default registry result as logged-out semgrep 1.178.0 prints it (matched lines withheld). */
const REGISTRY_RESULT = {
  check_id: "python.lang.security.audit.exec-detected.exec-detected",
  path: join(ROOT, "skills/evil/scripts/run.py"),
  start: { line: 4, col: 1, offset: 192 },
  end: { line: 4, col: 39, offset: 230 },
  extra: {
    message:
      "Detected the use of exec(). exec() can be dangerous if used to evaluate dynamic content. If this content can be input from outside the program, this may be a code injection vulnerability. Ensure evaluated content is not definable by external sources.",
    metadata: {
      cwe: ["CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')"],
      owasp: ["A03:2021 - Injection"],
      category: "security",
      subcategory: ["audit"],
      likelihood: "LOW",
      impact: "HIGH",
      confidence: "LOW",
      license: "Semgrep Rules License v1.0. For more details, visit semgrep.dev/legal/rules-license",
      vulnerability_class: ["Code Injection"],
    },
    severity: "WARNING",
    fingerprint: "requires login",
    lines: "requires login",
    validation_state: "NO_VALIDATOR",
    engine_kind: "OSS",
  },
};

/** A local rule as opengrep 1.30.0 prints it with --no-rewrite-rule-ids (matched lines included). */
function localResult(lines: string, severity = "ERROR"): Record<string, unknown> {
  return {
    check_id: "python-exec-b64",
    path: join(ROOT, "skills/evil/scripts/hidden.py"),
    start: { line: 7, col: 5, offset: 90 },
    end: { line: 8, col: 2, offset: 140 },
    extra: { metavars: {}, message: "exec of decoded data", metadata: {}, severity, fingerprint: "0", lines, is_ignored: false },
  };
}

describe("parseSemgrepOutput", () => {
  test("maps a registry result, keeping the full rule id in the message", () => {
    // Arrange
    const report = { version: "1.178.0", results: [REGISTRY_RESULT], errors: [], paths: { scanned: [] } };

    // Act
    const [finding] = parseSemgrepOutput(JSON.stringify(report), ROOT);

    // Assert
    expect(finding).toMatchObject({
      ruleId: "external/semgrep",
      title: "Semgrep: exec-detected",
      category: "remote-execution",
      severity: "medium",
      confidence: "medium",
      source: "external:semgrep",
      bundle: "",
      location: { file: "skills/evil/scripts/run.py", line: 4, column: 1 },
    });
    expect(finding?.message).toStartWith("[python.lang.security.audit.exec-detected.exec-detected] Detected the use of exec().");
    // The logged-out placeholder is not a snippet.
    expect(finding?.location.snippet).toBeUndefined();
  });

  test("keeps the first matched line as a redacted snippet", () => {
    // Arrange: a token-shaped value assembled at run time.
    const token = `ghp_${"aB3dE5fG7h".repeat(3)}xYz9Q8`;
    const report = { results: [localResult(`exec(base64.b64decode(k))  # ${token}\nmore()`)] };

    // Act
    const [finding] = parseSemgrepOutput(JSON.stringify(report), ROOT);

    // Assert
    expect(finding?.location).toMatchObject({ file: "skills/evil/scripts/hidden.py", line: 7, column: 5, endLine: 8 });
    expect(finding?.location.snippet).toStartWith("exec(base64.b64decode(k))  # ghp_");
    expect(JSON.stringify(finding)).not.toContain(token);
  });

  test("maps the legacy and the new severity scales", () => {
    // Arrange
    const report = { results: ["ERROR", "WARNING", "INFO", "CRITICAL", "LOW", "INVENTORY", "???"].map((s) => localResult("x", s)) };

    // Act
    const severities = parseSemgrepOutput(JSON.stringify(report), ROOT).map((f) => f.severity);

    // Assert
    expect(severities).toEqual(["high", "medium", "low", "critical", "low", "info", "medium"]);
  });

  test("tolerates a report with engine errors but no results", () => {
    // Arrange / Act / Assert
    expect(parseSemgrepOutput('{"results": [], "errors": [{"message": "Syntax error"}]}', ROOT)).toEqual([]);
  });

  test("throws a clear error on malformed output", () => {
    // Arrange / Act / Assert
    expect(() => parseSemgrepOutput("<html>", ROOT)).toThrow(/semgrep produced malformed JSON/);
    expect(() => parseSemgrepOutput('{"results": 3}', ROOT)).toThrow(/results is not an array/);
  });
});

describe("semgrep invocation", () => {
  test("passes --metrics=off to semgrep only; opengrep rejects it", () => {
    // Arrange / Act
    const sg = semgrepArgs("semgrep", "p/default", "/r", true);
    const og = semgrepArgs("opengrep", "p/default", "/r", true);

    // Assert
    expect(sg).toContain("--metrics=off");
    expect(og).not.toContain("--metrics=off");
    for (const args of [sg, og]) {
      expect(args[0]).toBe("scan");
      expect(args.at(-1)).toBe("/r");
      expect(args).toContain("--disable-nosem");
      expect(args).toContain("--no-git-ignore");
      expect(args).toContain("--x-ignore-semgrepignore-files");
    }
    expect(semgrepArgs("semgrep", "p/default", "/r", false)).not.toContain("--x-ignore-semgrepignore-files");
  });

  test("tells the engine apart by binary name", () => {
    // Arrange / Act / Assert
    expect(engineOf("/usr/local/bin/opengrep")).toBe("opengrep");
    expect(engineOf("C:\\tools\\opengrep.exe")).toBe("opengrep");
    expect(engineOf("/usr/local/bin/semgrep")).toBe("semgrep");
  });

  test("treats registry shorthands and URLs as network, local paths as offline", () => {
    // Arrange / Act / Assert
    expect(isRegistryConfig("p/default")).toBe(true);
    expect(isRegistryConfig("r/python.lang.security.audit.exec-detected")).toBe(true);
    expect(isRegistryConfig("auto")).toBe(true);
    expect(isRegistryConfig("https://example.com/rules.yml")).toBe(true);
    expect(isRegistryConfig("./rules/skills.yml")).toBe(false);
    expect(isRegistryConfig("/etc/semgrep")).toBe(false);
    expect(semgrepDriver.network(DEFAULT_CONFIG)).toBe(true);
    expect(semgrepDriver.network({ ...DEFAULT_CONFIG, semgrepConfig: "/home/me/rules.yml" })).toBe(false);
  });

  test("resolves the config: default registry ruleset, home-relative and cwd-relative paths", () => {
    // Arrange
    const env = { HOME: "/home/me" };

    // Act / Assert
    expect(resolveSemgrepConfig({}, env)).toBe(DEFAULT_SEMGREP_CONFIG);
    expect(resolveSemgrepConfig({ semgrepConfig: "p/python" }, env)).toBe("p/python");
    expect(resolveSemgrepConfig({ semgrepConfig: "~/rules.yml" }, env)).toBe(join("/home/me", "rules.yml"));
    expect(resolveSemgrepConfig({ semgrepConfig: "rules.yml" }, env)).toBe(join(process.cwd(), "rules.yml"));
  });
});
