import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { osvArgs, parseOsvOutput } from "../../src/analyzers/osv";

const ROOT = "/tmp/scan-root";

/** Trimmed from `osv-scanner scan source -r --format json` (2.6.0) on a requirements.txt pinning old packages. */
const REPORT = {
  results: [
    {
      source: { path: join(ROOT, "skills/evil/requirements.txt"), type: "lockfile" },
      packages: [
        {
          package: { name: "requests", version: "2.19.0", ecosystem: "PyPI" },
          vulnerabilities: [
            { id: "PYSEC-2023-74", aliases: ["CVE-2023-32681", "GHSA-j8r2-6x86-q33q"], summary: null, affected: [] },
            {
              id: "GHSA-j8r2-6x86-q33q",
              summary: "Unintended leak of Proxy-Authorization header in requests",
              details: "### Impact\n\nSince Requests v2.3.0 ...",
              aliases: ["CVE-2023-32681", "PYSEC-2023-74"],
              severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N" }],
              database_specific: { severity: "MODERATE", cwe_ids: ["CWE-200"] },
            },
            { id: "PYSEC-2018-28", aliases: ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg"] },
          ],
          groups: [
            {
              ids: ["PYSEC-2023-74", "GHSA-j8r2-6x86-q33q"],
              aliases: ["CVE-2023-32681", "GHSA-j8r2-6x86-q33q", "PYSEC-2023-74"],
              max_severity: "6.1",
            },
            { ids: ["PYSEC-2018-28"], aliases: ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg", "PYSEC-2018-28"], max_severity: "9.8" },
          ],
        },
      ],
    },
  ],
  experimental_config: { licenses: { summary: false, allowlist: null } },
};

describe("parseOsvOutput", () => {
  test("reports one supply-chain finding per advisory group, rated by CVSS", () => {
    // Arrange / Act
    const findings = parseOsvOutput(JSON.stringify(REPORT), ROOT);

    // Assert
    expect(findings).toHaveLength(2);
    expect(findings[0]).toMatchObject({
      ruleId: "external/osv-scanner",
      title: "Vulnerable dependency requests@2.19.0",
      category: "supply-chain",
      severity: "medium",
      source: "external:osv-scanner",
      bundle: "",
      location: { file: "skills/evil/requirements.txt" },
    });
    expect(findings[0]?.message).toBe(
      "[PYSEC-2023-74] requests@2.19.0 (PyPI) has a known vulnerability: Unintended leak of Proxy-Authorization header in requests. Also known as CVE-2023-32681, GHSA-j8r2-6x86-q33q.",
    );
    expect(findings[1]?.severity).toBe("critical");
    expect(findings[1]?.message).toStartWith("[PYSEC-2018-28] requests@2.19.0 (PyPI) has a known vulnerability.");
  });

  test("falls back to one finding per advisory and the database rating when groups are missing", () => {
    // Arrange
    const report = structuredClone(REPORT);
    const pkg = report.results[0]!.packages[0]! as Record<string, unknown>;
    delete pkg.groups;

    // Act
    const findings = parseOsvOutput(JSON.stringify(report), ROOT);

    // Assert
    expect(findings.map((f) => f.message.slice(0, f.message.indexOf("]") + 1))).toEqual([
      "[PYSEC-2023-74]",
      "[GHSA-j8r2-6x86-q33q]",
      "[PYSEC-2018-28]",
    ]);
    expect(findings[1]?.severity).toBe("medium");
    expect(findings[0]?.severity).toBe("medium");
  });

  test("returns nothing when no packages were found", () => {
    // Arrange / Act / Assert
    expect(parseOsvOutput('{"results": [], "experimental_config": {}}', ROOT)).toEqual([]);
    expect(parseOsvOutput("{}", ROOT)).toEqual([]);
  });

  test("throws a clear error on malformed output", () => {
    // Arrange / Act / Assert
    expect(() => parseOsvOutput("Scanning dir ...", ROOT)).toThrow(/osv-scanner produced malformed JSON/);
    expect(() => parseOsvOutput("[]", ROOT)).toThrow(/not an object/);
    expect(() => parseOsvOutput('{"results": {}}', ROOT)).toThrow(/results is not an array/);
  });
});

describe("osvArgs", () => {
  test("pins an empty config and scans ignored files", () => {
    // Arrange / Act
    const args = osvArgs("/r", "/w/osv-scanner.toml");

    // Assert
    expect(args.slice(0, 2)).toEqual(["scan", "source"]);
    expect(args.at(-1)).toBe("/r");
    expect(args.join(" ")).toContain("--config /w/osv-scanner.toml");
    expect(args).toContain("--no-ignore");
    expect(args).toContain("--recursive");
    expect(args.join(" ")).toContain("--format json");
  });
});
