import { describe, expect, test } from "bun:test";
import { renderRulesDoc } from "../../scripts/gen-rules-doc";
import type { RuleMeta } from "../../src/core/rule";
import { knownRules } from "../../src/report/shared";

const sample: RuleMeta[] = [
  {
    id: "exec/example-run",
    title: "Runs something",
    category: "remote-execution",
    severity: "critical",
    confidence: "high",
    hard: true,
    description: "Runs a thing.",
    remediation: "Do not.",
  },
  { id: "network/example-call", title: "Calls out", category: "network", severity: "low", confidence: "low", description: "Calls a host." },
];

describe("rules doc", () => {
  test("explains verdicts and suppression before listing rules", () => {
    // Arrange / Act
    const doc = renderRulesDoc(sample);

    // Assert
    expect(doc.startsWith("# Rules\n")).toBe(true);
    expect(doc).toContain("## How findings become a verdict");
    expect(doc).toContain("## Suppressing a finding");
    expect(doc).toContain("skill-scanner trust <path>");
    expect(doc.indexOf("## Suppressing a finding")).toBeLessThan(doc.indexOf("### exec/example-run"));
  });

  test("gives each rule an anchor matching the SARIF help link, and its facts", () => {
    const doc = renderRulesDoc(sample);

    expect(doc).toContain('<a name="exec-example-run"></a>\n\n### exec/example-run\n\n**Runs something**');
    expect(doc).toContain("Severity: critical. Confidence: high. Hard: the jev judge can confirm but never doubt it.");
    expect(doc).toContain("Remediation: Do not.");
    expect(doc).toContain("Severity: low. Confidence: low.\n\nCalls a host.");
  });

  test("groups rules by category in catalog category order, with a table of contents", () => {
    const doc = renderRulesDoc(sample);

    expect(doc).toContain("- [remote-execution](#remote-execution) (1)\n- [network](#network) (1)");
    expect(doc.indexOf("## remote-execution")).toBeLessThan(doc.indexOf("## network"));
  });

  test("covers every known rule, including engine and judge rules", () => {
    const rules = knownRules();

    const doc = renderRulesDoc(rules);

    for (const r of rules) expect(doc).toContain(`### ${r.id}\n`);
    expect(doc).toContain("### obfuscation/encoded-payload\n");
  });

  test("is deterministic", () => {
    expect(renderRulesDoc(knownRules())).toBe(renderRulesDoc(knownRules()));
  });
});
