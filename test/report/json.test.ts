import { describe, expect, test } from "bun:test";
import { formatJson, toJsonReport } from "../../src/report/json";
import { FAKE_TOKEN, FILE_BODY_MARKER, makeReport } from "./fixture";

describe("JSON report", () => {
  test("has a stable schema version and the report summary", () => {
    // Arrange
    const report = makeReport();

    // Act
    const json = toJsonReport(report);

    // Assert
    expect(json.schemaVersion).toBe(1);
    expect(json.tool).toEqual({ name: "skill-scanner", version: "0.1.0" });
    expect(json.target).toBe("./repo");
    expect(json.verdict).toBe("block");
    expect(json.counts).toEqual({ info: 1, low: 0, medium: 2, high: 1, critical: 1 });
    expect(json.suppressed).toBe(2);
    expect(json.analyzers).toHaveLength(3);
  });

  test("describes bundles by name, kind, root, digest, verdict, file count, notes, and findings only", () => {
    const json = toJsonReport(makeReport());

    const helper = json.bundles[0]!;
    expect(Object.keys(helper).sort()).toEqual(["digest", "fileCount", "findings", "kind", "name", "notes", "root", "verdict"]);
    expect(helper).toMatchObject({ name: "helper", kind: "skill", root: "skills/helper", verdict: "block", fileCount: 2 });
    expect(helper.findings).toHaveLength(4);
  });

  test("never contains file contents or frontmatter", () => {
    const out = formatJson(makeReport());

    expect(out.includes(FILE_BODY_MARKER)).toBe(false);
    expect(out).not.toContain('"files"');
    expect(out).not.toContain('"frontmatter"');
  });

  test("never contains a secret", () => {
    const out = formatJson(makeReport());

    expect(out.includes(FAKE_TOKEN)).toBe(false);
  });

  test("keeps judge notes and findings without a line", () => {
    const json = toJsonReport(makeReport());

    const [critical, binary] = json.bundles[0]!.findings;
    expect(critical?.judge).toEqual({ model: "jev-test", pTrue: 0.97, effect: "confirmed" });
    expect(binary?.location).toEqual({ file: "skills/helper/bin/tool" });
  });

  test("is pretty printed with a trailing newline and parses back", () => {
    const out = formatJson(makeReport());

    expect(out.endsWith("}\n")).toBe(true);
    expect(out).toContain('\n  "schemaVersion": 1,');
    expect(JSON.parse(out).bundles).toHaveLength(3);
  });

  test("renders several reports as an array", () => {
    const out = formatJson([makeReport(), makeReport({ target: "other" })]);

    const parsed = JSON.parse(out) as { target: string }[];
    expect(parsed.map((r) => r.target)).toEqual(["./repo", "other"]);
  });
});
