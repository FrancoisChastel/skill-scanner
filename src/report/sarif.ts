import { createHash } from "node:crypto";
import type { RuleMeta } from "../core/rule";
import type { Confidence, Finding, JudgeNote, ScanReport, Severity } from "../core/types";
import { clean, knownRules, rulesFor } from "./shared";
import type { SarifOptions } from "./types";

/** SARIF 2.1.0 for GitHub code scanning and other SARIF viewers. One run per scan target. */

export const SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";
export const INFORMATION_URI = "https://github.com/FrancoisChastel/skill-scanner";
const RULES_DOC = `${INFORMATION_URI}/blob/main/docs/rules.md`;

export type SarifLevel = "error" | "warning" | "note";

export interface SarifRule {
  readonly id: string;
  readonly name: string;
  readonly shortDescription: { readonly text: string };
  readonly fullDescription: { readonly text: string };
  readonly help: { readonly text: string };
  readonly helpUri: string;
  readonly defaultConfiguration: { readonly level: SarifLevel };
  readonly properties: {
    readonly tags: readonly string[];
    readonly "security-severity": string;
    readonly precision: Confidence;
  };
}

export interface SarifRegion {
  readonly startLine: number;
  readonly startColumn?: number;
  readonly snippet?: { readonly text: string };
}

export interface SarifResult {
  readonly ruleId: string;
  readonly ruleIndex: number;
  readonly level: SarifLevel;
  readonly message: { readonly text: string };
  readonly locations: readonly {
    readonly physicalLocation: {
      readonly artifactLocation: { readonly uri: string; readonly uriBaseId: "%SRCROOT%" };
      readonly region?: SarifRegion;
    };
  }[];
  readonly partialFingerprints: { readonly "skillScanner/v1": string };
  readonly properties: {
    readonly severity: Severity;
    readonly confidence: Confidence;
    readonly bundle: string;
    readonly source: Finding["source"];
    /** The virtual path, e.g. `package.json#scripts.postinstall`, when the uri names its parent file. */
    readonly path?: string;
    readonly judge?: JudgeNote;
  };
}

export interface SarifRun {
  readonly tool: {
    readonly driver: {
      readonly name: string;
      readonly version: string;
      readonly semanticVersion: string;
      readonly informationUri: string;
      readonly rules: readonly SarifRule[];
    };
  };
  readonly automationDetails: { readonly id: string };
  readonly invocations: readonly { readonly executionSuccessful: boolean }[];
  readonly columnKind: "utf16CodeUnits";
  readonly results: readonly SarifResult[];
  readonly properties: { readonly target: string; readonly verdict: ScanReport["verdict"]; readonly suppressed: number };
}

export interface SarifLog {
  readonly $schema: string;
  readonly version: "2.1.0";
  readonly runs: readonly SarifRun[];
}

export function sarifLevel(s: Severity): SarifLevel {
  if (s === "critical" || s === "high") return "error";
  return s === "medium" ? "warning" : "note";
}

/** GitHub ranks alerts by this CVSS-like score. */
export const SECURITY_SEVERITY: Readonly<Record<Severity, string>> = {
  critical: "9.5",
  high: "7.5",
  medium: "5.0",
  low: "3.0",
  info: "1.0",
};

/** `exec/download-and-run` -> `DownloadAndRun`. */
export function ruleName(id: string): string {
  const slug = id.slice(id.indexOf("/") + 1);
  return slug
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((w) => w[0]!.toUpperCase() + w.slice(1))
    .join("");
}

/** The docs anchor of a rule: its id with `/` replaced by `-`. */
export const ruleAnchor = (id: string): string => id.replaceAll("/", "-");

function toSarifRule(r: RuleMeta): SarifRule {
  const help = r.remediation ? `${r.description}\n\nRemediation: ${r.remediation}` : r.description;
  return {
    id: r.id,
    name: ruleName(r.id),
    shortDescription: { text: r.title },
    fullDescription: { text: r.description },
    help: { text: help },
    helpUri: `${RULES_DOC}#${ruleAnchor(r.id)}`,
    defaultConfiguration: { level: sarifLevel(r.severity) },
    properties: { tags: ["security", r.category], "security-severity": SECURITY_SEVERITY[r.severity], precision: r.confidence },
  };
}

/** A POSIX, percent-encoded path under `%SRCROOT%`. Virtual files point at the file they came from. */
export function toUri(file: string, prefix?: string): string {
  const real = file.replaceAll("\\", "/").split("#")[0]!;
  const joined = prefix ? `${prefix.replace(/\/+$/, "")}/${real}` : real;
  const parts = joined.split("/").filter((p) => p !== "" && p !== ".");
  return parts.length === 0 ? "." : parts.map(encodeURIComponent).join("/");
}

export function fingerprint(f: Finding): string {
  return createHash("sha256")
    .update(`${f.ruleId}|${f.location.file}|${f.location.snippet ?? ""}`)
    .digest("hex");
}

function toResult(f: Finding, ruleIndex: number, prefix: string | undefined): SarifResult {
  const loc = f.location;
  const region: SarifRegion | undefined = loc.line
    ? {
        startLine: loc.line,
        ...(loc.column ? { startColumn: loc.column } : {}),
        ...(loc.snippet ? { snippet: { text: clean(loc.snippet) } } : {}),
      }
    : undefined;
  return {
    ruleId: f.ruleId,
    ruleIndex,
    level: sarifLevel(f.severity),
    message: { text: clean(f.message) },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: toUri(loc.file, prefix), uriBaseId: "%SRCROOT%" },
          ...(region ? { region } : {}),
        },
      },
    ],
    partialFingerprints: { "skillScanner/v1": fingerprint(f) },
    properties: {
      severity: f.severity,
      confidence: f.confidence,
      bundle: clean(f.bundle),
      source: f.source,
      ...(loc.file.includes("#") ? { path: clean(loc.file) } : {}),
      ...(f.judge ? { judge: { ...f.judge, model: clean(f.judge.model) } } : {}),
    },
  };
}

function toRun(report: ScanReport, catalog: readonly RuleMeta[], opts: SarifOptions): SarifRun {
  const findings = report.bundles.flatMap((b) => b.findings);
  const rules = rulesFor(findings, catalog);
  const index = new Map(rules.map((r, i) => [r.id, i]));
  const prefix = opts.uriPrefix?.(report);
  return {
    tool: {
      driver: {
        name: report.tool.name,
        version: report.tool.version,
        semanticVersion: report.tool.version,
        informationUri: INFORMATION_URI,
        rules: rules.map(toSarifRule),
      },
    },
    // A trailing slash makes the whole id the category, so runs for different targets stay distinct.
    automationDetails: { id: `${report.target.replace(/\/+$/, "") || "root"}/` },
    invocations: [{ executionSuccessful: true }],
    columnKind: "utf16CodeUnits",
    results: findings.map((f) => toResult(f, index.get(f.ruleId)!, prefix)),
    properties: { target: report.target, verdict: report.verdict, suppressed: report.suppressed },
  };
}

export function toSarifLog(reports: readonly ScanReport[], opts: SarifOptions = {}): SarifLog {
  const catalog = knownRules();
  return { $schema: SARIF_SCHEMA, version: "2.1.0", runs: reports.map((r) => toRun(r, catalog, opts)) };
}

export function formatSarif(reports: readonly ScanReport[], opts: SarifOptions = {}): string {
  return `${JSON.stringify(toSarifLog(reports, opts), null, 2)}\n`;
}
