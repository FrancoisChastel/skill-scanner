import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Finding, Severity } from "../core/types";
import {
  expectArray,
  expectExit,
  expectObject,
  externalFinding,
  isObject,
  type JsonObject,
  parseJson,
  relativeFile,
  severityFrom,
  str,
  toolAnalyzer,
} from "./common";
import { which } from "./run";
import type { AnalyzerInfo, ToolDriver } from "./types";

/**
 * OSV-Scanner v2 (Apache-2.0), https://github.com/google/osv-scanner. Invoked as (verified with 2.6.0):
 *
 *   osv-scanner scan source --recursive --format json --no-resolve --allow-no-lockfiles --no-ignore
 *     --verbosity error --config <tmp>/osv-scanner.toml <root>
 *
 * It sends package coordinates (not file contents) to api.osv.dev, so it is marked network. Exit codes:
 * 0 clean, 1 vulnerabilities found, 128 no packages found, anything else is an error. The empty pinned
 * `--config` replaces the per-directory `osv-scanner.toml` files a skill could ship to ignore its own
 * advisories, and `--no-ignore` scans manifests that a shipped `.gitignore` would hide.
 */

export const OSV_INFO: AnalyzerInfo = {
  name: "osv-scanner",
  title: "OSV-Scanner",
  binary: "osv-scanner",
  install: "brew install osv-scanner",
  homepage: "https://github.com/google/osv-scanner",
  license: "Apache-2.0",
  network: true,
  description: "Known vulnerabilities in declared dependencies (requirements.txt, package-lock.json, ...), from the OSV database.",
};

const EXIT_OK = 0;
const EXIT_VULNS = 1;
const EXIT_NO_PACKAGES = 128;

export function osvArgs(root: string, config: string): string[] {
  return [
    "scan",
    "source",
    "--recursive",
    "--format",
    "json",
    "--no-resolve",
    "--allow-no-lockfiles",
    "--no-ignore",
    "--verbosity",
    "error",
    "--config",
    config,
    root,
  ];
}

/** CVSS base score to severity, using the CVSS v3 qualitative bands. */
function severityFromScore(score: number): Severity {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return score > 0 ? "low" : "info";
}

interface Group {
  readonly ids: readonly string[];
  readonly aliases: readonly string[];
  readonly maxSeverity?: string;
}

const sentence = (text: string): string => (/[.!?]$/.test(text.trim()) ? text.trim() : `${text.trim()}.`);

const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && x !== "") : []);

/** Advisory groups of one package; OSV-Scanner groups aliases of the same issue. Falls back to one group per advisory. */
function groupsOf(pkg: JsonObject, vulns: readonly JsonObject[]): Group[] {
  const groups = Array.isArray(pkg.groups) ? pkg.groups.filter(isObject) : [];
  if (groups.length > 0) {
    return groups.map((g) => ({
      ids: strings(g.ids),
      aliases: strings(g.aliases),
      ...(str(g.max_severity) ? { maxSeverity: str(g.max_severity)! } : {}),
    }));
  }
  return vulns.map((v) => ({ ids: strings([v.id]), aliases: strings(v.aliases) }));
}

function severityOf(group: Group, vulns: readonly JsonObject[]): Severity {
  const score = group.maxSeverity === undefined ? Number.NaN : Number.parseFloat(group.maxSeverity);
  if (Number.isFinite(score)) return severityFromScore(score);
  // No CVSS score: use the advisory database's own rating (GHSA uses LOW/MODERATE/HIGH/CRITICAL).
  const rated = vulns.find((v) => isObject(v.database_specific) && str(v.database_specific.severity));
  return rated && isObject(rated.database_specific) ? severityFrom(rated.database_specific.severity) : "medium";
}

function packageFindings(file: string, pkg: JsonObject): Finding[] {
  const info = isObject(pkg.package) ? pkg.package : {};
  const name = str(info.name) ?? "unknown package";
  const version = str(info.version);
  const ecosystem = str(info.ecosystem);
  const vulns = Array.isArray(pkg.vulnerabilities) ? pkg.vulnerabilities.filter(isObject) : [];
  const label = `${name}${version ? `@${version}` : ""}`;
  return groupsOf(pkg, vulns)
    .filter((g) => g.ids.length > 0)
    .map((g) => {
      const members = vulns.filter((v) => g.ids.includes(str(v.id) ?? ""));
      const summary = members.map((v) => str(v.summary)).find((s) => s !== undefined);
      const aliases = [...new Set([...g.aliases, ...g.ids])].filter((a) => a !== g.ids[0]);
      return externalFinding("osv-scanner", {
        toolRule: g.ids[0]!,
        title: `Vulnerable dependency ${label}`,
        category: "supply-chain",
        severity: severityOf(g, members),
        message: [
          `${label}${ecosystem ? ` (${ecosystem})` : ""} has a known vulnerability${summary ? `: ${sentence(summary)}` : "."}`,
          aliases.length > 0 ? `Also known as ${aliases.join(", ")}.` : "",
        ].join(" "),
        file,
        remediation: `Upgrade ${name} to a version that fixes ${g.ids[0]}.`,
      });
    });
}

/** Findings from `osv-scanner --format json`: one per advisory group per package. */
export function parseOsvOutput(text: string, root: string): Finding[] {
  const report = expectObject(parseJson(text, "osv-scanner"), "osv-scanner", "the report");
  const results = expectArray(report.results ?? [], "osv-scanner", "results");
  return results.filter(isObject).flatMap((r) => {
    const source = isObject(r.source) ? r.source : {};
    const file = relativeFile(root, str(source.path) ?? ".");
    const packages = Array.isArray(r.packages) ? r.packages.filter(isObject) : [];
    return packages.flatMap((p) => packageFindings(file, p));
  });
}

export const osvDriver: ToolDriver = {
  info: OSV_INFO,
  locate: (env) => which("osv-scanner", env),
  versionArgs: ["--version"],
  toolEnv: (env) => ({ ...env, NO_COLOR: "1" }),
  network: () => true,
  create: (env) =>
    toolAnalyzer(osvDriver, env, async ({ root, workDir, exec }) => {
      const config = join(workDir, "osv-scanner.toml");
      await writeFile(config, "", "utf8");
      const result = await exec(osvArgs(root, config));
      if (result.code === EXIT_NO_PACKAGES) return [];
      expectExit("osv-scanner", result, [EXIT_OK, EXIT_VULNS]);
      return parseOsvOutput(result.stdout, root);
    }),
};
