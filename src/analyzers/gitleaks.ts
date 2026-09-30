import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { maskSecret } from "../core/secrets";
import type { Finding, Severity } from "../core/types";
import {
  expectArray,
  expectExit,
  externalFinding,
  isObject,
  parseJson,
  posInt,
  readReport,
  relativeFile,
  str,
  toolAnalyzer,
} from "./common";
import { which } from "./run";
import type { AnalyzerInfo, ToolDriver } from "./types";

/**
 * Gitleaks (MIT), https://github.com/gitleaks/gitleaks. Invoked as (v8.19+, verified with 8.30.1):
 *
 *   gitleaks dir <root> --no-banner --exit-code 0 --redact --report-format json --report-path <tmp>/gitleaks.json
 *     --config <tmp>/gitleaks.toml --gitleaks-ignore-path <tmp> --ignore-gitleaks-allow --log-level error
 *     --max-target-megabytes 10
 *
 * Gitleaks reads configuration from the scanned tree: `<root>/.gitleaks.toml` (it can allowlist every
 * path), `.gitleaksignore` in the cwd, and `gitleaks:allow` comments. The pinned `--config`, a private
 * cwd and ignore path, and `--ignore-gitleaks-allow` take those away from the skill. One remains that
 * no flag disables: `<root>/.gitleaksignore` (cmd/root.go); its entries must match the absolute path
 * gitleaks reports, and the core `packaging/unexpected-dotfile` rule flags the file.
 */

export const GITLEAKS_INFO: AnalyzerInfo = {
  name: "gitleaks",
  title: "Gitleaks",
  binary: "gitleaks",
  install: "brew install gitleaks",
  homepage: "https://github.com/gitleaks/gitleaks",
  license: "MIT",
  network: false,
  description: "Secret scanner with a large, maintained set of credential rules. Runs offline.",
};

/** The built-in rule set, whatever the scanned tree ships. */
const PINNED_CONFIG = 'title = "skill-scanner"\n\n[extend]\nuseDefault = true\n';
const MAX_FILE_MEGABYTES = "10";

export function gitleaksArgs(root: string, report: string, config: string, ignoreDir: string): string[] {
  return [
    "dir",
    root,
    "--no-banner",
    "--exit-code",
    "0",
    "--redact",
    "--report-format",
    "json",
    "--report-path",
    report,
    "--config",
    config,
    "--gitleaks-ignore-path",
    ignoreDir,
    "--ignore-gitleaks-allow",
    "--log-level",
    "error",
    "--max-target-megabytes",
    MAX_FILE_MEGABYTES,
  ];
}

function severityOf(ruleId: string): Severity {
  if (/private-key/i.test(ruleId)) return "high";
  // The catch-all rule matches any high-entropy assignment and is the noisiest.
  if (ruleId === "generic-api-key") return "low";
  return "medium";
}

/** The matched text with the secret masked, in case the report was written without `--redact`. */
function maskedMatch(leak: Readonly<Record<string, unknown>>): string | undefined {
  const match = str(leak.Match);
  const secret = str(leak.Secret);
  if (!match || !secret || secret === "REDACTED") return match;
  return match.split(secret).join(maskSecret(secret));
}

/** Findings from a gitleaks JSON report (an array of leaks). The secret itself is never copied. */
export function parseGitleaksOutput(text: string, root: string): Finding[] {
  const leaks = expectArray(parseJson(text, "gitleaks"), "gitleaks", "the report");
  return leaks.filter(isObject).map((leak) => {
    const ruleId = str(leak.RuleID) ?? "unknown-rule";
    const line = posInt(leak.StartLine);
    return externalFinding("gitleaks", {
      toolRule: ruleId,
      title: `Embedded secret (${ruleId})`,
      category: "secrets",
      severity: severityOf(ruleId),
      message: `${str(leak.Description) ?? "Secret detected"} The value is not reproduced here.`,
      file: relativeFile(root, str(leak.File) ?? "."),
      line,
      column: posInt(leak.StartColumn),
      endLine: posInt(leak.EndLine),
      snippet: maskedMatch(leak),
      remediation: "Remove the credential from the skill and revoke it; a published secret must be treated as compromised.",
    });
  });
}

export const gitleaksDriver: ToolDriver = {
  info: GITLEAKS_INFO,
  locate: (env) => which("gitleaks", env),
  versionArgs: ["version"],
  toolEnv: (env) => ({ ...env, NO_COLOR: "1" }),
  network: () => false,
  create: (env) =>
    toolAnalyzer(gitleaksDriver, env, async ({ root, workDir, exec }) => {
      const report = join(workDir, "gitleaks.json");
      const config = join(workDir, "gitleaks.toml");
      await writeFile(config, PINNED_CONFIG, "utf8");
      expectExit("gitleaks", await exec(gitleaksArgs(root, report, config, workDir)), [0]);
      const text = await readReport(report, "gitleaks");
      if (text === undefined) throw new Error("gitleaks did not write its report");
      return parseGitleaksOutput(text, root);
    }),
};
