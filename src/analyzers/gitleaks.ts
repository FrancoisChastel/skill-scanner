import { readdir, writeFile } from "node:fs/promises";
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
import { stageTree } from "./stage";
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
 * cwd and ignore path, and `--ignore-gitleaks-allow` take those away from the skill. No flag stops it
 * reading `<root>/.gitleaksignore` (cmd/root.go, v8.30.1), so when the tree has one, gitleaks scans a
 * copy of the tree without it (hard links, in the private work directory). The core
 * `packaging/unexpected-dotfile` rule still reports the file.
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
const IGNORE_FILE = ".gitleaksignore";
const MAX_STAGED_ENTRIES = 100_000;

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
      const target = (await hasRootIgnoreFile(root)) ? await stageWithoutIgnoreFile(root, join(workDir, "tree")) : root;
      expectExit("gitleaks", await exec(gitleaksArgs(target, report, config, workDir)), [0]);
      const text = await readReport(report, "gitleaks");
      if (text === undefined) throw new Error("gitleaks did not write its report");
      return parseGitleaksOutput(text, target);
    }),
};

/** Case-insensitively, since gitleaks' check matches any case on macOS and Windows file systems. */
async function hasRootIgnoreFile(root: string): Promise<boolean> {
  const names = await readdir(root).catch(() => [] as string[]);
  return names.some((name) => name.toLowerCase() === IGNORE_FILE);
}

/** The tree without its root `.gitleaksignore`, so the scanned skill cannot silence gitleaks. */
export async function stageWithoutIgnoreFile(root: string, dest: string): Promise<string> {
  await stageTree(root, dest, {
    skip: (rel) => rel.toLowerCase() === IGNORE_FILE,
    maxFileBytes: Number(MAX_FILE_MEGABYTES) * 1024 * 1024,
    maxEntries: MAX_STAGED_ENTRIES,
  });
  return dest;
}
