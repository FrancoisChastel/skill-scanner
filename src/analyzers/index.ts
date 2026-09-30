/**
 * Optional external open-source analyzers. None is required: each is used only when installed and
 * asked for, runs as a separate process without a shell, and reports through the scanner's findings.
 */
import { ANALYZER_NAMES, type AnalyzerName, type Config } from "../config";
import type { RuleMeta } from "../core/rule";
import type { Category } from "../core/types";
import type { ExternalAnalyzer } from "../scan";
import { ciscoDriver } from "./cisco";
import { versionFrom } from "./common";
import { gitleaksDriver } from "./gitleaks";
import { osvDriver } from "./osv";
import { runTool } from "./run";
import { semgrepDriver } from "./semgrep";
import { skillspectorDriver } from "./skillspector";
import type { AnalyzerInfo, ToolDriver } from "./types";

export type { AnalyzerInfo } from "./types";

const VERSION_PROBE_MS = 5_000;
const VERSION_PROBE_BYTES = 64 * 1024;

const DRIVERS: Readonly<Record<AnalyzerName, ToolDriver>> = {
  skillspector: skillspectorDriver,
  cisco: ciscoDriver,
  gitleaks: gitleaksDriver,
  "osv-scanner": osvDriver,
  semgrep: semgrepDriver,
};

export const ANALYZERS: readonly AnalyzerInfo[] = ANALYZER_NAMES.map((n) => DRIVERS[n].info);

const RULE_CATEGORY: Readonly<Partial<Record<AnalyzerName, Category>>> = { gitleaks: "secrets", "osv-scanner": "supply-chain" };

/** One rule per external tool, so findings from `external/<tool>` can be documented, reported in SARIF, and suppressed. */
export const ANALYZER_RULES: readonly RuleMeta[] = ANALYZERS.map((info) => ({
  id: `external/${info.name}`,
  title: `${info.title} finding`,
  category: RULE_CATEGORY[info.name] ?? "packaging",
  severity: "medium",
  confidence: "medium",
  description: `Finding reported by ${info.title}; see its message for the tool's own rule.`,
}));

async function autoNames(cfg: Config, env: NodeJS.ProcessEnv): Promise<AnalyzerName[]> {
  const offline = ANALYZER_NAMES.filter((n) => !DRIVERS[n].network(cfg));
  const installed = await Promise.all(offline.map(async (n) => ((await DRIVERS[n].locate(env)) ? n : undefined)));
  return installed.filter((n): n is AnalyzerName => n !== undefined);
}

/** Analyzers for the given names. `auto` expands to every installed analyzer that needs no network. */
export async function createAnalyzers(
  names: readonly (AnalyzerName | "auto")[],
  cfg: Config,
  env: NodeJS.ProcessEnv,
): Promise<ExternalAnalyzer[]> {
  const auto = names.includes("auto") ? await autoNames(cfg, env) : [];
  const expanded = names.flatMap((n) => (n === "auto" ? auto : [n]));
  const unique = expanded.filter((n, i) => expanded.indexOf(n) === i);
  return unique.map((n) => DRIVERS[n].create(env, cfg));
}

async function probeVersion(driver: ToolDriver, path: string, env: NodeJS.ProcessEnv): Promise<string | undefined> {
  try {
    const r = await runTool(path, driver.versionArgs, {
      env: driver.toolEnv(env),
      timeoutMs: VERSION_PROBE_MS,
      maxOutputBytes: VERSION_PROBE_BYTES,
    });
    return r.timedOut ? undefined : versionFrom(`${r.stdout}\n${r.stderr}`);
  } catch {
    return undefined;
  }
}

/** Which analyzers are installed here, for `doctor`. */
export async function detectAnalyzers(env: NodeJS.ProcessEnv): Promise<{ info: AnalyzerInfo; path?: string; version?: string }[]> {
  return Promise.all(
    ANALYZER_NAMES.map(async (n) => {
      const driver = DRIVERS[n];
      const path = await driver.locate(env);
      if (!path) return { info: driver.info };
      const version = await probeVersion(driver, path, env);
      return { info: driver.info, path, ...(version ? { version } : {}) };
    }),
  );
}
