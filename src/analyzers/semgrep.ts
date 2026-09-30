import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import type { Config } from "../config";
import type { Finding, Severity } from "../core/types";
import {
  categoryFrom,
  cleanText,
  expectArray,
  expectExit,
  expectObject,
  externalFinding,
  isObject,
  type JsonObject,
  parseJson,
  posInt,
  relativeFile,
  severityFrom,
  str,
  toolAnalyzer,
} from "./common";
import { type ToolResult, which } from "./run";
import type { AnalyzerInfo, ToolDriver } from "./types";

/**
 * Semgrep CE (engine LGPL-2.1), https://github.com/semgrep/semgrep, or its fork Opengrep (LGPL-2.1),
 * https://github.com/opengrep/opengrep, which takes the same CLI minus `--metrics`. Invoked as
 * (verified with semgrep 1.178.0 and opengrep 1.30.0):
 *
 *   semgrep scan --json --metrics=off --disable-version-check --disable-nosem --no-git-ignore
 *     --no-rewrite-rule-ids --x-ignore-semgrepignore-files --quiet --timeout 30 --max-target-bytes 5000000
 *     --config <cfg> <root>
 *
 * The config is `semgrepConfig` from the user's configuration, else the `p/default` registry ruleset,
 * fetched from semgrep.dev at scan time (network). Registry rules carry their own license (the Semgrep
 * Rules License); they are invoked, never vendored.
 *
 * A scanned skill could hide code from the engine: `nosem` comments, `.gitignore`, `.semgrepignore`,
 * and the built-in default ignores (which skip `tests/` and `node_modules/`). `--disable-nosem`,
 * `--no-git-ignore`, and `--x-ignore-semgrepignore-files` close those. The last is an experimental
 * flag, so an engine that rejects it is run again without it.
 */

export const DEFAULT_SEMGREP_CONFIG = "p/default";
const IGNORE_FILES_FLAG = "--x-ignore-semgrepignore-files";
const RULE_TIMEOUT_SECONDS = "30";
const MAX_TARGET_BYTES = "5000000";
/** 0 clean, 1 findings (only with --error). Anything else is a failure (2 fatal, 7 bad config, ...). */
const OK_CODES = [0, 1];
const MAX_ERROR = 300;

export const SEMGREP_INFO: AnalyzerInfo = {
  name: "semgrep",
  title: "Semgrep",
  binary: "semgrep",
  install: "uv tool install semgrep",
  homepage: "https://github.com/semgrep/semgrep",
  license: "LGPL-2.1 (engine); registry rules under the Semgrep Rules License",
  network: true,
  description:
    "Static analysis of bundled scripts. Uses `semgrepConfig` when set (local rules run offline), else the p/default registry ruleset. Opengrep is used when semgrep is absent.",
};

export type Engine = "semgrep" | "opengrep";

/** Registry shorthands and URLs are fetched at scan time; anything else is a local file or directory. */
export function isRegistryConfig(config: string): boolean {
  return /^(?:auto$|[prs]\/|https?:\/\/)/i.test(config.trim());
}

/** Resolve a local config path against the user's cwd and home, since the tool runs elsewhere. */
export function resolveSemgrepConfig(cfg: Pick<Config, "semgrepConfig">, env: NodeJS.ProcessEnv): string {
  const config = cfg.semgrepConfig?.trim() || DEFAULT_SEMGREP_CONFIG;
  if (isRegistryConfig(config) || isAbsolute(config)) return config;
  if (config === "~" || config.startsWith("~/")) return join(env.HOME || homedir(), config.slice(1));
  return resolve(config);
}

export function engineOf(bin: string): Engine {
  const name = bin.split(/[\\/]/).pop() ?? bin;
  return name.toLowerCase().startsWith("opengrep") ? "opengrep" : "semgrep";
}

export function semgrepArgs(engine: Engine, config: string, root: string, ignoreFiles: boolean): string[] {
  return [
    "scan",
    "--json",
    // Opengrep removed metrics altogether and rejects the flag.
    ...(engine === "semgrep" ? ["--metrics=off"] : []),
    "--disable-version-check",
    "--disable-nosem",
    "--no-git-ignore",
    "--no-rewrite-rule-ids",
    ...(ignoreFiles ? [IGNORE_FILES_FLAG] : []),
    "--quiet",
    "--timeout",
    RULE_TIMEOUT_SECONDS,
    "--max-target-bytes",
    MAX_TARGET_BYTES,
    "--config",
    config,
    root,
  ];
}

function severityOf(value: unknown): Severity {
  // Semgrep's legacy scale is ERROR / WARNING / INFO; INFO rules are advisory, not informational noise.
  if (typeof value === "string" && value.toUpperCase() === "INFO") return "low";
  if (typeof value === "string" && /^(?:INVENTORY|EXPERIMENTAL)$/i.test(value)) return "info";
  return severityFrom(value);
}

const texts = (v: unknown): string[] =>
  typeof v === "string" ? [v] : Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];

function resultFinding(r: JsonObject, root: string): Finding {
  const checkId = str(r.check_id) ?? "unknown-rule";
  const extra = isObject(r.extra) ? r.extra : {};
  const meta = isObject(extra.metadata) ? extra.metadata : {};
  const start = isObject(r.start) ? r.start : {};
  const end = isObject(r.end) ? r.end : {};
  const lines = str(extra.lines);
  const shortId = checkId.split(".").pop() || checkId;
  return externalFinding("semgrep", {
    toolRule: checkId,
    title: `Semgrep: ${shortId}`,
    category: categoryFrom([
      ...texts(meta.vulnerability_class),
      ...texts(meta.subcategory),
      ...texts(meta.cwe),
      checkId,
      str(extra.message),
    ]),
    severity: severityOf(extra.severity),
    message: str(extra.message) ?? "Semgrep rule matched.",
    file: relativeFile(root, str(r.path) ?? "."),
    line: posInt(start.line),
    column: posInt(start.col),
    endLine: posInt(end.line),
    // Logged-out Semgrep replaces the matched source with this placeholder.
    snippet: lines === "requires login" ? undefined : lines,
    remediation: str(extra.fix) ? `Suggested fix: ${str(extra.fix)}` : undefined,
  });
}

/** Findings from `semgrep --json` (or opengrep). Throws on malformed output; engine errors are handled by the exit check. */
export function parseSemgrepOutput(text: string, root: string): Finding[] {
  const report = expectObject(parseJson(text, "semgrep"), "semgrep", "the report");
  return expectArray(report.results ?? [], "semgrep", "results")
    .filter(isObject)
    .map((r) => resultFinding(r, root));
}

/** The first error message in a semgrep JSON report, when there is one. */
function reportedError(stdout: string): string | undefined {
  try {
    const report: unknown = JSON.parse(stdout);
    if (!isObject(report) || !Array.isArray(report.errors)) return undefined;
    const first = report.errors.find(isObject);
    return first ? (str(first.message) ?? str(first.type)) : undefined;
  } catch {
    return undefined;
  }
}

function rejectedIgnoreFlag(r: ToolResult): boolean {
  return r.code !== null && !OK_CODES.includes(r.code) && `${r.stderr}${r.stdout}`.includes(IGNORE_FILES_FLAG);
}

/** Like expectExit, but prefers the error semgrep put in its JSON report over the stderr tail. */
function checkSemgrepExit(engine: Engine, r: ToolResult): void {
  const failed = r.code !== null && !OK_CODES.includes(r.code) && !r.timedOut && !r.truncated;
  const why = failed ? reportedError(r.stdout) : undefined;
  if (why) throw new Error(`${engine} exited with ${r.code}: ${cleanText(why, MAX_ERROR)}`);
  expectExit(engine, r, OK_CODES);
}

export const semgrepDriver: ToolDriver = {
  info: SEMGREP_INFO,
  locate: async (env) => (await which("semgrep", env)) ?? (await which("opengrep", env)),
  versionArgs: ["--version"],
  toolEnv: (env) => ({ ...env, NO_COLOR: "1", SEMGREP_SEND_METRICS: "off", SEMGREP_ENABLE_VERSION_CHECK: "0" }),
  network: (cfg) => isRegistryConfig(cfg.semgrepConfig?.trim() || DEFAULT_SEMGREP_CONFIG),
  create: (env, cfg) =>
    toolAnalyzer(semgrepDriver, env, async ({ root, bin, exec }) => {
      const engine = engineOf(bin);
      const config = resolveSemgrepConfig(cfg, env);
      let result = await exec(semgrepArgs(engine, config, root, true));
      if (rejectedIgnoreFlag(result)) result = await exec(semgrepArgs(engine, config, root, false));
      checkSemgrepExit(engine, result);
      return parseSemgrepOutput(result.stdout, root);
    }),
};
