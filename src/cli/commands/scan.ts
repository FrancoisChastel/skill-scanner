import { mkdir, stat, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { createAnalyzers as defaultCreateAnalyzers } from "../../analyzers";
import { ANALYZER_NAMES, type AnalyzerName, type Config, loadConfig } from "../../config";
import { isSeverity } from "../../core/severity";
import type { ScanReport, Severity, Verdict } from "../../core/types";
import { createJudge as defaultCreateJudge } from "../../judge";
import { formatJson, formatReports, isReportFormat, oneLineSummary, type ReportFormat, type ReportOptions } from "../../report";
import { type BundleJudge, type ExternalAnalyzer, type ScanOptions, scanPath } from "../../scan";
import { scanSource as defaultScanSource, isRemoteSource } from "../../sources";
import { TOOL_NAME } from "../../version";
import { bool, type FlagSpecs, list, parseArgs, str, UsageError } from "../args";
import { type Command, EXIT } from "../command";
import { type CliIO, useColor } from "../io";

type FailOn = "block" | "warn" | "never";
const FAIL_ON: readonly FailOn[] = ["block", "warn", "never"];

/** What `scan` calls outside itself, injectable so tests never touch the network or real keys. */
export interface ScanDeps {
  readonly scanPath: typeof scanPath;
  readonly scanSource: typeof defaultScanSource;
  readonly createJudge: typeof defaultCreateJudge;
  readonly createAnalyzers: typeof defaultCreateAnalyzers;
}

const DEFAULT_DEPS: ScanDeps = {
  scanPath,
  scanSource: defaultScanSource,
  createJudge: defaultCreateJudge,
  createAnalyzers: defaultCreateAnalyzers,
};

const FLAGS: FlagSpecs = {
  format: { type: "string", short: "f", value: "<format>", description: "text, json, sarif, or markdown (default text)" },
  output: { type: "string", short: "o", value: "<file>", description: "Write the report to a file and print a one-line summary" },
  "fail-on": { type: "string", value: "<level>", description: "Exit 1 when the verdict reaches block (default), warn, or never" },
  "min-severity": {
    type: "string",
    value: "<severity>",
    description: "Hide findings below info, low (default), medium, high, or critical",
  },
  verbose: { type: "boolean", short: "v", description: "Show evidence, remediation, and judge notes" },
  config: { type: "string", value: "<file>", description: "Config file (default ~/.skill-scanner/config.json)" },
  judge: {
    type: "boolean",
    description:
      "The jev judge runs by default when a jev key is set; --judge also uses a gateway key and warns without one, --no-judge turns it off",
  },
  with: {
    type: "string",
    multiple: true,
    value: "<analyzers>",
    description: `Also run external analyzers: ${ANALYZER_NAMES.join(", ")}, or auto (comma list, repeatable)`,
  },
  skill: { type: "string", short: "s", multiple: true, value: "<name>", description: "Only report on these skills (repeatable)" },
  "no-color": { type: "boolean", description: "Plain output without ANSI colors" },
  quiet: { type: "boolean", short: "q", description: "Print nothing unless --output is set; only the exit code" },
};

const DETAILS = `Targets are local paths (directories, SKILL.md files, zip archives) or sources as
\`npx skills add\` accepts them (owner/repo, git URLs, npm:package). Default: the current directory.

Exit codes: 0 below the --fail-on level, 1 at or above it, 2 when a target could not be scanned.
Reading config never looks inside the target: a skill cannot ship its own allowlist.`;

interface Settings {
  readonly format: ReportFormat;
  readonly output?: string;
  readonly failOn: FailOn;
  readonly minSeverity: Severity;
  readonly verbose: boolean;
  readonly quiet: boolean;
  readonly noColor: boolean;
  readonly judge?: boolean;
  readonly with: readonly (AnalyzerName | "auto")[];
  readonly skills: readonly string[];
  readonly configPath?: string;
  readonly targets: readonly string[];
}

function parseSettings(argv: readonly string[]): Settings {
  const { flags, positionals, rest } = parseArgs(argv, FLAGS);
  const format = str(flags.format) ?? "text";
  if (!isReportFormat(format)) throw new UsageError(`--format must be text, json, sarif, or markdown, not "${format}"`);
  const failOn = str(flags["fail-on"]) ?? "block";
  if (!(FAIL_ON as readonly string[]).includes(failOn)) throw new UsageError(`--fail-on must be block, warn, or never, not "${failOn}"`);
  const minSeverity = str(flags["min-severity"]) ?? "low";
  if (!isSeverity(minSeverity)) throw new UsageError(`--min-severity must be info, low, medium, high, or critical, not "${minSeverity}"`);
  const withNames = list(flags.with);
  for (const n of withNames) {
    if (n !== "auto" && !(ANALYZER_NAMES as readonly string[]).includes(n))
      throw new UsageError(`unknown analyzer "${n}" for --with (known: ${ANALYZER_NAMES.join(", ")}, auto)`);
  }
  const output = str(flags.output);
  const configPath = str(flags.config);
  const targets = [...positionals, ...rest];
  return {
    format,
    failOn: failOn as FailOn,
    minSeverity,
    verbose: bool(flags.verbose),
    quiet: bool(flags.quiet),
    noColor: bool(flags["no-color"]),
    with: withNames as (AnalyzerName | "auto")[],
    skills: list(flags.skill),
    targets: targets.length > 0 ? targets : ["."],
    ...(output !== undefined ? { output } : {}),
    ...(configPath !== undefined ? { configPath } : {}),
    ...(typeof flags.judge === "boolean" ? { judge: flags.judge } : {}),
  };
}

/** Shown after a text scan when the judge is on by default but has no key. Figures: docs/benchmark.md. */
export const JEV_HINT =
  `Tip: ${TOOL_NAME} runs TypeSafe's jev judge by default once it has a key, and then flags about twice as many ` +
  "malicious skills (78% against 40% for the rules alone in the benchmark), for about $0.0003 a skill. " +
  'Set TYPESAFE_API_KEY (https://typesafe.ai); `"judge": {"enabled": false}` in the config hides this tip.';

function reaches(verdict: Verdict, failOn: FailOn): boolean {
  if (failOn === "never") return false;
  return failOn === "warn" ? verdict !== "pass" : verdict === "block";
}

/**
 * The judge, or nothing. With `--judge` or `enabled: true`, a missing key is a warning; by default
 * (`auto`) it is not an error at all, and the scan ends with a hint on what a key adds.
 */
function resolveJudge(s: Settings, config: Config, io: CliIO, deps: ScanDeps): { judge?: BundleJudge; hint: boolean } {
  const mode = s.judge ?? config.judge.enabled;
  if (mode === false) return { hint: false };
  const { judge, reason, quiet } = deps.createJudge({ ...config.judge, enabled: mode }, io.env);
  if (judge) return { judge, hint: false };
  if (quiet) return { hint: true };
  io.stderr(`${TOOL_NAME}: the jev judge is not available (${reason ?? "no reason given"}); scanning offline only.\n`);
  return { hint: false };
}

async function resolveAnalyzers(s: Settings, config: Config, io: CliIO, deps: ScanDeps): Promise<ExternalAnalyzer[]> {
  const fromConfig = ANALYZER_NAMES.filter((n) => config.analyzers[n]);
  const names = [...new Set<AnalyzerName | "auto">([...fromConfig, ...s.with])];
  if (names.length === 0) return [];
  try {
    const all = await deps.createAnalyzers(names, config, io.env);
    // One the config turns on (gitleaks by default) but that is not installed is left out quietly; `doctor`
    // says how to add it. One asked for with --with stays, so the report says it could not run.
    const asked = new Set<string>(s.with);
    const kept = await Promise.all(
      all.map(async (a) => (asked.has(a.name) || !(await a.unavailable().catch(() => "unavailable")) ? a : undefined)),
    );
    return kept.filter((a): a is ExternalAnalyzer => a !== undefined);
  } catch (e) {
    io.stderr(`${TOOL_NAME}: external analyzers unavailable (${e instanceof Error ? e.message : String(e)}); continuing without them.\n`);
    return [];
  }
}

/** Where result paths of a local directory target sit relative to the working directory, for SARIF. */
function uriPrefixFor(abs: string, isFile: boolean, cwd: string): string | undefined {
  const dir = isFile ? dirname(abs) : abs;
  const rel = relative(cwd, dir);
  if (rel === "" || rel.startsWith("..") || isAbsolute(rel)) return undefined;
  return rel.split(sep).join("/");
}

interface TargetResult {
  readonly report?: ScanReport;
  readonly prefix?: string;
}

async function localKind(abs: string): Promise<"file" | "dir" | undefined> {
  try {
    const info = await stat(abs);
    return info.isFile() ? "file" : "dir";
  } catch {
    return undefined;
  }
}

async function scanTarget(target: string, opts: ScanOptions, io: CliIO, deps: ScanDeps): Promise<TargetResult> {
  const abs = resolve(io.cwd, target);
  const kind = await localKind(abs);
  if (kind) {
    const report = await deps.scanPath(abs, { ...opts, label: target });
    const prefix = uriPrefixFor(abs, kind === "file", io.cwd);
    return { report, ...(prefix ? { prefix } : {}) };
  }
  if (!isRemoteSource(target)) throw new Error(`no such file or directory, and not a source skill-scanner can fetch: ${target}`);
  const { report, fetched } = await deps.scanSource(target, { ...opts, label: target, cwd: io.cwd, env: io.env });
  try {
    return { report };
  } finally {
    await fetched.cleanup().catch((e: unknown) => {
      io.stderr(`${TOOL_NAME}: could not remove the temporary copy of ${target}: ${e instanceof Error ? e.message : String(e)}\n`);
    });
  }
}

function render(reports: readonly ScanReport[], prefixes: ReadonlyMap<ScanReport, string>, s: Settings, color: boolean, config: Config) {
  const opts: ReportOptions = {
    color,
    minSeverity: s.minSeverity,
    verbose: s.verbose,
    policy: { blockAt: config.blockAt, warnAt: config.warnAt },
    uriPrefix: (r) => prefixes.get(r),
  };
  // Several targets always give a JSON array, even if some failed, so the shape follows the command line.
  if (s.format === "json" && s.targets.length > 1) return formatJson(reports);
  return formatReports(reports, s.format, opts);
}

async function run(argv: readonly string[], io: CliIO, deps: ScanDeps): Promise<number> {
  const s = parseSettings(argv);
  const config = await loadConfig(s.configPath, io.env);
  const { judge, hint } = resolveJudge(s, config, io, deps);
  const analyzers = await resolveAnalyzers(s, config, io, deps);
  const opts: ScanOptions = {
    policy: { blockAt: config.blockAt, warnAt: config.warnAt },
    suppressions: config.ignore,
    analyzers,
    ...(judge ? { judge } : {}),
    ...(s.skills.length > 0 ? { onlySkills: s.skills } : {}),
  };

  let exit: number = EXIT.ok;
  const reports: ScanReport[] = [];
  const prefixes = new Map<ScanReport, string>();
  for (const target of s.targets) {
    try {
      const { report, prefix } = await scanTarget(target, opts, io, deps);
      if (!report) continue;
      reports.push(report);
      if (prefix) prefixes.set(report, prefix);
      if (reaches(report.verdict, s.failOn)) exit = Math.max(exit, EXIT.findings);
    } catch (e) {
      io.stderr(`${TOOL_NAME} scan: ${target}: ${e instanceof Error ? e.message : String(e)}\n`);
      exit = EXIT.error;
    }
  }
  if (reports.length === 0) return exit;

  const toFile = s.output !== undefined;
  const color = !toFile && s.format === "text" && !s.noColor && useColor(io);
  const text = render(reports, prefixes, s, color, config);
  if (s.output !== undefined) {
    const path = resolve(io.cwd, s.output);
    try {
      await mkdir(dirname(path), { recursive: true });
      await writeFile(path, text);
    } catch (e) {
      io.stderr(`${TOOL_NAME} scan: cannot write ${s.output}: ${e instanceof Error ? e.message : String(e)}\n`);
      return EXIT.error;
    }
    if (!s.quiet) for (const r of reports) io.stderr(`${oneLineSummary(r)}; report written to ${s.output}\n`);
  } else if (!s.quiet) {
    io.stdout(text);
  }
  // Only for a person at a terminal: piped output and CI logs stay as they were.
  if (hint && io.isTTY && s.format === "text" && !s.quiet) io.stderr(`\n${JEV_HINT}\n`);
  return exit;
}

export function createScanCommand(deps: Partial<ScanDeps> = {}): Command {
  const all: ScanDeps = { ...DEFAULT_DEPS, ...deps };
  return {
    name: "scan",
    summary: "Scan skills in local paths or remote sources and report what they could do",
    usage: "[target...] [options]",
    flags: FLAGS,
    details: DETAILS,
    run: (argv, io) => run(argv, io, all),
  };
}

export const scanCommand: Command = createScanCommand();
