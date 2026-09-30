import { loadConfig } from "../../config";
import type { ScanReport } from "../../core/types";
import { formatReport, type ReportFormat } from "../../report/index";
import { isolatedScanner } from "../../scan-worker";
import {
  cloneUrlVariants,
  currentRuntime,
  type FetchedSource,
  fetchSource,
  type GuardEnv,
  guardEnv,
  type MirrorMapping,
  parseSource,
  redactCredentials,
  type SourceSpec,
  scanFetched,
  scanGaps,
  shellQuote,
} from "../../sources/index";
import { runInherited } from "../../sources/spawn";
import { bool, type FlagSpecs, formatFlags, parseArgs, str, UsageError } from "../args";
import { type Command, EXIT } from "../command";
import { type CliIO, useColor } from "../io";
import { withRefusals } from "./guard";

const DEFAULT_SKILLS_CLI: readonly string[] = ["npx", "-y", "skills@1"];
const FORMATS: readonly ReportFormat[] = ["text", "json", "sarif", "markdown"];

const FLAGS: FlagSpecs = {
  force: { type: "boolean", description: "Install even when the scan blocks (prints a loud warning)" },
  "accept-warnings": { type: "boolean", description: "Install without asking when the scan only warns" },
  "dry-run": { type: "boolean", description: "Scan and print the skills command and environment that would run, then stop" },
  format: { type: "string", value: "<format>", description: "Report format: text (default), json, sarif, markdown" },
  color: { type: "boolean", description: "Color the report (default on a terminal; --no-color turns it off)" },
  help: { type: "boolean", short: "h", description: "Show this help" },
};

const DETAILS = `Everything else is passed to \`skills add\` unchanged: -g, -y, -a/--agent, -s/--skill, --all,
--copy, --full-depth, --json, ... The source is fetched and scanned the way the skills CLI reads
it (owner/repo, owner/repo@skill, #ref, GitHub/GitLab URLs, git URLs, local paths); -s/--skill and
--all limit the scan to the skills that will be installed. -l/--list is passed through unscanned.

The install then clones from the checkout that was scanned (git url.<mirror>.insteadOf), so what
lands on disk is what was reviewed; a post-checkout hook rescans anything else it checks out.

block refuses (exit 1) unless --force. warn asks on a terminal and refuses elsewhere unless
--accept-warnings. SKILL_SCANNER_SKILLS_CLI replaces the skills command (default: npx -y skills@1).
npm: packages and direct URLs cannot be installed by the skills CLI; use \`skill-scanner scan\`.`;

export const addCommand: Command = {
  name: "add",
  summary: "Scan a skill source, then install it with `npx skills add` if it passes",
  usage: "<source> [skills add options] [--force] [--accept-warnings] [--dry-run] [--format <format>]",
  flags: FLAGS,
  details: DETAILS,
  run: runAdd,
};

interface AddFlags {
  readonly force: boolean;
  readonly acceptWarnings: boolean;
  readonly dryRun: boolean;
  readonly format: ReportFormat;
}

async function runAdd(argv: readonly string[], io: CliIO): Promise<number> {
  const parsed = parseArgs(argv, FLAGS, { passUnknown: true });
  if (bool(parsed.flags.help)) {
    io.stdout(helpText());
    return EXIT.ok;
  }
  const flags: AddFlags = {
    force: bool(parsed.flags.force),
    acceptWarnings: bool(parsed.flags["accept-warnings"]),
    dryRun: bool(parsed.flags["dry-run"]),
    format: parseFormat(str(parsed.flags.format)),
  };
  const skillsArgs = parseSkillsAddArgs([...parsed.positionals, ...parsed.rest]);
  if (!skillsArgs.source) throw new UsageError("missing <source>");
  const cli = skillsCli(io.env);
  if (skillsArgs.list) return runInherited([...cli, "add", skillsArgs.source, ...skillsArgs.rest], { env: io.env, cwd: io.cwd });

  const spec = parseInstallable(skillsArgs.source, io);
  if (!spec) return EXIT.error;
  const config = await loadConfig(undefined, io.env);
  const fetched = await fetchSource(spec, { env: io.env });
  try {
    const selected = skillsArgs.all ? ["*"] : skillsArgs.skills;
    const report = await scanFetched(fetched, {
      policy: { blockAt: config.blockAt, warnAt: config.warnAt },
      suppressions: config.ignore,
      ...(selected.length > 0 ? { onlySkills: selected } : {}),
      skillBundlesOnly: true,
      // In a worker: Ctrl+C and the command's own signal handlers keep working during the scan.
      scanner: isolatedScanner(),
    });
    // stdout carries our report, unless the skills CLI was asked for JSON on stdout.
    (skillsArgs.json ? io.stderr : io.stdout)(
      formatReport(report, flags.format, { color: parsed.flags.color === false ? false : useColor(io) }),
    );
    if (!(await mayInstall(report, flags, io))) return EXIT.findings;
    const delegated = [...cli, "add", spec.kind === "local" ? spec.path! : skillsArgs.source, ...skillsArgs.rest];
    const guard = await guardEnv(
      { ...currentRuntime(), extraMirrors: mirrorsFor(fetched), approvedCommits: approvedFor(fetched), scope: "skills" },
      io.env,
    );
    try {
      if (flags.dryRun) {
        (flags.format === "text" && !skillsArgs.json ? io.stdout : io.stderr)(dryRunText(delegated, guard));
        return EXIT.ok;
      }
      const code = await withRefusals(await runInherited(delegated, { env: guard.env, cwd: io.cwd }), guard, io);
      return code === 0 ? await verifyHookRan(fetched, guard, io) : code;
    } finally {
      await guard.cleanup();
    }
  } finally {
    await fetched.cleanup();
  }
}

/** The source as a git or local spec the skills CLI can install; otherwise explain and return undefined. */
function parseInstallable(source: string, io: CliIO): SourceSpec | undefined {
  if (/^git:(?!\/\/)/i.test(source)) {
    io.stderr(
      `skill-scanner add: "${redactCredentials(source)}" is Pi's package syntax; the skills CLI takes owner/repo#ref or a git URL.\n`,
    );
    return undefined;
  }
  const spec = parseSource(source, io.cwd, io.env);
  if (spec.kind === "npm" || spec.kind === "url") {
    const what = spec.kind === "npm" ? "npm packages" : "direct URLs (archives, raw files, well-known endpoints)";
    io.stderr(
      `skill-scanner add: the skills CLI does not install ${what} through this wrapper.\n` +
        `Scan it with \`skill-scanner scan ${redactCredentials(source)}\`${spec.kind === "npm" ? " and install it with the tool that uses it (e.g. pi install)" : ""}.\n`,
    );
    return undefined;
  }
  return spec;
}

/** Apply the verdict: block needs --force; warn needs a yes on a terminal or --accept-warnings. */
async function mayInstall(report: ScanReport, flags: AddFlags, io: CliIO): Promise<boolean> {
  const gaps = scanGaps(report);
  if (report.verdict === "block" || gaps.length > 0) {
    // The install is approved by commit, so an incomplete scan must not pass as a warning.
    const why = report.verdict === "block" ? "the scan blocked it" : `parts of it were not scanned (${gaps[0]})`;
    if (!flags.force) {
      io.stderr(`skill-scanner: refusing to install ${report.target}: ${why}. Use --force to install anyway.\n`);
      return false;
    }
    io.stderr(
      `\n!!! skill-scanner: --force given: ${flags.dryRun ? "would install" : "installing"} ${report.target} DESPITE A BLOCKING SCAN (${why}).\n` +
        "!!! It will run with your agent's permissions. Remove it with `npx skills remove` if in doubt.\n\n",
    );
    return true;
  }
  if (report.verdict !== "warn" || flags.acceptWarnings) return true;
  if (flags.dryRun) {
    io.stderr("skill-scanner: the scan warns; a real run would ask (or need --accept-warnings).\n");
    return true;
  }
  if (io.isTTY && (await io.confirm("Install anyway?"))) return true;
  io.stderr(
    `skill-scanner: not installing ${report.target}: the scan has warnings.` +
      `${io.isTTY ? "" : " Pass --accept-warnings to install without a terminal prompt."}\n`,
  );
  return false;
}

/**
 * A git install that succeeded without our hook seeing a checkout went around the guard (a
 * snapshot download, a scrubbed environment, a changed installer): say so and fail.
 */
async function verifyHookRan(fetched: FetchedSource, guard: GuardEnv, io: CliIO): Promise<number> {
  if (fetched.spec.kind !== "git" || (await guard.checkouts()).length > 0) return EXIT.ok;
  io.stderr(
    "skill-scanner: the skills CLI finished without any git checkout passing through skill-scanner's hook, " +
      "so the installed files were not verified against the scan. Inspect them before use.\n",
  );
  return EXIT.findings;
}

function mirrorsFor(fetched: FetchedSource): MirrorMapping[] {
  const url = fetched.spec.cloneUrl;
  return fetched.spec.kind === "git" && url ? [{ mirror: fetched.root, urls: cloneUrlVariants(url) }] : [];
}

function approvedFor(fetched: FetchedSource): string[] {
  return fetched.commit ? [fetched.commit] : [];
}

function dryRunText(command: readonly string[], guard: GuardEnv): string {
  const envLines = Object.entries(guard.env)
    .filter(([k]) =>
      /^GIT_CONFIG_(?:COUNT|KEY_\d+|VALUE_\d+)$|^SKILLS_DOWNLOAD_URL$|^SKILL_SCANNER_(?:APPROVED_COMMITS|GUARD_STATE)$/.test(k),
    )
    .sort(([a], [b]) => envOrder(a) - envOrder(b) || a.localeCompare(b))
    .map(([k, v]) => `  ${k}=${quoteIfNeeded(redactCredentials(v ?? ""))}`);
  return [
    "",
    "Dry run: would run",
    `  ${command.map((c) => quoteIfNeeded(redactCredentials(c))).join(" ")}`,
    "with environment",
    ...envLines,
    "(the temporary hooks directory and checkout are removed after a dry run)",
    "",
  ].join("\n");
}

/** GIT_CONFIG_COUNT first, then each KEY_n next to its VALUE_n, then everything else. */
function envOrder(key: string): number {
  const m = /^GIT_CONFIG_(KEY|VALUE)_(\d+)$/.exec(key);
  if (m) return 1 + Number(m[2]) * 2 + (m[1] === "VALUE" ? 1 : 0);
  return key === "GIT_CONFIG_COUNT" ? 0 : Number.MAX_SAFE_INTEGER;
}

const quoteIfNeeded = (s: string): string => (/^[\w@%+=:,./-]+$/.test(s) ? s : shellQuote(s));

function parseFormat(value: string | undefined): ReportFormat {
  if (value === undefined) return "text";
  if ((FORMATS as readonly string[]).includes(value)) return value as ReportFormat;
  throw new UsageError(`--format must be one of ${FORMATS.join(", ")}`);
}

export function skillsCli(env: NodeJS.ProcessEnv): readonly string[] {
  const custom = (env.SKILL_SCANNER_SKILLS_CLI ?? "").trim().split(/\s+/).filter(Boolean);
  return custom.length > 0 ? custom : DEFAULT_SKILLS_CLI;
}

export interface SkillsAddArgs {
  /** The first positional, as the skills CLI takes it. */
  readonly source?: string;
  /** Every other token, in order, to forward. */
  readonly rest: readonly string[];
  readonly skills: readonly string[];
  readonly agents: readonly string[];
  readonly all: boolean;
  readonly list: boolean;
  readonly json: boolean;
}

/**
 * Read `skills add` arguments exactly as skills@1.7 parseAddOptions does: -s/-a/--subagent take
 * every following token up to the next one starting with `-`; --metadata takes one; the first
 * remaining non-flag is the source. Knowing which token it will treat as the source matters more
 * than being tidy.
 */
export function parseSkillsAddArgs(args: readonly string[]): SkillsAddArgs {
  const rest: string[] = [];
  const skills: string[] = [];
  const agents: string[] = [];
  let source: string | undefined;
  let all = false;
  let list = false;
  let json = false;
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i]!;
    const variadic = a === "-s" || a === "--skill" ? skills : a === "-a" || a === "--agent" ? agents : a === "--subagent" ? [] : undefined;
    if (variadic) {
      rest.push(a);
      while (i + 1 < args.length && args[i + 1] && !args[i + 1]!.startsWith("-")) {
        i += 1;
        variadic.push(args[i]!);
        rest.push(args[i]!);
      }
      continue;
    }
    if (a === "--metadata") {
      rest.push(a, ...(i + 1 < args.length ? [args[++i]!] : []));
      continue;
    }
    if (a === "--all") all = true;
    else if (a === "-l" || a === "--list") list = true;
    else if (a === "--json") json = true;
    else if (source === undefined && a && !a.startsWith("-")) {
      source = a;
      continue;
    }
    rest.push(a);
  }
  return { ...(source !== undefined ? { source } : {}), rest, skills, agents, all: all || skills.includes("*"), list, json };
}

function helpText(): string {
  return [
    addCommand.summary,
    "",
    "Usage:",
    `  skill-scanner add ${addCommand.usage}`,
    "",
    "Options:",
    formatFlags(FLAGS),
    "",
    DETAILS,
    "",
  ].join("\n");
}
