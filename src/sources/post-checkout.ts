import { appendFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import type { CliIO } from "../cli/io";
import { loadConfig } from "../config";
import type { ScanReport } from "../core/types";
import { summarizeForAgent } from "../report/index";
import { scanPath } from "../scan";
import { redactCredentials } from "./errors";
import { git } from "./git";
import { APPROVED_COMMITS_ENV, CHECKOUTS_FILE, GUARD_SCOPE_ENV, GUARD_STATE_ENV, REFUSALS_FILE } from "./guard-env";
import { onlySkillBundles, scanGaps } from "./select";

/**
 * The git `post-checkout` hook installed by `skill-scanner guard` (and `add`). Git runs the hook
 * script inside the new checkout with `<prev-head> <new-head> <branch-flag>`; the script moves out
 * of it and calls `skill-scanner hook git-post-checkout --dir <checkout> <args>`. A non-zero exit
 * fails the checkout, and the skills CLI, `pi install`, or `git clone` with it. It only runs where
 * the user asked for protection, so any failure to scan refuses the checkout (fail closed).
 */
export async function runPostCheckout(argv: readonly string[], io: CliIO): Promise<number> {
  const { dir, args } = splitDir(argv, io.cwd);
  const head = (args[1] ?? "").toLowerCase();
  try {
    if (isApproved(head, io.env[APPROVED_COMMITS_ENV])) {
      io.stderr(`skill-scanner: commit ${head.slice(0, 12)} was scanned before this install; allowed\n`);
      await record(io, CHECKOUTS_FILE, `${head} approved\n`);
      return 0;
    }
    const config = await loadConfig(undefined, io.env);
    const scanned = await scanPath(dir, {
      policy: { blockAt: config.blockAt, warnAt: config.warnAt },
      suppressions: config.ignore,
      label: await originOf(dir, io.env),
    });
    // Under the skills CLI only skill directories get installed; judge the checkout the same way.
    const report = io.env[GUARD_SCOPE_ENV] === "skills" ? onlySkillBundles(scanned) : scanned;
    const summary = withNewline(summarizeForAgent(report));
    io.stderr(summary);
    const why = refusalReason(report, config.hooks.onWarn);
    await record(io, CHECKOUTS_FILE, `${head || "-"} ${why ? "refused" : report.verdict}\n`);
    if (!why) return 0;
    io.stderr(`skill-scanner: checkout refused: ${why}. Ask the user before retrying without the guard.\n`);
    await record(io, REFUSALS_FILE, summary);
    return 1;
  } catch (e) {
    const why = `skill-scanner: cannot scan ${dir} (${e instanceof Error ? e.message : String(e)}); refusing it.\n`;
    io.stderr(why);
    await record(io, CHECKOUTS_FILE, `${head || "-"} error\n`);
    await record(io, REFUSALS_FILE, why);
    return 1;
  }
}

/** Why the checkout must not be used, or undefined when it may. */
function refusalReason(report: ScanReport, onWarn: "ask" | "allow" | "deny"): string | undefined {
  if (report.verdict === "block") return "the scan blocked it";
  // Padding a repository past the collection limits hides whatever sorts after the padding.
  const gaps = scanGaps(report);
  if (gaps.length > 0) return `parts were not scanned (${gaps[0]})`;
  if (report.verdict === "warn" && onWarn === "deny") return "the scan warned and hooks.onWarn is deny";
  return undefined;
}

/** `--dir <checkout>` from the hook script; without it (a direct call), the working directory. */
function splitDir(argv: readonly string[], cwd: string): { dir: string; args: readonly string[] } {
  if (argv[0] === "--dir" && argv[1] !== undefined) return { dir: resolve(cwd, argv[1]), args: argv.slice(2) };
  return { dir: cwd, args: argv };
}

/**
 * Append to a file in the guard's state directory. Installers often swallow hook output (the
 * skills CLI's update path does), so `guard` and `add` repeat these once the command exits.
 */
async function record(io: CliIO, file: string, text: string): Promise<void> {
  const state = io.env[GUARD_STATE_ENV];
  if (!state) return;
  try {
    await appendFile(join(state, file), text);
  } catch (e) {
    // The decision itself stands; only the after-the-fact report is lost.
    io.stderr(`skill-scanner: could not record to ${state}: ${(e as Error).message}\n`);
  }
}

/** The remote this checkout came from (as the user named it, before insteadOf), else its path. */
async function originOf(dir: string, env: NodeJS.ProcessEnv): Promise<string> {
  try {
    const url = (await git(["-C", dir, "config", "--get", "remote.origin.url"], { env, timeoutMs: 5_000 })).trim();
    return url ? redactCredentials(url) : dir;
  } catch {
    return dir;
  }
}

function isApproved(head: string, approved: string | undefined): boolean {
  if (!/^[0-9a-f]{40}$/.test(head) || !approved) return false;
  return approved
    .split(/[\s,]+/)
    .map((s) => s.toLowerCase())
    .includes(head);
}

const withNewline = (text: string): string => (text.endsWith("\n") ? text : `${text}\n`);
