import { appendFile, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CliIO } from "../cli/io";
import { loadConfig } from "../config";
import type { ScanReport } from "../core/types";
import { withDeadline } from "../guard/deadline";
import { loadTrust, trustedDigests } from "../guard/state";
import { summarizeForAgent } from "../report/index";
import { scanPath, type TargetScanner } from "../scan";
import { GUARD_SCOPE_ENV, GUARD_STATE_ENV } from "./guard-env";
import { onlySkillBundles, scanGaps } from "./select";

/**
 * What the git hooks installed by `guard` share: scanning a tree under a hard deadline, deciding
 * whether to refuse it, and the files in the guard's state directory where they record what they
 * saw, refused, and let through.
 */

/** A hook scan that has not finished by then is refused. Scans run in a worker, so this holds. */
export const GIT_HOOK_SCAN_MS = 60_000;
/** Trees (by object id) that already passed under this guard, so a fetch and the reset after it scan once. */
export const PASSED_FILE = "passed.log";

export interface GitHookDeps {
  /** Default `scanPath`; `hook` passes the isolated (worker) scanner. */
  readonly scan?: TargetScanner;
  readonly deadlineMs?: number;
}

export interface HookScan {
  readonly report: ScanReport;
  /** Why the tree must not be used; undefined when it may. */
  readonly refusal?: string;
  /** The findings, one paragraph, ending in a newline. */
  readonly summary: string;
}

/** Scan `dir` for a git hook, judged the way the guard's scope asks. Throws when the scan fails or runs out of time. */
export async function scanForGitHook(dir: string, label: string, io: CliIO, deps: GitHookDeps): Promise<HookScan> {
  const config = await loadConfig(undefined, io.env);
  const scan = deps.scan ?? scanPath;
  const ms = deps.deadlineMs ?? GIT_HOOK_SCAN_MS;
  const outcome = await withDeadline(ms, undefined, (signal) =>
    scan(dir, { policy: { blockAt: config.blockAt, warnAt: config.warnAt }, suppressions: config.ignore, label, signal }),
  );
  if (outcome.status === "timeout") throw new Error(`the scan did not finish within ${Math.round(ms / 1000)} s`);
  if (outcome.status === "error") throw outcome.error;
  // Under the skills CLI only skill directories get installed; judge the tree the same way.
  const report = io.env[GUARD_SCOPE_ENV] === "skills" ? onlySkillBundles(outcome.value) : outcome.value;
  const refusal = refusalReason(report, config.hooks.onWarn, trustedDigests(await loadTrust(io.env)));
  return { report, summary: withNewline(summarizeForAgent(report)), ...(refusal ? { refusal } : {}) };
}

/**
 * Why a scanned tree must not be used, or undefined when it may. Bundles whose exact digest the
 * user approved with `skill-scanner trust` do not count, as for installs.
 */
export function refusalReason(
  report: ScanReport,
  onWarn: "ask" | "allow" | "deny",
  trusted: ReadonlySet<string> = new Set(),
): string | undefined {
  const untrusted = report.bundles.filter((b) => b.verdict !== "pass" && !trusted.has(b.bundle.digest));
  if (untrusted.some((b) => b.verdict === "block")) return "the scan blocked it";
  // Padding a repository past the collection limits hides whatever sorts after the padding.
  const gaps = scanGaps(report);
  if (gaps.length > 0) return `parts were not scanned (${gaps[0]})`;
  if (untrusted.some((b) => b.verdict === "warn") && onWarn === "deny") return "the scan warned and hooks.onWarn is deny";
  return undefined;
}

/**
 * Append to a file in the guard's state directory. Installers often swallow hook output (the
 * skills CLI's update path does), so `guard` and `add` repeat these once the command exits.
 */
export async function record(io: CliIO, file: string, text: string): Promise<void> {
  const state = io.env[GUARD_STATE_ENV];
  if (!state) return;
  try {
    await appendFile(join(state, file), text);
  } catch (e) {
    // The decision itself stands; only the after-the-fact report is lost.
    io.stderr(`skill-scanner: could not record to ${state}: ${(e as Error).message}\n`);
  }
}

/** Lines of a state file, empty when there is none (or no guard). */
export async function readRecord(io: CliIO, file: string): Promise<readonly string[]> {
  const state = io.env[GUARD_STATE_ENV];
  if (!state) return [];
  try {
    return (await readFile(join(state, file), "utf8")).split("\n").filter(Boolean);
  } catch {
    return [];
  }
}

export function isApproved(commit: string, approved: string | undefined): boolean {
  if (!/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/.test(commit) || !approved) return false;
  return approved
    .split(/[\s,]+/)
    .map((s) => s.toLowerCase())
    .includes(commit);
}

export const withNewline = (text: string): string => (text.endsWith("\n") ? text : `${text}\n`);

/**
 * The hook's environment without the variables git sets (or a caller inherited) that would point
 * our own git calls at another repository or index. The hook scripts pass the repository they ran
 * in as an absolute `--git-dir`, which every call names explicitly instead.
 */
export function hookGitEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const { GIT_DIR: _dir, GIT_WORK_TREE: _tree, GIT_INDEX_FILE: _index, GIT_PREFIX: _prefix, ...rest } = env;
  return rest;
}
