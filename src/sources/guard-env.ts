import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { ProgramError, runProgram } from "./exec";

/**
 * The environment that makes every git checkout under a command pass through the scanner.
 *
 * `npx skills`, `pi install`, and plain `git clone` have no extension points, but they all inherit
 * the environment and git reads config from GIT_CONFIG_COUNT/KEY_n/VALUE_n. That gives us:
 * - `core.hooksPath=<temp dir>` whose `post-checkout` runs `skill-scanner hook git-post-checkout`
 *   inside each fresh checkout; a non-zero exit makes git (and so the installer) fail.
 * - In the same directory, a `reference-transaction` hook that scans the commit a checked-out
 *   branch (or its upstream) is about to move to, and aborts the move when the scan refuses it:
 *   the gate for updates (`git pull`, `git reset`, `pi update`), which never check out.
 * - `url.<mirror>.insteadOf=<clone URL>` so an install clones the exact checkout we already scanned.
 * - SKILLS_DOWNLOAD_URL pointed at a dead port, so the skills CLI's snapshot-API fast path (which
 *   bypasses git and therefore the hook) falls back to cloning.
 */

export interface GuardRuntime {
  /** Absolute path of the node (or bun) binary. */
  readonly node: string;
  /** Absolute path of the skill-scanner CLI script. */
  readonly script: string;
}

export interface MirrorMapping {
  /** Local repository to clone from instead. */
  readonly mirror: string;
  /** Clone URLs to redirect to it (git matches them as prefixes; the longest wins). */
  readonly urls: readonly string[];
}

export interface GuardEnvOptions extends GuardRuntime {
  readonly extraMirrors?: readonly MirrorMapping[];
  /** Commits the caller already scanned and accepted; checkouts of them are let through without a rescan. */
  readonly approvedCommits?: readonly string[];
  /** Timeout for the git query that finds the hook to chain. Default 10 s. */
  readonly timeoutMs?: number;
  /** `skills`: the command installs through the skills CLI, which copies skill directories only. */
  readonly scope?: "skills";
}

export interface GuardEnv {
  readonly env: NodeJS.ProcessEnv;
  readonly hooksDir: string;
  /** The git config entries added, in order, for display (`--dry-run`). */
  readonly gitConfig: readonly (readonly [string, string])[];
  /** Summaries of the checkouts the hook refused so far (empty when none). Read before cleanup. */
  refusals(): Promise<string>;
  /** One `<commit> <outcome>` line per checkout the hook saw, so callers can tell it never ran. */
  checkouts(): Promise<readonly string[]>;
  /** Remove the hooks directory. Safe to call twice. */
  cleanup(): Promise<void>;
}

export const APPROVED_COMMITS_ENV = "SKILL_SCANNER_APPROVED_COMMITS";
/** Set to `skills` when the guarded command installs through the skills CLI (see GuardEnvOptions.scope). */
export const GUARD_SCOPE_ENV = "SKILL_SCANNER_GUARD_SCOPE";
/**
 * Directory where the hook records what it saw (`checkouts.log`) and refused (`refusals.log`), so
 * `guard` and `add` can report it even when the installer swallows hook output.
 */
export const GUARD_STATE_ENV = "SKILL_SCANNER_GUARD_STATE";
export const REFUSALS_FILE = "refusals.log";
export const CHECKOUTS_FILE = "checkouts.log";
/** Port 9 (discard) on loopback: connections are refused at once, so the fallback is immediate. */
export const DEAD_DOWNLOAD_URL = "http://127.0.0.1:9";

export async function guardEnv(opts: GuardEnvOptions, baseEnv: NodeJS.ProcessEnv): Promise<GuardEnv> {
  const hooksDir = await mkdtemp(join(tmpdir(), "skill-scanner-hooks-"));
  let removed: Promise<void> | undefined;
  const cleanup = (): Promise<void> => {
    removed ??= rm(hooksDir, { recursive: true, force: true });
    return removed;
  };
  try {
    const previous = await previousHooksPath(baseEnv, hooksDir, opts.timeoutMs ?? 10_000);
    for (const [name, script] of [
      ["post-checkout", postCheckoutScript(opts, previous, hooksDir)],
      ["reference-transaction", referenceTransactionScript(opts, previous, hooksDir)],
    ] as const) {
      const hook = join(hooksDir, name);
      await writeFile(hook, script, { mode: 0o755 });
      await chmod(hook, 0o755);
    }
    const gitConfig: [string, string][] = [["core.hooksPath", hooksDir], ...mirrorEntries(opts.extraMirrors ?? [])];
    const approved = mergeApproved(baseEnv[APPROVED_COMMITS_ENV], opts.approvedCommits ?? []);
    const env: NodeJS.ProcessEnv = {
      ...appendGitConfig(baseEnv, gitConfig),
      SKILLS_DOWNLOAD_URL: DEAD_DOWNLOAD_URL,
      [GUARD_STATE_ENV]: hooksDir,
      ...(approved ? { [APPROVED_COMMITS_ENV]: approved } : {}),
      ...(opts.scope ? { [GUARD_SCOPE_ENV]: opts.scope } : {}),
    };
    const refusals = (): Promise<string> => readIfExists(join(hooksDir, REFUSALS_FILE));
    const checkouts = async (): Promise<readonly string[]> =>
      (await readIfExists(join(hooksDir, CHECKOUTS_FILE))).split("\n").filter(Boolean);
    return { env, hooksDir, gitConfig, refusals, checkouts, cleanup };
  } catch (e) {
    await cleanup();
    throw e;
  }
}

const readIfExists = (path: string): Promise<string> =>
  readFile(path, "utf8").catch((e: NodeJS.ErrnoException) => (e.code === "ENOENT" ? "" : Promise.reject(e)));

/** Append entries after any GIT_CONFIG_COUNT entries already in `env`, so both the user's and ours apply (ours last). */
export function appendGitConfig(env: NodeJS.ProcessEnv, entries: readonly (readonly [string, string])[]): NodeJS.ProcessEnv {
  const raw = env.GIT_CONFIG_COUNT;
  if (raw !== undefined && raw !== "" && !/^\d+$/.test(raw)) {
    throw new Error(`GIT_CONFIG_COUNT is "${raw}", not a number; git would refuse to run with it`);
  }
  const start = raw ? Number(raw) : 0;
  const added = Object.fromEntries(
    entries.flatMap(([key, value], i) => [
      [`GIT_CONFIG_KEY_${start + i}`, key],
      [`GIT_CONFIG_VALUE_${start + i}`, value],
    ]),
  );
  return { ...env, ...added, GIT_CONFIG_COUNT: String(start + entries.length) };
}

function mirrorEntries(mirrors: readonly MirrorMapping[]): [string, string][] {
  return mirrors.flatMap((m) => {
    if (/[\n\r\0]/.test(m.mirror)) throw new Error("mirror path contains a line break");
    const base = mirrorUrl(m.mirror);
    return m.urls.map((u): [string, string] => [`url.${base}.insteadOf`, u]);
  });
}

/** A file:// URL git accepts for a local repository; file:// (not a bare path) keeps `--depth` working. */
export function mirrorUrl(path: string): string {
  return process.platform === "win32" ? pathToFileURL(path).href : `file://${path}`;
}

function mergeApproved(existing: string | undefined, added: readonly string[]): string {
  const all = [...(existing ?? "").split(/[\s,]+/), ...added].map((s) => s.trim().toLowerCase()).filter((s) => /^[0-9a-f]{40}$/.test(s));
  return [...new Set(all)].join(" ");
}

export type PreviousHooks = { readonly kind: "dir"; readonly path: string } | { readonly kind: "relative" } | { readonly kind: "default" };

/**
 * The hooks directory git would have used without us, from system, global, and env config only
 * (queried from our empty temp dir). Relative paths are not chained: they resolve inside each
 * checkout, so chaining them would run hooks shipped by the repository we are vetting.
 */
async function previousHooksPath(baseEnv: NodeJS.ProcessEnv, cwd: string, timeoutMs: number): Promise<PreviousHooks> {
  const { GIT_DIR: _dir, GIT_WORK_TREE: _tree, GIT_COMMON_DIR: _common, ...env } = baseEnv;
  try {
    const { stdout } = await runProgram("git", ["config", "--type=path", "--get", "core.hooksPath"], {
      cwd,
      env: { ...env, GIT_CEILING_DIRECTORIES: dirname(cwd) },
      timeoutMs,
    });
    const value = stdout.trim();
    if (!value) return { kind: "default" };
    return isAbsolute(value) ? { kind: "dir", path: resolve(value) } : { kind: "relative" };
  } catch (e) {
    // Exit 1 means "not set"; a missing git means nothing will check out anyway.
    if (e instanceof ProgramError) return { kind: "default" };
    throw e;
  }
}

/** POSIX single-quoting: safe for any string, including quotes and newlines. */
export function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/**
 * The hook. The scanner runs first, from the hooks directory: the checkout is untrusted, and
 * runtimes read config from their working directory (bun: bunfig.toml preloads, .env). Only when
 * the scan passes does the hook git would otherwise have run get to see the checkout.
 */
export function postCheckoutScript(runtime: GuardRuntime, previous: PreviousHooks, hooksDir: string): string {
  return [
    "#!/bin/sh",
    "# skill-scanner guard: every checkout is scanned before anything uses it; a non-zero exit fails it.",
    "# Generated for one guarded command and removed when that command exits.",
    "dir=$(pwd -P) || exit 1",
    'gitdir=$(git rev-parse --absolute-git-dir) || gitdir=""',
    `(cd ${shellQuote(hooksDir)} && exec ${shellQuote(runtime.node)} ${shellQuote(runtime.script)} hook git-post-checkout --dir "$dir" --git-dir "$gitdir" "$@") || exit $?`,
    ...chainLines(previous, "post-checkout", 'exec "$prev" "$@"'),
    "exit 0",
    "",
  ].join("\n");
}

/**
 * The update gate. Git feeds `<old> <new> <ref>` lines on stdin and the state as `$1`. Only the
 * `prepared` and `aborted` calls that move an existing HEAD, branch, or remote-tracking branch to
 * another commit reach the scanner (clones create refs, and are scanned by post-checkout). A
 * non-zero exit in `prepared` aborts the transaction. The previous hook, if any, then gets the
 * same input.
 */
export function referenceTransactionScript(runtime: GuardRuntime, previous: PreviousHooks, hooksDir: string): string {
  return [
    "#!/bin/sh",
    "# skill-scanner guard: a checked-out branch (or its upstream) only moves to a commit that passed the scan.",
    "# Generated for one guarded command and removed when that command exits.",
    "input=$(cat)",
    'case "$1" in',
    "prepared|aborted)",
    "  moves=$(printf '%s\\n' \"$input\" | grep -E '^[0-9a-f]{40,64} [0-9a-f]{40,64} (HEAD|refs/heads/.+|refs/remotes/.+)$' | grep -vE '^0+ |^[0-9a-f]+ 0+ ')",
    '  if [ -n "$moves" ]; then',
    "    dir=$(pwd -P) || exit 1",
    '    gitdir=$(git rev-parse --absolute-git-dir) || gitdir=""',
    `    printf '%s\\n' "$moves" | (cd ${shellQuote(hooksDir)} && exec ${shellQuote(runtime.node)} ${shellQuote(runtime.script)} hook git-reference-transaction --dir "$dir" --git-dir "$gitdir" "$1") || { code=$?; [ "$1" = prepared ] && exit $code; }`,
    "  fi",
    "  ;;",
    "esac",
    ...chainLines(previous, "reference-transaction", `{ [ -z "$input" ] || printf '%s\\n' "$input"; } | "$prev" "$@"; exit $?`),
    "exit 0",
    "",
  ].join("\n");
}

/** Runs `invoke` on the hook git would have run without us (`$prev`), if there is one. */
function chainLines(previous: PreviousHooks, hook: string, invoke: string): string[] {
  if (previous.kind === "relative") return ["# A relative core.hooksPath is not chained: it would run hooks shipped inside the checkout."];
  const locate =
    previous.kind === "dir"
      ? [`prev=${shellQuote(join(previous.path, hook))}`]
      : [
          `# No core.hooksPath configured: run the repository's own ${hook} (clones never bring hooks along).`,
          'common=$(git rev-parse --git-common-dir 2>/dev/null) || common=""',
          'prev=""',
          `if [ -n "$common" ]; then prev="$common/hooks/${hook}"; fi`,
        ];
  return [...locate, `if [ -n "$prev" ] && [ -f "$prev" ] && [ -x "$prev" ]; then ${invoke}; fi`];
}

/** A shell command that runs `command` under `skill-scanner guard`, for hooks that rewrite commands. */
export function guardCommandLine(runtime: GuardRuntime, command: string): string {
  return `${shellQuote(runtime.node)} ${shellQuote(runtime.script)} guard -- sh -c ${shellQuote(command)}`;
}

/** The runtime executing this process: node (or bun) and the CLI script it was started with. */
export function currentRuntime(): GuardRuntime {
  return { node: process.execPath, script: resolve(process.argv[1] ?? "") };
}
