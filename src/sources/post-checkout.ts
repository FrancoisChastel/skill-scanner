import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import type { CliIO } from "../cli/io";
import { redactCredentials } from "./errors";
import { runProgram } from "./exec";
import { git } from "./git";
import { APPROVED_COMMITS_ENV, CHECKOUTS_FILE, REFUSALS_FILE } from "./guard-env";
import { type GitHookDeps, hookGitEnv, isApproved, PASSED_FILE, record, scanForGitHook } from "./hook-scan";

/**
 * The git `post-checkout` hook installed by `skill-scanner guard` (and `add`). Git runs the hook
 * script inside the new checkout with `<prev-head> <new-head> <branch-flag>`; the script moves out
 * of it and calls `skill-scanner hook git-post-checkout --dir <checkout> --git-dir <its .git> <args>`. A non-zero exit
 * fails the checkout, and the skills CLI, `pi install`, or `git clone` with it. It only runs where
 * the user asked for protection, so any failure to scan refuses the checkout (fail closed). A
 * refused switch inside an existing repository (`git checkout <tag>`) is switched back.
 */

const GIT_TIMEOUT_MS = 30_000;
const ZERO_OID = /^0+$/;
const OID = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;
/** Operations that check out as they go; switching back in the middle of one would leave it broken. */
const IN_PROGRESS = ["rebase-merge", "rebase-apply", "MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "BISECT_LOG"];

export async function runPostCheckout(argv: readonly string[], io: CliIO, deps: GitHookDeps = {}): Promise<number> {
  const { dir, gitDir, args } = splitDir(argv, io.cwd);
  const [prev = "", head = "", flag = ""] = args.map((a) => a.toLowerCase());
  const repo: Checkout = { dir, gitDir, env: hookGitEnv(io.env) };
  try {
    if (isApproved(head, io.env[APPROVED_COMMITS_ENV])) {
      io.stderr(`skill-scanner: commit ${head.slice(0, 12)} was scanned before this install; allowed\n`);
      await record(io, CHECKOUTS_FILE, `${head} approved\n`);
      return 0;
    }
    // A branch switch that stays on the same commit (`git checkout -b topic`) brings nothing new.
    if (flag === "1" && OID.test(head) && !ZERO_OID.test(head) && prev === head) return 0;
    const scanned = await scanForGitHook(dir, await originOf(gitDir, repo.env), io, deps);
    io.stderr(scanned.summary);
    await record(io, CHECKOUTS_FILE, `${head || "-"} ${scanned.refusal ? "refused" : scanned.report.verdict}\n`);
    if (!scanned.refusal) {
      if (flag === "1") await rememberPassed(repo, head, io);
      return 0;
    }
    io.stderr(`skill-scanner: checkout refused: ${scanned.refusal}. Ask the user before retrying without the guard.\n`);
    await record(io, REFUSALS_FILE, scanned.summary);
    await switchBack(repo, prev, head, flag, io);
    return 1;
  } catch (e) {
    const why = `skill-scanner: cannot scan ${dir} (${e instanceof Error ? e.message : String(e)}); refusing it.\n`;
    io.stderr(why);
    await record(io, CHECKOUTS_FILE, `${head || "-"} error\n`);
    await record(io, REFUSALS_FILE, why);
    await switchBack(repo, prev, head, flag, io);
    return 1;
  }
}

/** The checkout and its repository, named explicitly so git's own variables cannot point our calls elsewhere. */
interface Checkout {
  readonly dir: string;
  readonly gitDir: string;
  readonly env: NodeJS.ProcessEnv;
}

/** `--dir <checkout> [--git-dir <dir>]` from the hook script; without them (a direct call), the working directory. */
function splitDir(argv: readonly string[], cwd: string): { dir: string; gitDir: string; args: readonly string[] } {
  let rest = argv;
  let dir = cwd;
  let gitDir = "";
  if (rest[0] === "--dir" && rest[1] !== undefined) [dir, rest] = [resolve(cwd, rest[1]), rest.slice(2)];
  if (rest[0] === "--git-dir" && rest[1] !== undefined) [gitDir, rest] = [rest[1] ? resolve(cwd, rest[1]) : "", rest.slice(2)];
  return { dir, gitDir: gitDir || join(dir, ".git"), args: rest };
}

/** git with the repository and working tree named on the command line, which outranks the environment. */
function inCheckout(c: Checkout, args: readonly string[], timeoutMs = GIT_TIMEOUT_MS): Promise<string> {
  return git(["--git-dir", c.gitDir, "--work-tree", c.dir, ...args], { env: c.env, timeoutMs, cwd: c.dir });
}

/** Record the checked-out tree, so the reference-transaction hook does not scan it again. */
async function rememberPassed(repo: Checkout, head: string, io: CliIO): Promise<void> {
  if (!OID.test(head)) return;
  try {
    const tree = (await inCheckout(repo, ["rev-parse", "--verify", `${head}^{tree}`])).trim();
    if (OID.test(tree)) await record(io, PASSED_FILE, `${tree}\n`);
  } catch {
    // Only an optimisation: the tree is scanned again if something moves to it.
  }
}

/**
 * A refused branch switch in a repository that already existed goes back to where it was, so the
 * refused files are not left for the next session to load. Clones and new worktrees (no previous
 * HEAD) have nothing to go back to; `guard` reports them instead.
 */
async function switchBack(repo: Checkout, prev: string, head: string, flag: string, io: CliIO): Promise<void> {
  if (flag !== "1" || !OID.test(prev) || ZERO_OID.test(prev) || prev === head) return;
  const { dir, gitDir } = repo;
  try {
    if (IN_PROGRESS.some((f) => existsSync(join(gitDir, f)))) return;
    // Hooks off: nothing needs scanning on the way back, and this must not recurse into the guard.
    await runProgram("git", ["-c", "core.hooksPath=/dev/null", "--git-dir", gitDir, "--work-tree", dir, "checkout", "--quiet", "-"], {
      env: repo.env,
      cwd: dir,
      timeoutMs: GIT_TIMEOUT_MS,
    });
    const note = `skill-scanner: switched ${dir} back to what was checked out before (${prev.slice(0, 12)}).\n`;
    io.stderr(note);
    await record(io, REFUSALS_FILE, note);
  } catch (e) {
    const note = `skill-scanner: could not switch ${dir} back (${e instanceof Error ? e.message : String(e)}); the refused files are checked out.\n`;
    io.stderr(note);
    await record(io, REFUSALS_FILE, note);
  }
}

/** The remote a repository came from (as the user named it, before insteadOf), else its path. */
export async function originOf(gitDir: string, env: NodeJS.ProcessEnv): Promise<string> {
  const fallback = gitDir.replace(/[\\/]\.git$/, "");
  try {
    const url = (await git(["--git-dir", gitDir, "config", "--get", "remote.origin.url"], { env, timeoutMs: 5_000 })).trim();
    return url ? redactCredentials(url) : fallback;
  } catch {
    return fallback;
  }
}
