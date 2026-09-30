import { redactCredentials, SourceError } from "./errors";
import { lastLines, ProgramError, runProgram } from "./exec";

/**
 * Shallow clones of untrusted repositories. Nothing from the checkout ever runs: hooks are pointed
 * at /dev/null (a path that can never hold a hook; an empty value has had version-dependent
 * meanings), LFS filters are disabled like the skills CLI does, and prompts are off so a missing
 * credential fails instead of hanging.
 */

export interface GitOptions {
  readonly env: NodeJS.ProcessEnv;
  readonly timeoutMs: number;
  readonly signal?: AbortSignal;
}

/** Protocols git may use for our clones: the skills CLI's list. `ext::` and friends stay off. */
const ALLOWED_PROTOCOLS = "https:http:ssh:git:file";

const SAFE_CONFIG: readonly string[] = [
  "core.hooksPath=/dev/null",
  "core.fsmonitor=false",
  "advice.detachedHead=false",
  "filter.lfs.required=false",
  "filter.lfs.smudge=",
  "filter.lfs.clean=",
  "filter.lfs.process=",
];

export function gitEnv(base: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  return {
    ...base,
    GIT_TERMINAL_PROMPT: "0",
    GIT_ALLOW_PROTOCOL: ALLOWED_PROTOCOLS,
    GIT_LFS_SKIP_SMUDGE: "1",
    GCM_INTERACTIVE: "never",
  };
}

export async function git(args: readonly string[], opts: GitOptions & { readonly cwd?: string }): Promise<string> {
  const argv = [...SAFE_CONFIG.flatMap((c) => ["-c", c]), ...args];
  const { stdout } = await runProgram("git", argv, {
    env: gitEnv(opts.env),
    timeoutMs: opts.timeoutMs,
    ...(opts.cwd ? { cwd: opts.cwd } : {}),
    ...(opts.signal ? { signal: opts.signal } : {}),
  });
  return stdout;
}

export const isCommitSha = (ref: string): boolean => /^[0-9a-f]{40}$/i.test(ref);

/**
 * Clone `url` at `ref` (branch, tag, or full commit SHA) into `dest`, which must not exist.
 * Returns the checked-out commit. `label` names the source in errors instead of the URL, which
 * may carry credentials.
 */
export async function cloneRepo(url: string, dest: string, ref: string | undefined, label: string, opts: GitOptions): Promise<string> {
  if (/^-|^[a-z0-9+.-]+::/i.test(url)) throw new SourceError(`${label}: unsupported git URL`);
  try {
    if (ref && isCommitSha(ref)) await cloneAtCommit(url, dest, ref, opts);
    else await git(["clone", "--quiet", "--depth", "1", ...(ref ? ["--branch", ref] : []), "--", url, dest], opts);
    return (await git(["-C", dest, "rev-parse", "--verify", "HEAD"], opts)).trim();
  } catch (e) {
    throw new SourceError(`cannot clone ${label}${ref ? ` at ${ref}` : ""}: ${describeGitFailure(e)}`);
  }
}

/** `clone --branch` cannot take a SHA: fetch that one commit into an empty repository instead. */
async function cloneAtCommit(url: string, dest: string, sha: string, opts: GitOptions): Promise<void> {
  await git(["init", "--quiet", "--", dest], opts);
  await git(["-C", dest, "remote", "add", "origin", "--", url], opts);
  await git(["-C", dest, "fetch", "--quiet", "--depth", "1", "origin", sha], opts);
  await git(["-C", dest, "checkout", "--quiet", "--detach", "FETCH_HEAD"], opts);
}

function describeGitFailure(e: unknown): string {
  if (e instanceof ProgramError) {
    if (e.failure === "not-found") return "git is not installed or not on PATH";
    if (e.failure === "timeout") return "timed out";
    if (e.failure === "aborted") return "cancelled";
    const tail = lastLines(e.stderr);
    if (/could not read Username|Authentication failed|terminal prompts disabled|Permission denied|403/i.test(e.stderr)) {
      return `authentication failed or repository not found (${redactCredentials(tail)})`;
    }
    return redactCredentials(tail || e.message);
  }
  return redactCredentials(e instanceof Error ? e.message : String(e));
}
