/**
 * Source resolution, fetching, and install gating for skills named the way `npx skills add`,
 * `pi install`, and Codex's skill-installer name them.
 */
import type { ScanReport } from "../core/types";
import { type ScanOptions, scanPath } from "../scan";
import { fetchSource } from "./fetch";
import { parseSource } from "./parse";
import { onlySkillBundles, restrictToSkills } from "./select";
import type { FetchedSource, FetchOptions } from "./types";

export { redactCredentials, SourceError, TarError, UnsupportedSourceError } from "./errors";
export { DEFAULT_FETCH_TIMEOUT_MS, fetchSource } from "./fetch";
export {
  APPROVED_COMMITS_ENV,
  appendGitConfig,
  currentRuntime,
  DEAD_DOWNLOAD_URL,
  GUARD_SCOPE_ENV,
  GUARD_STATE_ENV,
  type GuardEnv,
  type GuardEnvOptions,
  type GuardRuntime,
  guardCommandLine,
  guardEnv,
  type MirrorMapping,
  mirrorUrl,
  shellQuote,
} from "./guard-env";
export { parseSource } from "./parse";
export { runPostCheckout } from "./post-checkout";
export { onlySkillBundles, restrictToSkills, scanGaps } from "./select";
export type { FetchedSource, FetchOptions, SourceKind, SourceSpec } from "./types";
export { cloneUrlVariants } from "./urls";

/** Whether a positional looks like a remote source rather than a local path. */
export function isRemoteSource(raw: string): boolean {
  return (
    /^(?:[\w.-]+\/[\w.-]+(?:[/@#].*)?|https?:\/\/|git@|ssh:\/\/|git:|file:\/\/|github:|gitlab:|npm:)/.test(raw) &&
    !raw.startsWith("./") &&
    !raw.startsWith("/")
  );
}

export interface SourceScan {
  readonly report: ScanReport;
  readonly fetched: FetchedSource;
}

export interface InstallScope {
  /** Gate only on skill directories, as `npx skills` copies nothing else. */
  readonly skillBundlesOnly?: boolean;
}

export type SourceScanOptions = ScanOptions & FetchOptions & InstallScope & { readonly cwd: string; readonly keep?: boolean };

/**
 * Parse, fetch, and scan. The scan covers the skills named in the source (`owner/repo@skill`)
 * plus `onlySkills`. With `keep: false` the fetched copy is removed before returning, so
 * `fetched.dir` no longer exists; otherwise (the default) the caller must call `fetched.cleanup()`.
 */
export async function scanSource(raw: string, opts: SourceScanOptions): Promise<SourceScan> {
  const { cwd, keep = true, timeoutMs, env, ...scanOpts } = opts;
  const spec = parseSource(raw, cwd, env ?? process.env);
  const fetched = await fetchSource(spec, {
    ...(opts.signal ? { signal: opts.signal } : {}),
    ...(timeoutMs !== undefined ? { timeoutMs } : {}),
    ...(env ? { env } : {}),
  });
  try {
    const report = await scanFetched(fetched, scanOpts);
    if (!keep) await fetched.cleanup();
    return { report, fetched };
  } catch (e) {
    await fetched.cleanup();
    throw e;
  }
}

/**
 * Scan an already fetched source, reporting on the skills it names plus `opts.onlySkills`. The
 * whole source is scanned; the report then keeps every skill that may match a requested name
 * (see select.ts), since the installer's frontmatter parser may read names differently from ours.
 */
export async function scanFetched(fetched: FetchedSource, opts: ScanOptions & InstallScope = {}): Promise<ScanReport> {
  const onlySkills = unionSkills(fetched.spec.skills, opts.onlySkills);
  const { onlySkills: _ignored, skillBundlesOnly, ...rest } = opts;
  const report = await scanPath(fetched.dir, { ...rest, label: opts.label ?? fetched.spec.display });
  const selected = onlySkills ? restrictToSkills(report, onlySkills) : report;
  return skillBundlesOnly ? onlySkillBundles(selected) : selected;
}

/** Undefined means every skill: when neither side restricts, or either side asks for `*`. */
export function unionSkills(a: readonly string[] | undefined, b: readonly string[] | undefined): readonly string[] | undefined {
  if (!a?.length && !b?.length) return undefined;
  const all = [...(a ?? []), ...(b ?? [])];
  if (all.includes("*")) return undefined;
  return [...new Set(all)];
}
