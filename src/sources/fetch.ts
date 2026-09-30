import { mkdtemp, realpath, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { SourceError, UnsupportedSourceError } from "./errors";
import { cloneRepo } from "./git";
import { fetchNpmPackage } from "./npm";
import { sanitizeSubpath } from "./parse";
import type { FetchedSource, FetchOptions, SourceSpec } from "./types";

export const DEFAULT_FETCH_TIMEOUT_MS = 120_000;

/** Fetch a source for scanning. Local paths are scanned in place; remote ones land in a fresh temp directory. */
export async function fetchSource(spec: SourceSpec, opts: FetchOptions = {}): Promise<FetchedSource> {
  switch (spec.kind) {
    case "local":
      return fetchLocal(spec);
    case "git":
    case "npm":
      return fetchIntoTemp(spec, opts);
    case "url":
      throw new UnsupportedSourceError(
        `${spec.display}: direct URLs (archives, raw SKILL.md files, well-known endpoints) are not fetched by skill-scanner. ` +
          "Download it yourself and run `skill-scanner scan <path>` on the result.",
      );
  }
}

async function fetchLocal(spec: SourceSpec): Promise<FetchedSource> {
  const path = spec.path;
  if (!path) throw new SourceError(`${spec.display}: local source without a path`);
  try {
    await stat(path);
  } catch {
    throw new SourceError(`${spec.display}: no such file or directory`);
  }
  return { spec, dir: path, root: path, cleanup: async () => {} };
}

async function fetchIntoTemp(spec: SourceSpec, opts: FetchOptions): Promise<FetchedSource> {
  const work = await mkdtemp(join(tmpdir(), "skill-scanner-src-"));
  const cleanup = onceCleanup(work);
  const env = opts.env ?? process.env;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;
  const signal = opts.signal ? { signal: opts.signal } : {};
  try {
    if (spec.kind === "npm") {
      if (!spec.packageSpec) throw new SourceError(`${spec.display}: npm source without a package spec`);
      const pkg = await fetchNpmPackage(spec.packageSpec, work, spec.display, { env, timeoutMs, ...signal });
      return { spec, dir: pkg.root, root: pkg.root, ...(pkg.resolved ? { resolved: pkg.resolved } : {}), cleanup };
    }
    if (!spec.cloneUrl) throw new SourceError(`${spec.display}: git source without a clone URL`);
    const checkout = join(work, "repo");
    const commit = await cloneRepo(spec.cloneUrl, checkout, spec.ref, spec.display, { env, timeoutMs, ...signal });
    const root = await realpath(checkout);
    const dir = await resolveInside(root, spec.subpath, spec.display);
    return { spec, dir, root, commit, cleanup };
  } catch (e) {
    await cleanup();
    throw e;
  }
}

/** `root/subpath`, refusing anything that resolves outside `root` (a `..`, or a symlink in the checkout). */
export async function resolveInside(root: string, subpath: string | undefined, label: string): Promise<string> {
  const clean = subpath === undefined ? undefined : sanitizeSubpath(subpath);
  if (!clean) return root;
  let real: string;
  try {
    real = await realpath(join(root, clean));
  } catch {
    throw new SourceError(`${label}: "${clean}" does not exist in the source`);
  }
  const rel = relative(root, real);
  if (rel === ".." || rel.startsWith(`..${sep}`) || rel.startsWith("/") || /^[a-zA-Z]:/.test(rel)) {
    throw new SourceError(`${label}: "${clean}" resolves outside the source (symlink?)`);
  }
  if (!(await stat(real)).isDirectory()) throw new SourceError(`${label}: "${clean}" is not a directory`);
  return real;
}

/** Remove a temp directory; safe to call more than once and concurrently. */
function onceCleanup(dir: string): () => Promise<void> {
  let done: Promise<void> | undefined;
  return () => {
    done ??= rm(dir, { recursive: true, force: true, maxRetries: 3 });
    return done;
  };
}
