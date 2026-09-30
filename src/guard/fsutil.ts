import { randomBytes } from "node:crypto";
import { lstat, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, isAbsolute, relative } from "node:path";

/** Small file-system helpers shared by the guard's state, audit, and quarantine code. */

export function homeOf(env: NodeJS.ProcessEnv): string {
  return env.HOME || env.USERPROFILE || homedir();
}

/** Whether `p` is `root` itself or somewhere below it. Both must be absolute and normalised. */
export function isInside(root: string, p: string): boolean {
  const rel = relative(root, p);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

export async function exists(p: string): Promise<boolean> {
  try {
    await lstat(p);
    return true;
  } catch {
    return false;
  }
}

/** Write a file so readers never see a partial one: temp file in the same directory, then rename. */
export async function writeFileAtomic(path: string, data: string, mode = 0o600): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
  try {
    await writeFile(tmp, data, { mode });
    await rename(tmp, path);
  } catch (e) {
    await rm(tmp, { force: true }).catch(() => undefined);
    throw e;
  }
}

const warned = new Set<string>();

/** One stderr line per file per process: state files are advisory, a corrupt one must not spam every hook. */
export function warnOnce(key: string, message: string): void {
  if (warned.has(key)) return;
  warned.add(key);
  process.stderr.write(`skill-scanner: ${message}\n`);
}

/**
 * Read and validate a JSON state file. Missing means undefined; unreadable or invalid content is
 * treated as missing, with a single warning.
 */
export async function readJsonFile<T>(path: string, validate: (raw: unknown) => T | undefined): Promise<T | undefined> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") warnOnce(path, `cannot read ${path}: ${(e as Error).message}`);
    return undefined;
  }
  try {
    const value = validate(JSON.parse(text));
    if (value === undefined) warnOnce(path, `ignoring ${path}: unexpected content`);
    return value;
  } catch (e) {
    warnOnce(path, `ignoring ${path}: ${(e as Error).message}`);
    return undefined;
  }
}

export const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

export const errorMessage = (e: unknown): string => (e instanceof Error ? e.message : String(e));

/** Run `fn` over `items` with at most `limit` in flight. */
export async function forEachLimit<T>(items: readonly T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < items.length) {
      const item = items[next]!;
      next += 1;
      await fn(item);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
}
