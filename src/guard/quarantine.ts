import { cp, lstat, mkdir, readdir, readlink, realpath, rename, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { scannerPaths } from "../paths";
import { exists, homeOf, isInside, isRecord, readJsonFile } from "./fsutil";
import { skillRoots } from "./locations";
import type { QuarantineRecord, SkillRoot } from "./types";

/**
 * Quarantine moves a skill's real directory aside (never deletes it), removes every symlink in a
 * known skill root that pointed at it, and records enough to put everything back.
 */

export const QUARANTINE_RECORD = ".skill-scanner-quarantine.json";
const ID = /^[A-Za-z0-9._@+-]+$/;

export interface QuarantineOptions {
  /** Roots swept for symlinks to the quarantined directory. Default: every harness root for `cwd`. */
  readonly roots?: readonly SkillRoot[];
  readonly cwd?: string;
  readonly digest?: string;
  readonly now?: () => Date;
}

export async function quarantineSkill(
  path: string,
  reason: string,
  env: NodeJS.ProcessEnv,
  opts: QuarantineOptions = {},
): Promise<QuarantineRecord> {
  const found = resolve(path);
  const foundStat = await lstat(found);
  const real = await realpath(found);
  const roots = opts.roots ?? skillRoots("all", opts.cwd ?? homeOf(env), env);
  refuseDangerous(real, roots, env);
  const paths = scannerPaths(env);
  await mkdir(paths.quarantine, { recursive: true, mode: 0o700 });
  const now = opts.now?.() ?? new Date();
  const id = await freeId(paths.quarantine, `${now.toISOString().replace(/[:.]/g, "-")}-${safeName(basename(real))}`);
  const dir = join(paths.quarantine, id);
  const links = await linksTo(real, roots, foundStat.isSymbolicLink() ? found : undefined);
  await moveDir(real, dir);
  for (const l of links) await unlink(l.path).catch(() => undefined);
  const record: QuarantineRecord = {
    id,
    originalPath: found,
    realPath: real,
    digest: opts.digest ?? "",
    reason,
    quarantinedAt: now.toISOString(),
    links,
    dir,
  };
  await writeFile(join(dir, QUARANTINE_RECORD), `${JSON.stringify(record, null, 2)}\n`, { mode: 0o600 });
  return record;
}

/** Never move a root, a home directory, or the scanner's own state. */
function refuseDangerous(real: string, roots: readonly SkillRoot[], env: NodeJS.ProcessEnv): void {
  const home = homeOf(env);
  const scannerHome = scannerPaths(env).home;
  if (real === "/" || real === home || isInside(real, home) || isInside(scannerHome, real) || roots.some((r) => r.path === real)) {
    throw new Error(`refusing to quarantine ${real}: not a skill directory`);
  }
}

async function freeId(parent: string, base: string): Promise<string> {
  for (let n = 1; n < 1000; n += 1) {
    const id = n === 1 ? base : `${base}-${n}`;
    if (!(await exists(join(parent, id)))) return id;
  }
  throw new Error(`cannot find a free quarantine name for ${base}`);
}

const safeName = (name: string): string => name.replace(/[^A-Za-z0-9._@+-]/g, "_").slice(0, 80) || "skill";

/** Symlinks directly inside skill roots (and the found path itself) that resolve to `real`. */
async function linksTo(real: string, roots: readonly SkillRoot[], found: string | undefined): Promise<{ path: string; target: string }[]> {
  const candidates = new Set<string>(found ? [found] : []);
  for (const r of roots.filter((x) => x.kind === "skills")) {
    for (const name of await readdir(r.path).catch(() => [] as string[])) candidates.add(join(r.path, name));
  }
  const out: { path: string; target: string }[] = [];
  for (const p of candidates) {
    const st = await lstat(p).catch(() => undefined);
    if (!st?.isSymbolicLink()) continue;
    const resolved = await realpath(p).catch(() => undefined);
    if (resolved === real) out.push({ path: p, target: await readlink(p) });
  }
  return out;
}

async function moveDir(from: string, to: string): Promise<void> {
  try {
    await rename(from, to);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "EXDEV") throw e;
    // Different file systems: copy, then remove the original only once the copy is complete.
    await cp(from, to, { recursive: true, verbatimSymlinks: true, errorOnExist: true, force: false });
    await rm(from, { recursive: true, force: true });
  }
}

function parseRecord(raw: unknown): QuarantineRecord | undefined {
  if (!isRecord(raw)) return undefined;
  const ok =
    ["id", "originalPath", "realPath", "reason", "quarantinedAt"].every((k) => typeof raw[k] === "string") && Array.isArray(raw.links);
  return ok ? (raw as unknown as QuarantineRecord) : undefined;
}

export async function listQuarantine(env: NodeJS.ProcessEnv): Promise<QuarantineRecord[]> {
  const root = scannerPaths(env).quarantine;
  const out: QuarantineRecord[] = [];
  for (const id of await readdir(root).catch(() => [] as string[])) {
    const rec = await readJsonFile(join(root, id, QUARANTINE_RECORD), parseRecord);
    if (rec) out.push({ ...rec, id, dir: join(root, id) });
  }
  return out.sort((a, b) => a.quarantinedAt.localeCompare(b.quarantinedAt));
}

/** Put a quarantined skill back where it was, with its symlinks. Refuses when anything is in the way. */
export async function restoreQuarantined(id: string, env: NodeJS.ProcessEnv): Promise<QuarantineRecord> {
  if (!ID.test(id) || id === "." || id === "..") throw new Error(`invalid quarantine id: ${id}`);
  const dir = join(scannerPaths(env).quarantine, id);
  const rec = await readJsonFile(join(dir, QUARANTINE_RECORD), parseRecord);
  if (!rec) throw new Error(`no quarantined skill with id ${id}`);
  if (await exists(rec.realPath)) throw new Error(`${rec.realPath} exists again; move it away before restoring`);
  for (const l of rec.links) if (await exists(l.path)) throw new Error(`${l.path} exists again; move it away before restoring`);
  await mkdir(dirname(rec.realPath), { recursive: true });
  await moveDir(dir, rec.realPath);
  await rm(join(rec.realPath, QUARANTINE_RECORD), { force: true });
  for (const l of rec.links) {
    await mkdir(dirname(l.path), { recursive: true });
    await symlink(l.target, l.path);
  }
  return { ...rec, id, dir };
}
