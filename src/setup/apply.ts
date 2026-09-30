import { randomBytes } from "node:crypto";
import { chmod, constants, copyFile, lstat, mkdir, realpath, rename, rm, stat, unlink, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { BACKUP_SUFFIX, type FileOp } from "./ops";
import { readText } from "./runtime";

export interface ApplyResult {
  readonly applied: readonly FileOp[];
  /** Backups created by this run (existing backups are never overwritten). */
  readonly backups: readonly string[];
  readonly failed?: { readonly op: FileOp; readonly error: string };
}

/**
 * Perform planned changes in order and stop at the first failure. Each write re-reads the file and
 * refuses if it changed since planning, backs it up once, and lands atomically (temp file + rename).
 */
export async function applyOps(ops: readonly FileOp[]): Promise<ApplyResult> {
  const applied: FileOp[] = [];
  const backups: string[] = [];
  for (const op of ops) {
    try {
      const backup = await applyOne(op);
      if (backup) backups.push(backup);
      applied.push(op);
    } catch (e) {
      return { applied, backups, failed: { op, error: e instanceof Error ? e.message : String(e) } };
    }
  }
  return { applied, backups };
}

async function applyOne(op: FileOp): Promise<string | undefined> {
  if (op.kind === "remove-dir") {
    await rm(op.path, { recursive: true, force: true });
    return undefined;
  }
  // Write through a symlink (dotfile managers link settings files) instead of replacing the link.
  const target = await followLink(op.path);
  const current = await readText(target);
  if (current !== op.before) throw new Error(`${op.path} changed after setup read it; re-run setup`);
  if (op.kind === "remove") {
    await unlink(target);
    return undefined;
  }
  const backup = op.backup && current !== undefined ? await backupOnce(target, `${op.path}${BACKUP_SUFFIX}`) : undefined;
  const mode = op.mode ?? (current !== undefined ? (await stat(target)).mode & 0o777 : 0o644);
  await atomicWrite(target, op.after, mode);
  return backup;
}

async function followLink(path: string): Promise<string> {
  const st = await lstat(path).catch(() => undefined);
  if (!st?.isSymbolicLink()) return path;
  try {
    return await realpath(path);
  } catch {
    throw new Error(`${path} is a symlink to a file that does not exist; fix or remove the link`);
  }
}

/** Copy `source` to `backup` unless a backup already exists: the first backup holds the pre-setup state. */
async function backupOnce(source: string, backup: string): Promise<string | undefined> {
  try {
    await copyFile(source, backup, constants.COPYFILE_EXCL);
    return backup;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "EEXIST") return undefined;
    throw e;
  }
}

export async function atomicWrite(path: string, text: string, mode: number): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const tmp = join(dirname(path), `.${basename(path)}.${process.pid}-${randomBytes(4).toString("hex")}.tmp`);
  try {
    await writeFile(tmp, text, { mode });
    await chmod(tmp, mode);
    await rename(tmp, path);
  } catch (e) {
    await rm(tmp, { force: true });
    throw e;
  }
}
