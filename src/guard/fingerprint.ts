import { createHash } from "node:crypto";
import type { Dirent, Stats } from "node:fs";
import { lstat, readdir } from "node:fs/promises";
import { join } from "node:path";

/**
 * A cheap change detector for a skill directory: relative paths, sizes, modes, and times of every
 * entry, without reading contents. `ctime` is included because it cannot be set back by a user
 * process, so `touch -r` does not hide an edit. Directories `collect` skips are skipped here too.
 */

const SKIP_DIRS = new Set([".git", "node_modules", ".venv", "venv", "__MACOSX"]);
/** Claude Code bookkeeping inside plugin versions that changes on every session. */
export const PLUGIN_MARKERS: ReadonlySet<string> = new Set([".in_use", ".orphaned_at"]);

export interface FingerprintOptions {
  /** Names ignored at the top level only. */
  readonly ignoreTop?: ReadonlySet<string>;
  readonly maxEntries?: number;
  readonly maxDepth?: number;
}

export async function statFingerprint(dir: string, opts: FingerprintOptions = {}): Promise<string> {
  const lines: string[] = [];
  const max = opts.maxEntries ?? 20_000;
  const maxDepth = opts.maxDepth ?? 16;
  const visit = async (abs: string, rel: string, depth: number): Promise<void> => {
    if (depth > maxDepth || lines.length >= max) return;
    let entries: Dirent[];
    try {
      entries = (await readdir(abs, { withFileTypes: true })).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    } catch {
      lines.push(`${rel}\0unreadable`);
      return;
    }
    const kept = entries.filter((e) => !(depth === 0 && opts.ignoreTop?.has(e.name)));
    const stats = await Promise.all(kept.map((e) => lstat(join(abs, e.name)).catch(() => undefined)));
    for (let k = 0; k < kept.length; k += 1) {
      const name = kept[k]!.name;
      const st = stats[k];
      const r = rel ? `${rel}/${name}` : name;
      if (!st) continue;
      if (st.isDirectory()) {
        if (SKIP_DIRS.has(name)) lines.push(`${r}\0skipped`);
        else await visit(join(abs, name), r, depth + 1);
      } else lines.push(entryLine(r, st));
    }
  };
  await visit(dir, "", 0);
  return createHash("sha256").update(lines.join("\n")).digest("hex");
}

/** Whole milliseconds: Node and Bun report sub-millisecond times differently, and hooks may run on either. */
function entryLine(rel: string, st: Stats): string {
  const type = st.isSymbolicLink() ? "l" : st.isFile() ? "f" : "o";
  return `${rel}\0${type}\0${st.size}\0${st.mode}\0${Math.trunc(st.mtimeMs)}\0${Math.trunc(st.ctimeMs)}\0${st.ino}`;
}
