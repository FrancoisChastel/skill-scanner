import { copyFile, link, lstat, mkdir, readdir } from "node:fs/promises";
import { join } from "node:path";

/**
 * A copy of a tree for a tool that would otherwise read configuration from it. Regular files are
 * hard-linked (copied when linking fails, e.g. across file systems); symlinks and special files are
 * left out, as the tools skip them anyway; nothing is followed out of the tree.
 */

export interface StageOptions {
  /** Whether to leave out an entry, by its POSIX path relative to the root. */
  readonly skip: (rel: string) => boolean;
  /** Files larger than this are left out (the tool would skip them). */
  readonly maxFileBytes: number;
  /** More entries than this is an error rather than a slow copy. */
  readonly maxEntries: number;
}

export async function stageTree(root: string, dest: string, opts: StageOptions): Promise<void> {
  let entries = 0;
  const walk = async (from: string, to: string, rel: string): Promise<void> => {
    await mkdir(to, { recursive: true });
    for (const e of await readdir(from, { withFileTypes: true })) {
      const childRel = rel ? `${rel}/${e.name}` : e.name;
      if (opts.skip(childRel)) continue;
      entries += 1;
      if (entries > opts.maxEntries) throw new Error(`the tree has more than ${opts.maxEntries} entries`);
      const src = join(from, e.name);
      const dst = join(to, e.name);
      if (e.isDirectory()) await walk(src, dst, childRel);
      else if (e.isFile() && (await lstat(src)).size <= opts.maxFileBytes) await link(src, dst).catch(() => copyFile(src, dst));
    }
  };
  await walk(root, dest, "");
}
