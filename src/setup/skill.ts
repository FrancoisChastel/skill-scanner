import { isUtf8 } from "node:buffer";
import { readdir, readFile } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import { type FileOp, writeOp } from "./ops";

/** `--with-skill` copies the bundled `skills/skill-scanner` so agents know how to scan before installing. */
export const SKILL_NAME = "skill-scanner";
/** Present in every copy setup made, so uninstall removes only those. */
export const SKILL_MARKER = "INSTALLED-BY-SKILL-SCANNER.txt";
const MARKER_TEXT = "Installed by `skill-scanner setup --with-skill`. `skill-scanner setup --uninstall` removes this directory.\n";

export interface TreeFile {
  /** POSIX path relative to the tree root. */
  readonly rel: string;
  readonly text: string;
}

/** Every regular file under `dir`, as text; undefined when `dir` does not exist. Symlinks are not followed. */
export async function readTree(dir: string): Promise<TreeFile[] | undefined> {
  const out: TreeFile[] = [];
  const walk = async (d: string): Promise<void> => {
    for (const entry of await readdir(d, { withFileTypes: true })) {
      const full = join(d, entry.name);
      if (entry.isDirectory()) await walk(full);
      else if (entry.isFile()) {
        const bytes = await readFile(full);
        if (!isUtf8(bytes)) throw new Error(`${full} is not a text file; the bundled skill must be text only`);
        out.push({ rel: relative(dir, full).split(sep).join("/"), text: bytes.toString("utf8") });
      }
    }
  };
  try {
    await walk(dir);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw e;
  }
  return out.sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0));
}

export interface SkillPlan {
  readonly ops: readonly FileOp[];
  readonly warnings: readonly string[];
}

/** Make `targetDir` an exact copy of `source` plus the marker. A directory setup did not create is left alone. */
export function planSkillCopy(targetDir: string, source: readonly TreeFile[], target: readonly TreeFile[] | undefined): SkillPlan {
  if (target !== undefined && !target.some((f) => f.rel === SKILL_MARKER))
    return { ops: [], warnings: [`${targetDir} already exists and was not installed by setup; left as is.`] };
  const current = new Map((target ?? []).map((f) => [f.rel, f.text]));
  const wanted = [...source.filter((f) => f.rel !== SKILL_MARKER), { rel: SKILL_MARKER, text: MARKER_TEXT }];
  const verb = target === undefined ? "add" : "update";
  const writes = wanted.flatMap((f) => {
    const op = writeOp(join(targetDir, ...f.rel.split("/")), current.get(f.rel), f.text, `${verb} ${SKILL_NAME} skill`);
    return op ? [op] : [];
  });
  const keep = new Set(wanted.map((f) => f.rel));
  const removals: FileOp[] = (target ?? [])
    .filter((f) => !keep.has(f.rel))
    .map((f) => ({ kind: "remove", path: join(targetDir, ...f.rel.split("/")), before: f.text, summary: "no longer in the skill" }));
  return { ops: [...writes, ...removals], warnings: [] };
}

export function planSkillRemove(targetDir: string, target: readonly TreeFile[] | undefined): SkillPlan {
  if (target === undefined || !target.some((f) => f.rel === SKILL_MARKER)) return { ops: [], warnings: [] };
  return { ops: [{ kind: "remove-dir", path: targetDir, summary: `remove the ${SKILL_NAME} skill copy` }], warnings: [] };
}
