import { chmod, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

/** What to put at one path of a temporary skill tree. */
export type TreeEntry =
  | string
  | Uint8Array
  | { readonly symlink: string }
  | { readonly content: string | Uint8Array; readonly mode: number }
  | { readonly dir: true };

export interface SkillTree {
  /** Absolute path of the temporary root. */
  readonly root: string;
  /** Absolute path of a file inside the tree. */
  path(rel: string): string;
  cleanup(): Promise<void>;
}

/**
 * Build a temporary directory from a map of POSIX relative paths to contents. Parent directories
 * are created as needed. Call `cleanup()` (e.g. in `afterEach`) to remove it.
 *
 *   const tree = await makeSkillTree({ "SKILL.md": "---\nname: x\n---\n", "scripts/run.sh": { content: "echo", mode: 0o755 } });
 */
export async function makeSkillTree(files: Readonly<Record<string, TreeEntry>>): Promise<SkillTree> {
  const root = await mkdtemp(join(tmpdir(), "skill-scanner-test-"));
  for (const [rel, entry] of Object.entries(files)) {
    const abs = join(root, rel);
    await mkdir(dirname(abs), { recursive: true });
    if (typeof entry === "string" || entry instanceof Uint8Array) await writeFile(abs, entry);
    else if ("symlink" in entry) await symlink(entry.symlink, abs);
    else if ("dir" in entry) await mkdir(abs, { recursive: true });
    else {
      await writeFile(abs, entry.content);
      await chmod(abs, entry.mode);
    }
  }
  return {
    root,
    path: (rel: string) => join(root, rel),
    cleanup: () => rm(root, { recursive: true, force: true }),
  };
}

/** A minimal valid SKILL.md with the given name, description, and body. */
export function skillMd(body: string, fm: { name?: string; description?: string; extra?: string } = {}): string {
  const name = fm.name ?? "demo-skill";
  const description = fm.description ?? "Formats CSV files into Markdown tables.";
  return `---\nname: ${name}\ndescription: ${description}\n${fm.extra ? `${fm.extra}\n` : ""}---\n\n${body}`;
}
