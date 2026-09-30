import { readdir, readFile, realpath, stat } from "node:fs/promises";
import { basename, join } from "node:path";
import { exists, isRecord } from "./fsutil";
import type { SkillRoot, TargetKind } from "./types";

/**
 * Enumerate what is installed under skill roots: each skill directory (a child holding SKILL.md,
 * following the child link itself but nothing below it), each live plugin version in a plugin
 * cache, and each skill-bearing package in a package cache. Deduplicated by real path, so a skill
 * installed once and linked into several harnesses is scanned once.
 */

export interface AuditTarget {
  readonly harness: SkillRoot["harness"];
  readonly scope: SkillRoot["scope"];
  readonly kind: TargetKind;
  readonly name: string;
  /** As found; may be a symlink. */
  readonly path: string;
  readonly realPath: string;
  /** Other names the harness uses for it (`plugin@marketplace`). */
  readonly aliases?: readonly string[];
}

const MAX_NESTED_DEPTH = 3;
const KIND_ORDER: Readonly<Record<TargetKind, number>> = { skill: 0, plugin: 1, package: 2 };

export async function enumerateTargets(roots: readonly SkillRoot[]): Promise<AuditTarget[]> {
  const found = await Promise.all(roots.map((r) => targetsIn(r).catch(() => [] as AuditTarget[])));
  const seen = new Set<string>();
  const unique = found.flat().filter((t) => {
    if (seen.has(t.realPath)) return false;
    seen.add(t.realPath);
    return true;
  });
  // Skills first: they are small and the most common thing to change; big plugin caches last.
  return unique
    .map((t, i) => ({ t, i }))
    .sort((a, b) => KIND_ORDER[a.t.kind] - KIND_ORDER[b.t.kind] || a.i - b.i)
    .map((x) => x.t);
}

function targetsIn(root: SkillRoot): Promise<AuditTarget[]> {
  if (root.kind === "plugin-cache") return pluginVersionsIn(root);
  if (root.kind === "package-cache") return packagesIn(root, root.path, 0);
  return skillDirsIn(root, root.path, 0);
}

export async function hasSkillMd(dir: string): Promise<boolean> {
  return (await exists(join(dir, "SKILL.md"))) || (await exists(join(dir, "skill.md")));
}

async function listDir(dir: string): Promise<string[]> {
  try {
    return (await readdir(dir)).sort();
  } catch {
    return [];
  }
}

async function isDir(p: string): Promise<boolean> {
  return stat(p).then(
    (s) => s.isDirectory(),
    () => false,
  );
}

async function target(root: SkillRoot, path: string, kind: TargetKind, name: string, aliases?: readonly string[]): Promise<AuditTarget> {
  return {
    harness: root.harness,
    scope: root.scope,
    kind,
    name,
    path,
    realPath: await realpath(path),
    ...(aliases && aliases.length > 0 ? { aliases } : {}),
  };
}

async function skillDirsIn(root: SkillRoot, dir: string, depth: number): Promise<AuditTarget[]> {
  const names = (await listDir(dir)).filter((n) => n !== ".git" && n !== "node_modules");
  const nested = await Promise.all(
    names.map(async (name): Promise<AuditTarget[]> => {
      const p = join(dir, name);
      if (!(await isDir(p))) return [];
      if (await hasSkillMd(p)) return [await target(root, p, "skill", name)];
      return root.recursive && depth < MAX_NESTED_DEPTH ? skillDirsIn(root, p, depth + 1) : [];
    }),
  );
  return nested.flat();
}

/** `<cache>/<marketplace>/<plugin>/<version>`, skipping temporary clones and versions Claude Code marked orphaned. */
async function pluginVersionsIn(root: SkillRoot): Promise<AuditTarget[]> {
  const out: AuditTarget[] = [];
  for (const mkt of await listDir(root.path)) {
    if (mkt.startsWith(".") || mkt.startsWith("temp_")) continue;
    for (const plugin of await listDir(join(root.path, mkt))) {
      if (plugin.startsWith(".")) continue;
      for (const version of await listDir(join(root.path, mkt, plugin))) {
        const p = join(root.path, mkt, plugin, version);
        if (version.startsWith(".") || !(await isDir(p)) || (await exists(join(p, ".orphaned_at")))) continue;
        out.push(await target(root, p, "plugin", plugin, [`${plugin}@${mkt}`]));
      }
    }
  }
  return out;
}

/** Packages that carry skills or agent extensions: a `pi` manifest key, a `skills/` directory, or a SKILL.md. */
async function packagesIn(root: SkillRoot, dir: string, depth: number): Promise<AuditTarget[]> {
  const out: AuditTarget[] = [];
  for (const name of await listDir(dir)) {
    if (name.startsWith(".") || name === "node_modules") continue;
    const p = join(dir, name);
    if (!(await isDir(p))) continue;
    const manifest = await readManifest(p);
    if (await isAgentPackage(p, manifest)) out.push(await target(root, p, "package", packageName(p, manifest)));
    else if (!manifest && depth < MAX_NESTED_DEPTH) out.push(...(await packagesIn(root, p, depth + 1)));
  }
  return out;
}

async function readManifest(dir: string): Promise<Record<string, unknown> | undefined> {
  try {
    const raw: unknown = JSON.parse(await readFile(join(dir, "package.json"), "utf8"));
    return isRecord(raw) ? raw : {};
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "ENOENT" ? undefined : {};
  }
}

async function isAgentPackage(dir: string, manifest: Record<string, unknown> | undefined): Promise<boolean> {
  if (manifest && ("pi" in manifest || (Array.isArray(manifest.keywords) && manifest.keywords.includes("pi-package")))) return true;
  return (await isDir(join(dir, "skills"))) || (await hasSkillMd(dir));
}

function packageName(dir: string, manifest: Record<string, unknown> | undefined): string {
  return typeof manifest?.name === "string" && manifest.name ? manifest.name : basename(dir);
}
