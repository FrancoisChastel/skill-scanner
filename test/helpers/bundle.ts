import { textKindOf } from "../../src/core/classify";
import { analyzeBundle } from "../../src/core/engine";
import { splitFrontmatter } from "../../src/core/frontmatter";
import type { Rule } from "../../src/core/rule";
import { verdictFor } from "../../src/core/severity";
import type { BundleKind, Finding, SkillBundle, SkillFile, Verdict } from "../../src/core/types";
import { BUILTIN_RULES } from "../../src/rules";

/** A file for `bundleOf`: text content, or a full SkillFile shape without its path (binaries, symlinks). */
export type FileSpec = string | Omit<SkillFile, "path">;

export interface BundleOptions {
  readonly kind?: BundleKind;
  readonly root?: string;
  readonly name?: string;
  readonly notes?: readonly string[];
}

/**
 * Build an in-memory SkillBundle the way `collect` would for one directory: text files are
 * classified by path and content, `SKILL.md` at the root becomes the skill-md file and its
 * frontmatter is parsed. No disk access, so rule tests stay fast.
 */
export function bundleOf(files: Readonly<Record<string, FileSpec>>, opts: BundleOptions = {}): SkillBundle {
  const hasSkill = Object.hasOwn(files, "SKILL.md");
  const kind: BundleKind = opts.kind ?? (hasSkill ? "skill" : "package");
  let frontmatter: SkillBundle["frontmatter"];
  const list: SkillFile[] = Object.entries(files).map(([path, spec]) => {
    if (typeof spec !== "string") return { path, ...spec } as SkillFile;
    if (path === "SKILL.md" && kind === "skill") {
      frontmatter = splitFrontmatter(spec).frontmatter;
      return { path, kind: "skill-md", size: spec.length, text: spec };
    }
    const { kind: k, language } = textKindOf(path, spec.slice(0, 256), false);
    return { path, kind: k, ...(language ? { language } : {}), size: spec.length, text: spec };
  });
  const root = opts.root ?? ".";
  const dirName = root === "." ? "demo-skill" : root.slice(root.lastIndexOf("/") + 1);
  const nameField = frontmatter?.data.name;
  return {
    kind,
    name: opts.name ?? (typeof nameField === "string" ? nameField : dirName),
    root,
    dirName,
    files: list,
    ...(frontmatter ? { frontmatter } : {}),
    digest: "sha256:test",
    notes: opts.notes ?? [],
  };
}

/** Every finding the built-in rules (or `rules`) produce for an in-memory bundle. */
export function scanFiles(
  files: Readonly<Record<string, FileSpec>>,
  opts: BundleOptions & { rules?: readonly Rule[] } = {},
): { findings: Finding[]; verdict: Verdict; bundle: SkillBundle } {
  const bundle = bundleOf(files, opts);
  const findings = analyzeBundle(bundle, { rules: opts.rules ?? BUILTIN_RULES });
  return { findings, verdict: verdictFor(findings), bundle };
}

/** Findings of one rule id. */
export function findingsOf(files: Readonly<Record<string, FileSpec>>, ruleId: string, opts: BundleOptions = {}): Finding[] {
  return scanFiles(files, opts).findings.filter((f) => f.ruleId === ruleId);
}

/** A SKILL.md with valid frontmatter around `body`. */
export function skill(body: string, extraFrontmatter = ""): string {
  return `---\nname: demo-skill\ndescription: Formats CSV files into Markdown tables.\n${extraFrontmatter ? `${extraFrontmatter}\n` : ""}---\n\n${body}\n`;
}
