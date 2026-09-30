import { existsSync, readdirSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { homeOf, isInside } from "./fsutil";
import type { Harness, SkillRoot } from "./types";

/**
 * Where each harness loads skills from, as documented and observed (Claude Code 2.1, Codex 0.153,
 * OpenCode 1.x, Pi 0.87). Roots are returned whether or not they exist yet, so a command that
 * creates one is still recognised as writing into a skill directory.
 */

interface HarnessDirs {
  readonly home: string;
  readonly claude: string;
  readonly codex: string;
  readonly pi: string;
  readonly xdgConfig: string;
  readonly xdgCache: string;
}

export function harnessDirs(env: NodeJS.ProcessEnv): HarnessDirs {
  const home = homeOf(env);
  return {
    home,
    claude: env.CLAUDE_CONFIG_DIR || join(home, ".claude"),
    codex: env.CODEX_HOME || join(home, ".codex"),
    pi: env.PI_CODING_AGENT_DIR || join(home, ".pi", "agent"),
    xdgConfig: env.XDG_CONFIG_HOME || join(home, ".config"),
    xdgCache: env.XDG_CACHE_HOME || join(home, ".cache"),
  };
}

/** Skill directories a harness loads from, for this working directory. */
export function skillRoots(harness: Harness | "all", cwd: string, env: NodeJS.ProcessEnv): SkillRoot[] {
  const want = (h: Harness): boolean => harness === "all" || harness === h;
  const dirs = harnessDirs(env);
  const project = projectDirs(cwd, dirs.home);
  const roots: SkillRoot[] = [
    ...(want("claude-code") ? claudeRoots(dirs, project) : []),
    ...(want("codex") ? codexRoots(dirs, project) : []),
    ...(want("opencode") ? opencodeRoots(dirs, project, env) : []),
    ...(want("pi") ? piRoots(dirs, project) : []),
  ];
  const seen = new Set<string>();
  return roots.filter((r) => {
    if (seen.has(r.path)) return false;
    seen.add(r.path);
    return true;
  });
}

interface ProjectDirs {
  /** The working directory and its parents up to the repository root (just the working directory outside a repository). */
  readonly chain: readonly string[];
  readonly repoRoot?: string;
}

function projectDirs(cwd: string, home: string): ProjectDirs {
  const start = resolve(cwd);
  const chain: string[] = [];
  let dir = start;
  for (let k = 0; k < 64; k += 1) {
    chain.push(dir);
    if (existsSync(join(dir, ".git"))) return { chain, repoRoot: dir };
    const parent = dirname(dir);
    if (parent === dir || dir === home) break;
    dir = parent;
  }
  return { chain: [start] };
}

const root = (harness: SkillRoot["harness"], scope: SkillRoot["scope"], path: string, extra: Partial<SkillRoot> = {}): SkillRoot => ({
  harness,
  scope,
  path,
  kind: "skills",
  ...extra,
});

function claudeRoots(d: HarnessDirs, p: ProjectDirs): SkillRoot[] {
  const personal = join(d.claude, "skills");
  return [
    ...p.chain.map((dir) => root("claude-code", "project", join(dir, ".claude", "skills"))),
    root("claude-code", "user", personal),
    // Skills synced from claude.ai land in per-account buckets below `synced/`.
    ...childDirs(join(personal, "synced")).map((b) => root("claude-code", "user", b)),
    root("claude-code", "system", managedClaudeDir()),
    root("claude-code", "plugin", join(d.claude, "plugins", "cache"), { kind: "plugin-cache" }),
  ];
}

function managedClaudeDir(): string {
  return process.platform === "darwin"
    ? "/Library/Application Support/ClaudeCode/.claude/skills"
    : process.platform === "win32"
      ? "C:\\Program Files\\ClaudeCode\\.claude\\skills"
      : "/etc/claude-code/.claude/skills";
}

function codexRoots(d: HarnessDirs, p: ProjectDirs): SkillRoot[] {
  const codexSkills = join(d.codex, "skills");
  return [
    ...p.chain.map((dir) => root("shared", "project", join(dir, ".agents", "skills"))),
    ...(p.repoRoot ? [root("codex", "project", join(p.repoRoot, ".codex", "skills"))] : []),
    root("shared", "user", join(d.home, ".agents", "skills")),
    root("codex", "user", codexSkills),
    root("codex", "system", join(codexSkills, ".system")),
    root("codex", "system", "/etc/codex/skills"),
    root("codex", "plugin", join(d.codex, "plugins", "cache"), { kind: "plugin-cache" }),
  ];
}

const enabled = (v: string | undefined): boolean => v !== undefined && v !== "" && v !== "0" && v.toLowerCase() !== "false";

function opencodeRoots(d: HarnessDirs, p: ProjectDirs, env: NodeJS.ProcessEnv): SkillRoot[] {
  const claudeOn = !enabled(env.OPENCODE_DISABLE_CLAUDE_CODE_SKILLS);
  const externalOn = !enabled(env.OPENCODE_DISABLE_EXTERNAL_SKILLS);
  const configDirs = [
    join(d.xdgConfig, "opencode"),
    ...p.chain.map((dir) => join(dir, ".opencode")),
    ...(env.OPENCODE_CONFIG_DIR ? [env.OPENCODE_CONFIG_DIR] : []),
  ];
  return [
    ...(claudeOn ? p.chain.map((dir) => root("claude-code", "project", join(dir, ".claude", "skills"))) : []),
    ...(externalOn ? p.chain.map((dir) => root("shared", "project", join(dir, ".agents", "skills"))) : []),
    ...(claudeOn ? [root("claude-code", "user", join(d.claude, "skills"))] : []),
    ...(externalOn ? [root("shared", "user", join(d.home, ".agents", "skills"))] : []),
    ...configDirs.flatMap((c) =>
      ["skill", "skills"].map((n) => root("opencode", c.startsWith(d.xdgConfig) ? "user" : "project", join(c, n), { recursive: true })),
    ),
    root("opencode", "user", join(d.xdgCache, "opencode", "skills"), { recursive: true }),
  ];
}

function piRoots(d: HarnessDirs, p: ProjectDirs): SkillRoot[] {
  return [
    ...p.chain.map((dir) => root("pi", "project", join(dir, ".pi", "skills"))),
    ...p.chain.map((dir) => root("shared", "project", join(dir, ".agents", "skills"))),
    root("pi", "user", join(d.pi, "skills")),
    root("shared", "user", join(d.home, ".agents", "skills")),
    root("pi", "plugin", join(d.pi, "npm", "node_modules"), { kind: "package-cache" }),
    root("pi", "plugin", join(d.pi, "git"), { kind: "package-cache" }),
  ];
}

function childDirs(dir: string): string[] {
  try {
    return readdirSync(dir, { withFileTypes: true })
      .filter((e) => e.isDirectory() && !e.name.startsWith("."))
      .map((e) => join(dir, e.name))
      .sort();
  } catch {
    return [];
  }
}

/** Skill directories nested anywhere in a project (Claude Code loads `<subdir>/.claude/skills` lazily). */
const NESTED_SKILL_DIR = /[\\/](?:\.(?:claude|agents|codex|pi|opencode)|opencode)[\\/](?:agent[\\/])?skills?(?=[\\/]|$)/g;
const PLUGIN_CACHE_DIR = /[\\/]\.(?:claude|codex)[\\/]plugins[\\/](?:cache|marketplaces)(?=[\\/]|$)/;

/** Whether a path is a skill root, inside one, or looks like a skill directory of any harness. */
export function isInsideSkillRoot(path: string, roots: readonly SkillRoot[]): boolean {
  const p = resolve(path);
  if (roots.some((r) => isInside(r.path, p))) return true;
  NESTED_SKILL_DIR.lastIndex = 0;
  return NESTED_SKILL_DIR.test(p) || PLUGIN_CACHE_DIR.test(p);
}

export interface SkillLocation {
  /** The root the path is in, when it is a known root (not a nested pattern match). */
  readonly root?: SkillRoot;
  readonly rootPath: string;
  /** The skill (or plugin version, for plugin caches) directory holding the path; absent for files directly in the root. */
  readonly skillDir?: string;
}

/** The skill directory a file belongs to, for writes into skill roots. */
export function locateSkillDir(path: string, roots: readonly SkillRoot[]): SkillLocation | undefined {
  const p = resolve(path);
  let best: SkillRoot | undefined;
  for (const r of roots) if (isInside(r.path, p) && (!best || r.path.length > best.path.length)) best = r;
  if (best) {
    const parts = relative(best.path, p).split(sep).filter(Boolean);
    const depth = best.kind === "plugin-cache" ? 3 : best.kind === "package-cache" ? Number.POSITIVE_INFINITY : 1;
    const skillDir = parts.length > depth ? join(best.path, ...parts.slice(0, depth)) : undefined;
    return { root: best, rootPath: best.path, ...(skillDir ? { skillDir } : {}) };
  }
  let last: RegExpExecArray | undefined;
  NESTED_SKILL_DIR.lastIndex = 0;
  for (let m = NESTED_SKILL_DIR.exec(p); m; m = NESTED_SKILL_DIR.exec(p)) last = m;
  if (!last) return undefined;
  const rootPath = p.slice(0, last.index + last[0].length);
  const first = relative(rootPath, p).split(sep).filter(Boolean);
  return { rootPath, ...(first.length > 1 ? { skillDir: join(rootPath, first[0]!) } : {}) };
}
