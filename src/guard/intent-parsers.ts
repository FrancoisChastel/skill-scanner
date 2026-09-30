import { isInsideSkillRoot } from "./locations";
import { programName } from "./shell";
import { cloneDirName, type DetectState, resolvePath } from "./shellpath";
import type { InstallIntent } from "./types";

/** One parser per installer. Each takes the unwrapped words of a simple command and returns an intent or undefined. */

// ---- npx skills (vercel-labs/skills) and runners

const SKILLS_SUBCOMMANDS = new Set(["add", "a", "install", "i", "update", "upgrade", "check", "experimental_install", "experimental_sync"]);
const SKILLS_PACKAGE = /^(?:skills|add-skill)(?:@[^\s/]+)?$/;
const RUNNER_VALUE_FLAGS = new Set(["-p", "--package", "--registry", "--cache", "--userconfig", "--workspace", "-w"]);

interface SkillsCall {
  readonly args: readonly string[];
  /** `add-skill <source>` has no subcommand. */
  readonly impliedAdd: boolean;
}

export function parseSkillsCli(words: readonly string[]): InstallIntent | undefined {
  const call = skillsCall(words);
  return call ? parseSkillsArgs(call, words) : undefined;
}

function skillsCall(words: readonly string[]): SkillsCall | undefined {
  const prog = programName(words[0]);
  const sub = words[1];
  if (prog === "skills" || prog === "add-skill") return { args: words.slice(1), impliedAdd: prog === "add-skill" };
  if (prog === "npx" || prog === "pnpx" || prog === "bunx") return viaRunner(words.slice(1));
  if (prog === "npm" && (sub === "exec" || sub === "x")) return viaRunner(words.slice(2));
  if (prog === "bun" && sub === "x") return viaRunner(words.slice(2));
  if ((prog === "pnpm" || prog === "yarn") && (sub === "dlx" || sub === "exec")) return viaRunner(words.slice(2));
  if ((prog === "pnpm" || prog === "yarn") && (sub === "skills" || sub === "add-skill"))
    return { args: words.slice(2), impliedAdd: sub === "add-skill" };
  return undefined;
}

function viaRunner(args: readonly string[]): SkillsCall | undefined {
  const packages: string[] = [];
  let i = 0;
  for (; i < args.length; i += 1) {
    const a = args[i]!;
    if (a === "--") {
      i += 1;
      break;
    }
    if (!a.startsWith("-")) break;
    if (a === "-p" || a === "--package") packages.push(args[i + 1] ?? "");
    else if (a.startsWith("--package=")) packages.push(a.slice(10));
    if (RUNNER_VALUE_FLAGS.has(a)) i += 1;
  }
  const cmd = args[i];
  if (cmd === undefined) return undefined;
  const viaPackage = (cmd === "skills" || cmd === "add-skill") && packages.some((p) => SKILLS_PACKAGE.test(p));
  if (!SKILLS_PACKAGE.test(cmd) && !viaPackage) return undefined;
  return { args: args.slice(i + 1), impliedAdd: cmd.startsWith("add-skill") };
}

const looksLikeSource = (v: string): boolean => /[/:]/.test(v) || v.startsWith(".") || v.startsWith("~");

function parseSkillsArgs(call: SkillsCall, argv: readonly string[]): InstallIntent | undefined {
  let sub = call.impliedAdd ? "add" : undefined;
  let source: string | undefined;
  const skills: string[] = [];
  const variadic: string[] = [];
  let global = false;
  const a = call.args;
  for (let i = 0; i < a.length; i += 1) {
    const w = a[i]!;
    if (w === "-l" || w === "--list" || w === "-h" || w === "--help") return undefined;
    if (w === "-g" || w === "--global" || /^-[a-zA-Z]*g[a-zA-Z]*$/.test(w)) global = true;
    else if (w.startsWith("--skill=")) skills.push(...w.slice(8).split(","));
    else if (w === "-s" || w === "--skill" || w === "-a" || w === "--agent") {
      let j = i + 1;
      while (a[j] !== undefined && !a[j]!.startsWith("-")) j += 1;
      const values = a.slice(i + 1, j);
      i = j - 1;
      if (w === "-s" || w === "--skill") skills.push(...values);
      else variadic.push(...values);
    } else if (!w.startsWith("-")) {
      if (sub === undefined) sub = w;
      else source ??= w;
    }
  }
  if (sub === undefined || !SKILLS_SUBCOMMANDS.has(sub)) return undefined;
  // Commander's variadic options swallow a source placed after them; recover it so it is still scanned.
  if (source === undefined) source = [...skills, ...variadic].find(looksLikeSource);
  const picked = skills
    .filter((s) => s !== source)
    .flatMap((s) => s.split(","))
    .filter(Boolean);
  const subcommand = sub === "a" ? "add" : sub === "i" ? "install" : sub;
  return { kind: "skills-cli", subcommand, ...(source ? { source } : {}), skills: picked, global, argv: [...argv] };
}

// ---- git clone

const GIT_GLOBAL_VALUES = new Set(["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env"]);
const CLONE_VALUES = new Set([
  "-b",
  "--branch",
  "-o",
  "--origin",
  "-u",
  "--upload-pack",
  "--template",
  "-c",
  "--config",
  "--depth",
  "--shallow-since",
  "--shallow-exclude",
  "--reference",
  "--reference-if-able",
  "--separate-git-dir",
  "-j",
  "--jobs",
  "--filter",
  "--server-option",
  "--bundle-uri",
  "--ref-format",
  "--revision",
]);

export function parseGitClone(words: readonly string[], state: DetectState): InstallIntent | undefined {
  if (programName(words[0]) !== "git") return undefined;
  let cwd = state.cwd;
  let i = 1;
  for (; i < words.length && words[i]!.startsWith("-"); i += 1) {
    const w = words[i]!;
    if (w === "-C") cwd = resolvePath(words[i + 1] ?? ".", { ...state, cwd }) ?? cwd;
    if (GIT_GLOBAL_VALUES.has(w)) i += 1;
  }
  if (words[i] !== "clone") return undefined;
  const positionals: string[] = [];
  let ref: string | undefined;
  for (i += 1; i < words.length; i += 1) {
    const w = words[i]!;
    if (w === "--") {
      positionals.push(...words.slice(i + 1));
      break;
    }
    if (!w.startsWith("-")) positionals.push(w);
    else if (w === "-b" || w === "--branch") ref = words[i + 1];
    else if (w.startsWith("--branch=")) ref = w.slice(9);
    if (CLONE_VALUES.has(w)) i += 1;
  }
  const [url, dest] = positionals;
  if (!url) return undefined;
  const here = { ...state, cwd };
  const destPath = resolvePath(dest ?? cloneDirName(url), here);
  const intoSkills =
    (destPath !== undefined && isInsideSkillRoot(destPath, state.roots)) ||
    (cwd !== undefined && isInsideSkillRoot(cwd, state.roots)) ||
    /skill/i.test(url) ||
    (dest !== undefined && /skill/i.test(dest));
  if (!intoSkills) return undefined;
  return { kind: "git-clone", url, ...(destPath || dest ? { dest: destPath ?? dest! } : {}), ...(ref ? { ref } : {}) };
}

// ---- git updates of an installed skill's repository

/** Subcommands that can move a checked-out branch or HEAD to content from elsewhere (so `guard`'s hooks scan it). */
const GIT_UPDATES = new Set(["pull", "merge", "rebase", "reset", "checkout", "switch", "cherry-pick", "am"]);
/** Options of checkout and switch that take a value (a new branch's name is not where it starts). */
const CHECKOUT_VALUES = new Set(["-b", "-B", "-c", "-C", "--orphan", "--create", "--force-create", "--conflict", "--pathspec-from-file"]);

export function parseGitUpdate(words: readonly string[], state: DetectState): InstallIntent | undefined {
  if (programName(words[0]) !== "git") return undefined;
  let dir = state.cwd;
  let i = 1;
  for (; i < words.length && words[i]!.startsWith("-"); i += 1) {
    const w = words[i]!;
    if (w === "-C") dir = resolvePath(words[i + 1] ?? ".", { ...state, cwd: dir }) ?? dir;
    else if (w === "--work-tree") dir = resolvePath(words[i + 1] ?? ".", { ...state, cwd: dir }) ?? dir;
    else if (w.startsWith("--work-tree=")) dir = resolvePath(w.slice(12), { ...state, cwd: dir }) ?? dir;
    if (GIT_GLOBAL_VALUES.has(w)) i += 1;
  }
  const sub = words[i];
  if (sub === undefined || !GIT_UPDATES.has(sub) || dir === undefined || !isInsideSkillRoot(dir, state.roots)) return undefined;
  if (bringsNothingNew(sub, words.slice(i + 1))) return undefined;
  return { kind: "git-update", dir, subcommand: sub };
}

/**
 * Local work in a skill's repository that cannot bring in anything the repository does not already
 * have checked out: a new branch at HEAD, restoring paths from the index, a reset to HEAD, giving
 * up a rebase or merge. Wrapping those would only get in the way of someone developing a skill.
 */
function bringsNothingNew(sub: string, args: readonly string[]): boolean {
  if (args.some((w) => w === "-h" || w === "--help" || w === "--abort" || w === "--quit")) return true;
  const end = args.indexOf("--");
  const before = end === -1 ? args : args.slice(0, end);
  const operands: string[] = [];
  for (let k = 0; k < before.length; k += 1) {
    const w = before[k]!;
    if (w.startsWith("-") && w !== "-") {
      if ((sub === "checkout" || sub === "switch") && CHECKOUT_VALUES.has(w)) k += 1;
      continue;
    }
    operands.push(w);
  }
  // No start point: a new branch at HEAD, or paths restored from the index.
  if (sub === "checkout" || sub === "switch") return operands.length === 0;
  if (sub === "reset") return operands.every((w) => w === "HEAD" || w === "@");
  return false;
}

// ---- Codex's built-in skill-installer

const CODEX_INSTALLER = /(?:^|[\\/])install-skill-from-github\.py$/;

export function parseCodexInstaller(words: readonly string[]): InstallIntent | undefined {
  const at = words.findIndex((w, k) => k < 5 && CODEX_INSTALLER.test(w));
  if (at === -1) return undefined;
  const opts = longOptions(words.slice(at + 1), new Set(["--path"]));
  const url = opts.get("--url")?.[0];
  if (url) return { kind: "codex-skill-installer", source: url, paths: [] };
  const repo = opts.get("--repo")?.[0];
  if (!repo) return undefined;
  const ref = opts.get("--ref")?.[0];
  return { kind: "codex-skill-installer", source: ref ? `${repo}#${ref}` : repo, paths: opts.get("--path") ?? [] };
}

/** `--name value`, `--name=value`, and (for `multi`) `--name v1 v2`, collected by name. */
function longOptions(args: readonly string[], multi: ReadonlySet<string>): Map<string, string[]> {
  const out = new Map<string, string[]>();
  const add = (k: string, v: string): void => {
    out.set(k, [...(out.get(k) ?? []), v]);
  };
  for (let i = 0; i < args.length; i += 1) {
    const w = args[i]!;
    if (!w.startsWith("--")) continue;
    const eq = w.indexOf("=");
    if (eq !== -1) {
      add(w.slice(0, eq), w.slice(eq + 1));
      continue;
    }
    let j = i + 1;
    while (args[j] !== undefined && !args[j]!.startsWith("-") && (j === i + 1 || multi.has(w))) {
      add(w, args[j]!);
      j += 1;
    }
    i = j - 1;
  }
  return out;
}

// ---- Plugin managers

/** Positional words after the program, skipping options (and the values of `valueFlags`). */
function positionals(words: readonly string[], valueFlags: ReadonlySet<string>): string[] {
  const out: string[] = [];
  for (let i = 1; i < words.length; i += 1) {
    const w = words[i]!;
    if (w.startsWith("-")) {
      if (valueFlags.has(w)) i += 1;
      continue;
    }
    out.push(w);
  }
  return out;
}

const PLUGIN_VALUE_FLAGS = new Set([
  "-s",
  "--scope",
  "--sparse",
  "--ref",
  "-m",
  "--marketplace",
  "-c",
  "--config",
  "--enable",
  "--disable",
]);

/** The value of `-m`/`--marketplace` (either spelling, `--marketplace=x` too). */
function marketplaceFlag(words: readonly string[]): string | undefined {
  for (let i = 1; i < words.length; i += 1) {
    const w = words[i]!;
    if ((w === "-m" || w === "--marketplace") && words[i + 1]) return words[i + 1];
    if (w.startsWith("--marketplace=")) return w.slice(14);
  }
  return undefined;
}

export function parseClaudePlugin(words: readonly string[]): InstallIntent | undefined {
  if (programName(words[0]) !== "claude") return undefined;
  const [group, action, a, b] = positionals(words, PLUGIN_VALUE_FLAGS);
  if (group !== "plugin" && group !== "plugins") return undefined;
  if ((action === "install" || action === "i") && a) return { kind: "claude-plugin", action: "install", target: a };
  if (action === "marketplace" && a === "add" && b) return { kind: "claude-plugin", action: "marketplace-add", target: b };
  if (action === "update" && a) return { kind: "plugin-update", harness: "claude-code", target: a };
  if (action === "marketplace" && a === "update") return { kind: "plugin-update", harness: "claude-code", ...(b ? { target: b } : {}) };
  return undefined;
}

export function parseCodexPlugin(words: readonly string[]): InstallIntent | undefined {
  if (programName(words[0]) !== "codex") return undefined;
  const [group, action, a, b] = positionals(words, PLUGIN_VALUE_FLAGS);
  if (group !== "plugin" && group !== "plugins") return undefined;
  if ((action === "add" || action === "install") && a) {
    const marketplace = marketplaceFlag(words);
    return { kind: "codex-plugin", action: "add", target: a, ...(marketplace ? { marketplace } : {}) };
  }
  if (action === "marketplace" && a === "add" && b) return { kind: "codex-plugin", action: "marketplace-add", target: b };
  if (action === "marketplace" && (a === "upgrade" || a === "update"))
    return { kind: "plugin-update", harness: "codex", ...(b ? { target: b } : {}) };
  return undefined;
}

export function parsePi(words: readonly string[]): InstallIntent | undefined {
  if (programName(words[0]) !== "pi") return undefined;
  for (let i = 1; i < words.length; i += 1) {
    const w = words[i]!;
    if ((w === "-e" || w === "--extension") && words[i + 1]) return { kind: "pi-install", source: words[i + 1]! };
    if (w.startsWith("--extension=")) return { kind: "pi-install", source: w.slice(12) };
  }
  const [action, source] = positionals(words, new Set());
  if (action === "install" && source) return { kind: "pi-install", source };
  if (action === "update") return piUpdate(words, source);
  return undefined;
}

/** `pi update` alone, `self`, and `pi` update Pi itself; `--extensions`, `--all`, or a source update packages. */
function piUpdate(words: readonly string[], source: string | undefined): InstallIntent | undefined {
  if (words.some((w) => w === "-h" || w === "--help")) return undefined;
  if (source !== undefined) return source === "self" || source === "pi" ? undefined : { kind: "pi-update", source };
  return words.some((w) => w === "--extensions" || w === "--all") ? { kind: "pi-update" } : undefined;
}

export function parseOpencodePlugin(words: readonly string[]): InstallIntent | undefined {
  if (programName(words[0]) !== "opencode") return undefined;
  const [group, a, b] = positionals(words, new Set());
  if (group !== "plugin" && group !== "plugins") return undefined;
  const target = a === "add" || a === "install" ? b : a;
  return target ? { kind: "opencode-plugin", target } : undefined;
}
