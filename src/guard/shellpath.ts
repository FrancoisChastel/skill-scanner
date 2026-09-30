import { basename, isAbsolute, join, resolve } from "node:path";
import { homeOf } from "./fsutil";
import type { SkillRoot } from "./types";

/** Path handling for words taken from shell commands. */

export interface DetectState {
  readonly cwd: string | undefined;
  readonly env: NodeJS.ProcessEnv;
  readonly roots: readonly SkillRoot[];
}

/** Expand `~` and `$VAR`/`${VAR}` from the environment, then resolve against the working directory. */
export function resolvePath(word: string, state: Pick<DetectState, "cwd" | "env">): string | undefined {
  const p = expandPath(word, state.env, state.cwd);
  if (isAbsolute(p)) return resolve(p);
  return state.cwd ? resolve(state.cwd, p) : undefined;
}

export function expandPath(word: string, env: NodeJS.ProcessEnv, cwd?: string): string {
  const home = homeOf(env);
  const tilde = word === "~" ? home : word.startsWith("~/") ? join(home, word.slice(2)) : word;
  return tilde.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g, (m, a: string | undefined, b: string | undefined) => {
    const name = (a ?? b)!;
    if (name === "HOME") return home;
    if (name === "PWD" && cwd) return cwd;
    return env[name] ?? m;
  });
}

/** Repository directory name `git clone` would create: the last path segment without `.git`. */
export function cloneDirName(url: string): string {
  const trimmed = url.replace(/[\\/]+$/, "").replace(/\.git$/, "");
  return basename(trimmed.replace(/^.*:/, "")) || "repo";
}
