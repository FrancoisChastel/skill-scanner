import { access, constants } from "node:fs/promises";
import { homedir } from "node:os";
import { delimiter, join } from "node:path";
import type { Harness } from "../guard/types";

export type { Harness } from "../guard/types";

export const HARNESSES: readonly Harness[] = ["claude-code", "codex", "opencode", "pi"];

export const HARNESS_LABEL: Readonly<Record<Harness, string>> = {
  "claude-code": "Claude Code",
  codex: "Codex",
  opencode: "OpenCode",
  pi: "Pi",
};

const HARNESS_BINARY: Readonly<Record<Harness, string>> = { "claude-code": "claude", codex: "codex", opencode: "opencode", pi: "pi" };

const ALIASES: Readonly<Record<string, Harness>> = {
  claude: "claude-code",
  "claude-code": "claude-code",
  claudecode: "claude-code",
  codex: "codex",
  opencode: "opencode",
  "open-code": "opencode",
  pi: "pi",
};

export function parseHarness(name: string): Harness | undefined {
  return ALIASES[name.trim().toLowerCase()];
}

export type Scope = "user" | "project";

export const userHome = (env: NodeJS.ProcessEnv): string => env.HOME || env.USERPROFILE || homedir();

/** Each harness's own config directory, honoring the variables the harnesses themselves read. */
export function harnessConfigDir(harness: Harness, env: NodeJS.ProcessEnv): string {
  const home = userHome(env);
  switch (harness) {
    case "claude-code":
      return env.CLAUDE_CONFIG_DIR || join(home, ".claude");
    case "codex":
      return env.CODEX_HOME || join(home, ".codex");
    case "opencode":
      return env.OPENCODE_CONFIG_DIR || join(env.XDG_CONFIG_HOME || join(home, ".config"), "opencode");
    case "pi":
      return env.PI_CODING_AGENT_DIR || join(home, ".pi", "agent");
  }
}

export const SHIM_NAME = "skill-scanner.js";

/** The one file `setup` writes (or merges into) for a harness. */
export function harnessFile(harness: Harness, scope: Scope, env: NodeJS.ProcessEnv, cwd: string): string {
  const project = scope === "project";
  switch (harness) {
    case "claude-code":
      return join(project ? join(cwd, ".claude") : harnessConfigDir(harness, env), "settings.json");
    case "codex":
      return join(project ? join(cwd, ".codex") : harnessConfigDir(harness, env), "hooks.json");
    case "opencode":
      return join(project ? join(cwd, ".opencode") : harnessConfigDir(harness, env), "plugins", SHIM_NAME);
    case "pi":
      return join(project ? join(cwd, ".pi") : harnessConfigDir(harness, env), "extensions", SHIM_NAME);
  }
}

/** Where `--with-skill` copies the bundled skill: Claude Code reads its own directory, the others share `.agents/skills`. */
export function skillsDir(kind: "claude" | "agents", scope: Scope, env: NodeJS.ProcessEnv, cwd: string): string {
  if (kind === "claude") return scope === "project" ? join(cwd, ".claude", "skills") : join(harnessConfigDir("claude-code", env), "skills");
  return join(scope === "project" ? cwd : userHome(env), ".agents", "skills");
}

export interface Probe {
  readonly exists: (path: string) => Promise<boolean>;
  /** Absolute path of an executable on PATH, or undefined. */
  readonly which: (binary: string) => Promise<string | undefined>;
}

export interface Detection {
  readonly harness: Harness;
  readonly binary?: string;
  readonly configDir: string;
  readonly configDirExists: boolean;
  readonly detected: boolean;
}

export async function pathExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

/** First executable of this name in PATH. */
export async function whichBinary(binary: string, env: NodeJS.ProcessEnv): Promise<string | undefined> {
  const exts = process.platform === "win32" ? ["", ".exe", ".cmd"] : [""];
  for (const dir of (env.PATH ?? env.Path ?? "").split(delimiter).filter(Boolean)) {
    for (const ext of exts) {
      const candidate = join(dir, binary + ext);
      try {
        await access(candidate, constants.X_OK);
        return candidate;
      } catch {
        // next entry
      }
    }
  }
  return undefined;
}

export const defaultProbe = (env: NodeJS.ProcessEnv): Probe => ({ exists: pathExists, which: (b) => whichBinary(b, env) });

/** A harness counts as installed when its CLI is on PATH or its config directory exists. */
export async function detectHarnesses(env: NodeJS.ProcessEnv, probe: Probe = defaultProbe(env)): Promise<Detection[]> {
  return Promise.all(
    HARNESSES.map(async (harness) => {
      const configDir = harnessConfigDir(harness, env);
      const [binary, configDirExists] = await Promise.all([probe.which(HARNESS_BINARY[harness]), probe.exists(configDir)]);
      return {
        harness,
        ...(binary ? { binary } : {}),
        configDir,
        configDirExists,
        detected: binary !== undefined || configDirExists,
      };
    }),
  );
}
