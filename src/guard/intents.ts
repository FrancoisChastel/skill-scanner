import { homeOf } from "./fsutil";
import {
  parseClaudePlugin,
  parseCodexInstaller,
  parseCodexPlugin,
  parseGitClone,
  parseGitUpdate,
  parseOpencodePlugin,
  parsePi,
  parseSkillsCli,
} from "./intent-parsers";
import { writeDestinations } from "./intent-writes";
import { isInsideSkillRoot } from "./locations";
import { commandWords, parseShell, programName, type SimpleCommand } from "./shell";
import { type DetectState, resolvePath } from "./shellpath";
import type { InstallIntent, SkillRoot } from "./types";

/**
 * Recognise install actions in a shell command before it runs. Table-driven over the simple
 * commands the tokenizer finds, recursing into `sh -c`, `eval`, substitutions, and heredocs fed
 * to a shell. It is a best guess: anything it misses is caught by the post-change audit.
 */

export interface DetectOptions {
  /** Working directory the command runs in; relative destinations resolve against it. */
  readonly cwd?: string;
  readonly env?: NodeJS.ProcessEnv;
  /** Skill roots for destination checks. Without them only path patterns are used. */
  readonly roots?: readonly SkillRoot[];
}

const MAX_DEPTH = 3;
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "mksh", "fish"]);

export function detectInstallIntents(command: string, opts: DetectOptions = {}): InstallIntent[] {
  const state: DetectState = { cwd: opts.cwd, env: opts.env ?? process.env, roots: opts.roots ?? [] };
  return dedupe(detectIn(command, state, 0));
}

function detectIn(command: string, state: DetectState, depth: number): InstallIntent[] {
  if (depth > MAX_DEPTH || command.trim() === "") return [];
  const parsed = parseShell(command);
  const out: InstallIntent[] = [];
  let cwd = state.cwd;
  let prev: SimpleCommand | undefined;
  for (const cmd of parsed.commands) {
    const words = commandWords(cmd.words);
    const here: DetectState = { ...state, cwd };
    cwd = nextCwd(words, here) ?? cwd;
    out.push(...intentsOf(words, cmd, here));
    for (const nested of nestedScripts(words, cmd, prev)) out.push(...detectIn(nested, here, depth + 1));
    prev = cmd;
  }
  for (const sub of parsed.substitutions) out.push(...detectIn(sub, { ...state, cwd }, depth + 1));
  return out;
}

function intentsOf(words: readonly string[], cmd: SimpleCommand, state: DetectState): InstallIntent[] {
  const out: InstallIntent[] = [];
  if (words.length > 0) {
    const direct =
      parseSkillsCli(words) ??
      parseGitClone(words, state) ??
      parseGitUpdate(words, state) ??
      parseCodexInstaller(words) ??
      parseClaudePlugin(words) ??
      parseCodexPlugin(words) ??
      parsePi(words) ??
      parseOpencodePlugin(words);
    if (direct) out.push(direct);
  }
  // A clone already reports its destination; do not report it again as a write.
  if (out.some((i) => i.kind === "git-clone")) return out;
  for (const w of writeDestinations(words, cmd.redirects)) {
    const dest = resolvePath(w.dest, state);
    if (dest && isInsideSkillRoot(dest, state.roots)) out.push({ kind: "write-to-skill-dir", dest, via: w.via });
  }
  return out;
}

/** Command strings that also run: `sh -c '...'`, `eval ...`, `npx -c`, a heredoc or echo piped into a shell. */
function nestedScripts(words: readonly string[], cmd: SimpleCommand, prev: SimpleCommand | undefined): string[] {
  const prog = programName(words[0]);
  if (prog === "eval") return [words.slice(1).join(" ")];
  if ((prog === "npx" || prog === "pnpx") && words.some((w) => w === "-c" || w === "--call" || w.startsWith("--call="))) {
    const i = words.findIndex((w) => w === "-c" || w === "--call" || w.startsWith("--call="));
    const w = words[i]!;
    return [w.startsWith("--call=") ? w.slice(7) : (words[i + 1] ?? "")];
  }
  if (!SHELLS.has(prog)) return [];
  const script = shellCommandString(words);
  if (script !== undefined) return [script];
  if (hasScriptOperand(words)) return [];
  const fed = cmd.redirects.filter((r) => r.body !== undefined).map((r) => r.body!);
  if (fed.length > 0) return fed;
  if (cmd.after === "|" && prev) {
    const pw = commandWords(prev.words);
    const p = programName(pw[0]);
    if (p === "echo" || p === "printf")
      return [
        pw
          .slice(1)
          .filter((w) => !/^-[neE]+$/.test(w))
          .join(" "),
      ];
  }
  return [];
}

/** The string after `-c` (or a cluster ending in `c`, like `-lc`) for a shell invocation. */
function shellCommandString(words: readonly string[]): string | undefined {
  let sawC = false;
  for (let i = 1; i < words.length; i += 1) {
    const w = words[i]!;
    if (w === "--") return sawC ? words[i + 1] : undefined;
    if ((w === "-o" || w === "+o") && !sawC) {
      i += 1;
      continue;
    }
    if (/^[-+][a-zA-Z]+$/.test(w)) {
      if (w.startsWith("-") && w.includes("c")) sawC = true;
      continue;
    }
    return sawC ? w : undefined;
  }
  return undefined;
}

function hasScriptOperand(words: readonly string[]): boolean {
  return words.slice(1).some((w) => !w.startsWith("-") && !w.startsWith("+"));
}

function nextCwd(words: readonly string[], state: DetectState): string | undefined {
  const prog = programName(words[0]);
  if (prog !== "cd" && prog !== "pushd") return undefined;
  const arg = words.slice(1).find((w) => !w.startsWith("-"));
  if (arg === undefined) return homeOf(state.env);
  return resolvePath(arg, state);
}

function dedupe(intents: readonly InstallIntent[]): InstallIntent[] {
  const seen = new Set<string>();
  return intents.filter((i) => {
    const key = JSON.stringify(i);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
