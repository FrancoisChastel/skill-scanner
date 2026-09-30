import { parseShell, programName } from "./shell";

/**
 * Installs are guarded by environment that `guard` sets up: git config passed through
 * GIT_CONFIG_* variables (the post-checkout scan and the scanned mirror), SKILLS_DOWNLOAD_URL, and
 * skill-scanner's own variables. A command that sets, clears, or overrides those while installing
 * would switch its own guard off, so it is refused rather than rewritten.
 *
 * Matching runs on the words the shell will actually see, after quote removal, and recurses into
 * `sh -c`, `eval`, and command substitutions: `GIT_CONFIG_COU''NT=0` is `GIT_CONFIG_COUNT=0` to a
 * shell. What text matching cannot see (a name assembled at run time) is refused as well, and
 * `guard` still checks afterwards that the checkouts it expected went through the scan.
 */

const TAMPERING: ReadonlyArray<readonly [RegExp, string]> = [
  [/\bGIT_CONFIG_(?:COUNT|KEY_\d+|VALUE_\d+|PARAMETERS|GLOBAL|SYSTEM|NOSYSTEM)\b/, "git configuration passed through the environment"],
  [/\bcore\.hooksPath\b/i, "git's hooks path, which runs the install scan"],
  [/\burl\.[^\s=]+\.(?:insteadOf|pushInsteadOf)\b/i, "git URL rewriting"],
  [/\bSKILLS_DOWNLOAD_URL\b/, "the skills CLI download endpoint"],
  [/\bSKILL_SCANNER_[A-Z_]+\b/, "skill-scanner's own settings"],
];

const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "busybox"]);
const DECLARES = new Set(["export", "declare", "typeset", "readonly", "local"]);
const MAX_DEPTH = 4;

/** What the command would tamper with, or undefined when it touches none of the guard's settings. */
export function guardTampering(command: string): string | undefined {
  return inspect(command, 0);
}

function inspect(source: string, depth: number): string | undefined {
  // The raw text catches what quoting cannot hide; the parsed words catch what quoting can.
  const raw = matchTampering(source);
  if (raw || depth > MAX_DEPTH) return raw;
  const parsed = parseShell(source);
  for (const cmd of parsed.commands) {
    const found = inspectWords(cmd.words, depth);
    if (found) return found;
  }
  for (const body of parsed.substitutions) {
    const found = inspect(body, depth + 1);
    if (found) return found;
  }
  return undefined;
}

function inspectWords(words: readonly string[], depth: number): string | undefined {
  const joined = matchTampering(words.join("\n"));
  if (joined) return joined;
  const name = programName(words.find((w) => !/^[A-Za-z_][A-Za-z0-9_]*\+?=/.test(w)));
  const args = words.slice(words.findIndex((w) => programName(w) === name) + 1);
  if (name === "env" && args.some((a) => /^(?:-\w*i\w*|--ignore-environment)$/.test(a))) return "a cleared environment";
  if ((name === "unset" || name === "env") && args.some((a) => a.includes("$"))) return "variables whose names are computed at run time";
  // A name only known at run time (`export $V=0`, `declare -x "${N}"=1`) cannot be checked.
  if ((DECLARES.has(name) || name === "env") && args.some((a) => /^[^=]*\$/.test(a) && a.includes("=")))
    return "variables whose names are computed at run time";
  if (name === "eval") {
    const body = args.join(" ");
    if (/\$/.test(body)) return "an eval of text computed at run time";
    return inspect(body, depth + 1);
  }
  if (SHELLS.has(name)) {
    const c = args.findIndex((a) => /^-\w*c\w*$/.test(a));
    if (c !== -1 && args[c + 1] !== undefined) return inspect(args[c + 1]!, depth + 1);
  }
  return undefined;
}

function matchTampering(text: string): string | undefined {
  for (const [re, what] of TAMPERING) if (re.test(text)) return what;
  return undefined;
}
