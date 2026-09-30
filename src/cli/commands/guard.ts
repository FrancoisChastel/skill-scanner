import { detectInstallIntents } from "../../guard/intents";
import { commandWords, parseShell, programName } from "../../guard/shell";
import type { InstallIntent } from "../../guard/types";
import { currentRuntime, type GuardEnv, guardEnv, parseSource, shellQuote } from "../../sources/index";
import { runInherited } from "../../sources/spawn";
import { formatFlags, UsageError } from "../args";
import { type Command, EXIT } from "../command";
import type { CliIO } from "../io";

const FLAGS = { help: { type: "boolean", short: "h", description: "Show this help (only before the command)" } } as const;

const DETAILS = `Every git checkout the command makes (clone, checkout, switch, worktree add) first runs
skill-scanner's post-checkout hook: the new tree is scanned, and a blocking verdict fails the
checkout, so the command that asked for it fails too. Every update of an existing checkout (pull,
fetch of the branch's upstream, reset, merge, rebase) is scanned before the branch moves, by a
reference-transaction hook: a refused update is aborted, and when git had already written the
working tree (reset, merge, rebase) it is put back. Nothing is installed: the hooks live in a
temporary directory, named through GIT_CONFIG_* environment variables for this command only.

Gates, for example:
  skill-scanner guard npx skills update         (also \`check\`, which updates)
  skill-scanner guard pi install git:github.com/owner/repo
  skill-scanner guard pi update --extensions
  skill-scanner guard git -C ~/.claude/skills/some-skill pull
  skill-scanner guard git clone https://github.com/owner/repo
  skill-scanner guard -- sh -c 'anything that checks out git repositories'

It also turns off the skills CLI's snapshot download for well-known owners so those skills are
cloned (and scanned) too. The skills CLI and pi then install nothing; a bare \`git clone\` fails
but leaves the refused tree on disk, and a refused \`git checkout\` in an existing repository
switches back.

Not gated: downloads that never touch git (npm tarballs, archives, well-known URLs), and working
tree writes that move no ref (git restore, git apply, git checkout <commit> -- <path>); the
post-change audit catches those. An absolute core.hooksPath or the repository's own .git/hooks
post-checkout and reference-transaction still run, after the scan. Refusals are repeated on
stderr when the command exits. Exits with the command's exit code (128 + signal if a signal
ended it).`;

export const guardCommand: Command = {
  name: "guard",
  summary: "Run a command so that every git checkout and update it makes is scanned first",
  usage: "[--] <command> [args...]",
  flags: FLAGS,
  details: DETAILS,
  run: runGuard,
};

/** Whether every install in the command goes through the skills CLI, which copies skill directories only. */
function onlySkillsCli(command: readonly string[]): boolean {
  const intents = detectInstallIntents(command.map(shellQuote).join(" "));
  return intents.length > 0 && intents.every((i) => i.kind === "skills-cli");
}

async function runGuard(argv: readonly string[], io: CliIO): Promise<number> {
  const first = argv[0];
  if (first === "--help" || first === "-h") {
    io.stdout(helpText());
    return EXIT.ok;
  }
  const command = first === "--" ? argv.slice(1) : argv;
  if (command.length === 0) throw new UsageError("missing <command>");
  const guard = await guardEnv({ ...currentRuntime(), ...(onlySkillsCli(command) ? { scope: "skills" as const } : {}) }, io.env);
  try {
    const code = await runInherited(command, { env: guard.env, cwd: io.cwd });
    const refused = await withRefusals(code, guard, io);
    return refused === 0 ? await withExpectedCheckouts(command, guard, io) : refused;
  } catch (e) {
    // Mirror the shell: 127 when the command cannot be started.
    io.stderr(`skill-scanner guard: ${e instanceof Error ? e.message : String(e)}\n`);
    return 127;
  } finally {
    await guard.cleanup();
  }
}

/**
 * Repeat what the hook refused, since the wrapped installer may have hidden it behind its own
 * message, and never report success when something was refused.
 */
export async function withRefusals(code: number, guard: GuardEnv, io: CliIO): Promise<number> {
  const text = await guard.refusals();
  if (!text.trim()) return code;
  io.stderr(`\nskill-scanner guard refused these checkouts and updates:\n${text}`);
  io.stderr(
    "A refused `git clone` leaves its files on disk; delete them unless you trust them. Refused updates were undone as noted above.\n",
  );
  return code === 0 ? EXIT.findings : code;
}

const GIT_URL = /^git:|^https?:\/\/|^git@|^ssh:\/\/|^file:\/\//;

/** Whether an install must clone: then a successful run with no checkout means the guard was switched off. */
function mustCheckOut(intent: InstallIntent, io: CliIO): boolean {
  if (intent.kind === "git-clone") return true;
  if (intent.kind === "pi-install") return GIT_URL.test(intent.source);
  if (intent.kind !== "skills-cli" || !intent.source || !["add", "a", "install", "i"].includes(intent.subcommand)) return false;
  try {
    return parseSource(intent.source, io.cwd, io.env).kind === "git";
  } catch {
    return false;
  }
}

const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh"]);

/** Any `git clone` in the command, including inside `sh -c` and substitutions: under guard every clone must be scanned. */
function hasGitClone(source: string, depth: number): boolean {
  if (depth > 4) return false;
  const parsed = parseShell(source);
  const nested = parsed.substitutions.some((body) => hasGitClone(body, depth + 1));
  return (
    nested ||
    parsed.commands.some((cmd) => {
      const words = commandWords(cmd.words);
      const name = programName(words[0]);
      // --no-checkout, --bare, and --mirror clones never run post-checkout, legitimately.
      if (name === "git") return words.includes("clone") && !words.some((w) => ["--no-checkout", "-n", "--bare", "--mirror"].includes(w));
      if (SHELLS.has(name)) {
        const c = words.findIndex((w, i) => i > 0 && /^-\w*c\w*$/.test(w));
        return c !== -1 && words[c + 1] !== undefined && hasGitClone(words[c + 1]!, depth + 1);
      }
      return false;
    })
  );
}

/**
 * The backstop behind the backstop: shell text can hide its intent from any parser, but it cannot
 * clone without a checkout passing through the hook unless something switched the hook off.
 */
export async function withExpectedCheckouts(command: readonly string[], guard: GuardEnv, io: CliIO): Promise<number> {
  const text = command.map(shellQuote).join(" ");
  const intents = detectInstallIntents(text, { cwd: io.cwd, env: io.env });
  const expected = hasGitClone(text, 0) || intents.some((i) => mustCheckOut(i, io));
  if (!expected || (await guard.checkouts()).length > 0) return EXIT.ok;
  io.stderr(
    "\nskill-scanner guard: this command should have cloned a repository, but no checkout went through the scan.\n" +
      "Something in the command switched the guard off, so the install is treated as refused. Anything it wrote is on disk unscanned:\n" +
      "run `skill-scanner audit` and remove what it flags.\n",
  );
  return EXIT.findings;
}

function helpText(): string {
  return [
    guardCommand.summary,
    "",
    "Usage:",
    `  skill-scanner guard ${guardCommand.usage}`,
    "",
    "Options:",
    formatFlags(FLAGS),
    "",
    DETAILS,
    "",
  ].join("\n");
}
