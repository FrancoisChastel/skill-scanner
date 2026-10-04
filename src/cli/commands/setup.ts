import { DEFAULT_CONFIG, loadConfig } from "../../config";
import { describeSecondOpinions } from "../../second-opinions";
import { applyOps } from "../../setup/apply";
import { runCanaries } from "../../setup/canary";
import { HARNESSES, type Harness, parseHarness, userHome } from "../../setup/harnesses";
import { planErrors, planOps, planSetup, type SetupPlan } from "../../setup/index";
import { renderApply, renderCanaries, renderPlan } from "../../setup/render";
import { SetupError, selfCommand } from "../../setup/runtime";
import { bool, parseArgs, UsageError } from "../args";
import { type Command, EXIT } from "../command";
import type { CliIO } from "../io";

const flags = {
  project: {
    type: "boolean",
    description: "Set up the project in the current directory (.claude/, .codex/, .opencode/, .pi/) instead of your user config",
  },
  "dry-run": { type: "boolean", short: "n", description: "Print the plan and change nothing" },
  uninstall: { type: "boolean", description: "Remove skill-scanner's hooks, plugin, and extension files, and nothing else" },
  purge: { type: "boolean", description: "Uninstall and also delete ~/.skill-scanner (config, trust list, quarantine, cache)" },
  "with-skill": { type: "boolean", description: "Also copy the skill-scanner skill into ~/.claude/skills and ~/.agents/skills" },
  yes: { type: "boolean", short: "y", description: "Apply without asking (required when there is no terminal)" },
} as const;

const details = `
With no harness named, setup configures every coding agent it finds (CLI on PATH or config directory present).
It copies a pinned runtime to ~/.skill-scanner/bin and points each harness at it with an absolute Node path:
  claude-code  hooks merged into ~/.claude/settings.json (or .claude/settings.json with --project)
  codex        hooks merged into ~/.codex/hooks.json; trust them in Codex's /hooks screen
  opencode     plugin file ~/.config/opencode/plugins/skill-scanner.js
  pi           extension file ~/.pi/agent/extensions/skill-scanner.js
Every file is shown before it changes, edited files keep a .skill-scanner.bak copy of their original, and
re-running setup changes nothing that is already in place. \`setup --uninstall\` removes only what setup added.
`.trim();

function parseHarnesses(names: readonly string[]): Harness[] {
  return names.map((n) => {
    const h = parseHarness(n);
    if (!h) throw new UsageError(`unknown harness "${n}" (expected ${HARNESSES.join(", ")})`);
    return h;
  });
}

export const setupCommand: Command = {
  name: "setup",
  summary: "Install skill-scanner's hooks and plugins into Claude Code, Codex, OpenCode, and Pi",
  usage: "[claude-code|codex|opencode|pi ...] [options]",
  flags,
  details,
  async run(argv, io) {
    const args = parseArgs(argv, flags);
    const purge = bool(args.flags.purge);
    const uninstall = purge || bool(args.flags.uninstall);
    if (purge && bool(args.flags.project)) throw new UsageError("--purge deletes your user-level state; run it without --project");
    let plan: SetupPlan;
    try {
      plan = await planSetup({
        harnesses: parseHarnesses(args.positionals),
        scope: bool(args.flags.project) ? "project" : "user",
        mode: uninstall ? "uninstall" : "install",
        purge,
        withSkill: bool(args.flags["with-skill"]),
        env: io.env,
        cwd: io.cwd,
      });
    } catch (e) {
      if (!(e instanceof SetupError)) throw e;
      io.stderr(`skill-scanner setup: ${e.message}\n`);
      return EXIT.error;
    }
    return execute(plan, io, { dryRun: bool(args.flags["dry-run"]), yes: bool(args.flags.yes), purge });
  },
};

async function execute(plan: SetupPlan, io: CliIO, opts: { dryRun: boolean; yes: boolean; purge: boolean }): Promise<number> {
  const home = userHome(io.env);
  const self = selfCommand(plan.runtime?.packageRoot);
  if (plan.mode === "install" && plan.harnesses.length === 0) {
    io.stderr(
      "skill-scanner setup: no coding agent found (no claude, codex, opencode, or pi on PATH, and none of their config directories).\n" +
        `Name one to set it up anyway, e.g. \`${self} setup claude-code\`.\n`,
    );
    return EXIT.error;
  }
  io.stdout(renderPlan(plan, home));
  const ops = planOps(plan);
  const refused = planErrors(plan).length > 0;
  const status = refused ? EXIT.error : EXIT.ok;
  if (ops.length === 0) {
    io.stdout(`\n${plan.mode === "install" ? "Nothing to change." : "Nothing to remove."}\n`);
    if (plan.mode === "install" && !opts.dryRun) return finishInstall(plan, io, self, status);
    return status;
  }
  if (opts.dryRun) {
    io.stdout(`\nDry run: nothing was changed. Run the same command without --dry-run to apply ${ops.length} change(s).\n`);
    return status;
  }
  if (!opts.yes) {
    if (!io.isTTY) {
      io.stderr("\nskill-scanner setup: no terminal to confirm on. Re-run with --yes to apply this plan.\n");
      return EXIT.error;
    }
    const question = opts.purge ? `Apply ${ops.length} change(s), including deleting ${plan.stateDir}?` : `Apply ${ops.length} change(s)?`;
    if (!(await io.confirm(`\n${question}`))) {
      io.stdout("Nothing was changed.\n");
      return EXIT.findings;
    }
  }
  const result = await applyOps(ops);
  io.stdout(`\n${renderApply(result, home)}`);
  if (result.failed) return EXIT.error;
  if (plan.mode === "uninstall") {
    io.stdout("Restart any running coding agent so it drops the removed hooks. Backups (*.skill-scanner.bak) were left in place.\n");
    return status;
  }
  return finishInstall(plan, io, self, status);
}

async function finishInstall(plan: SetupPlan, io: CliIO, self: string, status: number): Promise<number> {
  if (!plan.node) return status;
  const canaries = await runCanaries(plan.node.path, plan.script, io.env);
  io.stdout(`\n${renderCanaries(canaries)}`);
  const failed = canaries.some((c) => !c.ok);
  const config = await loadConfig(undefined, io.env).catch(() => DEFAULT_CONFIG);
  const opinions = await describeSecondOpinions(config, io.env);
  io.stdout(`\nSecond opinions, on by default in every scan and install hook:\n${opinions.map((l) => `  - ${l}`).join("\n")}\n`);
  const steps = [
    ...(plan.harnesses.includes("codex")
      ? ["Codex: open Codex, run /hooks, and trust the skill-scanner entries (Codex skips them until then)."]
      : []),
    "Restart your coding agents so they load skill-scanner.",
    `Check the installation any time: ${self} doctor`,
    `Undo: ${self} setup --uninstall (edited files also keep a .skill-scanner.bak copy of their original)`,
  ];
  io.stdout(`\nNext:\n${steps.map((s) => `  - ${s}`).join("\n")}\n`);
  if (failed) {
    io.stderr(`\nskill-scanner setup: the canary failed, so the hooks may not protect you yet. Run \`${self} doctor\` for details.\n`);
    return EXIT.error;
  }
  return status;
}
