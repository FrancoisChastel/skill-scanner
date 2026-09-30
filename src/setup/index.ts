import { readdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { listQuarantine } from "../guard/quarantine";
import { scannerPaths } from "../paths";
import { VERSION } from "../version";
import {
  type Detection,
  detectHarnesses,
  HARNESS_LABEL,
  HARNESSES,
  type Harness,
  harnessFile,
  type Probe,
  type Scope,
  skillsDir,
  userHome,
} from "./harnesses";
import { runtimeHookCommand } from "./hooks-table";
import { type FileOp, type PlanSection, section } from "./ops";
import {
  codexHooksDisabled,
  codexInlineHooks,
  type FilePlan,
  opencodeShim,
  piShim,
  planConfig,
  planHooksInstall,
  planHooksUninstall,
  planShimInstall,
  planShimUninstall,
} from "./plans";
import {
  chooseHookNode,
  locateRuntimeSource,
  type NodeChoice,
  type NodeProbe,
  planRuntime,
  RUNTIME_ENTRY,
  RUNTIME_FILES,
  type RuntimeSource,
  readExisting,
  readRuntimeSource,
  readText,
  systemNodeProbe,
  VERSION_FILE,
} from "./runtime";
import { planSkillCopy, planSkillRemove, readTree, SKILL_NAME } from "./skill";

export type SetupMode = "install" | "uninstall";

export interface SetupOptions {
  /** Harnesses named on the command line; empty means every detected one (install) or all four (uninstall). */
  readonly harnesses: readonly Harness[];
  readonly scope: Scope;
  readonly mode: SetupMode;
  /** Uninstall and also delete the whole state directory. */
  readonly purge: boolean;
  readonly withSkill: boolean;
  readonly env: NodeJS.ProcessEnv;
  readonly cwd: string;
}

export interface SetupDeps {
  readonly probe?: Probe;
  readonly nodeProbe?: NodeProbe;
  /** Path of the running module, for locating the runtime to copy. */
  readonly self?: string;
}

export interface SetupPlan {
  readonly mode: SetupMode;
  readonly scope: Scope;
  readonly harnesses: readonly Harness[];
  /** Detection results, when harnesses were not named. */
  readonly detections?: readonly Detection[];
  readonly node?: NodeChoice;
  readonly runtime?: RuntimeSource;
  readonly stateDir: string;
  readonly script: string;
  readonly sections: readonly PlanSection[];
}

export const planOps = (plan: SetupPlan): FileOp[] => plan.sections.flatMap((s) => (s.error ? [] : s.ops));
export const planErrors = (plan: SetupPlan): PlanSection[] => plan.sections.filter((s) => s.error !== undefined);

export async function planSetup(opts: SetupOptions, deps: SetupDeps = {}): Promise<SetupPlan> {
  return opts.mode === "install" ? planInstall(opts, deps) : planUninstall(opts);
}

async function planInstall(opts: SetupOptions, deps: SetupDeps): Promise<SetupPlan> {
  const { env, scope } = opts;
  const paths = scannerPaths(env);
  const script = join(paths.bin, RUNTIME_ENTRY);
  const detections = opts.harnesses.length === 0 ? await detectHarnesses(env, deps.probe) : undefined;
  const harnesses = detections ? detections.filter((d) => d.detected).map((d) => d.harness) : dedupe(opts.harnesses);
  const base = { mode: opts.mode, scope, harnesses, ...(detections ? { detections } : {}), stateDir: paths.home, script };
  if (harnesses.length === 0) return { ...base, sections: [] };

  const runtime = await locateRuntimeSource(env, deps.self);
  const node = await chooseHookNode(deps.nodeProbe ?? (await systemNodeProbe(env)));
  const source = await readRuntimeSource(runtime.dir);
  const current = Object.fromEntries(
    await Promise.all([...RUNTIME_FILES, VERSION_FILE].map(async (f) => [f, await readExisting(join(paths.bin, f))] as const)),
  );
  const rt = planRuntime(paths.bin, source, current, VERSION);
  const configOp = planConfig(paths.config, await readText(paths.config));
  const sections: PlanSection[] = [
    section("runtime", `Runtime (${paths.bin})`, { ops: rt.ops, unchanged: rt.unchanged, warnings: node.warnings }),
    section("config", "Config", configOp ? { ops: [configOp] } : { unchanged: [paths.config] }),
  ];
  for (const harness of harnesses) sections.push(await installSection(harness, { ...opts, node: node.path, script, bin: paths.bin }));
  if (opts.withSkill) sections.push(await skillInstallSection(harnesses, opts, runtime.packageRoot));
  return { ...base, node, runtime, sections };
}

interface InstallContext extends SetupOptions {
  readonly node: string;
  readonly script: string;
  readonly bin: string;
}

async function installSection(harness: Harness, ctx: InstallContext): Promise<PlanSection> {
  const file = harnessFile(harness, ctx.scope, ctx.env, ctx.cwd);
  const text = await readText(file);
  const title = HARNESS_LABEL[harness];
  switch (harness) {
    case "claude-code": {
      const plan = planHooksInstall("claude-code", file, text, runtimeHookCommand(ctx.node, ctx.script, "claude-code"));
      const notes =
        ctx.scope === "project"
          ? [
              "The hook command holds absolute paths from this machine: teammates who clone the project run `skill-scanner setup --project` themselves.",
            ]
          : [];
      return fromFilePlan(
        "claude-code",
        title,
        file,
        plan,
        plan.op ? [...notes, "Restart Claude Code (or open /hooks) to load the hooks."] : notes,
      );
    }
    case "codex": {
      const plan = planHooksInstall("codex", file, text, runtimeHookCommand(ctx.node, ctx.script, "codex"));
      const toml = join(dirname(file), "config.toml");
      const tomlText = await readText(toml);
      const trust = "Codex skips new hooks until you trust them: open Codex, run /hooks, and trust the skill-scanner entries.";
      const warnings = [
        ...(codexHooksDisabled(tomlText) ? [`${toml} turns hooks off ([features] hooks = false); remove that line.`] : []),
        ...(codexInlineHooks(tomlText) ? [`${toml} also defines hooks inline; Codex runs both but warns at startup.`] : []),
      ];
      return fromFilePlan("codex", title, file, plan, plan.op ? [trust] : [], warnings);
    }
    case "opencode": {
      const plan = planShimInstall(file, text, opencodeShim(join(ctx.bin, "opencode-plugin.mjs")), "OpenCode plugin");
      return fromFilePlan("opencode", title, file, plan, plan.op ? ["Restart OpenCode to load the plugin."] : []);
    }
    case "pi": {
      const plan = planShimInstall(file, text, piShim(join(ctx.bin, "pi-extension.mjs")), "Pi extension");
      return fromFilePlan("pi", title, file, plan, plan.op ? ["Restart Pi (or run /reload) to load the extension."] : []);
    }
  }
}

function fromFilePlan(
  id: Harness,
  title: string,
  file: string,
  plan: FilePlan,
  notes: string[],
  extraWarnings: string[] = [],
): PlanSection {
  const warnings = [...plan.warnings, ...extraWarnings];
  if (plan.error) return section(id, title, { warnings, error: plan.error });
  return section(id, title, { ...(plan.op ? { ops: [plan.op] } : { unchanged: [file] }), notes, warnings });
}

/**
 * Which skill directories the chosen harnesses read: Claude Code its own, Codex and Pi `.agents/skills`.
 * OpenCode reads both, so it needs the `.agents` copy only without Claude Code (two copies make it warn).
 */
export function skillTargets(harnesses: readonly Harness[], scope: Scope, env: NodeJS.ProcessEnv, cwd: string): string[] {
  const claude = harnesses.includes("claude-code");
  const agents = harnesses.includes("codex") || harnesses.includes("pi") || (harnesses.includes("opencode") && !claude);
  return [
    ...(claude ? [join(skillsDir("claude", scope, env, cwd), SKILL_NAME)] : []),
    ...(agents ? [join(skillsDir("agents", scope, env, cwd), SKILL_NAME)] : []),
  ];
}

async function skillInstallSection(
  harnesses: readonly Harness[],
  opts: SetupOptions,
  packageRoot: string | undefined,
): Promise<PlanSection> {
  const title = "Skill (--with-skill)";
  const sourceDir = packageRoot ? join(packageRoot, "skills", SKILL_NAME) : undefined;
  const source = sourceDir ? await readTree(sourceDir) : undefined;
  if (!source || source.length === 0)
    return section("skill", title, { warnings: ["The bundled skill is not available in this copy of skill-scanner; skipped."] });
  const plans = await Promise.all(
    skillTargets(harnesses, opts.scope, opts.env, opts.cwd).map(async (dir) => ({
      dir,
      plan: planSkillCopy(dir, source, await readTree(dir)),
    })),
  );
  return section("skill", title, {
    ops: plans.flatMap((p) => p.plan.ops),
    unchanged: plans.filter((p) => p.plan.ops.length === 0 && p.plan.warnings.length === 0).map((p) => p.dir),
    warnings: plans.flatMap((p) => p.plan.warnings),
  });
}

async function planUninstall(opts: SetupOptions): Promise<SetupPlan> {
  const { env, cwd, scope } = opts;
  const paths = scannerPaths(env);
  const full = opts.harnesses.length === 0;
  const harnesses = full ? [...HARNESSES] : dedupe(opts.harnesses);
  const sections: PlanSection[] = [];
  for (const harness of harnesses) sections.push(await uninstallSection(harness, opts));
  const skillDirs = full
    ? [...skillTargets(HARNESSES, scope, env, cwd)]
    : harnesses.includes("claude-code")
      ? skillTargets(["claude-code"], scope, env, cwd)
      : [];
  const skillPlans = await Promise.all(skillDirs.map(async (dir) => planSkillRemove(dir, await readTree(dir))));
  const skillOps = skillPlans.flatMap((p) => p.ops);
  if (skillOps.length > 0) sections.push(section("skill", "Skill copies", { ops: skillOps }));
  // The runtime and state are user-level: a project uninstall leaves them for the user's own hooks.
  if (opts.purge) sections.push(await purgeSection(paths.home, env));
  else if (full && scope === "user") {
    const runtime = await runtimeRemovalSection(paths.bin, paths.home);
    if (runtime) sections.push(runtime);
  }
  return { mode: opts.mode, scope, harnesses, stateDir: paths.home, script: join(paths.bin, RUNTIME_ENTRY), sections };
}

async function uninstallSection(harness: Harness, opts: SetupOptions): Promise<PlanSection> {
  const file = harnessFile(harness, opts.scope, opts.env, opts.cwd);
  const text = await readText(file);
  const title = HARNESS_LABEL[harness];
  const plan =
    harness === "claude-code" || harness === "codex"
      ? planHooksUninstall(harness, file, text)
      : planShimUninstall(file, text, harness === "opencode" ? "OpenCode plugin" : "Pi extension");
  if (plan.error) return section(harness, title, { warnings: plan.warnings, error: plan.error });
  return section(harness, title, { ops: plan.op ? [plan.op] : [], warnings: plan.warnings });
}

const RUNTIME_ENTRIES = new Set<string>([...RUNTIME_FILES, VERSION_FILE]);

/**
 * Remove the runtime: the whole `bin` directory when it holds only runtime files, otherwise just
 * those files, so anything else someone put there survives.
 */
async function runtimeRemovalSection(bin: string, home: string): Promise<PlanSection | undefined> {
  const entries = await readdirIfExists(bin);
  if (!entries?.some((e) => RUNTIME_ENTRIES.has(e))) return undefined;
  const notes = [
    `${home} keeps your config, trust list, and quarantine; add --purge to delete it too.`,
    "Hooks added with `setup --project` stop working too; run `skill-scanner setup --uninstall --project` in those projects.",
  ];
  const foreign = entries.filter((e) => !RUNTIME_ENTRIES.has(e) && !e.endsWith(".tmp"));
  if (foreign.length === 0)
    return section("runtime", "Runtime", { ops: [{ kind: "remove-dir", path: bin, summary: "remove the hook runtime" }], notes });
  const files = await Promise.all(
    entries.filter((e) => RUNTIME_ENTRIES.has(e)).map(async (e) => ({ path: join(bin, e), existing: await readExisting(join(bin, e)) })),
  );
  const ops: FileOp[] = files.flatMap((f) =>
    f.existing ? [{ kind: "remove", path: f.path, before: f.existing.text, summary: "remove the hook runtime" } as const] : [],
  );
  return section("runtime", "Runtime", { ops, notes, warnings: [`${bin} also holds ${foreign.slice(0, 5).join(", ")}; left in place.`] });
}

/** Directory entries, or undefined when the directory does not exist; other errors propagate. */
async function readdirIfExists(dir: string): Promise<string[] | undefined> {
  try {
    return await readdir(dir);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw e;
  }
}

/** Entries skill-scanner itself keeps in its state directory. */
const STATE_ENTRIES = new Set(["config.json", "trust.json", "flagged.json", "cache", "quarantine", "bin", "decisions.jsonl", "git-hooks"]);

/** Why deleting `home` would be unsafe, or undefined. Anything but the default `~/.skill-scanner` must hold only our entries. */
export function purgeProblem(home: string, entries: readonly string[], userHomeDir: string): string | undefined {
  const target = resolve(home);
  if (target === dirname(target) || target === resolve(userHomeDir) || resolve(userHomeDir).startsWith(`${target}/`))
    return `refusing to delete ${target}: it is a root or home directory`;
  if (target === resolve(userHomeDir, ".skill-scanner")) return undefined;
  const foreign = entries.filter((e) => !STATE_ENTRIES.has(e) && !e.endsWith(".tmp") && !e.endsWith(".lock"));
  return foreign.length > 0
    ? `refusing to delete ${target}: it holds files skill-scanner did not create (${foreign.slice(0, 5).join(", ")}). Delete it yourself if you mean to.`
    : undefined;
}

async function purgeSection(home: string, env: NodeJS.ProcessEnv): Promise<PlanSection> {
  const title = `State (${home})`;
  const entries = await readdirIfExists(home);
  if (entries === undefined) return section("state", title, { notes: [`${home} does not exist; nothing to purge.`] });
  const problem = purgeProblem(home, entries, userHome(env));
  if (problem) return section("state", title, { error: problem });
  const quarantined = await listQuarantine(env);
  const what = ["config", "trust list", "cache", "decision log", "runtime"];
  if (quarantined.length > 0) what.push(`${quarantined.length} quarantined skill${quarantined.length === 1 ? "" : "s"}`);
  return section("state", title, { ops: [{ kind: "remove-dir", path: home, summary: `delete everything: ${what.join(", ")}` }] });
}

const dedupe = <T>(xs: readonly T[]): T[] => [...new Set(xs)];
