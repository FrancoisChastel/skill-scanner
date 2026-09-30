import { readdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import type { ScanReport } from "../core/types";
import { summarizeForAgent } from "../report/index";
import { scanPath } from "../scan";
import { guardCommandLine, shellQuote } from "../sources/guard-env";
import { type SourceScan, type SourceScanOptions, scanSource } from "../sources/index";
import type { TargetScanner } from "./audit";
import { codexPluginSource } from "./codex-plugin";
import { withDeadline } from "./deadline";
import { errorMessage, isInside, isRecord, readJsonFile } from "./fsutil";
import { detectInstallIntents } from "./intents";
import { harnessDirs, skillRoots } from "./locations";
import { askReason, doNotRetry, guardRequiredReason, scanErrorReason } from "./messages";
import { piNpmUpdates } from "./pi-update";
import { loadTrust, logDecision, trustedDigests } from "./state";
import { guardTampering } from "./tamper";
import type { GuardAction, GuardContext, GuardDecision, InstallIntent, SkillRoot, TrustStore } from "./types";

/**
 * Pre-install decisions: recognise what a command would install, fetch and scan it, and turn the
 * verdict into allow, ask, or deny per the user's config. A pass is `allow` with an empty reason;
 * harness adapters map that to "no output" so the harness's own permission prompts still apply.
 */

export type SourceScanner = (raw: string, opts: SourceScanOptions) => Promise<SourceScan>;

export interface GuardDeps {
  readonly scanSource?: SourceScanner;
  /** Scans a local directory (writes, marketplace plugins, audits). */
  readonly scanPath?: TargetScanner;
  readonly now?: () => Date;
  /** Override the 100 s install deadline (tests). */
  readonly installDeadlineMs?: number;
  /** Override the skill roots (tests). */
  readonly roots?: readonly SkillRoot[];
}

export const INSTALL_DEADLINE_MS = 100_000;
export const ALLOW: GuardDecision = Object.freeze({ action: "allow", reason: "" });
/** Nothing to scan before it runs: allowed only under `guard`, which scans each update as it lands. */
const UNDER_GUARD: GuardDecision = Object.freeze({ action: "allow", reason: "", guardRequired: true });

/** Decide whether a shell command may run: pre-scan whatever it would install. */
export async function evaluateCommand(command: string, ctx: GuardContext, deps: GuardDeps = {}): Promise<GuardDecision> {
  const roots = deps.roots ?? skillRoots("all", ctx.cwd, ctx.env);
  const intents = detectInstallIntents(command, { cwd: ctx.cwd, env: ctx.env, roots });
  if (intents.length === 0) return ALLOW;
  return evaluateIntents(command, intents, ctx, deps);
}

export async function evaluateIntents(
  command: string,
  intents: readonly InstallIntent[],
  ctx: GuardContext,
  deps: GuardDeps = {},
): Promise<GuardDecision> {
  const tampered = guardTampering(command);
  if (tampered) {
    const denied: GuardDecision = {
      action: "deny",
      reason: `skill-scanner refused this install: the command also changes ${tampered}, which the install guard relies on to scan what gets installed. Run the install without it. Do not retry with other settings or work around this; tell the user what was refused.`,
      source: describeIntents(intents),
    };
    await logDecision(
      { harness: ctx.harness, kind: "install", action: "deny", intents: intents.map((i) => i.kind), command: clip(command, 300), tampered },
      ctx.env,
      deps.now?.(),
    );
    return denied;
  }
  const trust = await loadTrust(ctx.env);
  const ms = deps.installDeadlineMs ?? INSTALL_DEADLINE_MS;
  const outcome = await withDeadline(ms, ctx.signal, async (signal) => {
    const decisions: GuardDecision[] = [];
    for (const intent of intents) decisions.push(await decideIntent(intent, { ...ctx, signal }, deps, trust));
    return decisions;
  });
  const decisions =
    outcome.status === "ok"
      ? outcome.value
      : [
          errorDecision(
            ctx,
            describeIntents(intents),
            outcome.status === "timeout" ? `timed out after ${Math.round(ms / 1000)} s` : errorMessage(outcome.error),
          ),
        ];
  const worst = mostSevere(decisions);
  const rewrite = ctx.runtime && worst.action !== "deny" && intents.some(isRewritable) ? guardCommandLine(ctx.runtime, command) : undefined;
  const decision = withGuard(worst, rewrite, command);
  await logDecision(
    {
      harness: ctx.harness,
      kind: "install",
      action: decision.action,
      verdict: decision.verdict,
      intents: intents.map((i) => i.kind),
      command: clip(command, 300),
    },
    ctx.env,
    deps.now?.(),
  );
  return decision;
}

const clip = (s: string, n: number): string => (s.length > n ? `${s.slice(0, n)}...` : s);

/** Attach the `guard` rewrite. An update that needs the guard but cannot get it (no runtime to name) is refused. */
function withGuard(decision: GuardDecision, rewrite: string | undefined, command: string): GuardDecision {
  if (rewrite) return { ...decision, rewrite };
  if (!decision.guardRequired || decision.action === "deny") return decision;
  return { action: "deny", reason: guardRequiredReason(`skill-scanner guard -- sh -c ${shellQuote(command)}`), guardRequired: true };
}

function isRewritable(i: InstallIntent): boolean {
  switch (i.kind) {
    case "skills-cli":
    case "git-clone":
    case "git-update":
    case "pi-update":
    case "plugin-update":
      return true;
    case "pi-install":
      return /^git:|^https?:\/\/|^git@|^ssh:\/\//.test(i.source);
    default:
      return false;
  }
}

function describeIntents(intents: readonly InstallIntent[]): string {
  const first = intents[0];
  if (!first) return "this install";
  switch (first.kind) {
    case "skills-cli":
      return first.source ?? `skills ${first.subcommand}`;
    case "git-clone":
      return first.url;
    case "codex-skill-installer":
    case "pi-install":
      return first.source;
    case "pi-update":
      return first.source ?? "pi packages";
    case "write-to-skill-dir":
      return first.dest;
    case "git-update":
      return first.dir;
    case "plugin-update":
      return first.target ?? `${first.harness} plugins`;
    default:
      return first.target;
  }
}

const ADD_SUBCOMMANDS = new Set(["add", "install"]);

async function decideIntent(intent: InstallIntent, ctx: GuardContext, deps: GuardDeps, trust: TrustStore): Promise<GuardDecision> {
  const scan = (raw: string, onlySkills?: readonly string[], skillBundlesOnly = false): Promise<GuardDecision> =>
    scanAndDecide(raw, ctx, deps, trust, onlySkills, skillBundlesOnly);
  switch (intent.kind) {
    case "skills-cli": {
      // update, check, and the lock-file installs fetch whatever is newest: scanned as they land, under guard.
      if (!intent.source || !ADD_SUBCOMMANDS.has(intent.subcommand)) return UNDER_GUARD;
      const only = intent.skills.includes("*") || intent.skills.length === 0 ? undefined : intent.skills;
      // The skills CLI copies skill directories only, so the rest of the repository does not gate it.
      return scan(intent.source, only, true);
    }
    case "git-clone":
      return scan(intent.ref ? `${intent.url}#${intent.ref}` : intent.url);
    case "codex-skill-installer":
      return mostSevere(await sequential(codexSources(intent), (s) => scan(s)));
    case "claude-plugin":
      return intent.action === "marketplace-add" ? scan(intent.target) : claudePluginInstall(intent.target, ctx, deps, trust);
    case "codex-plugin":
      return intent.action === "marketplace-add"
        ? scan(intent.target)
        : codexPluginAdd(intent.target, intent.marketplace, ctx, deps, trust);
    case "pi-install":
      return scan(intent.source);
    case "pi-update":
      // npm packages run their install scripts during the update: scan the versions it would install first.
      return mostSevere([UNDER_GUARD, ...(await sequential(await piNpmUpdates(intent.source, ctx.cwd, ctx.env), (s) => scan(s)))]);
    case "git-update":
    case "plugin-update":
      return UNDER_GUARD;
    default:
      // opencode plugins and plain writes into skill directories are checked right after they happen.
      return ALLOW;
  }
}

async function sequential<T, R>(items: readonly T[], fn: (t: T) => Promise<R>): Promise<R[]> {
  const out: R[] = [];
  for (const item of items) out.push(await fn(item));
  return out;
}

/** Codex's installer defaults to the `main` ref; scan each requested path as a tree URL. */
function codexSources(intent: Extract<InstallIntent, { kind: "codex-skill-installer" }>): string[] {
  if (intent.paths.length === 0) return [intent.source];
  const [repo, ref] = intent.source.split("#");
  return intent.paths.slice(0, 8).map((p) => `https://github.com/${repo}/tree/${ref || "main"}/${p.replace(/^\/+|\/+$/g, "")}`);
}

async function scanAndDecide(
  raw: string,
  ctx: GuardContext,
  deps: GuardDeps,
  trust: TrustStore,
  onlySkills?: readonly string[],
  skillBundlesOnly = false,
): Promise<GuardDecision> {
  const scanner = deps.scanSource ?? scanSource;
  let result: SourceScan | undefined;
  try {
    result = await scanner(raw, {
      cwd: ctx.cwd,
      env: ctx.env,
      keep: false,
      policy: { blockAt: ctx.config.blockAt, warnAt: ctx.config.warnAt },
      suppressions: ctx.config.ignore,
      ...(ctx.signal ? { signal: ctx.signal } : {}),
      ...(onlySkills ? { onlySkills } : {}),
      ...(skillBundlesOnly ? { skillBundlesOnly } : {}),
    });
    return decideReport(result.report, raw, ctx, trust);
  } catch (e) {
    return errorDecision(ctx, raw, errorMessage(e));
  } finally {
    await result?.fetched.cleanup().catch(() => undefined);
  }
}

/** A verdict to a decision. Findings in bundles whose exact digest the user trusted do not count. */
export function decideReport(report: ScanReport, source: string, ctx: Pick<GuardContext, "config">, trust: TrustStore): GuardDecision {
  const trusted = trustedDigests(trust);
  const risky = report.bundles.filter((b) => b.verdict !== "pass");
  if (report.verdict === "pass" || (risky.length > 0 && risky.every((b) => trusted.has(b.bundle.digest)))) {
    return { action: "allow", reason: "", verdict: report.verdict, report, source };
  }
  const summary = summarizeForAgent(report);
  if (report.verdict === "block") return { action: "deny", reason: `${summary}\n${doNotRetry(source)}`, verdict: "block", report, source };
  const action = ctx.config.hooks.onWarn;
  const reason = action === "deny" ? `${summary}\n${doNotRetry(source)}` : action === "ask" ? askReason(summary, source) : summary;
  return { action, reason, verdict: "warn", report, source };
}

export function errorDecision(ctx: Pick<GuardContext, "config">, source: string, message: string): GuardDecision {
  const action = ctx.config.hooks.onError;
  return { action, reason: scanErrorReason(source, message, action), source };
}

const RANK: Readonly<Record<GuardAction, number>> = { allow: 0, ask: 1, deny: 2 };

/** The most severe action wins; reasons of every decision at that level are kept, and any need for the guard. */
export function mostSevere(decisions: readonly GuardDecision[]): GuardDecision {
  if (decisions.length === 0) return ALLOW;
  const top = Math.max(...decisions.map((d) => RANK[d.action]));
  const atTop = decisions.filter((d) => RANK[d.action] === top);
  const first = atTop[0]!;
  const reason = atTop
    .map((d) => d.reason)
    .filter(Boolean)
    .join("\n\n");
  const guardRequired = decisions.some((d) => d.guardRequired);
  return { ...first, reason, ...(guardRequired ? { guardRequired } : {}) };
}

/**
 * `claude plugin install name@marketplace`: when the marketplace is already added and lists the
 * plugin with a relative source, that directory is what gets installed, so scan it now. Other
 * sources are fetched by Claude Code itself and caught by the post-install audit.
 */
async function claudePluginInstall(target: string, ctx: GuardContext, deps: GuardDeps, trust: TrustStore): Promise<GuardDecision> {
  const at = target.lastIndexOf("@");
  const plugin = at > 0 ? target.slice(0, at) : target;
  const market = at > 0 ? target.slice(at + 1) : undefined;
  const base = join(harnessDirs(ctx.env).claude, "plugins", "marketplaces");
  const markets = market ? [market] : await readdir(base).catch(() => [] as string[]);
  for (const m of markets.filter((x) => /^[\w.@+-]+$/.test(x) && x !== "..")) {
    const dir = join(base, m);
    const src = await relativePluginSource(dir, plugin);
    if (src === undefined) continue;
    if (!isInside(dir, src)) return ALLOW;
    const scan = deps.scanPath ?? scanPath;
    try {
      const report = await scan(src, {
        policy: { blockAt: ctx.config.blockAt, warnAt: ctx.config.warnAt },
        suppressions: ctx.config.ignore,
        label: target,
      });
      return decideReport(report, target, ctx, trust);
    } catch (e) {
      return errorDecision(ctx, target, errorMessage(e));
    }
  }
  return ALLOW;
}

/**
 * `codex plugin add <plugin>@<marketplace>`: Codex copies a local plugin from the marketplace, and
 * clones or packs a git or npm one at install time. Scan the directory, or fetch and scan the same
 * source. What cannot be resolved is left to the session-start audit.
 */
async function codexPluginAdd(
  target: string,
  marketplace: string | undefined,
  ctx: GuardContext,
  deps: GuardDeps,
  trust: TrustStore,
): Promise<GuardDecision> {
  const source = await codexPluginSource(target, marketplace, ctx.env);
  if (!source) return ALLOW;
  if (source.kind === "fetch") return scanAndDecide(source.source, ctx, deps, trust);
  const scan = deps.scanPath ?? scanPath;
  try {
    const report = await scan(source.path, {
      policy: { blockAt: ctx.config.blockAt, warnAt: ctx.config.warnAt },
      suppressions: ctx.config.ignore,
      label: target,
      ...(ctx.signal ? { signal: ctx.signal } : {}),
    });
    return decideReport(report, target, ctx, trust);
  } catch (e) {
    return errorDecision(ctx, target, errorMessage(e));
  }
}

async function relativePluginSource(marketDir: string, plugin: string): Promise<string | undefined> {
  const manifest = await readJsonFile(join(marketDir, ".claude-plugin", "marketplace.json"), (raw) => (isRecord(raw) ? raw : undefined));
  const plugins = Array.isArray(manifest?.plugins) ? manifest.plugins : [];
  const entry = plugins.find((p) => isRecord(p) && p.name === plugin);
  if (!isRecord(entry) || typeof entry.source !== "string") return undefined;
  const meta = isRecord(manifest?.metadata) ? manifest.metadata : {};
  const pluginRoot = typeof meta.pluginRoot === "string" && !/^\.\.?\//.test(entry.source) ? meta.pluginRoot : ".";
  return resolve(marketDir, pluginRoot, entry.source);
}
